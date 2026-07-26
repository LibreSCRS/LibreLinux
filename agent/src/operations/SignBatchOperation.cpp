// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#include "operations/SignBatchOperation.h"
#include <LibreSCRS/Agent/OperationPhase.h> // OperationPhase enum
#include <utility>

namespace LibreSCRS::Agent::Operations {

namespace {

// BatchSignFlow::Result::rows (operations/BatchSignFlow.h's per-field
// BatchSignRow) -> the channel-level BatchSignedRow (backend/
// OperationChannel.h) SignBatchOperation hands to emitResult. Deliberately a
// distinct type from the flow's own row (see BatchSignedRow's doc comment) —
// this mirrors how doWork() below builds a fresh SignMeta/SignedArtifact from
// SignFlow::Result's discrete fields rather than reusing a flow-owned type.
BatchSignResult toChannelRows(std::vector<BatchSignRow> rows)
{
    BatchSignResult out;
    out.reserve(rows.size());
    for (auto& row : rows) {
        out.push_back(BatchSignedRow{
            .displayName = std::move(row.displayName),
            .bytes = std::move(row.signedBytes),
            .meta =
                SignMeta{
                    .format = std::move(row.resolvedFormat),
                    .level = std::move(row.resolvedLevel),
                    .tsaUsed = row.tsaUsed,
                    .chainComplete = row.chainComplete,
                },
            .code = row.code,
        });
    }
    return out;
}

} // namespace

SignBatchOperation::SignBatchOperation(std::unique_ptr<OperationChannel> channel, Deps deps,
                                       std::shared_ptr<OperationState> state)
    : OperationBase(std::move(channel), std::move(state),
                    [prompter = &deps.prompter]() noexcept { prompter->cancel(); }),
      m_deps(std::move(deps))
{}

void SignBatchOperation::doWork()
{
    // Guard a null (mis-wired) session holder so doWork finishes with an
    // internal error instead of dereferencing nullptr.
    if (m_deps.holder == nullptr) {
        finish(OperationStatus::Error, ErrorCode::CommunicationError, "op.internal", "operation has no session holder");
        return;
    }
    // Card-I/O + signing has no meaningful completion percentage — honest spinner.
    setIndeterminate(true);
    setPhase(static_cast<std::uint32_t>(OperationPhase::Connecting));

    BatchSignFlow flow(BatchSignFlowDeps{
        .holder = *m_deps.holder,
        .signer = m_deps.signer,
        .prompter = m_deps.prompter,
        .serializer = m_deps.serializer,
        .cache = m_deps.credentials,
        .phaseSink = *this,
        .pinHolder = m_pinHolder,
        .cardKey = m_deps.cardKey,
        .requester = m_deps.requester,
        .params = m_deps.params,
        .documents = m_deps.documents,
        .token = token(),
    });
    auto result = flow.run();

    // Backend teardown in progress: skip the wire completion (the flow
    // already bailed at its post-prompt gate on the shutdown-cancel token,
    // before touching any torn-down member) — same discipline as SignOperation.
    if (shutdownRequested()) {
        return;
    }

    if (result.outcome == BatchSignFlow::Outcome::Cancelled) {
        finish(OperationStatus::Cancelled, result.code, std::move(result.msgKey), std::move(result.msgFallback));
        return;
    }
    if (result.outcome == BatchSignFlow::Outcome::InvalidRequest) {
        // Defense-in-depth only: Card1.SignBatch validates the document
        // count at method entry (mirroring BatchSignFlow's own
        // isValidBatchDocumentCount), before any Operation is ever
        // constructed, so this arm is unreachable in production — see
        // BatchSignFlow.h's own doc comment on the gate's intended caller.
        finish(OperationStatus::Error, ErrorCode::CommunicationError, std::move(result.msgKey),
               std::move(result.msgFallback));
        return;
    }

    // Ok or Error (both mean >= 1 document was attempted; only Cancelled /
    // InvalidRequest above leave `rows` empty) — deliver the per-row detail
    // BEFORE Finished, mirroring every sibling typed result. Unlike Sign1,
    // this fires even when the AGGREGATE status is Error: a batch conveys
    // meaningful per-row outcomes even when zero rows were signed (the
    // per-row errorCodes are exactly what a client needs to explain the
    // failure document-by-document).
    if (!emitResult(ResultPayload{toChannelRows(std::move(result.rows))})) {
        finish(OperationStatus::Error, ErrorCode::CommunicationError, "op.memfd_failed",
               "Failed to allocate a sealed memfd for a batch row");
        return;
    }

    if (result.outcome == BatchSignFlow::Outcome::Ok) {
        finish(OperationStatus::Ok, ErrorCode::None, std::move(result.msgKey), std::move(result.msgFallback));
    } else {
        finish(OperationStatus::Error, result.code, std::move(result.msgKey), std::move(result.msgFallback));
    }
}

} // namespace LibreSCRS::Agent::Operations
