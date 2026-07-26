// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#include "operations/ManagePinOperation.h"
#include <LibreSCRS/Agent/value/ErrorTaxonomy.h> // errorCodeFor(CredentialOutcome)
#include <utility>

namespace LibreSCRS::Agent::Operations {

ManagePinOperation::ManagePinOperation(std::unique_ptr<OperationChannel> channel, Deps deps,
                                       std::shared_ptr<OperationState> state)
    : OperationBase(std::move(channel), std::move(state),
                    [prompter = &deps.prompter]() noexcept { prompter->cancel(); }),
      m_deps(std::move(deps))
{}

void ManagePinOperation::doWork()
{
    if (m_deps.holder == nullptr) {
        finish(OperationStatus::Error, ErrorCode::CommunicationError, "op.internal", "operation has no session holder");
        return;
    }
    setIndeterminate(true);
    setPhase(static_cast<std::uint32_t>(OperationPhase::Connecting));

    PinManageFlowDeps deps{
        .holder = *m_deps.holder,
        .credentialManager = m_deps.credentials,
        .prompter = m_deps.prompter,
        .serializer = m_deps.serializer,
        .cache = m_deps.credCache,
        .snapshotCache = m_deps.snapshotCache,
        .cardReadCache = m_deps.readCache,
        .phaseSink = *this,
        .snapshot = &m_deps.snapshot,
        .cardKey = m_deps.cardKey,
        .requester = m_deps.requester,
        .reader = m_deps.readerName,
        .artifact = m_deps.artifact,
        .token = token(),
    };
    const CredentialOpResult result = runPinManage(deps, m_deps.request);

    // Backend teardown: skip the wire completion (the client observes agent-gone
    // via the dropped connection); the flow bailed at its post-prompt gate.
    if (shutdownRequested()) {
        return;
    }

    // Emit Credentials1.Result for EVERY completed attempt (invalidPin/blocked
    // carry retries_left/blocked) BEFORE Finished. An undeliverable Result
    // fails the op CLOSED (contract: ordering holds modulo channel allocation
    // failure) — never Finished(Ok) with a silently-missing payload.
    if (!emitResult(ResultPayload{CredentialResult{.op = result, .records = {}}})) {
        finish(OperationStatus::Error, ErrorCode::CommunicationError, "op.result_failed",
               "Failed to deliver the operation result");
        return;
    }

    const auto finishState = errorCodeFor(result.outcome);
    finish(finishState.status, finishState.code, {}, {});
}

} // namespace LibreSCRS::Agent::Operations
