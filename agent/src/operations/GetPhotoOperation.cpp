// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#include "operations/GetPhotoOperation.h"
#include <utility>

namespace LibreSCRS::Agent::Operations {

GetPhotoOperation::GetPhotoOperation(std::unique_ptr<OperationChannel> channel, Deps deps,
                                     std::shared_ptr<OperationState> state)
    : OperationBase(std::move(channel), std::move(state),
                    // See ReadIdentityOperation::ReadIdentityOperation
                    // for the rationale.
                    [prompter = &deps.prompter]() noexcept { prompter->cancel(); }),
      m_deps(std::move(deps))
{}

std::optional<CardReadSnapshot> GetPhotoOperation::obtainSnapshot()
{
    if (auto cached = m_deps.readCache.get(m_deps.cardKey)) {
        return cached;
    }
    // This op's cache-miss read reuses IdentityReadFlow, but the Operation
    // object here exports Photo1, not Identity1 -- there is no Group signal
    // to emit, so progressive delivery is gated OFF at this wiring site (see
    // NullGroupSink's own doc comment), never inside the flow or the channel.
    static NullGroupSink noGroupStream;
    IdentityReadFlow flow(IdentityReadFlowDeps{
        .holder = *m_deps.holder,
        .reader = m_deps.reader,
        .prompter = m_deps.prompter,
        .serializer = m_deps.serializer,
        .cache = m_deps.credentials,
        .phaseSink = *this,
        .groupSink = noGroupStream,
        .cardKey = m_deps.cardKey,
        .requester = m_deps.requester,
        .artifact = m_deps.artifact,
        .token = token(),
        .onCardType = m_deps.onCardType,
        .depositor = m_deps.depositor,
    });
    auto result = flow.run();
    if (result.outcome != IdentityReadFlow::Outcome::Ok || !result.snapshot) {
        if (result.outcome == IdentityReadFlow::Outcome::Cancelled) {
            finish(OperationStatus::Cancelled, result.code, std::move(result.msgKey), std::move(result.msgFallback));
        } else {
            finish(OperationStatus::Error, result.code, std::move(result.msgKey), std::move(result.msgFallback));
        }
        return std::nullopt;
    }
    // Backend teardown in progress: skip the read-cache write (the cache is a core
    // member NOT co-owned by this op) and return nullopt WITHOUT finishing — the
    // shutdownRequested() re-gate at the top of doWork then skips the wire
    // completion, exactly as ReadIdentityOperation gates before its own cache put.
    if (shutdownRequested()) {
        return std::nullopt;
    }
    m_deps.readCache.put(m_deps.cardKey, *result.snapshot);
    return result.snapshot;
}

void GetPhotoOperation::doWork()
{
    // Guard a null (mis-wired) session holder so doWork finishes with an
    // internal error instead of dereferencing nullptr (obtainSnapshot would
    // otherwise dereference *m_deps.holder on a cache miss).
    if (m_deps.holder == nullptr) {
        finish(OperationStatus::Error, ErrorCode::CommunicationError, "op.internal", "operation has no session holder");
        return;
    }
    // Card-I/O has no meaningful completion percentage — present an honest
    // spinner rather than a fabricated 0->100% bar.
    setIndeterminate(true);
    setPhase(static_cast<std::uint32_t>(OperationPhase::Connecting));
    auto snapshot = obtainSnapshot();

    // Backend teardown in progress: the reply channel + broker are being torn
    // down, so skip the wire completion (the client observes agent-gone via the
    // dropped connection). obtainSnapshot()'s IdentityReadFlow already bailed at
    // its post-read/prompt gate on the shutdown-cancel token before touching any
    // torn-down member. Matches SignOperation / ReadIdentityOperation.
    if (shutdownRequested()) {
        return;
    }

    if (!snapshot) {
        return; // obtainSnapshot already called finish()
    }

    // Collect the raw photo bytes keyed by "groupKey:fieldKey". The backend
    // channel seals each into a sealed memfd for the Photo1.Result signal; the
    // core stays transport-neutral and yields plain bytes.
    PhotoResult photos;
    for (const auto& g : snapshot->groups) {
        for (const auto& f : g.fields) {
            if (f.type != FieldType::Photo || f.binaryValue.empty()) {
                continue;
            }
            photos.push_back({g.groupKey + ":" + f.fieldKey, f.binaryValue});
        }
    }

    if (photos.empty()) {
        finish(OperationStatus::Error, ErrorCode::UnsupportedCard, "op.no_photo", "Card has no photo field to return");
        return;
    }

    // Emit Photo1.Result BEFORE Finished (strict ordering contract). A memfd seal
    // failure returns false: fail the op CLOSED rather than emit Finished(Ok) with
    // no Result signal.
    if (!emitResult(ResultPayload{std::move(photos)})) {
        finish(OperationStatus::Error, ErrorCode::CommunicationError, "op.memfd_failed",
               "Failed to allocate sealed memfd for photo");
        return;
    }
    finish(OperationStatus::Ok, ErrorCode::None, "op.ok", "Photo returned");
}

} // namespace LibreSCRS::Agent::Operations
