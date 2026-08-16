// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#include "operations/ReadIdentityOperation.h"
#include <utility>

namespace LibreSCRS::Agent::Operations {

ReadIdentityOperation::ReadIdentityOperation(std::unique_ptr<OperationChannel> channel, Deps deps,
                                             std::shared_ptr<OperationState> state)
    : OperationBase(std::move(channel), std::move(state),
                    // Per wire-cancel contract: dismiss the prompter
                    // modal when a request-side Cancel arrives during
                    // AwaitingConsent. Capture the prompter pointer (the
                    // owning instance outlives the op via AgentService's
                    // declaration order).
                    [prompter = &deps.prompter]() noexcept { prompter->cancel(); }),
      m_deps(std::move(deps))
{}

void ReadIdentityOperation::doWork()
{
    // The per-reader session holder is a raw pointer stamped by the
    // OperationManager; guard against a null (mis-wired) holder so doWork
    // finishes with an internal error instead of dereferencing nullptr.
    if (m_deps.holder == nullptr) {
        finish(OperationStatus::Error, ErrorCode::CommunicationError, "op.internal", "operation has no session holder");
        return;
    }
    // Card-I/O has no meaningful completion percentage — present an honest
    // spinner rather than a fabricated 0->100% bar.
    setIndeterminate(true);
    setPhase(static_cast<std::uint32_t>(OperationPhase::Connecting));

    // Serve a still-cached snapshot without re-walking the card: the same
    // per-card read cache GetPhoto consults and that the fresh read below
    // populates. A master-detail return to an already-read, still-seated card
    // then costs a RAM lookup instead of a fresh multi-second APDU walk. The
    // cache is dropped on CardRemoved and on an auth failure, so a re-inserted
    // or re-authenticated card still reads fresh. Mirror GetPhotoOperation and
    // the fresh-read path: skip the wire completion if the backend is tearing
    // down (the client observes agent-gone via the dropped connection).
    if (auto cached = m_deps.readCache.get(m_deps.cardKey)) {
        if (shutdownRequested()) {
            return;
        }
        static_cast<void>(emitResult(ResultPayload{*cached}));
        finish(OperationStatus::Ok, ErrorCode::None, "op.ok", "Read completed");
        return;
    }

    IdentityReadFlow flow(IdentityReadFlowDeps{
        .holder = *m_deps.holder,
        .reader = m_deps.reader,
        .prompter = m_deps.prompter,
        .serializer = m_deps.serializer,
        .cache = m_deps.credentials,
        .phaseSink = *this,
        .groupSink = *this,
        .cardKey = m_deps.cardKey,
        .requester = m_deps.requester,
        .artifact = m_deps.artifact,
        .token = token(),
        .onCardType = m_deps.onCardType,
        .depositor = m_deps.depositor,
    });
    auto result = flow.run();

    // Backend teardown in progress: the reply channel + broker are being torn
    // down, so skip the wire completion (the client observes agent-gone via the
    // dropped connection). The flow already bailed at its post-read gate on the
    // shutdown-cancel token, before touching any torn-down member.
    if (shutdownRequested()) {
        return;
    }

    if (result.outcome == IdentityReadFlow::Outcome::Cancelled) {
        finish(OperationStatus::Cancelled, result.code, std::move(result.msgKey), std::move(result.msgFallback));
        return;
    }
    if (result.outcome != IdentityReadFlow::Outcome::Ok || !result.snapshot) {
        finish(OperationStatus::Error, result.code, std::move(result.msgKey), std::move(result.msgFallback));
        return;
    }

    // Store the full snapshot (photos included) so GetPhoto can pull from
    // the cache without re-reading the card.
    m_deps.readCache.put(m_deps.cardKey, *result.snapshot);

    // Emit Identity1.Result BEFORE Finished (strict ordering contract). Identity1
    // delivers inline (no memfd seal), so delivery cannot fail — discard the
    // always-true status.
    static_cast<void>(emitResult(ResultPayload{*result.snapshot}));
    finish(OperationStatus::Ok, ErrorCode::None, std::move(result.msgKey), std::move(result.msgFallback));
}

} // namespace LibreSCRS::Agent::Operations
