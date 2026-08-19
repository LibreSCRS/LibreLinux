// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#include "operations/SignOperation.h"
#include <LibreSCRS/Agent/operations/PromptSerializer.h>
#include <utility>

namespace LibreSCRS::Agent::Operations {

SignOperation::SignOperation(std::unique_ptr<OperationChannel> channel, Deps deps,
                             std::shared_ptr<OperationState> state)
    : OperationBase(std::move(channel), std::move(state),
                    [prompter = &deps.prompter, serializer = &deps.serializer, cardKey = deps.cardKey]() noexcept {
                        // Dismiss THIS card's live prompt: more than one window
                        // can stand, and the gate is the only thing that knows
                        // which id is outstanding for this card.
                        for (const auto& id : serializer->liveIdsFor(cardKey)) {
                            prompter->cancel(id);
                        }
                    }),
      m_deps(std::move(deps))
{}

void SignOperation::doWork()
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

    SignFlow flow(SignFlowDeps{
        .holder = *m_deps.holder,
        .signer = m_deps.signer,
        .prompter = m_deps.prompter,
        .serializer = m_deps.serializer,
        .cache = m_deps.credentials,
        .phaseSink = *this,
        .cardKey = m_deps.cardKey,
        .requester = m_deps.requester,
        .params = m_deps.params,
        .token = token(),
    });
    auto result = flow.run();

    // Backend teardown in progress: the reply channel + broker are being torn
    // down, so skip the wire completion (the client observes agent-gone via the
    // dropped connection). The flow already bailed at its post-prompt gate on the
    // shutdown-cancel token, before touching any torn-down member.
    if (shutdownRequested()) {
        return;
    }

    if (result.outcome == SignFlow::Outcome::Cancelled) {
        finish(OperationStatus::Cancelled, result.code, std::move(result.msgKey), std::move(result.msgFallback));
        return;
    }
    if (result.outcome != SignFlow::Outcome::Ok) {
        finish(OperationStatus::Error, result.code, std::move(result.msgKey), std::move(result.msgFallback));
        return;
    }

    const SignMeta meta{
        .format = result.resolvedFormat,
        .level = result.resolvedLevel,
        .tsaUsed = result.tsaUsed,
        .chainComplete = result.chainComplete,
    };
    SignedArtifact artifact{std::move(result.signedDocumentBytes), meta};

    // Emit Sign1.Result BEFORE Finished (strict ordering contract). The backend
    // channel seals the bytes into a memfd for the signal and publishes the
    // recovery store (re-dup source for Sign1.GetResult) so a late subscriber
    // that races the signal can still recover the artifact. A memfd seal failure
    // returns false: fail the op CLOSED rather than emit Finished(Ok) with no
    // Result signal.
    if (!emitResult(ResultPayload{std::move(artifact)})) {
        finish(OperationStatus::Error, ErrorCode::CommunicationError, "op.memfd_failed",
               "Failed to allocate sealed memfd for the signed artifact");
        return;
    }
    finish(OperationStatus::Ok, ErrorCode::None, std::move(result.msgKey), std::move(result.msgFallback));
}

} // namespace LibreSCRS::Agent::Operations
