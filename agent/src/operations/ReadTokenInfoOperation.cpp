// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#include "operations/ReadTokenInfoOperation.h"
#include <utility>

namespace LibreSCRS::Agent::Operations {

ReadTokenInfoOperation::ReadTokenInfoOperation(std::unique_ptr<OperationChannel> channel, Deps deps,
                                               std::shared_ptr<OperationState> state)
    : OperationBase(std::move(channel), std::move(state),
                    [prompter = &deps.prompter]() noexcept { prompter->cancel(); }),
      m_deps(std::move(deps))
{}

void ReadTokenInfoOperation::doWork()
{
    // Guard a null (mis-wired) session holder so doWork finishes with an
    // internal error instead of dereferencing nullptr.
    if (m_deps.holder == nullptr) {
        finish(OperationStatus::Error, ErrorCode::CommunicationError, "op.internal", "operation has no session holder");
        return;
    }
    // Card-I/O has no meaningful completion percentage — honest spinner.
    setIndeterminate(true);
    setPhase(static_cast<std::uint32_t>(OperationPhase::Connecting));

    TokenInfoReadFlow flow(TokenInfoReadFlowDeps{
        .holder = *m_deps.holder,
        .reader = m_deps.reader,
        .prompter = m_deps.prompter,
        .serializer = m_deps.serializer,
        .cache = m_deps.credentials,
        .phaseSink = *this,
        .cardKey = m_deps.cardKey,
        .readerName = m_deps.readerName,
        .requester = m_deps.requester,
        .artifact = m_deps.artifact,
        .token = token(),
    });
    auto result = flow.run();

    // Backend teardown in progress: the reply channel + broker are being torn
    // down, so skip the wire completion (the client observes agent-gone via the
    // dropped connection). The flow already bailed at its post-open gate on the
    // shutdown-cancel token, before touching any torn-down member.
    if (shutdownRequested()) {
        return;
    }

    if (result.outcome == TokenInfoReadFlow::Outcome::Cancelled) {
        finish(OperationStatus::Cancelled, result.code, std::move(result.msgKey), std::move(result.msgFallback));
        return;
    }
    if (result.outcome != TokenInfoReadFlow::Outcome::Ok || !result.snapshot) {
        finish(OperationStatus::Error, result.code, std::move(result.msgKey), std::move(result.msgFallback));
        return;
    }

    // Emit Identity1.Result BEFORE Finished (strict ordering contract) — the
    // EXISTING result shape, no new interface: a single "token" group, or an
    // empty one (zero fields) for an unsupported/best-effort-miss plugin,
    // which is still SUCCESS. Identity1 delivers inline (no memfd seal), so
    // delivery cannot fail — discard the always-true status.
    static_cast<void>(emitResult(ResultPayload{*result.snapshot}));
    finish(OperationStatus::Ok, ErrorCode::None, std::move(result.msgKey), std::move(result.msgFallback));
}

} // namespace LibreSCRS::Agent::Operations
