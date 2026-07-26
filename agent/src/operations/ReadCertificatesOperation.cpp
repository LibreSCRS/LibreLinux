// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#include "operations/ReadCertificatesOperation.h"
#include <cstdint>
#include <utility>

namespace LibreSCRS::Agent::Operations {

ReadCertificatesOperation::ReadCertificatesOperation(std::unique_ptr<OperationChannel> channel, Deps deps,
                                                     std::shared_ptr<OperationState> state)
    : OperationBase(std::move(channel), std::move(state),
                    [prompter = &deps.prompter]() noexcept { prompter->cancel(); }),
      m_deps(std::move(deps))
{}

void ReadCertificatesOperation::doWork()
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

    // Cache hit: serve the certs from RAM without opening a session or re-walking
    // the card. The per-insertion cache is dropped on CardRemoved.
    if (auto cached = m_deps.readCache.getCertificates(m_deps.cardKey)) {
        // Backend teardown in progress: skip the wire completion (the reply
        // channel is being torn down), matching the miss-path gate below and
        // GetPhotoOperation — emitResult is not shutdown-gated, finish() is.
        if (shutdownRequested()) {
            return;
        }
        static_cast<void>(emitResult(ResultPayload{*cached}));
        finish(OperationStatus::Ok, ErrorCode::None, "op.ok", "Certificates returned");
        return;
    }

    CertReadFlow flow(CertReadFlowDeps{
        .holder = *m_deps.holder,
        .certReader = m_deps.certReader,
        .trustVerifier = m_deps.trustVerifier,
        .prompter = m_deps.prompter,
        .serializer = m_deps.serializer,
        .cache = m_deps.credentials,
        .phaseSink = *this,
        .cardKey = m_deps.cardKey,
        .reader = m_deps.readerName,
        .requester = m_deps.requester,
        .artifact = m_deps.artifact,
        .token = token(),
    });
    auto result = flow.run();

    // Backend teardown in progress: the reply channel + broker are being torn
    // down, so skip the wire completion (the client observes agent-gone via the
    // dropped connection). The flow already bailed at its post-read gate on the
    // shutdown-cancel token, before touching any torn-down member.
    if (shutdownRequested()) {
        return;
    }

    if (result.outcome == CertReadFlow::Outcome::Cancelled) {
        finish(OperationStatus::Cancelled, result.code, std::move(result.msgKey), std::move(result.msgFallback));
        return;
    }
    if (result.outcome != CertReadFlow::Outcome::Ok) {
        finish(OperationStatus::Error, result.code, std::move(result.msgKey), std::move(result.msgFallback));
        return;
    }

    // Populate the cache so the next read serves from RAM. Past the
    // shutdownRequested() gate above, so it never writes during teardown.
    m_deps.readCache.putCertificates(m_deps.cardKey, result.certs);

    // Emit Certificates1.Result BEFORE Finished (strict ordering contract).
    // Certificates1 delivers inline (no memfd seal), so delivery cannot fail —
    // discard the always-true status.
    static_cast<void>(emitResult(ResultPayload{result.certs}));
    finish(OperationStatus::Ok, ErrorCode::None, std::move(result.msgKey), std::move(result.msgFallback));
}

} // namespace LibreSCRS::Agent::Operations
