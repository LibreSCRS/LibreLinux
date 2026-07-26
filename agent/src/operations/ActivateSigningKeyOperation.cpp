// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#include "operations/ActivateSigningKeyOperation.h"
#include <LibreSCRS/Agent/operations/KeyActivationFlow.h>
#include <LibreSCRS/Agent/value/CredentialRecord.h>
#include <LibreSCRS/Agent/value/ErrorTaxonomy.h> // errorCodeFor(CredentialOutcome)
#include <optional>
#include <utility>

namespace LibreSCRS::Agent::Operations {

namespace {

// Resolve the signing-key credential from the latest listing: the record that can
// be activated NOW. When none exists (no listing, or nothing activatable) a
// default record is returned — its keyActivatable=false trips the flow's
// capability gate, so the operation answers Unsupported without prompting (the
// valid "card advertises nothing" result, not an entry error).
CredentialRecord resolveKeyRecord(const std::optional<CredentialSnapshot>& snapshot)
{
    if (snapshot) {
        for (const auto& record : snapshot->records) {
            if (record.keyActivatable) {
                return record;
            }
        }
    }
    return CredentialRecord{};
}

} // namespace

ActivateSigningKeyOperation::ActivateSigningKeyOperation(std::unique_ptr<OperationChannel> channel, Deps deps,
                                                         std::shared_ptr<OperationState> state)
    : OperationBase(std::move(channel), std::move(state),
                    [prompter = &deps.prompter]() noexcept { prompter->cancel(); }),
      m_deps(std::move(deps))
{}

void ActivateSigningKeyOperation::doWork()
{
    if (m_deps.holder == nullptr) {
        finish(OperationStatus::Error, ErrorCode::CommunicationError, "op.internal", "operation has no session holder");
        return;
    }
    setIndeterminate(true);
    setPhase(static_cast<std::uint32_t>(OperationPhase::Connecting));

    // Resolve the addressed record AND the snapshot's listing-plugin binding
    // from the same latest listing: the activation is routed to the plugin
    // whose listing produced the record, so another candidate cannot intercept
    // the mutation.
    const std::optional<CredentialSnapshot> snapshot = m_deps.snapshotCache.get(m_deps.cardKey);
    CredentialRecord record = resolveKeyRecord(snapshot);

    const CredentialOpResult result = runKeyActivation(KeyActivationFlowDeps{
        .holder = *m_deps.holder,
        .credentials = m_deps.credentials,
        .prompter = m_deps.prompter,
        .serializer = m_deps.serializer,
        .cache = m_deps.credCache,
        .snapshotCache = m_deps.snapshotCache,
        .cardReadCache = m_deps.readCache,
        .phaseSink = *this,
        .record = std::move(record),
        .listPluginId = snapshot ? snapshot->listPluginId : std::string{},
        .cardKey = m_deps.cardKey,
        .requester = m_deps.requester,
        .reader = m_deps.readerName,
        .artifact = m_deps.artifact,
        .pinActivated = std::nullopt,
        .token = token(),
    });

    if (shutdownRequested()) {
        return;
    }

    // Emit Credentials1.Result BEFORE Finished. An undeliverable Result fails
    // the op CLOSED (contract: ordering holds modulo channel allocation
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
