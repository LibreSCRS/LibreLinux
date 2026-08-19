// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#include "operations/ListCredentialsOperation.h"
#include <LibreSCRS/Agent/operations/PromptSerializer.h>
#include <LibreSCRS/Agent/operations/CredentialListFlow.h>
#include <utility>

namespace LibreSCRS::Agent::Operations {

namespace {

// Map a completed non-Ok list onto the closed outcome-token vocabulary the
// Credentials1.Result payload carries. Finished keeps the flow's richer
// ErrorCode (e.g. ParseError); the Result outcome names the coarse class —
// the two prompter-visible classes (cancel, undelivered prompt) and the
// removed card keep their precise tokens.
[[nodiscard]] CredentialOutcome listOutcomeFor(CredentialListFlow::Outcome outcome, ErrorCode code) noexcept
{
    if (outcome == CredentialListFlow::Outcome::Cancelled) {
        return CredentialOutcome::UserCancelled;
    }
    if (code == ErrorCode::CardRemoved) {
        return CredentialOutcome::CardRemoved;
    }
    if (code == ErrorCode::PrompterError) {
        return CredentialOutcome::MissingFields;
    }
    return CredentialOutcome::Unspecified;
}

} // namespace

ListCredentialsOperation::ListCredentialsOperation(std::unique_ptr<OperationChannel> channel, Deps deps,
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

void ListCredentialsOperation::doWork()
{
    if (m_deps.holder == nullptr) {
        finish(OperationStatus::Error, ErrorCode::CommunicationError, "op.internal", "operation has no session holder");
        return;
    }
    setIndeterminate(true);
    setPhase(static_cast<std::uint32_t>(OperationPhase::Connecting));

    CredentialListFlow flow(CredentialListFlowDeps{
        .holder = *m_deps.holder,
        .credentials = m_deps.credentials,
        .prompter = m_deps.prompter,
        .serializer = m_deps.serializer,
        .cache = m_deps.credCache,
        .snapshotCache = m_deps.snapshotCache,
        .phaseSink = *this,
        .cardKey = m_deps.cardKey,
        .requester = m_deps.requester,
        .artifact = m_deps.artifact,
        .token = token(),
    });
    auto result = flow.run();

    // Backend teardown: skip the wire completion (the client observes agent-gone
    // via the dropped connection); the flow already bailed at its post-prompt gate.
    if (shutdownRequested()) {
        return;
    }

    // Emit Credentials1.Result for EVERY completed list attempt BEFORE
    // Finished — the XML promises the payload "for every completed attempt",
    // mirroring the mutations: outcome=ok + the records on success, the
    // mapped outcome token + empty records for a cancel or failure (a client
    // must never have to guess a cancel from a Result-less terminal). An
    // undeliverable Result fails the op CLOSED (contract: ordering holds
    // modulo channel allocation failure) — never Finished(Ok) with a
    // silently-missing payload.
    CredentialResult payload;
    if (result.outcome == CredentialListFlow::Outcome::Ok) {
        payload.op.outcome = CredentialOutcome::Ok;
        payload.records = std::move(result.snapshot.records);
    } else {
        payload.op.outcome = listOutcomeFor(result.outcome, result.code);
    }
    if (!emitResult(ResultPayload{std::move(payload)})) {
        finish(OperationStatus::Error, ErrorCode::CommunicationError, "op.result_failed",
               "Failed to deliver the operation result");
        return;
    }
    if (result.outcome == CredentialListFlow::Outcome::Cancelled) {
        finish(OperationStatus::Cancelled, result.code, std::move(result.msgKey), std::move(result.msgFallback));
        return;
    }
    if (result.outcome != CredentialListFlow::Outcome::Ok) {
        finish(OperationStatus::Error, result.code, std::move(result.msgKey), std::move(result.msgFallback));
        return;
    }
    finish(OperationStatus::Ok, ErrorCode::None, std::move(result.msgKey), std::move(result.msgFallback));
}

} // namespace LibreSCRS::Agent::Operations
