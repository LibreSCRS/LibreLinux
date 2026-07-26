// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <LibreSCRS/Agent/cache/CardReadCache.h>
#include <LibreSCRS/Agent/cache/CredentialCache.h>
#include <LibreSCRS/Agent/cache/CredentialSnapshotCache.h>
#include <LibreSCRS/Agent/operations/OperationBase.h>
#include <LibreSCRS/Agent/operations/PinChangeFlow.h> // PinManageRequest
#include <LibreSCRS/Agent/operations/Seams.h>
#include <LibreSCRS/Agent/value/CredentialRecord.h> // CredentialSnapshot
#include <memory>
#include <string>

namespace LibreSCRS::Agent::Operations {

class CardSessionHolder;
class PromptSerializer;

// Thin adaptor over runPinManage: mutates one PIN credential (change / unblock /
// activate_pin). The addressed record is resolved from the snapshot captured at
// method entry (validatePinManageRequest already ran there, so a live Operation
// only exists for a resolvable request). Emits the Credentials1.Result (outcome +
// retries_left / blocked / ...) for every completed attempt, then
// Operation1.Finished with the mapped status/errorCode.
class ManagePinOperation final : public OperationBase
{
public:
    struct Deps
    {
        CardSessionHolder* holder{nullptr};
        CredentialManager& credentials; // the PIN-lifecycle plugin seam
        PrompterClientBase& prompter;
        PromptSerializer& serializer;
        CredentialCache& credCache;             // CAN/MRZ secret cache (read provider)
        CredentialSnapshotCache& snapshotCache; // invalidated when the mutation reaches the card
        CardReadCache& readCache;               // invalidated alongside the snapshot cache
        std::string cardKey;
        std::string readerName;
        std::string requester;
        std::string artifact;
        // Resolved at Credentials1.ManagePin entry; the flow consumes both.
        PinManageRequest request;
        CredentialSnapshot snapshot;
    };

    ManagePinOperation(std::unique_ptr<OperationChannel> channel, Deps deps, std::shared_ptr<OperationState> state);

protected:
    void doWork() override;

private:
    Deps m_deps;
};

} // namespace LibreSCRS::Agent::Operations
