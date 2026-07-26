// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <LibreSCRS/Agent/cache/CredentialCache.h>
#include <LibreSCRS/Agent/cache/CredentialSnapshotCache.h>
#include <LibreSCRS/Agent/operations/OperationBase.h>
#include <LibreSCRS/Agent/operations/Seams.h>
#include <memory>
#include <string>

namespace LibreSCRS::Agent::Operations {

class CardSessionHolder;
class PromptSerializer;

// Thin adaptor over CredentialListFlow: reads the card's PIN credentials, emits
// the Credentials1.Result (outcome=ok + the record listing) on success, then
// Operation1.Finished. The flow puts the produced snapshot into the shared
// per-card CredentialSnapshotCache (its version is the id namespace ManagePin /
// ActivateSigningKey later address).
class ListCredentialsOperation final : public OperationBase
{
public:
    struct Deps
    {
        // Per-reader shared-session holder, stamped by OperationManager from the
        // worker that serialises this reader's ops (single-threaded; no locking).
        CardSessionHolder* holder{nullptr};
        CredentialManager& credentials; // the PIN-lifecycle plugin seam
        PrompterClientBase& prompter;
        PromptSerializer& serializer;
        CredentialCache& credCache;             // CAN/MRZ secret cache (read provider)
        CredentialSnapshotCache& snapshotCache; // per-card listing store (flow puts here)
        std::string cardKey;
        // Human reader name, used by OperationManager to lazily build the reader's
        // CardSessionHolder. Not consumed by the flow.
        std::string readerName;
        std::string requester;
        std::string artifact;
    };

    ListCredentialsOperation(std::unique_ptr<OperationChannel> channel, Deps deps,
                             std::shared_ptr<OperationState> state);

protected:
    void doWork() override;

private:
    Deps m_deps;
};

} // namespace LibreSCRS::Agent::Operations
