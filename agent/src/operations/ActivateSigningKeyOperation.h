// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <LibreSCRS/Agent/cache/CardReadCache.h>
#include <LibreSCRS/Agent/cache/CredentialCache.h>
#include <LibreSCRS/Agent/cache/CredentialSnapshotCache.h>
#include <LibreSCRS/Agent/operations/OperationBase.h>
#include <LibreSCRS/Agent/operations/Seams.h>
#include <memory>
#include <string>

namespace LibreSCRS::Agent::Operations {

class CardSessionHolder;
class PromptSerializer;

// Thin adaptor over runKeyActivation: verifies the operational SIGN PIN and
// performs the on-card key ACTIVATE. The signing-key record is resolved from the
// most recent ListCredentials snapshot (the record advertising key activation);
// a card whose listing exposes no activatable key yields outcome=unsupported
// WITHOUT prompting (the flow's capability gate). Emits the Credentials1.Result
// then Operation1.Finished with the mapped status/errorCode.
class ActivateSigningKeyOperation final : public OperationBase
{
public:
    struct Deps
    {
        CardSessionHolder* holder{nullptr};
        CredentialManager& credentials; // the PIN-lifecycle plugin seam
        PrompterClientBase& prompter;
        PromptSerializer& serializer;
        CredentialCache& credCache;             // CAN/MRZ secret cache (read provider)
        CredentialSnapshotCache& snapshotCache; // read (record resolve) + invalidate-on-card
        CardReadCache& readCache;               // invalidated alongside the snapshot cache
        std::string cardKey;
        std::string readerName;
        std::string requester;
        std::string artifact;
    };

    ActivateSigningKeyOperation(std::unique_ptr<OperationChannel> channel, Deps deps,
                                std::shared_ptr<OperationState> state);

protected:
    void doWork() override;

private:
    Deps m_deps;
};

} // namespace LibreSCRS::Agent::Operations
