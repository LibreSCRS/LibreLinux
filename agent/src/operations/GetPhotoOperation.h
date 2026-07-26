// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <LibreSCRS/Agent/cache/CardReadCache.h>
#include <LibreSCRS/Agent/cache/CredentialCache.h>
#include <LibreSCRS/Agent/operations/IdentityReadFlow.h>
#include <LibreSCRS/Agent/operations/OperationBase.h>
#include <LibreSCRS/Agent/operations/Seams.h>
#include <functional>
#include <memory>
#include <optional>
#include <string>

namespace LibreSCRS::Agent::Operations {

class CardSessionHolder;

class GetPhotoOperation final : public OperationBase
{
public:
    struct Deps
    {
        // Per-reader shared-session holder, injected by OperationManager from the
        // worker that serialises this reader's ops (single-threaded; no locking).
        CardSessionHolder* holder{nullptr};
        CardReader& reader;
        PrompterClientBase& prompter;
        // Agent-wide single-live-prompt gate (see IdentityReadFlowDeps).
        PromptSerializer& serializer;
        CredentialCache& credentials;
        CardReadCache& readCache;
        std::string cardKey;
        // Human reader name, used by the OperationManager to lazily build this
        // reader's CardSessionHolder. Not consumed by the flow.
        std::string readerName;
        // Caller-identity chrome for the consent prompt: the requesting
        // client's best-effort label and the artifact being read ("photo").
        // Resolved at the Card1 method entry; client-supplied, may be empty.
        std::string requester;
        std::string artifact;
        // See ReadIdentityOperation::Deps::onCardType -- a GetPhoto cache miss
        // also runs IdentityReadFlow, so it is the OTHER entry point that may
        // resolve cardType for the first time.
        std::function<void(const std::string&)> onCardType;
    };

    GetPhotoOperation(std::unique_ptr<OperationChannel> channel, Deps deps, std::shared_ptr<OperationState> state);

protected:
    void doWork() override;

private:
    [[nodiscard]] std::optional<CardReadSnapshot> obtainSnapshot();
    Deps m_deps;
};

} // namespace LibreSCRS::Agent::Operations
