// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <LibreSCRS/Agent/cache/CredentialCache.h>
#include <LibreSCRS/Agent/operations/OperationBase.h>
#include <LibreSCRS/Agent/operations/Seams.h>
#include <LibreSCRS/Agent/operations/SignFlow.h>
#include <memory>
#include <string>

namespace LibreSCRS::Agent::Operations {

class CardSessionHolder;

class SignOperation final : public OperationBase
{
public:
    struct Deps
    {
        // Per-reader shared-session holder, injected by OperationManager from the
        // worker that serialises this reader's ops (single-threaded; no locking).
        CardSessionHolder* holder{nullptr};
        Signer& signer;
        PrompterClientBase& prompter;
        PromptSerializer& serializer;
        CredentialCache& credentials;
        std::string cardKey;
        // Human reader name, used by the OperationManager to lazily build this
        // reader's CardSessionHolder. Not consumed by the flow.
        std::string readerName;
        std::string requester;
        // Fully-resolved signing parameters (format/level/packaging concrete,
        // document bytes read off the input fd) — assembled at the Card1.Sign
        // method entry.
        SignParams params;
    };

    SignOperation(std::unique_ptr<OperationChannel> channel, Deps deps, std::shared_ptr<OperationState> state);

protected:
    void doWork() override;

private:
    Deps m_deps;
};

} // namespace LibreSCRS::Agent::Operations
