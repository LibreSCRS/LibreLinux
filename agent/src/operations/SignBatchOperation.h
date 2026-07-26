// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <LibreSCRS/Agent/cache/CredentialCache.h>
#include <LibreSCRS/Agent/operations/BatchSignFlow.h>
#include <LibreSCRS/Agent/operations/OperationBase.h>
#include <LibreSCRS/Agent/operations/Seams.h>
#include <memory>
#include <string>
#include <vector>

namespace LibreSCRS::Agent::Operations {

class CardSessionHolder;

class SignBatchOperation final : public OperationBase
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
        // Batch-wide signing parameters (certId/format/level/packaging/...),
        // resolved ONCE at the Card1.SignBatch method entry exactly like a
        // single Sign's own params — `inputDocument`/`displayName` are
        // ignored here (each entry of `documents` below supplies its own),
        // mirroring BatchSignFlowDeps::params.
        SignParams params;
        std::vector<BatchDocumentInput> documents;
    };

    SignBatchOperation(std::unique_ptr<OperationChannel> channel, Deps deps, std::shared_ptr<OperationState> state);

protected:
    void doWork() override;

private:
    Deps m_deps;
    // Owns the ONE PIN collected via consent for THIS operation's batch
    // duration. A fresh instance is constructed with every SignBatchOperation
    // — one per Card1.SignBatch dispatch (see dbus/OperationAdaptorFactory's
    // buildSignBatchOperation) — so it is NEVER shared or reused across
    // batches; BatchSignFlow's own scope guard wipes it on every run() exit
    // (success, halt, cancel, invalid-request, or an unwinding exception).
    BatchPinHolder m_pinHolder;
};

} // namespace LibreSCRS::Agent::Operations
