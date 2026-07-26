// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <LibreSCRS/Agent/value/CertSnapshot.h>
#include <LibreSCRS/Agent/cache/CardReadCache.h>
#include <LibreSCRS/Agent/cache/CredentialCache.h>
#include <LibreSCRS/Agent/operations/CertReadFlow.h>
#include <LibreSCRS/Agent/operations/OperationBase.h>
#include <LibreSCRS/Agent/operations/Seams.h>
#include <memory>
#include <string>
#include <vector>

namespace LibreSCRS::Agent::Operations {

class CardSessionHolder;

class ReadCertificatesOperation final : public OperationBase
{
public:
    struct Deps
    {
        // Per-reader shared-session holder, injected by OperationManager from the
        // worker that serialises this reader's ops (single-threaded; no locking).
        CardSessionHolder* holder{nullptr};
        CertificateReader& certReader;
        TrustVerifier& trustVerifier;
        PrompterClientBase& prompter;
        PromptSerializer& serializer;
        CredentialCache& credentials;
        // Per-insertion cache: a hot entry serves the certs from RAM.
        CardReadCache& readCache;
        std::string cardKey;
        // Human reader name, used by the OperationManager to lazily build this
        // reader's CardSessionHolder and threaded into the flow's per-request
        // audit line.
        std::string readerName;
        // Caller-identity chrome for the consent prompt (only reached if the card
        // demands a CAN to read its CDF). Resolved at the Card1 method entry.
        std::string requester;
        std::string artifact;
    };

    ReadCertificatesOperation(std::unique_ptr<OperationChannel> channel, Deps deps,
                              std::shared_ptr<OperationState> state);

protected:
    void doWork() override;

private:
    Deps m_deps;
};

} // namespace LibreSCRS::Agent::Operations
