// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// What a test of the bus surface needs to stand up the agent core a card object
// and the frontend launch their operations through: a core over the test's own
// authorizer, prompter and resolver, and seams that fail every call
// for the ones a test does not drive.
#pragma once

#include <LibreSCRS/Agent/AgentCore.h>
#include <LibreSCRS/Agent/operations/OperationLauncher.h>
#include <LibreSCRS/Agent/operations/Seams.h>
#include <LibreSCRS/Agent/presence/CapabilityResolver.h>

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace LibreSCRS::Agent::Testing {

// Resolves no candidate plugin for any card.
class NoCandidates final : public CapabilityResolver
{};

// Seams that fail every call.
class UnusedReader final : public Operations::CardReader
{
public:
    Operations::ReadOutcome read(LibreSCRS::SmartCard::CardSession&, const Operations::CandidateList&,
                                 LibreSCRS::CancelToken, Operations::GroupReadCallback = {}) override
    {
        return Operations::ReadOutcome{Operations::ReadOutcome::Status::CommunicationError, std::nullopt, "unused"};
    }
    GroupSnapshot readTokenInfo(LibreSCRS::SmartCard::CardSession&, const Operations::CandidateList&,
                                LibreSCRS::CancelToken) override
    {
        return {};
    }
};

class UnusedCertReader final : public Operations::CertificateReader
{
public:
    Operations::CertReadOutcome read(LibreSCRS::SmartCard::CardSession&, const Operations::CandidateList&,
                                     LibreSCRS::CancelToken) override
    {
        return {};
    }
};

class UnusedTrustVerifier final : public Operations::TrustVerifier
{
public:
    Operations::TrustVerdict verify(std::span<const std::uint8_t>, std::span<const std::vector<std::uint8_t>>) override
    {
        return {};
    }
};

class UnusedSigner final : public Operations::Signer
{
public:
    Operations::SignOutcome sign(const std::shared_ptr<LibreSCRS::SmartCard::CardSession>&,
                                 const Operations::SignParams&, const Operations::CandidateList&,
                                 LibreSCRS::Auth::CredentialProvider, LibreSCRS::CancelToken) override
    {
        return {};
    }
};

class UnusedCredentialManager final : public Operations::CredentialManager
{
public:
    Operations::CredentialListing list(LibreSCRS::SmartCard::CardSession&, const Operations::CandidateList&) override
    {
        return {};
    }
    LibreSCRS::Plugin::PINResult changePIN(LibreSCRS::SmartCard::CardSession&, const Operations::CandidateList&,
                                           std::string_view, const LibreSCRS::Secure::String&,
                                           const LibreSCRS::Secure::String&) override
    {
        return {};
    }
    LibreSCRS::Plugin::PINResult activateTransportPin(LibreSCRS::SmartCard::CardSession&,
                                                      const Operations::CandidateList&, std::string_view,
                                                      const LibreSCRS::Secure::String&,
                                                      const LibreSCRS::Secure::String&) override
    {
        return {};
    }
    LibreSCRS::Plugin::PINResult activateSigningKey(LibreSCRS::SmartCard::CardSession&,
                                                    const Operations::CandidateList&,
                                                    const LibreSCRS::Secure::String&) override
    {
        return {};
    }
};

// Every seam a launcher requires, each failing its call; a test replaces the
// ones it drives.
[[nodiscard]] inline Operations::OperationSeams unusedSeams()
{
    return Operations::OperationSeams{
        .reader = std::make_shared<UnusedReader>(),
        .certReader = std::make_shared<UnusedCertReader>(),
        .trustVerifier = std::make_shared<UnusedTrustVerifier>(),
        .signer = std::make_shared<UnusedSigner>(),
        .credentials = std::make_shared<UnusedCredentialManager>(),
        .depositor = {},
    };
}

// Where a test core named @p tag keeps its configuration and caches.
[[nodiscard]] inline std::filesystem::path testCoreDir(std::string_view tag)
{
    return std::filesystem::temp_directory_path() / ("ll-core-" + std::string{tag});
}

// The reader and card-key lookups of a core with no presence behind it: only
// the PKCS#11 broker asks them, and the answer is "none".
[[nodiscard]] inline ResolveReaderCard noReaderCard()
{
    return [](const std::string&) -> std::optional<ReaderCard> { return std::nullopt; };
}
[[nodiscard]] inline Pkcs11Broker::ResolveCardKeySeam noCardKey()
{
    return [](const std::string&) -> std::optional<ObjectId> { return std::nullopt; };
}

// A real agent core whose configuration and caches live in testCoreDir(@p tag).
// Its operation scheduler runs in production mode, as the launcher requires.
[[nodiscard]] inline AgentCore makeTestCore(std::string_view tag, CapabilityResolver& resolver, Authorizer& authorizer,
                                            std::shared_ptr<Operations::PrompterClientBase> prompter)
{
    const auto dir = testCoreDir(tag);
    return AgentCore{resolver,      authorizer,     std::move(prompter), dir / "agent.conf",
                     dir / "cache", noReaderCard(), noCardKey()};
}

} // namespace LibreSCRS::Agent::Testing
