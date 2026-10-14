// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// The shared AgentClient contract, instantiated over the bus transport.
//
// The claims are not here. They come from the agent project's installed header
// (<LibreSCRS/Agent/pkcs11/testing/AgentClientContract.h>), which the socket
// transport instantiates in its own tree over its own client. This file
// supplies only the traits type: the bus double's script.
//
// Runs under dbus-run-session, like every other bus suite here. The double
// claims the agent's well-known name, which one connection at a time can own,
// so the contract takes care to hold at most one harness alive at a time.

#include "AgentErrorNames.h" // the shared bus error-name table the double raises from
#include "DBusAgentClient.h"
#include "FakeAgent.h"

#include <LibreSCRS/Agent/pkcs11/testing/AgentClientContract.h>

#include <gtest/gtest.h>

#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace {

namespace P = LibreSCRS::Pkcs11Agent;
namespace W = LibreLinux::AgentWire;
namespace F = librescrs_pkcs11_testfake;
using P::Testing::Refusal;

/// The bus's own spelling for a contract refusal.
///
/// The DOUBLE's script, not the client's table. Both sides reach the same
/// shared constant here (that table is single-sourced on purpose, and pinned
/// against the wire enum by the agent-side parity suite), so what this drives
/// is the half that can still drift: the name-to-Status mapping the module
/// applies when the refusal comes back. A switch rather than a lookup, so a
/// Refusal appended to the contract is a build failure here.
const char* errorNameFor(Refusal r) noexcept
{
    switch (r) {
    case Refusal::UserNotLoggedIn:
        return W::kErrUserNotLoggedIn;
    case Refusal::NotAuthorized:
        return W::kErrNotAuthorized;
    case Refusal::AuthFailed:
        return W::kErrAuthFailed;
    case Refusal::Cancelled:
        return W::kErrCancelled;
    case Refusal::KeyNotFound:
        return W::kErrKeyNotFound;
    case Refusal::UnknownCard:
        return W::kErrUnknownCard;
    case Refusal::NotSupported:
        return W::kErrNotSupported;
    case Refusal::RateLimited:
        return W::kErrRateLimited;
    case Refusal::Communication:
        return W::kErrCommunication;
    case Refusal::InvalidRequest:
        return W::kErrInvalidRequest;
    }
    return W::kErrCommunication;
}

struct BusContractHarness
{
    std::unique_ptr<F::BusFixture> bus; // absent for the unreachable case
    std::unique_ptr<P::DBusAgentClient> impl;

    P::AgentClient& client()
    {
        return *impl;
    }
};

struct BusContractTraits
{
    using Harness = BusContractHarness;

    static std::string reader()
    {
        return F::kReader0;
    }
    static std::string certId()
    {
        return F::kCertId;
    }
    // The double's Reader1.Name.
    static std::string readerName()
    {
        return "FakeReader";
    }
    // The subject CN every harness below serves.
    static std::string holderName()
    {
        return "Fake Holder";
    }
    // The tail of the double's card path, kCard0.
    static std::string tokenSerial()
    {
        return "0";
    }

    // Pkcs11_1.Login answers an idleTimeoutSecs alongside the ack.
    static bool carriesLeaseDuration()
    {
        return true;
    }

    static std::unique_ptr<Harness> serving()
    {
        return make({});
    }

    static std::unique_ptr<Harness> servingCardWithoutCertificate()
    {
        return make([](F::FakeAgent& fake) { fake.serveNoCertificate(); });
    }

    // An empty CN serves the certificate with no subject fields at all.
    static std::unique_ptr<Harness> servingCertWithoutCommonName()
    {
        return make([](F::FakeAgent& fake) { fake.setSubjectCn(""); });
    }

    // The double marks its one certificate's key with the card's
    // per-operation consent rule.
    static std::unique_ptr<Harness> servingAlwaysAuthenticateCert()
    {
        return make([](F::FakeAgent& fake) { fake.setAlwaysAuthenticate(true); });
    }

    static std::unique_ptr<Harness> refusingLogin(Refusal r)
    {
        const std::string name = errorNameFor(r);
        return make([name](F::FakeAgent& fake) { fake.setLoginError(name); });
    }

    static std::unique_ptr<Harness> refusingSign(Refusal r)
    {
        const std::string name = errorNameFor(r);
        return make([name](F::FakeAgent& fake) { fake.setSignError(name); });
    }

    static std::unique_ptr<Harness> refusingDecrypt(Refusal r)
    {
        const std::string name = errorNameFor(r);
        return make([name](F::FakeAgent& fake) { fake.setDecryptError(name); });
    }

    // The card's own ID for its EC key, as the agent reads it off the card.
    static std::vector<std::uint8_t> ecKeyId()
    {
        return {0xF7, 0x13, 0x4B, 0x02, 0x7C, 0xD6, 0x45, 0x57, 0x86, 0x0A, 0xF5, 0x4E, 0xB9, 0xCD, 0x1D, 0x41};
    }
    // What the double's Derive answers.
    static std::vector<std::uint8_t> cannedSecret()
    {
        return std::vector<std::uint8_t>(48, 0x5A);
    }

    // The double's one certificate carries an EC P-384 key the agent derives with.
    static std::unique_ptr<Harness> servingEcCert()
    {
        return make([](F::FakeAgent& fake) { fake.setKeyFacts(ecKeyId(), "EC", 384, /*canDerive=*/true); });
    }

    // The same key for key agreement only: the certificate does not sign.
    static std::unique_ptr<Harness> servingDeriveOnlyEcCert()
    {
        return make([](F::FakeAgent& fake) {
            fake.serveKeyAgreementOnly();
            fake.setKeyFacts(ecKeyId(), "EC", 384, /*canDerive=*/true);
        });
    }

    static std::unique_ptr<Harness> refusingDerive(Refusal r)
    {
        const std::string name = errorNameFor(r);
        return make([name](F::FakeAgent& fake) {
            fake.setKeyFacts(ecKeyId(), "EC", 384, /*canDerive=*/true);
            fake.setDeriveError(name);
        });
    }

    static std::unique_ptr<Harness> unreachable()
    {
        // The session bus is there; nobody owns the agent's name on it. That is
        // what a stopped agent looks like from a client's side, and it is why
        // connected() cannot be the discriminator on this transport: a proxy
        // against an unowned name constructs fine.
        auto h = std::make_unique<Harness>();
        h->impl = std::make_unique<P::DBusAgentClient>();
        return h;
    }

private:
    static std::unique_ptr<Harness> make(const std::function<void(F::FakeAgent&)>& script)
    {
        auto h = std::make_unique<Harness>();
        h->bus = std::make_unique<F::BusFixture>(/*hasCard=*/true, "None", [script](F::FakeAgent& fake) {
            fake.setSubjectCn(holderName());
            if (script)
                script(fake);
        });
        h->impl = std::make_unique<P::DBusAgentClient>();
        return h;
    }
};

// The contract proves which mechanisms go out as a signature; this is the bus
// side of it: the token the agent reads for an ECDSA request is "ecdsa", as
// Pkcs11_1.SignRaw's mech argument spells it. The double records what arrived.
TEST(DBusAgentClientWire, AnEcdsaSignArrivesWithItsMechanismToken)
{
    auto harness = BusContractTraits::servingEcCert();
    const std::vector<std::uint8_t> digest(32, 0x5A);
    const auto r = harness->client().signRaw(BusContractTraits::reader(), BusContractTraits::certId(),
                                             LibreSCRS::Agent::Mechanism::EcdsaSign, digest);
    ASSERT_EQ(r.status, P::Status::Ok);
    EXPECT_EQ(harness->bus->fake->lastSignMechanism(), "ecdsa");
    EXPECT_EQ(harness->bus->fake->lastSignInput(), digest);
}

} // namespace

namespace LibreSCRS::Pkcs11Agent::Testing {

INSTANTIATE_TYPED_TEST_SUITE_P(Bus, AgentClientContract, ::BusContractTraits);

} // namespace LibreSCRS::Pkcs11Agent::Testing
