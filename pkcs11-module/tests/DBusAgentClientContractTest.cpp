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

#include <functional>
#include <memory>
#include <string>

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

    // Pkcs11_1.Login answers an idleTimeoutSecs alongside the ack.
    static bool carriesLeaseDuration()
    {
        return true;
    }

    static std::unique_ptr<Harness> serving()
    {
        return make({});
    }

    static std::unique_ptr<Harness> refusingLogin(Refusal r)
    {
        const std::string name = errorNameFor(r);
        return make([name](F::FakeAgent& fake) { fake.setLoginError(name); });
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
        h->bus = std::make_unique<F::BusFixture>(/*hasCard=*/true, "None", script);
        h->impl = std::make_unique<P::DBusAgentClient>();
        return h;
    }
};

} // namespace

namespace LibreSCRS::Pkcs11Agent::Testing {

INSTANTIATE_TYPED_TEST_SUITE_P(Bus, AgentClientContract, ::BusContractTraits);

} // namespace LibreSCRS::Pkcs11Agent::Testing
