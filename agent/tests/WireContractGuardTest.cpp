// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Cross-stack wire-contract drift guard — AGENT (LM-anchored) half.
//
// The agent's Card1.Capabilities + Operation1 ErrorCode are mirrored by hand
// across stacks (the agent forwards LM CardCapabilities onto the wire verbatim;
// LibreKDE AgentCapabilities.h re-types the bits and ErrorText.h re-types
// ErrorCode), and each mirror pins itself to hard-coded literals in its OWN
// stack but not to the upstream symbol — so an LM renumber (or an agent
// ErrorCode append) would go silently stale on the client.
//
// This fixture is the ONE place that ties the canonical wire literals to the
// upstream LibreMiddleware symbol. The agent test target already links
// LibreMiddleware::Plugin (via LibreLinuxAgentCore), so a static_assert here
// breaks the build the instant LM CardCapabilities renumbers — the half
// of the mirror no client-side test can catch (a client stack cannot link LM).
//
// The matching LM-free LibreKDE/tests/agentclient/WireContractGuardTest.cpp pins
// the KDE mirror to the SAME literals; the two together chain
// LM  <->  wire literals  <->  KDE   without the KDE stack ever linking LM.
//
// === Mirror manifest — keep these in lockstep ===
//   capability bits : LibreMiddleware Plugin/PluginTypes.h CardCapabilities (SOURCE)
//                     <-> LibreKDE shared/agentclient/AgentCapabilities.h Cap::*
//   ErrorCode       : canonical wire contract = dbus/org.librescrs.Agent.Operation1.xml
//                     (new codes land there first; Operation1ErrorCodeXmlGuardTest pins the
//                     LibreAgent include/LibreSCRS/Agent/value/ErrorTaxonomy.h enum to it)
//                     <-> LibreKDE shared/agentclient/ErrorText.h ErrorCode
//   cert Result sig : agent Certificates1XmlCodegenTest + module
//                     CertResultWireSignatureTest + KDE AgentResultSignatureTest
//                     all pin a(sba{sa{s(ssv)}}uasasu)

#include <LibreSCRS/Agent/value/ErrorTaxonomy.h>

#include <LibreSCRS/Plugin/PluginTypes.h>

#include <gtest/gtest.h>

#include <cstdint>

namespace {

using LibreSCRS::Agent::ErrorCode;
using LibreSCRS::Plugin::CardCapabilities;

constexpr std::uint32_t u(CardCapabilities c)
{
    return static_cast<std::uint32_t>(c);
}
constexpr std::uint32_t u(ErrorCode e)
{
    return static_cast<std::uint32_t>(e);
}

// --- LM CardCapabilities <-> canonical wire bits (THE anchor) ---------------
static_assert(u(CardCapabilities::None) == 0u, "wire contract: CardCapabilities::None drifted from 0");
static_assert(u(CardCapabilities::PKI) == (1u << 0), "wire contract: PKI bit drifted; KDE Cap::Pki mirror now stale");
static_assert(u(CardCapabilities::IdentityData) == (1u << 1),
              "wire contract: IdentityData bit drifted; KDE Cap::IdentityData mirror now stale");
static_assert(u(CardCapabilities::EmrtdCrypto) == (1u << 2),
              "wire contract: EmrtdCrypto bit drifted; KDE Cap::EmrtdCrypto mirror now stale");
static_assert(u(CardCapabilities::PinManagement) == (1u << 3),
              "wire contract: PinManagement bit drifted; KDE Cap::PinManagement mirror now stale");

// --- agent ErrorCode: renumber anchor ----------------------------------------
// ErrorCode is append-only on the wire. Pinning first + last value + count
// catches a RENUMBER of the existing range. An APPEND leaves these asserts
// green — that edge is machine-gated by Operation1ErrorCodeXmlGuardTest, whose
// -Werror=switch build fails on the new enumerator and whose runtime half then
// demands the matching Operation1.xml enumeration entry (the canonical wire
// contract clients mirror). Bump the pins here when the taxonomy grows.
static_assert(u(ErrorCode::None) == 0u, "wire contract: ErrorCode::None drifted from 0");
static_assert(u(ErrorCode::InvalidDocument) == 19u, "wire contract: ErrorCode::InvalidDocument drifted");
static_assert(u(ErrorCode::EntryExpired) == 20u,
              "wire contract: ErrorCode::EntryExpired (last) drifted; mirror in KDE");
static_assert(u(ErrorCode::EntryExpired) + 1u == 21u,
              "wire contract: ErrorCode count changed; append the new value to LibreKDE ErrorText.h + bump this guard");

} // namespace

// A compiled TU is required to evaluate the static_asserts; the runtime body is
// a formality (matches Certificates1XmlCodegenTest).
TEST(WireContractGuard, AgentAnchorsHold)
{
    SUCCEED();
}
