// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// The single definition of the agent's Certificates1.Result entry tuple as the
// module sees it on the wire. Previously hand-declared identically in both
// AgentClient.cpp (the production consumer) and tests/FakeAgent.h (the test
// double) — so the two drifted together and a shape change would have passed
// the module's own tests while diverging from the agent's XML. Sharing one
// definition (and pinning its D-Bus signature in CertResultWireSignatureTest)
// closes that gap. The frozen wire signature is a(sba{sa{s(ssv)}}uasasu); it
// must equal org.librescrs.Agent.Operation.Certificates1.xml.

#pragma once

#include <sdbus-c++/Types.h>

#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace LibreSCRS::Pkcs11Agent {

// a{sa{s(ssv)}}: groupKey -> fieldKey -> (labelKey, labelFallback, value).
using CertFieldGroups =
    std::map<std::string, std::map<std::string, sdbus::Struct<std::string, std::string, sdbus::Variant>>>;

// (s b a{sa{s(ssv)}} u as as u): certId, signingCapable, fields, keyUsageBits,
// ekuOids, chainSubjectCns, trustStatus. The Certificates1.Result is a vector
// of these → a(sba{sa{s(ssv)}}uasasu).
using CertResultEntry = sdbus::Struct<std::string,              // certId
                                      bool,                     // signingCapable
                                      CertFieldGroups,          // fields
                                      std::uint32_t,            // keyUsageBits
                                      std::vector<std::string>, // ekuOids
                                      std::vector<std::string>, // chainSubjectCns
                                      std::uint32_t>;           // trustStatus

} // namespace LibreSCRS::Pkcs11Agent
