// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <LibreSCRS/Agent/pkcs11/Pkcs11Broker.h>

namespace LibreSCRS::Agent {

// Backend mapping: a neutral broker Outcome -> the org.librescrs.Agent.Error.*
// wire error NAME the PKCS#11 module branches on. This lives in the D-Bus
// backend (not the broker) so Pkcs11Broker.{h,cpp} name no wire string: the
// broker delivers a hermetic CryptoOutcome/LoginOutcome and
// ManagerObject::deferReply binds it to an sdbus::Error through here. The
// strings ARE the wire contract (== common/AgentErrorNames.h, == the
// org.librescrs.Agent.Pkcs11_1.xml doc block); Pkcs11OutcomeNamesTest pins
// every value so an enum edit cannot silently drop a wire name.
[[nodiscard]] const char* errorNameFor(Pkcs11Broker::CryptoOutcome outcome) noexcept;
[[nodiscard]] const char* errorNameFor(Pkcs11Broker::LoginOutcome outcome) noexcept;

} // namespace LibreSCRS::Agent
