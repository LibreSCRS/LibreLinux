// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// The single definition of the agent's own bus name, manager path, and
// object-interface NAMES — the wire-routing half of the agent contract (the
// error-NAME half lives next door in AgentErrorNames.h).
//
// These were hand-spelled per translation unit on BOTH sides of the bus: the
// agent producer (BusExporter.cpp / PresenceModel.cpp / AgentService.cpp /
// Operation1Adaptor.cpp) and the PKCS#11-module consumer (AgentClient.cpp and
// its tests/FakeAgent.h test double) each kept their own copy under different
// constant names, with no compile/link tie between them — so a typo in any copy
// was a silent routing failure with no compile error. One constexpr table here
// keeps every exporter, model, proxy, and fake agreeing on the wire names. (The
// XML in agent/dbus/*.xml remains the cross-stack contract these mirror; the
// generated *_adaptor.h headers also expose an INTERFACE_NAME each, for the
// hand-written exporters/models that don't include a specific adaptor.)
//
// External-service names (PolicyKit1, freedesktop.DBus interfaces) that are NOT
// the agent's own contract stay with their callers — the one exception is the
// standard org.freedesktop.DBus.ObjectManager interface the module addresses on
// the agent's manager object, kept here because it is part of how the module
// routes to the agent.
//
// Header-only, dependency-free — both the agent core and the LM-free / Qt-free
// PKCS#11 module include it via the librelinux-common interface target.

#pragma once

namespace LibreLinux::AgentWire {

inline constexpr const char* kServiceName = "org.librescrs.Agent";
inline constexpr const char* kRootPath = "/org/librescrs/Agent";
inline constexpr const char* kReaderIface = "org.librescrs.Agent.Reader1";
inline constexpr const char* kCardIface = "org.librescrs.Agent.Card1";
inline constexpr const char* kCredentialsIface = "org.librescrs.Agent.Credentials1";
inline constexpr const char* kOperation1Iface = "org.librescrs.Agent.Operation1";
inline constexpr const char* kCertificatesIface = "org.librescrs.Agent.Operation.Certificates1";
inline constexpr const char* kOpCredentialsIface = "org.librescrs.Agent.Operation.Credentials1";
inline constexpr const char* kPkcs11Iface = "org.librescrs.Agent.Pkcs11_1";
inline constexpr const char* kObjectManagerIface = "org.freedesktop.DBus.ObjectManager";

} // namespace LibreLinux::AgentWire
