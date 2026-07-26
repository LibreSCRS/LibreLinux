// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// The single definition of the agent's Pkcs11_1 wire error-NAME vocabulary. The
// agent (Pkcs11Object.cpp) raises these sdbus errors and the PKCS#11 module
// (AgentClient.cpp::mapErrorName) maps them back to a Status — and each side
// used to hand-spell the same nine "org.librescrs.Agent.Error.*" strings, with
// no compile/link tie between producer and consumer, so a typo on either side
// silently degraded to the generic error. Sharing one constexpr table closes
// that gap. The strings ARE the wire contract; this table is the canonical set
// the agent raises and the module maps — a SUPERSET of the abbreviated list in
// the org.librescrs.Agent.Pkcs11_1.xml doc block (NotSupported / Cancelled are
// raised/mapped but not all enumerated there).
//
// Header-only, dependency-free — both the agent core and the LM-free / Qt-free
// PKCS#11 module include it via the librelinux-common interface target.

#pragma once

namespace LibreLinux::AgentWire {

inline constexpr const char* kErrUnknownCard = "org.librescrs.Agent.Error.UnknownCard";
inline constexpr const char* kErrKeyNotFound = "org.librescrs.Agent.Error.KeyNotFound";
inline constexpr const char* kErrNotAuthorized = "org.librescrs.Agent.Error.NotAuthorized";
inline constexpr const char* kErrRateLimited = "org.librescrs.Agent.Error.RateLimited";
inline constexpr const char* kErrUserNotLoggedIn = "org.librescrs.Agent.Error.UserNotLoggedIn";
inline constexpr const char* kErrAuthFailed = "org.librescrs.Agent.Error.AuthFailed";
inline constexpr const char* kErrNotSupported = "org.librescrs.Agent.Error.NotSupported";
inline constexpr const char* kErrCommunication = "org.librescrs.Agent.Error.CommunicationError";
inline constexpr const char* kErrCancelled = "org.librescrs.Agent.Error.Cancelled";

// Capability-precondition gate raised at method entry when a card does not
// advertise the capability a method needs (Card1.ReadIdentity/GetPhoto/
// ReadCertificates/Sign, Credentials1.ManagePin/ActivateSigningKey/
// ListCredentials). Hoisted here from CardObject.cpp so the Plan-C / macOS
// mirrors share one spelling with the producer.
inline constexpr const char* kErrUnsupportedOnThisCard = "org.librescrs.Agent.Error.UnsupportedOnThisCard";
// Credentials1.ManagePin entry rejections that are the client's fault: an unknown
// verb, an undefined options key, or an illegal verb/option combination.
inline constexpr const char* kErrInvalidRequest = "org.librescrs.Agent.Error.InvalidRequest";
// Credentials1.ManagePin addressed a pinId that resolves to no record in the
// latest ListCredentials snapshot — including the never-listed (no-snapshot) case.
inline constexpr const char* kErrUnknownCredential = "org.librescrs.Agent.Error.UnknownCredential";

} // namespace LibreLinux::AgentWire
