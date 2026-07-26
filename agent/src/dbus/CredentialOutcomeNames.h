// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <LibreSCRS/Agent/value/CredentialRecord.h> // CredentialOutcome

namespace LibreSCRS::Agent {

// The single agent-side table mapping a neutral-core CredentialOutcome to the
// camelCase wire token carried in the Operation.Credentials1.Result payload's
// "outcome" key. The strings ARE the wire contract (== the vocabulary documented
// in org.librescrs.Agent.Credentials1.xml); CredentialOutcomeNamesTest pins every
// value so an enum edit cannot silently drop or rename a token. Sibling of
// dbus/Pkcs11OutcomeNames — the outcome crosses the wire as this STRING, never as
// an integer.
[[nodiscard]] const char* credentialOutcomeToken(CredentialOutcome outcome) noexcept;

} // namespace LibreSCRS::Agent
