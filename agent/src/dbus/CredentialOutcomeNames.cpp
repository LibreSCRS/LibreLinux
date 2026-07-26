// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#include "dbus/CredentialOutcomeNames.h"

namespace LibreSCRS::Agent {

const char* credentialOutcomeToken(CredentialOutcome outcome) noexcept
{
    using O = CredentialOutcome;
    // Exhaustive, NO default: a newly-appended CredentialOutcome member is a hard
    // -Werror=switch break here (the CI/WERROR build) until its wire token is
    // added, so the enum and the wire vocabulary cannot drift apart silently.
#pragma GCC diagnostic push
#pragma GCC diagnostic error "-Wswitch"
    switch (outcome) {
    case O::Unspecified:
        return "unspecified";
    case O::Ok:
        return "ok";
    case O::UserCancelled:
        return "userCancelled";
    case O::MissingFields:
        return "missingFields";
    case O::InvalidPin:
        return "invalidPin";
    case O::Blocked:
        return "blocked";
    case O::PluginError:
        return "pluginError";
    case O::Unsupported:
        return "unsupported";
    case O::KeyActivationFailed:
        return "keyActivationFailed";
    case O::CardRemoved:
        return "cardRemoved";
    }
#pragma GCC diagnostic pop
    // Unreachable for a valid enumerator; fail closed to the neutral token.
    return "unspecified";
}

} // namespace LibreSCRS::Agent
