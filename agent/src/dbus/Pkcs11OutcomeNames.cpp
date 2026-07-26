// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#include "dbus/Pkcs11OutcomeNames.h"
#include "AgentErrorNames.h" // shared wire error-name table

namespace LibreSCRS::Agent {

const char* errorNameFor(Pkcs11Broker::CryptoOutcome outcome) noexcept
{
    using CO = Pkcs11Broker::CryptoOutcome;
    switch (outcome) {
    case CO::Cancelled:
        return LibreLinux::AgentWire::kErrCancelled;
    case CO::KeyNotFound:
        return LibreLinux::AgentWire::kErrKeyNotFound;
    case CO::AuthFailed:
        return LibreLinux::AgentWire::kErrAuthFailed;
    case CO::NotSupported:
        return LibreLinux::AgentWire::kErrNotSupported;
    case CO::CardError:
        return LibreLinux::AgentWire::kErrCommunication;
    case CO::UnknownCard:
        return LibreLinux::AgentWire::kErrUnknownCard;
    case CO::UserNotLoggedIn:
        return LibreLinux::AgentWire::kErrUserNotLoggedIn;
    case CO::RateLimited:
        return LibreLinux::AgentWire::kErrRateLimited;
    case CO::Ok:
        break; // Ok is not an error; fail closed to the device (communication) error.
    }
    return LibreLinux::AgentWire::kErrCommunication;
}

const char* errorNameFor(Pkcs11Broker::LoginOutcome outcome) noexcept
{
    using LO = Pkcs11Broker::LoginOutcome;
    switch (outcome) {
    case LO::Cancelled:
        return LibreLinux::AgentWire::kErrCancelled;
    case LO::NotAuthorizedByCard:
        return LibreLinux::AgentWire::kErrAuthFailed;
    case LO::CardError:
        return LibreLinux::AgentWire::kErrCommunication;
    case LO::UnknownCard:
        return LibreLinux::AgentWire::kErrUnknownCard;
    case LO::NotAuthorized:
        return LibreLinux::AgentWire::kErrNotAuthorized;
    case LO::Ok:
        break; // Ok is not an error; fail closed to the device (communication) error.
    }
    return LibreLinux::AgentWire::kErrCommunication;
}

} // namespace LibreSCRS::Agent
