// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <LibreSCRS/Auth/AuthRequirement.h>
#include <string_view>
namespace LibreSCRS::Agent {
// Single source of truth for the wire vocabulary of Card1.PreReadAuthMethod
// ('s'): the stable, domain-blind tokens a client matches on to decide whether
// a read will trigger a CAN/MRZ prompt. Kept in lock-step with the values
// documented in org.librescrs.Agent.Card1.xml.
[[nodiscard]] constexpr std::string_view authMethodName(LibreSCRS::Auth::PreReadAuthMethod method) noexcept
{
    switch (method) {
    case LibreSCRS::Auth::PreReadAuthMethod::None:
        return "None";
    case LibreSCRS::Auth::PreReadAuthMethod::Mrz:
        return "Mrz";
    case LibreSCRS::Auth::PreReadAuthMethod::Can:
        return "Can";
    }
    return "None";
}
} // namespace LibreSCRS::Agent
