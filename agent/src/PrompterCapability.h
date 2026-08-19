// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once

#include "PrompterWire.h"

#include <cstdint>
#include <optional>

namespace LibreSCRS::Agent {

/// Whether a prompter is one this agent can actually drive.
///
/// Measured on 2026-08-19: the prompter had been running since the previous
/// night and SURVIVED the agent restart. It is a long-lived user unit —
/// replacing the agent does not replace it — so a new agent routinely meets an
/// older helper. If that helper does not understand a dismissal by name, every
/// cancellation is silently lost and windows hang with nobody able to close
/// them: the very defect this work removes, returning through a mismatched pair.
///
/// The answer is refusal, not emulation. No compatibility shim, per the
/// project's zero-legacy rule — the agent raises no prompt it could not dismiss,
/// and the failure is loud rather than a window standing in silence.
///
/// Pure policy over a single read, so it is unit-testable without a bus.
namespace PrompterCapability {

/// The lowest contract this agent can work with. It equals what this tree's
/// prompter publishes: the agent needs the addressed dismissal, the prompt id,
/// the entry deadline and the expiry reply word, and they all arrived together.
inline constexpr std::uint32_t kRequiredVersion = LibreLinux::PrompterWire::kProtocolVersion;

/// @param reported the prompter's ProtocolVersion, or nullopt when the property
///        could not be read at all — which is what an older helper looks like,
///        since it publishes no such property.
///
/// A NEWER prompter is accepted: the agent uses only what it knows about, and
/// refusing forward would strand a session on the older half of an upgrade.
[[nodiscard]] constexpr bool usable(std::optional<std::uint32_t> reported) noexcept
{
    return reported.has_value() && *reported >= kRequiredVersion;
}

} // namespace PrompterCapability

} // namespace LibreSCRS::Agent
