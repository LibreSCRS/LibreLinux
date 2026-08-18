// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <LibreSCRS/Plugin/CardPlugin.h>
#include <memory>
#include <span>
#include <string>

namespace LibreSCRS::Agent {

/// @brief Pick the Card1.CardType string for a held-session candidate list.
///
/// A card routinely matches more than one driver: the family driver plus one or
/// both generic PKI drivers, or -- on a card no family driver claims -- the two
/// generic drivers alone. Requiring a single-entry list therefore left a large
/// class of perfectly identified cards untyped over the bus.
///
/// The rule is the registry's own precedence, applied to the candidates that
/// survived the probe: the driver with the strictly smallest probe priority
/// wins (CardPlugin::probePriority documents "lower numbers win"). Two drivers
/// tied at that smallest value are genuinely indistinguishable from the
/// candidate list alone, so the type stays empty and a later authoritative read
/// resolves it through the property-update path.
///
/// Reads the priority value rather than trusting list order: the registry sorts
/// ATR matches and AID probes in two independent runs, so a lower-priority AID
/// match can legitimately sit behind a higher-priority ATR match.
///
/// @param candidates The held session's candidate list; null entries are
///        skipped, never dereferenced.
/// @return The winner's pluginId(), or an empty string for "not known" -- no
///         candidates, or a tie at the smallest priority.
[[nodiscard]] inline std::string
arbitrateCardType(std::span<const std::shared_ptr<const LibreSCRS::Plugin::CardPlugin>> candidates)
{
    const LibreSCRS::Plugin::CardPlugin* winner = nullptr;
    bool tied = false;
    for (const auto& candidate : candidates) {
        if (!candidate) {
            continue;
        }
        if (winner == nullptr || candidate->probePriority() < winner->probePriority()) {
            winner = candidate.get();
            tied = false;
        } else if (candidate->probePriority() == winner->probePriority()) {
            tied = true;
        }
    }
    if (winner == nullptr || tied) {
        return {};
    }
    return winner->pluginId();
}

} // namespace LibreSCRS::Agent
