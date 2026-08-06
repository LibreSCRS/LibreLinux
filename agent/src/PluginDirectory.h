// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once

#include <LibreSCRS/Agent/backend/Logging.h>

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace LibreSCRS::Plugin {
class CardPluginService;
struct LoadOutcome;
} // namespace LibreSCRS::Plugin

namespace LibreSCRS::Agent {

// Where the daemon looks for card plugins, and what it says about it.
//
// Both candidate locations can come up empty on a machine that is otherwise
// healthy, so the outcome is a record of what was tried rather than a bare
// path: a directory that yields no plugins is indistinguishable, from the
// user's seat, from a card nothing supports, and recovering the compiled-in
// path from a silent daemon means reading it out of the binary.

// One candidate location, with the reason it was or was not taken.
struct PluginDirCandidate
{
    // The candidate locations, in the order they are probed. There is no
    // bundle-relative candidate here: the Linux daemon is installed to a
    // prefix, not shipped inside an application bundle.
    enum class Source : std::uint8_t {
        Environment,     // LIBRESCRS_PLUGIN_DIR
        CompiledDefault, // the compiled-in install prefix; the terminal fallback
    };

    // What became of this candidate.
    enum class Verdict : std::uint8_t {
        Chosen, // this is the directory the daemon will use
        Unset,  // the source produced no path at all
    };

    Source source{};
    // The path this source produced. Empty iff Verdict::Unset.
    std::filesystem::path path;
    Verdict verdict{};
};

// What the chosen directory turned out to be on disk.
//
// Three states, not two: "empty", "not there" and "there but unreadable" are
// three different faults with three different fixes, and a daemon that folds
// the third into the second sends the reader off to create a directory that
// already exists. `fs::is_directory` answers false for all three, so the error
// code has to be consulted rather than discarded.
enum class PluginDirState : std::uint8_t {
    Present,    // a directory, and we could look at it
    Absent,     // nothing there — or something there that is not a directory
    Unreadable, // it could not be examined at all; `dirError` says why
};

// The chosen plugin directory together with the full probe trail.
//
// The last entry of `candidates` is always the chosen one and its path is
// always `dir` — the fallback is terminal, so resolution cannot come up empty
// even when nothing exists on disk.
struct PluginDirResolution
{
    std::filesystem::path dir;
    PluginDirState dirState{};
    // The filesystem error that stopped the check. Non-empty iff
    // PluginDirState::Unreadable — it is the actionable half of that state.
    std::string dirError;
    std::vector<PluginDirCandidate> candidates;
};

// The two inputs to the cascade, injected so it can be exercised without a
// mutated environment or the daemon's own install prefix.
struct PluginDirInputs
{
    // LIBRESCRS_PLUGIN_DIR; empty when unset.
    std::string environment;
    // The compiled-in install prefix (LIBRESCRS_DEFAULT_PLUGIN_DIR, defined on
    // the daemon target rather than on this library).
    std::filesystem::path compiledDefault;
};

// Run the cascade: environment override, else the compiled-in default.
[[nodiscard]] PluginDirResolution resolvePluginDir(const PluginDirInputs& inputs);

// The lines describing a resolution and its load outcome, in order, each
// carrying the severity it should be emitted at.
//
// Split out from reportPluginLoad so the wording and — above all — the severity
// of the zero-plugin case are testable without a loadable plugin binary on disk.
//
// `loaded` is the number of plugins the registry actually loaded; `report` is
// its per-file load report.
[[nodiscard]] std::vector<std::pair<log::Level, std::string>>
pluginLoadReportLines(const PluginDirResolution& resolution, std::size_t loaded,
                      std::span<const LibreSCRS::Plugin::LoadOutcome> report);

// Emit pluginLoadReportLines for `service` over the log facade.
void reportPluginLoad(const PluginDirResolution& resolution, const LibreSCRS::Plugin::CardPluginService& service);

} // namespace LibreSCRS::Agent
