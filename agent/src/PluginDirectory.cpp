// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#include "PluginDirectory.h"

#include <LibreSCRS/Plugin/CardPluginService.h>

#include <format>
#include <system_error>

namespace LibreSCRS::Agent {
namespace {

namespace fs = std::filesystem;

using LoadOutcome = LibreSCRS::Plugin::LoadOutcome;
using Source = PluginDirCandidate::Source;
using Verdict = PluginDirCandidate::Verdict;

// Every line carries this prefix so the whole plugin story can be pulled out of
// the journal with one filter. Same tag the macOS daemon uses.
constexpr std::string_view kTag = "card plugins";

std::string_view sourceName(Source source)
{
    switch (source) {
    case Source::Environment:
        return "LIBRESCRS_PLUGIN_DIR";
    case Source::CompiledDefault:
        return "the compiled-in default";
    }
    return "an unknown source";
}

std::string_view statusName(LoadOutcome::Status status)
{
    switch (status) {
    case LoadOutcome::Status::Loaded:
        return "loaded";
    case LoadOutcome::Status::DlopenFailed:
        return "dlopen failed";
    case LoadOutcome::Status::MissingFactory:
        return "no plugin entry points";
    case LoadOutcome::Status::AbiMismatch:
        return "plugin ABI mismatch";
    case LoadOutcome::Status::FactoryThrew:
        return "the plugin factory failed";
    }
    return "unknown failure";
}

// Why a candidate that was probed did not supply the directory. Only the losing
// candidates reach this — the chosen one is announced by the caller.
std::string rejectionLine(const PluginDirCandidate& candidate)
{
    switch (candidate.source) {
    case Source::Environment:
        return std::format("{}: LIBRESCRS_PLUGIN_DIR is not set", kTag);
    case Source::CompiledDefault:
        break; // terminal fallback: it is always the chosen one, never rejected
    }
    return std::format("{}: {} did not supply a directory", kTag, sourceName(candidate.source));
}

// Zero plugins loaded, said three ways. This is the state that costs an hour of
// misdiagnosis — every card then reports as unusable, which is exactly what an
// unsupported card looks like — so it names the directory AND what is wrong with
// it, because "fill it", "create it" and "fix its permissions" are three
// different instructions.
std::string emptyDirLine(const PluginDirResolution& resolution)
{
    const std::string dir = resolution.dir.string();
    switch (resolution.dirState) {
    case PluginDirState::Absent:
        return std::format("{}: loaded 0 plugins from {} — that directory does not exist; no card can be used until "
                           "it does and holds plugins",
                           kTag, dir);
    case PluginDirState::Unreadable:
        return std::format("{}: loaded 0 plugins from {} — that directory could not be read ({}); no card can be used "
                           "until that is fixed",
                           kTag, dir, resolution.dirError);
    case PluginDirState::Present:
        break;
    }
    return std::format("{}: loaded 0 plugins from {} — no card can be used until this directory holds plugins", kTag,
                       dir);
}

} // namespace

PluginDirResolution resolvePluginDir(const PluginDirInputs& inputs)
{
    PluginDirResolution resolution;

    if (!inputs.environment.empty()) {
        resolution.dir = fs::path(inputs.environment);
        resolution.candidates.push_back(
            {.source = Source::Environment, .path = resolution.dir, .verdict = Verdict::Chosen});
    } else {
        resolution.candidates.push_back({.source = Source::Environment, .path = {}, .verdict = Verdict::Unset});
        resolution.dir = inputs.compiledDefault;
        resolution.candidates.push_back(
            {.source = Source::CompiledDefault, .path = resolution.dir, .verdict = Verdict::Chosen});
    }

    // Recorded rather than acted on: an unusable directory is still the
    // directory the daemon will use, and the report needs to tell "empty" from
    // "not there" from "there but unreadable".
    //
    // `is_directory` returns false for all three, so the error code decides —
    // but merely *having* an error code does not mean the path was unreadable:
    // an ordinary missing path reports ENOENT. Only a code that is neither
    // "nothing there" nor "a component is not a directory" means the check
    // itself could not be carried out (EACCES, ELOOP, ENAMETOOLONG). Folding
    // those into "does not exist" would send the reader to create a directory
    // that is already on disk.
    std::error_code ec;
    if (fs::is_directory(resolution.dir, ec)) {
        resolution.dirState = PluginDirState::Present;
    } else if (!ec || ec == std::errc::no_such_file_or_directory || ec == std::errc::not_a_directory) {
        // No error at all means the path resolved to something that simply is
        // not a directory — same fault, same instruction, as nothing being there.
        resolution.dirState = PluginDirState::Absent;
    } else {
        resolution.dirState = PluginDirState::Unreadable;
        resolution.dirError = ec.message();
    }
    return resolution;
}

std::vector<std::pair<log::Level, std::string>>
pluginLoadReportLines(const PluginDirResolution& resolution, std::size_t loaded,
                      std::span<const LibreSCRS::Plugin::LoadOutcome> report)
{
    std::vector<std::pair<log::Level, std::string>> lines;

    for (const auto& candidate : resolution.candidates) {
        if (candidate.verdict == Verdict::Chosen) {
            lines.emplace_back(log::Level::Info, std::format("{}: using {} ({})", kTag, candidate.path.string(),
                                                             sourceName(candidate.source)));
            continue;
        }
        lines.emplace_back(log::Level::Info, rejectionLine(candidate));
    }

    // Zero is the state that costs an hour of misdiagnosis: every card then
    // reports as unusable, which is exactly what an unsupported card looks like.
    if (loaded == 0) {
        lines.emplace_back(log::Level::Warn, emptyDirLine(resolution));
    } else {
        lines.emplace_back(log::Level::Info, std::format("{}: loaded {} plugin{} from {}", kTag, loaded,
                                                         loaded == 1 ? "" : "s", resolution.dir.string()));
    }

    for (const auto& outcome : report) {
        if (outcome.status == LoadOutcome::Status::Loaded) {
            continue;
        }
        std::string line =
            std::format("{}: {} was not loaded ({})", kTag, outcome.soPath.string(), statusName(outcome.status));
        if (!outcome.diagnostic.empty()) {
            line += std::format(": {}", outcome.diagnostic);
        }
        lines.emplace_back(log::Level::Warn, std::move(line));
    }

    return lines;
}

void reportPluginLoad(const PluginDirResolution& resolution, const LibreSCRS::Plugin::CardPluginService& service)
{
    for (const auto& [level, line] : pluginLoadReportLines(resolution, service.size(), service.loadReport())) {
        switch (level) {
        case log::Level::Info:
            log::info(line);
            break;
        case log::Level::Warn:
            log::warn(line);
            break;
        case log::Level::Error:
            log::error(line);
            break;
        }
    }
}

} // namespace LibreSCRS::Agent
