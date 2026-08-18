// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#include "ConfigPaths.h"
#include <cstdlib>
#include <optional>
#include <string>
#include <string_view>
namespace LibreSCRS::Agent {
namespace {
// XDG resolution mirroring LM's platformCacheDir(): $XDG_CONFIG_HOME or
// $HOME/.config; $XDG_CACHE_HOME or $HOME/.cache, each suffixed "/librescrs".
// Empty optional only when HOME is unset and no XDG override is present.
std::optional<std::filesystem::path> xdgDir(const char* xdgVar, const char* homeSuffix)
{
    if (const char* x = std::getenv(xdgVar); x != nullptr && x[0] != '\0') {
        return std::filesystem::path{x} / "librescrs";
    }
    if (const char* home = std::getenv("HOME"); home != nullptr && home[0] != '\0') {
        return std::filesystem::path{home} / homeSuffix / "librescrs";
    }
    return std::nullopt;
}
// systemd exports these as colon-separated lists; the first entry is ours.
std::optional<std::filesystem::path> systemdDir(const char* var)
{
    const char* d = std::getenv(var);
    if (d == nullptr || d[0] == '\0') {
        return std::nullopt;
    }
    std::string_view v{d};
    if (const auto colon = v.find(':'); colon != std::string_view::npos) {
        v = v.substr(0, colon);
    }
    return std::filesystem::path{std::string{v}};
}
std::optional<std::filesystem::path> cacheDir()
{
    // systemd CacheDirectory= exports $CACHE_DIRECTORY for the user unit; prefer
    // it so caches land in the unit's writable mount under ProtectHome=read-only.
    if (auto d = systemdDir("CACHE_DIRECTORY")) {
        return d;
    }
    return xdgDir("XDG_CACHE_HOME", ".cache");
}
} // namespace
std::filesystem::path resolveConfigFile()
{
    // Same rule as the cache root, and for the same reason: under the unit's
    // ProtectHome=read-only sandbox $XDG_CONFIG_HOME is NOT writable, so every
    // persist — the first-run seed and every Config1.SetValue a user makes —
    // failed with "read-only file system" and the configuration silently did
    // not survive a restart. ConfigurationDirectory= gives the unit a writable
    // mount and exports this variable to name it.
    if (auto d = systemdDir("CONFIGURATION_DIRECTORY")) {
        return *d / "agent.conf";
    }
    if (auto d = xdgDir("XDG_CONFIG_HOME", ".config")) {
        return *d / "agent.conf";
    }
    return std::filesystem::temp_directory_path() / "librescrs" / "agent.conf";
}
std::filesystem::path resolveCacheRoot()
{
    if (auto c = cacheDir()) {
        return *c;
    }
    return std::filesystem::temp_directory_path() / "librescrs";
}
} // namespace LibreSCRS::Agent
