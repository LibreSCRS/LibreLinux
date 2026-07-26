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
std::optional<std::filesystem::path> cacheDir()
{
    // systemd CacheDirectory= exports $CACHE_DIRECTORY for the user unit; prefer
    // it so caches land in the unit's writable mount under ProtectHome=read-only.
    if (const char* cd = std::getenv("CACHE_DIRECTORY"); cd != nullptr && cd[0] != '\0') {
        // CACHE_DIRECTORY may be a colon-separated list; the first entry is ours.
        std::string_view v{cd};
        if (const auto colon = v.find(':'); colon != std::string_view::npos) {
            v = v.substr(0, colon);
        }
        return std::filesystem::path{std::string{v}};
    }
    return xdgDir("XDG_CACHE_HOME", ".cache");
}
} // namespace
std::filesystem::path resolveConfigFile()
{
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
