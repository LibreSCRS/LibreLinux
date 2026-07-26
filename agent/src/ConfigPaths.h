// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <filesystem>
namespace LibreSCRS::Agent {
// Linux XDG / systemd-CacheDirectory resolution for the agent config file and
// cache root. Computed at startup and DI'd into the ConfigStore ctor; the model
// itself is path-agnostic. Never returns empty — falls back under the temp dir
// when HOME and every XDG/CACHE_DIRECTORY override is unset.
[[nodiscard]] std::filesystem::path resolveConfigFile();
[[nodiscard]] std::filesystem::path resolveCacheRoot();
} // namespace LibreSCRS::Agent
