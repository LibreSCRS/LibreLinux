// SPDX-License-Identifier: LGPL-2.1-or-later
#include "ConfigPaths.h"
#include <cstdlib>
#include <filesystem>
#include <gtest/gtest.h>
#include <optional>
#include <string>
#include <utility>
#include <vector>
using LibreSCRS::Agent::resolveCacheRoot;
using LibreSCRS::Agent::resolveConfigFile;
namespace {
class EnvGuard
{
public:
    EnvGuard()
    {
        for (const char* k : {"XDG_CONFIG_HOME", "XDG_CACHE_HOME", "CACHE_DIRECTORY", "HOME"}) {
            const char* v = ::getenv(k);
            m_saved.emplace_back(k, v ? std::optional<std::string>{v} : std::nullopt);
        }
    }
    ~EnvGuard()
    {
        for (auto& [k, v] : m_saved) {
            if (v) {
                ::setenv(k.c_str(), v->c_str(), 1);
            } else {
                ::unsetenv(k.c_str());
            }
        }
    }

private:
    std::vector<std::pair<std::string, std::optional<std::string>>> m_saved;
};
} // namespace
TEST(ConfigPaths, XdgConfigHomeWins)
{
    EnvGuard g;
    ::setenv("XDG_CONFIG_HOME", "/tmp/llcfg", 1);
    EXPECT_EQ(resolveConfigFile(), std::filesystem::path{"/tmp/llcfg/librescrs/agent.conf"});
}
TEST(ConfigPaths, CacheDirectoryFirstColonSegmentWins)
{
    EnvGuard g;
    ::setenv("CACHE_DIRECTORY", "/var/cache/a:/var/cache/b", 1);
    EXPECT_EQ(resolveCacheRoot(), std::filesystem::path{"/var/cache/a"});
}
TEST(ConfigPaths, HomeFallback)
{
    EnvGuard g;
    ::unsetenv("XDG_CONFIG_HOME");
    ::unsetenv("XDG_CACHE_HOME");
    ::unsetenv("CACHE_DIRECTORY");
    ::setenv("HOME", "/home/u", 1);
    EXPECT_EQ(resolveConfigFile(), std::filesystem::path{"/home/u/.config/librescrs/agent.conf"});
    EXPECT_EQ(resolveCacheRoot(), std::filesystem::path{"/home/u/.cache/librescrs"});
}
TEST(ConfigPaths, TempFallbackWhenNoHomeOrXdg)
{
    EnvGuard g;
    for (const char* k : {"XDG_CONFIG_HOME", "XDG_CACHE_HOME", "CACHE_DIRECTORY", "HOME"}) {
        ::unsetenv(k);
    }
    EXPECT_EQ(resolveConfigFile(), std::filesystem::temp_directory_path() / "librescrs" / "agent.conf");
    EXPECT_EQ(resolveCacheRoot(), std::filesystem::temp_directory_path() / "librescrs");
}
