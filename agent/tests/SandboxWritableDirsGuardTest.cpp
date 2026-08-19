// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Machine gate for the sandbox's writable directories.
//
// The unit runs with ProtectHome=read-only, which mounts the user's home
// read-only for the service. Every directory the agent WRITES to must
// therefore be declared to systemd, because those declarations are what mount
// the directory back in writable. A missing declaration does not fail loudly:
// the write simply returns EROFS at runtime, so nothing the user configures
// survives a restart and the first-run seed never lands on disk. It is
// invisible to every other test in this suite, because they all resolve their
// paths into a temporary directory that no sandbox governs — the defect was
// found by reading a journal, not by a red test.
//
// This gate reads the shipped unit template out of the source tree (path
// injected by CMake, the Operation1ErrorCodeXmlGuardTest pattern) and pins the
// pairing: while the unit confines the home directory, it must also declare a
// directory for each of the agent's two write roots — configuration
// (ConfigStore::persist) and cache (the trusted-list and AIA caches).
//
// The resolver half of that behaviour is covered by ConfigPathsTest, which
// exercises $CONFIGURATION_DIRECTORY / $CACHE_DIRECTORY directly. Both halves
// are needed: on a normal desktop session the resolver's systemd branch and its
// XDG fallback compute the SAME path, so the resolver tests pass whether or not
// the unit ever declares the directory. Only this file can tell the difference.

#include <gtest/gtest.h>

#include <fstream>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>

namespace {

std::string unitText()
{
    std::ifstream in{LIBRELINUX_AGENT_UNIT_IN};
    EXPECT_TRUE(in.is_open()) << "cannot open the unit template at " << LIBRELINUX_AGENT_UNIT_IN;
    std::ostringstream buf;
    buf << in.rdbuf();
    return buf.str();
}

std::string trim(std::string_view v)
{
    const auto first = v.find_first_not_of(" \t\r");
    if (first == std::string_view::npos) {
        return {};
    }
    const auto last = v.find_last_not_of(" \t\r");
    return std::string{v.substr(first, last - first + 1)};
}

// Value of the last assignment of `name`, ignoring comment lines. systemd lets
// a directive be repeated and the last one wins for these settings, so the last
// assignment is the one that governs.
std::optional<std::string> directive(const std::string& text, std::string_view name)
{
    std::optional<std::string> found;
    std::istringstream lines{text};
    std::string line;
    while (std::getline(lines, line)) {
        const std::string stripped = trim(line);
        if (stripped.empty() || stripped.front() == '#' || stripped.front() == ';') {
            continue;
        }
        const auto eq = stripped.find('=');
        if (eq == std::string::npos) {
            continue;
        }
        if (trim(std::string_view{stripped}.substr(0, eq)) == name) {
            found = trim(std::string_view{stripped}.substr(eq + 1));
        }
    }
    return found;
}

} // namespace

TEST(SandboxWritableDirs, ConfiningHomeRequiresDeclaringEveryWriteRoot)
{
    const std::string text = unitText();

    const std::optional<std::string> protectHome = directive(text, "ProtectHome");
    ASSERT_TRUE(protectHome.has_value()) << "the unit no longer confines the home directory; if that is deliberate "
                                            "this gate should be re-stated, not deleted";
    ASSERT_EQ(*protectHome, "read-only");

    // Configuration: ConfigStore::persist() writes agent.conf here. Without
    // this directive the persist fails with EROFS and every setting the user
    // changes is lost on restart, silently.
    const std::optional<std::string> configDir = directive(text, "ConfigurationDirectory");
    ASSERT_TRUE(configDir.has_value())
        << "ProtectHome=read-only without ConfigurationDirectory= makes every persist fail with EROFS";
    EXPECT_EQ(*configDir, "librescrs");

    // Cache: the trusted-list and AIA caches write here.
    const std::optional<std::string> cacheDir = directive(text, "CacheDirectory");
    ASSERT_TRUE(cacheDir.has_value())
        << "ProtectHome=read-only without CacheDirectory= makes every cache write fail with EROFS";
    EXPECT_EQ(*cacheDir, "librescrs");
}
