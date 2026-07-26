// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Pure-text assertions on the CONFIGURED p11-kit .module file and the
// deployment-(b) systemd user unit. No p11-kit dependency, no D-Bus, no card:
// the generated paths are passed in via -D so the test verifies the directives
// CMake produced (the in-process default + the documented remote:/server-address
// opt-in, and the 0600 socket UMask on the server unit).

#include <gtest/gtest.h>

#include <fstream>
#include <sstream>
#include <string>

namespace {

std::string slurp(const char* path)
{
    std::ifstream in{path};
    std::ostringstream ss;
    ss << in.rdbuf();
    return ss.str();
}

bool contains(const std::string& haystack, const std::string& needle)
{
    return haystack.find(needle) != std::string::npos;
}

// A non-comment line is one whose first non-space character is not '#'.
bool hasActiveDirective(const std::string& text, const std::string& directive)
{
    std::istringstream in{text};
    std::string line;
    while (std::getline(in, line)) {
        std::size_t i = line.find_first_not_of(" \t");
        if (i == std::string::npos || line[i] == '#')
            continue;
        if (line.compare(i, directive.size(), directive) == 0)
            return true;
    }
    return false;
}

} // namespace

TEST(ModuleConfig, InProcessModuleDirectiveIsTheActiveDefault)
{
    const std::string cfg = slurp(LIBRESCRS_MODULE_CONFIG_PATH);
    ASSERT_FALSE(cfg.empty()) << "configured .module file is empty/missing";

    // The DEFAULT deployment (a) is in-process: an active `module:` directive
    // naming the backend .so (relative -> resolved from p11_module_path).
    EXPECT_TRUE(hasActiveDirective(cfg, "module:")) << "no active module: directive";
    EXPECT_TRUE(contains(cfg, "librescrs-pkcs11-agent.so"));

    // critical: no — a failed load must never abort other modules.
    EXPECT_TRUE(hasActiveDirective(cfg, "critical:"));
    EXPECT_TRUE(contains(cfg, "critical: no"));
}

TEST(ModuleConfig, OutOfProcessOptInDocumentedButCommentedOut)
{
    const std::string cfg = slurp(LIBRESCRS_MODULE_CONFIG_PATH);

    // The remote:/server-address: opt-in (deployment b) MUST be documented...
    EXPECT_TRUE(contains(cfg, "remote:"));
    EXPECT_TRUE(contains(cfg, "server-address:"));
    EXPECT_TRUE(contains(cfg, "p11-kit remote"));

    // ...but NOT active (no second backend transport competes with module:).
    EXPECT_FALSE(hasActiveDirective(cfg, "remote:")) << "remote: must be commented out by default";
    EXPECT_FALSE(hasActiveDirective(cfg, "server-address:")) << "server-address: must be commented out by default";
}

TEST(ModuleConfig, NssFallbackDiscoveryDocumented)
{
    const std::string cfg = slurp(LIBRESCRS_MODULE_CONFIG_PATH);
    // The NSS / standalone discovery fallbacks live in the
    // .module comment so there is no forbidden README.
    EXPECT_TRUE(contains(cfg, "modutil"));
    EXPECT_TRUE(contains(cfg, "pkcs11-tool"));
    EXPECT_TRUE(contains(cfg, "-I")) << "ssh -I <module> usage should be documented";
}

TEST(ModuleConfig, ServerUnitForcesOwnerOnlySocket)
{
    const std::string unit = slurp(LIBRESCRS_SERVER_UNIT_PATH);
    ASSERT_FALSE(unit.empty()) << "configured server .service is empty/missing";

    // Deployment (b) out-of-process isolation: a Type=simple user unit that runs
    // `p11-kit server`. Empirically the server socket is created srw------- (0600)
    // under $XDG_RUNTIME_DIR/p11-kit; UMask=0077 keeps it owner-only regardless.
    EXPECT_TRUE(contains(unit, "p11-kit server"));
    EXPECT_TRUE(contains(unit, "--provider"));
    EXPECT_TRUE(contains(unit, "librescrs-pkcs11-agent.so"));
    EXPECT_TRUE(contains(unit, "UMask=0077"));
    EXPECT_TRUE(contains(unit, "Type=simple"));
}
