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

// The value of the first active occurrence of @p directive, trimmed.
std::string activeDirectiveValue(const std::string& text, const std::string& directive)
{
    std::istringstream in{text};
    std::string line;
    while (std::getline(in, line)) {
        std::size_t i = line.find_first_not_of(" \t");
        if (i == std::string::npos || line[i] == '#')
            continue;
        if (line.compare(i, directive.size(), directive) != 0)
            continue;
        std::size_t v = line.find_first_not_of(" \t", i + directive.size());
        if (v == std::string::npos)
            return {};
        std::size_t e = line.find_last_not_of(" \t\r");
        return line.substr(v, e - v + 1);
    }
    return {};
}

std::string firstLineContaining(const std::string& text, const std::string& needle)
{
    std::istringstream in{text};
    std::string line;
    while (std::getline(in, line)) {
        if (line.find(needle) != std::string::npos)
            return line;
    }
    return {};
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

TEST(ModuleConfig, ModuleReferenceResolvesUnderThisInstallLayout)
{
    const std::string cfg = slurp(LIBRESCRS_MODULE_CONFIG_PATH);
    const std::string ref = activeDirectiveValue(cfg, "module:");
    ASSERT_FALSE(ref.empty());

    // A bare name is resolved against p11-kit's own module path, never against
    // the install prefix. It is correct only when the two are the same
    // directory; anywhere else the reference dangles and p11-kit drops the
    // module without a word.
    if (ref.find('/') == std::string::npos) {
        EXPECT_STREQ(ref.c_str(), "librescrs-pkcs11-agent.so");
        EXPECT_STREQ(LIBRESCRS_MODULE_DIR_ABS, LIBRESCRS_P11_KIT_MODULE_PATH);
    } else {
        EXPECT_EQ(ref, std::string{LIBRESCRS_MODULE_DIR_ABS} + "/librescrs-pkcs11-agent.so");
    }
}

TEST(ModuleConfig, DeclaresPriorityBelowVendorMiddleware)
{
    const std::string cfg = slurp(LIBRESCRS_MODULE_CONFIG_PATH);
    EXPECT_TRUE(hasActiveDirective(cfg, "priority:"));
    EXPECT_TRUE(contains(cfg, "priority: 10"));
}

TEST(ModuleConfig, DocumentedCommandsCanBePastedIntoAShell)
{
    // The examples are the only instructions a user gets (project policy bans a
    // README here), so a relative path in them is not a cosmetic defect.
    // Each needle must pick the EXAMPLE line, not the prose that mentions the
    // tool. "p11-kit remote" alone matches a sentence four lines earlier which
    // carries no path at all, so the test would fail for the wrong reason and
    // then pass for the wrong reason once the prose is reworded.
    const struct
    {
        const char* tool;
        const char* needle;
    } examples[] = {
        {"modutil", "-libfile "},
        {"ssh", "ssh -I "},
        {"pkcs11-tool", "pkcs11-tool --module "},
        {"p11-kit remote", "remote: |p11-kit remote "},
    };
    const std::string cfg = slurp(LIBRESCRS_MODULE_CONFIG_PATH);
    for (const auto& e : examples) {
        const std::string line = firstLineContaining(cfg, e.needle);
        ASSERT_FALSE(line.empty()) << e.tool;
        EXPECT_NE(line.find("/librescrs-pkcs11-agent.so"), std::string::npos) << e.tool;
        EXPECT_NE(line.find(LIBRESCRS_MODULE_DIR_ABS), std::string::npos) << e.tool << ": " << line;
    }
}
