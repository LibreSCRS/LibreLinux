// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Pins the PRODUCTION shape of the expected-peer resolution: this target
// compiles CallerAuthorizer.cpp WITHOUT the LIBRELINUX_TESTING definition,
// exactly like the shipped librescrs-pinentry-kde binary. In that shape the
// LIBRESCRS_PROMPTER_EXPECTED_PEER environment override must not exist at
// all: a same-user launcher of the prompter must not be able to point the
// trust gate at an arbitrary "agent" from the environment. The override is
// honoured only by test targets that opt in via LIBRELINUX_TESTING (see
// CallerAuthorizerTest).

#include "CallerAuthorizer.h"

#include <unistd.h> // getpid

#include <gtest/gtest.h>

#include <cstdlib>
#include <filesystem>
#include <string>

using LibreLinux::Prompter::CallerAuthorizer;

namespace {

constexpr const char* kPeerEnv = "LIBRESCRS_PROMPTER_EXPECTED_PEER";

// Canonical path of the currently-running test executable.
std::filesystem::path selfExe()
{
    std::error_code ec;
    auto p = std::filesystem::read_symlink("/proc/self/exe", ec);
    EXPECT_FALSE(ec) << "read /proc/self/exe failed: " << ec.message();
    return std::filesystem::weakly_canonical(p, ec);
}

// RAII setenv/unsetenv guard so cases do not bleed the override into peers.
class EnvGuard
{
public:
    EnvGuard(const char* name, const std::string& value) : m_name(name)
    {
        ::setenv(name, value.c_str(), 1);
    }
    ~EnvGuard()
    {
        ::unsetenv(m_name);
    }
    EnvGuard(const EnvGuard&) = delete;
    EnvGuard& operator=(const EnvGuard&) = delete;

private:
    const char* m_name;
};

} // namespace

TEST(CallerAuthorizerProductionGate, EnvOverrideIsIgnoredInProductionShape)
{
    // Model the attack: a same-user launcher exports the override naming its
    // own binary before starting the prompter. The production TU must resolve
    // the compile-time install path regardless.
    EnvGuard guard(kPeerEnv, selfExe().string());
    const auto expected = CallerAuthorizer::resolveExpectedPeerPath();
    EXPECT_EQ(expected, std::filesystem::path{LIBRESCRS_AGENT_BINARY_PATH})
        << "production resolveExpectedPeerPath() must ignore the environment";
}

TEST(CallerAuthorizerProductionGate, EnvNamedSelfIsStillRejectedAsCaller)
{
    // End-to-end through the gate: even with the override naming THIS live
    // process, the production-shape authorizer must keep comparing against
    // the compiled agent path and reject us (we are not that binary).
    EnvGuard guard(kPeerEnv, selfExe().string());
    const auto expected = CallerAuthorizer::resolveExpectedPeerPath();
    EXPECT_FALSE(CallerAuthorizer::isAuthorizedCaller(::getpid(), expected))
        << "a caller authorised only by the env override must be rejected in production shape";
}
