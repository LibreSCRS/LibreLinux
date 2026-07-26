// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Pins the prompter trust-boundary gate: only a caller whose resolved
// executable matches the expected agent binary is authorised. A caller
// whose /proc/<pid>/exe differs (any other same-user process) is rejected.
//
// The check is deterministic without spinning up a real agent: we point the
// LIBRESCRS_PROMPTER_EXPECTED_PEER override at THIS test process's own
// executable (/proc/self/exe) to model "the configured peer", and at an
// unrelated binary to model "a rogue caller". No display server or D-Bus
// session is required. The override only compiles under LIBRELINUX_TESTING
// (defined for this target); CallerAuthorizerProductionGateTest pins that
// the production shape has no override at all.

#include "CallerAuthorizer.h"

#include <sys/wait.h> // waitpid
#include <unistd.h>   // fork, getpid, readlink, _exit

#include <gtest/gtest.h>

#include <cstdlib>
#include <filesystem>
#include <optional>
#include <string>

using LibreLinux::Prompter::CallerAuthorizer;

namespace {

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

TEST(CallerAuthorizer, ResolvesOwnPidToOwnExecutable)
{
    const auto resolved = CallerAuthorizer::resolvePidExePath(::getpid());
    ASSERT_TRUE(resolved.has_value()) << "must resolve /proc/self/exe for the live test process";
    EXPECT_EQ(*resolved, selfExe());
}

TEST(CallerAuthorizer, AuthorizesCallerWhoseExeMatchesExpectedPeer)
{
    // Model "the configured agent is the caller": expected peer == our exe.
    EnvGuard guard("LIBRESCRS_PROMPTER_EXPECTED_PEER", selfExe().string());
    const auto expected = CallerAuthorizer::resolveExpectedPeerPath();
    EXPECT_EQ(expected, selfExe());
    EXPECT_TRUE(CallerAuthorizer::isAuthorizedCaller(::getpid(), expected));
}

TEST(CallerAuthorizer, RejectsCallerWhoseExeDiffersFromExpectedPeer)
{
    // Model "a rogue same-user process": the live caller's exe is THIS test
    // binary, but the expected peer points elsewhere. Must fail closed.
    const std::filesystem::path bogusPeer{"/usr/bin/true"};
    EnvGuard guard("LIBRESCRS_PROMPTER_EXPECTED_PEER", bogusPeer.string());
    const auto expected = CallerAuthorizer::resolveExpectedPeerPath();
    EXPECT_EQ(expected, bogusPeer);
    EXPECT_FALSE(CallerAuthorizer::isAuthorizedCaller(::getpid(), expected))
        << "a caller whose exe != expected peer must be rejected";
}

TEST(CallerAuthorizer, NonexistentPidIsRejected)
{
    EnvGuard guard("LIBRESCRS_PROMPTER_EXPECTED_PEER", selfExe().string());
    const auto expected = CallerAuthorizer::resolveExpectedPeerPath();
    // PID 0 is never a real /proc/<pid>/exe target from a user perspective;
    // resolution must fail and the gate must reject.
    EXPECT_FALSE(CallerAuthorizer::resolvePidExePath(0).has_value());
    EXPECT_FALSE(CallerAuthorizer::isAuthorizedCaller(0, expected));
}

TEST(CallerAuthorizer, ReapedPidIsRejected)
{
    // A real-but-reaped PID exercises the pidfd fail-closed path: the pin
    // cannot be established for a process that no longer exists, so the exe
    // never resolves and the gate rejects — even though this very executable
    // (the child was a fork of us) is the configured peer.
    const pid_t child = ::fork();
    ASSERT_NE(child, -1) << "fork failed";
    if (child == 0) {
        ::_exit(0);
    }
    int status = 0;
    ASSERT_EQ(::waitpid(child, &status, 0), child);

    EnvGuard guard("LIBRESCRS_PROMPTER_EXPECTED_PEER", selfExe().string());
    const auto expected = CallerAuthorizer::resolveExpectedPeerPath();
    EXPECT_FALSE(CallerAuthorizer::resolvePidExePath(child).has_value())
        << "a reaped PID must not resolve to an executable";
    EXPECT_FALSE(CallerAuthorizer::isAuthorizedCaller(child, expected))
        << "a reaped PID must be rejected even when its exe would have matched";
}

TEST(CallerAuthorizer, EmptyOverrideFallsBackToCompiledDefault)
{
    // An empty override must be ignored (treated as unset) so we fall back to
    // the compile-time install path rather than resolving to "".
    EnvGuard guard("LIBRESCRS_PROMPTER_EXPECTED_PEER", std::string{});
    const auto expected = CallerAuthorizer::resolveExpectedPeerPath();
    EXPECT_FALSE(expected.empty()) << "empty override must fall back to the compiled default path";
}
