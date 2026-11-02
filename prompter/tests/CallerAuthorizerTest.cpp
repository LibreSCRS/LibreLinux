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
#include <unistd.h>   // fork, getpid, readlink, _exit, execv

#include <csignal> // kill

#include <gtest/gtest.h>

#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <optional>
#include <string>
#include <thread>

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

// A directory of its own under TMPDIR, removed with everything in it.
class ScratchDir
{
public:
    ScratchDir()
    {
        std::string tmpl = (std::filesystem::temp_directory_path() / "caller-authorizer-XXXXXX").string();
        const char* made = ::mkdtemp(tmpl.data());
        EXPECT_NE(made, nullptr) << "mkdtemp failed";
        m_path = std::filesystem::weakly_canonical(tmpl);
    }
    ~ScratchDir()
    {
        std::error_code ec;
        std::filesystem::remove_all(m_path, ec);
    }
    ScratchDir(const ScratchDir&) = delete;
    ScratchDir& operator=(const ScratchDir&) = delete;
    [[nodiscard]] const std::filesystem::path& path() const
    {
        return m_path;
    }

private:
    std::filesystem::path m_path;
};

// A process running a private copy of sleep(1) at @p exe, killed and reaped on
// destruction. Construction returns once the kernel reports the copy as the
// process's executable (the fork runs the test binary until execv lands).
class RunningCopy
{
public:
    explicit RunningCopy(const std::filesystem::path& exe)
    {
        std::filesystem::copy_file("/usr/bin/sleep", exe, std::filesystem::copy_options::overwrite_existing);
        m_pid = ::fork();
        if (m_pid == 0) {
            const std::string path = exe.string();
            char arg0[] = "sleep";
            char arg1[] = "30";
            char* argv[] = {arg0, arg1, nullptr};
            ::execv(path.c_str(), argv);
            ::_exit(127);
        }
        const std::string procExe = "/proc/" + std::to_string(m_pid) + "/exe";
        for (int i = 0; i < 500; ++i) {
            std::error_code ec;
            if (std::filesystem::read_symlink(procExe, ec) == exe) {
                return;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        ADD_FAILURE() << "the copy at " << exe << " never became the child's executable";
    }
    ~RunningCopy()
    {
        if (m_pid > 0) {
            ::kill(m_pid, SIGKILL);
            int status = 0;
            ::waitpid(m_pid, &status, 0);
        }
    }
    RunningCopy(const RunningCopy&) = delete;
    RunningCopy& operator=(const RunningCopy&) = delete;
    [[nodiscard]] pid_t pid() const
    {
        return m_pid;
    }

private:
    pid_t m_pid = -1;
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

// A package upgrade replaces the agent's binary while the agent runs: the
// kernel then reports the running process's executable as "<path> (deleted)".
// That process is still the agent installed at the expected, root-owned path,
// so it stays authorised; every prompt would otherwise fail until logout.
TEST(CallerAuthorizer, AnAgentWhoseBinaryWasReplacedIsStillTheAgent)
{
    ScratchDir dir;
    const auto agent = dir.path() / "librescrs-agent";
    RunningCopy running(agent);
    ASSERT_GT(running.pid(), 0);

    std::filesystem::remove(agent);
    std::filesystem::copy_file("/usr/bin/sleep", agent); // the upgraded binary lands at the same path

    const auto resolved = CallerAuthorizer::resolvePidExePath(running.pid());
    ASSERT_TRUE(resolved.has_value());
    EXPECT_EQ(resolved->string(), agent.string() + " (deleted)") << "the kernel's own spelling of a replaced binary";
    EXPECT_TRUE(CallerAuthorizer::isAuthorizedCaller(running.pid(), agent));
}

// The same suffix on any other path is still another program.
TEST(CallerAuthorizer, AReplacedBinaryAtAnotherPathIsNotTheAgent)
{
    ScratchDir dir;
    const auto agent = dir.path() / "librescrs-agent";
    std::filesystem::copy_file("/usr/bin/sleep", agent);
    const auto other = dir.path() / "librescrs-agent-other";
    RunningCopy running(other);
    ASSERT_GT(running.pid(), 0);

    std::filesystem::remove(other);

    EXPECT_FALSE(CallerAuthorizer::isAuthorizedCaller(running.pid(), agent));
}
