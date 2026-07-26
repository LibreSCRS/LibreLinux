// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "CallerAuthorizer.h"

#include "ProcPidPin.h" // librelinux-common pinned /proc readers

#include <string>
#include <system_error>

#ifdef LIBRELINUX_TESTING
#include <cstdlib>
#endif

#ifndef LIBRESCRS_AGENT_BINARY_PATH
// Fallback if the build did not inject the resolved install path. The
// canonical value is supplied by CMake via target_compile_definitions; this
// keeps a standalone compile honest without silently authorising nothing.
#define LIBRESCRS_AGENT_BINARY_PATH "/usr/libexec/librescrs-agent"
#endif

namespace LibreLinux::Prompter {

#ifdef LIBRELINUX_TESTING
namespace {

constexpr const char* kExpectedPeerEnv = "LIBRESCRS_PROMPTER_EXPECTED_PEER";

} // namespace
#endif

std::filesystem::path CallerAuthorizer::resolveExpectedPeerPath()
{
#ifdef LIBRELINUX_TESTING
    // Test-only escape hatch: hermetic tests name their own binary as the
    // expected peer. Compiled out of every production target — the
    // environment must not be able to re-point the trust gate at an
    // arbitrary "agent".
    if (const char* override = std::getenv(kExpectedPeerEnv); override != nullptr && *override != '\0') {
        return std::filesystem::path{override};
    }
#endif
    return std::filesystem::path{LIBRESCRS_AGENT_BINARY_PATH};
}

std::optional<std::filesystem::path> CallerAuthorizer::resolvePidExePath(pid_t pid)
{
    // Pidfd-anchored /proc/<pid>/exe read with a post-read liveness probe, so
    // a PID recycled while we look is rejected instead of resolving to the
    // recycled process's executable (guarantees + the pre-pin residual are
    // documented in common/ProcPidPin.h). Fails closed (nullopt) when the
    // process is gone or the kernel lacks pidfd support.
    const auto target = LibreLinux::Common::readProcExePinned(pid);
    if (!target) {
        return std::nullopt;
    }

    std::error_code ec;
    // weakly_canonical resolves any further symlinks and normalises, while
    // tolerating a target that no longer fully exists (process may be
    // exiting).
    std::filesystem::path canonical = std::filesystem::weakly_canonical(*target, ec);
    if (ec) {
        // Fall back to the un-canonicalised target rather than failing: the
        // raw /proc/<pid>/exe link is already an absolute, kernel-resolved
        // path. Canonicalisation only matters for symlink-equality vs the
        // expected peer, handled symmetrically by the caller.
        return *target;
    }
    return canonical;
}

bool CallerAuthorizer::isAuthorizedCaller(pid_t pid, const std::filesystem::path& expectedPeer)
{
    const auto callerExe = resolvePidExePath(pid);
    if (!callerExe) {
        return false;
    }

    std::error_code ec;
    std::filesystem::path expectedCanonical = std::filesystem::weakly_canonical(expectedPeer, ec);
    if (ec) {
        expectedCanonical = expectedPeer;
    }
    return *callerExe == expectedCanonical;
}

} // namespace LibreLinux::Prompter
