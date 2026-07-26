// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once

#include <sys/types.h> // pid_t

#include <filesystem>
#include <optional>

namespace LibreLinux::Prompter {

/// Caller-identity gate for the @c org.librescrs.Prompter1 trust boundary.
///
/// The prompter hosts a secure-input dialog (PIN / CAN / MRZ) and hands the
/// captured secret back over D-Bus. On the session bus every same-user peer
/// can reach the well-known name, so a binary-level check is the real gate:
/// only the LibreSCRS agent binary may drive the prompter. A rogue same-user
/// process must not be able to pop a PIN dialog and harvest the secret, nor
/// inject a @c CancelCurrent.
///
/// The check resolves the CALLER's PID (obtained from the sd-bus message
/// credentials) to its executable via @c /proc/<pid>/exe and compares the
/// canonical path against the expected agent binary. The expected path is
/// the compile-time install location of @c librescrs-agent. Test builds
/// (targets compiled with @c LIBRELINUX_TESTING) may override it via the
/// @c LIBRESCRS_PROMPTER_EXPECTED_PEER environment variable so hermetic
/// tests can name the real peer deterministically; the override does not
/// exist in production targets, so the environment cannot re-point the gate.
///
/// PID-reuse TOCTOU note: sdbus-c++ does not expose the sender's pidfd
/// credential, so the PID is taken from the kernel-validated sd-bus
/// credentials of the in-flight call and then pinned locally: the @c /proc/<pid>/exe
/// read is pidfd-anchored with a post-read liveness probe (see
/// common/ProcPidPin.h), so a PID recycled during the check is rejected
/// outright. The remaining residual is a PID recycled BEFORE the pin — the
/// sub-millisecond gap between the kernel stamping the credentials and
/// @c pidfd_open. The session-bus policy file (defense-in-depth) plus the
/// synchronous nature of the request (the agent is blocked on the reply)
/// make that window practically unexploitable; worst case a same-user
/// process is prompted in the agent's stead, and it still cannot exfiltrate
/// a secret it did not request.
class CallerAuthorizer
{
public:
    /// Resolve the expected agent-binary path: the compile-time install path
    /// of @c librescrs-agent (see @c LIBRESCRS_AGENT_BINARY_PATH). Only in
    /// targets compiled with @c LIBRELINUX_TESTING does a set, non-empty
    /// @c LIBRESCRS_PROMPTER_EXPECTED_PEER environment variable take
    /// precedence; production targets have no override path.
    [[nodiscard]] static std::filesystem::path resolveExpectedPeerPath();

    /// Resolve @p pid to the canonical path of its executable by reading
    /// @c /proc/<pid>/exe under a pidfd pin with a post-read liveness probe.
    /// Returns @c std::nullopt if the link cannot be read (process gone,
    /// permission denied, @c /proc unavailable, kernel without pidfd
    /// support) or if the process was reaped while being examined.
    [[nodiscard]] static std::optional<std::filesystem::path> resolvePidExePath(pid_t pid);

    /// @returns @c true iff the executable backing @p pid canonicalises to
    /// the same path as @p expectedPeer. A non-resolvable PID or a mismatch
    /// returns @c false (fail-closed). Both sides are weakly canonicalised
    /// (symlinks followed where the target exists) so an install symlink and
    /// its target compare equal.
    [[nodiscard]] static bool isAuthorizedCaller(pid_t pid, const std::filesystem::path& expectedPeer);
};

} // namespace LibreLinux::Prompter
