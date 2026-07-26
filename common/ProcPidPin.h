// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// PID-reuse-safe /proc readers, shared by the agent (polkit start-time
// subject, requester labels) and the prompter (caller trust gate).
//
// A PID obtained from kernel-validated D-Bus credentials (or anywhere else)
// can be recycled to a DIFFERENT process between the moment we learn it and
// the moment we read /proc/<pid>/...; acting on the recycled process is a
// security bug on an authorization gate. A pidfd does not prevent the reuse
// itself — holding one neither blocks reaping nor reserves the number — but
// it is a stable handle on the ORIGINAL process even after its PID moves on.
// Both readers therefore (1) open a pidfd FIRST, (2) read /proc/<pid>/...,
// and (3) probe the pidfd with signal 0 AFTER the read. A PID can only be
// recycled once its original process has been reaped, and a reaped process
// fails the probe with ESRCH, so any read that could have observed a
// recycled PID is discarded. Residual: a PID recycled BEFORE step (1) pins
// the recycled process and passes the probe; the exposure is the sub-
// millisecond gap between the kernel stamping the caller PID and the pin,
// and callers compare the read against an expected identity, so the recycled
// process is never blindly trusted.
//
// Kernels without pidfd_open(2) (< 5.3): both readers fail closed (nullopt)
// rather than degrade to an unpinned read. The glibc wrapper linked below
// already sets a glibc >= 2.36 (2022) floor, so a supported host always has
// the syscall; a deliberately older kernel loses these /proc-derived
// identities, never the pinning guarantee.
//
// Pure POSIX + glibc (no Qt, no sdbus, no LibreMiddleware), so every
// component links it freely. Header-only inline keeps it zero-plumbing
// beyond an include path.

#pragma once

#include <signal.h>    // siginfo_t
#include <sys/types.h> // pid_t
#include <unistd.h>    // close

// <sys/pidfd.h> on this glibc declares pidfd_open()/pidfd_send_signal()
// without the __BEGIN_DECLS C-linkage wrapper, so including it from C++ would
// mangle the symbols and fail to link against the C ABI libc exports. Declare
// the prototypes ourselves with explicit C linkage instead; they are thin
// glibc wrappers over the SYS_pidfd_* syscalls (glibc >= 2.36).
extern "C" int pidfd_open(pid_t pid, unsigned int flags) noexcept;
extern "C" int pidfd_send_signal(int pidfd, int sig, siginfo_t* info, unsigned int flags) noexcept;

#include <filesystem>
#include <fstream>
#include <optional>
#include <sstream>
#include <string>
#include <system_error>

namespace LibreLinux::Common {

namespace ProcPidPinDetail {

// RAII pidfd handle on the process that owned @p pid at construction time.
// Invalid (pidfd < 0) when the open failed (process gone / kernel without
// pidfd support / fd exhaustion) — callers fail closed on invalid.
class PidPin
{
public:
    explicit PidPin(pid_t pid) noexcept : m_fd(::pidfd_open(pid, 0u)) {}
    ~PidPin()
    {
        if (m_fd >= 0) {
            ::close(m_fd);
        }
    }
    PidPin(const PidPin&) = delete;
    PidPin& operator=(const PidPin&) = delete;

    [[nodiscard]] bool valid() const noexcept
    {
        return m_fd >= 0;
    }

    // Signal-0 probe of the pinned process. True while it is alive or a
    // zombie; false on ANY error (fail-closed), not just ESRCH. ESRCH is the
    // common case — the process has been reaped, the precondition for its PID
    // number being recycled — but any other errno (e.g. EPERM) also rejects
    // rather than trusts the read. Run AFTER a /proc/<pid> read to reject any
    // read that could have raced a reap-and-recycle.
    [[nodiscard]] bool stillPinsLiveProcess() const noexcept
    {
        return m_fd >= 0 && ::pidfd_send_signal(m_fd, 0, nullptr, 0u) == 0;
    }

private:
    int m_fd;
};

} // namespace ProcPidPinDetail

// Read /proc/<pid>/stat in full, pinned as documented above. nullopt if the
// process is gone / pidfd unsupported / the file cannot be read / the pinned
// process was reaped before the read completed.
[[nodiscard]] inline std::optional<std::string> readProcStatPinned(pid_t pid)
{
    if (pid <= 0) {
        return std::nullopt;
    }
    const ProcPidPinDetail::PidPin pin{pid};
    if (!pin.valid()) {
        return std::nullopt;
    }
    std::ifstream stat("/proc/" + std::to_string(pid) + "/stat");
    if (!stat.is_open()) {
        return std::nullopt;
    }
    std::ostringstream buf;
    buf << stat.rdbuf();
    if (!pin.stillPinsLiveProcess()) {
        return std::nullopt;
    }
    return buf.str();
}

// Resolve /proc/<pid>/exe (the kernel-resolved executable symlink), pinned as
// documented above. nullopt on any failure.
[[nodiscard]] inline std::optional<std::filesystem::path> readProcExePinned(pid_t pid)
{
    if (pid <= 0) {
        return std::nullopt;
    }
    const ProcPidPinDetail::PidPin pin{pid};
    if (!pin.valid()) {
        return std::nullopt;
    }
    const std::filesystem::path link = std::filesystem::path{"/proc"} / std::to_string(pid) / "exe";
    std::error_code ec;
    std::filesystem::path target = std::filesystem::read_symlink(link, ec);
    if (ec) {
        return std::nullopt;
    }
    if (!pin.stillPinsLiveProcess()) {
        return std::nullopt;
    }
    return target;
}

} // namespace LibreLinux::Common
