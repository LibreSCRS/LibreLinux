// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <sys/types.h> // pid_t

#include <string>

namespace LibreSCRS::Agent {

// Best-effort resolver for the human-meaningful identity of the client that
// invoked a Card1 operation. The agent surfaces this in the consent prompt
// ("Requested by: <x>") so the user can attribute a credential
// request to a process. It is also the foundation for the future signing
// authorisation (polkit) flow.
//
// This is the LINUX BACKEND half: it maps a kernel-validated D-Bus message
// credential PID to an executable path via /proc, then delegates the label
// shaping (basename extraction + anti-spoofing sanitisation) to the platform-
// neutral core (util/CallerLabel.h) so every backend renders caller labels
// through the same guard.
//
// Domain-blind: this resolver knows nothing about cards, applets or auth
// kinds — it only maps a caller PID to a display label.
//
// PID-reuse TOCTOU: the caller PID comes from the kernel-validated D-Bus
// message credentials, but between obtaining it and reading /proc the PID
// could in principle be recycled. The /proc read is pidfd-anchored with a
// post-read liveness probe (guarantees + residual documented in the shared
// common/ProcPidPin.h), so a read racing a reap-and-recycle is discarded. A
// label is best-effort: any failure (process gone, /proc unavailable, pidfd
// unsupported) yields an empty string and the prompt simply omits the
// requester line.
class CallerIdentity
{
public:
    // Resolve @p credsPid (a kernel-validated D-Bus message-credential PID) to
    // a sanitised display label, pinning the process via pidfd to avoid
    // PID-reuse. Returns an empty string on any failure (best-effort).
    [[nodiscard]] static std::string resolveRequesterLabel(pid_t credsPid);
};

} // namespace LibreSCRS::Agent
