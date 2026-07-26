// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#include "CallerIdentity.h"
#include "ProcPidPin.h" // librelinux-common pinned /proc readers

#include <LibreSCRS/Agent/util/CallerLabel.h> // exeBasename + sanitizeLabel (neutral core)

#include <optional>
#include <string>

namespace LibreSCRS::Agent {

std::string CallerIdentity::resolveRequesterLabel(pid_t credsPid)
{
    // readProcExePinned anchors the /proc read on a pidfd and probes it after
    // the read, so a PID recycled mid-read is discarded (see ProcPidPin.h).
    // nullopt on any failure -> empty (best-effort) label.
    // Basename extraction + anti-spoofing sanitisation are the platform-neutral
    // core's (util/CallerLabel.h), so every backend shapes labels identically.
    const auto exe = LibreLinux::Common::readProcExePinned(credsPid);
    if (!exe) {
        return {};
    }
    return sanitizeLabel(exeBasename(*exe));
}

} // namespace LibreSCRS::Agent
