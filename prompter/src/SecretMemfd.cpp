// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "SecretMemfd.h"

#include "SealedMemfdCreator.h" // LibreLinux::Common::makeSealedMemfd (shared creator)

#include <cstdint>
#include <span>

namespace LibreLinux::Prompter {

int makeSealedSecretFd(std::string_view bytes) noexcept
{
    // The label "librescrs-secret" is visible in /proc; deliberately generic —
    // no per-request metadata, no secret material. The seal-flag set + write
    // loop live in the shared creator (one definition for the whole tree).
    return Common::makeSealedMemfd(
        "librescrs-secret",
        std::span<const std::uint8_t>{reinterpret_cast<const std::uint8_t*>(bytes.data()), bytes.size()});
}

int makeEmptySealedFd() noexcept
{
    return makeSealedSecretFd({});
}

} // namespace LibreLinux::Prompter
