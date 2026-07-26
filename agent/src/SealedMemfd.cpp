// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#include "SealedMemfd.h" // agent-facing surface: LibreSCRS::Agent::SealedMemfd::create

#include "SealedMemfdCreator.h" // LibreLinux::Common::makeSealedMemfd (shared creator)

namespace LibreSCRS::Agent::SealedMemfd {

int create(std::span<const std::uint8_t> bytes) noexcept
{
    // The label "librescrs-photo" is visible in /proc — generic, no PII.
    return LibreLinux::Common::makeSealedMemfd("librescrs-photo", bytes);
}

} // namespace LibreSCRS::Agent::SealedMemfd
