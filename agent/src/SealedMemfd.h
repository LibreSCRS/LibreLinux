// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <cstdint>
#include <span>

namespace LibreSCRS::Agent::SealedMemfd {

// Allocate a memfd, write @p bytes, seal SHRINK|GROW|WRITE. Returns -1 on
// failure (no allocation occurs in that case). Caller takes ownership of
// the returned fd. The Qt-free agent core does not depend on the prompter
// binary's SecretMemfd implementation — this helper duplicates the
// behaviour for non-secret photo bytes.
[[nodiscard]] int create(std::span<const std::uint8_t> bytes) noexcept;

} // namespace LibreSCRS::Agent::SealedMemfd
