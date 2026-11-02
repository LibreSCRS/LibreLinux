// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include "PrompterWire.h"
#include <LibreSCRS/Secure/String.h>
#include <sdbus-c++/Types.h>
#include <cstddef>
#include <optional>
#include <string>
namespace LibreSCRS::Agent {

// Read a sealed memfd containing secret bytes into a LibreSCRS::Secure::String,
// scrubbing every intermediate buffer along the way and always closing the fd
// (RAII).
//
// Contract:
//   * The fd is consumed (closed) by this call regardless of outcome; pass an
//     sdbus::UnixFd by value so the caller transfers ownership.
//   * Returns std::nullopt on read / mmap failure or on an invalid fd; in that
//     case errorMessage (if non-null) is filled with a short diagnostic.
//   * Caps the accepted secret size at a sane upper bound (kMaxSecretBytes)
//     to defend against a hostile prompter handing back a multi-gigabyte fd.
//   * On success, the std::string holding the bytes during construction of
//     the Secure::String is explicitly zeroed before being released.
struct SecretMemfdReader
{
    // The cap every agent host enforces on a prompter (the agent library's).
    static constexpr std::size_t kMaxSecretBytes = LibreSCRS::PrompterWire::kMaxSecretBytes;

    [[nodiscard]] static std::optional<LibreSCRS::Secure::String> read(sdbus::UnixFd fd,
                                                                       std::string* errorMessage = nullptr);
};

} // namespace LibreSCRS::Agent
