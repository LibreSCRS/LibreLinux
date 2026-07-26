// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// The single definition of the sealed-memfd CREATOR for the whole LibreLinux
// tree. The prompter (SecretMemfd) and the agent (SealedMemfd) each used to
// hand-spell this — same memfd_create flags, same EINTR-tolerant write loop,
// same F_SEAL_SHRINK|GROW|WRITE set (SEAL_SEAL deliberately omitted) — and two
// agent integration tests carried a third copy. Defining the seal-flag set once
// here means a security-relevant change to it can never land in only one copy.
//
// Pure POSIX (no Qt, no sdbus, no LibreMiddleware), so every component links it
// freely. Header-only inline keeps it zero-plumbing beyond an include path.

#pragma once

#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>

#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <span>

namespace LibreLinux::Common {

/// @brief Create a sealed memfd holding @p bytes, named @p label.
///
/// @p label is visible in /proc — pass a generic, secret-free string. The fd is
/// sealed SHRINK|GROW|WRITE so its content is immutable from return onward;
/// SEAL_SEAL is deliberately omitted so a receiver may add its own seals.
/// Returns the owned fd, or -1 with errno preserved on any failure.
[[nodiscard]] inline int makeSealedMemfd(const char* label, std::span<const std::uint8_t> bytes) noexcept
{
    const int fd = ::memfd_create(label, MFD_CLOEXEC | MFD_ALLOW_SEALING);
    if (fd < 0) {
        return -1;
    }
    std::size_t off = 0;
    while (off < bytes.size()) {
        const ssize_t n = ::write(fd, bytes.data() + off, bytes.size() - off);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            const int saved = errno;
            ::close(fd);
            errno = saved;
            return -1;
        }
        if (n == 0) {
            // POSIX: write() == 0 on a regular fd means "no progress possible".
            ::close(fd);
            errno = EIO;
            return -1;
        }
        off += static_cast<std::size_t>(n);
    }
    constexpr int seals = F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE;
    if (::fcntl(fd, F_ADD_SEALS, seals) < 0) {
        const int saved = errno;
        ::close(fd);
        errno = saved;
        return -1;
    }
    return fd;
}

} // namespace LibreLinux::Common
