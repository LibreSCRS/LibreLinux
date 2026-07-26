// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once

#include <cstddef>
#include <string_view>

namespace LibreLinux::Prompter {

/// Write @p bytes into a freshly-created anonymous memfd, then apply
/// F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE so the file's size and
/// contents are immutable for the remainder of its lifetime. The receiver
/// (the agent) mmap()s or read()s the contents, copies them into a
/// @c Secure::String, and closes the fd. Sealing prevents a malicious peer
/// from race-rewriting the bytes between hand-off and consumption.
///
/// @param bytes The secret payload. May be empty (a 0-byte sealed memfd is
///              returned, which the receiver should treat as "no secret",
///              e.g. on the cancellation path).
/// @returns A non-negative file descriptor on success, -1 on failure.
///          On failure errno is set by the failing syscall (memfd_create,
///          write, fcntl). The caller takes ownership of a successful fd.
///
/// @note The memfd is created with @c MFD_CLOEXEC and @c MFD_ALLOW_SEALING.
///       The name passed to @c memfd_create is a kernel-side debugging
///       label only (visible in @c /proc/<pid>/fd) and contains no secret
///       material.
[[nodiscard]] int makeSealedSecretFd(std::string_view bytes) noexcept;

/// Convenience: an empty (0-byte) sealed memfd, used as the @c secret_fd
/// return value on the cancellation and error paths so the wire signature
/// always carries a real file descriptor. Equivalent to
/// @c makeSealedSecretFd({}). Returns -1 on syscall failure.
[[nodiscard]] int makeEmptySealedFd() noexcept;

} // namespace LibreLinux::Prompter
