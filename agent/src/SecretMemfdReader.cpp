// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#include "SecretMemfdReader.h"
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <cerrno>
#include <cstring>
#include <string>
#include <utility>

namespace LibreSCRS::Agent {

namespace {

// Best-effort in-place scrub of a std::string's underlying bytes.
// A volatile pointer prevents the compiler from optimising the loop away,
// matching the strategy of OPENSSL_cleanse for plain byte buffers we own.
void scrubString(std::string& s) noexcept
{
    if (s.empty()) {
        return;
    }
    volatile char* p = const_cast<volatile char*>(s.data());
    for (std::size_t i = 0; i < s.size(); ++i) {
        p[i] = 0;
    }
}

void setError(std::string* out, const char* message)
{
    if (out != nullptr) {
        *out = message;
    }
}

} // namespace

std::optional<LibreSCRS::Secure::String> SecretMemfdReader::read(sdbus::UnixFd fd, std::string* errorMessage)
{
    // sdbus::UnixFd dtor closes the fd, so any return path below is safe.
    if (!fd.isValid()) {
        setError(errorMessage, "invalid file descriptor");
        return std::nullopt;
    }

    const int rawFd = fd.get();

    // Trust-root input-shape check: the fd MUST be a sealed memfd carrying the
    // exact seal set the producer (SealedMemfdCreator::makeSealedMemfd) applies —
    // F_SEAL_WRITE keeps the bytes immutable, F_SEAL_SHRINK|F_SEAL_GROW pin the
    // size fstat is about to report. A compromised or rogue prompter must not be
    // able to hand back a writable/growable fd (content could mutate under us) or
    // a non-memfd such as a pipe (F_GET_SEALS fails with EINVAL). Enforce this
    // before reading a single byte, and before the zero-length fast path, so an
    // unsealed empty fd is rejected too.
    constexpr int kRequiredSeals = F_SEAL_WRITE | F_SEAL_SHRINK | F_SEAL_GROW;
    const int seals = ::fcntl(rawFd, F_GET_SEALS);
    if (seals < 0 || (seals & kRequiredSeals) != kRequiredSeals) {
        setError(errorMessage, "secret fd is not a sealed memfd");
        return std::nullopt;
    }

    struct ::stat st{};
    if (::fstat(rawFd, &st) != 0) {
        setError(errorMessage, std::strerror(errno));
        return std::nullopt;
    }

    // st.st_size is signed off_t; coerce to unsigned for the cap comparison,
    // refusing negative or oversized payloads outright.
    if (st.st_size < 0) {
        setError(errorMessage, "memfd reports negative size");
        return std::nullopt;
    }
    const auto size = static_cast<std::size_t>(st.st_size);
    if (size > kMaxSecretBytes) {
        setError(errorMessage, "memfd payload exceeds maximum allowed size");
        return std::nullopt;
    }

    // Zero-length payload is a legitimate "ok with empty secret" — return an
    // empty Secure::String rather than nullopt so callers can distinguish it
    // from read failure.
    if (size == 0) {
        return LibreSCRS::Secure::String{};
    }

    // Rewind defensively — the prompter may or may not have repositioned the
    // fd after sealing it. Ignore failure on a memfd seek; pread covers us.
    ::lseek(rawFd, 0, SEEK_SET);

    std::string buffer;
    try {
        buffer.resize(size);
    } catch (...) {
        setError(errorMessage, "allocation failed for secret buffer");
        return std::nullopt;
    }

    // Loop until all bytes are read or a hard error occurs; pread is used so
    // we are not dependent on the kernel/sdbus seek position state.
    std::size_t total = 0;
    while (total < size) {
        const ssize_t n = ::pread(rawFd, buffer.data() + total, size - total, static_cast<off_t>(total));
        if (n > 0) {
            total += static_cast<std::size_t>(n);
            continue;
        }
        if (n == 0) {
            // Premature EOF — payload shorter than fstat said. Treat as error.
            scrubString(buffer);
            setError(errorMessage, "short read from secret memfd");
            return std::nullopt;
        }
        if (errno == EINTR) {
            continue;
        }
        scrubString(buffer);
        setError(errorMessage, std::strerror(errno));
        return std::nullopt;
    }

    // Hand the bytes to Secure::String via the cleansing rvalue constructor,
    // which copies into cleansing storage AND zeros our buffer on success
    // (and on bad_alloc) — but we still scrub locally on the catch path in
    // case any other exception sneaks out.
    try {
        LibreSCRS::Secure::String secret{std::move(buffer)};
        // The moved-from std::string is left in a valid but unspecified state;
        // the Secure::String rvalue ctor cleanses both heap and SSO bytes of
        // the source, so no further action is needed here.
        return secret;
    } catch (...) {
        scrubString(buffer);
        setError(errorMessage, "Secure::String construction failed");
        return std::nullopt;
    }
}

} // namespace LibreSCRS::Agent
