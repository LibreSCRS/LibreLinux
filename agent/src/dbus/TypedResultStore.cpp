// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#include "dbus/TypedResultStore.h"
#include "SealedMemfd.h"
#include <unistd.h> // ::close
#include <cstdint>
#include <mutex>
#include <optional>
#include <span>
#include <utility>
#include <vector>

namespace LibreSCRS::Agent::Operations {

SealedSignResult sealStoredResult(SignResultState& state) noexcept
{
    std::lock_guard lock(state.mutex);
    if (!state.ready) {
        return {};
    }
    const int fd = SealedMemfd::create(std::span<const std::uint8_t>{state.payload.bytes});
    return SealedSignResult{.fd = fd, .meta = state.payload.meta};
}

std::optional<std::vector<SealedPhoto>> sealStoredPhotos(PhotoResultState& state, SealFn seal) noexcept
{
    // Declared OUTSIDE the try so the failure paths below can close every
    // already-sealed fd (SealedPhoto holds a raw owned int, deliberately — no
    // sdbus type leaks into the store).
    std::vector<SealedPhoto> sealed;
    const auto closeAll = [&sealed]() noexcept {
        for (const auto& s : sealed) {
            ::close(s.fd);
        }
    };
    try {
        std::lock_guard lock(state.mutex);
        if (!state.ready) {
            return std::nullopt;
        }
        sealed.reserve(state.payload.size());
        for (const auto& photo : state.payload) {
            if (photo.bytes.empty()) {
                continue; // mirrors the Photo1.Result emit's empty-entry skip
            }
            const int fd = seal(std::span<const std::uint8_t>{photo.bytes});
            if (fd < 0) {
                // Fail closed on a REQUIRED re-seal failure: close what was
                // already sealed and report "no result" — never a half-map.
                closeAll();
                return std::nullopt;
            }
            try {
                sealed.push_back(SealedPhoto{.key = photo.key, .fd = fd});
            } catch (...) {
                ::close(fd); // the push_back alloc failed; don't leak this fd
                closeAll();
                return std::nullopt;
            }
        }
        return sealed;
    } catch (...) {
        closeAll(); // reserve/key-copy alloc failure — no fd outlives the call
        return std::nullopt;
    }
}

int publishSealedResult(SignResultState& state, std::span<const std::uint8_t> bytes, const SignMeta& meta,
                        SealFn seal) noexcept
{
    // Seal FIRST: the store is marked ready ONLY after a successful seal, so a
    // seal failure leaves `ready` false (fail closed for a racing GetResult).
    const int fd = seal(bytes);
    if (fd < 0) {
        return -1;
    }
    try {
        std::lock_guard lock(state.mutex);
        // `ready` is written LAST: if either copy throws bad_alloc, `ready` stays
        // false and the catch below closes the sealed fd — no leak, still closed.
        state.payload.bytes.assign(bytes.begin(), bytes.end());
        state.payload.meta = meta;
        state.ready = true;
    } catch (...) {
        ::close(fd); // don't leak the sealed fd; store stays unpublished
        return -1;
    }
    return fd;
}

std::optional<std::vector<SealedBatchRow>>
publishSealedSignBatchResult(SignBatchResultState& state, const BatchSignResult& rows, SealFn seal) noexcept
{
    std::vector<SealedBatchRow> sealed;
    const auto closeAll = [&sealed]() noexcept {
        for (const auto& s : sealed) {
            if (s.fd >= 0) {
                ::close(s.fd);
            }
        }
    };
    try {
        sealed.reserve(rows.size());
        for (const auto& row : rows) {
            // A zero-length span (a failed row's empty `bytes`) is a VALID
            // seal — the wire's own convention for a failed row's artifact —
            // not a failure case here.
            const int fd = seal(std::span<const std::uint8_t>{row.bytes});
            if (fd < 0) {
                closeAll();
                return std::nullopt;
            }
            sealed.push_back(
                SealedBatchRow{.displayName = row.displayName, .fd = fd, .meta = row.meta, .code = row.code});
        }
    } catch (...) {
        closeAll();
        return std::nullopt;
    }
    try {
        std::lock_guard lock(state.mutex);
        // `ready` is written LAST: if the copy throws bad_alloc, `ready` stays
        // false and the catch below closes every sealed fd — no leak.
        state.payload = rows;
        state.ready = true;
    } catch (...) {
        closeAll();
        return std::nullopt;
    }
    return sealed;
}

std::optional<std::vector<SealedBatchRow>> sealStoredSignBatchResult(SignBatchResultState& state, SealFn seal) noexcept
{
    std::vector<SealedBatchRow> sealed;
    const auto closeAll = [&sealed]() noexcept {
        for (const auto& s : sealed) {
            if (s.fd >= 0) {
                ::close(s.fd);
            }
        }
    };
    try {
        std::lock_guard lock(state.mutex);
        if (!state.ready) {
            return std::nullopt;
        }
        sealed.reserve(state.payload.size());
        for (const auto& row : state.payload) {
            // Same zero-length-is-valid rule as publishSealedSignBatchResult:
            // every row gets a fresh fd, never skipped.
            const int fd = seal(std::span<const std::uint8_t>{row.bytes});
            if (fd < 0) {
                closeAll();
                return std::nullopt;
            }
            sealed.push_back(
                SealedBatchRow{.displayName = row.displayName, .fd = fd, .meta = row.meta, .code = row.code});
        }
        return sealed;
    } catch (...) {
        closeAll();
        return std::nullopt;
    }
}

} // namespace LibreSCRS::Agent::Operations
