// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <LibreSCRS/Agent/backend/Logging.h>          // log::warn (post-seal emit-throw diagnostic)
#include <LibreSCRS/Agent/backend/OperationChannel.h> // SignedArtifact, PhotoResult, CardReadSnapshot, CertSnapshot
#include <cstdint>
#include <exception>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace LibreSCRS::Agent::Operations {

// Late-subscriber recovery store, shared by a typed channel (writer, on the
// worker via OperationChannel::emitResult) and the matching typed sub-adaptor
// (reader, on the bus thread, in GetResult). The typed Result signal is a
// one-shot: a client that subscribes after the operation already emitted (hot
// card session -> op completes faster than the client's match-rule install)
// would lose the payload forever, so each typed interface re-serves it from
// this store for as long as the operation survives the cleanup-grace window.
// The store lives inside the channel, which lives inside the OperationBase, so
// eviction is the operation's own teardown: cleanup-grace GC after finish, card
// removal, or owner-client disconnect all destroy the op — and the retained
// payload with it. The retained payload (identity fields / certificate
// metadata / photo bytes / signed artifact) lives ONLY in agent RAM until that
// eviction — never persisted; same policy for all four operation kinds.
// `ready` is set only on a successful publish of an Ok result; GetResult maps
// an un-ready store to Error.NoResult.
template <typename Payload>
struct TypedResultState
{
    std::mutex mutex;
    bool ready{false};
    Payload payload;
};

// One store flavour per typed sub-interface (the ResultPayload variant arms).
using IdentityResultState = TypedResultState<CardReadSnapshot>;
using CertificatesResultState = TypedResultState<std::vector<CertSnapshot>>;
using PhotoResultState = TypedResultState<PhotoResult>;
using SignResultState = TypedResultState<SignedArtifact>;
// SignBatch1 retains the raw (possibly empty, per failed row) row bytes —
// exactly like PhotoResultState retains raw photo bytes — so every
// SignBatch1.GetResult mints FRESH sealed memfds rather than re-serving fds
// that were already handed to (and closed by) an earlier recipient.
using SignBatchResultState = TypedResultState<BatchSignResult>;
// Credentials1 delivers inline (a{sv} + aa{sv}, no memfd seal), so it reuses the
// same publishResult / readStoredResult inline path as Identity/Certificates.
using CredentialsResultState = TypedResultState<CredentialResult>;

// Writer side for the inline-payload channels (Identity/Certificates/Photo):
// copy @p payload into @p state and mark it ready — `ready` is written LAST so
// a copy failure (bad_alloc) leaves the store UNPUBLISHED and a racing
// GetResult maps to Error.NoResult (fail closed at the store; the caller
// decides whether the op itself fails open or closed per its wire contract).
// Locks @p state internally.
template <typename Payload>
[[nodiscard]] bool publishResult(TypedResultState<Payload>& state, const Payload& payload) noexcept
{
    try {
        std::lock_guard lock(state.mutex);
        state.payload = payload; // copy may throw; `ready` still false then
        state.ready = true;
    } catch (...) {
        return false; // store stays unpublished — GetResult fails closed
    }
    return true;
}

// Reader side for the inline-payload channels: copy the retained payload out
// while @p state is ready (the operation finished Ok and published). nullopt =
// no result available (not ready, or the copy-out failed) so the adaptor can
// map it to Error.NoResult. Fetch does NOT evict: a client may recover the
// same payload more than once while the op survives the cleanup grace (mirrors
// Sign1.GetResult's repeatable re-dup). Locks @p state internally.
template <typename Payload>
[[nodiscard]] std::optional<Payload> readStoredResult(TypedResultState<Payload>& state) noexcept
{
    try {
        std::lock_guard lock(state.mutex);
        if (!state.ready) {
            return std::nullopt;
        }
        return state.payload; // copy
    } catch (...) {
        return std::nullopt;
    }
}

// A freshly sealed copy of a stored signed artifact, for Sign1.GetResult
// recovery. fd < 0 means "no result available" (the operation has not finished
// Ok, or the re-seal failed). The caller owns the fd.
struct SealedSignResult
{
    int fd{-1};
    SignMeta meta;
};

// Re-dup the stored artifact into a fresh sealed memfd while @p state is ready
// (the operation finished Ok). Locks @p state internally. Returns fd == -1 when
// no result is available so the adaptor can map that to Error.NoResult.
[[nodiscard]] SealedSignResult sealStoredResult(SignResultState& state) noexcept;

// The seal primitive: allocate a fresh sealed memfd holding @p bytes and return
// its fd (caller owns it), or -1 on failure. SealedMemfd::create in production; a
// test injects a forced failure. A plain noexcept function pointer (not a
// std::function), so holding/passing the seal callback needs no heap allocation.
// (publishSealedResult itself DOES allocate — it copies @p bytes into the store —
// but does so under a try/catch, hence noexcept.)
using SealFn = int (*)(std::span<const std::uint8_t>) noexcept;

// One re-sealed photo for Photo1.GetResult recovery: the "groupKey:fieldKey"
// wire key plus a fresh sealed memfd of the retained bytes. The caller owns
// every fd.
struct SealedPhoto
{
    std::string key;
    int fd{-1};
};

// Re-seal the retained photos into fresh sealed memfds while @p state is ready
// (the operation finished Ok). The store retains raw BYTES, not fds — exactly
// like the Sign artifact — so every fetch mints independent sealed memfds and
// eviction (op teardown) frees plain memory with no fd bookkeeping. Entries
// with empty bytes are skipped, mirroring the Photo1.Result emit. nullopt when
// no result is available OR any REQUIRED re-seal fails (fail closed —
// already-sealed fds are closed, none leak) so the adaptor maps it to
// Error.NoResult. Locks @p state internally.
[[nodiscard]] std::optional<std::vector<SealedPhoto>> sealStoredPhotos(PhotoResultState& state, SealFn seal) noexcept;

// Writer side of the Sign recovery store — the fail-closed inverse of
// sealStoredResult. Seals @p bytes via @p seal and, ONLY on a successful seal,
// publishes {bytes, meta, ready=true} into @p state as the late-subscriber
// recovery source; returns the sealed fd (caller owns it). On a seal failure (or
// an allocation failure while copying into @p state) returns -1 and leaves
// @p state UNPUBLISHED — `ready` stays false — so a Sign1.GetResult that races
// the failure during the cleanup grace maps to Error.NoResult (fail closed)
// rather than re-sealing an artifact the client was already told failed.
// Ordering is load-bearing: the store must NOT be marked ready before the seal
// succeeds. The publish still precedes the caller's Result signal, so a late
// subscriber that races the signal recovers the artifact while the op survives
// the cleanup-grace window. Locks @p state internally.
[[nodiscard]] int publishSealedResult(SignResultState& state, std::span<const std::uint8_t> bytes, const SignMeta& meta,
                                      SealFn seal) noexcept;

// Writer + result-signal emit for the Sign channel: fail-CLOSED on the seal,
// fail-OPEN once the seal has succeeded. Seals @p bytes via @p seal and publishes
// the recovery store on success (publishSealedResult); then, ONLY when the seal
// succeeded, hands the sealed fd to @p emit (which adopts it and marshals the
// Sign1.Result signal). The bool return is exactly what OperationChannel::emitResult
// reports, so it drives the op's terminal status:
//   - seal FAILURE (fd < 0): returns false. The op finishes Error, @p emit is
//     never invoked, the store stays UNREADY, and a racing Sign1.GetResult maps to
//     Error.NoResult — fail closed, because nothing was published.
//   - seal SUCCESS, then @p emit THROWS: the throw is logged and SWALLOWED and the
//     function returns TRUE — fail OPEN. The store is already published (ready), so
//     the op finishes Ok and the client recovers the artifact via Sign1.GetResult.
//     Returning false here would report Error while the ready store still serves the
//     genuine artifact to a late GetResult — the inconsistency this arm closes.
//   - seal SUCCESS, @p emit returns normally: returns true.
// @p emit receives the sealed fd and MUST adopt it (take ownership) so the fd is
// closed on every path, including its own throw. noexcept: any exception escaping
// @p emit is caught here; @p emit is invoked at most once.
template <typename EmitFn>
[[nodiscard]] bool sealPublishAndEmitSignResult(SignResultState& state, std::span<const std::uint8_t> bytes,
                                                const SignMeta& meta, SealFn seal, EmitFn&& emit) noexcept
{
    const int fd = publishSealedResult(state, bytes, meta, seal);
    if (fd < 0) {
        return false; // fail closed: seal failed, store stays unready, op finishes Error
    }
    // Seal succeeded -> the recovery store is READY. The op MUST finish Ok to stay
    // consistent with the ready store, so an emit throw is swallowed (fail OPEN).
    try {
        std::forward<EmitFn>(emit)(fd);
    } catch (const std::exception& ex) {
        log::warnf("TypedResultStore: Sign1.Result emit failed after a successful seal "
                   "(store ready; client recovers via Sign1.GetResult): {}",
                   ex.what());
    } catch (...) {
        log::warn("TypedResultStore: Sign1.Result emit failed after a successful seal "
                  "(store ready; client recovers via Sign1.GetResult)");
    }
    return true;
}

// One re-sealed SignBatch1 row, for both the Result-signal emit and
// SignBatch1.GetResult recovery. `fd` is ALWAYS a real (possibly zero-length)
// sealed memfd — never -1 on a successful call into either helper below — the
// zero-length convention IS how a failed row's artifact is represented on the
// wire, mirroring SealedSignResult but per-row and never "no result" for an
// individual row (only the WHOLE batch can be "no result": not ready, or the
// operation never attempted a document).
struct SealedBatchRow
{
    std::string displayName;
    int fd{-1};
    SignMeta meta;
    ErrorCode code{ErrorCode::None};
};

// Seal EVERY row in @p rows via @p seal — a zero-length span (a failed row's
// empty `bytes`) is itself a VALID seal, not a failure, mirroring the wire's
// own zero-length-sealed-memfd convention for a failed row — and, ONLY once
// every seal in the batch has succeeded, publish {rows, ready=true} into
// @p state as the late-subscriber recovery source (SignBatch1.GetResult
// reseals from this store). Returns the sealed rows (caller owns EVERY fd)
// in request order on success. On any REQUIRED seal failure (a real OS-level
// memfd failure, not an empty span) — or an allocation failure copying into
// @p state — closes every fd already sealed THIS call and returns nullopt,
// leaving @p state UNPUBLISHED: a SignBatch1.GetResult that races the
// failure during the cleanup grace maps to Error.NoResult, exactly like
// Sign1's own publishSealedResult. Ordering is load-bearing: the store must
// never be marked ready before every seal in the batch has succeeded.
[[nodiscard]] std::optional<std::vector<SealedBatchRow>>
publishSealedSignBatchResult(SignBatchResultState& state, const BatchSignResult& rows, SealFn seal) noexcept;

// Re-seal EVERY retained row into FRESH sealed memfds for SignBatch1.GetResult
// recovery, while @p state is ready (the operation attempted at least one
// document). Unlike Photo1's sealStoredPhotos this NEVER skips an
// empty-bytes row: SignBatch1's wire shape is a positional array (one
// element per requested document), so a failed row's zero-length seal is
// itself the wire contract, not an omission to collapse away. nullopt when
// no result is available or any reseal fails (fail closed; already-sealed
// fds close via ::close, none leak).
[[nodiscard]] std::optional<std::vector<SealedBatchRow>> sealStoredSignBatchResult(SignBatchResultState& state,
                                                                                   SealFn seal) noexcept;

} // namespace LibreSCRS::Agent::Operations
