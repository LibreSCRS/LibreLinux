// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Late-subscriber recovery store for the inline typed results
// (Identity1/Certificates1/Photo1.GetResult) — the generalisation of the
// reviewed Sign1 store, whose seal-specific suite lives in SignFlowTest.cpp.
// Semantics mirrored 1:1 from that suite: an unpublished store yields NoResult,
// a published one serves the payload repeatedly (fetch does NOT evict), a
// publish failure leaves the store unready (fail closed), and the Photo re-seal
// mints independent byte-identical sealed memfds per fetch — retaining BYTES,
// never fds (eviction is the op's own teardown: cleanup-grace GC, card removal,
// owner disconnect all destroy the channel that owns the store).
#include "SealedMemfd.h"
#include "dbus/TypedResultStore.h"

#include <gtest/gtest.h>
#include <sys/mman.h>
#include <unistd.h>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <new> // std::bad_alloc
#include <optional>
#include <span>
#include <vector>

using namespace LibreSCRS::Agent;
using namespace LibreSCRS::Agent::Operations;

namespace {

// Count this process's open fds — the leak probe for the fail-closed paths.
std::size_t openFdCount()
{
    std::size_t n = 0;
    for ([[maybe_unused]] const auto& e : std::filesystem::directory_iterator("/proc/self/fd")) {
        ++n;
    }
    return n;
}

CardReadSnapshot makeSnapshot()
{
    CardReadSnapshot snap;
    GroupSnapshot group;
    group.groupKey = "personal";
    FieldSnapshot field;
    field.fieldKey = "given_name";
    field.labelKey = "label_given_name";
    field.labelFallback = "Given name";
    field.type = FieldType::Text;
    field.textValue = "Ana";
    group.fields.push_back(field);
    snap.groups.push_back(group);
    return snap;
}

} // namespace

// --- generic store (Identity/Certificates arms) ----------------------------

TEST(TypedResultStore, NotReadyYieldsNoResult)
{
    IdentityResultState state;
    EXPECT_FALSE(readStoredResult(state).has_value()) << "an unfinished/failed op has no recoverable payload";
}

TEST(TypedResultStore, PublishThenReadRoundTripsAndFetchDoesNotEvict)
{
    IdentityResultState state;
    ASSERT_TRUE(publishResult(state, makeSnapshot()));

    auto first = readStoredResult(state);
    ASSERT_TRUE(first.has_value());
    ASSERT_EQ(first->groups.size(), 1u);
    EXPECT_EQ(first->groups[0].groupKey, "personal");
    ASSERT_EQ(first->groups[0].fields.size(), 1u);
    EXPECT_EQ(first->groups[0].fields[0].textValue, "Ana");

    // A second recovery serves the same payload — fetch does NOT evict
    // (mirrors Sign1.GetResult's repeatable re-dup).
    auto second = readStoredResult(state);
    ASSERT_TRUE(second.has_value());
    EXPECT_EQ(second->groups[0].fields[0].textValue, "Ana");
}

namespace {

// A payload whose copy-assignment throws on demand — models the bad_alloc a
// publish copy can hit, so the fail-closed arm is exercised deterministically.
struct ThrowingPayload
{
    static inline bool throwOnCopy = false;
    int value{0};

    ThrowingPayload() = default;
    ThrowingPayload(const ThrowingPayload& other) : value(other.value)
    {
        maybeThrow();
    }
    ThrowingPayload& operator=(const ThrowingPayload& other)
    {
        maybeThrow();
        value = other.value;
        return *this;
    }
    ThrowingPayload(ThrowingPayload&&) = default;
    ThrowingPayload& operator=(ThrowingPayload&&) = default;
    ~ThrowingPayload() = default;

private:
    static void maybeThrow()
    {
        if (throwOnCopy) {
            throw std::bad_alloc{};
        }
    }
};

} // namespace

TEST(TypedResultStore, PublishCopyFailureLeavesStoreUnready)
{
    TypedResultState<ThrowingPayload> state;
    ThrowingPayload payload;
    payload.value = 7;

    ThrowingPayload::throwOnCopy = true;
    EXPECT_FALSE(publishResult(state, payload)) << "a publish copy failure reports false";
    ThrowingPayload::throwOnCopy = false;

    // Fail closed: the store stays unpublished, GetResult maps to NoResult.
    EXPECT_FALSE(readStoredResult(state).has_value()) << "a failed publish must not leave a half-published store";

    // And a subsequent successful publish still works (no poisoned state).
    ASSERT_TRUE(publishResult(state, payload));
    auto read = readStoredResult(state);
    ASSERT_TRUE(read.has_value());
    EXPECT_EQ(read->value, 7);
}

// --- Photo re-seal (bytes retained, fresh sealed memfds per fetch) ---------

TEST(TypedResultStorePhoto, NotReadyYieldsNoResult)
{
    PhotoResultState state;
    EXPECT_FALSE(sealStoredPhotos(state, &SealedMemfd::create).has_value())
        << "an unfinished/failed op has no recoverable photos";
}

TEST(TypedResultStorePhoto, ReSealsByteIdenticalIndependentFdsAndSkipsEmptyEntries)
{
    PhotoResultState state;
    const std::vector<std::uint8_t> bytes{0x89, 'P', 'N', 'G', 0x0D, 0x0A};
    ASSERT_TRUE(publishResult(
        state, PhotoResult{{"personal:photo", bytes}, {"supplementary:photo", {}}})); // empty entry — skipped on fetch

    auto sealed = sealStoredPhotos(state, &SealedMemfd::create);
    ASSERT_TRUE(sealed.has_value());
    ASSERT_EQ(sealed->size(), 1u) << "empty-bytes entries are skipped, mirroring the Photo1.Result emit";
    EXPECT_EQ((*sealed)[0].key, "personal:photo");
    ASSERT_GE((*sealed)[0].fd, 0);

    const auto size = ::lseek((*sealed)[0].fd, 0, SEEK_END);
    ASSERT_EQ(size, static_cast<off_t>(bytes.size()));
    void* p = ::mmap(nullptr, bytes.size(), PROT_READ, MAP_PRIVATE, (*sealed)[0].fd, 0);
    ASSERT_NE(p, MAP_FAILED);
    EXPECT_EQ(0, std::memcmp(p, bytes.data(), bytes.size()));
    ::munmap(p, bytes.size());

    // A second recovery mints an INDEPENDENT, equally byte-identical memfd —
    // the store retains bytes, never fds.
    auto again = sealStoredPhotos(state, &SealedMemfd::create);
    ASSERT_TRUE(again.has_value());
    ASSERT_EQ(again->size(), 1u);
    ASSERT_GE((*again)[0].fd, 0);
    EXPECT_NE((*again)[0].fd, (*sealed)[0].fd);

    ::close((*sealed)[0].fd);
    ::close((*again)[0].fd);
}

namespace {
int failingSeal(std::span<const std::uint8_t>) noexcept
{
    return -1;
}
// Fails on the SECOND photo, so the first one is already sealed when the
// failure hits — exercising the close-what-was-sealed cleanup.
int failSecondSeal(std::span<const std::uint8_t>) noexcept
{
    static int calls = 0;
    if (++calls >= 2) {
        calls = 0;
        return -1;
    }
    return SealedMemfd::create(std::span<const std::uint8_t>{});
}
} // namespace

TEST(TypedResultStorePhoto, SealFailureFailsClosedAndLeaksNoFd)
{
    PhotoResultState state;
    ASSERT_TRUE(publishResult(state, PhotoResult{{"personal:photo", {0x01}}, {"supplementary:photo", {0x02}}}));

    const std::size_t before = openFdCount();

    // Total seal failure: NoResult, nothing leaks.
    EXPECT_FALSE(sealStoredPhotos(state, &failingSeal).has_value())
        << "a re-seal failure yields NoResult (fail closed), never a half-map";

    // Partial failure (first seals, second fails): the already-sealed fd is
    // closed on the way out.
    EXPECT_FALSE(sealStoredPhotos(state, &failSecondSeal).has_value());

    EXPECT_EQ(openFdCount(), before) << "no sealed fd may outlive a failed recovery fetch";

    // The store itself stays READY — the retained bytes are intact and a later
    // fetch with a working sealer succeeds.
    auto sealed = sealStoredPhotos(state, &SealedMemfd::create);
    ASSERT_TRUE(sealed.has_value());
    ASSERT_EQ(sealed->size(), 2u);
    for (const auto& s : *sealed) {
        ::close(s.fd);
    }
}

// --- SignBatch re-seal (bytes retained; EVERY row gets a fresh fd, never
//     skipped — a failed row's zero-length seal IS the wire contract, unlike
//     Photo's empty-bytes-is-omitted convention) -----------------------------

namespace {
BatchSignedRow makeRow(std::string name, std::vector<std::uint8_t> bytes, ErrorCode code)
{
    return BatchSignedRow{
        .displayName = std::move(name),
        .bytes = std::move(bytes),
        .meta = SignMeta{.format = "pades", .level = "b-b", .tsaUsed = false, .chainComplete = true},
        .code = code,
    };
}

// A DEDICATED counter (not Photo's shared failSecondSeal above): sharing a
// static call-counter across unrelated test bodies is a latent coupling this
// section deliberately avoids by owning its own.
int failSecondSignBatchSeal(std::span<const std::uint8_t>) noexcept
{
    static int calls = 0;
    ++calls;
    return (calls >= 2) ? -1 : SealedMemfd::create(std::span<const std::uint8_t>{});
}
} // namespace

TEST(TypedResultStoreSignBatch, NotReadyYieldsNoResult)
{
    SignBatchResultState state;
    EXPECT_FALSE(sealStoredSignBatchResult(state, &SealedMemfd::create).has_value())
        << "an unfinished/failed op has no recoverable rows";
}

TEST(TypedResultStoreSignBatch, PublishSealsEveryRowIncludingAZeroLengthFailedRow)
{
    SignBatchResultState state;
    BatchSignResult rows{
        makeRow("a.pdf", {0x01, 0x02, 0x03}, ErrorCode::None),
        makeRow("b.pdf", {}, ErrorCode::CredentialBlocked), // failed row: zero-length bytes
    };

    auto sealed = publishSealedSignBatchResult(state, rows, &SealedMemfd::create);
    ASSERT_TRUE(sealed.has_value());
    ASSERT_EQ(sealed->size(), 2u);

    // Row 0: a real, non-empty sealed artifact.
    EXPECT_EQ((*sealed)[0].displayName, "a.pdf");
    EXPECT_EQ((*sealed)[0].code, ErrorCode::None);
    ASSERT_GE((*sealed)[0].fd, 0);
    {
        const auto size = ::lseek((*sealed)[0].fd, 0, SEEK_END);
        ASSERT_EQ(size, 3);
        void* p = ::mmap(nullptr, 3, PROT_READ, MAP_PRIVATE, (*sealed)[0].fd, 0);
        ASSERT_NE(p, MAP_FAILED);
        const std::vector<std::uint8_t> expected{0x01, 0x02, 0x03};
        EXPECT_EQ(0, std::memcmp(p, expected.data(), expected.size()));
        ::munmap(p, 3);
    }

    // Row 1: a REAL, ACTUALLY SEALED zero-length fd — never -1, never
    // omitted. This is the pinned failed-row convention: a non-nullable
    // D-Bus `h` still resolves a genuine descriptor.
    EXPECT_EQ((*sealed)[1].displayName, "b.pdf");
    EXPECT_EQ((*sealed)[1].code, ErrorCode::CredentialBlocked);
    ASSERT_GE((*sealed)[1].fd, 0) << "a failed row's artifact fd must be a REAL (sealed) descriptor, not -1";
    EXPECT_EQ(::lseek((*sealed)[1].fd, 0, SEEK_END), 0) << "a failed row's sealed memfd must be zero-length";

    for (const auto& s : *sealed) {
        ::close(s.fd);
    }
}

TEST(TypedResultStoreSignBatch, GetResultRecoveryReSealsByteIdenticalIndependentFdsForEveryRow)
{
    SignBatchResultState state;
    BatchSignResult rows{
        makeRow("a.pdf", {0xAA, 0xBB}, ErrorCode::None),
        makeRow("b.pdf", {}, ErrorCode::CredentialBlocked),
    };
    auto published = publishSealedSignBatchResult(state, rows, &SealedMemfd::create);
    ASSERT_TRUE(published.has_value());
    for (const auto& s : *published) {
        ::close(s.fd); // the "Result signal" recipient's copy; recovery mints its own
    }

    // GetResult-equivalent recovery: mints FRESH fds for BOTH rows, never
    // skipping the zero-length one (unlike Photo's omission of empty bytes).
    auto sealed = sealStoredSignBatchResult(state, &SealedMemfd::create);
    ASSERT_TRUE(sealed.has_value());
    ASSERT_EQ(sealed->size(), 2u);
    ASSERT_GE((*sealed)[0].fd, 0);
    EXPECT_EQ(::lseek((*sealed)[0].fd, 0, SEEK_END), 2);
    ASSERT_GE((*sealed)[1].fd, 0) << "the failed row is STILL present and STILL sealed on recovery";
    EXPECT_EQ(::lseek((*sealed)[1].fd, 0, SEEK_END), 0);

    // A second recovery mints INDEPENDENT fds (fetch does not evict; the
    // store retains bytes, never fds).
    auto again = sealStoredSignBatchResult(state, &SealedMemfd::create);
    ASSERT_TRUE(again.has_value());
    ASSERT_EQ(again->size(), 2u);
    EXPECT_NE((*again)[0].fd, (*sealed)[0].fd);
    EXPECT_NE((*again)[1].fd, (*sealed)[1].fd);

    for (const auto& s : *sealed) {
        ::close(s.fd);
    }
    for (const auto& s : *again) {
        ::close(s.fd);
    }
}

TEST(TypedResultStoreSignBatch, SealFailureFailsClosedAndLeaksNoFd)
{
    SignBatchResultState state;
    BatchSignResult rows{
        makeRow("a.pdf", {0x01}, ErrorCode::None),
        makeRow("b.pdf", {0x02}, ErrorCode::None),
    };

    const std::size_t before = openFdCount();

    // A REQUIRED seal failure (a real OS-level memfd failure, modelled here)
    // must publish NOTHING: the store stays unready, a racing GetResult maps
    // to Error.NoResult rather than half-publishing the batch.
    EXPECT_FALSE(publishSealedSignBatchResult(state, rows, &failingSeal).has_value());
    EXPECT_FALSE(sealStoredSignBatchResult(state, &SealedMemfd::create).has_value())
        << "a failed publish must not leave a half-published store";
    EXPECT_EQ(openFdCount(), before) << "no sealed fd may outlive a failed publish attempt";

    // A partial failure (first row seals, second fails) leaks no fd either —
    // the already-sealed first row's fd is closed on the way out.
    EXPECT_FALSE(publishSealedSignBatchResult(state, rows, &failSecondSignBatchSeal).has_value());
    EXPECT_EQ(openFdCount(), before);

    // A subsequent successful publish still works (no poisoned state).
    auto sealed = publishSealedSignBatchResult(state, rows, &SealedMemfd::create);
    ASSERT_TRUE(sealed.has_value());
    ASSERT_EQ(sealed->size(), 2u);
    for (const auto& s : *sealed) {
        ::close(s.fd);
    }
}
