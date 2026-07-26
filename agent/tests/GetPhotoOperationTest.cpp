// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "SealedMemfd.h"
#include <LibreSCRS/Agent/operations/CardSessionHolder.h>
#include "operations/GetPhotoOperation.h"
#include <LibreSCRS/Agent/operations/PromptSerializer.h>

#include <LibreSCRS/SmartCard/CardMap.h>
#include <LibreSCRS/SmartCard/CardSession.h>
#include <gtest/gtest.h>
#include <sys/mman.h>
#include <unistd.h>
#include <cstring>
#include <expected>
#include <map>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

using namespace LibreSCRS::Agent;
using namespace LibreSCRS::Agent::Operations;

namespace {

struct EmittedFinish
{
    std::uint32_t status;
    std::uint32_t errorCode;
};

class FakeOperationChannel final : public OperationChannel
{
public:
    void emitFinished(OperationStatus status, ErrorCode errorCode, std::string_view, std::string_view) noexcept override
    {
        finishes.push_back({static_cast<std::uint32_t>(status), static_cast<std::uint32_t>(errorCode)});
    }
    void emitPropertiesChanged() noexcept override {}
    bool emitResult(const ResultPayload& result) noexcept override
    {
        // The core yields raw photo bytes (no memfd in the op); the backend
        // channel is what seals them. Capture the raw bytes keyed by
        // "groupKey:fieldKey". `deliver` false models a backend memfd seal failure
        // so the op's restored fail-closed path can be exercised.
        if (const auto* photos = std::get_if<PhotoResult>(&result)) {
            for (const auto& p : *photos) {
                captured.emplace(p.key, p.bytes);
            }
        }
        return deliver;
    }
    bool deliver{true};
    std::vector<EmittedFinish> finishes;
    std::map<std::string, std::vector<std::uint8_t>> captured;
};

CardReadSnapshot snapshotWithPhotos()
{
    CardReadSnapshot snap;
    snap.cardType = "rs-eid";
    snap.groups.push_back({"personal",
                           "group.personal",
                           "Personal",
                           {{"given_name", "field.given_name", "Given name", FieldType::Text, "ANA", {}}}});
    snap.groups.push_back(
        {"photo",
         "group.photo",
         "Photo",
         {{"portrait", "field.portrait", "Portrait", FieldType::Photo, "", {0xFF, 0xD8, 0xFF, 0xE0}}}});
    return snap;
}

// Holder whose factory fails the test if invoked: the cache-hot path must never
// acquire a session.
inline std::unique_ptr<CardSessionHolder> makeUnusedHolder()
{
    auto factory = [](const std::string& r)
        -> std::expected<std::shared_ptr<LibreSCRS::SmartCard::CardSession>, LibreSCRS::SmartCard::OpenError> {
        ADD_FAILURE() << "holder must not open a session when cache is hot";
        return LibreSCRS::SmartCard::detail::makeDetachedCardSession(r);
    };
    auto resolver = [](std::span<const std::uint8_t>, LibreSCRS::SmartCard::CardSession&) { return CandidateList{}; };
    return std::make_unique<CardSessionHolder>("Unused", std::move(factory), std::move(resolver),
                                               std::make_shared<LibreSCRS::SmartCard::CardMap>());
}
class UnusedReader final : public CardReader
{
public:
    ReadOutcome read(LibreSCRS::SmartCard::CardSession&, const CandidateList&, LibreSCRS::CancelToken,
                     GroupReadCallback = {}) override
    {
        ADD_FAILURE() << "reader must not run when cache is hot";
        return ReadOutcome{};
    }
    GroupSnapshot readTokenInfo(LibreSCRS::SmartCard::CardSession&, const CandidateList&,
                                LibreSCRS::CancelToken) override
    {
        ADD_FAILURE() << "readTokenInfo is not exercised by this suite";
        return {};
    }
};
class UnusedPrompter final : public PrompterClientBase
{
public:
    PromptResult requestPin(const PromptOptions&) override
    {
        return {};
    }
    PromptResult requestCan(const PromptOptions&) override
    {
        return {};
    }
    PromptResult requestMrz(const PromptOptions&) override
    {
        return {};
    }
};

} // namespace

TEST(SealedMemfd, RoundTripsBytes)
{
    const std::vector<std::uint8_t> payload{0xFF, 0xD8, 0xFF, 0xE0};
    const int fd = SealedMemfd::create(std::span<const std::uint8_t>{payload});
    ASSERT_GE(fd, 0);

    const auto size = ::lseek(fd, 0, SEEK_END);
    ASSERT_EQ(size, static_cast<off_t>(payload.size()));
    void* p = ::mmap(nullptr, payload.size(), PROT_READ, MAP_PRIVATE, fd, 0);
    ASSERT_NE(p, MAP_FAILED);
    EXPECT_EQ(0, std::memcmp(p, payload.data(), payload.size()));
    ::munmap(p, payload.size());
    ::close(fd);
}

TEST(GetPhotoOperation, CacheHitSkipsFlowAndEmitsPhoto)
{
    CardReadCache readCache;
    readCache.put("card-A", snapshotWithPhotos());
    auto holder = makeUnusedHolder();
    UnusedReader reader;
    UnusedPrompter prompter;
    PromptSerializer serializer;
    CredentialCache credCache;

    auto adaptor = std::make_unique<FakeOperationChannel>();
    auto* raw = adaptor.get();

    auto state = std::make_shared<OperationState>();
    GetPhotoOperation op(std::move(adaptor),
                         GetPhotoOperation::Deps{
                             .holder = holder.get(),
                             .reader = reader,
                             .prompter = prompter,
                             .serializer = serializer,
                             .credentials = credCache,
                             .readCache = readCache,
                             .cardKey = "card-A",
                             .readerName = "FakeReader",
                         },
                         state);
    op.runOnWorker();

    ASSERT_EQ(raw->finishes.size(), 1u);
    EXPECT_EQ(raw->finishes[0].status, 0u);
    ASSERT_EQ(raw->captured.size(), 1u);
    ASSERT_TRUE(raw->captured.contains("photo:portrait"));
    // The op yields the raw JPEG bytes verbatim; sealing into a memfd is the
    // backend channel's job, not the op's.
    EXPECT_EQ(raw->captured.at("photo:portrait"), (std::vector<std::uint8_t>{0xFF, 0xD8, 0xFF, 0xE0}));
}

// Restored fail-closed contract: when the backend channel's memfd seal fails
// (emitResult returns false), the op finishes Error(CommunicationError,
// "op.memfd_failed") rather than leaking Finished(Ok) with no Photo1.Result.
TEST(GetPhotoOperation, MemfdSealFailureFinishesErrorClosed)
{
    CardReadCache readCache;
    readCache.put("card-A", snapshotWithPhotos());
    auto holder = makeUnusedHolder();
    UnusedReader reader;
    UnusedPrompter prompter;
    PromptSerializer serializer;
    CredentialCache credCache;

    auto adaptor = std::make_unique<FakeOperationChannel>();
    adaptor->deliver = false; // model a backend memfd seal failure
    auto* raw = adaptor.get();

    auto state = std::make_shared<OperationState>();
    GetPhotoOperation op(std::move(adaptor),
                         GetPhotoOperation::Deps{
                             .holder = holder.get(),
                             .reader = reader,
                             .prompter = prompter,
                             .serializer = serializer,
                             .credentials = credCache,
                             .readCache = readCache,
                             .cardKey = "card-A",
                             .readerName = "FakeReader",
                         },
                         state);
    op.runOnWorker();

    ASSERT_EQ(raw->finishes.size(), 1u);
    EXPECT_EQ(raw->finishes[0].status, static_cast<std::uint32_t>(OperationStatus::Error));
    EXPECT_EQ(raw->finishes[0].errorCode, static_cast<std::uint32_t>(ErrorCode::CommunicationError));
}

TEST(GetPhotoOperation, NoPhotoFieldYieldsError)
{
    CardReadCache readCache;
    CardReadSnapshot photoless;
    photoless.cardType = "rs-eid";
    photoless.groups.push_back({"personal", "group.personal", "Personal", {}});
    readCache.put("card-A", photoless);
    auto holder = makeUnusedHolder();
    UnusedReader reader;
    UnusedPrompter prompter;
    PromptSerializer serializer;
    CredentialCache credCache;

    auto adaptor = std::make_unique<FakeOperationChannel>();
    auto* raw = adaptor.get();
    auto state = std::make_shared<OperationState>();
    GetPhotoOperation op(std::move(adaptor),
                         GetPhotoOperation::Deps{
                             .holder = holder.get(),
                             .reader = reader,
                             .prompter = prompter,
                             .serializer = serializer,
                             .credentials = credCache,
                             .readCache = readCache,
                             .cardKey = "card-A",
                             .readerName = "FakeReader",
                         },
                         state);
    op.runOnWorker();
    ASSERT_EQ(raw->finishes.size(), 1u);
    EXPECT_EQ(raw->finishes[0].status, 2u);
    EXPECT_TRUE(raw->captured.empty());
}
