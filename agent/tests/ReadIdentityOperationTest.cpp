// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Worker-side semantics. A fake OperationChannel captures emits; Fake seams
// drive the flow. No bus, no LM.

#include <LibreSCRS/Agent/operations/CardSessionHolder.h>
#include <LibreSCRS/Agent/operations/PromptSerializer.h>
#include "operations/ReadIdentityOperation.h"

#include <LibreSCRS/SmartCard/CardMap.h>
#include <LibreSCRS/SmartCard/CardSession.h>
#include <gtest/gtest.h>
#include <expected>
#include <memory>
#include <span>
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
        if (const auto* snap = std::get_if<CardReadSnapshot>(&result)) {
            identityEmits.push_back(*snap);
        }
        return true;
    }
    std::vector<EmittedFinish> finishes;
    std::vector<CardReadSnapshot> identityEmits;
};
static_assert(std::variant_size_v<ResultPayload> == 6,
              "ResultPayload is a closed variant: 5 Card1 result arms (Identity/Certificates/Photo/Sign/SignBatch) + "
              "the Credentials1 arm");

inline std::unique_ptr<CardSessionHolder> makeHolder()
{
    auto factory = [](const std::string& r)
        -> std::expected<std::shared_ptr<LibreSCRS::SmartCard::CardSession>, LibreSCRS::SmartCard::OpenError> {
        return LibreSCRS::SmartCard::detail::makeDetachedCardSession(r);
    };
    auto resolver = [](std::span<const std::uint8_t>, LibreSCRS::SmartCard::CardSession&) { return CandidateList{}; };
    return std::make_unique<CardSessionHolder>("FakeReader", std::move(factory), std::move(resolver),
                                               std::make_shared<LibreSCRS::SmartCard::CardMap>());
}
class FakeReader final : public CardReader
{
public:
    ReadOutcome read(LibreSCRS::SmartCard::CardSession&, const CandidateList&, LibreSCRS::CancelToken,
                     GroupReadCallback = {}) override
    {
        ++reads;
        return outcome;
    }
    // Not exercised by this suite (ReadTokenInfoOperationTest owns dedicated
    // coverage); a well-formed default keeps this class non-abstract.
    GroupSnapshot readTokenInfo(LibreSCRS::SmartCard::CardSession&, const CandidateList&,
                                LibreSCRS::CancelToken) override
    {
        return {};
    }
    ReadOutcome outcome;
    int reads = 0; ///< how many times the card was actually walked
};
class FakePrompter final : public PrompterClientBase
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

CardReadSnapshot snapshotWithPhoto()
{
    CardReadSnapshot snap;
    snap.cardType = "rs-eid";
    snap.groups.push_back({"personal",
                           "group.personal",
                           "Personal",
                           {{"given_name", "field.given_name", "Given name", FieldType::Text, "ANA", {}}}});
    snap.groups.push_back({"photo",
                           "group.photo",
                           "Photo",
                           {{"portrait", "field.portrait", "Portrait", FieldType::Photo, "", {0xFF, 0xD8, 0xFF}}}});
    return snap;
}

} // namespace

TEST(ReadIdentityOperation, SuccessPathPopulatesCacheEmitsResultThenFinishes)
{
    auto holder = makeHolder();
    FakeReader reader;
    reader.outcome = ReadOutcome{ReadOutcome::Status::Ok, snapshotWithPhoto(), ""};
    FakePrompter prompter;
    PromptSerializer serializer;
    CredentialCache credCache;
    CardReadCache readCache;

    auto adaptor = std::make_unique<FakeOperationChannel>();
    auto* raw = adaptor.get();

    auto state = std::make_shared<OperationState>();
    ReadIdentityOperation op(std::move(adaptor),
                             ReadIdentityOperation::Deps{
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
    EXPECT_EQ(raw->finishes[0].status, 0u) << "OperationStatus::Ok";
    EXPECT_EQ(raw->finishes[0].errorCode, 0u);

    ASSERT_EQ(raw->identityEmits.size(), 1u);
    EXPECT_EQ(raw->identityEmits[0].cardType, "rs-eid");

    auto cached = readCache.get("card-A");
    ASSERT_TRUE(cached.has_value());
    EXPECT_EQ(cached->groups.size(), 2u) << "cache stores the full snapshot (photos included)";
}

// A re-read of a still-seated card (master-detail browsing / a reader switch
// back to it) must be served from the per-card read cache — the same cache
// GetPhoto already consults and that ReadIdentity itself populates — instead of
// re-walking the eID data groups. Without this the identity half of the cache
// is write-only from ReadIdentity's side, so every switch re-reads the card
// (the "reader switch is slow" symptom).
TEST(ReadIdentityOperation, SecondReadOfSameCardServesFromCacheWithoutReWalking)
{
    auto holder = makeHolder();
    FakeReader reader;
    reader.outcome = ReadOutcome{ReadOutcome::Status::Ok, snapshotWithPhoto(), ""};
    FakePrompter prompter;
    PromptSerializer serializer;
    CredentialCache credCache;
    CardReadCache readCache;

    // First ReadIdentity: walks the card, populates the cache, emits the result.
    {
        auto adaptor = std::make_unique<FakeOperationChannel>();
        auto* raw = adaptor.get();
        auto state = std::make_shared<OperationState>();
        ReadIdentityOperation op(std::move(adaptor),
                                 ReadIdentityOperation::Deps{
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
        ASSERT_EQ(raw->identityEmits.size(), 1u);
    }
    ASSERT_EQ(reader.reads, 1) << "the first read walks the card";
    ASSERT_TRUE(readCache.get("card-A").has_value()) << "the first read populates the cache";

    // Second ReadIdentity on the SAME still-seated card: served from cache — no
    // second card walk — yet it still emits Identity1.Result and finishes Ok.
    {
        auto adaptor = std::make_unique<FakeOperationChannel>();
        auto* raw = adaptor.get();
        auto state = std::make_shared<OperationState>();
        ReadIdentityOperation op(std::move(adaptor),
                                 ReadIdentityOperation::Deps{
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
        EXPECT_EQ(raw->finishes[0].status, 0u) << "a cached re-read still finishes Ok";
        ASSERT_EQ(raw->identityEmits.size(), 1u) << "a cached re-read still emits Identity1.Result";
        EXPECT_EQ(raw->identityEmits[0].cardType, "rs-eid");
    }
    EXPECT_EQ(reader.reads, 1) << "a second ReadIdentity on the same seated card must NOT re-walk it";
}

TEST(ReadIdentityOperation, FlowErrorMapsToFinishedError)
{
    auto holder = makeHolder();
    FakeReader reader;
    reader.outcome = ReadOutcome{ReadOutcome::Status::ParseError, std::nullopt, "malformed"};
    FakePrompter prompter;
    PromptSerializer serializer;
    CredentialCache credCache;
    CardReadCache readCache;

    auto adaptor = std::make_unique<FakeOperationChannel>();
    auto* raw = adaptor.get();

    auto state = std::make_shared<OperationState>();
    ReadIdentityOperation op(std::move(adaptor),
                             ReadIdentityOperation::Deps{
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
    EXPECT_EQ(raw->finishes[0].status, 2u) << "OperationStatus::Error";
    EXPECT_EQ(raw->finishes[0].errorCode, static_cast<std::uint32_t>(ErrorCode::ParseError));
    EXPECT_TRUE(raw->identityEmits.empty()) << "no Identity1.Result on error path";
    EXPECT_FALSE(readCache.get("card-A").has_value()) << "cache not populated on error";
}
