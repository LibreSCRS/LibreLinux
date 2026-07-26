// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Bus-less behaviour tests for the credential-management operation adaptors'
// wire-ordering contract (Operation.Credentials1.xml): the typed Result is
// available for EVERY completed attempt — success, soft-fail, user cancel and
// hard failure alike — always BEFORE Operation1.Finished; and a Result the
// channel could not deliver fails the op CLOSED (Error), never Finished(Ok)
// with a silently-missing Result. Each seam is a Fake and the ops run
// synchronously on the test thread via runOnWorker(); no bus, no card.
#include <LibreSCRS/Agent/cache/CardReadCache.h>
#include <LibreSCRS/Agent/cache/CredentialCache.h>
#include <LibreSCRS/Agent/cache/CredentialSnapshotCache.h>
#include <LibreSCRS/Agent/operations/CardSessionHolder.h>
#include <LibreSCRS/Agent/operations/PinChangeFlow.h> // PinManageRequest
#include <LibreSCRS/Agent/operations/PromptSerializer.h>
#include "operations/ActivateSigningKeyOperation.h"
#include "operations/ListCredentialsOperation.h"
#include "operations/ManagePinOperation.h"

#include <LibreSCRS/Agent/OperationState.h>
#include <LibreSCRS/Agent/backend/OperationChannel.h> // OperationChannel, ResultPayload, CredentialResult
#include <LibreSCRS/Agent/value/CredentialRecord.h>   // CredentialSnapshot, CredentialOutcome
#include <LibreSCRS/Agent/value/ErrorTaxonomy.h>      // ErrorCode
#include <LibreSCRS/CancelToken.h>
#include <LibreSCRS/LocalizedText.h>
#include <LibreSCRS/Plugin/PinStatusEntry.h>
#include <LibreSCRS/Plugin/PluginTypes.h>
#include <LibreSCRS/Secure/String.h>
#include <LibreSCRS/SmartCard/CardMap.h>
#include <LibreSCRS/SmartCard/CardSession.h>
#include <gtest/gtest.h>
#include <cstdint>
#include <expected>
#include <memory>
#include <optional>
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

// Records the ordered wire events (Result then Finished) plus the payloads so a
// test can assert BOTH the strict Result-before-Finished ordering and the
// contents. emitResultReturns=false models a channel whose (required) delivery
// step failed — the contract then demands the op finishes CLOSED.
class FakeCredentialChannel final : public OperationChannel
{
public:
    enum class Event { Result, Finish };

    bool emitResultReturns = true;

    void emitPropertiesChanged() noexcept override {}
    void emitFinished(OperationStatus status, ErrorCode code, std::string_view, std::string_view) noexcept override
    {
        events.push_back(Event::Finish);
        finishes.push_back({static_cast<std::uint32_t>(status), static_cast<std::uint32_t>(code)});
    }
    bool emitResult(const ResultPayload& result) noexcept override
    {
        if (const auto* cred = std::get_if<CredentialResult>(&result)) {
            events.push_back(Event::Result);
            results.push_back(*cred);
        }
        return emitResultReturns;
    }

    std::vector<Event> events;
    std::vector<CredentialResult> results;
    std::vector<EmittedFinish> finishes;
};

// Programmable double over the prompter: the change modal and the SIGN-PIN
// prompt return the seeded results; the CAN/MRZ surface is unused (detached
// sessions never activate a channel here).
class FakePrompter final : public PrompterClientBase
{
public:
    PromptResult pinResult{PromptStatus::Error, std::nullopt, "unseeded"};
    PinChangePromptResult pinChangeResult{PromptStatus::Error, std::nullopt, std::nullopt, "unseeded"};

    PromptResult requestPin(const PromptOptions&) override
    {
        return pinResult;
    }
    PromptResult requestCan(const PromptOptions&) override
    {
        return {};
    }
    PromptResult requestMrz(const PromptOptions&) override
    {
        return {};
    }
    PinChangePromptResult requestPinChange(const PromptOptions&) override
    {
        return pinChangeResult;
    }
};

// Scriptable CredentialManager seam double.
class FakeCredentialManager final : public CredentialManager
{
public:
    std::vector<LibreSCRS::Plugin::PinStatusEntry> listResult;
    LibreSCRS::Plugin::PINResult changePinResult{.outcome = LibreSCRS::Plugin::PINResultOutcome::Unsupported};
    LibreSCRS::Plugin::PINResult activateSigningKeyResult{.outcome = LibreSCRS::Plugin::PINResultOutcome::Unsupported};

    CredentialListing list(LibreSCRS::SmartCard::CardSession&, const CandidateList&) override
    {
        return {listResult, listResult.empty() ? std::string{} : std::string{"fake-listing-plugin"}};
    }
    LibreSCRS::Plugin::PINResult changePIN(LibreSCRS::SmartCard::CardSession&, const CandidateList&, std::string_view,
                                           const LibreSCRS::Secure::String&, const LibreSCRS::Secure::String&) override
    {
        return changePinResult;
    }
    LibreSCRS::Plugin::PINResult activateTransportPin(LibreSCRS::SmartCard::CardSession&, const CandidateList&,
                                                      std::string_view, const LibreSCRS::Secure::String&,
                                                      const LibreSCRS::Secure::String&) override
    {
        return {.outcome = LibreSCRS::Plugin::PINResultOutcome::Unsupported};
    }
    LibreSCRS::Plugin::PINResult activateSigningKey(LibreSCRS::SmartCard::CardSession&, const CandidateList&,
                                                    const LibreSCRS::Secure::String&) override
    {
        return activateSigningKeyResult;
    }
};

inline std::unique_ptr<CardSessionHolder> makeHolder(std::optional<LibreSCRS::SmartCard::OpenError> failWith)
{
    auto factory = [failWith = std::move(failWith)](const std::string& r)
        -> std::expected<std::shared_ptr<LibreSCRS::SmartCard::CardSession>, LibreSCRS::SmartCard::OpenError> {
        if (failWith) {
            return std::unexpected{*failWith};
        }
        return LibreSCRS::SmartCard::detail::makeDetachedCardSession(r);
    };
    auto resolver = [](std::span<const std::uint8_t>, LibreSCRS::SmartCard::CardSession&) { return CandidateList{}; };
    return std::make_unique<CardSessionHolder>("FakeReader", std::move(factory), std::move(resolver),
                                               std::make_shared<LibreSCRS::SmartCard::CardMap>());
}

// A single-record snapshot: a changeable UserPIN addressed by "user:0x01"; the
// activatable variant flips the key-activation capability on instead.
CredentialSnapshot makeSnapshot(bool keyActivatable = false)
{
    CredentialRecord r;
    r.id = keyActivatable ? "sign:0x92" : "user:0x01";
    r.label = keyActivatable ? "SignPIN" : "UserPIN";
    r.kind = keyActivatable ? "sign" : "user";
    r.state = "operational";
    r.minLength = 4;
    r.maxLength = 8;
    r.canChange = !keyActivatable;
    r.keyActivatable = keyActivatable;
    CredentialSnapshot s;
    s.records.push_back(std::move(r));
    s.version = 1;
    return s;
}

PinManageRequest changeReq()
{
    return PinManageRequest{.cardKey = "card-A", .pinId = "user:0x01", .verb = "change", .activateKey = false};
}

// Shared collaborators for one op run.
struct Harness
{
    std::unique_ptr<CardSessionHolder> holder = makeHolder(std::nullopt);
    FakeCredentialManager credentials;
    FakePrompter prompter;
    PromptSerializer serializer;
    CredentialCache credCache;
    CredentialSnapshotCache snapshotCache;
    CardReadCache readCache;

    ListCredentialsOperation::Deps listDeps()
    {
        return ListCredentialsOperation::Deps{
            .holder = holder.get(),
            .credentials = credentials,
            .prompter = prompter,
            .serializer = serializer,
            .credCache = credCache,
            .snapshotCache = snapshotCache,
            .cardKey = "card-A",
            .readerName = "FakeReader",
            .requester = "test",
            .artifact = "credentials",
        };
    }
    ManagePinOperation::Deps manageDeps()
    {
        return ManagePinOperation::Deps{
            .holder = holder.get(),
            .credentials = credentials,
            .prompter = prompter,
            .serializer = serializer,
            .credCache = credCache,
            .snapshotCache = snapshotCache,
            .readCache = readCache,
            .cardKey = "card-A",
            .readerName = "FakeReader",
            .requester = "test",
            .artifact = "credentials",
            .request = changeReq(),
            .snapshot = makeSnapshot(),
        };
    }
    ActivateSigningKeyOperation::Deps activateDeps()
    {
        return ActivateSigningKeyOperation::Deps{
            .holder = holder.get(),
            .credentials = credentials,
            .prompter = prompter,
            .serializer = serializer,
            .credCache = credCache,
            .snapshotCache = snapshotCache,
            .readCache = readCache,
            .cardKey = "card-A",
            .readerName = "FakeReader",
            .requester = "test",
            .artifact = "credentials",
        };
    }
};

void expectSingleResultThenFinish(const FakeCredentialChannel& ch)
{
    ASSERT_EQ(ch.events.size(), 2u);
    EXPECT_EQ(ch.events[0], FakeCredentialChannel::Event::Result) << "the Result must precede Finished";
    EXPECT_EQ(ch.events[1], FakeCredentialChannel::Event::Finish);
    ASSERT_EQ(ch.results.size(), 1u) << "exactly one Result for the completed attempt";
    ASSERT_EQ(ch.finishes.size(), 1u);
}

} // namespace

// --- L: every completed list attempt carries a typed Result ------------------

// A failed list (session open failure) still emits the typed Result (outcome
// unspecified, empty records) BEFORE Finished(Error): the XML promises the
// payload for EVERY completed attempt, and the KDE client otherwise rewrites
// the terminal into a spurious CommunicationError after fruitless GetResult
// recovery.
TEST(ListCredentialsOperation, FailedListEmitsUnspecifiedResultThenFinishesError)
{
    Harness h;
    h.holder = makeHolder(LibreSCRS::SmartCard::OpenError{LibreSCRS::SmartCard::OpenError::Kind::ReaderUnavailable,
                                                          LibreSCRS::LocalizedText{}, std::nullopt});
    auto channel = std::make_unique<FakeCredentialChannel>();
    auto* raw = channel.get();
    ListCredentialsOperation op(std::move(channel), h.listDeps(), std::make_shared<OperationState>());
    op.runOnWorker();

    ASSERT_NO_FATAL_FAILURE(expectSingleResultThenFinish(*raw));
    EXPECT_EQ(raw->results[0].op.outcome, CredentialOutcome::Unspecified);
    EXPECT_TRUE(raw->results[0].records.empty()) << "a failed list carries no records";
    EXPECT_EQ(raw->finishes[0].status, static_cast<std::uint32_t>(OperationStatus::Error));
    EXPECT_EQ(raw->finishes[0].errorCode, static_cast<std::uint32_t>(ErrorCode::CommunicationError));
}

// A card gone at open: the Result outcome names cardRemoved and Finished
// carries the CardRemoved code.
TEST(ListCredentialsOperation, RemovedCardListEmitsCardRemovedResult)
{
    Harness h;
    h.holder = makeHolder(LibreSCRS::SmartCard::OpenError{LibreSCRS::SmartCard::OpenError::Kind::NoCardPresent,
                                                          LibreSCRS::LocalizedText{}, std::nullopt});
    auto channel = std::make_unique<FakeCredentialChannel>();
    auto* raw = channel.get();
    ListCredentialsOperation op(std::move(channel), h.listDeps(), std::make_shared<OperationState>());
    op.runOnWorker();

    ASSERT_NO_FATAL_FAILURE(expectSingleResultThenFinish(*raw));
    EXPECT_EQ(raw->results[0].op.outcome, CredentialOutcome::CardRemoved);
    EXPECT_EQ(raw->finishes[0].status, static_cast<std::uint32_t>(OperationStatus::Error));
    EXPECT_EQ(raw->finishes[0].errorCode, static_cast<std::uint32_t>(ErrorCode::CardRemoved));
}

// A user-cancelled list finishes Cancelled/None WITH a preceding Result whose
// outcome is userCancelled — the client must never have to guess a cancel from
// a Result-less terminal (it would surface CommunicationError).
TEST(ListCredentialsOperation, CancelledListEmitsUserCancelledResultThenFinishesCancelled)
{
    Harness h;
    auto channel = std::make_unique<FakeCredentialChannel>();
    auto* raw = channel.get();
    ListCredentialsOperation op(std::move(channel), h.listDeps(), std::make_shared<OperationState>());
    op.requestCancel(); // trips the op token; the flow bails at its first gate
    op.runOnWorker();

    ASSERT_NO_FATAL_FAILURE(expectSingleResultThenFinish(*raw));
    EXPECT_EQ(raw->results[0].op.outcome, CredentialOutcome::UserCancelled);
    EXPECT_TRUE(raw->results[0].records.empty());
    EXPECT_EQ(raw->finishes[0].status, static_cast<std::uint32_t>(OperationStatus::Cancelled));
    EXPECT_EQ(raw->finishes[0].errorCode, static_cast<std::uint32_t>(ErrorCode::None));
}

// The Ok listing keeps its shape: outcome=ok + the records, Result before
// Finished(Ok).
TEST(ListCredentialsOperation, OkListStillEmitsRecordsBeforeFinishedOk)
{
    Harness h;
    LibreSCRS::Plugin::PinStatusEntry entry;
    entry.label = "UserPIN";
    entry.reference = 0x01;
    entry.kind = LibreSCRS::Plugin::PinKind::UserPin;
    h.credentials.listResult = {entry};
    auto channel = std::make_unique<FakeCredentialChannel>();
    auto* raw = channel.get();
    ListCredentialsOperation op(std::move(channel), h.listDeps(), std::make_shared<OperationState>());
    op.runOnWorker();

    ASSERT_NO_FATAL_FAILURE(expectSingleResultThenFinish(*raw));
    EXPECT_EQ(raw->results[0].op.outcome, CredentialOutcome::Ok);
    ASSERT_EQ(raw->results[0].records.size(), 1u);
    EXPECT_EQ(raw->finishes[0].status, static_cast<std::uint32_t>(OperationStatus::Ok));
}

// --- L: prompter failure during ManagePin is PrompterError, not Cancelled ----

TEST(ManagePinOperation, PrompterErrorSurfacesPrompterErrorNotCancelled)
{
    Harness h;
    h.prompter.pinChangeResult =
        PinChangePromptResult{PromptStatus::Error, std::nullopt, std::nullopt, "prompter gone"};
    auto channel = std::make_unique<FakeCredentialChannel>();
    auto* raw = channel.get();
    ManagePinOperation op(std::move(channel), h.manageDeps(), std::make_shared<OperationState>());
    op.runOnWorker();

    ASSERT_NO_FATAL_FAILURE(expectSingleResultThenFinish(*raw));
    EXPECT_EQ(raw->results[0].op.outcome, CredentialOutcome::MissingFields);
    EXPECT_EQ(raw->finishes[0].status, static_cast<std::uint32_t>(OperationStatus::Error));
    EXPECT_EQ(raw->finishes[0].errorCode, static_cast<std::uint32_t>(ErrorCode::PrompterError))
        << "a dead prompter must surface as PrompterError, never as a user cancel";
}

// --- L: a failed Result delivery fails the op CLOSED -------------------------

// "Ordering holds modulo channel allocation failure, which fails the op
// closed": when emitResult reports failure the op must finish Error — never
// Finished(Ok) with a missing Result the client cannot recover.
TEST(ListCredentialsOperation, EmitResultFailureFinishesClosed)
{
    Harness h;
    auto channel = std::make_unique<FakeCredentialChannel>();
    channel->emitResultReturns = false;
    auto* raw = channel.get();
    ListCredentialsOperation op(std::move(channel), h.listDeps(), std::make_shared<OperationState>());
    op.runOnWorker();

    ASSERT_EQ(raw->finishes.size(), 1u);
    EXPECT_EQ(raw->finishes[0].status, static_cast<std::uint32_t>(OperationStatus::Error))
        << "an undeliverable Result must fail the op closed, not finish Ok";
    EXPECT_EQ(raw->finishes[0].errorCode, static_cast<std::uint32_t>(ErrorCode::CommunicationError));
}

TEST(ManagePinOperation, EmitResultFailureFinishesClosed)
{
    Harness h;
    h.prompter.pinChangeResult = PinChangePromptResult{PromptStatus::Ok, LibreSCRS::Secure::String{"1111"},
                                                       LibreSCRS::Secure::String{"2222"}, ""};
    h.credentials.changePinResult = LibreSCRS::Plugin::PINResult{.outcome = LibreSCRS::Plugin::PINResultOutcome::Ok};
    auto channel = std::make_unique<FakeCredentialChannel>();
    channel->emitResultReturns = false;
    auto* raw = channel.get();
    ManagePinOperation op(std::move(channel), h.manageDeps(), std::make_shared<OperationState>());
    op.runOnWorker();

    ASSERT_EQ(raw->finishes.size(), 1u);
    EXPECT_EQ(raw->finishes[0].status, static_cast<std::uint32_t>(OperationStatus::Error));
    EXPECT_EQ(raw->finishes[0].errorCode, static_cast<std::uint32_t>(ErrorCode::CommunicationError));
}

TEST(ActivateSigningKeyOperation, EmitResultFailureFinishesClosed)
{
    Harness h;
    h.snapshotCache.put("card-A", makeSnapshot(/*keyActivatable=*/true));
    h.prompter.pinResult = PromptResult{PromptStatus::Ok, LibreSCRS::Secure::String{"123456"}, ""};
    h.credentials.activateSigningKeyResult =
        LibreSCRS::Plugin::PINResult{.outcome = LibreSCRS::Plugin::PINResultOutcome::Ok};
    auto channel = std::make_unique<FakeCredentialChannel>();
    channel->emitResultReturns = false;
    auto* raw = channel.get();
    ActivateSigningKeyOperation op(std::move(channel), h.activateDeps(), std::make_shared<OperationState>());
    op.runOnWorker();

    ASSERT_EQ(raw->finishes.size(), 1u);
    EXPECT_EQ(raw->finishes[0].status, static_cast<std::uint32_t>(OperationStatus::Error));
    EXPECT_EQ(raw->finishes[0].errorCode, static_cast<std::uint32_t>(ErrorCode::CommunicationError));
}
