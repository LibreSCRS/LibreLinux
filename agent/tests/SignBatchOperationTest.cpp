// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Hermetic exercise of SignBatchOperation (Card1.SignBatch's worker-side
// Operation, wrapping BatchSignFlow). Every seam is a Fake; the flow runs
// synchronously on the test thread via runOnWorker() -- mirrors
// GetPhotoOperationTest.cpp's bus-less convention.
//
// BatchSignFlow's OWN orchestration (ask-once/cached-thereafter credential
// provider, halt-on-wrong/blocked-credential row marking, the PIN holder's
// wipe-on-every-exit-path contract, the terminal Ok-iff-any-row-signed
// matrix) is exhaustively covered card-free in LibreAgent's own
// BatchSignFlowTest.cpp and is NOT re-tested here. This file covers what is
// NEW at this layer: SignBatchOperation's conversion of BatchSignFlow::
// Result rows into the channel-level BatchSignResult (real bytes/meta/code
// per row, in order), the terminal status/code SignBatchOperation reports to
// Operation1.Finished, and that a FRESH BatchPinHolder backs every
// SignBatchOperation instance (a ctor-scoped member, never shared/reused
// across operations by construction -- see SignBatchOperation.h).
#include <LibreSCRS/Agent/backend/PrompterWire.h>
#include <LibreSCRS/Agent/cache/CredentialCache.h>
#include <LibreSCRS/Agent/operations/CardSessionHolder.h>
#include <LibreSCRS/Agent/operations/OperationBase.h> // Phase enum, OperationPhaseSink
#include <LibreSCRS/Agent/operations/PromptSerializer.h>
#include "operations/SignBatchOperation.h"

#include <LibreSCRS/Auth/AuthRequirement.h>
#include <LibreSCRS/Auth/CredentialResult.h>
#include <LibreSCRS/Auth/ErrorKeys.h>
#include <LibreSCRS/CancelToken.h>
#include <LibreSCRS/LocalizedText.h>
#include <LibreSCRS/Plugin/CardPlugin.h>
#include <LibreSCRS/Secure/String.h>
#include <LibreSCRS/SmartCard/CardMap.h>
#include <LibreSCRS/SmartCard/CardSession.h>
#include <gtest/gtest.h>
#include <cstdint>
#include <expected>
#include <map>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

using namespace LibreSCRS::Agent;
using namespace LibreSCRS::Agent::Operations;

namespace {

std::unique_ptr<CardSessionHolder> makeHolder()
{
    auto factory = [](const std::string& r)
        -> std::expected<std::shared_ptr<LibreSCRS::SmartCard::CardSession>, LibreSCRS::SmartCard::OpenError> {
        return LibreSCRS::SmartCard::detail::makeDetachedCardSession(r);
    };
    auto resolver = [](std::span<const std::uint8_t>, LibreSCRS::SmartCard::CardSession&) { return CandidateList{}; };
    return std::make_unique<CardSessionHolder>("FakeReader", std::move(factory), std::move(resolver),
                                               std::make_shared<LibreSCRS::SmartCard::CardMap>());
}

// Records every requestPin() call's options -- the "consent options
// assertions" RED-matrix item lives entirely in this fake: the trusted
// artifact token, the untrusted artifacts list, and the truncated
// description fallback all ride PromptOptions, which BatchSignFlow builds
// fresh on the FIRST (ask-once) call.
class FakePrompter final : public PrompterClientBase
{
public:
    int pinCalls = 0;
    PromptResult pinResult{PromptStatus::Ok, LibreSCRS::Secure::String{std::string{"1234"}}, ""};
    std::optional<PromptOptions> firstOptions;

    PromptResult requestPin(const PromptOptions& options) override
    {
        ++pinCalls;
        if (!firstOptions) {
            firstOptions = options;
        }
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
};

class RecordingPhaseSink final : public OperationPhaseSink
{
public:
    void setPhase(std::uint32_t phase) noexcept override
    {
        phases.push_back(phase);
    }
    std::vector<std::uint32_t> phases;
};

// Fetches the credential provider's PIN on the REAL path (proving the
// ask-once/cached-thereafter behaviour end to end, not a fake that ignores
// the provider it is handed) -- mirrors LibreAgent's BatchSignFlowTest.cpp
// FakeSigner. `scriptedStatus` overrides the outcome AFTER a successful PIN
// match, keyed by the 1-based call index, so a test can force a halting
// status (AuthFailed/CardBlocked) or a non-halting per-row failure on a
// specific document.
class FakeSigner final : public Signer
{
public:
    int calls = 0;
    std::string cardPin = "1234";
    std::map<int, SignOutcome::Status> scriptedStatus;

    SignOutcome sign(const std::shared_ptr<LibreSCRS::SmartCard::CardSession>&, const SignParams& params,
                     const CandidateList&, LibreSCRS::Auth::CredentialProvider credentials,
                     LibreSCRS::CancelToken) override
    {
        ++calls;
        const auto req =
            LibreSCRS::Auth::AuthRequirement::forSigning(LibreSCRS::LocalizedText{"", "PIN", {}}, std::nullopt);
        const auto result = credentials(req);
        if (result.status != LibreSCRS::Auth::CredentialResult::Status::Ok) {
            SignOutcome out;
            out.status = SignOutcome::Status::CommunicationError;
            return out;
        }
        const auto* pin = result.find(LibreSCRS::PrompterWire::kKindPin);
        if (pin == nullptr || std::string{pin->view()} != cardPin) {
            SignOutcome out;
            out.status = SignOutcome::Status::AuthFailed;
            return out;
        }
        const auto it = scriptedStatus.find(calls);
        const auto status = (it != scriptedStatus.end()) ? it->second : SignOutcome::Status::Ok;
        SignOutcome out;
        out.status = status;
        if (status == SignOutcome::Status::Ok) {
            out.signedDocumentBytes = params.inputDocument;
            out.signedDocumentBytes.push_back(0xAA); // trivial "signature" marker
            out.resolvedFormat = params.format;
            out.resolvedLevel = params.level;
            out.chainComplete = true;
        }
        return out;
    }
};

struct EmittedFinish
{
    std::uint32_t status;
    std::uint32_t errorCode;
};

// Captures every BatchSignResult row delivered via emitResult -- the
// channel-level shape SignBatchOperation converts BatchSignFlow::Result's
// rows into. Sealing into a memfd (incl. the zero-length convention for a
// failed row) is the BACKEND channel's job (dbus/OperationAdaptorFactory's
// SignBatchChannel, exercised by TypedResultStoreTest.cpp), not the op's --
// this fake, like GetPhotoOperationTest's, only ever sees raw bytes.
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
        if (const auto* batch = std::get_if<BatchSignResult>(&result)) {
            rows = *batch;
        }
        return deliver;
    }
    bool deliver{true};
    std::vector<EmittedFinish> finishes;
    BatchSignResult rows;
};

std::vector<BatchDocumentInput> threeDocuments()
{
    return {
        BatchDocumentInput{"invoice-1.pdf", {0x01}},
        BatchDocumentInput{"invoice-2.pdf", {0x02}},
        BatchDocumentInput{"invoice-3.pdf", {0x03}},
    };
}

SignParams baseParams()
{
    SignParams p;
    p.certId = "abc123";
    p.format = "pades";
    p.level = "b-b";
    p.packaging = "enveloped";
    return p;
}

// One-shot harness: builds the Deps + the FakeOperationChannel, constructs a
// FRESH SignBatchOperation, runs it, and hands back the raw channel pointer
// (owned by the operation) for assertions. A caller that wants a SECOND,
// independent operation instance (the fresh-pin-holder-per-operation case)
// simply calls this again with its own signer/prompter.
FakeOperationChannel* runBatch(CardSessionHolder& holder, FakeSigner& signer, FakePrompter& prompter,
                               PromptSerializer& serializer, CredentialCache& cache, RecordingPhaseSink& phaseSink,
                               std::vector<BatchDocumentInput> documents, std::unique_ptr<SignBatchOperation>& opOut)
{
    auto channel = std::make_unique<FakeOperationChannel>();
    auto* raw = channel.get();
    auto state = std::make_shared<OperationState>();
    opOut = std::make_unique<SignBatchOperation>(std::move(channel),
                                                 SignBatchOperation::Deps{
                                                     .holder = &holder,
                                                     .signer = signer,
                                                     .prompter = prompter,
                                                     .serializer = serializer,
                                                     .credentials = cache,
                                                     .cardKey = "card-A",
                                                     .readerName = "FakeReader",
                                                     .requester = "test-client",
                                                     .params = baseParams(),
                                                     .documents = std::move(documents),
                                                 },
                                                 state);
    opOut->runOnWorker();
    return raw;
}

} // namespace

TEST(SignBatchOperation, ThreeDocumentHappyPathEmitsRowsThenFinishedOk)
{
    auto holder = makeHolder();
    FakeSigner signer;
    FakePrompter prompter;
    PromptSerializer serializer;
    CredentialCache cache;
    RecordingPhaseSink phaseSink;
    std::unique_ptr<SignBatchOperation> op;

    auto* raw = runBatch(*holder, signer, prompter, serializer, cache, phaseSink, threeDocuments(), op);

    ASSERT_EQ(raw->finishes.size(), 1u);
    EXPECT_EQ(raw->finishes[0].status, static_cast<std::uint32_t>(OperationStatus::Ok));
    EXPECT_EQ(raw->finishes[0].errorCode, static_cast<std::uint32_t>(ErrorCode::None));

    ASSERT_EQ(raw->rows.size(), 3u);
    const char* names[] = {"invoice-1.pdf", "invoice-2.pdf", "invoice-3.pdf"};
    const std::vector<std::uint8_t> inputs[] = {{0x01}, {0x02}, {0x03}};
    for (std::size_t i = 0; i < 3; ++i) {
        const auto& row = raw->rows[i];
        EXPECT_EQ(row.displayName, names[i]);
        auto expected = inputs[i];
        expected.push_back(0xAA);
        EXPECT_EQ(row.bytes, expected) << "row " << i << " must carry the REAL signed bytes";
        EXPECT_EQ(row.meta.format, "pades");
        EXPECT_EQ(row.meta.level, "b-b");
        EXPECT_TRUE(row.meta.chainComplete);
        EXPECT_EQ(row.code, ErrorCode::None);
    }
    EXPECT_EQ(signer.calls, 3);
    EXPECT_EQ(prompter.pinCalls, 1) << "one consent covers the whole batch";
}

TEST(SignBatchOperation, MidBatchCredentialFailureHaltsAndInheritsTheHaltCode)
{
    auto holder = makeHolder();
    FakeSigner signer;
    signer.scriptedStatus[2] = SignOutcome::Status::CardBlocked; // 2nd document halts
    FakePrompter prompter;
    PromptSerializer serializer;
    CredentialCache cache;
    RecordingPhaseSink phaseSink;
    std::unique_ptr<SignBatchOperation> op;

    auto* raw = runBatch(*holder, signer, prompter, serializer, cache, phaseSink, threeDocuments(), op);

    // >= 1 row signed (the first) -> the AGGREGATE status is still Ok; the
    // per-row codes carry the halt (BatchSignFlow's own terminal rule).
    ASSERT_EQ(raw->finishes.size(), 1u);
    EXPECT_EQ(raw->finishes[0].status, static_cast<std::uint32_t>(OperationStatus::Ok));
    EXPECT_EQ(raw->finishes[0].errorCode, static_cast<std::uint32_t>(ErrorCode::None));

    ASSERT_EQ(raw->rows.size(), 3u);
    EXPECT_EQ(raw->rows[0].code, ErrorCode::None);
    EXPECT_FALSE(raw->rows[0].bytes.empty());

    EXPECT_EQ(raw->rows[1].code, ErrorCode::CredentialBlocked);
    EXPECT_TRUE(raw->rows[1].bytes.empty()) << "a halting row carries no artifact bytes at this layer";

    EXPECT_EQ(raw->rows[2].code, ErrorCode::CredentialBlocked)
        << "the 3rd document was never attempted and inherits the SAME halt code";
    EXPECT_TRUE(raw->rows[2].bytes.empty());

    // The credential provider was consulted for document 1 and 2 (the 2nd
    // is where the card reports blocked) but NEVER for the 3rd -- the halt
    // stops the signer from being called again, so it never re-prompts.
    EXPECT_EQ(signer.calls, 2);
    EXPECT_EQ(prompter.pinCalls, 1);
}

TEST(SignBatchOperation, AllRowsFailIndependentlyFinishesError)
{
    auto holder = makeHolder();
    FakeSigner signer;
    signer.scriptedStatus[1] = SignOutcome::Status::InvalidDocument;
    signer.scriptedStatus[2] = SignOutcome::Status::InvalidDocument;
    signer.scriptedStatus[3] = SignOutcome::Status::InvalidDocument;
    FakePrompter prompter;
    PromptSerializer serializer;
    CredentialCache cache;
    RecordingPhaseSink phaseSink;
    std::unique_ptr<SignBatchOperation> op;

    auto* raw = runBatch(*holder, signer, prompter, serializer, cache, phaseSink, threeDocuments(), op);

    // Zero rows signed -> the AGGREGATE status is Error, carrying the last
    // row's code (BatchSignFlow's own generalisation of the halt rule to an
    // all-independently-failed batch with no halt at all).
    ASSERT_EQ(raw->finishes.size(), 1u);
    EXPECT_EQ(raw->finishes[0].status, static_cast<std::uint32_t>(OperationStatus::Error));
    EXPECT_EQ(raw->finishes[0].errorCode, static_cast<std::uint32_t>(ErrorCode::InvalidDocument));

    // The rows are STILL delivered (unlike Sign1, which never fires on
    // failure): a batch conveys meaningful per-row detail even when the
    // aggregate status is Error.
    ASSERT_EQ(raw->rows.size(), 3u);
    for (const auto& row : raw->rows) {
        EXPECT_EQ(row.code, ErrorCode::InvalidDocument);
        EXPECT_TRUE(row.bytes.empty());
    }
    EXPECT_EQ(signer.calls, 3) << "InvalidDocument is non-halting; every document is independently attempted";
}

TEST(SignBatchOperation, ConsentCarriesTheTrustedTokenTheUntrustedListAndTheTruncatedSummary)
{
    auto holder = makeHolder();
    FakeSigner signer;
    FakePrompter prompter;
    PromptSerializer serializer;
    CredentialCache cache;
    RecordingPhaseSink phaseSink;
    std::unique_ptr<SignBatchOperation> op;

    runBatch(*holder, signer, prompter, serializer, cache, phaseSink, threeDocuments(), op);

    ASSERT_TRUE(prompter.firstOptions.has_value());
    const auto& opts = *prompter.firstOptions;

    // TRUSTED, agent-owned category token -- never the client-supplied name.
    EXPECT_EQ(opts.artifact, "signature-batch");

    // UNTRUSTED enumerated per-document display-name list, verbatim.
    ASSERT_EQ(opts.artifacts.size(), 3u);
    EXPECT_EQ(opts.artifacts[0], "invoice-1.pdf");
    EXPECT_EQ(opts.artifacts[1], "invoice-2.pdf");
    EXPECT_EQ(opts.artifacts[2], "invoice-3.pdf");

    // Legacy `description` fallback: a truncated, honest summary so a
    // prompter build that drops the unknown `artifacts` option key still
    // shows a meaningful consent.
    EXPECT_EQ(opts.description, "3 documents: invoice-1.pdf, invoice-2.pdf, invoice-3.pdf");
}

TEST(SignBatchOperation, DescriptionFallbackTruncatesBeyondThreeNames)
{
    auto holder = makeHolder();
    FakeSigner signer;
    FakePrompter prompter;
    PromptSerializer serializer;
    CredentialCache cache;
    RecordingPhaseSink phaseSink;
    std::unique_ptr<SignBatchOperation> op;

    std::vector<BatchDocumentInput> five{
        BatchDocumentInput{"a.pdf", {0x01}}, BatchDocumentInput{"b.pdf", {0x02}}, BatchDocumentInput{"c.pdf", {0x03}},
        BatchDocumentInput{"d.pdf", {0x04}}, BatchDocumentInput{"e.pdf", {0x05}},
    };
    runBatch(*holder, signer, prompter, serializer, cache, phaseSink, std::move(five), op);

    ASSERT_TRUE(prompter.firstOptions.has_value());
    ASSERT_EQ(prompter.firstOptions->artifacts.size(), 5u);
    EXPECT_EQ(prompter.firstOptions->description, "5 documents: a.pdf, b.pdf, c.pdf (+2 more)");
}

// The fresh-pin-holder-per-operation invariant is, first and foremost, a
// STRUCTURAL guarantee: BatchPinHolder is a plain ctor-scoped member of
// SignBatchOperation (SignBatchOperation.h), never a shared/static/injected
// instance -- so two operations can never alias the same storage by
// construction, independent of what either one does at runtime. This test
// is the behavioural regression-guard: two INDEPENDENT operations (own
// signer/prompter, own document sets) each still prompt exactly once, which
// a shared holder that survived between them (skipping the second prompt
// via a stale cache hit) would violate.
TEST(SignBatchOperation, EachOperationInstanceCollectsItsOwnConsentIndependently)
{
    auto holder1 = makeHolder();
    FakeSigner signer1;
    FakePrompter prompter1;
    PromptSerializer serializer1;
    CredentialCache cache1;
    RecordingPhaseSink phaseSink1;
    std::unique_ptr<SignBatchOperation> op1;
    runBatch(*holder1, signer1, prompter1, serializer1, cache1, phaseSink1, threeDocuments(), op1);
    EXPECT_EQ(prompter1.pinCalls, 1);

    auto holder2 = makeHolder();
    FakeSigner signer2;
    FakePrompter prompter2;
    PromptSerializer serializer2;
    CredentialCache cache2;
    RecordingPhaseSink phaseSink2;
    std::unique_ptr<SignBatchOperation> op2;
    auto* raw2 = runBatch(*holder2, signer2, prompter2, serializer2, cache2, phaseSink2, threeDocuments(), op2);

    EXPECT_EQ(prompter2.pinCalls, 1) << "the second operation's own holder starts empty -- no leakage from the first";
    ASSERT_EQ(raw2->rows.size(), 3u);
    EXPECT_EQ(raw2->rows[0].code, ErrorCode::None);
}

TEST(SignBatchOperation, MemfdSealFailureFinishesErrorClosed)
{
    auto holder = makeHolder();
    FakeSigner signer;
    FakePrompter prompter;
    PromptSerializer serializer;
    CredentialCache cache;
    RecordingPhaseSink phaseSink;

    auto channel = std::make_unique<FakeOperationChannel>();
    channel->deliver = false; // model a backend memfd seal failure
    auto* raw = channel.get();
    auto state = std::make_shared<OperationState>();
    SignBatchOperation op(std::move(channel),
                          SignBatchOperation::Deps{
                              .holder = holder.get(),
                              .signer = signer,
                              .prompter = prompter,
                              .serializer = serializer,
                              .credentials = cache,
                              .cardKey = "card-A",
                              .readerName = "FakeReader",
                              .requester = "test-client",
                              .params = baseParams(),
                              .documents = threeDocuments(),
                          },
                          state);
    op.runOnWorker();

    ASSERT_EQ(raw->finishes.size(), 1u);
    EXPECT_EQ(raw->finishes[0].status, static_cast<std::uint32_t>(OperationStatus::Error));
    EXPECT_EQ(raw->finishes[0].errorCode, static_cast<std::uint32_t>(ErrorCode::CommunicationError));
}
