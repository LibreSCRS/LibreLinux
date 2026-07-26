// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Hermetic exercise of SignFlow + the Sign1 recovery store. Every seam is a
// Fake; the flow runs synchronously on the test thread. This covers the
// orchestration: the unified PIN/CAN credential lambda, the watchdog-safe phase
// ordering, status mapping, cache eviction and the GetResult recovery store.
//
// NOT covered here (they live inside LmSigner, which uses real LM types + a live
// card): the anti-TOCTOU SHA-256(DER)==certId re-assert and the on-card
// SigningService::sign — those are hardware-validated. The pure expired-gate
// DECISION is split out and unit-tested in SignGateTest; the FakeSigner here only
// echoes a configured SignOutcome status, so its CertExpiredBlocked case verifies
// the flow's mapping/no-prompt contract, not the notAfter computation.
#include <LibreSCRS/Agent/cache/CredentialCache.h>
#include "SealedMemfd.h"
#include "dbus/TypedResultStore.h" // SignResultState, sealStoredResult (Sign1 recovery store)
#include <LibreSCRS/Agent/operations/CardSessionHolder.h>
#include <LibreSCRS/Agent/operations/OperationBase.h> // Phase enum, OperationPhaseSink
#include <LibreSCRS/Agent/operations/PromptSerializer.h>
#include <LibreSCRS/Agent/operations/SignFlow.h>
#include "operations/SignOperation.h"

#include <LibreSCRS/Auth/AuthRequirement.h>
#include <LibreSCRS/Auth/CredentialResult.h>
#include <LibreSCRS/Auth/ErrorKeys.h>
#include <LibreSCRS/Auth/PaceSecretKind.h>
#include <LibreSCRS/CancelToken.h>
#include <LibreSCRS/Plugin/CardPlugin.h>
#include <LibreSCRS/LocalizedText.h>
#include <LibreSCRS/Secure/String.h>
#include <LibreSCRS/SmartCard/AppletAid.h>
#include <LibreSCRS/SmartCard/CardMap.h>
#include <LibreSCRS/SmartCard/CardSession.h>
#include <gtest/gtest.h>
#include <sys/mman.h>
#include <unistd.h>
#include <cstdint>
#include <cstring>
#include <expected>
#include <memory>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

using namespace LibreSCRS::Agent;
using namespace LibreSCRS::Agent::Operations;

namespace {

// Minimal CardPlugin stub: declares capabilities + an id; the rest of the
// CardPlugin surface is unused by SignFlow (the FakeSigner never invokes the
// plugin — the production LmSigner does, exercised by the HW smoke test).
class StubPlugin final : public LibreSCRS::Plugin::CardPlugin
{
public:
    StubPlugin(std::string id, LibreSCRS::Plugin::CardCapabilities caps) : m_caps(caps)
    {
        setIdentity(std::move(id), "stub", 0);
    }
    LibreSCRS::Plugin::CardCapabilities capabilities() const override
    {
        return m_caps;
    }
    std::span<const LibreSCRS::Plugin::Atr> supportedAtrs() const noexcept override
    {
        return {};
    }

protected:
    LibreSCRS::Plugin::ReadResult doReadCard(LibreSCRS::SmartCard::CardSession&, GroupCallback) const override
    {
        return LibreSCRS::Plugin::ReadResult::communicationError(LibreSCRS::Auth::ErrorKeys::genericComm());
    }

private:
    LibreSCRS::Plugin::CardCapabilities m_caps;
};

inline std::shared_ptr<const LibreSCRS::Plugin::CardPlugin> mkSigning(std::string id)
{
    return std::make_shared<StubPlugin>(std::move(id), LibreSCRS::Plugin::CardCapabilities::PKI |
                                                           LibreSCRS::Plugin::CardCapabilities::PinManagement);
}

inline std::unique_ptr<CardSessionHolder> makeHolder(std::optional<LibreSCRS::SmartCard::OpenError> failWith,
                                                     CandidateList candidates = {})
{
    auto factory = [failWith = std::move(failWith)](const std::string& r)
        -> std::expected<std::shared_ptr<LibreSCRS::SmartCard::CardSession>, LibreSCRS::SmartCard::OpenError> {
        if (failWith) {
            return std::unexpected{*failWith};
        }
        return LibreSCRS::SmartCard::detail::makeDetachedCardSession(r);
    };
    auto resolver = [candidates = std::move(candidates)](std::span<const std::uint8_t>,
                                                         LibreSCRS::SmartCard::CardSession&) { return candidates; };
    return std::make_unique<CardSessionHolder>("FakeReader", std::move(factory), std::move(resolver),
                                               std::make_shared<LibreSCRS::SmartCard::CardMap>());
}

class FakePrompter final : public PrompterClientBase
{
public:
    int pinCalls = 0;
    int canCalls = 0;
    PromptResult pinResult{PromptStatus::Error, std::nullopt, ""};
    PromptResult canResult{PromptStatus::Error, std::nullopt, ""};

    PromptResult requestPin(const PromptOptions&) override
    {
        ++pinCalls;
        return pinResult;
    }
    PromptResult requestCan(const PromptOptions&) override
    {
        ++canCalls;
        return canResult;
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

// FakeSigner stands in for LmSigner: it returns a configured outcome and can
// drive the injected credential provider to exercise the flow's lambda.
class FakeSigner final : public Signer
{
public:
    enum class Drive { None, Pin, Can };
    Drive drive = Drive::None;
    SignOutcome outcome;
    int signCalls = 0;
    bool sawPin = false;
    SignParams captured;
    CandidateList capturedCandidates; // the routed list the flow handed the signer

    FakeSigner()
    {
        outcome.status = SignOutcome::Status::Ok;
        outcome.signedDocumentBytes = {'S', 'I', 'G'};
        outcome.resolvedFormat = "pades";
        outcome.resolvedLevel = "b-b";
    }

    SignOutcome sign(const std::shared_ptr<LibreSCRS::SmartCard::CardSession>&, const SignParams& params,
                     const CandidateList& candidates, LibreSCRS::Auth::CredentialProvider credentials,
                     LibreSCRS::CancelToken) override
    {
        ++signCalls;
        captured = params;
        capturedCandidates = candidates;
        if (drive == Drive::Pin) {
            auto req = LibreSCRS::Auth::AuthRequirement::forSigning(
                LibreSCRS::LocalizedText{.key = "", .defaultText = "PIN", .placeholders = {}}, std::nullopt);
            auto r = credentials(req);
            if (r.status == LibreSCRS::Auth::CredentialResult::Status::UserCancelled) {
                SignOutcome c;
                c.status = SignOutcome::Status::Cancelled;
                return c;
            }
            if (r.status != LibreSCRS::Auth::CredentialResult::Status::Ok) {
                SignOutcome e;
                e.status = SignOutcome::Status::AuthFailed;
                return e;
            }
            sawPin = (r.find("pin") != nullptr);
        } else if (drive == Drive::Can) {
            auto req = LibreSCRS::Auth::AuthRequirement::forPaceSecret(LibreSCRS::SmartCard::AppletAid{},
                                                                       LibreSCRS::Auth::PaceSecretKind::Can,
                                                                       std::nullopt, LibreSCRS::LocalizedText{});
            (void)credentials(req);
        }
        return outcome;
    }
};

struct Harness
{
    // Set BEFORE make() to drive an acquire failure (mirrors the old
    // FakeOpener.failWith); the holder is built lazily in make().
    std::optional<LibreSCRS::SmartCard::OpenError> failWith;
    // Set BEFORE make() to inject the resolved candidate plugin list the holder
    // hands the flow (which the flow then capability-filters for the signer).
    CandidateList candidates;
    std::unique_ptr<CardSessionHolder> holder;
    FakeSigner signer;
    FakePrompter prompter;
    PromptSerializer serializer;
    CredentialCache cache;
    RecordingPhaseSink phaseSink;
    LibreSCRS::CancelSource source;
    // The resolved level on the request handed to the flow. The Card1.Sign entry
    // resolves b-b/b-t before SignFlow runs; tests set it directly here.
    std::string level = "b-b";

    SignParams params()
    {
        SignParams p;
        p.certId = "abc123";
        p.inputDocument = {'%', 'P', 'D', 'F'};
        p.format = "pades";
        p.level = level;
        p.packaging = "enveloped";
        p.displayName = "doc.pdf";
        return p;
    }

    SignFlow make()
    {
        holder = makeHolder(failWith, candidates);
        return SignFlow{SignFlowDeps{
            .holder = *holder,
            .signer = signer,
            .prompter = prompter,
            .serializer = serializer,
            .cache = cache,
            .phaseSink = phaseSink,
            .cardKey = "card-A",
            .requester = "test-client",
            .params = params(),
            .token = source.token(),
        }};
    }
};

constexpr auto kAwaiting = static_cast<std::uint32_t>(OperationPhase::AwaitingConsent);
constexpr auto kAuth = static_cast<std::uint32_t>(OperationPhase::Authenticating);
constexpr auto kSigning = static_cast<std::uint32_t>(OperationPhase::Signing);
constexpr auto kTimestamping = static_cast<std::uint32_t>(OperationPhase::Timestamping);

bool contains(const std::vector<std::uint32_t>& v, std::uint32_t p)
{
    for (const auto x : v) {
        if (x == p) {
            return true;
        }
    }
    return false;
}

} // namespace

TEST(SignFlow, SuccessReturnsBytesAndMeta)
{
    Harness h;
    auto r = h.make().run();
    EXPECT_EQ(r.outcome, SignFlow::Outcome::Ok);
    EXPECT_EQ(r.code, ErrorCode::None);
    EXPECT_EQ(r.signedDocumentBytes, (std::vector<std::uint8_t>{'S', 'I', 'G'}));
    EXPECT_EQ(r.resolvedFormat, "pades");
    EXPECT_EQ(r.resolvedLevel, "b-b");
    auto acq = h.holder->acquire();
    ASSERT_TRUE(acq.has_value());
    EXPECT_TRUE(acq->session->hasCredentialProvider())
        << "the flow installs its provider on the held session (reset to a stateless no-op on exit) so the "
           "holder-owned session never re-invokes the dangling flow-scoped lambda";
    EXPECT_EQ(h.signer.captured.certId, "abc123");
}

TEST(SignFlow, RoutesSigningCandidatesToTheSigner)
{
    // Two signing-capable (PKI+PinManagement) candidates resolve for the card.
    // The flow filters with signingCandidates() and hands the whole subset to the
    // signer (which then routes to the certId owner inside the production seam).
    Harness h;
    h.candidates = CandidateList{mkSigning("pkcs15-a"), mkSigning("pkcs15-b")};
    auto r = h.make().run();
    EXPECT_EQ(r.outcome, SignFlow::Outcome::Ok);
    ASSERT_EQ(h.signer.capturedCandidates.size(), 2u) << "both signing candidates reached the signer";
    EXPECT_EQ(h.signer.capturedCandidates[0]->pluginId(), "pkcs15-a");
    EXPECT_EQ(h.signer.capturedCandidates[1]->pluginId(), "pkcs15-b");
    // The full (unfiltered) candidate list is still threaded into the Result.
    EXPECT_EQ(r.candidates.size(), 2u);
}

TEST(SignFlow, SignerCancelledMapsCancelled)
{
    Harness h;
    h.signer.outcome.status = SignOutcome::Status::Cancelled;
    auto r = h.make().run();
    EXPECT_EQ(r.outcome, SignFlow::Outcome::Cancelled);
    EXPECT_EQ(r.code, ErrorCode::None);
}

TEST(SignFlow, StatusMapping)
{
    const std::pair<SignOutcome::Status, ErrorCode> cases[] = {
        {SignOutcome::Status::KeyNotFound, ErrorCode::KeyNotFound},
        {SignOutcome::Status::KeyAmbiguous, ErrorCode::KeyAmbiguous},
        {SignOutcome::Status::CertExpiredBlocked, ErrorCode::CertExpiredBlocked},
        {SignOutcome::Status::ChainIncomplete, ErrorCode::ChainIncomplete},
        {SignOutcome::Status::TsaUnreachable, ErrorCode::TsaUnreachable},
        {SignOutcome::Status::AuthFailed, ErrorCode::AuthFailed},
        {SignOutcome::Status::CardBlocked, ErrorCode::CredentialBlocked},
        {SignOutcome::Status::SigningEngineError, ErrorCode::SigningEngineError},
        {SignOutcome::Status::EngineUnavailable, ErrorCode::EngineUnavailable},
        {SignOutcome::Status::InvalidDocument, ErrorCode::InvalidDocument},
    };
    for (const auto& [status, code] : cases) {
        Harness h;
        h.signer.outcome.status = status;
        auto r = h.make().run();
        EXPECT_EQ(r.outcome, SignFlow::Outcome::Error);
        EXPECT_EQ(r.code, code);
    }
}

// V6 regression: a sign that fails authentication must evict the cached PACE
// secret so a retry / card-swap re-establishes cleanly (a wrong signing PIN, or
// a wrong CAN that unlocked the channel, must not be silently replayed). The
// agent-side eviction is the directly observable half (cache.invalidate); the
// flow ALSO calls session->clearCachedPaceCredentials() on the same path (the
// LM-side PACE-slot wipe is covered by LM's own tests — the hermetic detached
// CardSession here has no PC/SC to exercise activateChannelWithSm against).
//
// UAF note: every assertion reads the
// harness-owned CredentialCache directly, never state vended through a test
// double's transient pointer after a funnel returns.
TEST(SignFlow, AuthFailedEvictsCachedPaceSecret)
{
    Harness h;
    // Drive the cacheable CAN path so a successful prompt populates the cache,
    // then make the on-card sign report AuthFailed.
    h.signer.drive = FakeSigner::Drive::Can;
    h.prompter.canResult = {PromptStatus::Ok, LibreSCRS::Secure::String{std::string{"123456"}}, ""};
    h.signer.outcome.status = SignOutcome::Status::AuthFailed;

    auto r = h.make().run();

    EXPECT_EQ(r.outcome, SignFlow::Outcome::Error);
    EXPECT_EQ(r.code, ErrorCode::AuthFailed);
    EXPECT_FALSE(h.cache.hasCan("card-A")) << "AuthFailed must evict the cached CAN so a retry re-prompts";
}

TEST(SignFlow, CardBlockedEvictsCachedPaceSecret)
{
    Harness h;
    h.signer.drive = FakeSigner::Drive::Can;
    h.prompter.canResult = {PromptStatus::Ok, LibreSCRS::Secure::String{std::string{"123456"}}, ""};
    h.signer.outcome.status = SignOutcome::Status::CardBlocked;

    auto r = h.make().run();

    EXPECT_EQ(r.outcome, SignFlow::Outcome::Error);
    EXPECT_EQ(r.code, ErrorCode::CredentialBlocked);
    EXPECT_FALSE(h.cache.hasCan("card-A")) << "CardBlocked must evict the cached CAN too";
}

TEST(SignFlow, NonAuthFailureKeepsCachedPaceSecret)
{
    // A non-auth failure (e.g. the chosen key was not found) leaves a CORRECT
    // cached CAN in place — eviction is strictly the auth-failure path, matching
    // the read flows. This is the negative control for the two eviction tests.
    Harness h;
    h.signer.drive = FakeSigner::Drive::Can;
    h.prompter.canResult = {PromptStatus::Ok, LibreSCRS::Secure::String{std::string{"123456"}}, ""};
    h.signer.outcome.status = SignOutcome::Status::KeyNotFound;

    auto r = h.make().run();

    EXPECT_EQ(r.outcome, SignFlow::Outcome::Error);
    EXPECT_EQ(r.code, ErrorCode::KeyNotFound);
    EXPECT_TRUE(h.cache.hasCan("card-A")) << "a non-auth failure must not evict a correct cached CAN";
}

TEST(SignFlow, ExpiredBlockedNeverPrompts)
{
    // The signer's expired gate fires before any credential prompt: the flow
    // maps it and the prompter is never touched (contract: gate before consent).
    Harness h;
    h.signer.drive = FakeSigner::Drive::None;
    h.signer.outcome.status = SignOutcome::Status::CertExpiredBlocked;
    auto r = h.make().run();
    EXPECT_EQ(r.code, ErrorCode::CertExpiredBlocked);
    EXPECT_EQ(h.prompter.pinCalls, 0);
    EXPECT_EQ(h.prompter.canCalls, 0);
}

TEST(SignFlow, BtExpiredBlockedMapsAndDoesNotPromptOrTimestamp)
{
    // FLOW-level coverage for a b-t request the signer reports CertExpiredBlocked:
    // the flow maps status -> code, never touches the prompter, and never surfaces
    // the Timestamping phase. The qualified-family-ignores-allowExpired DECISION
    // (the notAfter + allowExpired evaluation) lives in the signer's gate and is
    // asserted in SignGateTest; the FakeSigner here only echoes the configured
    // status, so this proves the flow contract, not the gate decision.
    Harness h;
    h.level = "b-t";
    h.signer.drive = FakeSigner::Drive::None; // gate fires before driving the provider
    h.signer.outcome.status = SignOutcome::Status::CertExpiredBlocked;
    h.signer.outcome.resolvedLevel = "b-t";
    auto flow = h.make();
    auto r = flow.run();
    EXPECT_EQ(r.outcome, SignFlow::Outcome::Error);
    EXPECT_EQ(r.code, ErrorCode::CertExpiredBlocked);
    EXPECT_EQ(h.prompter.pinCalls, 0) << "gate fires before consent";
    EXPECT_EQ(h.prompter.canCalls, 0);
    EXPECT_TRUE(r.signedDocumentBytes.empty());
    EXPECT_FALSE(contains(h.phaseSink.phases, kTimestamping));
}

TEST(SignFlow, PinPathPhaseOrderingAndUncachedPrompt)
{
    Harness h;
    h.signer.drive = FakeSigner::Drive::Pin;
    h.prompter.pinResult = {PromptStatus::Ok, LibreSCRS::Secure::String{std::string{"1234"}}, ""};
    auto r = h.make().run();
    EXPECT_EQ(r.outcome, SignFlow::Outcome::Ok);
    EXPECT_TRUE(h.signer.sawPin) << "the pin field reached the signer";
    EXPECT_EQ(h.prompter.pinCalls, 1) << "PIN prompted (uncached)";
    EXPECT_EQ(h.prompter.canCalls, 0);
    // AwaitingConsent precedes Authenticating+Signing: the watchdog (armed on
    // Authenticating) covers signing but never times the human at the prompt.
    ASSERT_EQ(h.phaseSink.phases.size(), 3u);
    EXPECT_EQ(h.phaseSink.phases[0], kAwaiting);
    EXPECT_EQ(h.phaseSink.phases[1], kAuth);
    EXPECT_EQ(h.phaseSink.phases[2], kSigning);
}

TEST(SignFlow, PinPromptCancelMapsCancelledAndArmsNothing)
{
    Harness h;
    h.signer.drive = FakeSigner::Drive::Pin;
    h.prompter.pinResult = {PromptStatus::Cancelled, std::nullopt, ""};
    auto r = h.make().run();
    EXPECT_EQ(r.outcome, SignFlow::Outcome::Cancelled);
    EXPECT_EQ(h.prompter.pinCalls, 1);
    // Only AwaitingConsent — the watchdog-arming phases never fire on a cancel.
    ASSERT_EQ(h.phaseSink.phases.size(), 1u);
    EXPECT_EQ(h.phaseSink.phases[0], kAwaiting);
}

TEST(SignFlow, PinPrompterErrorMapsPrompterErrorNotAuthFailed)
{
    // The prompter UI broke / was absent on the bus: requestPin returns
    // PromptStatus::Error (the FakePrompter default), the provider returns an
    // error CredentialResult, and the signer reports AuthFailed. The flow must
    // remap the final code to PrompterError so the client can tell "the prompter
    // failed" from a card-side auth failure (which would stay AuthFailed).
    Harness h;
    h.signer.drive = FakeSigner::Drive::Pin;
    h.prompter.pinResult = {PromptStatus::Error, std::nullopt, "prompter unavailable"};
    auto r = h.make().run();
    EXPECT_EQ(r.outcome, SignFlow::Outcome::Error);
    EXPECT_EQ(r.code, ErrorCode::PrompterError);
    EXPECT_EQ(h.prompter.pinCalls, 1);
}

TEST(SignFlow, PinWrongSecretStaysAuthFailedNotPrompterError)
{
    // A prompt that SUCCEEDS but yields a wrong PIN (card rejects it ->
    // signer AuthFailed) must NOT be reported as PrompterError: the prompter
    // worked fine. PromptStatus::Ok never sets the prompter-failed flag.
    Harness h;
    h.signer.drive = FakeSigner::Drive::Pin;
    h.prompter.pinResult = {PromptStatus::Ok, LibreSCRS::Secure::String{std::string{"0000"}}, ""};
    h.signer.outcome.status = SignOutcome::Status::AuthFailed;
    auto r = h.make().run();
    EXPECT_EQ(r.outcome, SignFlow::Outcome::Error);
    EXPECT_EQ(r.code, ErrorCode::AuthFailed) << "a wrong-but-collected PIN is not a prompter failure";
}

TEST(SignFlow, CanPathIsCachedAndAddsNoSignPhases)
{
    Harness h;
    h.signer.drive = FakeSigner::Drive::Can;
    h.prompter.canResult = {PromptStatus::Ok, LibreSCRS::Secure::String{std::string{"654321"}}, ""};
    auto r = h.make().run();
    EXPECT_EQ(r.outcome, SignFlow::Outcome::Ok);
    EXPECT_EQ(h.prompter.canCalls, 1);
    EXPECT_EQ(h.prompter.pinCalls, 0);
    EXPECT_TRUE(h.cache.hasCan("card-A")) << "CAN cached for reuse (PIN never is)";
    // Channel establishment surfaces AwaitingConsent only — not the sign phases.
    ASSERT_EQ(h.phaseSink.phases.size(), 1u);
    EXPECT_EQ(h.phaseSink.phases[0], kAwaiting);
}

TEST(SignFlow, ChainCompleteIsAlwaysFalseReservedThisRelease)
{
    // chainComplete is RESERVED this release and hard-wired false on every sign:
    // the signing backend exposes no chain verdict, so nothing in the flow or
    // the seam ever sets it true — not even at the long-term family (b-lta).
    // Pin the current value + meaning so a future LM verdict wiring is a
    // deliberate, test-visible change rather than a silent flip.
    Harness h;
    h.level = "b-lta";
    h.signer.drive = FakeSigner::Drive::Pin;
    h.signer.outcome.resolvedLevel = "b-lta";
    h.signer.outcome.tsaUsed = true;
    h.prompter.pinResult = {PromptStatus::Ok, LibreSCRS::Secure::String{std::string{"1234"}}, ""};
    auto r = h.make().run();
    EXPECT_EQ(r.outcome, SignFlow::Outcome::Ok);
    EXPECT_FALSE(r.chainComplete) << "chainComplete is reserved/always-false until the backend reports a verdict";
}

TEST(SignFlow, BtSuccessEmitsTimestampingAndReportsTsaUsed)
{
    // A qualified-family (b-t) success surfaces the declarative Timestamping
    // phase AFTER Signing, and threads the signer's resolvedLevel + tsaUsed back.
    Harness h;
    h.level = "b-t";
    h.signer.drive = FakeSigner::Drive::Pin;
    h.signer.outcome.resolvedLevel = "b-t";
    h.signer.outcome.tsaUsed = true;
    h.prompter.pinResult = {PromptStatus::Ok, LibreSCRS::Secure::String{std::string{"1234"}}, ""};
    auto r = h.make().run();
    EXPECT_EQ(r.outcome, SignFlow::Outcome::Ok);
    EXPECT_EQ(r.resolvedLevel, "b-t");
    EXPECT_TRUE(r.tsaUsed) << "a b-t success reports the timestamp was applied";
    EXPECT_FALSE(r.signedDocumentBytes.empty());
    EXPECT_TRUE(contains(h.phaseSink.phases, kTimestamping)) << "b-t surfaces the Timestamping phase";
    // Ordering: Signing precedes Timestamping (declarative UX, after the sign).
    ASSERT_EQ(h.phaseSink.phases.back(), kTimestamping);
    EXPECT_TRUE(contains(h.phaseSink.phases, kSigning));
}

TEST(SignFlow, BbSuccessOmitsTimestampingAndReportsNoTsa)
{
    // The baseline (b-b) success never surfaces Timestamping and never reports a
    // TSA — tsaUsed is false for the baseline family.
    Harness h;
    h.level = "b-b";
    h.signer.drive = FakeSigner::Drive::Pin;
    h.signer.outcome.resolvedLevel = "b-b";
    h.signer.outcome.tsaUsed = false;
    h.prompter.pinResult = {PromptStatus::Ok, LibreSCRS::Secure::String{std::string{"1234"}}, ""};
    auto r = h.make().run();
    EXPECT_EQ(r.outcome, SignFlow::Outcome::Ok);
    EXPECT_EQ(r.resolvedLevel, "b-b");
    EXPECT_FALSE(r.tsaUsed);
    EXPECT_FALSE(contains(h.phaseSink.phases, kTimestamping)) << "b-b must not surface Timestamping";
}

TEST(SignFlow, TsaUnreachableIsAtomicNoHalfSignedArtifactLeaks)
{
    // A b-t request whose TSA cannot be reached fails closed: the signer reports
    // TsaUnreachable with NO bytes (the LM never emits a half-signed B-B artifact
    // when the requested level needed a timestamp). The flow must surface
    // TsaUnreachable, empty bytes, tsaUsed==false, and (crucially) NOT publish a
    // recoverable artifact — GetResult must yield no fd.
    Harness h;
    h.level = "b-t";
    h.signer.drive = FakeSigner::Drive::Pin;
    h.signer.outcome.status = SignOutcome::Status::TsaUnreachable;
    h.signer.outcome.resolvedLevel = "b-t";
    h.signer.outcome.tsaUsed = false;
    h.signer.outcome.signedDocumentBytes = {}; // no artifact on a TSA failure
    h.prompter.pinResult = {PromptStatus::Ok, LibreSCRS::Secure::String{std::string{"1234"}}, ""};
    auto r = h.make().run();
    EXPECT_EQ(r.outcome, SignFlow::Outcome::Error);
    EXPECT_EQ(r.code, ErrorCode::TsaUnreachable);
    EXPECT_TRUE(r.signedDocumentBytes.empty()) << "no bytes leak on a TSA failure";
    EXPECT_FALSE(r.tsaUsed);
    EXPECT_FALSE(contains(h.phaseSink.phases, kTimestamping)) << "Timestamping never surfaces on a TSA failure";
}

namespace {

// Records whether the op emitted a Sign1 result and its terminal finish, so the
// op's ACTUAL emit-iff-Ok decision is exercised (not a detached proxy). The
// backend channel is what would seal + populate the recovery store; the op only
// decides whether to hand it a SignedArtifact at all.
class RecordingSignChannel final : public OperationChannel
{
public:
    void emitPropertiesChanged() noexcept override {}
    void emitFinished(OperationStatus status, ErrorCode, std::string_view, std::string_view) noexcept override
    {
        finishStatus = status;
        ++finishCount;
    }
    bool emitResult(const ResultPayload&) noexcept override
    {
        emittedResult = true;
        return true;
    }
    bool emittedResult{false};
    int finishCount{0};
    OperationStatus finishStatus{OperationStatus::Ok};
};

} // namespace

TEST(SignFlow, TsaUnreachableDoesNotEmitResult)
{
    // Exercise SignOperation's ACTUAL emit-iff-Ok decision (not a detached proxy):
    // a TsaUnreachable outcome must finish the op Error and NEVER emit a Sign1
    // result — so no signed artifact reaches the channel (and thus the backend
    // recovery store the channel would populate stays empty). The op runs against
    // the same Fake seams as the flow tests.
    auto holder = makeHolder(std::nullopt, {});
    FakeSigner signer;
    FakePrompter prompter;
    PromptSerializer serializer;
    CredentialCache cache;
    signer.drive = FakeSigner::Drive::Pin;
    signer.outcome.status = SignOutcome::Status::TsaUnreachable;
    signer.outcome.resolvedLevel = "b-t";
    signer.outcome.tsaUsed = false;
    signer.outcome.signedDocumentBytes = {};
    prompter.pinResult = {PromptStatus::Ok, LibreSCRS::Secure::String{std::string{"1234"}}, ""};

    SignParams params;
    params.certId = "abc123";
    params.inputDocument = {'%', 'P', 'D', 'F'};
    params.format = "pades";
    params.level = "b-t";
    params.packaging = "enveloped";
    params.displayName = "doc.pdf";

    SignOperation::Deps deps{
        .holder = holder.get(),
        .signer = signer,
        .prompter = prompter,
        .serializer = serializer,
        .credentials = cache,
        .cardKey = "card-A",
        .readerName = "FakeReader",
        .requester = "test",
        .params = std::move(params),
    };
    auto state = std::make_shared<OperationState>();
    auto channel = std::make_unique<RecordingSignChannel>();
    auto* raw = channel.get();
    SignOperation op(std::move(channel), std::move(deps), state);
    op.runOnWorker();

    // The Ok-only emit block was never reached. A regression that emitted on a
    // non-Ok outcome would flip emittedResult here.
    EXPECT_FALSE(raw->emittedResult) << "a TsaUnreachable op must not emit a Sign1 result";
    ASSERT_EQ(raw->finishCount, 1);
    EXPECT_EQ(raw->finishStatus, OperationStatus::Error) << "a b-t op with an unreachable TSA finishes Error";
}

TEST(SignFlow, CancelTokenPreEmpts)
{
    Harness h;
    h.source.requestCancel();
    auto r = h.make().run();
    EXPECT_EQ(r.outcome, SignFlow::Outcome::Cancelled);
    EXPECT_EQ(h.signer.signCalls, 0) << "no signer call after a pre-emptive cancel";
}

TEST(SignFlow, OpenErrorMapsCommunicationError)
{
    Harness h;
    h.failWith = LibreSCRS::SmartCard::OpenError{LibreSCRS::SmartCard::OpenError::Kind::ReaderUnavailable,
                                                 LibreSCRS::LocalizedText{}, std::nullopt};
    auto r = h.make().run();
    EXPECT_EQ(r.outcome, SignFlow::Outcome::Error);
    EXPECT_EQ(r.code, ErrorCode::CommunicationError);
}

// --- Sign1 GetResult recovery store ---------------------------------------

TEST(SignResultStore, NotReadyYieldsNoResult)
{
    SignResultState state;
    auto sealed = sealStoredResult(state);
    EXPECT_LT(sealed.fd, 0) << "an unfinished/failed op has no recoverable artifact";
}

TEST(SignResultStore, ReadyReDupsByteIdenticalArtifact)
{
    SignResultState state;
    const std::vector<std::uint8_t> bytes{'P', 'D', 'F', 0x00, 0x01, 0x02};
    {
        std::lock_guard lock(state.mutex);
        state.payload.bytes = bytes;
        state.payload.meta = SignMeta{.format = "pades", .level = "b-b", .tsaUsed = false, .chainComplete = false};
        state.ready = true;
    }
    auto sealed = sealStoredResult(state);
    ASSERT_GE(sealed.fd, 0);
    EXPECT_EQ(sealed.meta.format, "pades");
    EXPECT_EQ(sealed.meta.level, "b-b");

    const auto size = ::lseek(sealed.fd, 0, SEEK_END);
    ASSERT_EQ(size, static_cast<off_t>(bytes.size()));
    void* p = ::mmap(nullptr, bytes.size(), PROT_READ, MAP_PRIVATE, sealed.fd, 0);
    ASSERT_NE(p, MAP_FAILED);
    EXPECT_EQ(0, std::memcmp(p, bytes.data(), bytes.size()));
    ::munmap(p, bytes.size());
    ::close(sealed.fd);

    // A second recovery re-dups an independent, equally byte-identical artifact.
    auto again = sealStoredResult(state);
    ASSERT_GE(again.fd, 0);
    ::close(again.fd);
}

// The writer side (publishSealedResult) is what SignChannel::emitResult calls:
// on a SUCCESSFUL seal it publishes the recovery store so a late Sign1.GetResult
// re-dups a byte-identical artifact.
TEST(SignResultStore, PublishOnSealSuccessMakesResultRecoverable)
{
    SignResultState state;
    const std::vector<std::uint8_t> bytes{'P', 'D', 'F', 0x10, 0x20, 0x30};
    const SignMeta meta{.format = "pades", .level = "b-b", .tsaUsed = false, .chainComplete = false};
    const int fd = publishSealedResult(state, bytes, meta, &SealedMemfd::create);
    ASSERT_GE(fd, 0) << "a successful seal returns the sealed fd";
    ::close(fd);

    auto sealed = sealStoredResult(state);
    ASSERT_GE(sealed.fd, 0) << "GetResult after a successful publish recovers the artifact";
    const auto size = ::lseek(sealed.fd, 0, SEEK_END);
    ASSERT_EQ(size, static_cast<off_t>(bytes.size()));
    void* p = ::mmap(nullptr, bytes.size(), PROT_READ, MAP_PRIVATE, sealed.fd, 0);
    ASSERT_NE(p, MAP_FAILED);
    EXPECT_EQ(0, std::memcmp(p, bytes.data(), bytes.size()));
    ::munmap(p, bytes.size());
    ::close(sealed.fd);
}

// Regression (M2 fail-closed): a memfd SEAL FAILURE must NOT publish the recovery
// store. Before the fix, SignChannel::emitResult set `ready = true` BEFORE the
// seal and did not roll it back on failure, so a late Sign1.GetResult during the
// cleanup grace would re-seal and hand back an artifact whose op was already
// finished Error(op.memfd_failed) — a fail-open hole. publishSealedResult now
// seals FIRST and publishes only on success, so a seal failure leaves the store
// UNREADY and GetResult maps to Error.NoResult.
TEST(SignResultStore, SealFailureLeavesStoreUnreadyForGetResult)
{
    SignResultState state;
    const std::vector<std::uint8_t> bytes{'P', 'D', 'F', 0x01, 0x02, 0x03};
    const SignMeta meta{.format = "pades", .level = "b-b", .tsaUsed = false, .chainComplete = false};

    // Inject a forced seal failure (models memfd exhaustion / seal rejection).
    const int fd = publishSealedResult(state, bytes, meta, [](std::span<const std::uint8_t>) noexcept { return -1; });
    EXPECT_LT(fd, 0) << "a seal failure returns no fd";

    // The store stays unpublished: a racing GetResult during the cleanup grace
    // fails closed (NoResult) instead of re-sealing an already-failed artifact.
    auto sealed = sealStoredResult(state);
    EXPECT_LT(sealed.fd, 0) << "GetResult after a seal failure yields NoResult (fail closed)";
    if (sealed.fd >= 0) {
        ::close(sealed.fd);
    }
}

// Regression (fail-OPEN after a successful seal): once the seal SUCCEEDS the recovery
// store is published (ready), so a subsequent Sign1.Result signal-emit throw must NOT
// fail the op closed. Before the fix, SignChannel::emitResult wrapped the publish AND
// the emit in one try/catch and returned false on any throw — so an emit throw AFTER a
// successful publish finished the op Error(op.memfd_failed) while the ready store still
// served the genuine artifact to a late Sign1.GetResult: the client was told Error but
// GetResult would hand it Ok. sealPublishAndEmitSignResult now publishes first, then
// swallows+logs an emit throw and returns TRUE (fail OPEN): the op finishes Ok and the
// client recovers via GetResult (store ready <=> Ok).
TEST(SignResultStore, EmitThrowAfterSuccessfulSealFailsOpenAndStaysRecoverable)
{
    log::init([](log::Level, std::string_view) {}); // silence the expected post-seal warn line
    SignResultState state;
    const std::vector<std::uint8_t> bytes{'P', 'D', 'F', 0x0A, 0x0B, 0x0C};
    const SignMeta meta{.format = "pades", .level = "b-b", .tsaUsed = false, .chainComplete = false};

    // The emit throws AFTER a real (successful) seal. It still adopts+closes the fd
    // (mirrors sdbus::UnixFd{fd, adopt_fd} in production) so nothing leaks.
    int emitCalls = 0;
    const bool ok = sealPublishAndEmitSignResult(state, bytes, meta, &SealedMemfd::create, [&emitCalls](int fd) {
        ++emitCalls;
        ::close(fd);
        throw std::runtime_error("signal marshaling failed after seal");
    });

    EXPECT_TRUE(ok) << "a post-seal emit throw fails OPEN: op finishes Ok, client recovers via GetResult";
    EXPECT_EQ(emitCalls, 1) << "emit runs exactly once on a successful seal";

    // The store is READY: a late Sign1.GetResult recovers the artifact, so the
    // client that was told Ok can actually retrieve it (consistent).
    auto sealed = sealStoredResult(state);
    ASSERT_GE(sealed.fd, 0) << "the published store still serves the artifact after the emit throw";
    const auto size = ::lseek(sealed.fd, 0, SEEK_END);
    EXPECT_EQ(size, static_cast<off_t>(bytes.size()));
    ::close(sealed.fd);
    log::resetForTest();
}

// A seal FAILURE still fails CLOSED through the same writer path: emit is never
// invoked, the store stays unready, and the return is false (op finishes Error).
TEST(SignResultStore, SealFailureThroughWriterPathFailsClosedAndSkipsEmit)
{
    SignResultState state;
    const std::vector<std::uint8_t> bytes{'P', 'D', 'F', 0x01};
    const SignMeta meta{.format = "pades", .level = "b-b", .tsaUsed = false, .chainComplete = false};

    int emitCalls = 0;
    const bool ok = sealPublishAndEmitSignResult(
        state, bytes, meta, [](std::span<const std::uint8_t>) noexcept { return -1; },
        [&emitCalls](int) { ++emitCalls; });

    EXPECT_FALSE(ok) << "a seal failure fails closed: the op finishes Error";
    EXPECT_EQ(emitCalls, 0) << "emit is never reached when the seal fails";
    auto sealed = sealStoredResult(state);
    EXPECT_LT(sealed.fd, 0) << "the store stays unready after a seal failure (fail closed)";
    if (sealed.fd >= 0) {
        ::close(sealed.fd);
    }
}
