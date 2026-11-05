// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// End-to-end: agent (CardObject hosting Card1 + Credentials1) + a fake
// CredentialManager seam + FakePrompterService on a private session bus
// (dbus-run-session). Covers:
//   * introspection exposes Credentials1 on the card path;
//   * entry gating: unknown verb / stray options key / bad pinId / missing
//     PinManagement capability -> the exact typed D-Bus error, NO op;
//   * the complementary rule: a card WITH the capability whose seam answers
//     Unsupported yields a well-formed Unsupported *Result* (op IS created);
//   * ListCredentials empty -> Ok empty list, and populated -> records with the
//     exact snake_case keys + camelCase value tokens;
//   * the ManagePin change happy path -> Credentials1.Result outcome=ok with the
//     pinned payload keys, before Operation1.Finished(Ok);
//   * ActivateSigningKey happy path -> outcome=ok;
//   * the mutation ops route through the Authorizer + RateLimiter (over-cap ->
//     RateLimited BEFORE any prompt);
//   * card removal drops the snapshot (the AgentService removal-lambda contract).

#include "AgentErrorNames.h"
#include "AgentInterfaceNames.h"
#include "AllowAllAuthorizer.h" // test support: grants every action
#include <LibreSCRS/Agent/OperationPhase.h>
#include <LibreSCRS/Agent/backend/Authorizer.h>
#include <LibreSCRS/Agent/cache/CardRemovalCaches.h> // invalidateCardRemovalCaches (the production removal-invalidation code)
#include "dbus/CardObject.h"
#include <LibreSCRS/Agent/cache/CardReadCache.h>
#include <LibreSCRS/Agent/cache/CredentialCache.h>
#include <LibreSCRS/Agent/cache/CredentialSnapshotCache.h>
#include "PrompterClient.h"
#include "PrompterWire.h"
#include "TestAgentCore.h"
#include <LibreSCRS/Agent/operations/CardPluginRouting.h> // CandidateList
#include <LibreSCRS/Agent/operations/OperationLauncher.h>
#include <LibreSCRS/Agent/operations/OperationManager.h>
#include <LibreSCRS/Agent/operations/RateLimiter.h>
#include <LibreSCRS/Agent/operations/Seams.h> // CredentialManager
#include <LibreSCRS/Agent/value/CredentialRecord.h>
#include "org.librescrs.Prompter1_adaptor.h"

#include "SealedMemfdCreator.h"

#include <LibreSCRS/Plugin/PinStatusEntry.h>
#include <LibreSCRS/Plugin/PluginTypes.h>
#include <LibreSCRS/SmartCard/CardSession.h>
#include <LibreSCRS/SmartCard/testing/CardSessionTesting.h>
#include <LibreSCRS/Secure/String.h>

#include <sdbus-c++/sdbus-c++.h>

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <condition_variable>
#include <expected>
#include <future>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <thread>
#include <utility>
#include <vector>

using namespace LibreSCRS::Agent;
using namespace LibreSCRS::Agent::Operations;
using namespace std::chrono_literals;

namespace {

constexpr const char* kPrompterObject = "/org/librescrs/Prompter1";
constexpr const char* kReaderPath = "/org/librescrs/Agent/reader/0";
constexpr const char* kCardPath = "/org/librescrs/Agent/card/2";
constexpr std::uint32_t kPinMgmtBit = static_cast<std::uint32_t>(LibreSCRS::Plugin::CardCapabilities::PinManagement);

using ResultDict = std::map<std::string, sdbus::Variant>;
using RecordsWire = std::vector<std::map<std::string, sdbus::Variant>>;

int makeSealedMemfd(std::string_view bytes)
{
    return LibreLinux::Common::makeSealedMemfd(
        "librescrs-cred-e2e",
        std::span<const std::uint8_t>{reinterpret_cast<const std::uint8_t*>(bytes.data()), bytes.size()});
}

// Hosts org.librescrs.Prompter1: RequestSecrets (change_pin) returns current
// "111111" + new "222222" as sealed memfds, so the change flow gets deterministic
// secrets. RequestSecret answers "111111" at once, or -- with holdPinWindow() --
// stands like an open window until a Cancel names it.
class FakePrompterService final : public sdbus::AdaptorInterfaces<org::librescrs::Prompter1_adaptor>
{
public:
    using SecretResult = sdbus::Result<std::string, sdbus::UnixFd, std::string>;

    FakePrompterService(sdbus::IConnection& connection, sdbus::ObjectPath path)
        : AdaptorInterfaces(connection, std::move(path))
    {
        registerAdaptor();
    }
    ~FakePrompterService()
    {
        unregisterAdaptor();
    }
    FakePrompterService(const FakePrompterService&) = delete;
    FakePrompterService& operator=(const FakePrompterService&) = delete;
    FakePrompterService(FakePrompterService&&) = delete;
    FakePrompterService& operator=(FakePrompterService&&) = delete;

    // The next RequestSecret is left unanswered, as a window the user has not
    // dealt with yet.
    void holdPinWindow()
    {
        const std::lock_guard lock{m_mutex};
        m_holdNext = true;
    }
    // The prompt id of the window being held, once one is.
    std::optional<std::string> waitForHeldWindow(std::chrono::milliseconds timeout)
    {
        std::unique_lock lock{m_mutex};
        if (!m_cv.wait_for(lock, timeout, [this] { return m_held.has_value(); })) {
            return std::nullopt;
        }
        return m_heldId;
    }
    std::vector<std::string> cancelledIds()
    {
        const std::lock_guard lock{m_mutex};
        return m_cancelledIds;
    }
    // Answers a window still held as dismissed, so no request outlives the test.
    void dismissHeldWindow()
    {
        std::optional<SecretResult> held;
        {
            const std::lock_guard lock{m_mutex};
            held = std::exchange(m_held, std::nullopt);
        }
        if (held) {
            answerDismissed(std::move(*held));
        }
    }

private:
    static void answerDismissed(SecretResult&& result)
    {
        result.returnResults(std::string{LibreLinux::PrompterWire::replyStatusToken(
                                 LibreLinux::PrompterWire::PromptReplyStatus::Cancelled)},
                             sdbus::UnixFd{makeSealedMemfd(""), sdbus::adopt_fd}, std::string{});
    }

    // Asynchronous on the server side (the production prompter returns while
    // its window stands); unless told to hold, this fake raises none, so it
    // answers at once.
    void RequestSecret(SecretResult&& result, std::string, std::map<std::string, sdbus::Variant> options) override
    {
        {
            const std::lock_guard lock{m_mutex};
            if (m_holdNext) {
                m_holdNext = false;
                const auto id = options.find(LibreLinux::PrompterWire::kOptPromptId);
                m_heldId = id != options.end() ? id->second.get<std::string>() : std::string{};
                m_held.emplace(std::move(result));
                m_cv.notify_all();
                return;
            }
        }
        result.returnResults(std::string{"ok"}, sdbus::UnixFd{makeSealedMemfd("111111"), sdbus::adopt_fd},
                             std::string{});
    }
    void RequestSecrets(sdbus::Result<std::string, sdbus::UnixFd, sdbus::UnixFd, std::string>&& result, std::string,
                        std::map<std::string, sdbus::Variant>) override
    {
        result.returnResults(std::string{"ok"}, sdbus::UnixFd{makeSealedMemfd("111111"), sdbus::adopt_fd},
                             sdbus::UnixFd{makeSealedMemfd("222222"), sdbus::adopt_fd}, std::string{});
    }
    // No window is raised here, so the startup sweep has nothing to do.
    void Reset() override {}

    // On the same contract as the production prompter, so an agent driving this
    // mock is not refused by the capability guard.
    uint32_t ProtocolVersion() override
    {
        return LibreLinux::PrompterWire::kProtocolVersion;
    }

    // Closes the held window when the dismissal names it, the way the
    // production prompter answers a request whose window it took down.
    void Cancel(const std::string& promptId) override
    {
        std::optional<SecretResult> held;
        {
            const std::lock_guard lock{m_mutex};
            m_cancelledIds.push_back(promptId);
            if (m_held && promptId == m_heldId) {
                held = std::exchange(m_held, std::nullopt);
            }
        }
        if (held) {
            answerDismissed(std::move(*held));
        }
    }

    std::mutex m_mutex;
    std::condition_variable m_cv;
    bool m_holdNext = false;
    std::optional<SecretResult> m_held;
    std::string m_heldId;
    std::vector<std::string> m_cancelledIds;
};

// Scriptable CredentialManager seam (test double). Ignores the session/candidates
// (a detached fake session) and returns the seeded results; an optional delay lets
// the client subscribe to the Result signal before it fires.
class FakeCredentialManager final : public CredentialManager
{
public:
    std::vector<LibreSCRS::Plugin::PinStatusEntry> listResult;
    LibreSCRS::Plugin::PINResult changePinResult;
    LibreSCRS::Plugin::PINResult activateSigningKeyResult;
    std::chrono::milliseconds seamDelay{0};
    std::atomic<int> changeCalls{0};
    std::atomic<int> activateCalls{0};

    // The two change secrets AS THEY ARRIVED at the seam, captured under the mutex
    // by changePIN and read after the op completes. Lets the happy-path test pin
    // the end-to-end current->oldPin / new->newPin mapping across the real bus.
    std::mutex captureMutex;
    std::string capturedOldPinValue;
    std::string capturedNewPinValue;
    [[nodiscard]] std::string capturedOldPin()
    {
        const std::lock_guard<std::mutex> lock(captureMutex);
        return capturedOldPinValue;
    }
    [[nodiscard]] std::string capturedNewPin()
    {
        const std::lock_guard<std::mutex> lock(captureMutex);
        return capturedNewPinValue;
    }

    CredentialListing list(LibreSCRS::SmartCard::CardSession&, const CandidateList&) override
    {
        return {listResult, listResult.empty() ? std::string{} : std::string{"fake-listing-plugin"}};
    }
    LibreSCRS::Plugin::PINResult changePIN(LibreSCRS::SmartCard::CardSession&, const CandidateList&, std::string_view,
                                           const LibreSCRS::Secure::String& oldPin,
                                           const LibreSCRS::Secure::String& newPin) override
    {
        ++changeCalls;
        {
            // Snapshot the two secrets as the seam received them. Fixed test
            // values (not a real PIN), so a plain-string copy is acceptable here.
            const std::lock_guard<std::mutex> lock(captureMutex);
            capturedOldPinValue = std::string{oldPin.view()};
            capturedNewPinValue = std::string{newPin.view()};
        }
        if (seamDelay.count() > 0) {
            std::this_thread::sleep_for(seamDelay);
        }
        return changePinResult;
    }
    LibreSCRS::Plugin::PINResult activateTransportPin(LibreSCRS::SmartCard::CardSession&, const CandidateList&,
                                                      std::string_view, const LibreSCRS::Secure::String&,
                                                      const LibreSCRS::Secure::String&) override
    {
        return {};
    }
    LibreSCRS::Plugin::PINResult activateSigningKey(LibreSCRS::SmartCard::CardSession&, const CandidateList&,
                                                    const LibreSCRS::Secure::String&) override
    {
        ++activateCalls;
        if (seamDelay.count() > 0) {
            std::this_thread::sleep_for(seamDelay);
        }
        return activateSigningKeyResult;
    }
};

// Fail-closed authorizer double: rejects every action, so a test can pin that
// the authorization gate fires BEFORE any validation side effect.
class DenyAllAuthorizer final : public Authorizer
{
public:
    [[nodiscard]] AuthorizationOutcome authorize(std::string_view, const CallerToken&) override
    {
        return AuthorizationOutcome::Denied;
    }
};

// An authority that keeps its answer: authorizeAsync() parks the completion
// for the test to answer -- or to drop, as an authorizer torn down while a
// question is outstanding does.
class HoldingAuthorizer final : public Authorizer
{
public:
    [[nodiscard]] AuthorizationOutcome authorize(std::string_view, const CallerToken&) override
    {
        return AuthorizationOutcome::Granted;
    }
    void authorizeAsync(std::string_view, const CallerToken&, Completion done) override
    {
        const std::lock_guard lock{m_mutex};
        m_held = std::move(done);
        m_cv.notify_all();
    }
    // The completion of the question asked, once one is.
    Completion waitForQuestion(std::chrono::milliseconds timeout)
    {
        std::unique_lock lock{m_mutex};
        m_cv.wait_for(lock, timeout, [this] { return static_cast<bool>(m_held); });
        return std::exchange(m_held, {});
    }

private:
    std::mutex m_mutex;
    std::condition_variable m_cv;
    Completion m_held;
};

SessionFactory fakeSessionFactory()
{
    return [](const std::string& r)
               -> std::expected<std::shared_ptr<LibreSCRS::SmartCard::CardSession>, LibreSCRS::SmartCard::OpenError> {
        return LibreSCRS::SmartCard::Testing::makeDetachedCardSession(r);
    };
}

// A hand-built listing record (bypasses the list flow) to seed the snapshot cache
// for the ManagePin / ActivateSigningKey entry-resolution tests.
CredentialRecord makeRecord(std::string id, std::string kind, bool canChange, bool keyActivatable)
{
    CredentialRecord r;
    r.id = std::move(id);
    r.label = "test-pin";
    r.kind = std::move(kind);
    r.state = "operational";
    r.minLength = 4;
    r.maxLength = 8;
    r.canChange = canChange;
    r.keyActivatable = keyActivatable;
    return r;
}

// The whole agent-side composition for one test: three connections (agent bus
// [async, hosts the CardObject], prompter bus [async, hosts the fake prompter],
// and a dedicated prompter-client connection the worker pumps inline for its
// blocking RequestSecrets), a client connection, the agent core over the
// prompter client and the authorizer the test asks for, and the CardObject
// launching through a launcher whose credential seam is the fake.
struct Harness
{
    std::shared_ptr<sdbus::IConnection> agentBus;
    std::shared_ptr<sdbus::IConnection> prompterBus;
    std::shared_ptr<sdbus::IConnection> prompterClientConn;
    std::unique_ptr<FakePrompterService> prompterHost;
    std::shared_ptr<FakeCredentialManager> credMgrShare = std::make_shared<FakeCredentialManager>();
    FakeCredentialManager& credMgr = *credMgrShare;
    AllowAllAuthorizer authorizer;
    DenyAllAuthorizer denyAuthorizer;
    HoldingAuthorizer holdingAuthorizer;
    Testing::NoCandidates resolver;
    std::optional<AgentCore> core;
    std::optional<OperationLauncher> launcher;
    std::unique_ptr<CardObject> card;
    std::shared_ptr<sdbus::IConnection> client;
    std::string agentName;

    Harness(const std::string& suffix, std::uint32_t capabilities, bool denyMutations = false,
            bool holdAuthorization = false)
    {
        agentName = "org.librescrs.Agent.Test.Cred." + suffix;
        const std::string prompterName = "org.librescrs.Prompter1.Test.Cred." + suffix;
        agentBus = sdbus::createSessionBusConnection();
        agentBus->requestName(sdbus::ServiceName{agentName});
        prompterBus = sdbus::createSessionBusConnection();
        prompterBus->requestName(sdbus::ServiceName{prompterName});
        prompterHost = std::make_unique<FakePrompterService>(*prompterBus, sdbus::ObjectPath{kPrompterObject});
        agentBus->enterEventLoopAsync();
        prompterBus->enterEventLoopAsync();
        prompterClientConn = sdbus::createSessionBusConnection(); // no async loop: worker pumps it inline
        Authorizer& authority = denyMutations       ? static_cast<Authorizer&>(denyAuthorizer)
                                : holdAuthorization ? static_cast<Authorizer&>(holdingAuthorizer)
                                                    : static_cast<Authorizer&>(authorizer);
        const auto dir = Testing::testCoreDir("cred-" + suffix);
        core.emplace(resolver, authority, std::make_shared<PrompterClient>(prompterName, kPrompterObject),
                     dir / "agent.conf", dir / "cache", Testing::noReaderCard(), Testing::noCardKey());
        core->operationManager().setSessionFactoryForTest(fakeSessionFactory());
        auto seams = Testing::unusedSeams();
        seams.credentials = credMgrShare;
        launcher.emplace(*core, std::move(seams));

        CardOperationDeps deps;
        deps.cardKey = kCardPath;
        deps.readerName = "FakeReader";
        card = std::make_unique<CardObject>(*agentBus, sdbus::ObjectPath{kCardPath}, capabilities,
                                            sdbus::ObjectPath{kReaderPath}, *core, *launcher, std::move(deps));

        client = sdbus::createSessionBusConnection();
        client->enterEventLoopAsync();
    }
    ~Harness()
    {
        if (client) {
            client->leaveEventLoop();
        }
        if (prompterBus) {
            prompterBus->leaveEventLoop();
        }
        if (agentBus) {
            agentBus->leaveEventLoop();
        }
    }
    Harness(const Harness&) = delete;
    Harness& operator=(const Harness&) = delete;

    [[nodiscard]] std::unique_ptr<sdbus::IProxy> cardProxy() const
    {
        return sdbus::createProxy(*client, sdbus::ServiceName{agentName}, sdbus::ObjectPath{kCardPath});
    }
    [[nodiscard]] std::unique_ptr<sdbus::IProxy> opProxy(const sdbus::ObjectPath& op) const
    {
        return sdbus::createProxy(*client, sdbus::ServiceName{agentName}, op);
    }
};

// Poll the op's terminal properties until Completed==true; return the Status enum
// (race-free late-subscriber recovery, no reliance on catching the one-shot signal).
int waitCompleted(sdbus::IProxy& op)
{
    const auto deadline = std::chrono::steady_clock::now() + 3s;
    while (std::chrono::steady_clock::now() < deadline) {
        sdbus::Variant completed;
        op.callMethod("Get")
            .onInterface(sdbus::InterfaceName{"org.freedesktop.DBus.Properties"})
            .withArguments(std::string{LibreLinux::AgentWire::kOperation1Iface}, std::string{"Completed"})
            .storeResultsTo(completed);
        if (completed.get<bool>()) {
            sdbus::Variant status;
            op.callMethod("Get")
                .onInterface(sdbus::InterfaceName{"org.freedesktop.DBus.Properties"})
                .withArguments(std::string{LibreLinux::AgentWire::kOperation1Iface}, std::string{"Status"})
                .storeResultsTo(status);
            return static_cast<int>(status.get<std::uint32_t>());
        }
        std::this_thread::sleep_for(20ms);
    }
    return -1;
}

// Fetch the Credentials1 payload via GetResult (re-serves the exact Result payload
// while the op survives the cleanup grace).
std::pair<ResultDict, RecordsWire> getResult(sdbus::IProxy& op)
{
    ResultDict result;
    RecordsWire records;
    op.callMethod("GetResult")
        .onInterface(sdbus::InterfaceName{"org.librescrs.Agent.Operation.Credentials1"})
        .storeResultsTo(result, records);
    return {result, records};
}

sdbus::ObjectPath callManagePin(sdbus::IProxy& card, const std::string& pinId, const std::string& verb,
                                const std::map<std::string, sdbus::Variant>& options)
{
    sdbus::ObjectPath op;
    card.callMethod("ManagePin")
        .onInterface(sdbus::InterfaceName{"org.librescrs.Agent.Credentials1"})
        .withArguments(pinId, verb, options)
        .storeResultsTo(op);
    return op;
}

} // namespace

TEST(CredentialsDbus, IntrospectionExposesCredentials1OnCardPath)
{
    Harness h("Introspect", kPinMgmtBit);
    auto card = h.cardProxy();
    std::string xml;
    card->callMethod("Introspect")
        .onInterface(sdbus::InterfaceName{"org.freedesktop.DBus.Introspectable"})
        .storeResultsTo(xml);
    EXPECT_NE(xml.find("org.librescrs.Agent.Credentials1"), std::string::npos)
        << "Credentials1 must be introspectable on the card path";
    EXPECT_NE(xml.find("ManagePin"), std::string::npos);
    EXPECT_NE(xml.find("ListCredentials"), std::string::npos);
}

TEST(CredentialsDbus, ManagePinUnknownVerbRejectedAtEntry)
{
    Harness h("BadVerb", kPinMgmtBit);
    h.core->credentialSnapshotCache().put(
        kCardPath, CredentialSnapshot{.records = {makeRecord("user:0x01", "user", true, false)}});
    auto card = h.cardProxy();
    try {
        static_cast<void>(callManagePin(*card, "user:0x01", "frobnicate", {}));
        FAIL() << "unknown verb must be rejected at entry (no Operation)";
    } catch (const sdbus::Error& e) {
        EXPECT_EQ(e.getName(), std::string{LibreLinux::AgentWire::kErrInvalidRequest});
    }
}

TEST(CredentialsDbus, ManagePinStrayOptionsKeyRejectedAtEntry)
{
    Harness h("StrayOption", kPinMgmtBit);
    h.core->credentialSnapshotCache().put(
        kCardPath, CredentialSnapshot{.records = {makeRecord("user:0x01", "user", true, false)}});
    auto card = h.cardProxy();
    std::map<std::string, sdbus::Variant> options;
    options.emplace("nonsenseKey", sdbus::Variant{true});
    try {
        static_cast<void>(callManagePin(*card, "user:0x01", "change", options));
        FAIL() << "undefined options key must be rejected at entry (no Operation)";
    } catch (const sdbus::Error& e) {
        EXPECT_EQ(e.getName(), std::string{LibreLinux::AgentWire::kErrInvalidRequest});
    }
}

TEST(CredentialsDbus, ManagePinBadPinIdRejectedAtEntry)
{
    Harness h("BadPin", kPinMgmtBit);
    // No snapshot yet (client never listed) -> UnknownCredential.
    auto card = h.cardProxy();
    try {
        static_cast<void>(callManagePin(*card, "user:0x01", "change", {}));
        FAIL() << "a pinId with no snapshot must be rejected at entry";
    } catch (const sdbus::Error& e) {
        EXPECT_EQ(e.getName(), std::string{"org.librescrs.Agent.Error.UnknownCredential"});
    }
    // Snapshot present but the id is absent -> still UnknownCredential.
    h.core->credentialSnapshotCache().put(
        kCardPath, CredentialSnapshot{.records = {makeRecord("user:0x01", "user", true, false)}});
    try {
        static_cast<void>(callManagePin(*card, "sign:0xFF", "change", {}));
        FAIL() << "an unlisted pinId must be rejected at entry";
    } catch (const sdbus::Error& e) {
        EXPECT_EQ(e.getName(), std::string{"org.librescrs.Agent.Error.UnknownCredential"});
    }
}

TEST(CredentialsDbus, MissingCapabilityRejectedAtEntry)
{
    Harness h("NoCap", 0u); // capabilities = 0: no PinManagement bit
    h.core->credentialSnapshotCache().put(
        kCardPath, CredentialSnapshot{.records = {makeRecord("user:0x01", "user", true, false)}});
    auto card = h.cardProxy();
    for (const char* method : {"ManagePin", "ActivateSigningKey", "ListCredentials"}) {
        try {
            sdbus::ObjectPath op;
            if (std::string{method} == "ManagePin") {
                op = callManagePin(*card, "user:0x01", "change", {});
            } else {
                card->callMethod(method)
                    .onInterface(sdbus::InterfaceName{"org.librescrs.Agent.Credentials1"})
                    .storeResultsTo(op);
            }
            FAIL() << method << " must be refused without the PinManagement capability";
        } catch (const sdbus::Error& e) {
            EXPECT_EQ(e.getName(), std::string{LibreLinux::AgentWire::kErrUnsupportedOnThisCard})
                << "method " << method;
        }
    }
}

TEST(CredentialsDbus, ManagePinChangeHappyPathEmitsOkResultBeforeFinished)
{
    Harness h("ChangeOk", kPinMgmtBit);
    h.core->credentialSnapshotCache().put(
        kCardPath, CredentialSnapshot{.records = {makeRecord("user:0x01", "user", true, false)}});
    h.credMgr.changePinResult.outcome = LibreSCRS::Plugin::PINResultOutcome::Ok;
    h.credMgr.changePinResult.retriesLeft = 3;
    h.credMgr.seamDelay = 250ms; // let the client subscribe before Result fires

    auto card = h.cardProxy();
    const auto opPath = callManagePin(*card, "user:0x01", "change", {});
    ASSERT_FALSE(std::string{opPath}.empty());

    std::atomic<bool> sawResult{false};
    std::atomic<int> orderedResultBeforeFinished{-1};
    auto op = h.opProxy(opPath);
    op->uponSignal(sdbus::SignalName{"Result"})
        .onInterface(sdbus::InterfaceName{"org.librescrs.Agent.Operation.Credentials1"})
        .call([&](const ResultDict&, const RecordsWire&) { sawResult.store(true); });
    op->uponSignal(sdbus::SignalName{"Finished"})
        .onInterface(sdbus::InterfaceName{LibreLinux::AgentWire::kOperation1Iface})
        .call([&](std::uint32_t, std::uint32_t, const std::string&, const std::string&) {
            orderedResultBeforeFinished.store(sawResult.load() ? 1 : 0);
        });

    ASSERT_EQ(waitCompleted(*op), 0) << "change must finish Ok";
    EXPECT_EQ(orderedResultBeforeFinished.load(), 1) << "Credentials1.Result must fire BEFORE Operation1.Finished";
    EXPECT_EQ(h.credMgr.changeCalls.load(), 1) << "the change seam must have been driven";

    // End-to-end secret mapping across the REAL path (prompter memfds ->
    // PrompterClient decode -> flow -> seam): the fake prompter returns fixed
    // current "111111" / new "222222". A swap or marshaling bug (passing the new
    // PIN as the old, burning a retry with the wrong value) is caught here — the
    // two composed half-tests (PrompterClient, PinChangeFlow) never cover the wire.
    EXPECT_EQ(h.credMgr.capturedOldPin(), "111111") << "the CURRENT secret must arrive at the seam as oldPin";
    EXPECT_EQ(h.credMgr.capturedNewPin(), "222222") << "the NEW secret must arrive at the seam as newPin";

    // Verify the pinned payload keys (via GetResult, the race-free re-serve).
    const auto [result, records] = getResult(*op);
    ASSERT_TRUE(records.empty()) << "a mutation carries no listing records";
    ASSERT_TRUE(result.count("outcome"));
    EXPECT_EQ(result.at("outcome").get<std::string>(), "ok");
    ASSERT_TRUE(result.count("blocked"));
    EXPECT_FALSE(result.at("blocked").get<bool>());
    ASSERT_TRUE(result.count("retries_left"));
    EXPECT_EQ(result.at("retries_left").get<int>(), 3);
}

TEST(CredentialsDbus, ManagePinChangeUnsupportedSeamYieldsUnsupportedResult)
{
    // Capability present but the seam advertises nothing -> the Operation IS
    // created and the Result carries outcome=unsupported (NOT an entry error).
    Harness h("ChangeUnsupported", kPinMgmtBit);
    h.core->credentialSnapshotCache().put(
        kCardPath, CredentialSnapshot{.records = {makeRecord("user:0x02", "user", false, false)}});
    h.credMgr.changePinResult.outcome = LibreSCRS::Plugin::PINResultOutcome::Unsupported;

    auto card = h.cardProxy();
    const auto opPath = callManagePin(*card, "user:0x02", "change", {});
    ASSERT_FALSE(std::string{opPath}.empty()) << "the op IS created (not gated at entry)";

    auto op = h.opProxy(opPath);
    ASSERT_GE(waitCompleted(*op), 0);
    const auto [result, records] = getResult(*op);
    ASSERT_TRUE(result.count("outcome"));
    EXPECT_EQ(result.at("outcome").get<std::string>(), "unsupported");
}

TEST(CredentialsDbus, ListCredentialsEmptyReturnsOkEmptyList)
{
    Harness h("ListEmpty", kPinMgmtBit);
    h.credMgr.listResult.clear(); // card advertises the capability but exposes nothing
    auto card = h.cardProxy();
    sdbus::ObjectPath opPath;
    card->callMethod("ListCredentials")
        .onInterface(sdbus::InterfaceName{"org.librescrs.Agent.Credentials1"})
        .storeResultsTo(opPath);
    ASSERT_FALSE(std::string{opPath}.empty());

    auto op = h.opProxy(opPath);
    ASSERT_EQ(waitCompleted(*op), 0) << "an empty listing is a valid Ok result";
    const auto [result, records] = getResult(*op);
    EXPECT_TRUE(records.empty());
    ASSERT_TRUE(result.count("outcome"));
    EXPECT_EQ(result.at("outcome").get<std::string>(), "ok");
}

TEST(CredentialsDbus, ListCredentialsReturnsRecordsWithWireKeys)
{
    Harness h("ListRecords", kPinMgmtBit);
    LibreSCRS::Plugin::PinStatusEntry entry;
    entry.label = "user-pin";
    entry.reference = 0x01;
    entry.kind = LibreSCRS::Plugin::PinKind::UserPin;
    entry.state = LibreSCRS::Plugin::PinState::Operational;
    entry.canChange = true;
    entry.minLength = 4;
    entry.maxLength = 8;
    entry.retriesLeft = 3;
    entry.retriesMax = 3;
    h.credMgr.listResult = {entry};

    auto card = h.cardProxy();
    sdbus::ObjectPath opPath;
    card->callMethod("ListCredentials")
        .onInterface(sdbus::InterfaceName{"org.librescrs.Agent.Credentials1"})
        .storeResultsTo(opPath);
    ASSERT_FALSE(std::string{opPath}.empty());

    auto op = h.opProxy(opPath);
    ASSERT_EQ(waitCompleted(*op), 0);
    const auto [result, records] = getResult(*op);
    EXPECT_EQ(result.at("outcome").get<std::string>(), "ok");
    ASSERT_EQ(records.size(), 1u);
    const auto& rec = records.front();
    // Exact snake_case keys + camelCase value tokens.
    ASSERT_TRUE(rec.count("id"));
    EXPECT_EQ(rec.at("id").get<std::string>(), "user:0x01");
    EXPECT_EQ(rec.at("kind").get<std::string>(), "user");
    EXPECT_EQ(rec.at("state").get<std::string>(), "operational");
    EXPECT_EQ(rec.at("label").get<std::string>(), "user-pin");
    ASSERT_TRUE(rec.count("can_change"));
    EXPECT_TRUE(rec.at("can_change").get<bool>());
    ASSERT_TRUE(rec.count("retries_left"));
    EXPECT_EQ(rec.at("retries_left").get<int>(), 3);

    // The listing was cached under the card path so ManagePin can address it.
    const auto cached = h.core->credentialSnapshotCache().get(kCardPath);
    ASSERT_TRUE(cached);
    ASSERT_EQ(cached->records.size(), 1u);
    EXPECT_EQ(cached->records.front().id, "user:0x01");
}

TEST(CredentialsDbus, ActivateSigningKeyHappyPathReportsOk)
{
    Harness h("ActivateOk", kPinMgmtBit);
    h.core->credentialSnapshotCache().put(
        kCardPath, CredentialSnapshot{.records = {makeRecord("sign:0x92", "sign", false, true)}});
    h.credMgr.activateSigningKeyResult.outcome = LibreSCRS::Plugin::PINResultOutcome::Ok;

    auto card = h.cardProxy();
    sdbus::ObjectPath opPath;
    card->callMethod("ActivateSigningKey")
        .onInterface(sdbus::InterfaceName{"org.librescrs.Agent.Credentials1"})
        .storeResultsTo(opPath);
    ASSERT_FALSE(std::string{opPath}.empty());

    auto op = h.opProxy(opPath);
    ASSERT_EQ(waitCompleted(*op), 0);
    EXPECT_EQ(h.credMgr.activateCalls.load(), 1);
    const auto [result, records] = getResult(*op);
    EXPECT_EQ(result.at("outcome").get<std::string>(), "ok");
}

// Operation1.Cancel while the PIN window stands: the window the operation
// raised is closed by name, the operation ends Cancelled, and the card is
// never asked to activate anything.
TEST(CredentialsDbus, CancelWhileThePinWindowStandsClosesItAndEndsTheOp)
{
    Harness h("CancelAtPrompt", kPinMgmtBit);
    h.core->credentialSnapshotCache().put(
        kCardPath, CredentialSnapshot{.records = {makeRecord("sign:0x92", "sign", false, true)}});
    h.credMgr.activateSigningKeyResult.outcome = LibreSCRS::Plugin::PINResultOutcome::Ok;
    h.prompterHost->holdPinWindow();

    auto card = h.cardProxy();
    sdbus::ObjectPath opPath;
    card->callMethod("ActivateSigningKey")
        .onInterface(sdbus::InterfaceName{"org.librescrs.Agent.Credentials1"})
        .storeResultsTo(opPath);
    ASSERT_FALSE(std::string{opPath}.empty());

    const auto promptId = h.prompterHost->waitForHeldWindow(3s);
    ASSERT_TRUE(promptId.has_value()) << "the operation never asked for the PIN";
    ASSERT_FALSE(promptId->empty()) << "a window with no id cannot be dismissed by name";
    auto op = h.opProxy(opPath);
    sdbus::Variant phase;
    op->callMethod("Get")
        .onInterface(sdbus::InterfaceName{"org.freedesktop.DBus.Properties"})
        .withArguments(std::string{LibreLinux::AgentWire::kOperation1Iface}, std::string{"Phase"})
        .storeResultsTo(phase);
    ASSERT_EQ(phase.get<std::uint32_t>(), static_cast<std::uint32_t>(OperationPhase::AwaitingConsent));

    op->callMethod("Cancel").onInterface(sdbus::InterfaceName{LibreLinux::AgentWire::kOperation1Iface});

    const int status = waitCompleted(*op);
    const auto cancelled = h.prompterHost->cancelledIds();
    h.prompterHost->dismissHeldWindow(); // a no-op once the Cancel closed it
    EXPECT_EQ(cancelled, std::vector<std::string>{*promptId}) << "the standing window was not closed";
    EXPECT_EQ(status, static_cast<int>(OperationStatus::Cancelled));
    EXPECT_EQ(h.credMgr.activateCalls.load(), 0) << "a cancelled activation must not reach the card";
}

TEST(CredentialsDbus, ActivateSigningKeyNotActivatableIsUnsupportedNotEntryError)
{
    // Card WITH the bit but no activatable key in the listing -> op created,
    // Result outcome=unsupported, seam never driven (capability short-circuit).
    Harness h("ActivateUnsupported", kPinMgmtBit);
    h.core->credentialSnapshotCache().put(
        kCardPath, CredentialSnapshot{.records = {makeRecord("sign:0x92", "sign", false, false)}});
    auto card = h.cardProxy();
    sdbus::ObjectPath opPath;
    card->callMethod("ActivateSigningKey")
        .onInterface(sdbus::InterfaceName{"org.librescrs.Agent.Credentials1"})
        .storeResultsTo(opPath);
    ASSERT_FALSE(std::string{opPath}.empty());
    auto op = h.opProxy(opPath);
    ASSERT_GE(waitCompleted(*op), 0);
    const auto [result, records] = getResult(*op);
    EXPECT_EQ(result.at("outcome").get<std::string>(), "unsupported");
    EXPECT_EQ(h.credMgr.activateCalls.load(), 0) << "not-activatable must not prompt or drive the seam";
}

TEST(CredentialsDbus, MutationRateLimitedBeforePrompt)
{
    Harness h("RateLimit", kPinMgmtBit);
    // Pre-exhaust the shared limiter for THIS client's caller token (the same key
    // CardObject rate-limits on: the message sender). RateLimiter::kMaxPerWindow is
    // 5, so five accepted attempts leave the sixth (the real ActivateSigningKey) denied.
    const CallerToken caller{std::string{h.client->getUniqueName()}};
    for (int i = 0; i < 5; ++i) {
        ASSERT_TRUE(h.core->rateLimiter().allow(caller));
    }
    auto card = h.cardProxy();
    try {
        sdbus::ObjectPath op;
        card->callMethod("ActivateSigningKey")
            .onInterface(sdbus::InterfaceName{"org.librescrs.Agent.Credentials1"})
            .storeResultsTo(op);
        FAIL() << "an over-cap caller must be rejected with RateLimited before any prompt";
    } catch (const sdbus::Error& e) {
        EXPECT_EQ(e.getName(), std::string{LibreLinux::AgentWire::kErrRateLimited});
    }
    EXPECT_EQ(h.credMgr.activateCalls.load(), 0) << "the seam (and prompt) must not be reached when rate-limited";
}

// Authorization must precede validation (same posture as Card1.Sign): an
// unauthorized caller gets NotAuthorized even for a request that would fail
// validation, and no validation side effect (snapshot get / entry-error
// classification) runs on its behalf.
TEST(CredentialsDbus, ManagePinUnauthorizedBeforeValidation)
{
    Harness h("DenyAuth", kPinMgmtBit, /*denyMutations=*/true);
    // No snapshot and a nonsense verb: validation would answer InvalidRequest /
    // UnknownCredential — NotAuthorized proves the gate fired first.
    auto card = h.cardProxy();
    try {
        static_cast<void>(callManagePin(*card, "user:0x01", "frobnicate", {}));
        FAIL() << "an unauthorized caller must be rejected before validation";
    } catch (const sdbus::Error& e) {
        EXPECT_EQ(e.getName(), std::string{LibreLinux::AgentWire::kErrNotAuthorized});
    }
}

// A card pulled while the authority is still deciding (a password dialog
// open): the grant that arrives afterwards runs nothing on the withdrawn card,
// and the caller is told that nothing was changed.
TEST(CredentialsDbus, ACardPulledWhileTheAuthorityDecidesChangesNothing)
{
    Harness h("PulledMidAuth", kPinMgmtBit, /*denyMutations=*/false, /*holdAuthorization=*/true);
    h.core->credentialSnapshotCache().put(
        kCardPath, CredentialSnapshot{.records = {makeRecord("user:0x01", "user", true, false)}});
    auto card = h.cardProxy();
    auto pending = std::async(std::launch::async, [&card]() -> std::pair<std::string, std::string> {
        try {
            static_cast<void>(callManagePin(*card, "user:0x01", "change", {}));
            return {};
        } catch (const sdbus::Error& e) {
            return {e.getName(), e.getMessage()};
        }
    });
    auto answer = h.holdingAuthorizer.waitForQuestion(5s);
    ASSERT_TRUE(answer) << "the authority was never asked";
    h.card.reset(); // the reader monitor withdraws the card
    answer(AuthorizationOutcome::Granted);
    const auto [name, message] = pending.get();
    EXPECT_EQ(name, std::string{LibreLinux::AgentWire::kErrCommunication});
    EXPECT_NE(message.find("went away"), std::string::npos) << message;
    EXPECT_EQ(h.credMgr.changeCalls.load(), 0);
}

// An authorizer torn down with a question outstanding (the agent stopping)
// drops its completion unanswered. The caller still hears that nothing was
// changed, at once, instead of nothing until its own timeout.
TEST(CredentialsDbus, AQuestionTheAuthorizerDropsIsStillAnswered)
{
    Harness h("DroppedQuestion", kPinMgmtBit, /*denyMutations=*/false, /*holdAuthorization=*/true);
    auto card = h.cardProxy();
    const auto start = std::chrono::steady_clock::now();
    auto pending = std::async(std::launch::async, [&card]() -> std::string {
        try {
            static_cast<void>(callManagePin(*card, "user:0x01", "change", {}));
            return {};
        } catch (const sdbus::Error& e) {
            return e.getName();
        }
    });
    {
        auto answer = h.holdingAuthorizer.waitForQuestion(5s);
        ASSERT_TRUE(answer) << "the authority was never asked";
    } // dropped unanswered
    const auto name = pending.get();
    EXPECT_EQ(name, std::string{LibreLinux::AgentWire::kErrCommunication});
    EXPECT_LT(std::chrono::steady_clock::now() - start, 5s) << "the caller waited for its own timeout";
}

// The rate limit shares the pre-validation posture: an over-cap caller is
// answered RateLimited, not with a validation verdict computed on its behalf.
TEST(CredentialsDbus, ManagePinRateLimitedBeforeValidation)
{
    Harness h("RateLimitOrder", kPinMgmtBit);
    const CallerToken caller{std::string{h.client->getUniqueName()}};
    for (int i = 0; i < 5; ++i) {
        ASSERT_TRUE(h.core->rateLimiter().allow(caller));
    }
    auto card = h.cardProxy();
    try {
        static_cast<void>(callManagePin(*card, "user:0x01", "frobnicate", {}));
        FAIL() << "an over-cap caller must be rejected before validation";
    } catch (const sdbus::Error& e) {
        EXPECT_EQ(e.getName(), std::string{LibreLinux::AgentWire::kErrRateLimited});
    }
}

// A DEFINED options key carrying the WRONG variant type must be an
// InvalidRequest entry error — silently coercing a mistyped activateKey to
// false would run a different mutation than the client asked for.
TEST(CredentialsDbus, ManagePinMistypedActivateKeyRejectedAtEntry)
{
    Harness h("MistypedOption", kPinMgmtBit);
    h.core->credentialSnapshotCache().put(
        kCardPath, CredentialSnapshot{.records = {makeRecord("user:0x01", "user", true, false)}});
    auto card = h.cardProxy();
    std::map<std::string, sdbus::Variant> options;
    options.emplace("activateKey", sdbus::Variant{std::string{"true"}}); // string, not bool
    try {
        static_cast<void>(callManagePin(*card, "user:0x01", "activate_pin", options));
        FAIL() << "a mistyped defined options key must be rejected at entry (no Operation)";
    } catch (const sdbus::Error& e) {
        EXPECT_EQ(e.getName(), std::string{LibreLinux::AgentWire::kErrInvalidRequest});
    }
}

// Two same-label records (distinct disambiguated ids): the mutation would make
// the seam guess which PIN the label addresses, so entry validation answers
// InvalidRequest (EntryError::AmbiguousCredential's wire mapping).
TEST(CredentialsDbus, ManagePinAmbiguousLabelRejectedAtEntry)
{
    Harness h("AmbiguousLabel", kPinMgmtBit);
    auto first = makeRecord("user:0x01:0", "user", true, false);
    auto second = makeRecord("user:0x01:1", "user", true, false); // same "test-pin" label
    h.core->credentialSnapshotCache().put(kCardPath, CredentialSnapshot{.records = {first, second}});
    auto card = h.cardProxy();
    try {
        static_cast<void>(callManagePin(*card, "user:0x01:0", "change", {}));
        FAIL() << "a non-unique label must be rejected at entry (no Operation)";
    } catch (const sdbus::Error& e) {
        EXPECT_EQ(e.getName(), std::string{LibreLinux::AgentWire::kErrInvalidRequest});
    }
}

// Card removal must drop the per-card ListCredentials snapshot. Rather than
// hand-mirroring the invalidation set (which would pass even if the real hook
// forgot the snapshot), this drives invalidateCardRemovalCaches() — the SHARED
// helper the production AgentService::setOnKeyRemoved lambda actually calls. A
// regression that drops the snapshot cache from that helper fails here AND in
// production together, so the hook's cache set is genuinely under test.
TEST(CredentialsDbus, CardRemovalDropsSnapshot)
{
    CredentialCache credCache;
    CardReadCache readCache;
    CredentialSnapshotCache snapshotCache;
    const std::string cardPath = kCardPath;
    snapshotCache.put(cardPath, CredentialSnapshot{.records = {makeRecord("user:0x01", "user", true, false)}});
    ASSERT_TRUE(snapshotCache.get(cardPath).has_value());

    // The exact production removal-invalidation code (not a re-implementation).
    invalidateCardRemovalCaches(credCache, readCache, snapshotCache, cardPath);

    EXPECT_FALSE(snapshotCache.get(cardPath).has_value()) << "card removal must drop the credential snapshot";
}
