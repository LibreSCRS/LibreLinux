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
//   * ActivateSigningKey happy path -> key_activated;
//   * the mutation ops route through the Authorizer + RateLimiter (over-cap ->
//     RateLimited BEFORE any prompt);
//   * card removal drops the snapshot (the AgentService removal-lambda contract).

#include "AgentErrorNames.h"
#include "AgentInterfaceNames.h"
#include <LibreSCRS/Agent/backend/Authorizer.h>
#include "CardRemovalCaches.h" // invalidateCardRemovalCaches (the production removal-invalidation code)
#include "dbus/CardObject.h"
#include <LibreSCRS/Agent/cache/CardReadCache.h>
#include <LibreSCRS/Agent/cache/CredentialCache.h>
#include <LibreSCRS/Agent/cache/CredentialSnapshotCache.h>
#include "PrompterClient.h"
#include <LibreSCRS/Agent/operations/CardPluginRouting.h> // CandidateList
#include <LibreSCRS/Agent/operations/OperationManager.h>
#include <LibreSCRS/Agent/operations/PromptSerializer.h>
#include <LibreSCRS/Agent/operations/RateLimiter.h>
#include <LibreSCRS/Agent/operations/Seams.h> // CredentialManager
#include <LibreSCRS/Agent/value/CredentialRecord.h>
#include "org.librescrs.Prompter1_adaptor.h"

#include "SealedMemfdCreator.h"

#include <LibreSCRS/Plugin/PinStatusEntry.h>
#include <LibreSCRS/Plugin/PluginTypes.h>
#include <LibreSCRS/SmartCard/CardSession.h>
#include <LibreSCRS/Secure/String.h>

#include <sdbus-c++/sdbus-c++.h>

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <expected>
#include <map>
#include <memory>
#include <mutex>
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
// secrets. RequestSecret is present for wire-realism.
class FakePrompterService final : public sdbus::AdaptorInterfaces<org::librescrs::Prompter1_adaptor>
{
public:
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

private:
    std::tuple<std::string, sdbus::UnixFd, std::string>
    RequestSecret(const std::string&, const std::map<std::string, sdbus::Variant>&) override
    {
        return std::make_tuple(std::string{"ok"}, sdbus::UnixFd{makeSealedMemfd("111111"), sdbus::adopt_fd},
                               std::string{});
    }
    std::tuple<std::string, sdbus::UnixFd, sdbus::UnixFd, std::string>
    RequestSecrets(const std::string&, const std::map<std::string, sdbus::Variant>&) override
    {
        return std::make_tuple(std::string{"ok"}, sdbus::UnixFd{makeSealedMemfd("111111"), sdbus::adopt_fd},
                               sdbus::UnixFd{makeSealedMemfd("222222"), sdbus::adopt_fd}, std::string{});
    }
    void CancelCurrent() override {}
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
    [[nodiscard]] bool authorize(std::string_view, const CallerToken&) override
    {
        return false;
    }
};

SessionFactory fakeSessionFactory()
{
    return [](const std::string& r)
               -> std::expected<std::shared_ptr<LibreSCRS::SmartCard::CardSession>, LibreSCRS::SmartCard::OpenError> {
        return LibreSCRS::SmartCard::detail::makeDetachedCardSession(r);
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
// blocking RequestSecrets), a client connection, and the CardObject with the
// credential seams wired.
struct Harness
{
    std::shared_ptr<sdbus::IConnection> agentBus;
    std::shared_ptr<sdbus::IConnection> prompterBus;
    std::shared_ptr<sdbus::IConnection> prompterClientConn;
    std::unique_ptr<FakePrompterService> prompterHost;
    std::unique_ptr<PrompterClient> prompterClient;
    FakeCredentialManager credMgr;
    CredentialCache credCache;
    CardReadCache readCache;
    CredentialSnapshotCache snapshotCache;
    PromptSerializer serializer;
    AllowAllAuthorizer authorizer;
    DenyAllAuthorizer denyAuthorizer;
    RateLimiter rateLimiter;
    OperationManager mgr{nullptr};
    std::unique_ptr<CardObject> card;
    std::shared_ptr<sdbus::IConnection> client;
    std::string agentName;

    Harness(const std::string& suffix, std::uint32_t capabilities, bool denyMutations = false)
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
        prompterClient = std::make_unique<PrompterClient>(prompterName, kPrompterObject);
        mgr.setSessionFactoryForTest(fakeSessionFactory());

        CardOperationDeps deps;
        deps.credentialManager = &credMgr;
        deps.prompter = prompterClient.get();
        deps.serializer = &serializer;
        deps.credentials = &credCache;
        deps.snapshotCache = &snapshotCache;
        deps.readCache = &readCache;
        deps.authorizer = denyMutations ? static_cast<Authorizer*>(&denyAuthorizer) : &authorizer;
        deps.rateLimiter = &rateLimiter;
        deps.cardKey = kCardPath;
        deps.readerName = "FakeReader";
        card = std::make_unique<CardObject>(*agentBus, sdbus::ObjectPath{kCardPath}, capabilities,
                                            sdbus::ObjectPath{kReaderPath}, mgr, std::move(deps));

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
        .onInterface(sdbus::InterfaceName{LibreLinux::AgentWire::kOpCredentialsIface})
        .storeResultsTo(result, records);
    return {result, records};
}

sdbus::ObjectPath callManagePin(sdbus::IProxy& card, const std::string& pinId, const std::string& verb,
                                const std::map<std::string, sdbus::Variant>& options)
{
    sdbus::ObjectPath op;
    card.callMethod("ManagePin")
        .onInterface(sdbus::InterfaceName{LibreLinux::AgentWire::kCredentialsIface})
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
    h.snapshotCache.put(kCardPath, CredentialSnapshot{.records = {makeRecord("user:0x01", "user", true, false)}});
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
    h.snapshotCache.put(kCardPath, CredentialSnapshot{.records = {makeRecord("user:0x01", "user", true, false)}});
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
        EXPECT_EQ(e.getName(), std::string{LibreLinux::AgentWire::kErrUnknownCredential});
    }
    // Snapshot present but the id is absent -> still UnknownCredential.
    h.snapshotCache.put(kCardPath, CredentialSnapshot{.records = {makeRecord("user:0x01", "user", true, false)}});
    try {
        static_cast<void>(callManagePin(*card, "sign:0xFF", "change", {}));
        FAIL() << "an unlisted pinId must be rejected at entry";
    } catch (const sdbus::Error& e) {
        EXPECT_EQ(e.getName(), std::string{LibreLinux::AgentWire::kErrUnknownCredential});
    }
}

TEST(CredentialsDbus, MissingCapabilityRejectedAtEntry)
{
    Harness h("NoCap", 0u); // capabilities = 0: no PinManagement bit
    h.snapshotCache.put(kCardPath, CredentialSnapshot{.records = {makeRecord("user:0x01", "user", true, false)}});
    auto card = h.cardProxy();
    for (const char* method : {"ManagePin", "ActivateSigningKey", "ListCredentials"}) {
        try {
            sdbus::ObjectPath op;
            if (std::string{method} == "ManagePin") {
                op = callManagePin(*card, "user:0x01", "change", {});
            } else {
                card->callMethod(method)
                    .onInterface(sdbus::InterfaceName{LibreLinux::AgentWire::kCredentialsIface})
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
    h.snapshotCache.put(kCardPath, CredentialSnapshot{.records = {makeRecord("user:0x01", "user", true, false)}});
    h.credMgr.changePinResult.outcome = LibreSCRS::Plugin::PINResultOutcome::Ok;
    h.credMgr.changePinResult.retriesLeft = 3;
    h.credMgr.seamDelay = 250ms; // let the client subscribe before Result fires

    auto card = h.cardProxy();
    const auto opPath = callManagePin(*card, "user:0x01", "change", {});
    ASSERT_FALSE(std::string{opPath}.empty());

    auto op = h.opProxy(opPath);
    std::atomic<bool> sawResult{false};
    std::atomic<int> orderedResultBeforeFinished{-1};
    op->uponSignal(sdbus::SignalName{"Result"})
        .onInterface(sdbus::InterfaceName{LibreLinux::AgentWire::kOpCredentialsIface})
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
    // pin_activated / key_activated are omitted for a plain change (not engaged).
    EXPECT_FALSE(result.count("pin_activated"));
    EXPECT_FALSE(result.count("key_activated"));
}

TEST(CredentialsDbus, ManagePinChangeUnsupportedSeamYieldsUnsupportedResult)
{
    // Capability present but the seam advertises nothing -> the Operation IS
    // created and the Result carries outcome=unsupported (NOT an entry error).
    Harness h("ChangeUnsupported", kPinMgmtBit);
    h.snapshotCache.put(kCardPath, CredentialSnapshot{.records = {makeRecord("user:0x02", "user", false, false)}});
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
        .onInterface(sdbus::InterfaceName{LibreLinux::AgentWire::kCredentialsIface})
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
        .onInterface(sdbus::InterfaceName{LibreLinux::AgentWire::kCredentialsIface})
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
    ASSERT_TRUE(rec.count("min_length"));
    EXPECT_EQ(rec.at("min_length").get<int>(), 4);

    // The listing was cached under the card path so ManagePin can address it.
    const auto cached = h.snapshotCache.get(kCardPath);
    ASSERT_TRUE(cached);
    ASSERT_EQ(cached->records.size(), 1u);
    EXPECT_EQ(cached->records.front().id, "user:0x01");
}

TEST(CredentialsDbus, ActivateSigningKeyHappyPathReportsKeyActivated)
{
    Harness h("ActivateOk", kPinMgmtBit);
    h.snapshotCache.put(kCardPath, CredentialSnapshot{.records = {makeRecord("sign:0x92", "sign", false, true)}});
    h.credMgr.activateSigningKeyResult.outcome = LibreSCRS::Plugin::PINResultOutcome::Ok;

    auto card = h.cardProxy();
    sdbus::ObjectPath opPath;
    card->callMethod("ActivateSigningKey")
        .onInterface(sdbus::InterfaceName{LibreLinux::AgentWire::kCredentialsIface})
        .storeResultsTo(opPath);
    ASSERT_FALSE(std::string{opPath}.empty());

    auto op = h.opProxy(opPath);
    ASSERT_EQ(waitCompleted(*op), 0);
    EXPECT_EQ(h.credMgr.activateCalls.load(), 1);
    const auto [result, records] = getResult(*op);
    EXPECT_EQ(result.at("outcome").get<std::string>(), "ok");
    ASSERT_TRUE(result.count("key_activated"));
    EXPECT_TRUE(result.at("key_activated").get<bool>());
}

TEST(CredentialsDbus, ActivateSigningKeyNotActivatableIsUnsupportedNotEntryError)
{
    // Card WITH the bit but no activatable key in the listing -> op created,
    // Result outcome=unsupported, seam never driven (capability short-circuit).
    Harness h("ActivateUnsupported", kPinMgmtBit);
    h.snapshotCache.put(kCardPath, CredentialSnapshot{.records = {makeRecord("sign:0x92", "sign", false, false)}});
    auto card = h.cardProxy();
    sdbus::ObjectPath opPath;
    card->callMethod("ActivateSigningKey")
        .onInterface(sdbus::InterfaceName{LibreLinux::AgentWire::kCredentialsIface})
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
        ASSERT_TRUE(h.rateLimiter.allow(caller));
    }
    auto card = h.cardProxy();
    try {
        sdbus::ObjectPath op;
        card->callMethod("ActivateSigningKey")
            .onInterface(sdbus::InterfaceName{LibreLinux::AgentWire::kCredentialsIface})
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

// The rate limit shares the pre-validation posture: an over-cap caller is
// answered RateLimited, not with a validation verdict computed on its behalf.
TEST(CredentialsDbus, ManagePinRateLimitedBeforeValidation)
{
    Harness h("RateLimitOrder", kPinMgmtBit);
    const CallerToken caller{std::string{h.client->getUniqueName()}};
    for (int i = 0; i < 5; ++i) {
        ASSERT_TRUE(h.rateLimiter.allow(caller));
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
    h.snapshotCache.put(kCardPath, CredentialSnapshot{.records = {makeRecord("user:0x01", "user", true, false)}});
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
    h.snapshotCache.put(kCardPath, CredentialSnapshot{.records = {first, second}});
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
