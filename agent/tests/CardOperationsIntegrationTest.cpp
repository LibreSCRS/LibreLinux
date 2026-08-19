// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// End-to-end: agent (CardObject + OperationManager) + Fake prompter on a
// private session bus (dbus-run-session). Two scenarios:
//   * Happy path — client calls Card1.ReadIdentity, the agent returns an
//     Operation path, then Identity1.Result fires before
//     Operation1.Finished(Ok) on the same path.
//   * Cancel path — client drops its bus connection mid-read; the agent's
//     NameOwnerChanged listener (owned by the BusExporter/AgentTransport and
//     forwarded to OperationManager::dispatchClientDisconnect, fed by
//     CardObject::callerSender on the inbound method) propagates the cancel,
//     the in-flight read returns Status::Cancelled, and the Operation
//     transitions to OperationPhase::Done.
//
// The production CardObject auto-records the inbound sender via
// getCurrentlyProcessedMessage(); the cancel test deliberately does
// NOT call OperationManager::recordSenderForTest -- the real wiring is
// the contract under test.

#include <LibreSCRS/Agent/backend/Authorizer.h>
#include "AgentFrontend.h"
#include <LibreSCRS/Agent/CryptoWorkerContext.h>
#include "BusExporter.h"
#include <LibreSCRS/Agent/presence/CapabilityResolver.h>
#include <LibreSCRS/Agent/cache/CardReadCache.h>
#include <LibreSCRS/Agent/value/CardReadSnapshot.h>
#include <LibreSCRS/Agent/cache/CredentialCache.h>
#include "EventLoopPoster.h"
#include <LibreSCRS/Agent/presence/ObjectRegistry.h>
#include <LibreSCRS/Agent/presence/PresenceModel.h>
#include "PrompterClient.h"
#include <LibreSCRS/Agent/config/ConfigStore.h>
#include "dbus/CardObject.h"
#include <LibreSCRS/Agent/operations/OperationManager.h>
#include <LibreSCRS/Agent/operations/PromptSerializer.h>
#include <LibreSCRS/Agent/operations/RateLimiter.h>
#include <LibreSCRS/Agent/operations/Seams.h>
#include <LibreSCRS/Agent/operations/SigningEngineProvider.h>
#include <LibreSCRS/Agent/pkcs11/LeaseManager.h>
#include "org.librescrs.Prompter1_adaptor.h"

#include "SealedMemfdCreator.h" // shared sealed-memfd creator

#include <LibreSCRS/Auth/AuthRequirement.h>
#include <LibreSCRS/Auth/ErrorKeys.h>
#include <LibreSCRS/Plugin/CardPlugin.h>
#include <LibreSCRS/Plugin/PluginTypes.h>
#include <LibreSCRS/SmartCard/CardSession.h>

#include <systemd/sd-event.h>

#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>

#include <sdbus-c++/AdaptorInterfaces.h>
#include <sdbus-c++/IConnection.h>
#include <sdbus-c++/IProxy.h>
#include <sdbus-c++/Types.h>
#include <sdbus-c++/sdbus-c++.h>

#include <gtest/gtest.h>

#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <span>
#include <expected>
#include <map>
#include <memory>
#include <mutex>
#include <semaphore>
#include <string>
#include <string_view>
#include <thread>
#include <tuple>
#include <utility>
#include <vector>

using namespace LibreSCRS::Agent;
using namespace LibreSCRS::Agent::Operations;
using namespace std::chrono_literals;

namespace {

constexpr const char* kAgentServiceHappy = "org.librescrs.Agent.Test.E2E.Happy";
constexpr const char* kAgentServiceCancel = "org.librescrs.Agent.Test.E2E.Cancel";
constexpr const char* kAgentServiceGroupStream = "org.librescrs.Agent.Test.E2E.GroupStream";
constexpr const char* kPrompterServiceHappy = "org.librescrs.Prompter1.Test.E2E.Happy";
constexpr const char* kPrompterServiceCancel = "org.librescrs.Prompter1.Test.E2E.Cancel";
constexpr const char* kPrompterServiceGroupStream = "org.librescrs.Prompter1.Test.E2E.GroupStream";
constexpr const char* kPrompterObject = "/org/librescrs/Prompter1";
constexpr const char* kReaderPath = "/org/librescrs/Agent/reader/0";
// The single global opaque counter mints the first reader ("R0") as id 1 and its
// card as id 2 -> card/2 in the PresenceModel-driven tests; the hand-constructed
// CardObject tests reuse this path self-consistently.
constexpr const char* kCardPath = "/org/librescrs/Agent/card/2";
constexpr const char* kCard1Iface = "org.librescrs.Agent.Card1";
constexpr const char* kIdentity1Iface = "org.librescrs.Agent.Operation.Identity1";
constexpr const char* kOperation1Iface = "org.librescrs.Agent.Operation1";

// Build a sealed memfd containing @p bytes via the shared creator (the same one
// the prompter + agent use). Returns -1 on failure.
int makeSealedMemfd(std::string_view bytes)
{
    return LibreLinux::Common::makeSealedMemfd(
        "librescrs-e2e-secret",
        std::span<const std::uint8_t>{reinterpret_cast<const std::uint8_t*>(bytes.data()), bytes.size()});
}

// Mirrors PrompterIntegrationTest's MockPrompter — hosts org.librescrs.Prompter1
// on the test bus and returns a canned sealed memfd. The flow under test goes
// through PreReadAuthMethod::None so RequestSecret is never called in either
// scenario, but the host is exported anyway for wire-realism.
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
    void RequestSecret(sdbus::Result<std::string, sdbus::UnixFd, std::string>&& result, std::string kind,
                       std::map<std::string, sdbus::Variant> options) override
    {
        // No window is raised here, so the reply is built and sent at once;
        // the adaptor is asynchronous for the production prompter's sake.
        auto reply = buildSecretReply(kind, options);
        result.returnResults(std::get<0>(reply), std::get<1>(reply), std::get<2>(reply));
    }

    std::tuple<std::string, sdbus::UnixFd, std::string>
    buildSecretReply(const std::string& /*kind*/, const std::map<std::string, sdbus::Variant>& /*options*/)
    {
        const int fd = makeSealedMemfd("111111");
        return std::make_tuple(std::string{"ok"}, sdbus::UnixFd{fd, sdbus::adopt_fd}, std::string{});
    }

    // Multi-secret variant (kind "change_pin"): scripted fixed values —
    // "111111" as the current secret (matching RequestSecret above) and
    // "222222" as the new one — so broker-side suites can drive the full
    // change flow against deterministic prompter output.
    void RequestSecrets(sdbus::Result<std::string, sdbus::UnixFd, sdbus::UnixFd, std::string>&& result,
                        std::string kind, std::map<std::string, sdbus::Variant> options) override
    {
        auto reply = buildSecretsReply(kind, options);
        result.returnResults(std::get<0>(reply), std::get<1>(reply), std::get<2>(reply), std::get<3>(reply));
    }

    std::tuple<std::string, sdbus::UnixFd, sdbus::UnixFd, std::string>
    buildSecretsReply(const std::string& /*kind*/, const std::map<std::string, sdbus::Variant>& /*options*/)
    {
        const int primary = makeSealedMemfd("111111");
        const int secondary = makeSealedMemfd("222222");
        return std::make_tuple(std::string{"ok"}, sdbus::UnixFd{primary, sdbus::adopt_fd},
                               sdbus::UnixFd{secondary, sdbus::adopt_fd}, std::string{});
    }

    void Cancel(const std::string& promptId) override
    {
        (void)promptId;
    }
};

// Fake session factory — same shape as the other suites. The session is
// constructed via the LM test factory so the flow's run() can pass a
// CardSession& to downstream seams. Installed on the OperationManager via
// setSessionFactoryForTest so the per-reader holder reuses it.
inline LibreSCRS::Agent::Operations::SessionFactory fakeSessionFactory()
{
    return [](const std::string& r)
               -> std::expected<std::shared_ptr<LibreSCRS::SmartCard::CardSession>, LibreSCRS::SmartCard::OpenError> {
        return LibreSCRS::SmartCard::detail::makeDetachedCardSession(r);
    };
}

// Happy-path reader — returns a one-field snapshot after a brief delay.
// The delay gives the test thread time to construct the opProxy and
// register both signal subscriptions BEFORE the worker emits them; without
// it the read finishes microseconds after the method-call return and the
// signals land before any client-side subscription exists.
class OkReader final : public CardReader
{
public:
    ReadOutcome read(LibreSCRS::SmartCard::CardSession&, const CandidateList&, LibreSCRS::CancelToken,
                     GroupReadCallback onGroup = {}) override
    {
        std::this_thread::sleep_for(300ms);
        CardReadSnapshot snap;
        snap.cardType = "fake-card";
        GroupSnapshot group;
        group.groupKey = "personal";
        group.labelKey = "g.personal";
        group.labelFallback = "Personal";
        FieldSnapshot field;
        field.fieldKey = "given_name";
        field.labelKey = "f.given_name";
        field.labelFallback = "Given name";
        field.type = FieldType::Text;
        field.textValue = "ANA";
        group.fields.push_back(std::move(field));
        // Stream the group before it lands in the snapshot below, exactly
        // like a real plugin's onGroup callback fires ahead of its own
        // aggregate ReadResult.
        if (onGroup) {
            onGroup(group);
        }
        snap.groups.push_back(std::move(group));
        return ReadOutcome{ReadOutcome::Status::Ok, std::move(snap), ""};
    }
    // Not exercised by this suite; a well-formed default keeps this class
    // non-abstract.
    GroupSnapshot readTokenInfo(LibreSCRS::SmartCard::CardSession&, const CandidateList&,
                                LibreSCRS::CancelToken) override
    {
        return {};
    }
};

// Streams 2 groups via onGroup, in order, before returning a snapshot whose
// own groups are the SAME 2 -- proves the wire-level ordering guarantee
// (Group signals before Result) end to end, over a real bus.
class TwoGroupStreamingReader final : public CardReader
{
public:
    ReadOutcome read(LibreSCRS::SmartCard::CardSession&, const CandidateList&, LibreSCRS::CancelToken,
                     GroupReadCallback onGroup = {}) override
    {
        std::this_thread::sleep_for(300ms);

        GroupSnapshot personal;
        personal.groupKey = "personal";
        personal.labelKey = "g.personal";
        personal.labelFallback = "Personal";
        FieldSnapshot givenName;
        givenName.fieldKey = "given_name";
        givenName.labelKey = "f.given_name";
        givenName.labelFallback = "Given name";
        givenName.type = FieldType::Text;
        givenName.textValue = "ANA";
        personal.fields.push_back(std::move(givenName));

        GroupSnapshot address;
        address.groupKey = "address";
        address.labelKey = "g.address";
        address.labelFallback = "Address";
        FieldSnapshot city;
        city.fieldKey = "city";
        city.labelKey = "f.city";
        city.labelFallback = "City";
        city.type = FieldType::Text;
        city.textValue = "Belgrade";
        address.fields.push_back(std::move(city));

        if (onGroup) {
            onGroup(personal);
            onGroup(address);
        }

        CardReadSnapshot snap;
        snap.cardType = "fake-card";
        snap.groups.push_back(personal);
        snap.groups.push_back(address);
        return ReadOutcome{ReadOutcome::Status::Ok, std::move(snap), ""};
    }
    GroupSnapshot readTokenInfo(LibreSCRS::SmartCard::CardSession&, const CandidateList&,
                                LibreSCRS::CancelToken) override
    {
        return {};
    }
};

// Cancellable reader — checks the token in a tight loop so the in-flight
// read aborts within ~50 ms once the cancel propagates.
class CancellableReader final : public CardReader
{
public:
    ReadOutcome read(LibreSCRS::SmartCard::CardSession&, const CandidateList&, LibreSCRS::CancelToken token,
                     GroupReadCallback = {}) override
    {
        // Up to 5 s of wait — well past the test deadline. Polled at 20 ms
        // to honour cancel quickly.
        for (int i = 0; i < 250; ++i) {
            if (token.isCancelled()) {
                return ReadOutcome{ReadOutcome::Status::Cancelled, std::nullopt, "cancelled"};
            }
            std::this_thread::sleep_for(20ms);
        }
        return ReadOutcome{ReadOutcome::Status::CommunicationError, std::nullopt, "timeout"};
    }
    GroupSnapshot readTokenInfo(LibreSCRS::SmartCard::CardSession&, const CandidateList&,
                                LibreSCRS::CancelToken) override
    {
        return {};
    }
};

// Build the non-owning seam handle bundle for a CardObject — mirrors
// CardObjectOperationsTest's makeDeps() so the field names stay in sync.
CardOperationDeps makeDeps(CardReader& reader, PrompterClientBase& prompter, PromptSerializer& serializer,
                           CredentialCache& credentials, CardReadCache& readCache)
{
    CardOperationDeps deps;
    deps.reader = &reader;
    deps.prompter = &prompter;
    deps.serializer = &serializer;
    deps.credentials = &credentials;
    deps.readCache = &readCache;
    deps.cardKey = kCardPath;
    deps.readerName = "FakeReader";
    return deps;
}

} // namespace

TEST(CardOperationsIntegration, ReadIdentityHappyPathEmitsResultThenFinishedOk)
{
    // Three separate bus connections per the dbus-run-session pattern from
    // PrompterIntegrationTest: agent (hosts Card1 + Operation paths),
    // prompter (hosts org.librescrs.Prompter1), and a client that consumes
    // both. Distinct connections avoid sd-bus self-call rejection.
    std::shared_ptr<sdbus::IConnection> agentBus = sdbus::createSessionBusConnection();
    ASSERT_NE(agentBus, nullptr) << "run under dbus-run-session";
    agentBus->requestName(sdbus::ServiceName{kAgentServiceHappy});

    auto prompterBus = sdbus::createSessionBusConnection();
    ASSERT_NE(prompterBus, nullptr);
    prompterBus->requestName(sdbus::ServiceName{kPrompterServiceHappy});
    FakePrompterService prompterHost(*prompterBus, sdbus::ObjectPath{kPrompterObject});

    agentBus->enterEventLoopAsync();
    prompterBus->enterEventLoopAsync();

    // Agent-side state.
    OkReader reader;
    PrompterClient prompterClient(kPrompterServiceHappy, kPrompterObject);
    CredentialCache credCache;
    CardReadCache readCache;
    PromptSerializer serializer;
    OperationManager mgr(nullptr); // production (cleanup-grace) mode; no resolver
    mgr.setSessionFactoryForTest(fakeSessionFactory());
    // Happy path: the client stays connected through every assertion, so no
    // client-disconnect watch is needed here (that path is exercised by
    // ClientDisconnectCancelsInflightOp below).

    auto deps = makeDeps(reader, prompterClient, serializer, credCache, readCache);

    constexpr std::uint32_t kIdentityBit =
        static_cast<std::uint32_t>(LibreSCRS::Plugin::CardCapabilities::IdentityData);
    CardObject card(*agentBus, sdbus::ObjectPath{kCardPath}, kIdentityBit, sdbus::ObjectPath{kReaderPath}, mgr,
                    std::move(deps));

    // Client connection.
    auto client = sdbus::createSessionBusConnection();
    ASSERT_NE(client, nullptr);
    client->enterEventLoopAsync();

    // Call ReadIdentity and capture the returned Operation path.
    auto cardProxy = sdbus::createProxy(*client, sdbus::ServiceName{kAgentServiceHappy}, sdbus::ObjectPath{kCardPath});
    sdbus::ObjectPath opPath;
    cardProxy->callMethod("ReadIdentity").onInterface(sdbus::InterfaceName{kCard1Iface}).storeResultsTo(opPath);
    ASSERT_FALSE(std::string{opPath}.empty());

    // Subscribe to Identity1.Result + Operation1.Finished on the returned path.
    // sdbus-c++ delivers signals via the proxy's owning connection (the
    // client) — both signals are observed on the client's async event loop.
    auto opProxy = sdbus::createProxy(*client, sdbus::ServiceName{kAgentServiceHappy}, opPath);
    std::atomic<bool> sawResult{false};
    std::atomic<int> finishedStatus{-1};
    std::atomic<int> finishOrderingObservedResult{0};

    using IdentityFieldsMap =
        std::map<std::string,
                 std::map<std::string, sdbus::Struct<std::string, std::string, std::string, sdbus::Variant>>>;

    std::mutex resultMutex;
    IdentityFieldsMap signalledFields;
    opProxy->uponSignal(sdbus::SignalName{"Result"})
        .onInterface(sdbus::InterfaceName{kIdentity1Iface})
        .call([&sawResult, &resultMutex, &signalledFields](const IdentityFieldsMap& fields) {
            {
                std::lock_guard lock(resultMutex);
                signalledFields = fields;
            }
            sawResult.store(true, std::memory_order_release);
        });

    opProxy->uponSignal(sdbus::SignalName{"Finished"})
        .onInterface(sdbus::InterfaceName{kOperation1Iface})
        .call([&](std::uint32_t status, std::uint32_t /*errorCode*/, const std::string& /*msgKey*/,
                  const std::string& /*msgFallback*/) {
            // Capture whether Result had landed BEFORE Finished — the spec
            // requires this ordering. Done as an int (1 if seen before, 0
            // otherwise) so a late Result doesn't retroactively pass us.
            finishOrderingObservedResult.store(sawResult.load(std::memory_order_acquire) ? 1 : 0,
                                               std::memory_order_release);
            finishedStatus.store(static_cast<int>(status), std::memory_order_release);
        });

    // Wait for Finished. The FakeReader is synchronous; the round-trip
    // through the worker + cleanup-grace queue is bounded by tens of ms.
    const auto deadline = std::chrono::steady_clock::now() + 3s;
    while (finishedStatus.load(std::memory_order_acquire) < 0 && std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(20ms);
    }
    EXPECT_EQ(finishedStatus.load(std::memory_order_acquire), 0) << "Operation1.Finished should report Ok (0)";
    EXPECT_EQ(finishOrderingObservedResult.load(std::memory_order_acquire), 1)
        << "Identity1.Result must fire BEFORE Operation1.Finished";
    EXPECT_TRUE(sawResult.load(std::memory_order_acquire));

    // Late-subscriber recovery over the real bus: Identity1.GetResult (the pull
    // a client whose match rules raced the one-shot Result signal falls back
    // to) must re-serve the EXACT payload the signal carried, for as long as
    // the op survives the cleanup grace. Field-wise comparison (sdbus::Variant
    // has no operator==; the frozen `type` string selects the variant arm).
    {
        IdentityFieldsMap recovered;
        opProxy->callMethod("GetResult").onInterface(sdbus::InterfaceName{kIdentity1Iface}).storeResultsTo(recovered);
        std::lock_guard lock(resultMutex);
        EXPECT_FALSE(recovered.empty()) << "Identity1.GetResult must recover the finished-Ok payload";
        ASSERT_EQ(recovered.size(), signalledFields.size());
        for (const auto& [groupKey, group] : signalledFields) {
            const auto rg = recovered.find(groupKey);
            ASSERT_NE(rg, recovered.end()) << "GetResult dropped group " << groupKey;
            ASSERT_EQ(rg->second.size(), group.size());
            for (const auto& [fieldKey, field] : group) {
                const auto rf = rg->second.find(fieldKey);
                ASSERT_NE(rf, rg->second.end()) << "GetResult dropped field " << groupKey << ":" << fieldKey;
                EXPECT_EQ(std::get<0>(rf->second), std::get<0>(field)); // labelKey
                EXPECT_EQ(std::get<1>(rf->second), std::get<1>(field)); // labelFallback
                ASSERT_EQ(std::get<2>(rf->second), std::get<2>(field)); // type
                if (std::get<2>(field) == "binary") {
                    EXPECT_EQ(std::get<3>(rf->second).get<std::vector<std::uint8_t>>(),
                              std::get<3>(field).get<std::vector<std::uint8_t>>());
                } else {
                    EXPECT_EQ(std::get<3>(rf->second).get<std::string>(), std::get<3>(field).get<std::string>());
                }
            }
        }
    }

    client->leaveEventLoop();
    prompterBus->leaveEventLoop();
    agentBus->leaveEventLoop();
}

TEST(CardOperationsIntegration, GroupSignalsStreamInOrderBeforeResult)
{
    std::shared_ptr<sdbus::IConnection> agentBus = sdbus::createSessionBusConnection();
    ASSERT_NE(agentBus, nullptr) << "run under dbus-run-session";
    agentBus->requestName(sdbus::ServiceName{kAgentServiceGroupStream});

    auto prompterBus = sdbus::createSessionBusConnection();
    ASSERT_NE(prompterBus, nullptr);
    prompterBus->requestName(sdbus::ServiceName{kPrompterServiceGroupStream});
    FakePrompterService prompterHost(*prompterBus, sdbus::ObjectPath{kPrompterObject});

    agentBus->enterEventLoopAsync();
    prompterBus->enterEventLoopAsync();

    TwoGroupStreamingReader reader;
    PrompterClient prompterClient(kPrompterServiceGroupStream, kPrompterObject);
    CredentialCache credCache;
    CardReadCache readCache;
    PromptSerializer serializer;
    OperationManager mgr(nullptr); // production (cleanup-grace) mode; no resolver
    mgr.setSessionFactoryForTest(fakeSessionFactory());

    auto deps = makeDeps(reader, prompterClient, serializer, credCache, readCache);

    constexpr std::uint32_t kIdentityBit =
        static_cast<std::uint32_t>(LibreSCRS::Plugin::CardCapabilities::IdentityData);
    CardObject card(*agentBus, sdbus::ObjectPath{kCardPath}, kIdentityBit, sdbus::ObjectPath{kReaderPath}, mgr,
                    std::move(deps));

    auto client = sdbus::createSessionBusConnection();
    ASSERT_NE(client, nullptr);
    client->enterEventLoopAsync();

    auto cardProxy =
        sdbus::createProxy(*client, sdbus::ServiceName{kAgentServiceGroupStream}, sdbus::ObjectPath{kCardPath});
    sdbus::ObjectPath opPath;
    cardProxy->callMethod("ReadIdentity").onInterface(sdbus::InterfaceName{kCard1Iface}).storeResultsTo(opPath);
    ASSERT_FALSE(std::string{opPath}.empty());

    // Subscribe to Identity1.Group + Identity1.Result + Operation1.Finished,
    // all on the returned path, and record their arrival ORDER — the
    // invariant under test is that both Group signals precede Result, over a
    // REAL bus (not just "the production code calls them in this order",
    // which the unit-level flow test already covers — this proves the wire
    // delivers them in that order too).
    auto opProxy = sdbus::createProxy(*client, sdbus::ServiceName{kAgentServiceGroupStream}, opPath);

    using IdentityGroupFieldsMap =
        std::map<std::string, sdbus::Struct<std::string, std::string, std::string, sdbus::Variant>>;
    using IdentityFieldsMap = std::map<std::string, IdentityGroupFieldsMap>;

    std::mutex orderMutex;
    std::vector<std::string> arrivalOrder;
    std::atomic<int> finishedStatus{-1};

    opProxy->uponSignal(sdbus::SignalName{"Group"})
        .onInterface(sdbus::InterfaceName{kIdentity1Iface})
        .call([&](const std::string& groupKey, const IdentityGroupFieldsMap&) {
            std::lock_guard lock(orderMutex);
            arrivalOrder.push_back("group:" + groupKey);
        });

    opProxy->uponSignal(sdbus::SignalName{"Result"})
        .onInterface(sdbus::InterfaceName{kIdentity1Iface})
        .call([&](const IdentityFieldsMap&) {
            std::lock_guard lock(orderMutex);
            arrivalOrder.emplace_back("result");
        });

    opProxy->uponSignal(sdbus::SignalName{"Finished"})
        .onInterface(sdbus::InterfaceName{kOperation1Iface})
        .call([&](std::uint32_t status, std::uint32_t /*errorCode*/, const std::string& /*msgKey*/,
                  const std::string& /*msgFallback*/) { finishedStatus.store(static_cast<int>(status)); });

    const auto deadline = std::chrono::steady_clock::now() + 3s;
    while (finishedStatus.load(std::memory_order_acquire) < 0 && std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(20ms);
    }
    EXPECT_EQ(finishedStatus.load(std::memory_order_acquire), 0) << "Operation1.Finished should report Ok (0)";

    {
        std::lock_guard lock(orderMutex);
        ASSERT_EQ(arrivalOrder.size(), 3u) << "expected 2 Group signals + 1 Result, in that order";
        EXPECT_EQ(arrivalOrder[0], "group:personal");
        EXPECT_EQ(arrivalOrder[1], "group:address");
        EXPECT_EQ(arrivalOrder[2], "result");
    }

    client->leaveEventLoop();
    prompterBus->leaveEventLoop();
    agentBus->leaveEventLoop();
}

TEST(CardOperationsIntegration, ClientDisconnectCancelsInflightOp)
{
    std::shared_ptr<sdbus::IConnection> agentBus = sdbus::createSessionBusConnection();
    ASSERT_NE(agentBus, nullptr);
    agentBus->requestName(sdbus::ServiceName{kAgentServiceCancel});

    auto prompterBus = sdbus::createSessionBusConnection();
    ASSERT_NE(prompterBus, nullptr);
    prompterBus->requestName(sdbus::ServiceName{kPrompterServiceCancel});
    FakePrompterService prompterHost(*prompterBus, sdbus::ObjectPath{kPrompterObject});

    agentBus->enterEventLoopAsync();
    prompterBus->enterEventLoopAsync();

    CancellableReader reader; // blocks on the token, honours cancel
    PrompterClient prompterClient(kPrompterServiceCancel, kPrompterObject);
    CredentialCache credCache;
    CardReadCache readCache;
    PromptSerializer serializer;
    OperationManager mgr(nullptr); // production (cleanup-grace) mode; no resolver
    mgr.setSessionFactoryForTest(fakeSessionFactory());

    // The client-disconnect watch now lives in the BusExporter (AgentTransport):
    // its ctor installs the org.freedesktop.DBus NameOwnerChanged proxy on the
    // agent bus, and each unique-name drop (empty new-owner) fires the registered
    // handlers. We wire the op auto-cancel handler exactly as AgentService does, so
    // this test drives the real production path end to end (bus drop -> proxy ->
    // handler -> dispatchClientDisconnect -> cancel). Only the transport wire (the
    // NameOwnerChanged watch) is needed here; the CardObject is built directly.
    ObjectRegistry registry;
    BusExporter exporter(*agentBus, registry);
    exporter.onClientDisconnect([&mgr](CallerToken caller) { mgr.dispatchClientDisconnect(caller); });

    auto deps = makeDeps(reader, prompterClient, serializer, credCache, readCache);

    constexpr std::uint32_t kIdentityBit =
        static_cast<std::uint32_t>(LibreSCRS::Plugin::CardCapabilities::IdentityData);
    CardObject card(*agentBus, sdbus::ObjectPath{kCardPath}, kIdentityBit, sdbus::ObjectPath{kReaderPath}, mgr,
                    std::move(deps));

    auto client = sdbus::createSessionBusConnection();
    ASSERT_NE(client, nullptr);
    client->enterEventLoopAsync();

    auto cardProxy = sdbus::createProxy(*client, sdbus::ServiceName{kAgentServiceCancel}, sdbus::ObjectPath{kCardPath});
    sdbus::ObjectPath opPath;
    cardProxy->callMethod("ReadIdentity").onInterface(sdbus::InterfaceName{kCard1Iface}).storeResultsTo(opPath);
    ASSERT_FALSE(std::string{opPath}.empty());

    // Production CardObject::ReadIdentity has already called
    // OperationManager::recordSender() with the client's unique name --
    // captured automatically via getCurrentlyProcessedMessage(). No
    // test-side simulation here; that is the contract under test.

    // Give the worker a moment to begin the read loop so the cancel hits
    // it mid-flight rather than as a pre-flight bypass.
    std::this_thread::sleep_for(80ms);

    // Drop the client connection -- bus dispatches NameOwnerChanged on
    // agentBus with empty new-owner for the client's unique name. The
    // agent's listener picks it up and triggers cancel, which trips
    // the CancellableReader's cancel poll.
    client.reset();

    // Allow time for: NameOwnerChanged dispatch + cancel propagation +
    // CancellableReader exit + IdentityReadFlow tail + finish() +
    // OperationManager's cleanup-grace queue. The op object stays
    // exported for 5 s post-finish, so a property Get within ~1 s of the
    // disconnect lands while it is still on the bus.
    std::this_thread::sleep_for(1500ms);

    // Verify the op transitioned to Done -- Properties.Get on Phase via a
    // fresh client connection.
    auto checker = sdbus::createSessionBusConnection();
    ASSERT_NE(checker, nullptr);
    checker->enterEventLoopAsync();
    auto opProxy = sdbus::createProxy(*checker, sdbus::ServiceName{kAgentServiceCancel}, opPath);
    sdbus::Variant phase;
    opProxy->callMethod("Get")
        .onInterface(sdbus::InterfaceName{"org.freedesktop.DBus.Properties"})
        .withArguments(std::string{kOperation1Iface}, std::string{"Phase"})
        .storeResultsTo(phase);
    EXPECT_EQ(phase.get<std::uint32_t>(), static_cast<std::uint32_t>(OperationPhase::Done))
        << "expected OperationPhase::Done (7) after disconnect-driven cancel";

    checker->leaveEventLoop();
    prompterBus->leaveEventLoop();
    agentBus->leaveEventLoop();
}

// ---------------------------------------------------------------------------
// The deferred-async PKCS#11 worker hop (OperationManager::enqueueOnReaderWorker
// — used by Login/SignRaw/Decrypt/CertDer/PublicKey) MUST thread the real PC/SC
// reader name through to workerFor -> the per-reader CardSessionHolder. A
// regression here (an empty name) makes the CACHED holder open
// CardSession::open("") and fail every op on a first-touch sign/login, poisoning
// the reader; the read paths (enqueue*) thread deps.readerName, so the
// divergence would be sign-first-only.
//
// enqueueOnReaderWorker requires the production-bus ctor (it throws when !m_bus),
// so the bus-less OperationManagerTest cannot reach it — this lives here, under
// dbus-run-session, with a name-recording SessionFactory.
// ---------------------------------------------------------------------------
TEST(CardOperationsIntegration, EnqueueOnReaderWorkerBuildsHolderWithRealReaderName)
{
    auto agentBus = sdbus::createSessionBusConnection();
    ASSERT_NE(agentBus, nullptr) << "run under dbus-run-session";
    agentBus->enterEventLoopAsync();

    OperationManager mgr(nullptr); // production (cleanup-grace) mode; no resolver

    // Capture the reader name the per-reader holder opens with (production opens
    // CardSession::open(readerName); the bug opened CardSession::open("")).
    auto recorded = std::make_shared<std::string>("<<factory-not-called>>");
    mgr.setSessionFactoryForTest(
        [recorded](const std::string& r)
            -> std::expected<std::shared_ptr<LibreSCRS::SmartCard::CardSession>, LibreSCRS::SmartCard::OpenError> {
            *recorded = r;
            return LibreSCRS::SmartCard::detail::makeDetachedCardSession(r);
        });

    // Drive the worker hop as the FIRST op on this reader, so workerFor CREATES
    // the holder here (the only moment readerName is consumed). enqueue is async,
    // so poll for the worker thread to run the probe before asserting.
    constexpr const char* kRealReaderName = "Gemalto PC Twin Reader (69988A87) 00 00";
    auto acquired = std::make_shared<std::atomic<bool>>(false);
    const bool queued = mgr.enqueueOnReaderWorker(ObjectId{1}, kRealReaderName, [acquired](CardSessionHolder& holder) {
        acquired->store(holder.acquire().has_value());
    });
    ASSERT_TRUE(queued) << "enqueueOnReaderWorker should accept the first op on the reader";

    for (int i = 0; i < 200 && !acquired->load(); ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds{5});
    }

    EXPECT_TRUE(acquired->load()) << "holder.acquire() should succeed against the detached fake session";
    EXPECT_EQ(*recorded, kRealReaderName)
        << "enqueueOnReaderWorker must build the per-reader CardSessionHolder with the REAL reader name, never an "
           "empty string (an empty name fails CardSession::open and poisons a first-touch SignRaw/Login)";

    agentBus->leaveEventLoop();
}

namespace {
constexpr const char* kAgentServiceLoad = "org.librescrs.Agent.Test.E2E.Load";
constexpr const char* kPrompterServiceLoad = "org.librescrs.Prompter1.Test.E2E.Load";

// Near-instant reader: no sleep, so each ReadIdentity finishes microseconds after
// the worker picks it up and lands in the 5 s cleanup-grace queue. A sustained
// burst therefore keeps the cleanup-grace thread DESTROYING expired ops (each
// destructor unregisters its Operation1 adaptor from the bus) WHILE the dispatch
// thread is enqueuing fresh ops — the exact overlap that exposes the bus<->agent
// lock-order inversion if cleanupLoop holds m_pathMutex/m_finishedMutex across the
// adaptor's Object::unregister.
class InstantReader final : public CardReader
{
public:
    ReadOutcome read(LibreSCRS::SmartCard::CardSession&, const CandidateList&, LibreSCRS::CancelToken,
                     GroupReadCallback = {}) override
    {
        CardReadSnapshot snap;
        snap.cardType = "fake-card";
        return ReadOutcome{ReadOutcome::Status::Ok, std::move(snap), ""};
    }
    GroupSnapshot readTokenInfo(LibreSCRS::SmartCard::CardSession&, const CandidateList&,
                                LibreSCRS::CancelToken) override
    {
        return {};
    }
};
} // namespace

// Regression for the sustained-load dispatch-thread wedge (lock-order inversion
// between the sd_bus connection mutex and m_pathMutex). cleanupLoop used to
// destroy each expired op — running its Operation1 adaptor's Object::unregister,
// which takes the sd_bus connection mutex — WHILE holding m_finishedMutex +
// m_pathMutex. The single bus dispatch thread holds the connection mutex across
// every method-call slot and, inside ReadIdentity -> enqueueIdentity, blocks on
// m_pathMutex to publish the new op. Under sustained load the two orderings cross
// and the whole agent deadlocks (D-Bus goes unresponsive, SIGTERM is ignored).
//
// This test drives a sustained ReadIdentity burst for longer than the 5 s grace
// so the cleanup-grace destruction overlaps live enqueues, then asserts the bus
// is STILL responsive (a fresh method call returns within a tight deadline). If
// the inversion regressed, the dispatch thread wedges and this final call hangs
// past the gtest timeout.
TEST(CardOperationsIntegration, SustainedReadLoadKeepsDispatchThreadResponsive)
{
    std::shared_ptr<sdbus::IConnection> agentBus = sdbus::createSessionBusConnection();
    ASSERT_NE(agentBus, nullptr) << "run under dbus-run-session";
    agentBus->requestName(sdbus::ServiceName{kAgentServiceLoad});

    auto prompterBus = sdbus::createSessionBusConnection();
    ASSERT_NE(prompterBus, nullptr);
    prompterBus->requestName(sdbus::ServiceName{kPrompterServiceLoad});
    FakePrompterService prompterHost(*prompterBus, sdbus::ObjectPath{kPrompterObject});

    agentBus->enterEventLoopAsync();
    prompterBus->enterEventLoopAsync();

    InstantReader reader;
    PrompterClient prompterClient(kPrompterServiceLoad, kPrompterObject);
    CredentialCache credCache;
    CardReadCache readCache;
    PromptSerializer serializer;
    OperationManager mgr(nullptr); // production (cleanup-grace) mode; no resolver
    mgr.setSessionFactoryForTest(fakeSessionFactory());
    // This test asserts dispatch-thread responsiveness under sustained load, not
    // disconnect-cancel, so no client-disconnect watch is wired.

    auto deps = makeDeps(reader, prompterClient, serializer, credCache, readCache);
    constexpr std::uint32_t kIdentityBit =
        static_cast<std::uint32_t>(LibreSCRS::Plugin::CardCapabilities::IdentityData);
    CardObject card(*agentBus, sdbus::ObjectPath{kCardPath}, kIdentityBit, sdbus::ObjectPath{kReaderPath}, mgr,
                    std::move(deps));

    auto client = sdbus::createSessionBusConnection();
    ASSERT_NE(client, nullptr);
    client->enterEventLoopAsync();
    auto cardProxy = sdbus::createProxy(*client, sdbus::ServiceName{kAgentServiceLoad}, sdbus::ObjectPath{kCardPath});

    // One ReadIdentity round-trip. Returns:
    //   true   = the dispatch thread answered (either an op path, or the BENIGN,
    //            by-design RateLimited backpressure when the per-reader backlog is
    //            momentarily full — both prove the bus is alive).
    //   false  = a connection/timeout error, i.e. the dispatch thread is WEDGED.
    constexpr const char* kRateLimited = "org.librescrs.Agent.Error.RateLimited";
    auto pokeDispatch = [&]() -> bool {
        try {
            sdbus::ObjectPath p;
            cardProxy->callMethod("ReadIdentity").onInterface(sdbus::InterfaceName{kCard1Iface}).storeResultsTo(p);
            return true;
        } catch (const sdbus::Error& e) {
            // RateLimited is the backpressure cap doing its job (the dispatch
            // thread replied synchronously) — NOT a wedge. Anything else
            // (Error.Timeout / NoReply / Disconnected) is the wedge signature.
            return e.getName() == kRateLimited;
        }
    };

    // Drive ReadIdentity for > the 5 s cleanup grace so expired-op destruction
    // (adaptor unregister) overlaps live enqueues. A tiny pace keeps the single
    // worker draining (so the backlog cap is not permanently saturated) while
    // still sustaining heavy concurrent enqueue/cleanup pressure on m_pathMutex.
    const auto loadDeadline = std::chrono::steady_clock::now() + 6500ms;
    std::uint64_t issued = 0;
    while (std::chrono::steady_clock::now() < loadDeadline) {
        ASSERT_TRUE(pokeDispatch()) << "dispatch thread wedged after " << issued
                                    << " reads (bus<->m_pathMutex lock-order inversion regressed)";
        ++issued;
        std::this_thread::sleep_for(2ms);
    }
    EXPECT_GT(issued, 50u) << "expected a sustained burst of reads across the cleanup grace window";

    // The decisive assertion: AFTER the sustained load, the dispatch thread must
    // still answer promptly. A wedged agent (the bug) leaves this hanging until
    // the sdbus call timeout; a healthy agent returns within milliseconds. Allow a
    // brief settle for any transient backlog-full to clear.
    bool responsive = false;
    const auto settleDeadline = std::chrono::steady_clock::now() + 2s;
    while (!responsive && std::chrono::steady_clock::now() < settleDeadline) {
        responsive = pokeDispatch();
        if (!responsive) {
            std::this_thread::sleep_for(20ms);
        }
    }
    EXPECT_TRUE(responsive) << "D-Bus must stay RESPONSIVE after the sustained read flood (no dispatch-thread wedge)";

    client->leaveEventLoop();
    prompterBus->leaveEventLoop();
    agentBus->leaveEventLoop();
}

// ---------------------------------------------------------------------------
// Card1.PreReadAuthMethod is resolved on the per-reader worker-held session
// (the sole CardSession opener) and published on the EVENT-LOOP thread.
//
// PresenceModel exports a card with the pending "None" token (pre-read auth
// needs a live session, which only the worker may touch). BusExporter::onAdd
// then enqueues a worker hop that computes preReadAuth() on the held session and
// marshals the result back onto the loop thread (EventLoopPoster) to update the
// live CardObject + emit PropertiesChanged. This drives the full path over a real
// bus attached to a user sd-event loop (the production topology) and asserts:
//   * Card1.PreReadAuthMethod becomes "Can" shortly after insert, and
//   * NO transient CardSession::open happened on the monitor thread (the
//     resolver's probe seams were never reached).
// ---------------------------------------------------------------------------
namespace {

constexpr const char* kAgentServicePreRead = "org.librescrs.Agent.Test.E2E.PreReadAuth";

// CardPlugin double: IdentityData-capable, reports Can as its pre-read auth.
class CanStubPlugin final : public LibreSCRS::Plugin::CardPlugin
{
public:
    CanStubPlugin()
    {
        setIdentity("can-stub", "stub", 0);
    }
    LibreSCRS::Plugin::CardCapabilities capabilities() const override
    {
        return LibreSCRS::Plugin::CardCapabilities::IdentityData;
    }
    std::span<const LibreSCRS::Plugin::Atr> supportedAtrs() const noexcept override
    {
        return {};
    }
    LibreSCRS::Auth::PreReadAuthMethod preReadAuth(LibreSCRS::SmartCard::CardSession& /*session*/) const override
    {
        return LibreSCRS::Auth::PreReadAuthMethod::Can;
    }

protected:
    LibreSCRS::Plugin::ReadResult doReadCard(LibreSCRS::SmartCard::CardSession& /*session*/,
                                             GroupCallback /*onGroup*/) const override
    {
        return LibreSCRS::Plugin::ReadResult::communicationError(LibreSCRS::Auth::ErrorKeys::genericComm());
    }
};

// Resolver: ATR-only capabilities (no session) + held-session candidates (the
// Can plugin). No transient session-opening seam remains, so the monitor
// thread cannot open a transient CardSession; pre-read auth is resolved on the
// worker via resolveCandidates on the held session.
class CanResolver final : public CapabilityResolver
{
public:
    std::shared_ptr<const LibreSCRS::Plugin::CardPlugin>
    resolvePlugin(std::span<const std::uint8_t> atr) const noexcept override
    {
        if (atr.empty()) {
            return nullptr;
        }
        return std::make_shared<CanStubPlugin>();
    }
    std::vector<std::shared_ptr<const LibreSCRS::Plugin::CardPlugin>>
    resolveCandidates(std::span<const std::uint8_t>, LibreSCRS::SmartCard::CardSession&) override
    {
        return {std::make_shared<CanStubPlugin>()};
    }
};

class NopPrompter final : public PrompterClientBase
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

TEST(CardOperationsIntegration, PreReadAuthResolvedOnWorkerAndPublishedOnLoop)
{
    std::shared_ptr<sdbus::IConnection> serverConn = sdbus::createSessionBusConnection();
    ASSERT_NE(serverConn, nullptr) << "run under dbus-run-session";
    serverConn->requestName(sdbus::ServiceName{kAgentServicePreRead});

    // Drive the server connection via a USER sd-event loop (attachSdEventLoop +
    // sd_event_loop) — the production topology — so the worker->loop marshal posts
    // the Card1 update onto the same loop that dispatches the property getters.
    sd_event* ev = nullptr;
    ASSERT_GE(sd_event_new(&ev), 0);
    serverConn->attachSdEventLoop(ev);

    {
        // Declared FIRST so its shared_ptr is dropped LAST (after the OperationManager
        // joins its workers and after the exporter), matching the production
        // declaration-order discipline. The transport + resolver sinks shared-own the
        // poster, so the underlying object outlives every worker that might post to it.
        auto poster = std::make_shared<EventLoopPoster>(ev);

        CanResolver resolver;
        ObjectRegistry registry;
        PresenceModel model(registry, resolver);
        auto prompter = std::make_shared<NopPrompter>();
        auto serializer = std::make_shared<PromptSerializer>();
        auto credCache = std::make_shared<CredentialCache>();
        CardReadCache readCache;
        const auto cfgDir = std::filesystem::temp_directory_path() / "ll-prereadauth-e2e";
        Config::ConfigStore cfg(cfgDir / "agent.conf", cfgDir / "cache");
        SigningEngineProvider signingEngine(cfg);
        AllowAllAuthorizer authz;
        RateLimiter rateLimiter;

        // Production ctor + the resolver so the per-reader holder resolves the
        // Can candidate; the detached fake session stands in for PC/SC.
        OperationManager mgr(&resolver);
        mgr.setSessionFactoryForTest(fakeSessionFactory());

        BusExporter exporter(*serverConn, registry);
        exporter.attachLoopPoster(poster);
        // The frontend records the pending card + enqueues the worker resolve, then
        // creates the Card1 on the loop thread when the resolve lands. This suite
        // exercises the deferred-publish path, not Pkcs11_1, so the broker is null.
        auto cryptoCtx = std::make_shared<CryptoWorkerContext>(
            CryptoWorkerContext{.prompter = prompter, .serializer = serializer, .credentials = credCache});
        AgentFrontend frontend(exporter, serverConn, mgr, cryptoCtx, readCache, signingEngine, authz, rateLimiter, cfg,
                               nullptr, "test");

        // onCardInserted fires materialization synchronously: it records the card
        // pending AND enqueues the worker pre-read-auth resolve.
        model.onReaderAdded("R0");
        model.onCardInserted("R0", {0x3B, 0x01});

        // Now start pumping the server loop: it dispatches client property reads
        // AND drains the worker's marshaled Card1 update. sd-event objects are
        // single-thread-affine, so the loop is driven (and only ever touched) on
        // THIS thread via a bounded sd_event_run tick; the main thread requests
        // shutdown with an atomic instead of a cross-thread sd_event_exit (which
        // cannot safely wake a loop owned by another thread).
        std::atomic<bool> stopLoop{false};
        std::jthread loopThread([ev, &stopLoop] {
            while (!stopLoop.load(std::memory_order_acquire)) {
                sd_event_run(ev, 50'000); // 50 ms tick
            }
        });

        auto client = sdbus::createSessionBusConnection();
        ASSERT_NE(client, nullptr);
        client->enterEventLoopAsync();
        auto cardProxy =
            sdbus::createProxy(*client, sdbus::ServiceName{kAgentServicePreRead}, sdbus::ObjectPath{kCardPath});

        std::string method = "<unset>";
        const auto deadline = std::chrono::steady_clock::now() + 3s;
        while (std::chrono::steady_clock::now() < deadline) {
            // The card is published via the deferred resolve (created on the loop
            // thread only AFTER the worker resolves caps + pre-read auth on the held
            // session), so Properties.Get throws UnknownObject until it exists —
            // tolerate that window and retry.
            try {
                sdbus::Variant v;
                cardProxy->callMethod("Get")
                    .onInterface(sdbus::InterfaceName{"org.freedesktop.DBus.Properties"})
                    .withArguments(std::string{kCard1Iface}, std::string{"PreReadAuthMethod"})
                    .storeResultsTo(v);
                method = v.get<std::string>();
            } catch (const sdbus::Error&) {
                method = "<unexported>";
            }
            if (method == "Can") {
                break;
            }
            std::this_thread::sleep_for(20ms);
        }

        EXPECT_EQ(method, "Can") << "the worker-resolved pre-read auth must be published on Card1.PreReadAuthMethod";

        client->leaveEventLoop();
        stopLoop.store(true, std::memory_order_release);
        loopThread.join();
        serverConn->detachSdEventLoop();
        // Inner-scope locals destruct here (reverse decl order): frontend, then
        // exporter, then mgr (joins its workers), then ... then poster.
    }
    sd_event_unref(ev);
}

// ---------------------------------------------------------------------------
// A card whose plugin family ships an EMPTY ATR table (eMRTD / health / pkcs15 /
// opensc / eu-vrc) is identified ONLY by the AID probe on an OPEN session:
// resolvePlugin(atr) returns nullptr, so an ATR-only capability resolution
// publishes Capabilities=0 and the fail-closed CardObject gate then refuses
// EVERY operation (ReadIdentity / GetPhoto / ReadCertificates / Sign). The agent
// must instead resolve capabilities from the per-reader worker-HELD session
// (CapabilityResolver::resolveCandidates, via CardSessionHolder::fullResolution)
// and create the Card1 object only AFTER that resolution completes, so the FIRST
// published snapshot carries the correct, NON-ZERO Capabilities AND the correct
// PreReadAuthMethod together (deferred publish).
//
// Asserts on the GetManagedObjects snapshot (exactly what the first-party PKCS#11
// client reads): the very first time card/0 appears it already carries caps != 0
// AND PreReadAuthMethod == "Can" in the SAME snapshot. On the pre-deferred
// code the card is exported synchronously with the ATR-only caps=0, so this fails.
// ---------------------------------------------------------------------------
namespace {

constexpr const char* kAgentServiceAidProbe = "org.librescrs.Agent.Test.E2E.AidProbe";
constexpr const char* kRootPath = "/org/librescrs/Agent";

using ManagedObjects = std::map<sdbus::ObjectPath, std::map<std::string, std::map<std::string, sdbus::Variant>>>;

// IdentityData|PKI-capable, Can pre-read auth, EMPTY ATR table — the
// AID-probe-only family shape (eMRTD / health / pkcs15 / opensc).
class AidProbeCapablePlugin final : public LibreSCRS::Plugin::CardPlugin
{
public:
    AidProbeCapablePlugin()
    {
        setIdentity("aid-probe-stub", "stub", 0);
    }
    LibreSCRS::Plugin::CardCapabilities capabilities() const override
    {
        return static_cast<LibreSCRS::Plugin::CardCapabilities>(
            static_cast<std::uint32_t>(LibreSCRS::Plugin::CardCapabilities::IdentityData) |
            static_cast<std::uint32_t>(LibreSCRS::Plugin::CardCapabilities::PKI));
    }
    std::span<const LibreSCRS::Plugin::Atr> supportedAtrs() const noexcept override
    {
        return {}; // empty ATR table: identified only via the AID probe
    }
    LibreSCRS::Auth::PreReadAuthMethod preReadAuth(LibreSCRS::SmartCard::CardSession& /*session*/) const override
    {
        return LibreSCRS::Auth::PreReadAuthMethod::Can;
    }

protected:
    LibreSCRS::Plugin::ReadResult doReadCard(LibreSCRS::SmartCard::CardSession& /*session*/,
                                             GroupCallback /*onGroup*/) const override
    {
        return LibreSCRS::Plugin::ReadResult::communicationError(LibreSCRS::Auth::ErrorKeys::genericComm());
    }
};

// AID-probe-only resolver: NO ATR fast-path match (resolvePlugin -> nullptr); the
// capable plugin is found ONLY on the open held session (resolveCandidates).
class AidProbeOnlyResolver final : public CapabilityResolver
{
public:
    std::shared_ptr<const LibreSCRS::Plugin::CardPlugin>
    resolvePlugin(std::span<const std::uint8_t>) const noexcept override
    {
        return nullptr;
    }
    std::vector<std::shared_ptr<const LibreSCRS::Plugin::CardPlugin>>
    resolveCandidates(std::span<const std::uint8_t>, LibreSCRS::SmartCard::CardSession&) override
    {
        return {std::make_shared<AidProbeCapablePlugin>()};
    }
};

} // namespace

TEST(CardOperationsIntegration, CapabilitiesResolvedFromHeldSessionForAidProbeOnlyCard)
{
    std::shared_ptr<sdbus::IConnection> serverConn = sdbus::createSessionBusConnection();
    ASSERT_NE(serverConn, nullptr) << "run under dbus-run-session";
    serverConn->requestName(sdbus::ServiceName{kAgentServiceAidProbe});

    sd_event* ev = nullptr;
    ASSERT_GE(sd_event_new(&ev), 0);
    serverConn->attachSdEventLoop(ev);

    {
        auto poster = std::make_shared<EventLoopPoster>(ev);

        AidProbeOnlyResolver resolver;
        ObjectRegistry registry;
        PresenceModel model(registry, resolver);
        auto prompter = std::make_shared<NopPrompter>();
        auto serializer = std::make_shared<PromptSerializer>();
        auto credCache = std::make_shared<CredentialCache>();
        CardReadCache readCache;
        const auto cfgDir = std::filesystem::temp_directory_path() / "ll-aidprobe-e2e";
        Config::ConfigStore cfg(cfgDir / "agent.conf", cfgDir / "cache");
        SigningEngineProvider signingEngine(cfg);
        AllowAllAuthorizer authz;
        RateLimiter rateLimiter;

        OperationManager mgr(&resolver);
        mgr.setSessionFactoryForTest(fakeSessionFactory());

        BusExporter exporter(*serverConn, registry);
        exporter.attachLoopPoster(poster);

        // The frontend owns the exported objects + the root ManagerObject (which
        // hosts the ObjectManager so the client can call GetManagedObjects — the
        // snapshot the first-party PKCS#11 client reads). This suite reads the
        // presence snapshot, not Pkcs11_1, so the broker is null.
        auto cryptoCtx = std::make_shared<CryptoWorkerContext>(
            CryptoWorkerContext{.prompter = prompter, .serializer = serializer, .credentials = credCache});
        AgentFrontend frontend(exporter, serverConn, mgr, cryptoCtx, readCache, signingEngine, authz, rateLimiter, cfg,
                               nullptr, "test");

        // onCardInserted fires materialization synchronously: the card is recorded PENDING and
        // a worker hop resolves caps + pre-read auth on the held session — the Card1
        // is NOT exported here.
        model.onReaderAdded("R0");
        model.onCardInserted("R0", {0x3B, 0x77}); // non-empty ATR, still no ATR-table match

        std::atomic<bool> stopLoop{false};
        std::jthread loopThread([ev, &stopLoop] {
            while (!stopLoop.load(std::memory_order_acquire)) {
                sd_event_run(ev, 50'000); // 50 ms tick
            }
        });

        auto client = sdbus::createSessionBusConnection();
        ASSERT_NE(client, nullptr);
        client->enterEventLoopAsync();
        auto rootProxy =
            sdbus::createProxy(*client, sdbus::ServiceName{kAgentServiceAidProbe}, sdbus::ObjectPath{kRootPath});

        // Poll GetManagedObjects until card/0 appears. With the deferred publish the
        // card is NEVER exported with the ATR-only caps=0: the first snapshot that
        // contains it already carries the held-session-resolved values, co-published.
        std::uint32_t caps = 0;
        std::string preRead = "<unset>";
        bool sawCard = false;
        const auto deadline = std::chrono::steady_clock::now() + 3s;
        while (std::chrono::steady_clock::now() < deadline) {
            ManagedObjects managed;
            rootProxy->callMethod("GetManagedObjects")
                .onInterface(sdbus::InterfaceName{"org.freedesktop.DBus.ObjectManager"})
                .storeResultsTo(managed);
            auto it = managed.find(sdbus::ObjectPath{kCardPath});
            if (it != managed.end() && it->second.contains(kCard1Iface)) {
                const auto& props = it->second.at(kCard1Iface);
                caps = props.at("Capabilities").get<std::uint32_t>();
                preRead = props.at("PreReadAuthMethod").get<std::string>();
                sawCard = true;
                break;
            }
            std::this_thread::sleep_for(20ms);
        }

        EXPECT_TRUE(sawCard) << "card/0 must eventually be published";
        constexpr std::uint32_t kExpectedCaps =
            static_cast<std::uint32_t>(LibreSCRS::Plugin::CardCapabilities::IdentityData) |
            static_cast<std::uint32_t>(LibreSCRS::Plugin::CardCapabilities::PKI);
        EXPECT_NE(caps, 0u)
            << "Capabilities must be resolved from the held session (AID probe), not ATR-only — an "
               "ATR-only 0 would fail-close every operation on an eMRTD / health / pkcs15 / opensc card";
        EXPECT_EQ(caps, kExpectedCaps);
        EXPECT_EQ(preRead, "Can")
            << "the same published snapshot must carry the correct PreReadAuthMethod (co-published, not async-after)";

        client->leaveEventLoop();
        stopLoop.store(true, std::memory_order_release);
        loopThread.join();
        serverConn->detachSdEventLoop();
    }
    sd_event_unref(ev);
}

// ---------------------------------------------------------------------------
// Card1.CardType + Card1.Atr. Mirrors PreReadAuthResolvedOnWorkerAndPublishedOnLoop's
// harness exactly (same deferred-publish machinery resolves cardType alongside
// caps/preReadAuth), then drives a REAL ReadIdentity through the SAME held
// session's ARBITRATED candidate to prove the post-read authoritative update
// reaches an already-published CardObject via PropertiesChanged (not just at
// construction time). Asserts:
//   * Atr is the uppercase-hex ATR, published from the FIRST snapshot;
//   * CardType is the arbitrated candidate's pluginId, ALSO from the FIRST
//     snapshot (the deferred-resolve point, not a later push);
//   * a completed ReadIdentity flips CardType to the read's authoritative
//     CardData::cardType (deliberately a DIFFERENT string than the pluginId
//     here, so the flip is unambiguous — not a coincidental re-read of the
//     same value).
// ---------------------------------------------------------------------------
namespace {

constexpr const char* kAgentServiceCardType = "org.librescrs.Agent.Test.E2E.CardType";
constexpr const char* kCardTypeAtInsertion = "srb-eid-stub";
constexpr const char* kCardTypeFromRead = "SRB-eID-authoritative-read";

// CardPlugin double: IdentityData-capable, no pre-read unlock, and a
// successful read whose CardData::cardType is DELIBERATELY DIFFERENT from
// pluginId() — proving the post-read push is a real value change, not a
// re-assertion. Identity is parameterised so the resolver below can present
// a CONTESTED candidate list: the id and priority are the whole point.
class CardTypeStubPlugin final : public LibreSCRS::Plugin::CardPlugin
{
public:
    explicit CardTypeStubPlugin(const char* id = kCardTypeAtInsertion, int priority = 100)
    {
        setIdentity(id, "stub", priority);
    }
    LibreSCRS::Plugin::CardCapabilities capabilities() const override
    {
        return LibreSCRS::Plugin::CardCapabilities::IdentityData;
    }
    std::span<const LibreSCRS::Plugin::Atr> supportedAtrs() const noexcept override
    {
        return {};
    }
    LibreSCRS::Auth::PreReadAuthMethod preReadAuth(LibreSCRS::SmartCard::CardSession& /*session*/) const override
    {
        return LibreSCRS::Auth::PreReadAuthMethod::None;
    }

protected:
    LibreSCRS::Plugin::ReadResult doReadCard(LibreSCRS::SmartCard::CardSession& /*session*/,
                                             GroupCallback /*onGroup*/) const override
    {
        return LibreSCRS::Plugin::ReadResult::ok(
            LibreSCRS::Plugin::CardData{.cardType = kCardTypeFromRead, .groups = {}});
    }
};

// Resolver: ATR-only resolvePlugin() never matches (empty table -> the
// PresenceModel-level insertion always publishes an empty cardType, exactly
// like the pinned "empty until known" default); resolveCandidates() (the
// held-session path) presents TWO candidates at different priorities. The
// published property must type as the strictly-lower-priority one — the
// two-generic-plugins tie-break that used to leave the token typed EMPTY.
// This is the wiring pin: an AgentFrontend reverted to the old
// exactly-one-candidate rule resolves nothing here and the property
// assertions below time out RED.
class CardTypeResolver final : public CapabilityResolver
{
public:
    std::shared_ptr<const LibreSCRS::Plugin::CardPlugin>
    resolvePlugin(std::span<const std::uint8_t> /*atr*/) const noexcept override
    {
        return nullptr;
    }
    std::vector<std::shared_ptr<const LibreSCRS::Plugin::CardPlugin>>
    resolveCandidates(std::span<const std::uint8_t>, LibreSCRS::SmartCard::CardSession&) override
    {
        // The winner (priority 100) is deliberately NOT first. With it at the
        // front, a revert of the arbitration to `candidates.front()` would
        // still produce the right answer and this pin would not notice — and
        // list order is precisely what the rule refuses to trust, because the
        // registry sorts ATR matches and AID probes in two independent runs.
        return {std::make_shared<CardTypeStubPlugin>("contender-generic", 900), std::make_shared<CardTypeStubPlugin>()};
    }
};

} // namespace

TEST(CardOperationsIntegration, CardTypeAndAtrResolvedAtInsertionThenAuthoritativelyUpdatedAfterRead)
{
    std::shared_ptr<sdbus::IConnection> serverConn = sdbus::createSessionBusConnection();
    ASSERT_NE(serverConn, nullptr) << "run under dbus-run-session";
    serverConn->requestName(sdbus::ServiceName{kAgentServiceCardType});

    sd_event* ev = nullptr;
    ASSERT_GE(sd_event_new(&ev), 0);
    serverConn->attachSdEventLoop(ev);

    {
        auto poster = std::make_shared<EventLoopPoster>(ev);

        CardTypeResolver resolver;
        ObjectRegistry registry;
        PresenceModel model(registry, resolver);
        auto prompter = std::make_shared<NopPrompter>();
        auto serializer = std::make_shared<PromptSerializer>();
        auto credCache = std::make_shared<CredentialCache>();
        CardReadCache readCache;
        const auto cfgDir = std::filesystem::temp_directory_path() / "ll-cardtype-e2e";
        Config::ConfigStore cfg(cfgDir / "agent.conf", cfgDir / "cache");
        SigningEngineProvider signingEngine(cfg);
        AllowAllAuthorizer authz;
        RateLimiter rateLimiter;

        OperationManager mgr(&resolver);
        mgr.setSessionFactoryForTest(fakeSessionFactory());

        BusExporter exporter(*serverConn, registry);
        exporter.attachLoopPoster(poster);

        auto cryptoCtx = std::make_shared<CryptoWorkerContext>(
            CryptoWorkerContext{.prompter = prompter, .serializer = serializer, .credentials = credCache});
        AgentFrontend frontend(exporter, serverConn, mgr, cryptoCtx, readCache, signingEngine, authz, rateLimiter, cfg,
                               nullptr, "test");

        const std::vector<std::uint8_t> atr{0x3B, 0x7F, 0x96, 0x00};
        model.onReaderAdded("R0");
        model.onCardInserted("R0", atr); // -> atrHex "3B7F9600"

        std::atomic<bool> stopLoop{false};
        std::jthread loopThread([ev, &stopLoop] {
            while (!stopLoop.load(std::memory_order_acquire)) {
                sd_event_run(ev, 50'000); // 50 ms tick
            }
        });

        auto client = sdbus::createSessionBusConnection();
        ASSERT_NE(client, nullptr);
        client->enterEventLoopAsync();
        auto cardProxy =
            sdbus::createProxy(*client, sdbus::ServiceName{kAgentServiceCardType}, sdbus::ObjectPath{kCardPath});

        auto getProp = [&](const char* name) -> std::string {
            sdbus::Variant v;
            cardProxy->callMethod("Get")
                .onInterface(sdbus::InterfaceName{"org.freedesktop.DBus.Properties"})
                .withArguments(std::string{kCard1Iface}, std::string{name})
                .storeResultsTo(v);
            return v.get<std::string>();
        };

        // Step 1: the deferred-resolve snapshot (arbitrated cardType +
        // atrHex), before any read.
        std::string cardType = "<unset>";
        std::string atrProp = "<unset>";
        {
            const auto deadline = std::chrono::steady_clock::now() + 3s;
            while (std::chrono::steady_clock::now() < deadline) {
                try {
                    cardType = getProp("CardType");
                    atrProp = getProp("Atr");
                } catch (const sdbus::Error&) {
                    std::this_thread::sleep_for(20ms);
                    continue;
                }
                if (cardType == kCardTypeAtInsertion) {
                    break;
                }
                std::this_thread::sleep_for(20ms);
            }
        }
        EXPECT_EQ(atrProp, "3B7F9600") << "Atr must be the uppercase-hex ATR, published from insertion";
        EXPECT_EQ(cardType, kCardTypeAtInsertion)
            << "CardType must be the strictly-highest-priority held-session candidate's pluginId (100 beats 900 "
               "— arbitrated, not merely the only entry), co-published with caps/preReadAuth";

        // Step 2: a real ReadIdentity flips CardType to the read's
        // authoritative CardData::cardType via the property-update path.
        sdbus::ObjectPath opPath;
        cardProxy->callMethod("ReadIdentity").onInterface(sdbus::InterfaceName{kCard1Iface}).storeResultsTo(opPath);
        ASSERT_FALSE(opPath.empty());

        std::string cardTypeAfterRead = "<unset>";
        {
            const auto deadline = std::chrono::steady_clock::now() + 3s;
            while (std::chrono::steady_clock::now() < deadline) {
                cardTypeAfterRead = getProp("CardType");
                if (cardTypeAfterRead == kCardTypeFromRead) {
                    break;
                }
                std::this_thread::sleep_for(20ms);
            }
        }
        EXPECT_EQ(cardTypeAfterRead, kCardTypeFromRead)
            << "a completed read must authoritatively update CardType via PropertiesChanged, even though the card "
               "was already published before the read started";

        client->leaveEventLoop();
        stopLoop.store(true, std::memory_order_release);
        loopThread.join();
        serverConn->detachSdEventLoop();
    }
    sd_event_unref(ev);
}

// ---------------------------------------------------------------------------
// CRITICAL race regression: a card REMOVED while a read that resolves its
// cardType is STILL IN FLIGHT. withdrawObject's card branch does NOT drain the
// reader's in-flight ops (unlike the reader branch's removeReader), so the
// completing read fires onCardType -> applyCardTypeUpdate on the LOOP thread
// AFTER the CardObject was withdrawn on the MONITOR thread. The pre-fix code
// held a raw CardObject* across the m_cardsMutex unlock and could dereference
// freed memory; the fix co-owns the CardObject (shared_ptr copy taken under the
// lock) for the whole update so a concurrent withdraw only drops the map's owner.
//
// This drives the DETERMINISTIC slice the harness supports without a test-only
// seam: the withdraw fully lands (monitor thread, synchronous) while the read is
// parked mid-flight, THEN the read is released so the update marshals in for an
// already-gone card. It asserts the update is safely DROPPED — the process does
// not crash (a UAF here would trip under ASAN), the card stays unexported, and
// NO CardType PropertiesChanged is emitted for the withdrawn card — while still
// proving the update path was actually reached (the op reaches Finished, which
// only happens once the read completed and fired onCardType). The pure
// use-after-free window (the update dereferencing the object mid-destroy) needs
// a latch BETWEEN applyCardTypeUpdate's lookup and its updateCardType() call,
// which has no non-seam injection point; see task-7-report.md.
// ---------------------------------------------------------------------------
namespace {

constexpr const char* kAgentServiceWithdrawRace = "org.librescrs.Agent.Test.E2E.WithdrawRace";
constexpr const char* kWithdrawRaceInsertionType = "latched-read-stub";
constexpr const char* kWithdrawRaceReadType = "latched-read-authoritative";

// Test-owned gate: doReadCard signals `entered` and then blocks on `release`, so
// the test can land the withdraw WHILE the read is parked mid-flight.
struct ReadGate
{
    std::binary_semaphore entered{0};
    std::binary_semaphore release{0};
};

// Single ATR-table-less candidate (held-session resolve), no pre-read unlock, a
// successful read whose CardData::cardType DIFFERS from pluginId() so a wrongly
// applied post-read update would be observable. doReadCard parks on the gate.
class LatchedReadPlugin final : public LibreSCRS::Plugin::CardPlugin
{
public:
    explicit LatchedReadPlugin(ReadGate* gate) : m_gate(gate)
    {
        setIdentity(kWithdrawRaceInsertionType, "stub", 0);
    }
    LibreSCRS::Plugin::CardCapabilities capabilities() const override
    {
        return LibreSCRS::Plugin::CardCapabilities::IdentityData;
    }
    std::span<const LibreSCRS::Plugin::Atr> supportedAtrs() const noexcept override
    {
        return {};
    }
    LibreSCRS::Auth::PreReadAuthMethod preReadAuth(LibreSCRS::SmartCard::CardSession& /*session*/) const override
    {
        return LibreSCRS::Auth::PreReadAuthMethod::None;
    }

protected:
    LibreSCRS::Plugin::ReadResult doReadCard(LibreSCRS::SmartCard::CardSession& /*session*/,
                                             GroupCallback /*onGroup*/) const override
    {
        if (m_gate != nullptr) {
            m_gate->entered.release(); // the read has started ...
            m_gate->release.acquire(); // ... park until the test lets it finish
        }
        return LibreSCRS::Plugin::ReadResult::ok(
            LibreSCRS::Plugin::CardData{.cardType = kWithdrawRaceReadType, .groups = {}});
    }

private:
    ReadGate* m_gate;
};

class LatchedReadResolver final : public CapabilityResolver
{
public:
    explicit LatchedReadResolver(ReadGate* gate) : m_gate(gate) {}
    std::shared_ptr<const LibreSCRS::Plugin::CardPlugin>
    resolvePlugin(std::span<const std::uint8_t>) const noexcept override
    {
        return nullptr;
    }
    std::vector<std::shared_ptr<const LibreSCRS::Plugin::CardPlugin>>
    resolveCandidates(std::span<const std::uint8_t>, LibreSCRS::SmartCard::CardSession&) override
    {
        return {std::make_shared<LatchedReadPlugin>(m_gate)};
    }

private:
    ReadGate* m_gate;
};

} // namespace

TEST(CardOperationsIntegration, CardTypeUpdateForWithdrawnCardIsDroppedWithoutCrash)
{
    std::shared_ptr<sdbus::IConnection> serverConn = sdbus::createSessionBusConnection();
    ASSERT_NE(serverConn, nullptr) << "run under dbus-run-session";
    serverConn->requestName(sdbus::ServiceName{kAgentServiceWithdrawRace});

    sd_event* ev = nullptr;
    ASSERT_GE(sd_event_new(&ev), 0);
    serverConn->attachSdEventLoop(ev);

    {
        auto poster = std::make_shared<EventLoopPoster>(ev);

        ReadGate gate;
        LatchedReadResolver resolver(&gate);
        ObjectRegistry registry;
        PresenceModel model(registry, resolver);
        auto prompter = std::make_shared<NopPrompter>();
        auto serializer = std::make_shared<PromptSerializer>();
        auto credCache = std::make_shared<CredentialCache>();
        CardReadCache readCache;
        const auto cfgDir = std::filesystem::temp_directory_path() / "ll-withdrawrace-e2e";
        Config::ConfigStore cfg(cfgDir / "agent.conf", cfgDir / "cache");
        SigningEngineProvider signingEngine(cfg);
        AllowAllAuthorizer authz;
        RateLimiter rateLimiter;

        OperationManager mgr(&resolver);
        mgr.setSessionFactoryForTest(fakeSessionFactory());

        BusExporter exporter(*serverConn, registry);
        exporter.attachLoopPoster(poster);

        auto cryptoCtx = std::make_shared<CryptoWorkerContext>(
            CryptoWorkerContext{.prompter = prompter, .serializer = serializer, .credentials = credCache});
        AgentFrontend frontend(exporter, serverConn, mgr, cryptoCtx, readCache, signingEngine, authz, rateLimiter, cfg,
                               nullptr, "test");

        model.onReaderAdded("R0");
        model.onCardInserted("R0", {0x3B, 0x10});

        std::atomic<bool> stopLoop{false};
        std::jthread loopThread([ev, &stopLoop] {
            while (!stopLoop.load(std::memory_order_acquire)) {
                sd_event_run(ev, 50'000); // 50 ms tick
            }
        });

        auto client = sdbus::createSessionBusConnection();
        ASSERT_NE(client, nullptr);
        client->enterEventLoopAsync();
        auto rootProxy =
            sdbus::createProxy(*client, sdbus::ServiceName{kAgentServiceWithdrawRace}, sdbus::ObjectPath{kRootPath});
        auto cardProxy =
            sdbus::createProxy(*client, sdbus::ServiceName{kAgentServiceWithdrawRace}, sdbus::ObjectPath{kCardPath});

        auto cardPresent = [&]() -> bool {
            ManagedObjects managed;
            rootProxy->callMethod("GetManagedObjects")
                .onInterface(sdbus::InterfaceName{"org.freedesktop.DBus.ObjectManager"})
                .storeResultsTo(managed);
            auto it = managed.find(sdbus::ObjectPath{kCardPath});
            return it != managed.end() && it->second.contains(kCard1Iface);
        };

        // Step 1: wait for the deferred publish (card exported with the
        // single-candidate insertion cardType).
        {
            const auto deadline = std::chrono::steady_clock::now() + 3s;
            while (std::chrono::steady_clock::now() < deadline && !cardPresent()) {
                std::this_thread::sleep_for(20ms);
            }
        }
        ASSERT_TRUE(cardPresent()) << "card/2 must be published before the race";

        // Watch for a CardType PropertiesChanged carrying the post-read value: the
        // withdrawn card must NEVER emit one (the update is dropped, not applied).
        std::atomic<bool> sawReadTypeEmit{false};
        cardProxy->uponSignal(sdbus::SignalName{"PropertiesChanged"})
            .onInterface(sdbus::InterfaceName{"org.freedesktop.DBus.Properties"})
            .call([&sawReadTypeEmit](const std::string& iface, const std::map<std::string, sdbus::Variant>& changed,
                                     const std::vector<std::string>&) {
                if (iface != kCard1Iface) {
                    return;
                }
                if (auto it = changed.find("CardType"); it != changed.end()) {
                    try {
                        if (it->second.get<std::string>() == kWithdrawRaceReadType) {
                            sawReadTypeEmit.store(true, std::memory_order_release);
                        }
                    } catch (const sdbus::Error&) {
                    }
                }
            });

        // Step 2: kick a read; it parks in doReadCard on the worker.
        sdbus::ObjectPath opPath;
        cardProxy->callMethod("ReadIdentity").onInterface(sdbus::InterfaceName{kCard1Iface}).storeResultsTo(opPath);
        ASSERT_FALSE(std::string{opPath}.empty());
        auto opProxy = sdbus::createProxy(*client, sdbus::ServiceName{kAgentServiceWithdrawRace}, opPath);
        std::atomic<int> finishedStatus{-1};
        opProxy->uponSignal(sdbus::SignalName{"Finished"})
            .onInterface(sdbus::InterfaceName{kOperation1Iface})
            .call([&finishedStatus](std::uint32_t status, std::uint32_t, const std::string&, const std::string&) {
                finishedStatus.store(static_cast<int>(status), std::memory_order_release);
            });

        // Wait until the read is provably in flight (parked in doReadCard).
        ASSERT_TRUE(gate.entered.try_acquire_for(3s)) << "the read must reach doReadCard";

        // Step 3: remove the card WHILE the read is parked. onCardRemoved runs the
        // registry withdraw -> withdrawObject synchronously on THIS (monitor)
        // thread, destroying the CardObject. The reader stays; the in-flight read
        // is NOT drained by the card withdraw.
        model.onCardRemoved("R0");
        {
            const auto deadline = std::chrono::steady_clock::now() + 3s;
            while (std::chrono::steady_clock::now() < deadline && cardPresent()) {
                std::this_thread::sleep_for(20ms);
            }
        }
        ASSERT_FALSE(cardPresent()) << "the card must be unexported after removal";

        // Step 4: release the read. It completes and fires onCardType -> the
        // update marshals onto the loop thread for the already-withdrawn card.
        gate.release.release();
        {
            const auto deadline = std::chrono::steady_clock::now() + 3s;
            while (finishedStatus.load(std::memory_order_acquire) < 0 && std::chrono::steady_clock::now() < deadline) {
                std::this_thread::sleep_for(20ms);
            }
        }
        EXPECT_GE(finishedStatus.load(std::memory_order_acquire), 0)
            << "the parked read must complete (proving onCardType fired for the withdrawn card)";

        // Let the marshaled update drain on the loop thread, then assert it was a
        // safe no-op: no crash reaching here, the card stays gone, and no CardType
        // emit ever fired for the withdrawn object.
        std::this_thread::sleep_for(200ms);
        EXPECT_FALSE(cardPresent()) << "a dropped update must not resurrect or re-touch the withdrawn card";
        EXPECT_FALSE(sawReadTypeEmit.load(std::memory_order_acquire))
            << "no CardType PropertiesChanged may be emitted for a withdrawn card";

        client->leaveEventLoop();
        stopLoop.store(true, std::memory_order_release);
        loopThread.join();
        serverConn->detachSdEventLoop();
    }
    sd_event_unref(ev);
}
