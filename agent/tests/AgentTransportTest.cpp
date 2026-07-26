// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Conformance test pinning the frozen AgentTransport backend surface.
// Proves the interface with a fake so any drift in the signatures/semantics the
// platform impls (Linux BusExporter, macOS XPC) must honour is caught at compile
// time (static_asserts) and run time:
//   1. publishReader/publishCard/withdraw/updateProperties are recorded verbatim
//      by an in-memory fake (typed presence deltas, no wire path or Variant).
//   2. post(fn) is a straight worker->loop hop the fake can run inline.
//   3. postAfter(delay, fn) carries the delay through to the backing sink.
//   4. onClientDisconnect(handler) registers a startup-wired handler the
//      backend fires with the disconnecting client's CallerToken.
// It also drives the real Linux BusExporter loop-marshaling implementation: its
// post/postAfter must marshal onto the EventLoopPoster attached via
// attachLoopPoster. That case needs a private session bus (dbus-run-session).

#include <LibreSCRS/Agent/backend/AgentTransport.h>
#include <LibreSCRS/Agent/backend/Authorizer.h>
#include "AgentFrontend.h"
#include <LibreSCRS/Agent/CryptoWorkerContext.h>
#include "BusExporter.h"
#include "EventLoopPoster.h"
#include <LibreSCRS/Agent/presence/CapabilityResolver.h>
#include <LibreSCRS/Agent/cache/CardReadCache.h>
#include <LibreSCRS/Agent/cache/CredentialCache.h>
#include <LibreSCRS/Agent/Identity.h>
#include <LibreSCRS/Agent/presence/ObjectRegistry.h>
#include <LibreSCRS/Agent/PresenceTypes.h>
#include <LibreSCRS/Agent/config/ConfigStore.h>
#include <LibreSCRS/Agent/operations/OperationManager.h>
#include <LibreSCRS/Agent/operations/PromptSerializer.h>
#include <LibreSCRS/Agent/backend/PrompterClientBase.h>
#include <LibreSCRS/Agent/operations/RateLimiter.h>
#include <LibreSCRS/Agent/operations/SigningEngineProvider.h>
#include <LibreSCRS/Agent/pkcs11/LeaseManager.h>

#include <sdbus-c++/sdbus-c++.h>
#include <systemd/sd-event.h>
#include <gtest/gtest.h>

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <type_traits>
#include <utility>
#include <vector>

using LibreSCRS::Agent::AgentFrontend;
using LibreSCRS::Agent::AgentTransport;
using LibreSCRS::Agent::AllowAllAuthorizer;
using LibreSCRS::Agent::BusExporter;
using LibreSCRS::Agent::CallerToken;
using LibreSCRS::Agent::CapabilityResolver;
using LibreSCRS::Agent::CardReadCache;
using LibreSCRS::Agent::CardState;
using LibreSCRS::Agent::CredentialCache;
using LibreSCRS::Agent::CryptoWorkerContext;
using LibreSCRS::Agent::EventLoopPoster;
using LibreSCRS::Agent::ObjectId;
using LibreSCRS::Agent::ObjectRegistry;
using LibreSCRS::Agent::PromptOptions;
using LibreSCRS::Agent::PromptResult;
using LibreSCRS::Agent::PropertyDelta;
using LibreSCRS::Agent::ReaderState;
using LibreSCRS::Agent::Config::ConfigStore;
using LibreSCRS::Agent::Operations::OperationManager;
using LibreSCRS::Agent::Operations::PrompterClientBase;
using LibreSCRS::Agent::Operations::PromptSerializer;
using LibreSCRS::Agent::Operations::RateLimiter;
using LibreSCRS::Agent::Operations::SigningEngineProvider;
using LibreSCRS::Agent::Pkcs11::LeaseConfig;
using LibreSCRS::Agent::Pkcs11::LeaseManager;

namespace {

// Minimal no-op backends the BusExporter ctor requires (it does no capability
// resolution or prompting in the loop-marshaling path under test).
class NopResolver : public CapabilityResolver
{};

class NopPrompter : public PrompterClientBase
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

// A fake exercising every arm of the frozen surface. Presence calls land in
// vectors, post() runs inline, postAfter() records its delay, and the disconnect
// handlers are stored (additive multi-subscriber, matching production) so the
// test can fire them all in order (as the real bus would).
class FakeAgentTransport final : public AgentTransport
{
public:
    std::vector<ReaderState> readers;
    std::vector<CardState> cards;
    std::vector<ObjectId> withdrawn;
    std::vector<std::pair<ObjectId, PropertyDelta>> propertyUpdates;
    std::vector<std::chrono::microseconds> postAfterDelays;
    std::vector<std::function<void(CallerToken)>> disconnectHandlers;

    void fireDisconnect(const CallerToken& caller)
    {
        for (const auto& handler : disconnectHandlers) {
            if (handler) {
                handler(caller);
            }
        }
    }

    void publishReader(const ReaderState& reader) override
    {
        readers.push_back(reader);
    }
    void publishCard(const CardState& card) override
    {
        cards.push_back(card);
    }
    void withdraw(ObjectId object) override
    {
        withdrawn.push_back(object);
    }
    void updateProperties(ObjectId reader, const PropertyDelta& delta) override
    {
        propertyUpdates.emplace_back(reader, delta);
    }
    void post(std::function<void()> fn) override
    {
        if (fn) {
            fn();
        }
    }
    void postAfter(std::chrono::microseconds delay, std::function<void()> fn) override
    {
        postAfterDelays.push_back(delay);
        if (fn) {
            fn();
        }
    }
    void onClientDisconnect(std::function<void(CallerToken)> handler) override
    {
        disconnectHandlers.push_back(std::move(handler));
    }
};

// --- Frozen-surface locks (compile-time) --------------------------------

// The four presence methods take typed deltas by const-ref / by value ObjectId.
static_assert(std::is_same_v<decltype(&AgentTransport::publishReader), void (AgentTransport::*)(const ReaderState&)>,
              "frozen: publishReader(const ReaderState&)");
static_assert(std::is_same_v<decltype(&AgentTransport::publishCard), void (AgentTransport::*)(const CardState&)>,
              "frozen: publishCard(const CardState&)");
static_assert(std::is_same_v<decltype(&AgentTransport::withdraw), void (AgentTransport::*)(ObjectId)>,
              "frozen: withdraw(ObjectId)");
static_assert(std::is_same_v<decltype(&AgentTransport::updateProperties),
                             void (AgentTransport::*)(ObjectId, const PropertyDelta&)>,
              "frozen: updateProperties(ObjectId, const PropertyDelta&)");

// The two loop-marshaling methods.
static_assert(std::is_same_v<decltype(&AgentTransport::post), void (AgentTransport::*)(std::function<void()>)>,
              "frozen: post(std::function<void()>)");
static_assert(std::is_same_v<decltype(&AgentTransport::postAfter),
                             void (AgentTransport::*)(std::chrono::microseconds, std::function<void()>)>,
              "frozen: postAfter(std::chrono::microseconds, std::function<void()>)");

// The client-liveness registration.
static_assert(std::is_same_v<decltype(&AgentTransport::onClientDisconnect),
                             void (AgentTransport::*)(std::function<void(CallerToken)>)>,
              "frozen: onClientDisconnect(std::function<void(CallerToken)>)");

} // namespace

TEST(AgentTransportConformance, PresenceDeltasRecordedVerbatim)
{
    FakeAgentTransport fake;
    AgentTransport& transport = fake;

    transport.publishReader(ReaderState{ObjectId{1}, "R0", false, {}});
    ASSERT_EQ(fake.readers.size(), 1U);
    EXPECT_EQ(fake.readers[0].id, ObjectId{1});
    EXPECT_EQ(fake.readers[0].name, std::string{"R0"});
    EXPECT_FALSE(fake.readers[0].hasCard);
    EXPECT_FALSE(fake.readers[0].card.valid());

    transport.publishCard(CardState{ObjectId{2}, ObjectId{1}, 0U, {}});
    ASSERT_EQ(fake.cards.size(), 1U);
    EXPECT_EQ(fake.cards[0].id, ObjectId{2});
    EXPECT_EQ(fake.cards[0].reader, ObjectId{1});

    transport.updateProperties(ObjectId{1}, PropertyDelta{true, ObjectId{2}});
    ASSERT_EQ(fake.propertyUpdates.size(), 1U);
    EXPECT_EQ(fake.propertyUpdates[0].first, ObjectId{1});
    EXPECT_TRUE(fake.propertyUpdates[0].second.hasCard);
    EXPECT_EQ(fake.propertyUpdates[0].second.card, ObjectId{2});

    transport.withdraw(ObjectId{2});
    ASSERT_EQ(fake.withdrawn.size(), 1U);
    EXPECT_EQ(fake.withdrawn[0], ObjectId{2});
}

TEST(AgentTransportConformance, PostRunsImmediatelyAndPostAfterCarriesDelay)
{
    FakeAgentTransport fake;
    AgentTransport& transport = fake;

    int ran = 0;
    transport.post([&] { ++ran; });
    EXPECT_EQ(ran, 1);

    transport.postAfter(std::chrono::milliseconds{5}, [&] { ++ran; });
    EXPECT_EQ(ran, 2);
    ASSERT_EQ(fake.postAfterDelays.size(), 1U);
    EXPECT_EQ(fake.postAfterDelays[0], std::chrono::microseconds{5000});
}

TEST(AgentTransportConformance, DisconnectHandlersFireAllInRegistrationOrder)
{
    FakeAgentTransport fake;
    AgentTransport& transport = fake;

    // Additive multi-subscriber contract: EVERY registered handler fires, in
    // registration order, on each disconnect (production registers op auto-cancel
    // then lease revoke).
    std::vector<int> order;
    CallerToken fired;
    transport.onClientDisconnect([&](CallerToken c) {
        order.push_back(1);
        fired = std::move(c);
    });
    transport.onClientDisconnect([&order](CallerToken) { order.push_back(2); });
    ASSERT_EQ(fake.disconnectHandlers.size(), 2u);

    fake.fireDisconnect(CallerToken{":1.5"});
    EXPECT_EQ(order, (std::vector<int>{1, 2}));
    EXPECT_EQ(fired, CallerToken{":1.5"});
    EXPECT_EQ(fired.str(), std::string{":1.5"});
}

// The Linux impl side: BusExporter::post/postAfter must marshal onto the
// EventLoopPoster attached via attachLoopPoster (draining the sd-event loop runs
// the callbacks). With no poster attached the calls are silent no-ops.
TEST(AgentTransportBusExporter, PostAndPostAfterMarshalThroughAttachedPoster)
{
    auto bus = sdbus::createSessionBusConnection();
    ASSERT_NE(bus, nullptr) << "run under dbus-run-session";

    ObjectRegistry registry;
    BusExporter exporter(*bus, registry);

    // No poster attached -> silent no-ops (bus-less / pre-loop path).
    EXPECT_FALSE(exporter.hasLoopPoster());
    int ran = 0;
    exporter.post([&] { ++ran; });
    exporter.postAfter(std::chrono::milliseconds{5}, [&] { ++ran; });
    EXPECT_EQ(ran, 0);

    // Attach a real EventLoopPoster on a user sd-event loop; post/postAfter marshal
    // the callback onto it. The transport SHARED-owns the poster (attachLoopPoster
    // takes a shared_ptr), so the sink it hands out keeps the poster alive.
    sd_event* ev = nullptr;
    ASSERT_GE(sd_event_new(&ev), 0);
    {
        auto poster = std::make_shared<EventLoopPoster>(ev);
        exporter.attachLoopPoster(poster);
        EXPECT_TRUE(exporter.hasLoopPoster());

        exporter.post([&] { ++ran; });                                    // immediate
        exporter.postAfter(std::chrono::milliseconds{5}, [&] { ++ran; }); // after 5 ms

        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{2};
        while (ran < 2 && std::chrono::steady_clock::now() < deadline) {
            sd_event_run(ev, 20'000); // 20 ms tick
        }
        EXPECT_EQ(ran, 2) << "post + postAfter must both marshal onto the attached poster";
    }
    sd_event_unref(ev);
}

// The Linux impl side of the presence surface: BusExporter IS-A AgentTransport, so
// publishReader/publishCard/updateProperties/withdraw driven THROUGH the interface
// reference must materialise real, introspectable sdbus objects at the
// backend-derived wire paths (the core hands opaque ObjectIds; the backend owns
// the ObjectId<->path mapping). No loop poster is wired, so publishCard exports the
// Card1 synchronously from the typed CardState -- enough to observe the object tree.
TEST(AgentTransportBusExporter, PublishesPresenceTreeThroughInterface)
{
    constexpr const char* kService = "org.librescrs.Agent.Test.Transport";
    constexpr const char* kReaderPath = "/org/librescrs/Agent/reader/1";
    constexpr const char* kCardPath = "/org/librescrs/Agent/card/2";
    constexpr const char* kReader1Iface = "org.librescrs.Agent.Reader1";
    constexpr const char* kCard1Iface = "org.librescrs.Agent.Card1";
    using ManagedObjects = std::map<sdbus::ObjectPath, std::map<std::string, std::map<std::string, sdbus::Variant>>>;

    // shared_ptr: AgentFrontend co-owns the connection (each typed op keepAlives a
    // share). BusExporter still borrows the bare reference via *serverConn.
    std::shared_ptr<sdbus::IConnection> serverConn = sdbus::createSessionBusConnection();
    ASSERT_NE(serverConn, nullptr) << "run under dbus-run-session";
    serverConn->requestName(sdbus::ServiceName{kService});

    ObjectRegistry registry;
    NopResolver resolver;
    OperationManager mgr;
    auto prompter = std::make_shared<NopPrompter>();
    auto serializer = std::make_shared<PromptSerializer>();
    auto creds = std::make_shared<CredentialCache>();
    CardReadCache readCache;
    ConfigStore cfg(std::filesystem::temp_directory_path() / "librescrs-test-transport-tree" / "agent.conf",
                    std::filesystem::temp_directory_path() / "librescrs-test-transport-tree" / "cache");
    SigningEngineProvider signingEngine(cfg);
    AllowAllAuthorizer authz;
    RateLimiter rateLimiter;
    // No loop poster -> the frontend exports the Card1 synchronously.
    BusExporter exporter(*serverConn, registry);
    // The frontend owns the exported objects + the root ManagerObject (which hosts
    // the ObjectManager adaptor on the root path so GetManagedObjects reports the
    // reader/card children the frontend materialises). This suite drives only the
    // presence tree, so the Pkcs11_1 broker is null.
    auto cryptoCtx = std::make_shared<CryptoWorkerContext>(
        CryptoWorkerContext{.prompter = prompter, .serializer = serializer, .credentials = creds});
    AgentFrontend frontend(exporter, serverConn, mgr, cryptoCtx, readCache, signingEngine, authz, rateLimiter, cfg,
                           nullptr, "test");

    // Drive the presence surface through the interface reference (proves the
    // virtual dispatch onto BusExporter's overrides).
    AgentTransport& transport = exporter;
    transport.publishReader(ReaderState{ObjectId{1}, "R0", false, {}});
    transport.publishCard(CardState{ObjectId{2}, ObjectId{1}, 0x3U, {}});
    transport.updateProperties(ObjectId{1}, PropertyDelta{true, ObjectId{2}});

    serverConn->enterEventLoopAsync();
    auto clientConn = sdbus::createSessionBusConnection();
    clientConn->enterEventLoopAsync();
    auto root =
        sdbus::createProxy(*clientConn, sdbus::ServiceName{kService}, sdbus::ObjectPath{"/org/librescrs/Agent"});

    // (a) Reader1 + Card1 are reported at the backend-derived paths.
    {
        ManagedObjects managed;
        root->callMethod("GetManagedObjects")
            .onInterface(sdbus::InterfaceName{"org.freedesktop.DBus.ObjectManager"})
            .storeResultsTo(managed);
        EXPECT_TRUE(managed.contains(sdbus::ObjectPath{kReaderPath})) << "reader/1 not published";
        ASSERT_TRUE(managed.contains(sdbus::ObjectPath{kCardPath})) << "card/2 not published";
        ASSERT_TRUE(managed[sdbus::ObjectPath{kCardPath}].contains(kCard1Iface));
        EXPECT_EQ(managed[sdbus::ObjectPath{kCardPath}][kCard1Iface]["Capabilities"].get<std::uint32_t>(), 0x3U);
    }

    // (b) Reader1.HasCard flipped to true and Card points at card/2 (real object,
    // Properties.Get works -> not a phantom path).
    {
        auto readerProxy =
            sdbus::createProxy(*clientConn, sdbus::ServiceName{kService}, sdbus::ObjectPath{kReaderPath});
        sdbus::Variant hasCard;
        readerProxy->callMethod("Get")
            .onInterface(sdbus::InterfaceName{"org.freedesktop.DBus.Properties"})
            .withArguments(std::string{kReader1Iface}, std::string{"HasCard"})
            .storeResultsTo(hasCard);
        EXPECT_TRUE(hasCard.get<bool>()) << "updateProperties did not flip Reader1.HasCard";
        sdbus::Variant cardPath;
        readerProxy->callMethod("Get")
            .onInterface(sdbus::InterfaceName{"org.freedesktop.DBus.Properties"})
            .withArguments(std::string{kReader1Iface}, std::string{"Card"})
            .storeResultsTo(cardPath);
        EXPECT_EQ(cardPath.get<sdbus::ObjectPath>(), sdbus::ObjectPath{kCardPath});
    }

    // (c) withdraw(card) removes the Card1 object (production tears down from a
    // monitor thread while the loop runs; sdbus-c++ serialises bus access).
    transport.withdraw(ObjectId{2});
    {
        ManagedObjects managed;
        root->callMethod("GetManagedObjects")
            .onInterface(sdbus::InterfaceName{"org.freedesktop.DBus.ObjectManager"})
            .storeResultsTo(managed);
        EXPECT_FALSE(managed.contains(sdbus::ObjectPath{kCardPath})) << "card/2 still present after withdraw";
        EXPECT_TRUE(managed.contains(sdbus::ObjectPath{kReaderPath})) << "reader/1 must survive card withdraw";
    }

    clientConn->leaveEventLoop();
    serverConn->leaveEventLoop();
}

// The Linux impl side of client-liveness: BusExporter owns the
// org.freedesktop.DBus NameOwnerChanged proxy (created in its ctor). Handlers
// registered THROUGH the AgentTransport interface must fire, in registration
// order, with the disconnecting client's CallerToken when a unique-name client
// drops off the bus. Proves the watch folded out of OperationManager lands here.
// Needs a private session bus (dbus-run-session).
TEST(AgentTransportBusExporter, ClientDisconnectFiresHandlersInRegistrationOrder)
{
    auto agentBus = sdbus::createSessionBusConnection();
    ASSERT_NE(agentBus, nullptr) << "run under dbus-run-session";
    agentBus->requestName(sdbus::ServiceName{"org.librescrs.Agent.Test.Disconnect"});

    ObjectRegistry registry;
    BusExporter exporter(*agentBus, registry);

    // Register two handlers THROUGH the interface; the backend must fire them in
    // registration order for each unique-name drop (op auto-cancel before lease
    // revoke in production).
    std::mutex mtx;
    std::vector<std::pair<int, std::string>> fired;
    AgentTransport& transport = exporter;
    transport.onClientDisconnect([&](CallerToken c) {
        const std::lock_guard g(mtx);
        fired.emplace_back(1, c.str());
    });
    transport.onClientDisconnect([&](CallerToken c) {
        const std::lock_guard g(mtx);
        fired.emplace_back(2, c.str());
    });

    agentBus->enterEventLoopAsync();

    // A separate client with its own unique name; capture it, then drop it so the
    // bus broadcasts NameOwnerChanged(clientName, clientName, "").
    std::string clientName;
    {
        auto client = sdbus::createSessionBusConnection();
        ASSERT_NE(client, nullptr);
        clientName = client->getUniqueName();
        ASSERT_FALSE(clientName.empty());
        // client leaves scope here -> connection closed -> unique-name drop.
    }

    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{2};
    for (;;) {
        {
            const std::lock_guard g(mtx);
            if (fired.size() >= 2) {
                break;
            }
        }
        if (std::chrono::steady_clock::now() > deadline) {
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds{20});
    }

    const std::lock_guard g(mtx);
    ASSERT_EQ(fired.size(), 2U) << "both disconnect handlers must fire on a unique-name drop";
    EXPECT_EQ(fired[0].first, 1) << "the handler registered first must fire first";
    EXPECT_EQ(fired[1].first, 2);
    EXPECT_EQ(fired[0].second, clientName);
    EXPECT_EQ(fired[1].second, clientName);

    agentBus->leaveEventLoop();
}
