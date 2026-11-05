// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// The Linux BusExporter, driven directly. Its post/postAfter marshal onto the
// EventLoopPoster attached via attachLoopPoster; the presence calls it receives
// materialise real, introspectable sdbus objects through the frontend; a reader
// carries the roster's label; and every registered client-disconnect handler
// fires in registration order. These cases need a private session bus
// (dbus-run-session).

#include "TestAgentCore.h"
#include "AllowAllAuthorizer.h" // test support: grants every action
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

} // namespace

// BusExporter::post/postAfter must marshal onto the
// EventLoopPoster attached via attachLoopPoster (draining the sd-event loop runs
// the callbacks). With no poster attached the calls are silent no-ops.
TEST(BusExporter, PostAndPostAfterMarshalThroughAttachedPoster)
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

// The presence surface: publishReader/publishCard/updateProperties/withdraw
// driven on the BusExporter must materialise real, introspectable sdbus objects at the
// backend-derived wire paths (the core hands opaque ObjectIds; the backend owns
// the ObjectId<->path mapping). No loop poster is wired, so publishCard exports the
// Card1 synchronously from the typed CardState -- enough to observe the object tree.
TEST(BusExporter, PublishesPresenceTree)
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
    auto prompter = std::make_shared<NopPrompter>();
    AllowAllAuthorizer authz;
    LibreSCRS::Agent::AgentCore core =
        LibreSCRS::Agent::Testing::makeTestCore("librescrs-test-transport-tree", resolver, authz, prompter);
    // No loop poster -> the frontend exports the Card1 synchronously.
    BusExporter exporter(*serverConn, registry);
    // The frontend owns the exported objects + the root ManagerObject (which hosts
    // the ObjectManager adaptor on the root path so GetManagedObjects reports the
    // reader/card children the frontend materialises).
    AgentFrontend frontend(exporter, serverConn, core, "test");

    // Drive the presence surface on the exporter directly.
    exporter.publishReader(ReaderState{ObjectId{1}, "R0", false, {}});
    exporter.publishCard(CardState{ObjectId{2}, ObjectId{1}, 0x3U, {}});
    exporter.updateProperties(ObjectId{1}, PropertyDelta{true, ObjectId{2}});

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
    exporter.withdraw(ObjectId{2});
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

// Reader1.Model / Reader1.Interface: the reader is published with the label the
// agent library's registry decides over the whole roster, and a twin arriving
// beside it relabels the reader already on the bus -- one PropertiesChanged
// carrying both, and Get answering the new label. Driven through the registry
// (the production source), so nothing here classifies a reader name.
TEST(BusExporter, AReaderCarriesTheRostersLabelAndFollowsItsChanges)
{
    constexpr const char* kService = "org.librescrs.Agent.Test.ReaderLabel";
    constexpr const char* kReader1Iface = "org.librescrs.Agent.Reader1";
    constexpr const char* kContactSlot =
        "HID Global OMNIKEY 5422 Smartcard Reader [OMNIKEY 5422 Smartcard Reader] (IM0O2C00NF10456904) 01 00";
    constexpr const char* kContactlessSlot =
        "HID Global OMNIKEY 5422 Smartcard Reader [OMNIKEY 5422CL Smartcard Reader] (IM0O2C00NF10456904) 00 00";

    std::shared_ptr<sdbus::IConnection> serverConn = sdbus::createSessionBusConnection();
    ASSERT_NE(serverConn, nullptr) << "run under dbus-run-session";
    serverConn->requestName(sdbus::ServiceName{kService});

    ObjectRegistry registry;
    NopResolver resolver;
    auto prompter = std::make_shared<NopPrompter>();
    AllowAllAuthorizer authz;
    LibreSCRS::Agent::AgentCore core =
        LibreSCRS::Agent::Testing::makeTestCore("librescrs-test-transport-label", resolver, authz, prompter);
    BusExporter exporter(*serverConn, registry);
    AgentFrontend frontend(exporter, serverConn, core, "test");

    registry.addReader(ReaderState{.id = ObjectId{1}, .name = kContactSlot});

    serverConn->enterEventLoopAsync();
    auto clientConn = sdbus::createSessionBusConnection();
    clientConn->enterEventLoopAsync();
    auto first = sdbus::createProxy(*clientConn, sdbus::ServiceName{kService},
                                    sdbus::ObjectPath{"/org/librescrs/Agent/reader/1"});
    const auto property = [&](sdbus::IProxy& proxy, const char* name) {
        sdbus::Variant value;
        proxy.callMethod("Get")
            .onInterface(sdbus::InterfaceName{"org.freedesktop.DBus.Properties"})
            .withArguments(std::string{kReader1Iface}, std::string{name})
            .storeResultsTo(value);
        return value.get<std::string>();
    };

    // Alone on the roster, a contact slot cannot be told from a single-interface
    // reader: the agent says "unknown", never a guessed "contact".
    EXPECT_EQ(property(*first, "Model"), "OMNIKEY 5422");
    EXPECT_EQ(property(*first, "Interface"), "unknown");

    std::mutex mtx;
    std::vector<std::map<std::string, sdbus::Variant>> changes;
    first->uponSignal(sdbus::SignalName{"PropertiesChanged"})
        .onInterface(sdbus::InterfaceName{"org.freedesktop.DBus.Properties"})
        .call([&](const std::string& iface, const std::map<std::string, sdbus::Variant>& changed,
                  const std::vector<std::string>& /*invalidated*/) {
            if (iface == kReader1Iface) {
                const std::lock_guard guard(mtx);
                changes.push_back(changed);
            }
        });

    registry.addReader(ReaderState{.id = ObjectId{2}, .name = kContactlessSlot});

    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{5};
    for (;;) {
        {
            const std::lock_guard guard(mtx);
            if (!changes.empty() || std::chrono::steady_clock::now() >= deadline) {
                break;
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds{10});
    }
    {
        const std::lock_guard guard(mtx);
        ASSERT_EQ(changes.size(), 1U) << "the twin's arrival must relabel the reader beside it, once";
        ASSERT_TRUE(changes[0].contains("Model"));
        ASSERT_TRUE(changes[0].contains("Interface"));
        EXPECT_EQ(changes[0].at("Model").get<std::string>(), "OMNIKEY 5422");
        EXPECT_EQ(changes[0].at("Interface").get<std::string>(), "contact");
    }
    EXPECT_EQ(property(*first, "Interface"), "contact");
    auto second = sdbus::createProxy(*clientConn, sdbus::ServiceName{kService},
                                     sdbus::ObjectPath{"/org/librescrs/Agent/reader/2"});
    EXPECT_EQ(property(*second, "Model"), "OMNIKEY 5422");
    EXPECT_EQ(property(*second, "Interface"), "contactless");

    first.reset();
    second.reset();
    clientConn->leaveEventLoop();
    serverConn->leaveEventLoop();
}

// Client-liveness: BusExporter owns the org.freedesktop.DBus NameOwnerChanged
// proxy (created in its ctor). Registered handlers must fire, in registration
// order, with the disconnecting client's CallerToken when a unique-name client
// drops off the bus. Proves the watch folded out of OperationManager lands here.
// Needs a private session bus (dbus-run-session).
TEST(BusExporter, ClientDisconnectFiresHandlersInRegistrationOrder)
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
    exporter.onClientDisconnect([&](CallerToken c) {
        const std::lock_guard g(mtx);
        fired.emplace_back(1, c.str());
    });
    exporter.onClientDisconnect([&](CallerToken c) {
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
