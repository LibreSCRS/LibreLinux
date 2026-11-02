// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// The agent's answer to sleep, screen lock and session switch, driven by a fake
// systemd-logind on a private bus the agent reaches as its system bus
// (DBUS_SYSTEM_BUS_ADDRESS). The first two cases pin which logind event means
// which reason; the last two run the composition the agent itself runs
// (watchSessionLifecycle over a real AgentCore and AgentFrontend) and read the
// result where it matters: what the core still holds, and the Manager1.Quiesced
// signal a client receives.

#include "AgentCoreSeams.h"
#include "AgentFrontend.h"
#include "AgentObjectPath.h"
#include "AllowAllAuthorizer.h" // test support: grants every action
#include "BusExporter.h"
#include "SessionLifecycleWatch.h"
#include <LibreSCRS/Agent/AgentCore.h>
#include <LibreSCRS/Agent/backend/PrompterClientBase.h>
#include <LibreSCRS/Agent/cache/CredentialCache.h>
#include <LibreSCRS/Agent/pkcs11/LeaseManager.h>
#include <LibreSCRS/Agent/presence/CapabilityResolver.h>
#include <LibreSCRS/Agent/presence/PresenceModel.h>

#include <sdbus-c++/sdbus-c++.h>
#include <gtest/gtest.h>

#include <unistd.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>

using namespace LibreSCRS::Agent;
using namespace std::chrono_literals;
namespace fs = std::filesystem;

namespace {

constexpr const char* kLogindService = "org.freedesktop.login1";
constexpr const char* kLogindPath = "/org/freedesktop/login1";
constexpr const char* kManagerIface = "org.freedesktop.login1.Manager";
constexpr const char* kSessionIface = "org.freedesktop.login1.Session";
constexpr const char* kPropertiesIface = "org.freedesktop.DBus.Properties";
constexpr const char* kHolderSession = "/org/freedesktop/login1/session/_32";
constexpr const char* kOtherSession = "/org/freedesktop/login1/session/_7";

using Changed = std::map<std::string, sdbus::Variant>;

Changed one(const char* property, bool value)
{
    return Changed{{property, sdbus::Variant{value}}};
}

// A logind with one manager and two sessions: the holder's, which "auto"
// resolves to, and somebody else's.
struct FakeLogind
{
    explicit FakeLogind(sdbus::IConnection& conn)
    {
        conn.requestName(sdbus::ServiceName{kLogindService});
        manager = sdbus::createObject(conn, sdbus::ObjectPath{kLogindPath});
        manager
            ->addVTable(sdbus::registerMethod("GetSession")
                            .implementedAs([this](const std::string& id) -> sdbus::ObjectPath {
                                {
                                    const std::lock_guard lock{mutex};
                                    askedFor = id;
                                }
                                if (noSession) {
                                    throw sdbus::Error{sdbus::Error::Name{"org.freedesktop.login1.NoSessionForPID"},
                                                       "fake logind: no session"};
                                }
                                return sdbus::ObjectPath{kHolderSession};
                            })
                            .withInputParamNames("session_id")
                            .withOutputParamNames("object_path"),
                        sdbus::registerSignal("PrepareForSleep").withParameters<bool>("start"))
            .forInterface(sdbus::InterfaceName{kManagerIface});
        holder = makeSession(conn, kHolderSession);
        other = makeSession(conn, kOtherSession);
    }

    static std::unique_ptr<sdbus::IObject> makeSession(sdbus::IConnection& conn, const char* path)
    {
        auto session = sdbus::createObject(conn, sdbus::ObjectPath{path});
        session->addVTable(sdbus::registerSignal("Lock"), sdbus::registerSignal("Unlock"))
            .forInterface(sdbus::InterfaceName{kSessionIface});
        return session;
    }

    void prepareForSleep(bool start)
    {
        manager->emitSignal("PrepareForSleep").onInterface(kManagerIface).withArguments(start);
    }
    static void signal(sdbus::IObject& session, const char* name)
    {
        session.emitSignal(name).onInterface(kSessionIface).withArguments();
    }
    static void propertiesChanged(sdbus::IObject& session, const char* iface, const Changed& changed)
    {
        session.emitSignal("PropertiesChanged")
            .onInterface(kPropertiesIface)
            .withArguments(std::string{iface}, changed, std::vector<std::string>{});
    }

    std::string asked()
    {
        const std::lock_guard lock{mutex};
        return askedFor;
    }

    std::atomic<bool> noSession{false};
    std::mutex mutex;
    std::string askedFor;
    std::unique_ptr<sdbus::IObject> manager;
    std::unique_ptr<sdbus::IObject> holder;
    std::unique_ptr<sdbus::IObject> other;
};

// The private session bus doubles as the system bus: logind runs on its own
// connection (it must answer GetSession while the watch blocks in its
// constructor), the watch on a connection opened the way the agent opens it.
struct LogindBus
{
    LogindBus()
    {
        setenv("DBUS_SYSTEM_BUS_ADDRESS", getenv("DBUS_SESSION_BUS_ADDRESS"), 1);
        logindConn = sdbus::createSessionBusConnection();
        logind = std::make_unique<FakeLogind>(*logindConn);
        logindConn->enterEventLoopAsync();
        systemBus = sdbus::createSystemBusConnection();
    }
    ~LogindBus()
    {
        systemBus->leaveEventLoop();
        logindConn->leaveEventLoop();
    }
    LogindBus(const LogindBus&) = delete;
    LogindBus& operator=(const LogindBus&) = delete;

    std::unique_ptr<sdbus::IConnection> logindConn;
    std::unique_ptr<FakeLogind> logind;
    std::unique_ptr<sdbus::IConnection> systemBus;
};

// Collects reasons as they arrive, from whichever thread delivers them.
struct Reasons
{
    void add(QuiesceReason reason)
    {
        {
            const std::lock_guard lock{mutex};
            seen.push_back(reason);
        }
        arrived.notify_all();
    }
    std::vector<QuiesceReason> waitFor(std::size_t count, std::chrono::milliseconds budget = 5s)
    {
        std::unique_lock lock{mutex};
        arrived.wait_for(lock, budget, [&] { return seen.size() >= count; });
        return seen;
    }
    std::mutex mutex;
    std::condition_variable arrived;
    std::vector<QuiesceReason> seen;
};

struct Event
{
    const char* what;
    std::function<void(FakeLogind&)> send;
    std::optional<QuiesceReason> expected;
};

} // namespace

TEST(SessionLifecycleWatch, EachLogindEventQuiescesForItsOwnReason)
{
    LogindBus bus;
    Reasons reasons;
    SessionLifecycleWatch watch(*bus.systemBus, [&reasons](QuiesceReason r) { reasons.add(r); });
    bus.systemBus->enterEventLoopAsync();

    ASSERT_EQ(bus.logind->asked(), "auto") << "the holder's session is the one logind resolves \"auto\" to";
    ASSERT_EQ(watch.sessionPath(), kHolderSession);

    using R = QuiesceReason;
    const std::vector<Event> events{
        {"PrepareForSleep(true)", [](FakeLogind& l) { l.prepareForSleep(true); }, R::SystemSleep},
        {"PrepareForSleep(false)", [](FakeLogind& l) { l.prepareForSleep(false); }, std::nullopt},
        {"holder Lock", [](FakeLogind& l) { FakeLogind::signal(*l.holder, "Lock"); }, R::ScreenLocked},
        {"holder Unlock", [](FakeLogind& l) { FakeLogind::signal(*l.holder, "Unlock"); }, std::nullopt},
        {"holder LockedHint true",
         [](FakeLogind& l) { FakeLogind::propertiesChanged(*l.holder, kSessionIface, one("LockedHint", true)); },
         R::ScreenLocked},
        {"holder LockedHint false",
         [](FakeLogind& l) { FakeLogind::propertiesChanged(*l.holder, kSessionIface, one("LockedHint", false)); },
         std::nullopt},
        {"holder Active false",
         [](FakeLogind& l) { FakeLogind::propertiesChanged(*l.holder, kSessionIface, one("Active", false)); },
         R::SessionInactive},
        {"holder Active true",
         [](FakeLogind& l) { FakeLogind::propertiesChanged(*l.holder, kSessionIface, one("Active", true)); },
         std::nullopt},
        {"holder IdleHint true",
         [](FakeLogind& l) { FakeLogind::propertiesChanged(*l.holder, kSessionIface, one("IdleHint", true)); },
         std::nullopt},
        {"holder Active false on another interface",
         [](FakeLogind& l) {
             FakeLogind::propertiesChanged(*l.holder, "org.example.NotASession", one("Active", false));
         },
         std::nullopt},
        {"another session's Lock", [](FakeLogind& l) { FakeLogind::signal(*l.other, "Lock"); }, std::nullopt},
        {"another session's Active false",
         [](FakeLogind& l) { FakeLogind::propertiesChanged(*l.other, kSessionIface, one("Active", false)); },
         std::nullopt},
        {"another session's LockedHint true",
         [](FakeLogind& l) { FakeLogind::propertiesChanged(*l.other, kSessionIface, one("LockedHint", true)); },
         std::nullopt},
        // Last, so everything above has been delivered (one sender, in order)
        // by the time this arrives.
        {"PrepareForSleep(true) again", [](FakeLogind& l) { l.prepareForSleep(true); }, R::SystemSleep},
    };

    std::vector<QuiesceReason> expected;
    for (const auto& event : events) {
        event.send(*bus.logind);
        if (event.expected) {
            expected.push_back(*event.expected);
        }
    }
    static_cast<void>(reasons.waitFor(expected.size()));
    std::this_thread::sleep_for(100ms); // nothing may follow the last expected reason
    const std::lock_guard lock{reasons.mutex};
    std::string trace;
    for (const auto r : reasons.seen) {
        trace += std::to_string(static_cast<unsigned>(r)) + " ";
    }
    EXPECT_EQ(reasons.seen, expected) << "reasons seen, in order: " << trace;
}

TEST(SessionLifecycleWatch, WithoutASessionOnlySleepIsWatched)
{
    LogindBus bus;
    bus.logind->noSession = true;
    Reasons reasons;
    SessionLifecycleWatch watch(*bus.systemBus, [&reasons](QuiesceReason r) { reasons.add(r); });
    bus.systemBus->enterEventLoopAsync();

    EXPECT_TRUE(watch.sessionPath().empty());
    FakeLogind::signal(*bus.logind->holder, "Lock");
    bus.logind->prepareForSleep(true);
    EXPECT_EQ(reasons.waitFor(1), std::vector<QuiesceReason>{QuiesceReason::SystemSleep});
}

namespace {

class NeutralResolver final : public CapabilityResolver
{};

class NopPrompter final : public Operations::PrompterClientBase
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

constexpr const char* kAgentService = "org.librescrs.Agent.Test.Lifecycle";
constexpr const char* kRootPath = "/org/librescrs/Agent";
const CallerToken kCaller{":1.42"};

// The agent's composition around one card: a cached CAN and a PKCS#11 lease on
// it, and a client listening for Manager1.Quiesced.
struct Agent
{
    Agent()
    {
        serverConn->requestName(sdbus::ServiceName{kAgentService});
        core.emplace(resolver, exporter, authz, prompter, dir / "agent.conf", dir / "cache",
                     makeResolveReaderCard(exporter), makeResolveCardKey(exporter));
        frontend = std::make_unique<AgentFrontend>(exporter, serverConn, *core, "t");
        serverConn->enterEventLoopAsync();

        core->presenceModel().onReaderAdded("reader-A");
        core->presenceModel().onCardInserted("reader-A", {0x3B, 0x00});
        card = core->presenceModel().cardIdFor("reader-A");
        cardKey = agentObjectPath("card", card);
        core->credentialCache().putCan(cardKey, CredentialCache::Secret{"123456"});
        grantLease();

        clientConn->enterEventLoopAsync();
        client = sdbus::createProxy(*clientConn, sdbus::ServiceName{kAgentService}, sdbus::ObjectPath{kRootPath});
        client->uponSignal(sdbus::SignalName{"Quiesced"})
            .onInterface(sdbus::InterfaceName{"org.librescrs.Agent.Manager1"})
            .call([this](std::uint32_t reason) { announced.add(static_cast<QuiesceReason>(reason)); });

        watch = watchSessionLifecycle(*bus.systemBus, *core, stateMutex, *frontend);
        bus.systemBus->enterEventLoopAsync();
    }
    ~Agent()
    {
        bus.systemBus->leaveEventLoop();
        watch.reset();
        client.reset();
        clientConn->leaveEventLoop();
        serverConn->leaveEventLoop();
        frontend.reset();
        core.reset();
        fs::remove_all(dir);
    }
    Agent(const Agent&) = delete;
    Agent& operator=(const Agent&) = delete;

    void grantLease()
    {
        core->leaseManager().grant(Pkcs11::LeaseKey{.caller = kCaller, .card = card}, std::chrono::steady_clock::now());
    }
    bool leaseActive()
    {
        return core->leaseManager().isActive(Pkcs11::LeaseKey{.caller = kCaller, .card = card},
                                             std::chrono::steady_clock::now());
    }
    bool canCached()
    {
        return core->credentialCache().getCan(cardKey).has_value();
    }

    const fs::path dir = fs::temp_directory_path() / ("ll-lifecycle-" + std::to_string(::getpid()));
    LogindBus bus;
    std::shared_ptr<sdbus::IConnection> serverConn = sdbus::createSessionBusConnection();
    NeutralResolver resolver;
    AllowAllAuthorizer authz;
    std::shared_ptr<NopPrompter> prompter = std::make_shared<NopPrompter>();
    BusExporter exporter{*serverConn};
    std::optional<AgentCore> core;
    std::unique_ptr<AgentFrontend> frontend;
    std::mutex stateMutex;
    ObjectId card;
    std::string cardKey;
    std::unique_ptr<sdbus::IConnection> clientConn = sdbus::createSessionBusConnection();
    std::unique_ptr<sdbus::IProxy> client;
    Reasons announced;
    std::unique_ptr<SessionLifecycleWatch> watch;
};

} // namespace

TEST(SessionLifecycleWatch, TheAgentForgetsWhatTheReasonCallsForAndTellsItsClientsWhy)
{
    Agent agent;
    ASSERT_NE(agent.card, ObjectId{});
    ASSERT_TRUE(agent.canCached());
    ASSERT_TRUE(agent.leaseActive());

    // A screen lock: the PKCS#11 login goes, the card's secrets stay.
    FakeLogind::signal(*agent.bus.logind->holder, "Lock");
    ASSERT_EQ(agent.announced.waitFor(1), std::vector<QuiesceReason>{QuiesceReason::ScreenLocked});
    EXPECT_FALSE(agent.leaseActive()) << "a screen lock revokes the PKCS#11 login";
    EXPECT_TRUE(agent.canCached()) << "a screen lock keeps the session and its secrets";

    // Sleep: everything goes.
    agent.grantLease();
    agent.bus.logind->prepareForSleep(true);
    ASSERT_EQ(agent.announced.waitFor(2),
              (std::vector<QuiesceReason>{QuiesceReason::ScreenLocked, QuiesceReason::SystemSleep}));
    EXPECT_FALSE(agent.leaseActive()) << "sleep revokes the PKCS#11 login";
    EXPECT_FALSE(agent.canCached()) << "sleep forgets the card's CAN";
}

TEST(SessionLifecycleWatch, TheCoreForgetsOnlyUnderTheRegistryLock)
{
    Agent agent;
    {
        // The monitor holds this lock while it changes the registry the core walks.
        const std::lock_guard held{agent.stateMutex};
        FakeLogind::propertiesChanged(*agent.bus.logind->holder, kSessionIface, one("Active", false));
        std::this_thread::sleep_for(300ms);
        EXPECT_TRUE(agent.canCached()) << "the core forgot while the registry lock was held elsewhere";
        EXPECT_TRUE(agent.leaseActive()) << "the core revoked while the registry lock was held elsewhere";
    }
    ASSERT_EQ(agent.announced.waitFor(1), std::vector<QuiesceReason>{QuiesceReason::SessionInactive});
    EXPECT_FALSE(agent.canCached());
    EXPECT_FALSE(agent.leaseActive());
}
