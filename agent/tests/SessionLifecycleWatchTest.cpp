// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// The agent's answer to sleep, screen lock and session switch, driven by a fake
// systemd-logind on a private bus the agent reaches as its system bus
// (DBUS_SYSTEM_BUS_ADDRESS). The first two cases pin which logind event means
// which reason; the last two run the composition the agent itself runs
// (watchSessionLifecycle over a real AgentCore) and read the result where it
// matters: what the core still holds.

#include "AgentCoreSeams.h"
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

// What the watch reported: "Q<reason>" for a quiesce, "R<reason>" for the end of
// one, in arrival order, from whichever thread delivers them.
struct Trace
{
    void add(const char* kind, QuiesceReason reason)
    {
        {
            const std::lock_guard lock{mutex};
            seen.push_back(kind + std::to_string(static_cast<unsigned>(reason)));
        }
        arrived.notify_all();
    }
    std::vector<std::string> waitFor(std::size_t count, std::chrono::milliseconds budget = 5s)
    {
        std::unique_lock lock{mutex};
        arrived.wait_for(lock, budget, [&] { return seen.size() >= count; });
        return seen;
    }
    std::mutex mutex;
    std::condition_variable arrived;
    std::vector<std::string> seen;
};

// The two callbacks a watch takes, recording into @p trace.
struct Recorder
{
    explicit Recorder(Trace& trace)
        : quiesce([&trace](QuiesceReason r) { trace.add("Q", r); }),
          resume([&trace](QuiesceReason r) { trace.add("R", r); })
    {}
    SessionLifecycleWatch::OnQuiesce quiesce;
    SessionLifecycleWatch::OnResume resume;
};

struct Event
{
    const char* what;
    std::function<void(FakeLogind&)> send;
    std::optional<std::string> expected; ///< "Q<reason>" / "R<reason>", or nothing
};

// The watch answers on the bus thread, so a test waits for what it
// changed: true once @p done holds, false if it never does.
bool waitUntil(const std::function<bool()>& done)
{
    const auto deadline = std::chrono::steady_clock::now() + 5s;
    while (!done()) {
        if (std::chrono::steady_clock::now() >= deadline) {
            return false;
        }
        std::this_thread::sleep_for(10ms);
    }
    return true;
}

} // namespace

TEST(SessionLifecycleWatch, EachLogindEventBeginsOrEndsItsOwnReason)
{
    LogindBus bus;
    Trace trace;
    Recorder recorder{trace};
    SessionLifecycleWatch watch(*bus.systemBus, recorder.quiesce, recorder.resume);
    bus.systemBus->enterEventLoopAsync();

    ASSERT_EQ(bus.logind->asked(), "auto") << "the holder's session is the one logind resolves \"auto\" to";
    ASSERT_EQ(watch.sessionPath(), kHolderSession);

    const std::vector<Event> events{
        {"PrepareForSleep(true)", [](FakeLogind& l) { l.prepareForSleep(true); }, "Q0"},
        {"PrepareForSleep(false)", [](FakeLogind& l) { l.prepareForSleep(false); }, "R0"},
        {"holder Lock", [](FakeLogind& l) { FakeLogind::signal(*l.holder, "Lock"); }, "Q1"},
        // Unlock is a request to the locker, not a report: only LockedHint ends the lock.
        {"holder Unlock", [](FakeLogind& l) { FakeLogind::signal(*l.holder, "Unlock"); }, std::nullopt},
        {"holder LockedHint true",
         [](FakeLogind& l) { FakeLogind::propertiesChanged(*l.holder, kSessionIface, one("LockedHint", true)); }, "Q1"},
        {"holder LockedHint false",
         [](FakeLogind& l) { FakeLogind::propertiesChanged(*l.holder, kSessionIface, one("LockedHint", false)); },
         "R1"},
        {"holder Active false",
         [](FakeLogind& l) { FakeLogind::propertiesChanged(*l.holder, kSessionIface, one("Active", false)); }, "Q2"},
        {"holder Active true",
         [](FakeLogind& l) { FakeLogind::propertiesChanged(*l.holder, kSessionIface, one("Active", true)); }, "R2"},
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
        {"PrepareForSleep(true) again", [](FakeLogind& l) { l.prepareForSleep(true); }, "Q0"},
    };

    std::vector<std::string> expected;
    for (const auto& event : events) {
        event.send(*bus.logind);
        if (event.expected) {
            expected.push_back(*event.expected);
        }
    }
    static_cast<void>(trace.waitFor(expected.size()));
    std::this_thread::sleep_for(100ms); // nothing may follow the last expected report
    const std::lock_guard lock{trace.mutex};
    EXPECT_EQ(trace.seen, expected);
}

// The end of a lock is the session's LockedHint going false, never the Unlock
// signal alone.
TEST(SessionLifecycleWatch, UnlockSignalAloneEndsNothing)
{
    LogindBus bus;
    Trace trace;
    Recorder recorder{trace};
    SessionLifecycleWatch watch(*bus.systemBus, recorder.quiesce, recorder.resume);
    bus.systemBus->enterEventLoopAsync();

    FakeLogind::signal(*bus.logind->holder, "Unlock");
    // Last, so the Unlock above has been delivered (one sender, in order).
    bus.logind->prepareForSleep(true);
    EXPECT_EQ(trace.waitFor(1), std::vector<std::string>{"Q0"});
    std::this_thread::sleep_for(100ms);
    EXPECT_EQ(trace.waitFor(2, 100ms), std::vector<std::string>{"Q0"}) << "Unlock must not report an end";
}

TEST(SessionLifecycleWatch, WithoutASessionOnlySleepIsWatched)
{
    LogindBus bus;
    bus.logind->noSession = true;
    Trace trace;
    Recorder recorder{trace};
    SessionLifecycleWatch watch(*bus.systemBus, recorder.quiesce, recorder.resume);
    bus.systemBus->enterEventLoopAsync();

    EXPECT_TRUE(watch.sessionPath().empty());
    FakeLogind::signal(*bus.logind->holder, "Lock");
    bus.logind->prepareForSleep(true);
    EXPECT_EQ(trace.waitFor(1), std::vector<std::string>{"Q0"});
}

TEST(SessionLifecycleWatch, WakeDeliversResume)
{
    LogindBus bus;
    Trace trace;
    Recorder recorder{trace};
    SessionLifecycleWatch watch(*bus.systemBus, recorder.quiesce, recorder.resume);
    bus.systemBus->enterEventLoopAsync();

    bus.logind->prepareForSleep(false);
    ASSERT_EQ(trace.waitFor(1), std::vector<std::string>{"R0"}) << "the wake ends SystemSleep";
    std::this_thread::sleep_for(100ms); // a second delivery would show up here
    EXPECT_EQ(trace.waitFor(2, 100ms), std::vector<std::string>{"R0"}) << "waking must not quiesce";
}

TEST(SessionLifecycleWatch, SleepDoesNotDeliverResume)
{
    LogindBus bus;
    Trace trace;
    Recorder recorder{trace};
    SessionLifecycleWatch watch(*bus.systemBus, recorder.quiesce, recorder.resume);
    bus.systemBus->enterEventLoopAsync();

    bus.logind->prepareForSleep(true);
    EXPECT_EQ(trace.waitFor(1), std::vector<std::string>{"Q0"});
    std::this_thread::sleep_for(100ms);
    EXPECT_EQ(trace.waitFor(2, 100ms), std::vector<std::string>{"Q0"}) << "going to sleep must not resume";
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
const CallerToken kCaller{":1.42"};

// The agent's composition around one card: a cached CAN and a PKCS#11 lease on
// it.
struct Agent
{
    Agent()
    {
        serverConn->requestName(sdbus::ServiceName{kAgentService});
        core.emplace(resolver, authz, prompter, dir / "agent.conf", dir / "cache", makeResolveReaderCard(exporter),
                     makeResolveCardKey(exporter));
        serverConn->enterEventLoopAsync();

        core->presenceModel().onReaderAdded("reader-A");
        core->presenceModel().onCardInserted("reader-A", {0x3B, 0x00});
        card = core->presenceModel().cardIdFor("reader-A");
        cardKey = agentObjectPath("card", card);
        core->credentialCache().putCan(cardKey, CredentialCache::Secret{"123456"});
        grantLease();

        watch = watchSessionLifecycle(*bus.systemBus, *core, stateMutex,
                                      LifecycleNotifier{
                                          .quiesced = [this](QuiesceReason r) { announced("Q", r); },
                                          .resumed = [this](QuiesceReason r) { announced("R", r); },
                                      });
        bus.systemBus->enterEventLoopAsync();
    }
    ~Agent()
    {
        bus.systemBus->leaveEventLoop();
        watch.reset();
        serverConn->leaveEventLoop();
        core.reset();
        fs::remove_all(dir);
    }
    Agent(const Agent&) = delete;
    Agent& operator=(const Agent&) = delete;

    // What the notifier was told. A notification that arrives while the state
    // mutex is held would deadlock a thread that needs it, so each one probes
    // the mutex from another thread: the agent announces outside the lock.
    void announced(const char* kind, QuiesceReason reason)
    {
        std::thread probe([this] {
            if (stateMutex.try_lock()) {
                stateMutex.unlock();
            } else {
                ++announcedUnderLock;
            }
        });
        probe.join();
        notices.add(kind, reason);
    }
    void grantLease()
    {
        core->leaseManager().grant(Pkcs11::LeaseKey{.caller = kCaller, .card = card}, std::chrono::steady_clock::now());
    }
    bool leaseActive()
    {
        return core->leaseManager().isActive(Pkcs11::LeaseKey{.caller = kCaller, .card = card},
                                             std::chrono::steady_clock::now());
    }
    bool holdsSuspended()
    {
        return core->operationManager().holdsSuspended();
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
    std::mutex stateMutex;
    ObjectId card;
    std::string cardKey;
    Trace notices;
    std::atomic<int> announcedUnderLock{0};
    std::unique_ptr<SessionLifecycleWatch> watch;
};

} // namespace

TEST(SessionLifecycleWatch, TheAgentForgetsWhatTheReasonCallsFor)
{
    Agent agent;
    ASSERT_NE(agent.card, ObjectId{});
    ASSERT_TRUE(agent.canCached());
    ASSERT_TRUE(agent.leaseActive());

    // A screen lock: the PKCS#11 login goes, the card's secrets stay.
    FakeLogind::signal(*agent.bus.logind->holder, "Lock");
    ASSERT_TRUE(waitUntil([&agent] { return !agent.leaseActive(); }));
    EXPECT_FALSE(agent.leaseActive()) << "a screen lock revokes the PKCS#11 login";
    EXPECT_TRUE(agent.canCached()) << "a screen lock keeps the session and its secrets";

    // Sleep: everything goes.
    agent.grantLease();
    agent.bus.logind->prepareForSleep(true);
    ASSERT_TRUE(waitUntil([&agent] { return !agent.canCached() && !agent.leaseActive(); }));
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
    ASSERT_TRUE(waitUntil([&agent] { return !agent.canCached() && !agent.leaseActive(); }));
    EXPECT_FALSE(agent.canCached());
    EXPECT_FALSE(agent.leaseActive());
}

// The production binding, not a stand-in lambda: logind's wake reaches the
// core, so the hold suspension a sleep left is lifted again.
TEST(SessionLifecycleWatch, WakeLiftsTheHoldSuspension)
{
    Agent agent;
    agent.bus.logind->prepareForSleep(true);
    ASSERT_TRUE(waitUntil([&agent] { return agent.holdsSuspended(); })) << "sleep suspends the card holds";
    agent.bus.logind->prepareForSleep(false);
    ASSERT_TRUE(waitUntil([&agent] { return !agent.holdsSuspended(); })) << "wake lifts the suspension";
}

TEST(SessionLifecycleWatch, TheCoreResumesOnlyUnderTheRegistryLock)
{
    Agent agent;
    agent.bus.logind->prepareForSleep(true);
    ASSERT_TRUE(waitUntil([&agent] { return agent.holdsSuspended(); }));
    {
        // resume() walks the registry too, so it waits for the monitor's lock.
        const std::lock_guard held{agent.stateMutex};
        agent.bus.logind->prepareForSleep(false);
        std::this_thread::sleep_for(300ms);
        EXPECT_TRUE(agent.holdsSuspended()) << "the core resumed while the registry lock was held elsewhere";
    }
    ASSERT_TRUE(waitUntil([&agent] { return !agent.holdsSuspended(); }));
}

// What the agent announces to its clients, through the production composition:
// each quiesce, and the end of a reason only when that reason was quiesced and
// has not ended since.
TEST(SessionLifecycleWatch, TheAgentAnnouncesAQuiesceAndItsEnd)
{
    Agent agent;
    FakeLogind::propertiesChanged(*agent.bus.logind->holder, kSessionIface, one("LockedHint", true));
    ASSERT_EQ(agent.notices.waitFor(1), std::vector<std::string>{"Q1"});
    FakeLogind::propertiesChanged(*agent.bus.logind->holder, kSessionIface, one("LockedHint", false));
    EXPECT_EQ(agent.notices.waitFor(2), (std::vector<std::string>{"Q1", "R1"}));
    EXPECT_EQ(agent.announcedUnderLock.load(), 0) << "an announcement was made while the state mutex was held";
}

TEST(SessionLifecycleWatch, TheAgentAnnouncesNoEndForAQuiesceItNeverAnnounced)
{
    Agent agent;
    agent.bus.logind->prepareForSleep(false);
    FakeLogind::propertiesChanged(*agent.bus.logind->holder, kSessionIface, one("LockedHint", false));
    FakeLogind::propertiesChanged(*agent.bus.logind->holder, kSessionIface, one("Active", true));
    // Last, so the three reports above have been delivered (one sender, in order).
    agent.bus.logind->prepareForSleep(true);
    EXPECT_EQ(agent.notices.waitFor(1), std::vector<std::string>{"Q0"});
    std::this_thread::sleep_for(100ms);
    EXPECT_EQ(agent.notices.waitFor(2, 100ms), std::vector<std::string>{"Q0"})
        << "an end with no quiesce before it must stay silent";
}

TEST(SessionLifecycleWatch, OneReasonEndingLeavesTheOthersAndEachEndIsAnnouncedOnce)
{
    Agent agent;
    FakeLogind::signal(*agent.bus.logind->holder, "Lock");                                             // Q1
    FakeLogind::propertiesChanged(*agent.bus.logind->holder, kSessionIface, one("LockedHint", true));  // Q1, again
    agent.bus.logind->prepareForSleep(true);                                                           // Q0
    agent.bus.logind->prepareForSleep(false);                                                          // R0
    FakeLogind::propertiesChanged(*agent.bus.logind->holder, kSessionIface, one("LockedHint", false)); // R1
    FakeLogind::propertiesChanged(*agent.bus.logind->holder, kSessionIface, one("LockedHint", false)); // nothing
    agent.bus.logind->prepareForSleep(true);                                                           // Q0, a sentinel
    const std::vector<std::string> expected{"Q1", "Q1", "Q0", "R0", "R1", "Q0"};
    EXPECT_EQ(agent.notices.waitFor(expected.size()), expected);
    std::this_thread::sleep_for(100ms);
    EXPECT_EQ(agent.notices.waitFor(expected.size() + 1, 100ms), expected);
}

// Only the wake is the core's to act on: the session coming back lifts nothing
// the sleep suspended.
TEST(SessionLifecycleWatch, OnlyTheWakeLiftsTheHoldSuspension)
{
    Agent agent;
    agent.bus.logind->prepareForSleep(true);
    ASSERT_TRUE(waitUntil([&agent] { return agent.holdsSuspended(); }));
    FakeLogind::propertiesChanged(*agent.bus.logind->holder, kSessionIface, one("Active", false));
    FakeLogind::propertiesChanged(*agent.bus.logind->holder, kSessionIface, one("Active", true));
    ASSERT_EQ(agent.notices.waitFor(3), (std::vector<std::string>{"Q0", "Q2", "R2"}));
    EXPECT_TRUE(agent.holdsSuspended()) << "the session coming back must not lift the sleep's suspension";
    agent.bus.logind->prepareForSleep(false);
    ASSERT_TRUE(waitUntil([&agent] { return !agent.holdsSuspended(); })) << "the wake does";
}
