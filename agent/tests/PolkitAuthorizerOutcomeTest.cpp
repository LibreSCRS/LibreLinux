// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Drives the REAL PolkitAuthorizer (not a test double) against a fake
// org.freedesktop.PolicyKit1 on a private bus, with a real ManagerObject
// exported on the same bus, and asserts the D-Bus error name a client
// receives. This is what the review's original claim reduces to at the wire:
// a client cannot tell "polkit said no" from "polkit said nothing" through
// the error name alone -- until this fix, both arrive as NotAuthorized.

#include "EventLoopPoster.h"
#include "PolkitAuthorizer.h"
#include "dbus/ManagerObject.h"
#include <LibreSCRS/Agent/config/ConfigStore.h>
#include <LibreSCRS/Agent/operations/RateLimiter.h>

#include <sdbus-c++/sdbus-c++.h>
#include <gtest/gtest.h>

#include <systemd/sd-event.h>

#include <fcntl.h>
#include <unistd.h>

#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <future>
#include <algorithm>
#include <atomic>
#include <map>
#include <mutex>
#include <string>
#include <thread>
#include <tuple>
#include <vector>

using namespace LibreSCRS::Agent;
namespace fs = std::filesystem;

namespace {

constexpr const char* kRootPath = "/org/librescrs/Agent";
constexpr const char* kCfgIface = "org.librescrs.Agent.Config1";
constexpr const char* kMethod = "ImportCscaMasterList";
constexpr const char* kPolkitService = "org.freedesktop.PolicyKit1";
constexpr const char* kPolkitPath = "/org/freedesktop/PolicyKit1/Authority";
constexpr const char* kPolkitIface = "org.freedesktop.PolicyKit1.Authority";

// A single struct out-arg, (bba{ss}) -- matching the real CheckAuthorization
// wire signature and what PolkitAuthorizer::Impl::authorize() decodes
// (sdbus::Struct<bool, bool, map>, NOT three separate out-args: a plain
// std::tuple return here marshals as three top-level D-Bus arguments and the
// production side then fails to demarshal a struct that was never sent).
using CheckAuthReply = sdbus::Struct<bool, bool, std::map<std::string, std::string>>;

// Fake polkit authority: exports CheckAuthorization on the PolicyKit1 path.
// Configurable to fail outright (the mapping gate) or to hold the reply for
// a set duration before granting (the budget gate).
struct FakePolicyKit
{
    explicit FakePolicyKit(sdbus::IConnection& conn)
    {
        conn.requestName(sdbus::ServiceName{kPolkitService});
        object = sdbus::createObject(conn, sdbus::ObjectPath{kPolkitPath});
        object
            ->addVTable(
                sdbus::registerMethod("CheckAuthorization")
                    .implementedAs([this](sdbus::Struct<std::string, std::map<std::string, sdbus::Variant>> subject,
                                          std::string, std::map<std::string, std::string>, std::uint32_t,
                                          std::string) -> CheckAuthReply {
                        const auto& details = subject.get<1>();
                        {
                            const std::lock_guard lock{mutex};
                            subjectKind = subject.get<0>();
                            subjectKeys.clear();
                            subjectTypes.clear();
                            for (const auto& [key, value] : details) {
                                subjectKeys.push_back(key);
                                subjectTypes[key] = value.peekValueType();
                            }
                        }
                        // polkit's own reading of a unix-process subject: an
                        // entry of another type than it expects is absent, and
                        // a pidfd without a uid is refused.
                        const auto typed = [&details](const char* key, const char* signature) {
                            const auto it = details.find(key);
                            return it != details.end() && std::string{it->second.peekValueType()} == signature;
                        };
                        if (typed("pidfd", "h") && !typed("uid", "i")) {
                            throw sdbus::Error{sdbus::Error::Name{"org.freedesktop.PolicyKit1.Error.Failed"},
                                               "Error parsing unix-process subject: 'pidfd' specified without 'uid'"};
                        }
                        if (failOutright) {
                            throw sdbus::Error{sdbus::Error::Name{"org.freedesktop.PolicyKit1.Error.Failed"},
                                               "fake authority: deliberately unreachable"};
                        }
                        if (holdFor.count() > 0) {
                            std::this_thread::sleep_for(holdFor);
                        }
                        return {true, false, {}};
                    })
                    .withInputParamNames("subject", "action_id", "details", "flags", "cancellation_id")
                    .withOutputParamNames("result")) // one name: one struct out-arg, not three
            .forInterface(sdbus::InterfaceName{kPolkitIface});
    }

    bool failOutright = false;
    std::chrono::seconds holdFor{0};
    std::unique_ptr<sdbus::IObject> object;
    // What the last CheckAuthorization asked about.
    std::mutex mutex;
    std::string subjectKind;
    std::vector<std::string> subjectKeys;
    std::map<std::string, std::string> subjectTypes; // key -> D-Bus signature
};

struct Harness
{
    explicit Harness(const char* tag) : dir(fs::temp_directory_path() / (std::string{"ll-polkit-outcome-"} + tag))
    {
        fs::remove_all(dir);
        bus = sdbus::createSessionBusConnection();
        setenv("DBUS_SYSTEM_BUS_ADDRESS", getenv("DBUS_SESSION_BUS_ADDRESS"), 1);
        bus->requestName(sdbus::ServiceName{std::string{"org.librescrs.Agent.Test.PolkitOutcome."} + tag});

        // The fake authority lives on its OWN connection, deliberately separate
        // from `bus` (which hosts ManagerObject). ImportCscaMasterList's handler
        // runs ON bus's single dispatch thread and BLOCKS there for the whole
        // synchronous CheckAuthorization round trip; if the fake authority were
        // exported on that same connection, the one thread able to dispatch the
        // incoming CheckAuthorization call would be the very thread blocked
        // waiting for its reply -- a self-deadlock that resolves only by timing
        // out. A second connection gives the fake its own dispatch thread.
        fakePolkitBus = sdbus::createSessionBusConnection();
        fakePolkit = std::make_unique<FakePolicyKit>(*fakePolkitBus);
        fakePolkitBus->enterEventLoopAsync();

        authorizer = std::make_unique<PolkitAuthorizer>(*bus);
        config = std::make_unique<Config::ConfigStore>(dir / "agent.conf", dir / "cache");
        manager = std::make_unique<ManagerObject>(*bus, sdbus::ObjectPath{kRootPath}, "t", *config, *authorizer,
                                                  limiter, nullptr);
        bus->enterEventLoopAsync();

        clientBus = sdbus::createSessionBusConnection();
        clientBus->enterEventLoopAsync();
        proxy = sdbus::createProxy(*clientBus,
                                   sdbus::ServiceName{std::string{"org.librescrs.Agent.Test.PolkitOutcome."} + tag},
                                   sdbus::ObjectPath{kRootPath});
    }
    ~Harness()
    {
        proxy.reset();
        manager.reset();
        fs::remove_all(dir);
    }
    Harness(const Harness&) = delete;
    Harness& operator=(const Harness&) = delete;

    // Returns the D-Bus error name the client actually received.
    std::string importAndCollectErrorName(std::chrono::seconds timeout = std::chrono::seconds{120})
    {
        const int fd = ::open("/dev/null", O_RDONLY | O_CLOEXEC);
        try {
            std::map<std::string, sdbus::Variant> out;
            proxy->callMethod(kMethod)
                .onInterface(sdbus::InterfaceName{kCfgIface})
                .withTimeout(timeout) // by default the TEST'S leg must not be what expires
                .withArguments(sdbus::UnixFd{fd})
                .storeResultsTo(out);
            ::close(fd);
            return {}; // succeeded — no error name
        } catch (const sdbus::Error& e) {
            ::close(fd);
            return e.getName();
        }
    }

    fs::path dir;
    std::unique_ptr<sdbus::IConnection> bus;
    std::unique_ptr<sdbus::IConnection> fakePolkitBus;
    std::unique_ptr<FakePolicyKit> fakePolkit;
    std::unique_ptr<PolkitAuthorizer> authorizer;
    std::unique_ptr<Config::ConfigStore> config;
    Operations::RateLimiter limiter;
    std::unique_ptr<ManagerObject> manager;
    std::unique_ptr<sdbus::IConnection> clientBus;
    std::unique_ptr<sdbus::IProxy> proxy;
};

// An sd-event loop on its own thread with an EventLoopPoster on it: what the
// agent hands the authorizer's answers back through. Its callbacks run outside
// any bus dispatch, as they do in the agent.
struct LoopThread
{
    LoopThread()
    {
        std::promise<void> ready;
        thread = std::thread([this, &ready] {
            sd_event_new(&event);
            poster = std::make_shared<EventLoopPoster>(event);
            ready.set_value();
            sd_event_loop(event);
            poster.reset();
            sd_event_unref(event);
        });
        ready.get_future().wait();
    }
    ~LoopThread()
    {
        poster->post([ev = event] { sd_event_exit(ev, 0); });
        thread.join();
    }
    LoopThread(const LoopThread&) = delete;
    LoopThread& operator=(const LoopThread&) = delete;

    sd_event* event = nullptr;
    std::shared_ptr<EventLoopPoster> poster;
    std::thread thread;
};

} // namespace

// The mapping gate: the fake authority answers with a D-Bus error (sub-second
// — no timeout involved at all). Today: NotAuthorized (a timeout/failure is
// mapped to the same bool `false` a real refusal produces). After: the
// distinct CommunicationError name, because nothing was decided.
TEST(PolkitAuthorizerOutcome, CommunicationFailureIsNotReportedAsRefusal)
{
    Harness h("mapping");
    h.fakePolkit->failOutright = true;
    const auto name = h.importAndCollectErrorName();
    EXPECT_EQ(name, "org.librescrs.Agent.Error.CommunicationError");
}

// The budget gate: the fake authority holds its reply for 26s (past the
// inherited 25.02s D-Bus default) and THEN grants. Today: the call already
// timed out at ~25s and reports NotAuthorized for a human who was never
// asked. After: the widened budget lets the real grant through, ~26s.
TEST(PolkitAuthorizerOutcome, ASlowButRealGrantStillCompletes)
{
    Harness h("budget");
    h.fakePolkit->holdFor = std::chrono::seconds{26};
    const auto start = std::chrono::steady_clock::now();
    const auto name = h.importAndCollectErrorName();
    const auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now() - start);
    // The empty /dev/null descriptor is not a master list, so the import may
    // still fail on ITS OWN terms once authorization clears -- what this test
    // asserts is only that the grant got through in time to be asked at all:
    // the widened budget must not still be reporting NotAuthorized for a
    // human who answered, just slowly.
    EXPECT_NE(name, "org.librescrs.Agent.Error.NotAuthorized")
        << "the fake authority granted the request after the long hold; a subsequent failure on the "
           "empty /dev/null descriptor is fine, but it must not be reported as a policy refusal; got: "
        << name;
    EXPECT_GE(elapsed.count(), 26);
}

// While a person is still answering the authority (a polkit password dialog),
// the agent keeps serving: another client's call is answered and a signal a
// worker thread emits goes out. The fake authority holds its answer for 3 s.
TEST(PolkitAuthorizerOutcome, TheAgentKeepsServingWhileTheAuthorityDecides)
{
    Harness h("serving");
    h.fakePolkit->holdFor = std::chrono::seconds{3};

    // What a worker thread emits on the agent's connection.
    auto worker = sdbus::createObject(*h.bus, sdbus::ObjectPath{"/org/librescrs/Agent/test/worker"});
    worker->addVTable(sdbus::registerSignal("Progress").withParameters<std::uint32_t>("step"))
        .forInterface(sdbus::InterfaceName{"org.librescrs.Agent.Test.Worker"});

    auto pending = std::async(std::launch::async, [&h] { return h.importAndCollectErrorName(); });
    std::this_thread::sleep_for(std::chrono::milliseconds(500)); // the import is now waiting on the authority

    const auto emittedAt = std::chrono::steady_clock::now();
    worker->emitSignal(sdbus::SignalName{"Progress"})
        .onInterface(sdbus::InterfaceName{"org.librescrs.Agent.Test.Worker"})
        .withArguments(std::uint32_t{1});
    const auto emittedIn = std::chrono::steady_clock::now() - emittedAt;
    EXPECT_LT(emittedIn, std::chrono::seconds{1}) << "a worker's emit waited for the authority";

    // Another client: its own connection, so nothing on the first client's side
    // can hold it up.
    auto otherClient = sdbus::createSessionBusConnection();
    auto otherProxy = sdbus::createProxy(
        *otherClient, sdbus::ServiceName{std::string{"org.librescrs.Agent.Test.PolkitOutcome."} + "serving"},
        sdbus::ObjectPath{kRootPath});
    const auto askedAt = std::chrono::steady_clock::now();
    const std::string version = otherProxy->getProperty(sdbus::PropertyName{"Version"})
                                    .onInterface("org.librescrs.Agent.Manager1")
                                    .get<std::string>();
    const auto answeredIn = std::chrono::steady_clock::now() - askedAt;
    EXPECT_EQ(version, "t");
    EXPECT_LT(answeredIn, std::chrono::seconds{1}) << "another client's call waited for the authority";

    // The import itself still gets the authority's answer (a grant), then
    // fails on its own terms: /dev/null is not a master list.
    const auto name = pending.get();
    EXPECT_NE(name, "org.librescrs.Agent.Error.NotAuthorized") << name;
    EXPECT_NE(name, "org.librescrs.Agent.Error.CommunicationError") << name;
}

// The bus hands out a pidfd for the caller (dbus-daemon >= 1.15.6 and
// dbus-broker publish ProcessFD), and polkit takes one as the subject: the
// process is then named by a handle that cannot be recycled, with no pid read
// and no /proc/<pid>/stat start time to pin.
TEST(PolkitAuthorizerOutcome, TheSubjectIsTheCallersPidfdWhenTheBusHandsOneOut)
{
    Harness h("pidfd");
    static_cast<void>(h.importAndCollectErrorName());
    const std::lock_guard lock{h.fakePolkit->mutex};
    EXPECT_EQ(h.fakePolkit->subjectKind, "unix-process");
    const auto& keys = h.fakePolkit->subjectKeys;
    EXPECT_NE(std::find(keys.begin(), keys.end(), "pidfd"), keys.end()) << "the subject names no pidfd";
    EXPECT_EQ(std::find(keys.begin(), keys.end(), "start-time"), keys.end())
        << "a start time is only for a bus that hands out no pidfd";
    // polkit takes a pidfd only together with a uid it can read: int32.
    EXPECT_EQ(h.fakePolkit->subjectTypes["uid"], "i") << "polkit reads the uid as int32 and ignores any other type";
}

// The agent hands every answer back through its event loop's poster, so the
// part of a method that runs after a grant runs there, outside any dispatch.
// The answer must still reach the caller that way.
TEST(PolkitAuthorizerOutcome, TheAnswerResumesThroughTheAgentsLoop)
{
    // Declared first so it outlives the authorizer that holds its poster: the
    // poster is then released on its own loop thread.
    LoopThread loop;
    std::atomic<int> posted{0};
    Harness h("loop");
    h.authorizer->deliverAnswersThrough([&posted, poster = loop.poster](std::function<void()> answer) {
        ++posted;
        poster->post(std::move(answer));
    });
    const auto name = h.importAndCollectErrorName(std::chrono::seconds{10});
    EXPECT_EQ(posted.load(), 1) << "the answer did not go through the loop";
    // A grant, then the import fails on its own terms: /dev/null is not a
    // master list.
    EXPECT_NE(name, "org.librescrs.Agent.Error.NotAuthorized") << name;
    EXPECT_NE(name, "org.librescrs.Agent.Error.CommunicationError") << name;
    EXPECT_NE(name, "org.freedesktop.DBus.Error.NoReply") << name;
}

// The agent stops while the authority is still deciding: the authorizer goes
// away with the question outstanding. The caller is told at once that nothing
// was changed, instead of hearing nothing until its own timeout.
TEST(PolkitAuthorizerOutcome, AQuestionOutstandingWhenTheAuthorizerGoesIsAnswered)
{
    Harness h("teardown");
    h.fakePolkit->holdFor = std::chrono::seconds{4};
    const auto start = std::chrono::steady_clock::now();
    auto pending =
        std::async(std::launch::async, [&h] { return h.importAndCollectErrorName(std::chrono::seconds{30}); });
    std::this_thread::sleep_for(std::chrono::milliseconds(500)); // the import is now waiting on the authority
    h.authorizer.reset();
    const auto name = pending.get();
    const auto elapsed = std::chrono::steady_clock::now() - start;
    EXPECT_EQ(name, "org.librescrs.Agent.Error.CommunicationError");
    EXPECT_LT(elapsed, std::chrono::seconds{3}) << "the caller waited for its own timeout";
}
