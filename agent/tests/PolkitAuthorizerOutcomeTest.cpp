// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Drives the REAL PolkitAuthorizer (not a test double) against a fake
// org.freedesktop.PolicyKit1 on a private bus, with a real ManagerObject
// exported on the same bus, and asserts the D-Bus error name a client
// receives. This is what the review's original claim reduces to at the wire:
// a client cannot tell "polkit said no" from "polkit said nothing" through
// the error name alone -- until this fix, both arrive as NotAuthorized.

#include "PolkitAuthorizer.h"
#include "dbus/ManagerObject.h"
#include <LibreSCRS/Agent/config/ConfigStore.h>
#include <LibreSCRS/Agent/operations/RateLimiter.h>

#include <sdbus-c++/sdbus-c++.h>
#include <gtest/gtest.h>

#include <fcntl.h>
#include <unistd.h>

#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <map>
#include <string>
#include <thread>
#include <tuple>

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
            ->addVTable(sdbus::registerMethod("CheckAuthorization")
                            .implementedAs([this](sdbus::Struct<std::string, std::map<std::string, sdbus::Variant>>,
                                                  std::string, std::map<std::string, std::string>, std::uint32_t,
                                                  std::string) -> CheckAuthReply {
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
    std::string importAndCollectErrorName()
    {
        const int fd = ::open("/dev/null", O_RDONLY | O_CLOEXEC);
        try {
            std::map<std::string, sdbus::Variant> out;
            proxy->callMethod(kMethod)
                .onInterface(sdbus::InterfaceName{kCfgIface})
                .withTimeout(std::chrono::seconds{120}) // the TEST'S leg must not be what expires
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
