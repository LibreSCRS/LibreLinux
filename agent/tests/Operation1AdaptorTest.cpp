// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Lifecycle + cancel-seam tests for Operation1Adaptor. Uses a private
// session bus (dbus-run-session) so registerAdaptor / unregisterAdaptor
// exercise the real codepath but no agent infrastructure is needed.
#include "dbus/OperationAdaptorFactory.h"
#include "operations/Operation1Adaptor.h"
#include <LibreSCRS/Agent/KeyType.h>
#include <LibreSCRS/Agent/OperationState.h> // relocated struct
#include <LibreSCRS/Agent/value/CardReadSnapshot.h>
#include <LibreSCRS/Agent/value/CertSnapshot.h>
#include "org.librescrs.Agent.Operation.Identity1_adaptor.h"

#include <sdbus-c++/Error.h>
#include <sdbus-c++/IConnection.h>
#include <sdbus-c++/IProxy.h>

#include <gtest/gtest.h>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <future>
#include <map>
#include <memory>
#include <thread>
#include <vector>

using LibreSCRS::Agent::Operations::CancelRoute;
using LibreSCRS::Agent::Operations::Operation1Adaptor;
using LibreSCRS::Agent::Operations::OperationState;
using IdentityAdaptor = org::librescrs::Agent::Operation::Identity1_adaptor;

namespace {
// Operation1Adaptor is abstract (every typed sub-interface declares the
// GetResult recovery method); this probe supplies the minimal no-store
// implementation so the Operation1 machinery can be exercised in isolation.
class IdentityProbeAdaptor final : public Operation1Adaptor<IdentityAdaptor>
{
public:
    using Operation1Adaptor<IdentityAdaptor>::Operation1Adaptor;

    // When set, GetResult emits PropertiesChanged from inside its dispatch, i.e.
    // from the bus thread, the way the agent does from enqueue.
    std::atomic<bool> emitFromGetResult{false};
    // When set, Status() (served for Properties.Get("Status")) emits
    // PropertiesChanged from inside that dispatch. sd-bus then calls Phase() and
    // Completed() on the bus thread while the current message is the owner's own
    // Properties.Get: only the agent-emitting flag tells that from a client read.
    std::atomic<bool> emitFromStatus{false};

private:
    std::uint32_t Status() override
    {
        if (emitFromStatus.exchange(false)) { // the emit itself reads Status again
            emitPropertiesChangedForOperation1();
        }
        return terminalStatus();
    }
    LibreSCRS::Agent::Operations::Identity1Wire GetResult() override
    {
        if (emitFromGetResult.load()) {
            emitPropertiesChangedForOperation1();
        }
        throw sdbus::Error{sdbus::Error::Name{"org.librescrs.Agent.Error.NoResult"}, "probe has no store"};
    }
};
} // namespace

TEST(Operation1Adaptor, OperationStateDefaults)
{
    LibreSCRS::Agent::Operations::OperationState s;
    EXPECT_EQ(s.phase.load(), 0u);
    EXPECT_FALSE(s.cancelled.load());
    EXPECT_FALSE(s.completed.load());
    EXPECT_EQ(s.watchdogTimeoutSec.load(), 60u);
}

TEST(Operation1Adaptor, ConstructsAndUnregistersCleanly)
{
    auto conn = sdbus::createSessionBusConnection();
    ASSERT_NE(conn, nullptr) << "private session bus (run under dbus-run-session)";
    conn->requestName(sdbus::ServiceName{"org.librescrs.Agent.Test.Op"});
    conn->enterEventLoopAsync();

    auto state = std::make_shared<OperationState>();
    state->phase.store(4u);
    state->completed.store(true);
    state->terminalStatus.store(2u);
    state->terminalErrorCode.store(1u);
    {
        IdentityProbeAdaptor adaptor(*conn, sdbus::ObjectPath{"/org/librescrs/Agent/op/0"}, state, {});
        EXPECT_EQ(adaptor.phase(), 4u);
        EXPECT_TRUE(adaptor.completed());
        EXPECT_EQ(adaptor.terminalStatus(), 2u);
        EXPECT_EQ(adaptor.terminalErrorCode(), 1u);
    }
    conn->leaveEventLoop();
}

TEST(Operation1Adaptor, CancelRunsTheRouteOnlyForTheLaunchingClient)
{
    auto conn = sdbus::createSessionBusConnection();
    ASSERT_NE(conn, nullptr);
    conn->requestName(sdbus::ServiceName{"org.librescrs.Agent.Test.OpCancel"});
    conn->enterEventLoopAsync();
    auto owner = sdbus::createSessionBusConnection();
    ASSERT_NE(owner, nullptr);
    auto other = sdbus::createSessionBusConnection();
    ASSERT_NE(other, nullptr);

    std::atomic<int> runs{0};
    const sdbus::ObjectPath path{"/org/librescrs/Agent/op/1"};
    IdentityProbeAdaptor adaptor(*conn, path, std::make_shared<OperationState>(),
                                 {.owner = owner->getUniqueName(), .run = [&runs] { ++runs; }});
    const auto cancelFrom = [&path](sdbus::IConnection& bus) {
        auto proxy = sdbus::createProxy(bus, sdbus::ServiceName{"org.librescrs.Agent.Test.OpCancel"}, path);
        proxy->callMethod("Cancel").onInterface(sdbus::InterfaceName{"org.librescrs.Agent.Operation1"});
    };

    cancelFrom(*other);
    EXPECT_EQ(runs.load(), 0) << "a client that did not launch the operation ended it";
    cancelFrom(*owner);
    EXPECT_EQ(runs.load(), 1) << "Cancel from the launching client did not reach the operation";

    conn->leaveEventLoop();
}

TEST(Operation1Adaptor, EmitWrappersAreNoexceptAndCompleteWithoutSubscribers)
{
    auto conn = sdbus::createSessionBusConnection();
    ASSERT_NE(conn, nullptr);
    conn->requestName(sdbus::ServiceName{"org.librescrs.Agent.Test.OpEmit"});
    conn->enterEventLoopAsync();

    auto state = std::make_shared<OperationState>();
    IdentityProbeAdaptor adaptor(*conn, sdbus::ObjectPath{"/org/librescrs/Agent/op/2"}, state, {});

    // Compile-time noexcept contract.
    static_assert(noexcept(adaptor.emitFinishedNx(0u, 0u, std::string{}, std::string{})));
    static_assert(noexcept(adaptor.emitPropertiesChangedForOperation1()));

    // No subscribers yet -- the emit path still runs end-to-end without
    // raising. (No observable side effect on the wire; the contract is
    // simply that the noexcept surface is honoured.)
    adaptor.emitFinishedNx(0u, 0u, "test.ok", "OK");
    adaptor.emitPropertiesChangedForOperation1();

    conn->leaveEventLoop();
}

// The card's per-operation consent rule is the struct's last member, after
// trustStatus. Each entry holds opposite values in the two booleans, so a
// rule written into signingCapable's place (or the reverse) is seen.
TEST(Operation1Adaptor, CertificatesWireCarriesTheConsentRuleLast)
{
    LibreSCRS::Agent::CertSnapshot marked;
    marked.certId = "aa";
    marked.signingCapable = false;
    marked.alwaysAuthenticate = true;
    LibreSCRS::Agent::CertSnapshot ordinary;
    ordinary.certId = "bb";
    ordinary.signingCapable = true;
    ordinary.alwaysAuthenticate = false;
    const auto wire = LibreSCRS::Agent::Operations::buildCertificates1Wire({marked, ordinary});
    ASSERT_EQ(wire.size(), 2u);
    EXPECT_FALSE(wire[0].get<1>());
    EXPECT_TRUE(wire[0].get<7>());
    EXPECT_TRUE(wire[1].get<1>());
    EXPECT_FALSE(wire[1].get<7>());
}

// The key facts are the struct's last four members, after the consent rule.
// The entry's two booleans are opposite, so a consent rule written into
// canDerive's place (or the reverse) is seen.
TEST(Operation1Adaptor, CertificatesWireCarriesTheKeyFactsLast)
{
    LibreSCRS::Agent::CertSnapshot lk;
    lk.certId = "lk";
    lk.alwaysAuthenticate = false;
    lk.keyId = {0xF7, 0x13};
    lk.keyType = LibreSCRS::Agent::KeyType::Ec;
    lk.keyBits = 384;
    lk.canDerive = true;
    const auto wire = LibreSCRS::Agent::Operations::buildCertificates1Wire({lk});
    ASSERT_EQ(wire.size(), 1u);
    EXPECT_FALSE(wire[0].get<7>());
    EXPECT_EQ(wire[0].get<8>(), (std::vector<std::uint8_t>{0xF7, 0x13}));
    EXPECT_EQ(wire[0].get<9>(), "EC");
    EXPECT_EQ(wire[0].get<10>(), 384u);
    EXPECT_TRUE(wire[0].get<11>());
}

namespace {
constexpr const char* kObserveSvc = "org.librescrs.Agent.Test.OpObserve";
constexpr const char* kPropsIface = "org.freedesktop.DBus.Properties";

struct ObserveRig
{
    std::unique_ptr<sdbus::IConnection> conn = sdbus::createSessionBusConnection();
    std::unique_ptr<sdbus::IConnection> owner = sdbus::createSessionBusConnection();
    std::unique_ptr<sdbus::IConnection> other = sdbus::createSessionBusConnection();
    std::shared_ptr<OperationState> state = std::make_shared<OperationState>();
    std::atomic<int> observed{0};
    sdbus::ObjectPath path;
    std::unique_ptr<IdentityProbeAdaptor> adaptor;

    explicit ObserveRig(const char* objectPath) : path(objectPath) {}
    // False without a private session bus; the tests ASSERT on it, as the
    // neighbouring ones do for createSessionBusConnection().
    [[nodiscard]] bool start()
    {
        if (!conn || !owner || !other) {
            return false;
        }
        conn->requestName(sdbus::ServiceName{kObserveSvc});
        conn->enterEventLoopAsync();
        state->onObserved([this] { ++observed; });
        adaptor =
            std::make_unique<IdentityProbeAdaptor>(*conn, path, state, CancelRoute{.owner = owner->getUniqueName()});
        return true;
    }
    ~ObserveRig()
    {
        adaptor.reset();
        if (conn) {
            conn->leaveEventLoop();
        }
    }
    void getAllFrom(sdbus::IConnection& bus) const
    {
        auto proxy = sdbus::createProxy(bus, sdbus::ServiceName{kObserveSvc}, path);
        std::map<sdbus::PropertyName, sdbus::Variant> props;
        proxy->callMethod("GetAll")
            .onInterface(sdbus::InterfaceName{kPropsIface})
            .withArguments(sdbus::InterfaceName{"org.librescrs.Agent.Operation1"})
            .storeResultsTo(props);
        EXPECT_FALSE(props.empty());
    }
};
} // namespace

TEST(Operation1Adaptor, AgentsOwnPropertiesChangedNeverCountsAsTheClientReading)
{
    ObserveRig rig{"/org/librescrs/Agent/op/3"};
    ASSERT_TRUE(rig.start()) << "private session bus (run under dbus-run-session)";

    // Both emits happen with no client Properties call behind them. This catches a
    // trigger that fires on any getter call; the flag itself is proved by the
    // test below, where the message check alone would pass.

    // From another thread (a worker, e.g. enqueue).
    std::thread worker([&rig] { rig.adaptor->emitPropertiesChangedForOperation1(); });
    worker.join();
    EXPECT_EQ(rig.observed.load(), 0) << "an emit from a worker thread was taken for a client read";

    // From the bus thread, inside a method dispatch.
    rig.adaptor->emitFromGetResult = true;
    auto proxy = sdbus::createProxy(*rig.owner, sdbus::ServiceName{kObserveSvc}, rig.path);
    try {
        proxy->callMethod("GetResult").onInterface(sdbus::InterfaceName{"org.librescrs.Agent.Operation.Identity1"});
    } catch (const sdbus::Error&) {
        // NoResult is the probe's expected answer; the emit happened before it.
    }
    EXPECT_EQ(rig.observed.load(), 0) << "an emit from the bus thread was taken for a client read";
}

// The emit runs inside the owner's Properties.Get of Status, so the current
// message is a Get from the owner: without the agent-emitting flag the nested
// Phase()/Completed() calls would count it as the client reading them.
TEST(Operation1Adaptor, EmitInsideTheOwnersPropertiesGetIsNotTheClientReadingPhase)
{
    ObserveRig rig{"/org/librescrs/Agent/op/6"};
    ASSERT_TRUE(rig.start()) << "private session bus (run under dbus-run-session)";
    rig.adaptor->emitFromStatus = true;
    auto proxy = sdbus::createProxy(*rig.owner, sdbus::ServiceName{kObserveSvc}, rig.path);
    sdbus::Variant status;
    proxy->callMethod("Get")
        .onInterface(sdbus::InterfaceName{kPropsIface})
        .withArguments(sdbus::InterfaceName{"org.librescrs.Agent.Operation1"}, sdbus::PropertyName{"Status"})
        .storeResultsTo(status);
    EXPECT_EQ(rig.observed.load(), 0) << "the agent's own PropertiesChanged was taken for a client read";
}

TEST(Operation1Adaptor, OwnersGetAllCountsAsTheClientReadingExactlyOnce)
{
    ObserveRig rig{"/org/librescrs/Agent/op/4"};
    ASSERT_TRUE(rig.start()) << "private session bus (run under dbus-run-session)";
    rig.getAllFrom(*rig.owner);
    EXPECT_EQ(rig.observed.load(), 1);
    rig.getAllFrom(*rig.owner);
    EXPECT_EQ(rig.observed.load(), 1) << "the observation must be one-shot";
}

TEST(Operation1Adaptor, AnotherCallersGetAllDoesNotCount)
{
    ObserveRig rig{"/org/librescrs/Agent/op/5"};
    ASSERT_TRUE(rig.start()) << "private session bus (run under dbus-run-session)";
    rig.getAllFrom(*rig.other);
    EXPECT_EQ(rig.observed.load(), 0) << "a client that did not launch the operation observed it";
    rig.getAllFrom(*rig.owner);
    EXPECT_EQ(rig.observed.load(), 1);
}

// Production path: the Identity channel's own adaptor, a real OperationState
// whose onObserved action emits a Group through the same channel (what the
// core's relay release does). The owner's Properties.GetAll runs the getter on
// the bus thread, which fires the action, so sdbus-c++ must emit a signal from
// inside a getter of a method dispatch without deadlocking or losing it.
TEST(Operation1Adaptor, GroupEmittedFromTheOwnersGetAllReachesTheSubscriber)
{
    auto conn = sdbus::createSessionBusConnection();
    auto owner = sdbus::createSessionBusConnection();
    ASSERT_NE(conn, nullptr) << "private session bus (run under dbus-run-session)";
    ASSERT_NE(owner, nullptr);
    conn->requestName(sdbus::ServiceName{kObserveSvc});
    conn->enterEventLoopAsync();
    owner->enterEventLoopAsync();

    const sdbus::ObjectPath path{"/org/librescrs/Agent/op/7"};
    auto state = std::make_shared<OperationState>();
    auto channel =
        LibreSCRS::Agent::makeIdentityChannel(*conn, path, state, CancelRoute{.owner = owner->getUniqueName()});
    ASSERT_NE(channel, nullptr);

    LibreSCRS::Agent::GroupSnapshot group;
    group.groupKey = "document";
    group.fields.push_back({.fieldKey = "docRegNo", .labelKey = "k", .labelFallback = "Doc", .textValue = "123"});
    state->onObserved([&] { channel->emitGroup(group); });

    std::promise<std::string> got;
    auto proxy = sdbus::createProxy(*owner, sdbus::ServiceName{kObserveSvc}, path);
    proxy->uponSignal("Group")
        .onInterface(sdbus::InterfaceName{"org.librescrs.Agent.Operation.Identity1"})
        .call([&got](const std::string& key, const LibreSCRS::Agent::Operations::Identity1GroupFieldsWire& fields) {
            got.set_value(key + ":" + std::to_string(fields.size()));
        });

    std::map<sdbus::PropertyName, sdbus::Variant> props;
    proxy->callMethod("GetAll")
        .onInterface(sdbus::InterfaceName{kPropsIface})
        .withArguments(sdbus::InterfaceName{"org.librescrs.Agent.Operation1"})
        .withTimeout(std::chrono::seconds(5))
        .storeResultsTo(props);
    EXPECT_TRUE(props.contains(sdbus::PropertyName{"Phase"}));
    EXPECT_TRUE(props.contains(sdbus::PropertyName{"Completed"}));

    auto fut = got.get_future();
    ASSERT_EQ(fut.wait_for(std::chrono::seconds(5)), std::future_status::ready)
        << "the Group emitted from the getter never arrived";
    EXPECT_EQ(fut.get(), "document:1");

    proxy.reset();
    channel.reset();
    owner->leaveEventLoop();
    conn->leaveEventLoop();
}
