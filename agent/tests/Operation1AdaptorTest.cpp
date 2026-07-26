// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Lifecycle + cancel-seam tests for Operation1Adaptor. Uses a private
// session bus (dbus-run-session) so registerAdaptor / unregisterAdaptor
// exercise the real codepath but no agent infrastructure is needed.
#include "operations/Operation1Adaptor.h"
#include <LibreSCRS/Agent/OperationState.h> // relocated struct
#include "org.librescrs.Agent.Operation.Identity1_adaptor.h"

#include <sdbus-c++/Error.h>
#include <sdbus-c++/IConnection.h>

#include <gtest/gtest.h>
#include <memory>

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

private:
    LibreSCRS::Agent::Operations::Identity1Wire GetResult() override
    {
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
    state->progress.store(0.75);
    state->isIndeterminate.store(true);
    state->watchdogTimeoutSec.store(60u);
    state->completed.store(true);
    state->terminalStatus.store(2u);
    state->terminalErrorCode.store(1u);
    {
        IdentityProbeAdaptor adaptor(*conn, sdbus::ObjectPath{"/org/librescrs/Agent/op/0"}, state);
        EXPECT_EQ(adaptor.phase(), 4u);
        EXPECT_DOUBLE_EQ(adaptor.progress(), 0.75);
        EXPECT_TRUE(adaptor.isIndeterminate());
        EXPECT_EQ(adaptor.watchdogTimeoutSeconds(), 60u);
        EXPECT_TRUE(adaptor.completed());
        EXPECT_EQ(adaptor.terminalStatus(), 2u);
        EXPECT_EQ(adaptor.terminalErrorCode(), 1u);
    }
    conn->leaveEventLoop();
}

TEST(Operation1Adaptor, CancelFlagFlipsOnInvocation)
{
    auto conn = sdbus::createSessionBusConnection();
    ASSERT_NE(conn, nullptr);
    conn->requestName(sdbus::ServiceName{"org.librescrs.Agent.Test.OpCancel"});
    conn->enterEventLoopAsync();

    auto state = std::make_shared<OperationState>();
    IdentityProbeAdaptor adaptor(*conn, sdbus::ObjectPath{"/org/librescrs/Agent/op/1"}, state);

    EXPECT_FALSE(state->cancelled.load());
    adaptor.invokeCancelForTest();
    EXPECT_TRUE(state->cancelled.load());
    // Idempotent.
    adaptor.invokeCancelForTest();
    EXPECT_TRUE(state->cancelled.load());

    conn->leaveEventLoop();
}

TEST(Operation1Adaptor, EmitWrappersAreNoexceptAndCompleteWithoutSubscribers)
{
    auto conn = sdbus::createSessionBusConnection();
    ASSERT_NE(conn, nullptr);
    conn->requestName(sdbus::ServiceName{"org.librescrs.Agent.Test.OpEmit"});
    conn->enterEventLoopAsync();

    auto state = std::make_shared<OperationState>();
    IdentityProbeAdaptor adaptor(*conn, sdbus::ObjectPath{"/org/librescrs/Agent/op/2"}, state);

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
