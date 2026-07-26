// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Teeth test for the typed zombie op's OWN sdbus channel/adaptor resource class
// (a DIFFERENT class than the core members the crypto-worker context covers).
//
// A typed Operation1 op carries a REAL Operation1Adaptor-backed channel bound to
// the agent bus connection. When such an op is abandoned to the process-lifetime
// zombie list and the backend (AgentService) is torn down, the op's channel makes
// two post-teardown touches on that connection:
//   (a) an armed watchdog firing finish() -> emitFinished() through the adaptor;
//   (b) the adaptor unregister when the zombie finally drains (op.reset()).
// The fix: gate finish()'s emit on the shutdown token, stop the watchdog on the
// abandon path, and CO-OWN the connection (shared_ptr, keepAlive'd into the typed
// op exactly as CardObject::attachLifetimeGuards does) so both touches land on
// LIVE memory. The existing drain tests use FAKE channels and structurally cannot
// see this; this one uses the real adaptor.
//
// PROVE TEETH (manual): remove `op->keepAlive(conn)` below (or the OperationBase
// m_keepAlives-before-m_channel member order) and re-run under ThreadSanitizer —
// the connection is freed with the composition and the zombie's adaptor unregister
// then reads/writes freed memory, which TSan traps. Meaningful under TSan.

#include <LibreSCRS/Agent/OperationState.h>
#include <LibreSCRS/Agent/backend/OperationChannel.h>
#include <LibreSCRS/Agent/operations/OperationBase.h>
#include <LibreSCRS/Agent/operations/OperationManager.h>
#include "operations/Operation1Adaptor.h"
#include "org.librescrs.Agent.Operation.Identity1_adaptor.h"
#include <LibreSCRS/CancelToken.h>

#include <sdbus-c++/Error.h>
#include <sdbus-c++/IConnection.h>

#include <gtest/gtest.h>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string_view>
#include <utility>

using namespace LibreSCRS::Agent;
using namespace LibreSCRS::Agent::Operations;
using namespace std::chrono_literals;
using IdentityAdaptor = org::librescrs::Agent::Operation::Identity1_adaptor;

namespace {

// Operation1Adaptor is abstract (every typed sub-interface declares the
// GetResult recovery method); this probe supplies the minimal no-store
// implementation — this test only exercises the channel teardown class.
class IdentityProbeAdaptor final : public Operation1Adaptor<IdentityAdaptor>
{
public:
    using Operation1Adaptor<IdentityAdaptor>::Operation1Adaptor;

private:
    Identity1Wire GetResult() override
    {
        throw sdbus::Error{sdbus::Error::Name{"org.librescrs.Agent.Error.NoResult"}, "probe has no store"};
    }
};

const ObjectId kReader{7};

// A latch the wedged op blocks on (the stand-in for the human consent prompt).
struct Latch
{
    std::mutex mutex;
    std::condition_variable cv;
    bool released{false};

    void release()
    {
        {
            std::lock_guard lock(mutex);
            released = true;
        }
        cv.notify_all();
    }
    void waitForRelease()
    {
        std::unique_lock lock(mutex);
        cv.wait(lock, [this] { return released; });
    }
};

// A REAL typed channel: it hosts an Operation1Adaptor<Identity1> bound to the bus
// connection, so registerAdaptor (ctor) / emitFinished / unregisterAdaptor (dtor)
// all touch that connection — exactly like the production IdentityChannel. Records
// whether the terminal Finished ever reached the wire.
struct ChannelSlots
{
    std::atomic<int> finishCount{0};
};
class RealTypedChannel final : public OperationChannel
{
public:
    RealTypedChannel(sdbus::IConnection& bus, sdbus::ObjectPath path, std::shared_ptr<OperationState> state,
                     std::shared_ptr<ChannelSlots> slots)
        : m_inner(bus, std::move(path), std::move(state)), m_slots(std::move(slots))
    {}
    void emitPropertiesChanged() noexcept override
    {
        m_inner.emitPropertiesChangedForOperation1();
    }
    void emitFinished(OperationStatus s, ErrorCode e, std::string_view k, std::string_view f) noexcept override
    {
        m_slots->finishCount.fetch_add(1, std::memory_order_acq_rel);
        m_inner.emitFinishedNx(static_cast<std::uint32_t>(s), static_cast<std::uint32_t>(e), k, f);
    }
    bool emitResult(const ResultPayload&) noexcept override
    {
        return true;
    }

private:
    IdentityProbeAdaptor m_inner;
    std::shared_ptr<ChannelSlots> m_slots;
};

// A typed op that wedges in the "prompt" (a latch), then — on unblock — honours the
// shutdown-cancel token and SKIPS its wire completion, exactly as the production
// typed ops do after their flow returns.
class WedgingTypedOp final : public OperationBase
{
public:
    WedgingTypedOp(std::unique_ptr<OperationChannel> ch, std::shared_ptr<OperationState> st, Latch& latch,
                   std::atomic<int>& entered, std::atomic<int>& drained)
        : OperationBase(std::move(ch), std::move(st), []() noexcept {}), m_latch(latch), m_entered(entered),
          m_drained(drained)
    {}

protected:
    void doWork() override
    {
        // Do NOT transition into Authenticating/Reading: keep the per-op watchdog
        // unarmed so this test isolates the channel-unregister touch path.
        m_entered.fetch_add(1, std::memory_order_acq_rel);
        m_latch.waitForRelease();
        if (shutdownRequested()) {
            m_drained.fetch_add(1, std::memory_order_acq_rel);
            return; // teardown: skip the wire completion (as the real typed ops do)
        }
        finish(OperationStatus::Cancelled, ErrorCode::None, "op.cancelled", "cancelled");
        m_drained.fetch_add(1, std::memory_order_acq_rel);
    }

private:
    Latch& m_latch;
    std::atomic<int>& m_entered;
    std::atomic<int>& m_drained;
};

} // namespace

// A typed op with a REAL bus-bound channel is wedged, abandoned, and the backend
// connection share is dropped while it is still wedged. Only the op's co-owned
// connection share (attached exactly as CardObject::attachLifetimeGuards does)
// keeps the connection alive; the delayed drain then unregisters the adaptor
// against LIVE memory (TSan-clean) and the op skips its completion because the
// shutdown token fired.
TEST(TypedChannelWedgeDrain, AbandonedTypedOpKeepsItsBusConnectionAliveThroughCoOwnedShare)
{
    // The agent bus connection the composition (AgentService) owns as a shared_ptr.
    std::shared_ptr<sdbus::IConnection> conn = sdbus::createSessionBusConnection();
    ASSERT_NE(conn, nullptr) << "private session bus (run under dbus-run-session)";
    conn->requestName(sdbus::ServiceName{"org.librescrs.Agent.Test.TypedWedge"});
    conn->enterEventLoopAsync();

    Latch latch;
    std::atomic<int> entered{0};
    std::atomic<int> drained{0};
    auto slots = std::make_shared<ChannelSlots>();

    LibreSCRS::CancelSource shutdown; // the agent-wide shutdown-cancel source

    {
        OperationManager mgr; // bus-less worker path; the CHANNEL uses the real bus

        auto state = std::make_shared<OperationState>();
        auto channel =
            std::make_unique<RealTypedChannel>(*conn, sdbus::ObjectPath{"/org/librescrs/Agent/op/0"}, state, slots);
        auto op = std::make_unique<WedgingTypedOp>(std::move(channel), state, latch, entered, drained);
        // Co-own the bus connection + bind the shutdown token, EXACTLY as
        // CardObject::attachLifetimeGuards does for every production typed op.
        // Removing this keepAlive is the RED-proof: the connection is then freed at
        // conn.reset() below and the zombie's adaptor unregister traps under TSan.
        op->keepAlive(conn);
        op->bindShutdownToken(shutdown.token());
        mgr.enqueueForTest(kReader, std::move(op));

        const auto enteredDeadline = std::chrono::steady_clock::now() + 2s;
        while (entered.load(std::memory_order_acquire) == 0 && std::chrono::steady_clock::now() < enteredDeadline) {
            std::this_thread::sleep_for(5ms);
        }
        ASSERT_EQ(entered.load(std::memory_order_acquire), 1) << "typed op never entered the wedge";

        // The op co-owns the connection, so the composition is not the sole owner.
        EXPECT_GE(conn.use_count(), 2);

        // Model quiesce: cancel the shutdown token (requestCryptoShutdown analogue).
        shutdown.requestCancel();

        // Abandon the still-wedged worker (it is detached to the zombie list).
        const auto t0 = std::chrono::steady_clock::now();
        mgr.removeReader(kReader);
        EXPECT_LT(std::chrono::steady_clock::now() - t0, 1s) << "removeReader blocked on the wedged typed worker";

        // Tear the composition's connection down: stop its loop and drop the share.
        // Only the abandoned op's co-owned share keeps the connection alive now.
        conn->leaveEventLoop();
        conn.reset();

        // Delayed unblock (the late CancelCurrent / sd-bus timeout): the zombie
        // worker's doWork returns, the abandon branch quiesces + drops the op, and
        // ~RealTypedChannel unregisters the adaptor against the (still co-owned)
        // connection.
        latch.release();

        const auto drainDeadline = std::chrono::steady_clock::now() + 2s;
        while (drained.load(std::memory_order_acquire) == 0 && std::chrono::steady_clock::now() < drainDeadline) {
            std::this_thread::sleep_for(5ms);
        }
        EXPECT_EQ(drained.load(std::memory_order_acquire), 1) << "the abandoned typed op never drained";

        // Give the zombie worker thread time to run the abandon branch (op.reset()
        // -> ~RealTypedChannel -> unregisterAdaptor) so TSan observes the touch.
        std::this_thread::sleep_for(200ms);

        // Shutdown-cancel skip: the op must NOT have driven its wire completion, so
        // the watchdog-emit + finish-emit channel touches never happened.
        EXPECT_EQ(slots->finishCount.load(std::memory_order_acquire), 0)
            << "the typed op drove its channel completion on the shutdown-cancel path";
    }
}
