// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Regression for the agent's ordered teardown (AgentService::quiesce()). Two
// guarantees the quiesce provides, modelled with the SAME collaborators the
// backend composes (the core ObjectRegistry + presence model for the inbound
// edge, the OperationManager + prompter for the crypto-worker edge) — the full
// AgentService needs a live session bus + PC/SC monitor it cannot get in CI, so
// the invariants are exercised through those collaborators directly, exactly as
// DBusServiceTest / CardOperationsIntegrationTest replicate the backend wiring.
//
//   1. Ordered shutdown: the inbound presence SOURCE is stopped BEFORE the core
//      registry's presence observers are severed, so no observer can fire into a
//      half-torn-down composition during teardown. (The static call order in
//      quiesce() is additionally pinned by TransportCaptureGuardTest.)
//   2. Shutdown under load: crypto workers wedged in a blocking consent prompt
//      are drained by the quiesce cancel — the pending prompt returns and every
//      worker JOINS, so the OperationManager teardown finishes in bounded time
//      with no hang and no use-after-free (the abandoned/keep-alive path is
//      proven core-side by PrompterKeepAliveDrainTest / ZombieWorkerDrainTest).
// Meaningful under ThreadSanitizer.

#include <LibreSCRS/Agent/Identity.h>
#include <LibreSCRS/Agent/OperationState.h>
#include <LibreSCRS/Agent/backend/OperationChannel.h>
#include <LibreSCRS/Agent/backend/PromptTypes.h>
#include <LibreSCRS/Agent/backend/PrompterClientBase.h>
#include <LibreSCRS/Agent/cache/CredentialCache.h>
#include <LibreSCRS/Agent/operations/CardSessionHolder.h>
#include <LibreSCRS/Agent/operations/OperationBase.h>
#include <LibreSCRS/Agent/operations/OperationManager.h>
#include <LibreSCRS/Agent/operations/PromptSerializer.h>
#include <LibreSCRS/Agent/operations/SerializingPrompter.h>
#include <LibreSCRS/Agent/presence/CapabilityResolver.h>
#include <LibreSCRS/Agent/presence/ObjectRegistry.h>
#include <LibreSCRS/Agent/presence/PresenceModel.h>
#include <LibreSCRS/CancelToken.h>
#include <LibreSCRS/Secure/String.h>

#include <gtest/gtest.h>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>

using namespace LibreSCRS::Agent;
using namespace LibreSCRS::Agent::Operations;
using namespace std::chrono_literals;

namespace {

// ATR-only resolver that never resolves a plugin — the presence model can churn
// readers/cards without opening any CardSession.
class NopResolver : public CapabilityResolver
{};

// ---- shutdown-under-load fixtures -----------------------------------------

// A latch every wedged worker blocks on inside requestPin — the stand-in for the
// human PIN entry the crypto worker parks in. cancel() releases it, modelling the
// prompter dismissing its modal so the in-flight RequestSecret returns Cancelled.
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

// Fake prompter whose requestPin BLOCKS until cancel() releases the latch — the
// exact wedge AgentService::quiesce()'s prompter cancel is designed to drain. A
// crypto seam value-captures a shared_ptr to it, so it is owned as a shared_ptr.
class CancelReleasesPrompter final : public PrompterClientBase
{
public:
    CancelReleasesPrompter(Latch& latch, std::atomic<int>& entered, std::atomic<int>& returned)
        : m_latch(latch), m_entered(entered), m_returned(returned)
    {}

    [[nodiscard]] PromptResult requestPin(const PromptOptions&) override
    {
        m_entered.fetch_add(1, std::memory_order_acq_rel);
        m_latch.waitForRelease();
        m_returned.fetch_add(1, std::memory_order_acq_rel);
        return PromptResult{PromptStatus::Cancelled, std::nullopt, "cancelled"};
    }
    [[nodiscard]] PromptResult requestCan(const PromptOptions&) override
    {
        return PromptResult{PromptStatus::Cancelled, std::nullopt, ""};
    }
    [[nodiscard]] PromptResult requestMrz(const PromptOptions&) override
    {
        return PromptResult{PromptStatus::Cancelled, std::nullopt, ""};
    }
    // Models an addressed Prompter1.Cancel landing: the pending RequestSecret
    // returns. The id is immaterial here -- this fake hosts one prompt.
    void cancel(const std::string& promptId) noexcept override
    {
        (void)promptId;
        m_latch.release();
    }

private:
    Latch& m_latch;
    std::atomic<int>& m_entered;
    std::atomic<int>& m_returned;
};

constexpr int kWedgedReaders = 6;

} // namespace

// ---- (1) ordered shutdown --------------------------------------------------

// The inbound presence source is stopped (its dispatch thread joined) BEFORE the
// core registry's presence observers are severed, so between the two no observer
// can fire, and after the sever a further presence delta reaches nothing.
TEST(AgentQuiesce, StopsInboundBeforeSeveringCorePresenceObservers)
{
    ObjectRegistry registry;
    NopResolver resolver;
    PresenceModel model(registry, resolver);

    std::atomic<int> fires{0};
    registry.setObservers([&fires](const ReaderState&) { fires.fetch_add(1, std::memory_order_acq_rel); },
                          [&fires](const CardState&) { fires.fetch_add(1, std::memory_order_acq_rel); },
                          [&fires](ObjectId) { fires.fetch_add(1, std::memory_order_acq_rel); },
                          [&fires](ObjectId, const PropertyDelta&) { fires.fetch_add(1, std::memory_order_acq_rel); });

    // Seed a reader, then let the "monitor" churn its card so the change observer
    // fires repeatedly — the sole registry-mutating thread while it runs (the main
    // thread only touches the registry again after joining it, mirroring how
    // MonitorBridge::stop() drains the poll thread before the core is quiesced).
    model.onReaderAdded("R0");
    const std::vector<std::uint8_t> atr{0x3b, 0x9f, 0x96, 0x80};

    std::atomic<bool> stop{false};
    std::atomic<bool> ran{false};
    std::thread monitor([&] {
        while (!stop.load(std::memory_order_acquire)) {
            model.onCardInserted("R0", atr);
            model.onCardRemoved("R0");
            ran.store(true, std::memory_order_release);
        }
    });

    const auto spinUp = std::chrono::steady_clock::now() + 2s;
    while (!ran.load(std::memory_order_acquire) && std::chrono::steady_clock::now() < spinUp) {
        std::this_thread::sleep_for(2ms);
    }
    ASSERT_TRUE(ran.load(std::memory_order_acquire)) << "the monitor never drove the presence observers";

    // ---- quiesce order ----
    // (a) STOP the inbound source: signal + JOIN so no thread touches the registry.
    stop.store(true, std::memory_order_release);
    monitor.join();
    const int firesAtStop = fires.load(std::memory_order_acquire);

    // (b) sever the presence observers — the core-quiesce step.
    registry.setObservers({}, {}, {});

    // The STATIC stop-before-sever ordering in quiesce() is pinned by
    // TransportCaptureGuardTest::QuiesceStopsInboundBeforeSeveringObservers; here
    // the RUNTIME proof is behavioural: the load drove the observers before the
    // stop, and NO observer fires after the sever (severed while alive).
    EXPECT_GT(firesAtStop, 0) << "the load never drove the observers, so the sever proves nothing";
    model.onCardInserted("R0", atr);
    model.onCardRemoved("R0");
    EXPECT_EQ(fires.load(std::memory_order_acquire), firesAtStop) << "a presence observer fired after the core quiesce";
}

// ---- (2) shutdown under load ----------------------------------------------

// Several per-reader crypto workers are wedged in the blocking prompt; the quiesce
// cancel drains them (each RequestSecret returns) so they JOIN, and the manager
// teardown finishes in bounded time — no hang, and (under TSan) no use-after-free.
TEST(AgentQuiesce, CancelDrainsWedgedCryptoWorkersSoTeardownIsBounded)
{
    Latch latch;
    std::atomic<int> entered{0};
    std::atomic<int> returned{0};

    // Owned as a shared_ptr — the crypto seam value-captures its own share.
    std::shared_ptr<PrompterClientBase> prompter = std::make_shared<CancelReleasesPrompter>(latch, entered, returned);

    auto mgr = std::make_unique<OperationManager>(); // bus-less worker path

    // One wedged crypto worker per reader: each value-captures the prompter share
    // (as the raw-crypto seam's worker closure does) and blocks in the prompt.
    for (int r = 0; r < kWedgedReaders; ++r) {
        const ObjectId reader{static_cast<std::uint64_t>(r) + 1};
        mgr->enqueueHolderProbeForTest(
            reader, [prompter](CardSessionHolder&) { static_cast<void>(prompter->requestPin(PromptOptions{})); });
    }

    // Wait until every worker is parked in the prompt.
    const auto enteredDeadline = std::chrono::steady_clock::now() + 5s;
    while (entered.load(std::memory_order_acquire) < kWedgedReaders &&
           std::chrono::steady_clock::now() < enteredDeadline) {
        std::this_thread::sleep_for(5ms);
    }
    ASSERT_EQ(entered.load(std::memory_order_acquire), kWedgedReaders) << "not every crypto worker reached the prompt";

    // The captured shares mean the composition is no longer the sole owner.
    EXPECT_GE(prompter.use_count(), 2);

    // Quiesce cancel: the dismissal lands so each pending RequestSecret returns
    // and the wedged workers unwedge (the JOIN path, not abandon). These workers
    // call the prompter directly, without the gate that mints ids, so the id is
    // a stand-in here -- what this case measures is the unwedging, not the
    // addressing (AddressedCancelTest covers that).
    prompter->cancel("shutdown-drain");

    const auto returnedDeadline = std::chrono::steady_clock::now() + 5s;
    while (returned.load(std::memory_order_acquire) < kWedgedReaders &&
           std::chrono::steady_clock::now() < returnedDeadline) {
        std::this_thread::sleep_for(5ms);
    }
    EXPECT_EQ(returned.load(std::memory_order_acquire), kWedgedReaders)
        << "the quiesce cancel did not drain every wedged crypto worker";

    // Tear the manager down (the ~AgentCore step that joins/abandons the workers)
    // and time it: with the workers drained it JOINS them, bounded.
    const auto t0 = std::chrono::steady_clock::now();
    mgr.reset();
    const auto elapsed = std::chrono::steady_clock::now() - t0;
    EXPECT_LT(elapsed, 5s) << "teardown hung on a wedged crypto worker after cancel";

    // The joined workers dropped their captured shares; the composition holds the
    // last one. No dangling worker, no UAF.
    EXPECT_EQ(prompter.use_count(), 1);
}

// ---- (3) typed-path abandoned-worker drain --------------------------------

namespace {

constexpr int kMarker = 0x5A5A;
const ObjectId kTypedReader{11};

// Emit-only channel that records whether the terminal Finished ever fired.
// Heap-shared so it outlives an abandoned op that completes (or, on the shutdown
// path, deliberately does NOT complete) on the zombie thread.
struct TypedSlots
{
    std::atomic<int> finishCount{0};
};
class RecordingChannel final : public OperationChannel
{
public:
    explicit RecordingChannel(std::shared_ptr<TypedSlots> slots) : m_slots(std::move(slots)) {}
    void emitPropertiesChanged() noexcept override {}
    void emitFinished(OperationStatus, ErrorCode, std::string_view, std::string_view) noexcept override
    {
        m_slots->finishCount.fetch_add(1, std::memory_order_acq_rel);
    }
    bool emitResult(const ResultPayload&) noexcept override
    {
        return true;
    }

private:
    std::shared_ptr<TypedSlots> m_slots;
};

// A prompter whose requestPin BLOCKS until the test releases the latch directly,
// modelling a prompter that ignores CancelCurrent so the worker is abandoned and
// unblocks only on the delayed sd-bus timeout. On unblock it reads its OWN marker
// (a deref of `this`), so a freed prompter would trip TSan there.
class ZombiePrompter final : public PrompterClientBase
{
public:
    ZombiePrompter(Latch& latch, std::atomic<int>& entered, std::atomic<int>& observedMarker, int marker)
        : m_latch(latch), m_entered(entered), m_observed(observedMarker), m_marker(marker)
    {}
    [[nodiscard]] PromptResult requestPin(const PromptOptions&) override
    {
        m_entered.fetch_add(1, std::memory_order_acq_rel);
        m_latch.waitForRelease();
        m_observed.store(m_marker, std::memory_order_release); // live-memory read of `this`
        return PromptResult{PromptStatus::Cancelled, std::nullopt, "cancelled"};
    }
    [[nodiscard]] PromptResult requestCan(const PromptOptions&) override
    {
        return PromptResult{PromptStatus::Cancelled, std::nullopt, ""};
    }
    [[nodiscard]] PromptResult requestMrz(const PromptOptions&) override
    {
        return PromptResult{PromptStatus::Cancelled, std::nullopt, ""};
    }
    // Models a prompter that does NOT dismiss on CancelCurrent — so the worker
    // stays wedged and is abandoned (the pathological zombie path).
    void cancel(const std::string& promptId) noexcept override
    {
        (void)promptId;
    }

private:
    Latch& m_latch;
    std::atomic<int>& m_entered;
    std::atomic<int>& m_observed;
    int m_marker;
};

// A typed op that routes its consent prompt through the REAL agent-wide seam
// (SerializingPrompter -> PromptSerializer) carrying its own token, and skips its
// wire completion on the shutdown-cancel path — exactly what the production typed
// ops (Sign / ReadIdentity / ReadCertificates) do after their flow returns.
class PromptingOp final : public OperationBase
{
public:
    PromptingOp(std::unique_ptr<OperationChannel> ch, std::shared_ptr<OperationState> st, PromptSerializer& serializer,
                PrompterClientBase& prompter)
        : OperationBase(std::move(ch), std::move(st),
                        [p = &prompter, sz = &serializer]() noexcept {
                            for (const auto& id : sz->liveIds()) {
                                p->cancel(id);
                            }
                        }),
          m_serializer(serializer), m_prompter(prompter)
    {}

protected:
    void doWork() override
    {
        setPhase(static_cast<std::uint32_t>(OperationPhase::AwaitingConsent));
        // The gate is keyed by card, as production keys it from the reader's card
        // object; this test drives one op, so the key only has to be stable.
        SerializingPrompter gated{m_serializer, m_prompter, token(), "card-typed-11"};
        static_cast<void>(gated.requestPin(PromptOptions{}));
        if (shutdownRequested()) {
            return; // teardown: skip the wire completion (as the real typed ops do)
        }
        finish(OperationStatus::Cancelled, ErrorCode::None, "op.cancelled", "cancelled");
    }

private:
    PromptSerializer& m_serializer;
    PrompterClientBase& m_prompter;
};

} // namespace

// A typed op is driven to the blocking consent prompt through the REAL seam, then
// the shutdown token is cancelled (requestCryptoShutdown analogue) and the worker
// is abandoned while still blocked (the prompter ignores CancelCurrent). Dropping
// the composition's prompter + prompt-gate shares leaves only the op's co-owned
// shares (attached exactly as CardObject::attachLifetimeGuards does); the delayed
// unblock then runs the SlotGuard release() + the prompter read against live
// memory (TSan-clean), and the op skips its completion because the shutdown token
// fired. A missing keepAlive(serializer) (the pre-fix bug) traps in release().
TEST(AgentQuiesce, AbandonedTypedOpKeepsGateAndPrompterAliveThroughCoOwnedShares)
{
    Latch latch;
    std::atomic<int> entered{0};
    std::atomic<int> observedMarker{0};
    auto slots = std::make_shared<TypedSlots>();

    auto serializer = std::make_shared<PromptSerializer>();
    std::shared_ptr<PrompterClientBase> prompter =
        std::make_shared<ZombiePrompter>(latch, entered, observedMarker, kMarker);

    LibreSCRS::CancelSource shutdown; // the agent-wide shutdown-cancel source

    {
        OperationManager mgr; // bus-less worker path

        auto op = std::make_unique<PromptingOp>(std::make_unique<RecordingChannel>(slots),
                                                std::make_shared<OperationState>(), *serializer, *prompter);
        // Co-own the two members + bind the shutdown token, exactly as
        // CardObject::attachLifetimeGuards does for every production typed op.
        op->keepAlive(serializer);
        op->keepAlive(prompter);
        op->bindShutdownToken(shutdown.token());
        mgr.enqueueForTest(kTypedReader, std::move(op));

        const auto enteredDeadline = std::chrono::steady_clock::now() + 2s;
        while (entered.load(std::memory_order_acquire) == 0 && std::chrono::steady_clock::now() < enteredDeadline) {
            std::this_thread::sleep_for(5ms);
        }
        ASSERT_EQ(entered.load(std::memory_order_acquire), 1) << "typed op never entered the blocking prompt";

        // The op co-owns both shares, so the composition is not the sole owner.
        EXPECT_GE(serializer.use_count(), 2);
        EXPECT_GE(prompter.use_count(), 2);

        // Model quiesce: cancel the shutdown token (requestCryptoShutdown), which
        // trips the op's token via the bound callback.
        shutdown.requestCancel();

        // Abandon the still-blocked worker (the prompter ignores CancelCurrent).
        const auto t0 = std::chrono::steady_clock::now();
        mgr.removeReader(kTypedReader);
        EXPECT_LT(std::chrono::steady_clock::now() - t0, 1s) << "removeReader blocked on the wedged typed worker";

        // Drop the composition's shares: only the abandoned op's co-owned shares
        // keep the serializer + prompter alive now.
        serializer.reset();
        prompter.reset();

        // Delayed unblock (the ~25 s sd-bus timeout / late CancelCurrent).
        latch.release();

        const auto readDeadline = std::chrono::steady_clock::now() + 2s;
        while (observedMarker.load(std::memory_order_acquire) == 0 && std::chrono::steady_clock::now() < readDeadline) {
            std::this_thread::sleep_for(5ms);
        }
        EXPECT_EQ(observedMarker.load(std::memory_order_acquire), kMarker)
            << "the abandoned typed op never completed its live-memory read through the real seam";
        // Shutdown-cancel skip: the op must NOT have driven its wire completion.
        EXPECT_EQ(slots->finishCount.load(std::memory_order_acquire), 0)
            << "the typed op drove its completion on the shutdown-cancel path";

        std::this_thread::sleep_for(100ms);
    }
}

// ---- (4) typed-path abandoned-worker credential-cache drain ---------------

namespace {

// A typed op that models the READ path's past-the-gate credential-cache touch: it
// blocks on a latch (the nested CAN/MRZ prompt), then writes putCan to the cache
// the instant it "returns" — exactly what a ReadIdentity/ReadCertificates flow does
// inside CredentialCache::requestCredential. The op holds the cache by reference
// (the flow's `&` Deps) but the CardObject co-owns the SAME cache via a keepAlive
// share, so an abandoned read op keeps the cache alive for this write.
class CredentialTouchingOp final : public OperationBase
{
public:
    CredentialTouchingOp(std::unique_ptr<OperationChannel> ch, std::shared_ptr<OperationState> st,
                         CredentialCache& cache, Latch& latch, std::atomic<int>& entered, std::atomic<int>& observed)
        : OperationBase(std::move(ch), std::move(st), []() noexcept {}), m_cache(cache), m_latch(latch),
          m_entered(entered), m_observed(observed)
    {}

protected:
    void doWork() override
    {
        m_entered.fetch_add(1, std::memory_order_acq_rel);
        m_latch.waitForRelease();
        // Past-the-gate write of the (co-owned) credential cache — a UAF if the
        // cache were freed with the composition and NOT co-owned by this op.
        m_cache.putCan("card-A", LibreSCRS::Secure::String{"123456"});
        if (m_cache.hasCan("card-A")) {
            m_observed.store(kMarker, std::memory_order_release);
        }
        if (shutdownRequested()) {
            return; // teardown: skip the wire completion (as the real typed ops do)
        }
        finish(OperationStatus::Cancelled, ErrorCode::None, "op.cancelled", "cancelled");
    }

private:
    CredentialCache& m_cache;
    Latch& m_latch;
    std::atomic<int>& m_entered;
    std::atomic<int>& m_observed;
};

} // namespace

// A typed read op is driven to its nested CAN/MRZ credential prompt, then abandoned
// while blocked. Dropping the composition's credential-cache share leaves only the
// op's co-owned share (attached exactly as CardObject::attachLifetimeGuards does);
// the delayed unblock then runs putCan against live memory (TSan-clean). Removing
// the keepAlive(credentials) (the pre-fix bug) traps in putCan.
TEST(AgentQuiesce, AbandonedTypedReadOpKeepsCredentialCacheAliveThroughCoOwnedShare)
{
    Latch latch;
    std::atomic<int> entered{0};
    std::atomic<int> observedMarker{0};
    auto slots = std::make_shared<TypedSlots>();

    auto credentials = std::make_shared<CredentialCache>();
    LibreSCRS::CancelSource shutdown;

    {
        OperationManager mgr; // bus-less worker path

        auto op = std::make_unique<CredentialTouchingOp>(std::make_unique<RecordingChannel>(slots),
                                                         std::make_shared<OperationState>(), *credentials, latch,
                                                         entered, observedMarker);
        // Co-own the credential-cache share + bind the shutdown token, exactly as
        // CardObject::attachLifetimeGuards does for every production typed op.
        op->keepAlive(credentials);
        op->bindShutdownToken(shutdown.token());
        mgr.enqueueForTest(kTypedReader, std::move(op));

        const auto enteredDeadline = std::chrono::steady_clock::now() + 2s;
        while (entered.load(std::memory_order_acquire) == 0 && std::chrono::steady_clock::now() < enteredDeadline) {
            std::this_thread::sleep_for(5ms);
        }
        ASSERT_EQ(entered.load(std::memory_order_acquire), 1) << "typed read op never entered the credential prompt";

        // The op co-owns the cache, so the composition is not the sole owner.
        EXPECT_GE(credentials.use_count(), 2);

        shutdown.requestCancel();

        const auto t0 = std::chrono::steady_clock::now();
        mgr.removeReader(kTypedReader);
        EXPECT_LT(std::chrono::steady_clock::now() - t0, 1s) << "removeReader blocked on the wedged typed worker";

        // Drop the composition's cache share: only the abandoned op's co-owned share
        // keeps the credential cache alive now.
        credentials.reset();

        latch.release();

        const auto readDeadline = std::chrono::steady_clock::now() + 2s;
        while (observedMarker.load(std::memory_order_acquire) == 0 && std::chrono::steady_clock::now() < readDeadline) {
            std::this_thread::sleep_for(5ms);
        }
        EXPECT_EQ(observedMarker.load(std::memory_order_acquire), kMarker)
            << "the abandoned typed read op never completed its live-memory write to the credential cache";
        EXPECT_EQ(slots->finishCount.load(std::memory_order_acquire), 0)
            << "the typed op drove its completion on the shutdown-cancel path";

        std::this_thread::sleep_for(100ms);
    }
}
