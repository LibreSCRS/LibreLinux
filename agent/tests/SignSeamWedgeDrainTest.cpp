// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Teeth test for the qualified-timestamped-sign path's LM-seam keep-alive — the
// last abandoned-worker gap. A Card1.Sign op carries its signing seam (the
// production LmSigner) by BARE reference in its Deps, backed by a CardObject-owned
// share (CardOperationDeps::ownedSigner). The seam holds the signing-engine
// provider by reference and, on the abandoned-worker path, unblocks past the flow
// gate and dereferences its OWN vtable + that engine (snapshot() at entry,
// recordLastTsaUrlUsed() at success-exit). If the seam is freed with the CardObject
// while the worker is parked, that unblock is a use-after-free.
//
// The fix makes the owned seams shared_ptr and keepAlives the signer share into the
// typed op (CardObject::attachLifetimeGuards), exactly alongside the crypto context
// (which co-owns the engine + config). This test wires a fake signer seam through
// the SAME bare-Signer& Deps + keepAlive(share) shape, wedges it, abandons the
// worker, drops the composition's seam + context shares, and releases: only the
// op's co-owned shares keep the seam + engine + config alive, so the delayed unblock
// runs the whole LmSigner touch sequence against LIVE memory.
//
// PROVE TEETH (manual): remove `op->keepAlive(seam)` below (the seam co-ownership
// the production CardObject::attachLifetimeGuards adds) and re-run under
// ThreadSanitizer — the seam is then freed at the composition drop and the wedged
// worker's sign() call (a virtual dispatch through the freed seam's vtable, then its
// m_engine deref) traps on freed memory. Removing the context keepAlive instead
// frees the engine + config and traps at recordLastTsaUrlUsed. Meaningful under TSan.

#include <LibreSCRS/Agent/CryptoWorkerContext.h>
#include <LibreSCRS/Agent/OperationState.h>
#include <LibreSCRS/Agent/backend/OperationChannel.h>
#include <LibreSCRS/Agent/config/ConfigStore.h>
#include <LibreSCRS/Agent/operations/OperationBase.h>
#include <LibreSCRS/Agent/operations/OperationManager.h>
#include <LibreSCRS/Agent/operations/Seams.h>
#include <LibreSCRS/Agent/operations/SigningEngineProvider.h>
#include <LibreSCRS/Auth/CredentialProvider.h>
#include <LibreSCRS/CancelToken.h>
#include <LibreSCRS/SmartCard/CardSession.h>

#include <gtest/gtest.h>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

using namespace LibreSCRS::Agent;
using namespace LibreSCRS::Agent::Operations;
using namespace std::chrono_literals;
namespace fs = std::filesystem;

namespace {

constexpr int kMarker = 0x5157;
const ObjectId kReader{19};
constexpr const char* kTsaUrl = "https://tsa.example.test/tsr";

fs::path uniqueDir(const char* tag)
{
    return fs::temp_directory_path() / (std::string{"ll-signseamwedge-"} + tag);
}

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

// A fake signing seam wired EXACTLY like the production LmSigner: it holds the
// signing-engine provider by BARE reference (SigningEngineProvider& m_engine) and
// its sign() reads its own marker (a deref of the seam `this`/vtable), wedges on a
// latch (the uncancellable on-card sign), then on unblock runs snapshot() at entry
// and recordLastTsaUrlUsed() at success-exit — the config write past the flow gate.
// A freed seam would trap on the virtual dispatch + the m_engine deref; a freed
// engine/config would trap at snapshot()/recordLastTsaUrlUsed().
class WedgingSignerSeam final : public Signer
{
public:
    WedgingSignerSeam(SigningEngineProvider& engine, const Config::ConfigStore& config, Latch& latch,
                      std::atomic<int>& entered, std::atomic<int>& observed)
        : m_engine(engine), m_config(config), m_latch(latch), m_entered(entered), m_observed(observed)
    {}

    SignOutcome sign(const std::shared_ptr<LibreSCRS::SmartCard::CardSession>&, const SignParams&, const CandidateList&,
                     LibreSCRS::Auth::CredentialProvider, LibreSCRS::CancelToken) override
    {
        m_entered.fetch_add(1, std::memory_order_acq_rel);
        const int mine = m_marker; // deref of the seam `this`
        m_latch.waitForRelease();
        const auto snap = m_engine.snapshot();           // deref of the co-owned provider
        m_engine.recordLastTsaUrlUsed(snap.boundTsaUrl); // deref provider -> co-owned config
        if (!snap.boundTsaUrl.empty() && m_config.lastTsaUrl() == snap.boundTsaUrl) {
            m_observed.store(mine, std::memory_order_release);
        }
        return SignOutcome{SignOutcome::Status::Cancelled, {}, {}, {}, false, false, "cancelled"};
    }

private:
    SigningEngineProvider& m_engine;
    const Config::ConfigStore& m_config;
    Latch& m_latch;
    std::atomic<int>& m_entered;
    std::atomic<int>& m_observed;
    int m_marker{kMarker};
};

// A typed op that drives its signing seam by BARE reference — the exact shape of
// SignOperation::Deps.signer (a Signer&, bound at build time from the owned share's
// .get()). doWork calls m_signer.sign(...) and skips its wire completion on the
// shutdown-cancel path, as the production SignOperation does after SignFlow returns.
class SignSeamDrivingOp final : public OperationBase
{
public:
    SignSeamDrivingOp(std::unique_ptr<OperationChannel> ch, std::shared_ptr<OperationState> st, Signer& signer)
        : OperationBase(std::move(ch), std::move(st), []() noexcept {}), m_signer(signer)
    {}

protected:
    void doWork() override
    {
        static_cast<void>(m_signer.sign(std::shared_ptr<LibreSCRS::SmartCard::CardSession>{}, SignParams{},
                                        CandidateList{}, LibreSCRS::Auth::CredentialProvider{}, token()));
        if (shutdownRequested()) {
            return; // teardown: skip the wire completion (as SignOperation does)
        }
        finish(OperationStatus::Cancelled, ErrorCode::None, "op.cancelled", "cancelled");
    }

private:
    Signer& m_signer;
};

} // namespace

// A typed sign op driven through the bare-Signer& Deps is wedged in the seam's
// sign(), abandoned, and the composition's seam + engine/config shares are dropped
// while it is parked. Only the op's co-owned shares (the signer share + the crypto
// context that holds the engine + config) keep them alive — attached exactly as
// CardObject::attachLifetimeGuards does; the delayed unblock then runs the whole
// LmSigner touch sequence (vtable dispatch, snapshot(), recordLastTsaUrlUsed) on
// LIVE memory (TSan-clean) and the op skips its completion because the shutdown
// token fired.
TEST(SignSeamWedgeDrain, AbandonedSignOpKeepsItsSeamEngineAndConfigAliveThroughCoOwnedShares)
{
    const auto dir = uniqueDir("seam");
    fs::remove_all(dir);

    Latch latch;
    std::atomic<int> entered{0};
    std::atomic<int> observedMarker{0};
    auto slots = std::make_shared<TypedSlots>();

    LibreSCRS::CancelSource shutdown; // the agent-wide shutdown-cancel source

    // Composition-owned config + provider (a configured TSA so the bound URL is
    // non-empty and recordLastTsaUrlUsed writes), gathered into the single crypto
    // context — the exact shares the AgentCore ctor populates.
    auto config = std::make_shared<Config::ConfigStore>(dir / "agent.conf", dir / "cache");
    ASSERT_TRUE(config->setTsaUrls(std::vector<std::string>{kTsaUrl}).ok);
    auto engine = std::make_shared<SigningEngineProvider>(*config);
    ASSERT_EQ(engine->snapshot().boundTsaUrl, kTsaUrl);

    auto ctx = std::make_shared<CryptoWorkerContext>(CryptoWorkerContext{
        .shutdown = shutdown.token(),
        .config = config,
        .signingEngine = engine,
    });
    // The CardObject-owned signing seam (CardOperationDeps::ownedSigner): a share the
    // typed op co-owns via keepAlive so an abandoned worker keeps the seam OBJECT
    // alive for its post-unblock vtable dispatch + engine deref.
    std::shared_ptr<Signer> seam =
        std::make_shared<WedgingSignerSeam>(*engine, *config, latch, entered, observedMarker);

    {
        OperationManager mgr; // bus-less worker path

        auto op = std::make_unique<SignSeamDrivingOp>(std::make_unique<RecordingChannel>(slots),
                                                      std::make_shared<OperationState>(), *seam);
        // Co-own the seam share + the crypto context (engine + config) + bind the
        // shutdown token, EXACTLY as CardObject::attachLifetimeGuards does for the
        // production sign op. Removing keepAlive(seam) is the RED-proof.
        op->keepAlive(seam);
        op->keepAlive(ctx);
        op->bindShutdownToken(shutdown.token());
        mgr.enqueueForTest(kReader, std::move(op));

        const auto enteredDeadline = std::chrono::steady_clock::now() + 2s;
        while (entered.load(std::memory_order_acquire) == 0 && std::chrono::steady_clock::now() < enteredDeadline) {
            std::this_thread::sleep_for(5ms);
        }
        ASSERT_EQ(entered.load(std::memory_order_acquire), 1) << "sign op never entered the seam wedge";

        // The op co-owns the seam + context, so the composition is not the sole owner.
        EXPECT_GE(seam.use_count(), 2);
        EXPECT_GE(ctx.use_count(), 2);

        // Model quiesce, then abandon the still-wedged worker.
        shutdown.requestCancel();
        const auto t0 = std::chrono::steady_clock::now();
        mgr.removeReader(kReader);
        EXPECT_LT(std::chrono::steady_clock::now() - t0, 1s) << "removeReader blocked on the wedged sign worker";

        // Drop the composition's shares: only the abandoned op's co-owned shares keep
        // the seam + engine + config alive now.
        seam.reset();
        ctx.reset();
        engine.reset();
        config.reset();

        // Delayed unblock (the on-card sign finally returns / late CancelCurrent).
        latch.release();

        const auto readDeadline = std::chrono::steady_clock::now() + 2s;
        while (observedMarker.load(std::memory_order_acquire) == 0 && std::chrono::steady_clock::now() < readDeadline) {
            std::this_thread::sleep_for(5ms);
        }
        EXPECT_EQ(observedMarker.load(std::memory_order_acquire), kMarker)
            << "the abandoned sign op never completed the seam sign() + engine/config touch on live memory";
        EXPECT_EQ(slots->finishCount.load(std::memory_order_acquire), 0)
            << "the sign op drove its completion on the shutdown-cancel path";

        std::this_thread::sleep_for(100ms); // let the zombie thread fully unwind
    }

    fs::remove_all(dir);
}
