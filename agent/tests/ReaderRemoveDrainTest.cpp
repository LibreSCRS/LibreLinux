// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// End-to-end drain contract: when the registry erases a reader (the
// PresenceModel side-effect of reader-removal), the BusExporter must
// call OperationManager::removeReader BEFORE dropping its own
// ReaderObject. That call stops the per-reader worker AND drains queued
// ops with errorCode=CardRemoved, so a queued op never strands a worker
// thread on a torn-down reader.

#include <LibreSCRS/Agent/backend/Authorizer.h>
#include "AgentFrontend.h"
#include <LibreSCRS/Agent/CryptoWorkerContext.h>
#include "BusExporter.h"
#include <LibreSCRS/Agent/presence/CapabilityResolver.h>
#include <LibreSCRS/Agent/cache/CardReadCache.h>
#include <LibreSCRS/Agent/cache/CredentialCache.h>
#include <LibreSCRS/Agent/presence/ObjectRegistry.h>
#include <LibreSCRS/Agent/presence/PresenceModel.h>
#include <LibreSCRS/Agent/config/ConfigStore.h>
#include <LibreSCRS/Agent/operations/OperationBase.h>
#include <LibreSCRS/Agent/operations/OperationManager.h>
#include <LibreSCRS/Agent/operations/PromptSerializer.h>
#include <LibreSCRS/Agent/backend/PrompterClientBase.h>
#include <LibreSCRS/Agent/operations/RateLimiter.h>
#include <LibreSCRS/Agent/operations/SigningEngineProvider.h>
#include <LibreSCRS/Agent/pkcs11/LeaseManager.h>

#include <sdbus-c++/sdbus-c++.h>
#include <gtest/gtest.h>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <thread>

using namespace LibreSCRS::Agent;
using namespace LibreSCRS::Agent::Operations;
using namespace std::chrono_literals;

namespace {

// Drain test: never resolves a plugin. The base ATR-only seam (no match) opens
// no CardSession.
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

// Per-op observation slots. Owned by the test fixture (not by the
// adaptor) so the test can read the captured status AFTER the op has
// been destroyed (the drain path destroys both the op and its adaptor
// inside removeReader).
struct ObservationSlots
{
    std::atomic<std::uint32_t> status{99};
    std::atomic<std::uint32_t> errorCode{99};
};

class CapturingChannel final : public OperationChannel
{
public:
    explicit CapturingChannel(ObservationSlots& slots) : m_slots(slots) {}
    void emitPropertiesChanged() noexcept override {}
    void emitFinished(OperationStatus s, ErrorCode e, std::string_view, std::string_view) noexcept override
    {
        m_slots.status.store(static_cast<std::uint32_t>(s), std::memory_order_release);
        m_slots.errorCode.store(static_cast<std::uint32_t>(e), std::memory_order_release);
    }
    bool emitResult(const ResultPayload&) noexcept override
    {
        return true;
    }

private:
    ObservationSlots& m_slots;
};

// In-flight op: polls the cancel token in a tight loop so the worker
// honours the stop request promptly. The first op in the queue takes
// this role so the second op stays queued when removeReader hits.
class PollingOp final : public OperationBase
{
public:
    PollingOp(std::unique_ptr<OperationChannel> a, std::shared_ptr<OperationState> s)
        : OperationBase(std::move(a), std::move(s))
    {}

protected:
    void doWork() override
    {
        // Up to 5 s total at 10 ms cadence. The test deadline cuts this
        // short via cancel.
        for (int i = 0; i < 500; ++i) {
            if (isCancelled() || token().isCancelled()) {
                finish(OperationStatus::Cancelled, ErrorCode::None, "op.cancelled", "cancelled");
                return;
            }
            std::this_thread::sleep_for(10ms);
        }
        finish(OperationStatus::Ok, ErrorCode::None, "op.ok", "ok");
    }
};

// Queued op: never gets to run. The drain path in workerLoop should call
// finishCardRemoved() on it once the worker observes the stop request.
class StagedOp final : public OperationBase
{
public:
    StagedOp(std::unique_ptr<OperationChannel> a, std::shared_ptr<OperationState> s)
        : OperationBase(std::move(a), std::move(s))
    {}

protected:
    void doWork() override
    {
        // Should never execute; the test triggers reader removal while
        // this op sits behind the polling op in the per-reader queue.
        ADD_FAILURE() << "queued op should be drained, not executed";
        finish(OperationStatus::Ok, ErrorCode::None, "op.ok", "ok");
    }
};

constexpr const char* kReaderName = "R0";
// The single global opaque counter mints the first reader as id 1; this must
// match the ObjectId BusExporter::withdraw passes to removeReader so the ops
// enqueued below are actually drained on reader removal.
const ObjectId kReaderId{1};

} // namespace

TEST(ReaderRemoveDrain, ExporterRemovalDrainsOperationManagerWorker)
{
    std::shared_ptr<sdbus::IConnection> bus = sdbus::createSessionBusConnection();
    ASSERT_NE(bus, nullptr) << "run under dbus-run-session";
    bus->requestName(sdbus::ServiceName{"org.librescrs.Agent.Test.ReaderDrain"});
    bus->enterEventLoopAsync();

    ObjectRegistry registry;
    NopResolver resolver;
    PresenceModel model(registry, resolver);
    OperationManager mgr; // bus-less: workers + enqueueForTest + removeReader only
    auto prompter = std::make_shared<NopPrompter>();
    auto serializer = std::make_shared<PromptSerializer>();
    auto creds = std::make_shared<CredentialCache>();
    CardReadCache readCache;
    Config::ConfigStore cfg(std::filesystem::temp_directory_path() / "librescrs-test-readerdrain" / "agent.conf",
                            std::filesystem::temp_directory_path() / "librescrs-test-readerdrain" / "cache");
    Operations::SigningEngineProvider signingEngine(cfg);
    AllowAllAuthorizer authz;
    Operations::RateLimiter rateLimiter;
    BusExporter exporter(*bus, registry);
    // The frontend owns the exported objects + the reader-removal drain (its
    // withdraw path calls OperationManager::removeReader before dropping the
    // ReaderObject). This suite drives only the presence/drain path, so the
    // Pkcs11_1 broker is null.
    auto cryptoCtx = std::make_shared<CryptoWorkerContext>(
        CryptoWorkerContext{.prompter = prompter, .serializer = serializer, .credentials = creds});
    AgentFrontend frontend(exporter, bus, mgr, cryptoCtx, readCache, signingEngine, authz, rateLimiter, cfg, nullptr,
                           "test");

    // Publish reader -> the frontend materializes a ReaderObject on the bus.
    model.onReaderAdded(kReaderName);

    // Queue two ops at the path the BusExporter will pass through to
    // OperationManager::removeReader. The polling op runs first; the
    // staged op stays in the queue. Observation slots live in the test
    // frame so the captured status survives the op's destruction during
    // the drain path.
    ObservationSlots pollingSlots;
    ObservationSlots stagedSlots;

    auto pollingState = std::make_shared<OperationState>();
    auto stagedState = std::make_shared<OperationState>();
    mgr.enqueueForTest(kReaderId,
                       std::make_unique<PollingOp>(std::make_unique<CapturingChannel>(pollingSlots), pollingState));
    mgr.enqueueForTest(kReaderId,
                       std::make_unique<StagedOp>(std::make_unique<CapturingChannel>(stagedSlots), stagedState));

    // Give the worker a moment to pick up the polling op.
    std::this_thread::sleep_for(50ms);

    // Trigger removal through PresenceModel -> registry -> BusExporter
    // -> OperationManager::removeReader. This is the chain the fix wires.
    model.onReaderRemoved(kReaderName);

    // Wait for both ops to terminate. The staged op finishes with
    // CardRemoved via the drain path; the polling op finishes with
    // Cancelled status because doWork honoured the cancel before the
    // drain ran finishCardRemoved on it.
    const auto deadline = std::chrono::steady_clock::now() + 3s;
    while ((stagedSlots.status.load(std::memory_order_acquire) == 99u ||
            pollingSlots.status.load(std::memory_order_acquire) == 99u) &&
           std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(20ms);
    }

    EXPECT_NE(stagedSlots.status.load(std::memory_order_acquire), 99u)
        << "staged op was never finished -- drain did not run";
    EXPECT_EQ(stagedSlots.errorCode.load(std::memory_order_acquire), static_cast<std::uint32_t>(ErrorCode::CardRemoved))
        << "queued op must report CardRemoved on reader removal";

    EXPECT_NE(pollingSlots.status.load(std::memory_order_acquire), 99u)
        << "in-flight op never finished after stop_request";

    bus->leaveEventLoop();
}
