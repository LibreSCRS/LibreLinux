// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <LibreSCRS/Agent/operations/OperationManager.h>

#include <sdbus-c++/IConnection.h>
#include <sdbus-c++/Types.h> // sdbus::ServiceName (was transitively via OperationManager.h)
#include <gtest/gtest.h>
#include <atomic>
#include <chrono>
#include <memory>
#include <string_view>
#include <thread>

using namespace LibreSCRS::Agent;
using namespace LibreSCRS::Agent::Operations;
using namespace std::chrono_literals;

namespace {

class CountingChannel final : public OperationChannel
{
public:
    void emitPropertiesChanged() noexcept override {}
    void emitFinished(OperationStatus s, ErrorCode, std::string_view, std::string_view) noexcept override
    {
        finishStatus.store(static_cast<std::uint32_t>(s));
    }
    bool emitResult(const ResultPayload&) noexcept override
    {
        return true;
    }
    std::atomic<std::uint32_t> finishStatus{99};
};

class CancellableOp final : public OperationBase
{
public:
    using OperationBase::OperationBase;

protected:
    void doWork() override
    {
        for (int i = 0; i < 100; ++i) {
            if (isCancelled() || token().isCancelled()) {
                finish(OperationStatus::Cancelled, ErrorCode::None, "op.cancelled", "cancelled");
                return;
            }
            std::this_thread::sleep_for(20ms);
        }
        finish(OperationStatus::Ok, ErrorCode::None, "op.ok", "ok");
    }
};

} // namespace

TEST(OperationManagerNameOwnerChanged, ClientDisconnectCancelsRecordedOps)
{
    auto bus = sdbus::createSessionBusConnection();
    ASSERT_NE(bus, nullptr);
    bus->requestName(sdbus::ServiceName{"org.librescrs.Agent.Test.NOC"});
    bus->enterEventLoopAsync();

    OperationManager mgr(nullptr); // production (cleanup-grace) mode; no resolver
    // The NameOwnerChanged proxy now lives in the AgentTransport (BusExporter),
    // which forwards each unique-name drop here via dispatchClientDisconnect. This
    // test drives that forwarding target directly (the same call the transport
    // handler makes), so no proxy is wired here.

    auto adaptor = std::make_unique<CountingChannel>();
    auto* raw = adaptor.get();
    auto state = std::make_shared<OperationState>();
    auto op = std::make_unique<CancellableOp>(std::move(adaptor), state);
    auto* opPtr = op.get();
    mgr.enqueueForTest(ObjectId{1}, std::move(op));
    mgr.recordSenderForTest(OperationId{1}, CallerToken{":1.999"}, opPtr);

    std::this_thread::sleep_for(50ms);
    // Simulate the bus firing NameOwnerChanged: invoke the same dispatch
    // entry-point the production listener forwards to.
    mgr.dispatchClientDisconnect(CallerToken{":1.999"});

    const auto deadline = std::chrono::steady_clock::now() + 2s;
    while (raw->finishStatus.load() == 99 && std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(20ms);
    }
    EXPECT_EQ(raw->finishStatus.load(), 1u) << "expected OperationStatus::Cancelled";

    bus->leaveEventLoop();
}
