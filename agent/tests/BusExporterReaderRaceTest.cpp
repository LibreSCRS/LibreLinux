// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Concurrency guard for the transport presence snapshot.
//
// BusExporter::m_presence (readerPath -> {name, hasCard, cardPath}) is mutated on
// the MONITOR thread (publishReader/updateProperties/withdraw, driven here through
// PresenceModel) while the LOOP/BUS thread reads it through resolveReaderCard (the
// PKCS#11 host's reader->card seam). Without synchronisation that is a data race,
// and a reader dropped mid-resolve is a use-after-free. These tests hammer both
// threads so a thread-sanitizer build flags any regression; under a plain/ASan
// build they are a use-after-free smoke that must run clean.
//
// The slim transport creates NO exported object (the AgentFrontend owns those), so
// the only shared state under test is the presence snapshot map itself.

#include "BusExporter.h"
#include <LibreSCRS/Agent/presence/CapabilityResolver.h>
#include <LibreSCRS/Agent/presence/ObjectRegistry.h>
#include <LibreSCRS/Agent/presence/PresenceModel.h>

#include <sdbus-c++/sdbus-c++.h>
#include <gtest/gtest.h>
#include <atomic>
#include <cstdint>
#include <optional>
#include <string>
#include <thread>
#include <vector>

using namespace LibreSCRS::Agent;
using namespace std::chrono_literals;

namespace LibreSCRS::Agent {
// White-box access to the private client-disconnect handler vector the transport
// fires on the bus thread (the resolveReaderCard seam is public).
struct BusExporterTestPeer
{
    static std::optional<std::string> resolveCardKey(const BusExporter& exporter, const std::string& readerPath)
    {
        auto rc = exporter.resolveReaderCard(readerPath);
        return rc ? std::optional<std::string>{rc->cardKey} : std::nullopt;
    }
    // Runs the exact loop the ctor's NameOwnerChanged callback runs: fire every
    // registered client-disconnect handler in registration order (S8 regression).
    static void fireClientDisconnect(BusExporter& exporter, const CallerToken& caller)
    {
        for (const auto& handler : exporter.m_disconnectHandlers) {
            if (handler) {
                handler(caller);
            }
        }
    }
    static std::size_t handlerCount(const BusExporter& exporter)
    {
        return exporter.m_disconnectHandlers.size();
    }
};
} // namespace LibreSCRS::Agent

namespace {

class NopResolver : public CapabilityResolver
{};

constexpr const char* kReaderName = "RaceReader";
// The single global opaque counter mints the first reader as id 1 -> reader/1.
constexpr const char* kReaderPath = "/org/librescrs/Agent/reader/1";
constexpr int kIterations = 3000;

} // namespace

// resolveReaderCard (loop thread) vs updateProperties-driven presence writes
// (monitor thread): the snapshot {hasCard, cardPath} pair must never tear.
TEST(BusExporterReaderRace, ResolveVsCardChurnIsFieldRaceFree)
{
    auto bus = sdbus::createSessionBusConnection();
    ASSERT_NE(bus, nullptr) << "run under dbus-run-session";

    ObjectRegistry registry;
    NopResolver resolver;
    PresenceModel model(registry, resolver);
    // The slim transport keeps only the presence snapshot resolveReaderCard reads;
    // no materializer is wired, so publishReader/updateProperties only touch it.
    BusExporter exporter(*bus, registry);

    model.onReaderAdded(kReaderName); // stable reader/1 for the whole test
    const std::vector<std::uint8_t> atr{0x3b, 0x9f, 0x96, 0x80};

    std::atomic<bool> go{false};
    std::atomic<bool> done{false};

    std::thread monitor([&] {
        while (!go.load(std::memory_order_acquire)) {
        }
        for (int i = 0; i < kIterations; ++i) {
            model.onCardInserted(kReaderName, atr); // update: HasCard=true, Card=card/n
            model.onCardRemoved(kReaderName);       // update: HasCard=false
        }
        done.store(true, std::memory_order_release);
    });

    std::atomic<int> engaged{0};
    std::thread loop([&] {
        while (!go.load(std::memory_order_acquire)) {
        }
        while (!done.load(std::memory_order_acquire)) {
            if (auto ck = BusExporterTestPeer::resolveCardKey(exporter, kReaderPath)) {
                EXPECT_FALSE(ck->empty()); // an engaged snapshot must be self-consistent
                engaged.fetch_add(1, std::memory_order_relaxed);
            }
        }
    });

    go.store(true, std::memory_order_release);
    monitor.join();
    loop.join();
    SUCCEED() << engaged.load() << " engaged resolves under card churn";
}

// resolveReaderCard (loop thread) vs reader add/remove (monitor thread): the
// snapshot map must never be walked while it is being mutated, and a dropped
// reader must never be dereferenced.
TEST(BusExporterReaderRace, ResolveVsReaderChurnIsMapRaceFree)
{
    auto bus = sdbus::createSessionBusConnection();
    ASSERT_NE(bus, nullptr) << "run under dbus-run-session";

    ObjectRegistry registry;
    NopResolver resolver;
    PresenceModel model(registry, resolver);
    BusExporter exporter(*bus, registry);

    const std::vector<std::uint8_t> atr{0x3b, 0x9f, 0x96, 0x80};
    std::atomic<bool> go{false};
    std::atomic<bool> done{false};

    std::thread monitor([&] {
        while (!go.load(std::memory_order_acquire)) {
        }
        for (int i = 0; i < kIterations; ++i) {
            model.onReaderAdded(kReaderName);       // seed a presence entry
            model.onCardInserted(kReaderName, atr); // make the reader hold a card
            model.onReaderRemoved(kReaderName);     // drop card + erase the entry
        }
        done.store(true, std::memory_order_release);
    });

    std::thread loop([&] {
        while (!go.load(std::memory_order_acquire)) {
        }
        while (!done.load(std::memory_order_acquire)) {
            // find() races insert/erase on the shared map regardless of whether
            // the path matches the live reader.
            (void)BusExporterTestPeer::resolveCardKey(exporter, kReaderPath);
        }
    });

    go.store(true, std::memory_order_release);
    monitor.join();
    loop.join();
    SUCCEED();
}

// S8 regression: clearClientDisconnectHandlers() severs the NameOwnerChanged proxy
// AND clears the handler vector, so a stray unique-name drop after it invokes ZERO
// handlers — nulling the raw dependencies (OperationManager + PKCS#11 broker) the
// handlers reach, so a mid-destruction deref is impossible. AgentService calls it
// as the first statement of its dtor while those dependencies are still alive.
TEST(BusExporterDisconnectTeardown, ClearSeversHandlersSoStrayFireIsNoOp)
{
    auto bus = sdbus::createSessionBusConnection();
    ASSERT_NE(bus, nullptr) << "run under dbus-run-session";

    ObjectRegistry registry;
    BusExporter exporter(*bus, registry);

    int fired = 0;
    exporter.onClientDisconnect([&fired](CallerToken) { ++fired; });
    exporter.onClientDisconnect([&fired](CallerToken) { ++fired; });
    ASSERT_EQ(BusExporterTestPeer::handlerCount(exporter), 2u);

    // Both registered handlers fire, in registration order, before teardown.
    BusExporterTestPeer::fireClientDisconnect(exporter, CallerToken{":1.7"});
    EXPECT_EQ(fired, 2);

    exporter.clearClientDisconnectHandlers();
    EXPECT_EQ(BusExporterTestPeer::handlerCount(exporter), 0u) << "clear nulls the raw dependencies";

    // A stray unique-name drop after the sever must invoke no handler (no deref of a
    // mid-destruction OperationManager / PKCS#11 broker).
    BusExporterTestPeer::fireClientDisconnect(exporter, CallerToken{":1.7"});
    EXPECT_EQ(fired, 2) << "no handler fires after clearClientDisconnectHandlers()";
}
