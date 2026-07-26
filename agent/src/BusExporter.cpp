// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#include "BusExporter.h"
#include "AgentObjectPath.h" // agentObjectPath (ObjectId <-> wire path)
#include "EventLoopPoster.h"
#include <LibreSCRS/Agent/presence/ObjectRegistry.h>
#include <sdbus-c++/IProxy.h> // createProxy (NameOwnerChanged client-disconnect watch)
#include <chrono>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <utility>

namespace LibreSCRS::Agent {

BusExporter::BusExporter(sdbus::IConnection& connection) : m_connection(connection)
{
    // Process-global client-liveness watch (was OperationManager's). A unique-name
    // drop (':' prefix, empty new-owner) fires every registered onClientDisconnect
    // handler in registration order. Registration succeeds before the event loop
    // runs (matching the old export-time wiring); handlers are attached right after
    // construction, so no drop is observed with an empty handler set in production.
    m_nocProxy = sdbus::createProxy(m_connection, sdbus::ServiceName{"org.freedesktop.DBus"},
                                    sdbus::ObjectPath{"/org/freedesktop/DBus"});
    m_nocProxy->uponSignal(sdbus::SignalName{"NameOwnerChanged"})
        .onInterface(sdbus::InterfaceName{"org.freedesktop.DBus"})
        .call([this](const std::string& name, const std::string& /*oldOwner*/, const std::string& newOwner) {
            if (name.empty() || name[0] != ':' || !newOwner.empty()) {
                return;
            }
            for (const auto& handler : m_disconnectHandlers) {
                handler(CallerToken{name});
            }
        });
}

BusExporter::BusExporter(sdbus::IConnection& connection, ObjectRegistry& registry) : BusExporter(connection)
{
    // Test/convenience path: wire the presence source now so a test can drive
    // PresenceModel and see the deltas arrive. No back-pointer is kept — the
    // test-owned registry outlives this exporter and is not mutated after it, so its
    // dangling observers are simply freed un-fired at registry teardown.
    observePresenceFrom(registry);
}

void BusExporter::observePresenceFrom(ObjectRegistry& registry)
{
    registry.setObservers([this](const ReaderState& reader) { publishReader(reader); },
                          [this](const CardState& card) { publishCard(card); }, [this](ObjectId id) { withdraw(id); },
                          [this](ObjectId reader, const PropertyDelta& delta) { updateProperties(reader, delta); });
}

BusExporter::~BusExporter()
{
    // Sever the NameOwnerChanged proxy so a late unique-name drop cannot fire a
    // disconnect handler into our half-torn-down `this`. Idempotent with
    // clearClientDisconnectHandlers (AgentService severs it there during a clean
    // shutdown; this covers ephemeral test instances that skip that call). This
    // destructor performs NO core deref: the presence observers the core registry
    // holds against this transport are severed by the backend earlier in shutdown,
    // while both are still alive, so there is nothing to unwind here.
    m_nocProxy.reset();
}

std::optional<BusExporter::ReaderCard> BusExporter::resolveReaderCard(const std::string& readerPath) const
{
    // Take a single-lock ATOMIC presence snapshot so the {hasCard, cardPath, name}
    // triple is self-consistent (a monitor-thread updateProperties can neither tear
    // the map nor half-update an entry mid-read). No sd-bus call is made under the
    // lock; the result is returned by value.
    const std::lock_guard guard(m_presenceMutex);
    auto it = m_presence.find(readerPath);
    if (it == m_presence.end()) {
        return std::nullopt;
    }
    const auto& entry = it->second;
    if (!entry.hasCard || entry.cardPath.empty() || entry.cardPath == "/") {
        return std::nullopt;
    }
    return ReaderCard{.readerName = entry.name, .cardKey = entry.cardPath};
}

void BusExporter::setMaterializer(Materializer materializer)
{
    m_materializer = std::move(materializer);
}

void BusExporter::clearMaterializer() noexcept
{
    m_materializer = Materializer{};
}

void BusExporter::attachLoopPoster(std::shared_ptr<EventLoopPoster> poster)
{
    m_loopPoster = std::move(poster);
}

bool BusExporter::hasLoopPoster() const noexcept
{
    return m_loopPoster != nullptr;
}

std::function<void(std::chrono::microseconds, std::function<void()>)> BusExporter::loopPostSink() const
{
    // Hand out a sink that SHARED-owns the backing poster (captures a shared_ptr
    // copy), so a worker closure that value-captures it keeps the poster alive even
    // if the worker is abandoned and resumes after this transport is gone.
    return [poster = m_loopPoster](std::chrono::microseconds delay, std::function<void()> fn) {
        if (poster) {
            poster->postAfter(delay, std::move(fn));
        }
    };
}

void BusExporter::post(std::function<void()> fn)
{
    if (m_loopPoster) {
        m_loopPoster->post(std::move(fn));
    }
}

void BusExporter::postAfter(std::chrono::microseconds delay, std::function<void()> fn)
{
    if (m_loopPoster) {
        m_loopPoster->postAfter(delay, std::move(fn));
    }
}

void BusExporter::publishReader(const ReaderState& reader)
{
    const std::string readerPath = agentObjectPath("reader", reader.id);
    const std::string cardPath = reader.card.valid() ? agentObjectPath("card", reader.card) : "/";
    {
        const std::lock_guard guard(m_presenceMutex);
        m_presence[readerPath] = PresenceEntry{.name = reader.name, .hasCard = reader.hasCard, .cardPath = cardPath};
    }
    if (m_materializer.onReader) {
        m_materializer.onReader(reader);
    }
}

void BusExporter::publishCard(const CardState& card)
{
    // Cards are not keyed in the reader-presence snapshot (resolveReaderCard reads
    // the reader's HasCard/Card, set by updateProperties). Just materialise the
    // Card1 object through the frontend.
    if (m_materializer.onCard) {
        m_materializer.onCard(card);
    }
}

void BusExporter::updateProperties(ObjectId reader, const PropertyDelta& delta)
{
    // A reader's HasCard/Card flipping on card insert/remove: mutate the presence
    // snapshot so resolveReaderCard sees the current card, then forward the delta
    // to the frontend, which emits PropertiesChanged on the live ReaderObject.
    const std::string readerPath = agentObjectPath("reader", reader);
    const std::string cardPath = delta.card.valid() ? agentObjectPath("card", delta.card) : "/";
    {
        const std::lock_guard guard(m_presenceMutex);
        if (auto it = m_presence.find(readerPath); it != m_presence.end()) {
            it->second.hasCard = delta.hasCard;
            it->second.cardPath = cardPath;
        }
    }
    if (m_materializer.onUpdate) {
        m_materializer.onUpdate(reader, delta);
    }
}

void BusExporter::withdraw(ObjectId id)
{
    // The ObjectId is a single per-process counter, so a reader path and a card
    // path for the same id never coexist. Only readers are keyed in the presence
    // snapshot; erasing a card path is a harmless no-op. The frontend then destroys
    // whichever exported object (reader or card) actually holds the id.
    const std::string readerPath = agentObjectPath("reader", id);
    {
        const std::lock_guard guard(m_presenceMutex);
        m_presence.erase(readerPath);
    }
    if (m_materializer.onWithdraw) {
        m_materializer.onWithdraw(id);
    }
}

void BusExporter::onClientDisconnect(std::function<void(CallerToken)> handler)
{
    // Append-only, wired once during single-threaded startup. The ctor-created
    // NameOwnerChanged proxy iterates these in registration order on the bus
    // thread; no lock is needed because no handler is added after the loop runs.
    m_disconnectHandlers.push_back(std::move(handler));
}

void BusExporter::clearClientDisconnectHandlers() noexcept
{
    // Sever order: drop the NameOwnerChanged proxy FIRST so no new unique-name
    // drop can start a handler, THEN clear the handler vector. Clearing destroys
    // the capturing closures, which NULLS the raw dependencies they reach — the
    // AgentService-owned OperationManager and the PKCS#11 broker — so a stray fire
    // can never deref a mid-destruction unique_ptr. AgentService calls this early in
    // quiesce() (before the member chain unwinds), while those dependencies are still
    // alive. An explicit member reset in the AgentService dtor body is deliberately NOT used
    // as an alternative: the monitor thread is still running at that point (the
    // bridge tears down later), and it drives the registry observers this exporter
    // owns, so resetting a monitor-touched member from the dtor body would be a
    // data race. Severing the bus-thread proxy (the bus loop is already stopped) is
    // the sole race-free teardown hook, and it is idempotent with ~BusExporter.
    m_nocProxy.reset();
    m_disconnectHandlers.clear();
}

} // namespace LibreSCRS::Agent
