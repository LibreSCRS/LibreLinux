// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <LibreSCRS/Agent/backend/AgentTransport.h>
#include <LibreSCRS/Agent/PresenceTypes.h>
#include <sdbus-c++/IConnection.h>
#include <sdbus-c++/IProxy.h> // m_nocProxy (client-disconnect NameOwnerChanged watch)
#include <chrono>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <vector>
namespace LibreSCRS::Agent {
class ObjectRegistry;
class EventLoopPoster;
// White-box test access to the private disconnect-handler vector (agent/tests).
struct BusExporterTestPeer;

// The transport wire (AgentTransport impl). Keeps a synchronised presence
// SNAPSHOT (a pure projection of the typed reader deltas — no exported sdbus
// object), the worker->loop marshaling seam, the client-liveness
// (NameOwnerChanged) watch, and the reader->card resolveReaderCard seam the core
// PKCS#11 lookup consults. It exports NO object itself: each typed presence delta
// updates the snapshot and is forwarded to a registered materialization callback
// (the AgentFrontend) that owns the real Reader1/Card1 object lifetimes. The
// snapshot lets the core reader->card lookup stay off the frontend's object maps.
class BusExporter : public AgentTransport
{
public:
    // The transport wire is decoupled from the presence SOURCE: this ctor only
    // installs the process-global NameOwnerChanged watch on connection. The core
    // ObjectRegistry — which now lives inside the owning AgentCore aggregate,
    // constructed AFTER this transport — is wired separately via
    // observePresenceFrom() once it exists (AgentService does this after emplacing
    // the core). The backend severs those observers explicitly at shutdown, while
    // both are still alive; this transport keeps no back-pointer to the registry and
    // its destructor never touches it.
    explicit BusExporter(sdbus::IConnection& connection);

    // Convenience overload for unit tests + the presence-driven suites: wires this
    // exporter as @p registry's observer target IMMEDIATELY (so a test can drive
    // PresenceModel and see the deltas arrive). The test-owned registry outlives
    // this exporter and is not mutated after it, so the dangling observers are freed
    // un-fired at registry teardown; this exporter keeps no back-pointer, so its
    // destructor never touches the registry. Production uses the single-arg ctor +
    // observePresenceFrom().
    BusExporter(sdbus::IConnection& connection, ObjectRegistry& registry);

    // Wire this exporter as @p registry's observer target (each typed delta drives
    // publishReader/publishCard/withdraw/updateProperties). Keeps no back-pointer to
    // the registry: the caller (AgentService) severs the observers explicitly during
    // shutdown, and the destructor here never touches the registry.
    void observePresenceFrom(ObjectRegistry& registry);

    ~BusExporter();
    BusExporter(const BusExporter&) = delete;
    BusExporter& operator=(const BusExporter&) = delete;

    // Reader object path -> the card object path it currently holds (+ the
    // reader's human name), or nullopt when the path is not a live reader or
    // holds no card. Served from the presence snapshot (m_presence) under a
    // single lock so the {hasCard, card, name} triple is self-consistent. This is
    // the seam the core PKCS#11 host + the frontend's worker-hop reader-name
    // lookup consult; it reads NO exported object.
    struct ReaderCard
    {
        std::string readerName;
        std::string cardKey; // card object path
    };
    [[nodiscard]] std::optional<ReaderCard> resolveReaderCard(const std::string& readerPath) const;

    // The whole reader roster and the card each one currently holds, taken in
    // ONE lock and index-aligned. A prompt's reader label needs both: which
    // reader holds a given card, and the full set — a dual-interface unit is
    // only distinguishable across the set, so a per-reader query could not tell
    // its two slots apart. An entry with no card carries an empty card path.
    struct PresenceRoster
    {
        std::vector<std::string> readerNames;
        std::vector<std::string> cardPaths;
    };
    [[nodiscard]] PresenceRoster presenceRoster() const;

    // The callbacks the AgentFrontend registers so each typed presence delta
    // (forwarded from the AgentTransport overrides) materialises/withdraws its
    // real exported sdbus object. Mirrors the ObjectRegistry observer triple. Set
    // once at startup (before the monitor emits) and cleared by the frontend as it
    // tears down, so no delta materialises into a half-destroyed frontend.
    struct Materializer
    {
        std::function<void(const ReaderState&)> onReader;
        std::function<void(const CardState&)> onCard;
        std::function<void(ObjectId)> onWithdraw;
        std::function<void(ObjectId, const PropertyDelta&)> onUpdate;
    };
    void setMaterializer(Materializer materializer);
    void clearMaterializer() noexcept;

    // Marshal seam: attach the worker->loop poster once the sd-event loop exists.
    // The transport SHARED-owns it so the sink it hands out (loopPostSink) keeps it
    // alive for a worker that is abandoned and resumes after this transport is gone.
    // Until attached (a bus-less unit test, or before the loop is wired) post/
    // postAfter are no-ops and the frontend falls back to synchronous card creation.
    // Must be attached before the monitor starts emitting card inserts.
    void attachLoopPoster(std::shared_ptr<EventLoopPoster> poster);
    // True once a loop poster is wired (a real bus + event loop); the frontend
    // branches its synchronous vs deferred card-publish path on this.
    [[nodiscard]] bool hasLoopPoster() const noexcept;
    // Hands out the worker->loop post sink so a worker closure can VALUE-CAPTURE it
    // (rather than dereference a concrete transport pointer off the loop thread).
    [[nodiscard]] std::function<void(std::chrono::microseconds, std::function<void()>)> loopPostSink() const;

    // --- AgentTransport: presence object tree --------------------------------
    // The core hands typed presence deltas (ReaderState/CardState/PropertyDelta,
    // keyed by opaque ObjectId); these overrides update the internal presence
    // snapshot (readerPath -> {name, hasCard, cardPath}) and forward the delta to
    // the frontend materialization callback, which owns the ObjectId<->wire-path
    // mapping and all Variant/interface-name tagging and materialises the real
    // exported sdbus object.
    void publishReader(const ReaderState& reader) override;
    void publishCard(const CardState& card) override;
    void withdraw(ObjectId id) override;
    void updateProperties(ObjectId reader, const PropertyDelta& delta) override;

    // Loop-marshaling surface: run @p fn on the event-loop thread now (post) or
    // after @p delay (postAfter), through the wired poster. A no-op when no poster
    // is wired (a bus-less unit test or before the loop exists).
    void post(std::function<void()> fn) override;
    void postAfter(std::chrono::microseconds delay, std::function<void()> fn) override;

    // Client liveness. This exporter owns the process-global
    // org.freedesktop.DBus NameOwnerChanged proxy (created in the ctor on
    // m_connection). Each unique-name drop (':' prefix, empty new-owner) fires
    // every registered handler in registration order with the disconnecting
    // client's CallerToken. Handlers are append-only, wired once at startup
    // (AgentService registers the op auto-cancel first, then the PKCS#11 lease
    // revoke -- preserving the order the OperationManager watch used).
    void onClientDisconnect(std::function<void(CallerToken)> handler) override;

    // Sever the NameOwnerChanged proxy and drop every registered handler so no
    // late unique-name drop can fire a handler into a half-torn-down composition.
    // AgentService calls this early in quiesce() (before the member chain unwinds),
    // while the OperationManager and PKCS#11 broker the handlers reach are still alive.
    void clearClientDisconnectHandlers() noexcept;

private:
    friend struct BusExporterTestPeer;

    sdbus::IConnection& m_connection;

    // readerPath -> {name, hasCard, cardPath}. A pure projection of the typed
    // reader deltas (publishReader seeds it, updateProperties mutates it, withdraw
    // erases it) — NO exported sdbus object. Read on the loop/bus thread
    // (resolveReaderCard) while mutated on the monitor thread; m_presenceMutex
    // serialises the two so a consumer never observes a torn {hasCard, cardPath}
    // pair.
    struct PresenceEntry
    {
        std::string name;
        bool hasCard{false};
        std::string cardPath; // "/" when no card
    };
    mutable std::mutex m_presenceMutex;
    std::map<std::string, PresenceEntry> m_presence;

    // The frontend's materialization callbacks (wired once at startup via
    // setMaterializer, cleared as the frontend tears down). Invoked synchronously
    // from the AgentTransport overrides on the same thread the delta arrives on.
    Materializer m_materializer;

    // The worker->loop poster (attached once the loop exists). SHARED-owned so the
    // sink loopPostSink() hands out keeps it alive for an abandoned worker. Null in
    // a bus-less unit test or before the loop is wired.
    std::shared_ptr<EventLoopPoster> m_loopPoster;

    // Client-disconnect handlers (op auto-cancel + PKCS#11 lease revoke). Wired
    // once during single-threaded startup via onClientDisconnect; iterated
    // read-only on the bus thread inside the NameOwnerChanged callback, so no
    // lock is needed. Declared BEFORE m_nocProxy so automatic destruction tears
    // the proxy down first (it reads this vector).
    std::vector<std::function<void(CallerToken)>> m_disconnectHandlers;
    // Process-global org.freedesktop.DBus NameOwnerChanged proxy on m_connection.
    // Fires m_disconnectHandlers on each unique-name drop. Reset first in the dtor
    // (and by clearClientDisconnectHandlers) so a late drop cannot dereference a
    // half-torn-down `this`.
    std::unique_ptr<sdbus::IProxy> m_nocProxy;
};
} // namespace LibreSCRS::Agent
