// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include "BusExporter.h" // BusExporter::Materializer / BusExporter::ReaderCard
#include <LibreSCRS/Agent/operations/OperationLauncher.h>
#include <LibreSCRS/Agent/presence/CardResolutionPolicy.h>
#include <LibreSCRS/Agent/wire/QuiesceReason.h>
#include <sdbus-c++/IConnection.h>
#include <chrono>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <string>
namespace LibreSCRS::Plugin {
class CardPluginService;
}
namespace LibreSCRS::Agent {
class AgentCore;
class ReaderObject;
class CardObject;
class ManagerObject;
class Pkcs11Broker;
struct CardOperationDeps;

// The inbound frontend. OWNS the exported Reader1/Card1 object lifetimes, the
// root ManagerObject (Manager1 + Config1 + Pkcs11_1 + ObjectManager), and the
// PKCS#11 broker. It registers a materialization callback on the transport; each
// typed presence delta creates/destroys the matching sdbus object. Card creation
// is DEFERRED: the authoritative capabilities + pre-read auth are resolved on the
// per-reader worker-HELD session (the sole CardSession opener) and marshaled back
// onto the loop thread before the Card1 object is created.
//
// Borrows the transport, the connection and the AgentCore (whose operation
// scheduler, caches, authorizer, rate limiter, configuration and PKCS#11 broker it
// serves), and owns the OperationLauncher every card object launches through. All
// borrowed objects MUST outlive this frontend (AgentService enforces this via
// member declaration order: the core -- including the OperationManager whose
// workers the deferred-publish hop enqueues and the broker -- is torn down AFTER
// this frontend, and the transport AFTER the core).
class AgentFrontend
{
public:
    // @p pluginService is the plugin registry the credential depositor resolves
    // its mutable plugin handles from (the SAME registry the capability resolver
    // wraps; it MUST outlive this frontend). Null in tests that never
    // renegotiate a CAN prompt into an MRZ read: the read operations then
    // deposit nothing.
    AgentFrontend(BusExporter& transport, std::shared_ptr<sdbus::IConnection> connection, AgentCore& core,
                  std::string version, LibreSCRS::Plugin::CardPluginService* pluginService = nullptr);
    ~AgentFrontend();
    AgentFrontend(const AgentFrontend&) = delete;
    AgentFrontend& operator=(const AgentFrontend&) = delete;

    // The PKCS#11 broker logic object (Pkcs11_1 surface). Never null after
    // construction. Consumed by AgentService to wire the client-disconnect lease
    // revoke handler.
    [[nodiscard]] Pkcs11Broker* pkcs11() noexcept;

    // Lease invalidation entry point for card removal (AgentService wires this
    // into CardKeyTracker::onKeyRemoved alongside the cache scrub). The cardKey is
    // the per-insertion card's opaque ObjectId.
    void onCardRemovedForLease(ObjectId cardKey);

    // A config mutation (D-Bus or agent-internal) emits Config1.Changed on the
    // root ManagerObject. AgentService wires this into ConfigStore::setOnChanged.
    void emitConfigChanged(const std::string& key) noexcept;

    // Tell every client the agent quiesced card access, and why (Manager1.Quiesced
    // on the root ManagerObject).
    void emitQuiesced(QuiesceReason reason) noexcept;

private:
    // Materialization callbacks the transport forwards each typed presence delta
    // to (registered via BusExporter::setMaterializer at construction). These CREATE
    // / DESTROY the real exported ReaderObject / CardObject, guarded by
    // m_readersMutex / m_cardsMutex.
    void materializeReader(const ReaderState& reader);
    void materializeCard(const CardState& card);
    void withdrawObject(ObjectId id);
    void updateReaderProperties(ObjectId reader, const PropertyDelta& delta);
    void relabelReader(const ReaderState& reader);

    // What a new card object knows about its own card.
    [[nodiscard]] CardOperationDeps buildDepsForCard(const std::string& cardPath, const std::string& readerName) const;

    // Probe @p cardPath's card on its reader's worker (the held session, the sole
    // opener) through the agent library's resolution policy and marshal the
    // probe onto the loop thread (applyCardResolution), which then CREATES +
    // exports the Card1 object. On worker-queue backpressure it reschedules
    // itself on the loop after the policy's first retry delay, so the card is
    // eventually published and never silently dropped. Safe to call from the
    // monitor thread (materializeCard) or the loop thread (a retry). No-op when
    // no loop poster is wired (bus-less test).
    void scheduleCardResolve(const std::string& cardPath, const std::string& readerPath, const std::string& readerName);
    // Loop-thread helper: re-run scheduleCardResolve after @p delay, but only if
    // the card is still pending (dropped meanwhile by a withdraw).
    void rescheduleCardResolve(const std::string& cardPath, const std::string& readerPath,
                               const std::string& readerName, std::chrono::milliseconds delay);
    // Loop-thread sink: what the policy makes of @p probe -- probe again after
    // a wait, or CREATE + export the Card1 object now with what the probe
    // learned (deferred publish), taking the reader's power hold when the
    // policy says so. A no-op if the card was removed meanwhile. Guarded by
    // m_cardsMutex.
    void applyCardResolution(const std::string& cardPath, const std::string& readerPath, const std::string& readerName,
                             const CardProbe& probe);
    // Build the onCardTypeResolved callback CardOperationDeps carries into every
    // typed op this card spawns: value-captures cardPath + the transport's
    // loop-post sink (mirroring scheduleCardResolve's worker->loop marshal) so the
    // callback is safe to invoke from the PER-READER WORKER THREAD (inside
    // IdentityReadFlow::run()) at any later time, including after this card (or
    // the whole frontend) is gone -- it just no-ops.
    [[nodiscard]] std::function<void(const std::string&)> makeCardTypeResolvedCallback(const std::string& cardPath);
    // Loop-thread target of that callback: re-resolve @p cardPath by its STRING
    // path under m_cardsMutex (the same claim-by-key safety applyCardResolution
    // uses) and push the update onto the live CardObject if it is still there.
    void applyCardTypeUpdate(const std::string& cardPath, const std::string& cardType);

    // The one rule for a fresh card: probe on the worker, ask again only when the
    // probe could not open it (three repeats 50 ms apart -- shared PC/SC access
    // loses an open to another process's transaction only for a moment), then
    // decide the hold. Stateless; shared by the monitor and loop threads.
    const CardResolutionPolicy m_resolution{};

    BusExporter& m_transport;
    // The agent bus connection, co-owned (shared_ptr) so each typed op the
    // launcher builds co-owns a share for abandoned-worker keep-alive: its
    // channel's emit + unregister then touch a LIVE connection. Dereferenced for
    // the bare `IConnection&` the exported objects (Manager/Reader/Card) need.
    std::shared_ptr<sdbus::IConnection> m_connection;
    AgentCore& m_core;
    std::string m_version;
    // Every card operation is assembled and queued here, over the production
    // seams. Declared before the object maps so it outlives every card object
    // that launches through it.
    Operations::OperationLauncher m_launcher;

    // std::map (not unordered_map) -- InterfacesRemoved fires in a deterministic
    // path order on teardown, which is easier to read in journald and to test.
    // m_readers is mutated on the MONITOR thread (materialize/update/withdraw) and
    // read on the loop thread (materializeCard's reader-name lookup);
    // m_readersMutex serialises the two. ReaderObject construction (registerAdaptor)
    // and destruction (unregisterAdaptor) take the sd-bus lock and are therefore
    // always done OUTSIDE m_readersMutex to preserve the bus/agent lock order.
    mutable std::mutex m_readersMutex;
    std::map<std::string, std::unique_ptr<ReaderObject>> m_readers;
    // Cards awaiting their held-session capability + pre-read-auth resolution
    // before they are CREATED + exported (deferred publish). Keyed by the card
    // object path; carries the reader path/name the worker hop needs and how much
    // of the policy's retry budget the card has used. Guarded by m_cardsMutex.
    struct PendingCard
    {
        std::string readerPath;
        std::string readerName;
        ResolveAttempts attempts;
        // atrHex is known synchronously at insertion (PresenceModel), well
        // before the held-session resolve this struct waits on; carried here
        // so applyCardResolution can seed it once the CardObject is finally
        // constructed.
        std::string atrHex;
    };
    std::map<std::string, PendingCard> m_pendingCards;
    // shared_ptr (not unique_ptr) so a CardObject can be CO-OWNED across the
    // thread boundary while a cross-thread property update is in flight:
    // applyCardTypeUpdate (EVENT-LOOP thread) copies the share out under
    // m_cardsMutex and calls updateCardType() through the copy, so a concurrent
    // withdrawObject (MONITOR thread) that drops the map's owner meanwhile only
    // removes ONE of the two owners — the object is never freed while the loop
    // thread is dereferencing it. Whichever owner drops the LAST ref runs
    // ~CardObject (bus unexport), always OUTSIDE m_cardsMutex.
    std::map<std::string, std::shared_ptr<CardObject>> m_cards;
    // Guards m_cards + m_pendingCards: materialize/withdraw mutate them on the
    // MONITOR thread while applyCardResolution creates/claims on the EVENT-LOOP
    // thread. Bus (un)registration is always done OUTSIDE this lock; the shared
    // ownership above lets the loop thread keep a CardObject alive past a
    // concurrent withdraw's map erase.
    std::mutex m_cardsMutex;

    // Root object (Manager1 + Config1 + Pkcs11_1 + ObjectManager), forwarding its
    // Pkcs11_1 surface to the core's broker. Declared LAST so it destructs FIRST.
    std::unique_ptr<ManagerObject> m_manager;
};
} // namespace LibreSCRS::Agent
