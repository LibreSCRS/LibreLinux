// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include "BusExporter.h" // BusExporter::Materializer / BusExporter::ReaderCard
#include <LibreSCRS/CancelToken.h>
#include <sdbus-c++/IConnection.h>
#include <chrono>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <vector>
namespace LibreSCRS::Plugin {
class CardPluginService;
}
namespace LibreSCRS::Agent {
class ReaderObject;
class CardObject;
class ManagerObject;
class CredentialCache;
class CardReadCache;
class Authorizer;
class Pkcs11Broker;
struct CardOperationDeps;
struct CryptoWorkerContext;
namespace Config {
class ConfigStore;
}
namespace Operations {
class OperationManager;
class PrompterClientBase;
class PromptSerializer;
class SigningEngineProvider;
class RateLimiter;
class CardSessionHolder;
} // namespace Operations

// The inbound frontend. OWNS the exported Reader1/Card1 object lifetimes, the
// root ManagerObject (Manager1 + Config1 + Pkcs11_1 + ObjectManager), and the
// PKCS#11 broker. It registers a materialization callback on the transport; each
// typed presence delta creates/destroys the matching sdbus object. Card creation
// is DEFERRED: the authoritative capabilities + pre-read auth are resolved on the
// per-reader worker-HELD session (the sole CardSession opener) and marshaled back
// onto the loop thread before the Card1 object is created.
//
// Borrows the transport, the connection, and the neutral core members + PKCS#11
// broker (all now OWNED by the AgentCore aggregate; AgentService re-sources each
// from m_core->…() accessors at construction). All MUST outlive this frontend
// (AgentService enforces this via member declaration order: the core — including
// the OperationManager whose workers the deferred-publish hop enqueues and the
// broker — is torn down AFTER this frontend, and the transport AFTER the core).
class AgentFrontend
{
public:
    // Every dependency (transport, connection, opManager, caches, crypto context,
    // signing engine, authorizer, rate limiter, config) MUST outlive this frontend.
    // @p pkcs11 is the AgentCore-owned PKCS#11 broker the root ManagerObject's
    // Pkcs11_1 surface forwards to; it is borrowed, never owned here, and may be
    // null in conformance tests that never exercise Pkcs11_1. @p cryptoContext is
    // the AgentCore-owned crypto-worker context (prompter + prompt gate + credential
    // cache + lease + shutdown token); the frontend takes a shared handle so every
    // typed op it spawns CO-OWNS it for abandoned-worker keep-alive and binds its
    // shutdown token so each op bails + skips completion on backend teardown. Tests
    // construct an ephemeral context at test scope (or leave its shares null).
    // @p pluginService is the plugin registry the per-card credential depositor
    // resolves its mutable plugin handles from (the SAME registry the capability
    // resolver wraps; it MUST outlive this frontend). Null in tests that never
    // renegotiate a CAN prompt into an MRZ read: each card then carries no
    // depositor and the read operations fall back to the no-op seam.
    AgentFrontend(BusExporter& transport, std::shared_ptr<sdbus::IConnection> connection,
                  Operations::OperationManager& opManager, std::shared_ptr<CryptoWorkerContext> cryptoContext,
                  CardReadCache& readCache, Operations::SigningEngineProvider& signingEngine, Authorizer& authorizer,
                  Operations::RateLimiter& rateLimiter, Config::ConfigStore& config, Pkcs11Broker* pkcs11,
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

private:
    // Materialization callbacks the transport forwards each typed presence delta
    // to (registered via BusExporter::setMaterializer at construction). These CREATE
    // / DESTROY the real exported ReaderObject / CardObject, guarded by
    // m_readersMutex / m_cardsMutex.
    void materializeReader(const ReaderState& reader);
    void materializeCard(const CardState& card);
    void withdrawObject(ObjectId id);
    void updateReaderProperties(ObjectId reader, const PropertyDelta& delta);

    // Builds the per-card seam bundle (CardObject deps).
    [[nodiscard]] CardOperationDeps buildDepsForCard(const std::string& cardPath, const std::string& readerName) const;

    // Enqueue a per-reader worker hop that resolves @p cardPath's capabilities +
    // pre-read auth on the held session (the sole opener) and marshals the result
    // onto the loop thread (applyCardResolution), which then CREATES + exports the
    // Card1 object. On worker-queue backpressure it reschedules itself on the loop
    // after kResolveRetryDelay so the card is eventually published and never
    // silently dropped. Safe to call from the monitor thread (materializeCard) or
    // the loop thread (a retry). No-op when no loop poster is wired (bus-less test).
    void scheduleCardResolve(const std::string& cardPath, const std::string& readerPath, const std::string& readerName);
    // Loop-thread helper: re-run scheduleCardResolve after kResolveRetryDelay, but
    // only if the card is still pending (dropped meanwhile by a withdraw). Throttles
    // the retry so a momentarily-full reader queue never busy-spins the loop.
    void rescheduleCardResolve(const std::string& cardPath, const std::string& readerPath,
                               const std::string& readerName);
    // Builds the worker closure for scheduleCardResolve: it runs ON THE WORKER
    // THREAD (it may only touch the holder), computes fullResolution() (capability
    // union + strongest pre-read auth + cardType on the held session), then hands
    // the wire values to the loop via a value-captured post sink the transport
    // hands out.
    [[nodiscard]] std::function<void(Operations::CardSessionHolder&)>
    makeCardResolver(const std::string& cardPath, const std::string& readerPath, const std::string& readerName);
    // Loop-thread sink: CREATE + export the Card1 object for @p cardPath with the
    // worker-resolved @p caps + @p preReadAuth + @p cardType (deferred publish). A
    // no-op if the card was removed meanwhile; on a caps==0 resolve failure it
    // retries a bounded number of times before exporting caps==0 as a last resort.
    // Guarded by m_cardsMutex.
    void applyCardResolution(const std::string& cardPath, const std::string& readerPath, const std::string& readerName,
                             std::uint32_t caps, const std::string& preReadAuth, const std::string& cardType);
    // Build the onCardTypeResolved callback CardOperationDeps carries into every
    // typed op this card spawns: value-captures cardPath + the transport's
    // loop-post sink (mirroring makeCardResolver's worker->loop marshal) so the
    // callback is safe to invoke from the PER-READER WORKER THREAD (inside
    // IdentityReadFlow::run()) at any later time, including after this card (or
    // the whole frontend) is gone -- it just no-ops.
    [[nodiscard]] std::function<void(const std::string&)> makeCardTypeResolvedCallback(const std::string& cardPath);
    // Loop-thread target of that callback: re-resolve @p cardPath by its STRING
    // path under m_cardsMutex (the same claim-by-key safety applyCardResolution
    // uses) and push the update onto the live CardObject if it is still there.
    void applyCardTypeUpdate(const std::string& cardPath, const std::string& cardType);

    // Backpressure / resolve-retry reschedule delay for scheduleCardResolve.
    static constexpr std::chrono::milliseconds kResolveRetryDelay{50};
    // Bounded retries when fullResolution() yields caps==0 (e.g. the session could
    // not open): after this many failed attempts the card is exported with caps==0
    // as a last resort so a card is never left unexported forever.
    static constexpr int kMaxResolveAttempts{3};

    BusExporter& m_transport;
    // The agent bus connection, co-owned (shared_ptr) so each typed op the frontend
    // spawns can co-own a share for abandoned-worker keep-alive (buildDepsForCard
    // threads a copy into every CardObject's deps.connectionKeepAlive). Dereferenced
    // for the bare `IConnection&` the exported objects (Manager/Reader/Card) need.
    std::shared_ptr<sdbus::IConnection> m_connection;
    Operations::OperationManager& m_opManager;
    // The single crypto-worker context (prompter + prompt gate + credential cache +
    // lease + shutdown token), co-owned so each typed op this frontend spawns can
    // co-own it too for abandoned-worker keep-alive; the bare `&` the flows want is
    // taken via .get() on its members, the shutdown token via .shutdown.
    std::shared_ptr<CryptoWorkerContext> m_cryptoCtx;
    CardReadCache& m_readCache;
    Operations::SigningEngineProvider& m_signingEngine;
    Authorizer& m_authorizer;
    Operations::RateLimiter& m_rateLimiter;
    Config::ConfigStore& m_config;
    std::string m_version;
    // The plugin registry the per-card credential depositor resolves mutable
    // plugin handles from (borrowed, owned by the composition root; the SAME
    // registry the capability resolver wraps). Null in tests -- see the ctor.
    LibreSCRS::Plugin::CardPluginService* m_pluginService{nullptr};

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
    // object path; carries the reader path/name the worker hop needs and a bounded
    // retry counter for caps==0 resolve failures. Guarded by m_cardsMutex.
    struct PendingCard
    {
        std::string readerPath;
        std::string readerName;
        int resolveAttempts{0};
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

    // The AgentCore-owned PKCS#11 broker logic (BORROWED, not owned — the broker,
    // its Deps, and all its worker-hop crypto seams live inside AgentCore). May be
    // null in conformance tests. m_manager forwards its Pkcs11_1 surface here.
    Pkcs11Broker* m_pkcs11{nullptr};
    // Root object (Manager1 + Config1 + Pkcs11_1 + ObjectManager). Declared LAST so
    // it destructs FIRST (it borrows m_pkcs11).
    std::unique_ptr<ManagerObject> m_manager;
};
} // namespace LibreSCRS::Agent
