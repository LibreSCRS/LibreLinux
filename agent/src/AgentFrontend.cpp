// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#include "AgentFrontend.h"
#include "AgentInterfaceNames.h" // LibreLinux::AgentWire::kRootPath
#include "AgentObjectPath.h"     // agentObjectPath / objectIdFromPath (ObjectId <-> wire path)
#include "AuthMethodName.h"      // authMethodName (PreReadAuthMethod -> wire string)
#include <LibreSCRS/Agent/CryptoWorkerContext.h>
#include <LibreSCRS/Agent/cache/CardReadCache.h>
#include <LibreSCRS/Agent/cache/CredentialCache.h>
#include <LibreSCRS/Agent/backend/Logging.h>
#include <LibreSCRS/Agent/config/ConfigStore.h>
#include "dbus/CardObject.h"
#include "dbus/ManagerObject.h"
#include <LibreSCRS/Agent/pkcs11/Pkcs11Broker.h>
#include "dbus/ReaderObject.h"
#include <LibreSCRS/Agent/operations/CardSessionHolder.h>
#include <LibreSCRS/Agent/operations/FlowPrelude.h>
#include <LibreSCRS/Agent/operations/LmSeams.h>
#include <LibreSCRS/Agent/operations/OperationManager.h>
#include <LibreSCRS/Agent/backend/PrompterClientBase.h>
#include <LibreSCRS/Plugin/CardPlugin.h> // CardPlugin::pluginId() (the single-candidate cardType)
#include <sdbus-c++/Types.h>
#include <chrono>
#include <cstdint>
#include <functional>
#include <mutex>
#include <optional>
#include <utility>
#include <vector>

namespace LibreSCRS::Agent {

AgentFrontend::AgentFrontend(BusExporter& transport, std::shared_ptr<sdbus::IConnection> connection,
                             Operations::OperationManager& opManager,
                             std::shared_ptr<CryptoWorkerContext> cryptoContext, CardReadCache& readCache,
                             Operations::SigningEngineProvider& signingEngine, Authorizer& authorizer,
                             Operations::RateLimiter& rateLimiter, Config::ConfigStore& config, Pkcs11Broker* pkcs11,
                             std::string version)
    : m_transport(transport), m_connection(std::move(connection)), m_opManager(opManager),
      m_cryptoCtx(std::move(cryptoContext)), m_readCache(readCache), m_signingEngine(signingEngine),
      m_authorizer(authorizer), m_rateLimiter(rateLimiter), m_config(config), m_version(std::move(version)),
      m_pkcs11(pkcs11)
{
    // Root: Manager1 + Config1 + Pkcs11_1 + ObjectManager on one path. Children
    // the frontend materialises under this path are picked up by sdbus-c++'s
    // ObjectManager natively. The Pkcs11_1 surface forwards to the AgentCore-owned
    // broker this frontend borrows.
    m_manager = std::make_unique<ManagerObject>(*m_connection, sdbus::ObjectPath{LibreLinux::AgentWire::kRootPath},
                                                m_version, m_config, m_authorizer, m_pkcs11);

    // Register the materialization callbacks on the transport: each typed presence
    // delta forwarded here CREATES / DESTROYS the real exported sdbus object.
    m_transport.setMaterializer(BusExporter::Materializer{
        .onReader = [this](const ReaderState& reader) { materializeReader(reader); },
        .onCard = [this](const CardState& card) { materializeCard(card); },
        .onWithdraw = [this](ObjectId id) { withdrawObject(id); },
        .onUpdate = [this](ObjectId reader, const PropertyDelta& delta) { updateReaderProperties(reader, delta); },
    });
}

AgentFrontend::~AgentFrontend()
{
    // Sever the materialization registration FIRST so a late presence delta (should
    // one somehow reach the still-wired transport) cannot materialise into a
    // half-destroyed frontend. The monitor is already stopped by teardown order, so
    // no delta actually fires here; this makes the no-fire invariant explicit. The
    // transport [layer 2] outlives this frontend, so the call is well-defined.
    m_transport.clearMaterializer();
}

Pkcs11Broker* AgentFrontend::pkcs11() noexcept
{
    return m_pkcs11;
}

void AgentFrontend::onCardRemovedForLease(ObjectId cardKey)
{
    if (m_pkcs11) {
        m_pkcs11->onCardRemoved(cardKey);
    }
}

void AgentFrontend::emitConfigChanged(const std::string& key) noexcept
{
    if (m_manager) {
        m_manager->emitConfigChanged(key);
    }
}

CardOperationDeps AgentFrontend::buildDepsForCard(const std::string& cardPath, const std::string& readerName) const
{
    CardOperationDeps deps;
    deps.cardKey = cardPath;
    deps.readerName = readerName;
    // const_cast: buildDepsForCard is const (it only ASSEMBLES the deps bundle),
    // but the callback it builds here needs to call the non-const
    // applyCardTypeUpdate() when it eventually fires -- see
    // makeCardTypeResolvedCallback's doc comment for why capturing `this` is
    // safe despite running on a foreign thread at an arbitrary later time.
    deps.onCardTypeResolved = const_cast<AgentFrontend*>(this)->makeCardTypeResolvedCallback(cardPath);

    // The read/sign seams are stateless routers — they resolve the signing/read
    // plugin from the per-operation candidate list (from the holder) at op time,
    // so no plugin is bound here. Pre-read auth is derived from that same held
    // session inside the flow, so no per-card plugin handle is needed here.
    deps.ownedReader = std::make_shared<Operations::LmCardReader>();
    deps.ownedCertReader = std::make_shared<Operations::LmCertificateReader>();
    // Reuses m_signingEngine's already-built TrustStoreService (see
    // SigningEngineProvider::trustSnapshot()) -- no separate trust store, no
    // new LM API.
    deps.ownedTrustVerifier = std::make_shared<Operations::LmTrustVerifier>(m_signingEngine);
    deps.ownedSigner = std::make_shared<Operations::LmSigner>(m_signingEngine);
    // The PIN-lifecycle seam driving the Credentials1 flows. Stateless router over
    // the plugin list (like the read/cert seams); co-owned for keep-alive.
    deps.ownedCredentials = std::make_shared<Operations::LmCredentialManager>();

    // The prompter / prompt gate / credential cache the flows want by `&` all live
    // in the crypto-worker context. Hand each op the bare handles for its flow Deps
    // AND a shared copy of the WHOLE context to co-own for abandoned-worker
    // keep-alive, plus the context's shutdown-cancel token. An op whose worker is
    // abandoned mid-prompt then keeps every core member its unwind touches alive
    // through the one co-owned context (the cache for a nested CAN/MRZ prompt's
    // putCan/putMrz past the flow gate) and bails + skips completion on teardown. A
    // conformance test may leave the context null (no real prompt driven).
    if (m_cryptoCtx) {
        deps.prompter = m_cryptoCtx->prompter.get();
        deps.serializer = m_cryptoCtx->serializer.get();
        deps.credentials = m_cryptoCtx->credentials.get();
        // The per-card ListCredentials snapshot store is co-owned by the crypto
        // context (so an abandoned credential worker keeps it alive on unblock); the
        // op borrows the bare pointer for its flow deps. Same instance the removal
        // hook + AgentCore::credentialSnapshotCache() address.
        deps.snapshotCache = m_cryptoCtx->snapshotCache.get();
        deps.cryptoContext = m_cryptoCtx;
        deps.shutdownToken = m_cryptoCtx->shutdown;
    }
    // Co-own the agent bus connection: every typed op the CardObject spawns
    // keepAlives this share (attachLifetimeGuards), so a typed op abandoned to the
    // zombie list keeps the connection alive until it drains — its channel adaptor's
    // emit + unregister then touch a LIVE connection, not one freed with the host.
    deps.connectionKeepAlive = m_connection;
    deps.readCache = &m_readCache;
    deps.authorizer = &m_authorizer;
    deps.rateLimiter = &m_rateLimiter;
    deps.config = &m_config;
    return deps;
}

std::function<void(Operations::CardSessionHolder&)> AgentFrontend::makeCardResolver(const std::string& cardPath,
                                                                                    const std::string& readerPath,
                                                                                    const std::string& readerName)
{
    // Obtain the loop-post sink HERE (on the enqueueing thread) and VALUE-CAPTURE it
    // into the worker closure. The returned closure runs ON THE WORKER THREAD and may
    // touch ONLY the holder + the captured sink — it never dereferences the transport
    // (nor any concrete backend pointer) off the loop thread. The sink shared-owns its
    // backing poster, so a worker stuck in fullResolution() that is abandoned
    // (detached, NOT joined) and resumes AFTER this frontend is freed still posts into
    // live (leaked) memory. `this` is captured only to build the loop-thread
    // continuation (never dereferenced on the worker), which the stopped loop discards
    // without running — destroying that lambda does not touch the freed frontend.
    auto sink = m_transport.loopPostSink();
    return [this, sink, cardPath, readerPath, readerName](Operations::CardSessionHolder& holder) {
        const auto resolution = holder.fullResolution();
        const std::uint32_t caps = resolution.capabilities;
        const std::string wire{authMethodName(resolution.preReadAuth)};
        // Card1.CardType (single-candidate case): the SAME held-session
        // candidate list preReadAuth/capabilities were just resolved from.
        // Ambiguous (more than one match) or empty (no match) both mean "not
        // yet known" -- stays empty; a later real read resolves it
        // authoritatively via the property-update path (onCardTypeResolved).
        std::string cardType;
        if (resolution.candidates.size() == 1 && resolution.candidates.front()) {
            cardType = resolution.candidates.front()->pluginId();
        }
        // loopPostSink() always hands out a valid callable (it guards its own
        // captured poster internally), so the sink is dereferenced unconditionally.
        sink(std::chrono::microseconds{0}, [this, cardPath, readerPath, readerName, caps, wire, cardType] {
            applyCardResolution(cardPath, readerPath, readerName, caps, wire, cardType);
        });
    };
}

void AgentFrontend::scheduleCardResolve(const std::string& cardPath, const std::string& readerPath,
                                        const std::string& readerName)
{
    if (!m_transport.hasLoopPoster()) {
        // No loop wired: the worker-resolved values could not be marshaled back to
        // create the CardObject. This is the bus-less unit-test path (and a worker
        // hop would throw there anyway, since enqueueOnReaderWorker requires the
        // production bus ctor); materializeCard creates the card synchronously
        // instead. Production wires the poster before the monitor starts, so a real
        // card always proceeds through the deferred resolve.
        return;
    }
    const bool queued = m_opManager.enqueueOnReaderWorker(objectIdFromPath(readerPath), readerName,
                                                          makeCardResolver(cardPath, readerPath, readerName));
    if (queued) {
        return; // the worker will resolve + marshal the result
    }
    // Backpressure: the reader's worker queue is momentarily at its cap. Do NOT
    // drop the resolve — reschedule it on the loop thread after a short delay so it
    // retries once the backlog drains.
    rescheduleCardResolve(cardPath, readerPath, readerName);
}

void AgentFrontend::rescheduleCardResolve(const std::string& cardPath, const std::string& readerPath,
                                          const std::string& readerName)
{
    // postAfter hops onto the loop thread itself, so this is safe to call from the
    // monitor thread (materializeCard's scheduleCardResolve) and from a prior
    // loop-thread retry alike. Re-run only if the card is still pending (a withdraw
    // may have dropped it while we waited).
    m_transport.postAfter(kResolveRetryDelay, [this, cardPath, readerPath, readerName] {
        bool stillPending = false;
        {
            std::lock_guard lock(m_cardsMutex);
            stillPending = m_pendingCards.contains(cardPath);
        }
        if (stillPending) {
            scheduleCardResolve(cardPath, readerPath, readerName);
        }
    });
}

void AgentFrontend::applyCardResolution(const std::string& cardPath, const std::string& readerPath,
                                        const std::string& readerName, std::uint32_t caps,
                                        const std::string& preReadAuth, const std::string& cardType)
{
    // Event-loop thread (posted by the worker via the loop poster). This is the
    // deferred publish: the CardObject is CREATED here, with the held-session
    // capability union + pre-read auth, so the InterfacesAdded snapshot carries the
    // correct values from the start.
    enum class Action { Drop, Retry, Claim };
    Action action = Action::Drop;
    std::string atrHex;
    {
        std::lock_guard lock(m_cardsMutex);
        auto it = m_pendingCards.find(cardPath);
        if (it == m_pendingCards.end()) {
            action = Action::Drop; // removed while resolving (or already claimed)
        } else if (caps == 0 && it->second.resolveAttempts < kMaxResolveAttempts) {
            // Transient resolve failure (e.g. the session could not open): retry a
            // bounded number of times before giving up. Leave the card pending.
            ++it->second.resolveAttempts;
            action = Action::Retry;
        } else {
            // Claim for export. Leave the entry in m_pendingCards as the
            // "still-wanted" marker across the off-lock CardObject construction
            // (registerAdaptor takes the bus lock, which we keep off m_cardsMutex);
            // the re-check below erases it only if a withdraw has not dropped it.
            action = Action::Claim;
            atrHex = it->second.atrHex;
        }
    }
    if (action == Action::Drop) {
        return;
    }
    if (action == Action::Retry) {
        rescheduleCardResolve(cardPath, readerPath, readerName);
        return;
    }
    // Build the per-card deps + create the CardObject OUTSIDE m_cardsMutex
    // (registerAdaptor is a bus call). At most one resolve is ever in flight per
    // card, so there is no competing claim here.
    auto deps = buildDepsForCard(cardPath, readerName);
    deps.preReadAuth = preReadAuth;
    deps.cardType = cardType;
    deps.atrHex = atrHex;
    auto card = std::make_shared<CardObject>(*m_connection, sdbus::ObjectPath{cardPath}, caps,
                                             sdbus::ObjectPath{readerPath}, m_opManager, std::move(deps));
    std::shared_ptr<CardObject> dyingCard;
    {
        std::lock_guard lock(m_cardsMutex);
        auto it = m_pendingCards.find(cardPath);
        if (it == m_pendingCards.end()) {
            // A withdraw dropped the card while we were constructing it: do not
            // publish a CardObject for a card that is already gone. Destruct it
            // OUTSIDE the lock (it registered on the bus in its ctor).
            dyingCard = std::move(card);
        } else {
            m_pendingCards.erase(it);
            m_cards.insert_or_assign(cardPath, std::move(card));
        }
    }
    if (dyingCard) {
        dyingCard.reset(); // off-lock teardown (unregisterAdaptor)
        return;
    }
    log::infof("exported card {}", cardPath);
}

void AgentFrontend::materializeReader(const ReaderState& reader)
{
    const std::string readerPath = agentObjectPath("reader", reader.id);
    auto readerObj = std::make_unique<ReaderObject>(
        *m_connection, sdbus::ObjectPath{readerPath}, reader.name, reader.hasCard,
        sdbus::ObjectPath{reader.card.valid() ? agentObjectPath("card", reader.card) : "/"});
    // The ReaderObject is constructed (registerAdaptor, sd-bus lock) OUTSIDE
    // m_readersMutex; only the map mutation is guarded.
    {
        const std::lock_guard guard(m_readersMutex);
        m_readers.emplace(readerPath, std::move(readerObj));
    }
    log::infof("exported reader {}", readerPath);
}

void AgentFrontend::materializeCard(const CardState& card)
{
    const std::string cardPath = agentObjectPath("card", card.id);
    const std::string readerPath = agentObjectPath("reader", card.reader);

    // Look up the reader's human name via the live ReaderObject.
    std::string readerName;
    {
        const std::lock_guard guard(m_readersMutex);
        if (auto rIt = m_readers.find(readerPath); rIt != m_readers.end() && rIt->second) {
            readerName = rIt->second->name();
        }
    }

    if (!m_transport.hasLoopPoster()) {
        // Bus-less unit-test path (no loop poster / no production worker bus):
        // create + export the card synchronously from whatever capability +
        // pre-read-auth the typed CardState carries (PresenceModel's ATR-only
        // resolution). A worker hop would throw here, and there is no loop to
        // marshal a deferred result back onto.
        auto deps = buildDepsForCard(cardPath, readerName);
        deps.preReadAuth = std::string{authMethodName(card.preReadAuth)};
        deps.cardType = card.cardType;
        deps.atrHex = card.atrHex;
        auto cardObj = std::make_shared<CardObject>(*m_connection, sdbus::ObjectPath{cardPath}, card.capabilities,
                                                    sdbus::ObjectPath{readerPath}, m_opManager, std::move(deps));
        {
            std::lock_guard lock(m_cardsMutex);
            m_cards.insert_or_assign(cardPath, std::move(cardObj));
        }
        log::infof("exported card {}", cardPath);
        return;
    }

    // Deferred publish: the authoritative capabilities AND PreReadAuthMethod
    // both need the per-reader worker-HELD session (the sole CardSession
    // opener) — the AID-probe families (eMRTD / health / pkcs15 / opensc /
    // eu-vrc) ship empty ATR tables, so PresenceModel's ATR-only resolution
    // publishes caps=0 for them. Record the card as pending and resolve
    // caps + pre-read auth on the worker; applyCardResolution then CREATES +
    // exports the Card1 object on the loop thread with the correct values, so
    // the InterfacesAdded snapshot is right from the start (no async caps/auth
    // correction a snapshot-only client would miss).
    {
        std::lock_guard lock(m_cardsMutex);
        m_pendingCards.insert_or_assign(cardPath, PendingCard{readerPath, readerName, 0, card.atrHex});
    }
    scheduleCardResolve(cardPath, readerPath, readerName);
}

std::function<void(const std::string&)> AgentFrontend::makeCardTypeResolvedCallback(const std::string& cardPath)
{
    // Value-captured now (on whichever thread builds this card's deps), so the
    // callback itself never dereferences the transport off the loop thread —
    // the same worker->loop marshal discipline as makeCardResolver.
    auto sink = m_transport.loopPostSink();
    return [this, sink, cardPath](const std::string& cardType) {
        sink(std::chrono::microseconds{0}, [this, cardPath, cardType] { applyCardTypeUpdate(cardPath, cardType); });
    };
}

void AgentFrontend::applyCardTypeUpdate(const std::string& cardPath, const std::string& cardType)
{
    // Event-loop thread. Re-resolve the card by its STRING path (never a stashed
    // pointer) under m_cardsMutex AND copy the co-owning shared_ptr out while the
    // lock is held. That copy is a genuine LIFETIME guarantee, not merely the
    // pre-lookup claim-by-key check applyCardResolution does: withdrawObject runs
    // on the MONITOR thread and, for a card removal, this card branch does NOT
    // drain the reader's in-flight ops (unlike the reader branch's
    // removeReader) — so a ReadIdentity/GetPhoto that snapshotted just before
    // removal can still resolve this cardType and post here AFTER the withdraw
    // has erased the map entry. Holding only a raw pointer across the unlock (the
    // former shape) let that concurrent withdraw's map-erase + last-ref drop free
    // the object between the lookup and the updateCardType() call below —
    // dereferencing freed memory. Co-owning the share means the withdraw drops
    // only the map's owner; THIS scope keeps the object alive across the whole
    // update. A card withdrawn BEFORE this runs is simply not found (nothing to
    // update). NOTE: updateReaderProperties can safely hold only a raw pointer
    // because materialize/update/withdraw of readers are serialised on the
    // MONITOR thread by MonitorBridge::m_stateMutex; the card property update is
    // NOT — it originates on a per-reader WORKER thread and marshals here onto the
    // loop thread, racing the monitor-thread withdraw — hence the co-ownership.
    std::shared_ptr<CardObject> card;
    {
        const std::lock_guard lock(m_cardsMutex);
        if (auto it = m_cards.find(cardPath); it != m_cards.end()) {
            card = it->second; // co-own: refcount now >= 2 (map + this copy)
        }
    }
    if (!card) {
        return; // withdrawn (or never claimed) — nothing to update
    }
    // updateCardType emits PropertiesChanged (sd-bus lock), so it is called
    // OUTSIDE m_cardsMutex to preserve the bus/agent lock order. The co-owned
    // `card` keeps the object alive across the whole call; should a concurrent
    // withdrawObject drop the map's owner meanwhile, THIS scope holds the last
    // ref and runs ~CardObject (bus unexport) on return — still outside the lock.
    card->updateCardType(cardType);
}

void AgentFrontend::updateReaderProperties(ObjectId reader, const PropertyDelta& delta)
{
    // A reader's HasCard/Card flipping on card insert/remove: push the typed
    // presence delta onto the live ReaderObject, which emits a minimal
    // PropertiesChanged for whatever actually moved.
    const std::string readerPath = agentObjectPath("reader", reader);
    ReaderObject* readerObj = nullptr;
    {
        const std::lock_guard guard(m_readersMutex);
        auto it = m_readers.find(readerPath);
        if (it == m_readers.end() || !it->second) {
            return;
        }
        readerObj = it->second.get();
    }
    // updateCardPresence emits PropertiesChanged (sd-bus lock), so it is called
    // OUTSIDE m_readersMutex. The pointer stays valid because materialize/update/
    // withdraw are SERIALISED by MonitorBridge::m_stateMutex (the registry
    // observers only ever fire under it — whether on the monitor thread or, for a
    // card seated at start-up, on the main thread), so no concurrent erase can run
    // here.
    readerObj->updateCardPresence(delta.hasCard,
                                  sdbus::ObjectPath{delta.card.valid() ? agentObjectPath("card", delta.card) : "/"});
}

void AgentFrontend::withdrawObject(ObjectId id)
{
    // The ObjectId is a single per-process counter, so a reader path and a card
    // path for the same id never coexist — at most one of the two maps holds it.
    // Probe m_readers first with the reader path, then the card maps with the
    // card path. Whichever map holds it: destructor unregisters from the bus.
    const std::string readerPath = agentObjectPath("reader", id);
    std::unique_ptr<ReaderObject> dyingReader;
    {
        const std::lock_guard guard(m_readersMutex);
        if (auto readerIt = m_readers.find(readerPath); readerIt != m_readers.end()) {
            dyingReader = std::move(readerIt->second);
            m_readers.erase(readerIt);
        }
    }
    if (dyingReader) {
        // Drain any in-flight / queued ops bound to this reader BEFORE the
        // ReaderObject destructs. Queued ops finish with errorCode CardRemoved;
        // the worker thread for the reader stops + is released so the next insert
        // spins a fresh worker. removeReader + ~ReaderObject (unregisterAdaptor
        // takes the sd-bus lock) run OUTSIDE m_readersMutex; the map entry is
        // already gone, so a concurrent read sees no reader.
        m_opManager.removeReader(id);
        dyingReader.reset();
        log::infof("unexported reader {}", readerPath);
        return;
    }
    const std::string cardPath = agentObjectPath("card", id);
    // A card may be in either lifecycle state: still PENDING its held-session
    // resolution (not yet exported) or already EXPORTED in m_cards. Handle both
    // under m_cardsMutex (mutually exclusive with the loop-thread
    // applyCardResolution claim+create):
    //   * Pending: erase from m_pendingCards so a resolve that lands later finds
    //     nothing and is dropped (applyCardResolution's pending re-check), AND so
    //     an in-flight applyCardResolution that is mid-construction drops the
    //     just-built CardObject instead of publishing a gone card.
    //   * Exported: move the co-owning share out, erase the map entry, then drop
    //     the share OUTSIDE the lock. ~CardObject runs unregisterAdaptor (bus
    //     lock), which we keep off the m_cardsMutex critical section. Dropping the
    //     share here frees the object ONLY if no other owner exists: a concurrent
    //     loop-thread applyCardTypeUpdate that copied the share (see there) keeps
    //     it alive until its update completes and then runs ~CardObject itself, so
    //     this monitor-thread erase never pulls the object out from under it.
    std::shared_ptr<CardObject> dyingCard;
    bool wasCard = false;
    {
        std::lock_guard lock(m_cardsMutex);
        if (auto pit = m_pendingCards.find(cardPath); pit != m_pendingCards.end()) {
            m_pendingCards.erase(pit);
            wasCard = true;
        }
        if (auto it = m_cards.find(cardPath); it != m_cards.end()) {
            dyingCard = std::move(it->second);
            m_cards.erase(it);
            wasCard = true;
        }
    }
    if (dyingCard) {
        dyingCard.reset(); // drop this owner off-lock; last ref runs ~CardObject
    }
    if (wasCard) {
        log::infof("unexported card {}", cardPath);
    }
}

} // namespace LibreSCRS::Agent
