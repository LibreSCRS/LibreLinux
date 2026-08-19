// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#include "AgentService.h"
#include "AgentCoreSeams.h" // makeResolveReaderCard / makeResolveCardKey (transport seams)
#include "AgentFrontend.h"
#include "AgentInterfaceNames.h"
#include "AgentObjectPath.h"   // agentObjectPath (card ObjectId -> cache-key path)
#include "CardRemovalCaches.h" // invalidateCardRemovalCaches (shared with the removal test)
#include "EventLoopPoster.h"
#include <LibreSCRS/Agent/backend/Logging.h>
#include "PolkitAuthorizer.h"
#include <LibreSCRS/Agent/pkcs11/Pkcs11Broker.h>
#include <sdbus-c++/IConnection.h>
#include <sdbus-c++/sdbus-c++.h>
#include <systemd/sd-daemon.h>
#include <systemd/sd-event.h>
#include <chrono>
#include <csignal>
#include <filesystem>
#include <functional>
#include <thread>
#include <utility>

namespace LibreSCRS::Agent {

namespace {
// kServiceName lives in common/AgentInterfaceNames.h (shared agent-wire names under
// LibreLinux::AgentWire — qualified here since the agent's own types now live in the
// LibreSCRS::Agent namespace). kRootPath is consumed inside the AgentFrontend.
using LibreLinux::AgentWire::kServiceName;

// sd-event signal callback: a SIGTERM/SIGINT delivered through the event loop's
// signalfd source (NOT an async POSIX handler) cleanly exits the loop. Because
// the source fires from within the loop's own dispatch, it preempts the blocking
// poll and runs as the very next event — it does not depend on any in-flight slot
// returning, so shutdown is honoured promptly. Returning a negative value would
// abort the loop with that error; sd_event_exit(0) is the graceful stop.
int onShutdownSignal(sd_event_source* /*s*/, const struct signalfd_siginfo* /*si*/, void* userdata) noexcept
{
    auto* event = static_cast<sd_event*>(userdata);
    sd_event_exit(event, 0);
    return 0;
}
} // namespace

AgentService::AgentService(CapabilityResolver& resolver, std::string version, std::filesystem::path configFile,
                           std::filesystem::path cacheRoot, LibreSCRS::Plugin::CardPluginService* pluginService)
    : m_resolver(resolver), m_pluginService(pluginService), m_version(std::move(version)),
      m_configFile(std::move(configFile)), m_cacheRoot(std::move(cacheRoot))
{
    // The neutral core (which now owns the config store, caches, key tracker,
    // presence model, and operation scheduler) is assembled in registerOnBus once
    // its borrowed [2] collaborators exist; the CardKeyTracker callback that scrubs
    // the caches / revokes leases / invalidates the reader session on card removal
    // is wired there too (it must reach into the emplaced core).
}

AgentService::~AgentService()
{
    // Run the ordered quiesce FIRST — before ANY member unwinds — so the whole bus-
    // facing edge is severed and every wedged crypto worker is unblocked while the
    // core, transport, prompter, and connections are all still alive. The member
    // chain then tears down frontend-first (see the layer note in the header).
    quiesce();
}

void AgentService::quiesce() noexcept
{
    // Phase (a): sever every inbound edge and unblock any pending prompt so the
    // member chain can unwind with nothing firing into a half-torn-down composition
    // and every wedged crypto worker able to JOIN. Ordered stop-then-sever; each
    // step is guarded because registerOnBus may have failed partway. The event loop
    // is already stopped here (run() has returned), so no bus thread is dispatching.

    // 1) Stop the inbound presence SOURCE first. Drains any in-flight monitor
    //    dispatch and releases the poll thread, so no further registry mutation can
    //    fire a presence observer during the rest of teardown. This is the
    //    "inbound stopped" point that must precede the core quiesce below.
    if (m_bridge) {
        m_bridge->stop();
    }
    // 2) Sever the client-liveness (NameOwnerChanged) watch while the OperationManager
    //    and PKCS#11 broker its handlers reach are still alive (they live in m_core,
    //    torn down later), so a late unique-name drop fires nothing.
    if (m_exporter) {
        m_exporter->clearClientDisconnectHandlers();
    }
    // 3) Sever the presence observers the core registry holds against the transport.
    //    The monitor is already stopped, so this is a no-op-safe formality — but it
    //    makes the "no observer fires during teardown" invariant EXPLICIT (rather than
    //    resting on destruction order) and is done while both the registry (inside
    //    m_core) and the transport are still alive. This is the "core quiesced" point.
    if (m_core) {
        m_core->objectRegistry().setObservers({}, {}, {});
    }
    // 4) Tear the event loop down — detaching the bus connection from it — BEFORE the
    //    cancel below, so the blocking CancelCurrent owns the main bus outright (the
    //    sd-event loop has already returned; detaching removes any ambiguity about who
    //    drives the connection). teardownEventLoop() is itself noexcept + idempotent.
    teardownEventLoop();
    // 5) Begin crypto shutdown, then DRAIN every pending consent prompt so a wedged
    //    crypto worker returns and is JOINED (not abandoned) by ~AgentCore.
    //    requestCryptoShutdown() cancels the agent-wide token FIRST, so a worker
    //    that unblocks bails at its flow's post-prompt gate and skips its completion
    //    rather than driving into a half-torn-down composition. Then loop the
    //    dismissal of every id this agent raised — each on its own bus
    //    connection, so it is deliverable while a worker is still blocked
    //    pumping its own request inline — until the prompt gate is empty or a
    //    bounded cap, so a second/queued prompting worker JOINS rather than
    //    falling to the zombie path. Best-effort: if a prompt does not drain, the crypto seam's shared_ptr
    //    keep-alive keeps the worker UAF-safe.
    if (m_core) {
        m_core->requestCryptoShutdown();
    }
    if (m_prompter && m_core) {
        constexpr int kMaxDrainIterations = 40; // ~2 s cap at 50 ms/iteration
        for (int i = 0; i < kMaxDrainIterations; ++i) {
            // Re-read the live set each round so the loop shrinks toward empty
            // instead of dismissing "whatever is current" over and over.
            for (const auto& id : m_core->promptSerializer().liveIds()) {
                m_prompter->cancel(id);
            }
            if (!m_core->promptSerializer().hasPendingPrompt()) {
                break;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds{50});
        }
    }
    // 6) Release the well-known name so a restarting agent can reclaim it promptly.
    if (m_connection) {
        try {
            m_connection->releaseName(sdbus::ServiceName{kServiceName});
        } catch (...) {
            // Best-effort during teardown.
        }
    }
}

namespace {
// Block SIGTERM/SIGINT process-wide. sd_event_add_signal requires the signal to
// be blocked so it is delivered to the loop's signalfd rather than caught by a
// default-disposition async handler; doing this BEFORE any worker jthread is
// spawned means the mask is inherited by every thread, so a signal can only ever
// surface through the event loop.
bool blockShutdownSignals()
{
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGTERM);
    sigaddset(&mask, SIGINT);
    return sigprocmask(SIG_BLOCK, &mask, nullptr) == 0;
}
} // namespace

bool AgentService::installEventLoop()
{
    if (sd_event_new(&m_event) < 0 || m_event == nullptr) {
        log::error("failed to create the sd-event loop");
        return false;
    }
    try {
        // Drive the D-Bus connection from this same loop: sd_bus_process is now
        // pumped by sd_event, on this thread, alongside the signal sources.
        m_connection->attachSdEventLoop(m_event);
    } catch (const sdbus::Error& e) {
        log::errorf("failed to attach the bus connection to the event loop: {}", e.getMessage());
        return false;
    }
    if (sd_event_add_signal(m_event, &m_sigtermSource, SIGTERM, onShutdownSignal, m_event) < 0 ||
        sd_event_add_signal(m_event, &m_sigintSource, SIGINT, onShutdownSignal, m_event) < 0) {
        log::error("failed to register the SIGTERM/SIGINT event sources");
        return false;
    }
    // Build the loop poster now that the loop exists (its wakeup io source is
    // registered on this main thread, which also runs sd_event_loop) and wire it
    // into the exporter, so a worker-resolved Card1 pre-read-auth value is
    // marshaled back onto THIS loop thread.
    try {
        m_loopPoster = std::make_shared<EventLoopPoster>(m_event);
    } catch (const std::exception& e) {
        log::errorf("failed to create the event-loop poster: {}", e.what());
        return false;
    }
    if (m_exporter) {
        // Attach the poster by shared_ptr: the transport shared-owns it and hands out
        // a sink (loopPostSink) that the resolver closure value-captures, so a detached
        // (never-joined) worker that resumes after shutdown keeps the poster alive
        // through that ref instead of dereferencing a freed object.
        m_exporter->attachLoopPoster(m_loopPoster);
    }
    return true;
}

void AgentService::teardownEventLoop() noexcept
{
    if (m_sigtermSource) {
        sd_event_source_unref(m_sigtermSource);
        m_sigtermSource = nullptr;
    }
    if (m_sigintSource) {
        sd_event_source_unref(m_sigintSource);
        m_sigintSource = nullptr;
    }
    // Detach the connection from the loop BEFORE freeing the loop, so the bus
    // connection (which outlives this object's event-loop members) never holds a
    // dangling sd-event pointer.
    if (m_connection && m_event) {
        try {
            m_connection->detachSdEventLoop();
        } catch (...) {
            // Best-effort during teardown.
        }
    }
    if (m_event) {
        sd_event_unref(m_event);
        m_event = nullptr;
    }
}

bool AgentService::registerOnBus()
{
    // Block SIGTERM/SIGINT BEFORE constructing the OperationManager (whose cleanup
    // jthread spawns here) or starting the MonitorBridge, so every spawned thread
    // inherits the block mask and the signals reach only the event loop's signalfd.
    if (!blockShutdownSignals()) {
        log::error("failed to block SIGTERM/SIGINT for the event loop");
        return false;
    }

    try {
        m_connection = sdbus::createSessionBusConnection();
    } catch (const sdbus::Error& e) {
        log::errorf("failed to open session bus: {}", e.getMessage());
        return false;
    }

    // Claim the well-known name BEFORE exporting any objects. If the name
    // is taken we abort before publishing a half-state Manager/ObjectManager.
    try {
        m_connection->requestName(sdbus::ServiceName{kServiceName});
    } catch (const sdbus::Error& e) {
        log::errorf("name {} already taken: {}", kServiceName, e.getMessage());
        return false;
    }

    // Choose the client-authorization gate now that the session bus is live.
    // Prefer polkit (its own system-bus connection + caller pid resolution via
    // this session bus); fall back to the file-seeded DefaultAuthorizer if no
    // system bus / no polkit is reachable.
    try {
        m_authorizer = std::make_unique<PolkitAuthorizer>(*m_connection);
        log::info("client authorization gated through polkit (CheckAuthorization)");
    } catch (const sdbus::Error& e) {
        log::warnf("polkit unavailable ({}); falling back to the default authorizer: sign and low-tier config "
                   "stay allowed (PIN is the human-presence proof), but the trust/timestamping tier is "
                   "fail-closed and configurable only via the agent config file",
                   e.getMessage());
        m_authorizer = std::make_unique<DefaultAuthorizer>();
    } catch (const std::exception& e) {
        log::warnf("polkit unavailable ({}); falling back to the default authorizer (trust tier fail-closed)",
                   e.what());
        m_authorizer = std::make_unique<DefaultAuthorizer>();
    }

    try {
        // Prompter client — outbound proxy to org.librescrs.Prompter1. It owns
        // no connection: each call opens its own, because a per-reader worker
        // makes a BLOCKING RequestSecret and pumps the reply inline, and
        // sd-bus connections are not thread-safe. Held as a shared_ptr the
        // crypto seams co-own, so a zombie worker's in-flight call stays valid.
        m_prompter = std::make_shared<PrompterClient>();

        // [2] The slim AgentTransport wire. Built with NO registry: the core
        // registry it observes lives INSIDE m_core (constructed next), so the
        // registry->transport observers are wired below via observePresenceFrom
        // once both exist. The ctor still installs the NameOwnerChanged
        // client-liveness watch on the connection.
        m_exporter = std::make_unique<BusExporter>(*m_connection);

        // [3] The owning neutral-core aggregate. Borrows the resolver + the [2]
        // transport / authorizer / prompter, plus the reader/card resolution seams
        // served from the transport's presence snapshot (the readerId is recovered
        // from the reader path via the backend's ObjectId<->path bijection). It
        // OWNS the registry / presence model / caches / key tracker / prompt gate /
        // config store / signing engine / rate limiter / lease manager / operation
        // scheduler / PKCS#11 broker, and builds the broker's crypto seams from its
        // own members + the co-owned prompter (the shutdown keep-alive).
        m_core.emplace(m_resolver, *m_exporter, *m_authorizer, m_prompter, m_configFile, m_cacheRoot,
                       makeResolveReaderCard(*m_exporter), makeResolveCardKey(*m_exporter));

        // Which reader holds a card, for the prompt chrome. Set once here,
        // before any operation can run: two dialogs can stand at once, so each
        // has to name the reader it belongs to.
        m_core->promptSerializer().setReaderIdentityResolver(makeResolveReaderIdentity(*m_exporter));

        // Wire the core registry's presence observers to the transport (the natural
        // presence sink). Done now that both exist; at teardown the core (holding
        // the registry) is destroyed BEFORE the transport with the monitor already
        // stopped, so these observer std::functions are freed un-fired.
        m_exporter->observePresenceFrom(m_core->objectRegistry());

        // [4] The inbound frontend owns the exported Reader1/Card1 objects + the
        // root ManagerObject (Manager1 + Config1 + Pkcs11_1 + ObjectManager). It
        // re-sources every core dependency it needs from m_core accessors and
        // borrows the core-owned PKCS#11 broker for the Pkcs11_1 surface. Built
        // AFTER the core it borrows.
        m_frontend = std::make_unique<AgentFrontend>(
            *m_exporter, m_connection, m_core->operationManager(), m_core->sharedCryptoContext(),
            m_core->cardReadCache(), m_core->signingEngineProvider(), m_core->authorizer(), m_core->rateLimiter(),
            m_core->configStore(), &m_core->pkcs11(), m_version, m_pluginService);

        // Card-removal events from the monitor reach the core CardKeyTracker via
        // MonitorBridge; the tracker fires this callback with the dropped card's
        // opaque ObjectId. Map it back to the object path the caches were populated
        // under (the backend owns the ObjectId<->path bijection) so the CAN/MRZ +
        // identity-snapshot scrub hits; revoke the card's PKCS#11 login leases so
        // the next SignRaw/Decrypt after a re-insert forces a fresh Login; and
        // invalidate the reader's shared CardSession so the next op re-opens and
        // re-resolves against whatever card is present next. Fires only from the
        // monitor at runtime (m_core + m_frontend both live by then); guarded
        // regardless. Runs under m_stateMutex (the bridge holds it before calling
        // the tracker), so no extra synchronization is needed here.
        m_core->cardKeyTracker().setOnKeyRemoved([this](ObjectId cardKey, const std::string& readerName) {
            if (!m_core) {
                return;
            }
            const std::string cardPath = agentObjectPath("card", cardKey);
            // Drop every per-card cache keyed on the card path (CAN/MRZ secrets,
            // identity/cert reads, and the ListCredentials snapshot). The exact
            // set lives in invalidateCardRemovalCaches() — one source of truth
            // shared with the removal regression test.
            invalidateCardRemovalCaches(m_core->credentialCache(), m_core->cardReadCache(),
                                        m_core->credentialSnapshotCache(), cardPath);
            if (m_frontend) {
                m_frontend->onCardRemovedForLease(cardKey);
            }
            m_core->operationManager().invalidateReaderSession(m_core->presenceModel().readerIdFor(readerName));
        });

        // A successful config mutation (over D-Bus or agent-internal, e.g. a
        // recorded LastTsaUrl) emits Config1.Changed on the frontend's root object.
        // The capture guards on m_frontend so a stray callback during teardown is a
        // no-op.
        m_core->configStore().setOnChanged([this](const std::string& key) {
            if (m_frontend) {
                m_frontend->emitConfigChanged(key);
            }
        });

        // A D-Bus client dropping off the bus (unique-name vanish) triggers, in
        // registration order: (1) auto-cancel of every Operation recorded for that
        // caller, then (2) revocation of its PKCS#11 login leases so a reconnecting
        // client must re-Login. The BusExporter (AgentTransport) owns the
        // NameOwnerChanged watch and fires both handlers in order.
        m_exporter->onClientDisconnect([this](CallerToken caller) {
            if (m_core) {
                m_core->operationManager().dispatchClientDisconnect(caller);
            }
        });
        m_exporter->onClientDisconnect([this](CallerToken caller) {
            if (m_core) {
                m_core->pkcs11().onClientDisconnected(caller);
            }
        });

    } catch (const sdbus::Error& e) {
        log::errorf("failed to export the agent's D-Bus surface: {}", e.getMessage());
        return false;
    } catch (const std::exception& e) {
        log::errorf("failed to export the agent's D-Bus surface: {}", e.what());
        return false;
    }

    // Build the event loop (drives the bus + the SIGTERM/SIGINT sources) AND the
    // loop poster, then wire the poster into the exporter — all BEFORE starting
    // the monitor. A card already seated when the agent starts fires
    // onCardInserted synchronously from start(), whose worker-resolved pre-read
    // auth must marshal onto a loop+poster that already exist (otherwise the
    // first card's PreReadAuthMethod would be stuck at the pending None). Pumping
    // only begins in run(), so attaching the loop here (not last) is harmless.
    if (!installEventLoop()) {
        return false;
    }
    try {
        // Monitor -> core presence model + key tracker -> registry -> transport ->
        // frontend -> bus.
        m_bridge = std::make_unique<MonitorBridge>(m_core->presenceModel(), m_core->cardKeyTracker(), m_stateMutex);
        m_bridge->start(); // not noexcept — see surrounding try/catch.
    } catch (const std::exception& e) {
        log::errorf("failed to start the monitor bridge: {}", e.what());
        return false;
    }
    sd_notify(0, "READY=1");
    log::infof("librescrs-agent ready on session bus (version {})", m_version);
    return true;
}

void AgentService::run()
{
    // Blocks until a SIGTERM/SIGINT source calls sd_event_exit. The loop pumps
    // both the D-Bus connection and the shutdown signals, so a signal is honoured
    // as the next event rather than waiting for an in-flight slot to return.
    sd_event_loop(m_event);
    log::infof("librescrs-agent shutting down");
}

} // namespace LibreSCRS::Agent
