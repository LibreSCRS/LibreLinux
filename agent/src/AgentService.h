// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <LibreSCRS/Agent/AgentCore.h> // the owning neutral-core aggregate ([3])
#include <LibreSCRS/Agent/backend/Authorizer.h>
#include "BusExporter.h"
#include <LibreSCRS/Agent/presence/MonitorBridge.h>
#include "PrompterClient.h"
#include <filesystem>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
struct sd_event;
struct sd_event_source;
namespace sdbus {
class IConnection;
}
namespace LibreSCRS::Plugin {
class CardPluginService;
}
namespace LibreSCRS::Agent {
class CapabilityResolver;
class AgentFrontend;
class EventLoopPoster;

// The Linux backend host. Owns the session-bus connection + sd-event loop ([1]),
// the interface impls the neutral core borrows ([2]: prompter, authorizer,
// transport), the owning AgentCore aggregate ([3]), and the inbound frontend +
// monitor bridge ([4]). registerOnBus() claims org.librescrs.Agent, assembles
// the four layers, and exports the tree; run() blocks on the bus event loop
// until a SIGINT/SIGTERM signal handler stops it.
//
// `resolver` MUST outlive the AgentService — the caller owns it.
class AgentService
{
public:
    // @p pluginService is the plugin registry the per-card credential depositor
    // resolves mutable plugin handles from — the SAME registry @p resolver
    // wraps, borrowed here rather than reached through the resolver so the
    // capability seam keeps its narrow, card-facts-only surface. Like
    // @p resolver it MUST outlive this service. Null (the default) in
    // conformance harnesses that never renegotiate a read.
    AgentService(CapabilityResolver& resolver, std::string version, std::filesystem::path configFile,
                 std::filesystem::path cacheRoot, LibreSCRS::Plugin::CardPluginService* pluginService = nullptr);
    ~AgentService();
    AgentService(const AgentService&) = delete;
    AgentService& operator=(const AgentService&) = delete;

    [[nodiscard]] bool registerOnBus(); // claim well-known name + export tree + signal READY
    void run();                         // blocks on the sd-event loop

private:
    // Install an sd-event loop that drives both the D-Bus connection AND the
    // SIGTERM/SIGINT shutdown sources. Returns false on any sd-event failure.
    [[nodiscard]] bool installEventLoop();
    void teardownEventLoop() noexcept;

    // Ordered pre-destruction quiesce: run as the FIRST thing in the destructor,
    // before the member chain unwinds. Severs every inbound edge (stops the monitor,
    // drops the client-liveness watch, severs the presence observers) and cancels any
    // pending consent prompt so a wedged crypto worker returns and can be JOINED, then
    // releases the event loop + well-known name. noexcept and fully guarded (each step
    // no-ops if registerOnBus never ran it), so it is the single teardown entry point.
    void quiesce() noexcept;

    CapabilityResolver& m_resolver;
    // Borrowed plugin registry (may be null) threaded into the frontend, which
    // builds the per-card credential depositor from it.
    LibreSCRS::Plugin::CardPluginService* m_pluginService{nullptr};
    std::string m_version;
    // Config paths captured from the ctor and handed to the AgentCore aggregate
    // when it is emplaced in registerOnBus (the ConfigStore + caches it builds now
    // live inside the core, constructed there rather than in this ctor).
    std::filesystem::path m_configFile;
    std::filesystem::path m_cacheRoot;
    // The members below are the four ownership LAYERS, declared top-to-bottom in
    // construction order (destroyed bottom-to-top): platform primitives outlive the
    // interface impls the core borrows, which outlive the owning core aggregate,
    // which outlives the inbound frontend. quiesce() (run first from the destructor)
    // severs the bus-facing edge FIRST — it stops the inbound monitor, drops the
    // client-liveness watch, severs the presence observers, then cancels any pending
    // prompt — so the member chain then unwinds frontend-first with every collaborator
    // each layer borrowed still alive. Each member's note records why it sits in its
    // layer (borrower-before-borrowee).

    // ---- [1] platform primitives — constructed FIRST, destroyed LAST -----------
    // Main session bus. Hosts every [2] sdbus object + the NameOwnerChanged proxy,
    // so it MUST outlive them; detached from the loop in teardownEventLoop().
    // shared_ptr (not unique_ptr): every typed Operation1 op co-owns a share
    // (keepAlive'd through the frontend -> CardObject), so a typed op abandoned to
    // the process-lifetime zombie list keeps the connection alive until it drains —
    // its channel's adaptor emit + unregister then touch a LIVE connection instead
    // of one freed with this host.
    std::shared_ptr<sdbus::IConnection> m_connection;
    // sd-event loop driving the bus connection AND the SIGTERM/SIGINT sources (so a
    // signal is honoured promptly even mid-slot); detached/freed in
    // teardownEventLoop() before the member chain unwinds.
    sd_event* m_event{nullptr};
    sd_event_source* m_sigtermSource{nullptr};
    sd_event_source* m_sigintSource{nullptr};
    // Agent-state serialization shared by the MonitorBridge dispatch + the
    // CardKeyTracker callback; outlives both (they live in [4] / [3]).
    std::mutex m_stateMutex;

    // ---- [2] the interface impls the core borrows — destroyed BEFORE [1] -------
    // Client-authorization gate (Polkit, else Default), chosen in registerOnBus;
    // borrows m_connection only.
    std::unique_ptr<Authorizer> m_authorizer;
    // Prompter1 client. shared_ptr so a crypto seam value-captures it and keeps
    // the prompter alive for a zombie worker; the worker's bus connection lives
    // in its own blocked call frame, so nothing else has to outlive it.
    std::shared_ptr<PrompterClient> m_prompter;
    // AgentTransport.post backing (built in installEventLoop). shared_ptr so an
    // abandoned deferred-publish worker keeps it alive through the sink it
    // value-captured; declared before m_exporter, which shared-owns it.
    std::shared_ptr<EventLoopPoster> m_loopPoster;
    // The slim AgentTransport impl: presence snapshot + post + client-liveness + the
    // resolveReaderCard seam. Exports no object itself. Declared before m_core (which
    // borrows it) so it outlives the core; the presence observers the core registry
    // holds against this transport are severed explicitly in quiesce() (monitor
    // already stopped) while both are still alive, so this transport's destructor
    // never touches the core.
    std::unique_ptr<BusExporter> m_exporter;

    // ---- [3] the owning neutral-core aggregate — destroyed BEFORE [2] ----------
    // Owns the registry, presence model, caches, key tracker, prompt gate, config
    // store, signing engine, rate limiter, lease manager, operation scheduler, and
    // PKCS#11 broker in one clean internal order. Borrows ONLY the [2] interfaces
    // (transport + authorizer + prompter) plus the injected resolver; emplaced in
    // registerOnBus. Declared after m_prompter so ~AgentCore joins/abandons its
    // crypto workers while the prompter is still alive — the structural half of
    // the crypto-worker shutdown keep-alive.
    std::optional<AgentCore> m_core;

    // ---- [4] the inbound frontend — constructed LAST, destroyed FIRST ----------
    // Owns the exported Reader1/Card1 objects + the root ManagerObject; borrows the
    // core (re-sourced from m_core accessors) + the transport. Destroyed first: it
    // clears its materialization callback on the still-live transport and drops its
    // objects while the core it borrows is still alive.
    std::unique_ptr<AgentFrontend> m_frontend;
    // Inbound presence SOURCE. Declared LAST so quiesce() stops it FIRST: once its
    // monitor subscription is drained, no further registry mutation can fire a
    // presence observer during the rest of teardown.
    std::unique_ptr<MonitorBridge> m_bridge;
};
} // namespace LibreSCRS::Agent
