// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Guard: the per-reader deferred-publish worker closure must marshal back through a
// post sink the transport HANDS OUT (loopPostSink), value-captured by the closure,
// NOT through a concrete transport-owned poster member dereferenced off the loop
// thread. Reads the shipped source so the invariant survives refactors — the worker
// hop lives in AgentFrontend, and the transport (BusExporter) no longer exposes the
// bespoke poster seam the old fused type carried.

#include <fstream>
#include <gtest/gtest.h>
#include <sstream>
#include <string>

namespace {
std::string slurp(const char* path)
{
    std::ifstream in(path);
    std::stringstream buffer;
    buffer << in.rdbuf();
    return buffer.str();
}
} // namespace

// The worker hop (AgentFrontend::makeCardResolver) must obtain its post sink via the
// transport handout and never name the legacy concrete poster member/setter.
TEST(TransportCaptureGuard, WorkerHopMarshalsThroughTransportHandoutSink)
{
    const std::string src = slurp(LIBRELINUX_AGENTFRONTEND_CPP);
    ASSERT_FALSE(src.empty()) << "AgentFrontend source path not wired";

    EXPECT_NE(src.find("loopPostSink"), std::string::npos)
        << "the worker hop must value-capture the sink the transport hands out (loopPostSink)";
    EXPECT_EQ(src.find("m_postToLoop"), std::string::npos)
        << "the worker hop must not name the legacy concrete poster member";
    EXPECT_EQ(src.find("setLoopPoster"), std::string::npos)
        << "the legacy raw poster setter must be gone from the worker hop";
}

// The slim transport must no longer carry the bespoke setLoopPoster/m_postToLoop
// seam: the poster is shared-owned (attachLoopPoster) and handed out as a sink.
TEST(TransportCaptureGuard, TransportDropsBespokePosterSeam)
{
    const std::string src = slurp(LIBRELINUX_BUSEXPORTER_CPP);
    ASSERT_FALSE(src.empty()) << "BusExporter source path not wired";

    EXPECT_EQ(src.find("m_postToLoop"), std::string::npos) << "the transport must not carry m_postToLoop";
    EXPECT_EQ(src.find("setLoopPoster"), std::string::npos) << "the transport must not expose setLoopPoster";
    EXPECT_NE(src.find("attachLoopPoster"), std::string::npos)
        << "the transport must shared-own the poster via attachLoopPoster";
}

// The worker closure must value-capture the handed-out post sink, never a concrete
// BusExporter pointer it would dereference off the loop thread.
TEST(TransportCaptureGuard, WorkerClosureCapturesHandoutSinkNotConcreteTransport)
{
    const std::string src = slurp(LIBRELINUX_AGENTFRONTEND_CPP);
    ASSERT_FALSE(src.empty()) << "AgentFrontend source path not wired";

    EXPECT_NE(src.find("[this, sink"), std::string::npos)
        << "the worker closure must value-capture the transport's handout sink";
    EXPECT_EQ(src.find("BusExporter*"), std::string::npos)
        << "no worker closure may capture a concrete BusExporter pointer";
}

// Lifetime guard: the transport keeps NO back-pointer to the core registry and its
// destructor performs NO core deref. The empty-observer sever now lives EXCLUSIVELY
// in AgentService::quiesce(), issued while the registry (inside the core) and the
// transport are both still alive — not as a transport destructor side-effect.
TEST(TransportTeardownGuard, DestructorPerformsNoCoreDeref)
{
    const std::string cpp = slurp(LIBRELINUX_BUSEXPORTER_CPP);
    const std::string hdr = slurp(LIBRELINUX_BUSEXPORTER_H);
    ASSERT_FALSE(cpp.empty()) << "BusExporter source path not wired";
    ASSERT_FALSE(hdr.empty()) << "BusExporter header path not wired";

    EXPECT_EQ(cpp.find("m_registry"), std::string::npos) << "the transport must hold no registry back-pointer";
    EXPECT_EQ(hdr.find("m_registry"), std::string::npos) << "the transport must declare no registry back-pointer";
    EXPECT_EQ(cpp.find("setObservers({}, {}, {})"), std::string::npos)
        << "the transport must not sever the core registry observers (that belongs to AgentService::quiesce)";

    const std::string quiesce = slurp(LIBRELINUX_AGENTSERVICE_CPP);
    ASSERT_FALSE(quiesce.empty()) << "AgentService source path not wired";
    EXPECT_NE(quiesce.find("setObservers({}, {}, {})"), std::string::npos)
        << "the explicit observer sever must live in AgentService::quiesce()";
}

// Co-own guard: every typed op the frontend spawns must be handed the SINGLE
// crypto-worker context (for abandoned-worker keep-alive) plus the shutdown-cancel
// token, and the CardObject must attach the context to each op it builds — so an
// abandoned typed op co-owns every core member its unwind touches (the cache for a
// nested CAN/MRZ prompt's putCan/putMrz past the flow gate) through one share and
// bails + skips completion on teardown.
TEST(TypedOpKeepAliveGuard, FrontendHandsEachTypedOpTheCoOwnedContextAndShutdownToken)
{
    const std::string src = slurp(LIBRELINUX_AGENTFRONTEND_CPP);
    ASSERT_FALSE(src.empty()) << "AgentFrontend source path not wired";

    EXPECT_NE(src.find("deps.cryptoContext = m_cryptoCtx"), std::string::npos)
        << "each typed op's deps must co-own the single crypto-worker context";
    EXPECT_NE(src.find("deps.shutdownToken = m_cryptoCtx->shutdown"), std::string::npos)
        << "each typed op's deps must carry the context's shutdown-cancel token";
    EXPECT_NE(src.find("deps.connectionKeepAlive = m_connection"), std::string::npos)
        << "each typed op's deps must co-own the agent bus connection (channel keep-alive)";
    // The pre-fix per-member shares must be gone from the frontend.
    EXPECT_EQ(src.find("deps.prompterKeepAlive"), std::string::npos)
        << "the frontend must not co-own the prompter as a separate per-member share";
    EXPECT_EQ(src.find("deps.credentialsKeepAlive"), std::string::npos)
        << "the frontend must not co-own the credential cache as a separate per-member share";
}

TEST(TypedOpKeepAliveGuard, CardObjectAttachesLifetimeGuardsToEveryTypedOp)
{
    const std::string src = slurp(LIBRELINUX_CARDOBJECT_CPP);
    ASSERT_FALSE(src.empty()) << "CardObject source path not wired";

    // The guard helper co-owns the single context + the bus connection and binds
    // the shutdown token.
    EXPECT_NE(src.find("op.keepAlive(m_deps.cryptoContext)"), std::string::npos)
        << "attachLifetimeGuards must co-own the single crypto-worker context";
    EXPECT_NE(src.find("op.keepAlive(m_deps.connectionKeepAlive)"), std::string::npos)
        << "attachLifetimeGuards must co-own the agent bus connection (typed-op channel keep-alive)";
    EXPECT_EQ(src.find("op.keepAlive(m_deps.prompterKeepAlive)"), std::string::npos)
        << "the pre-fix per-member prompter keep-alive must be gone";
    EXPECT_NE(src.find("op.bindShutdownToken(m_deps.shutdownToken)"), std::string::npos)
        << "attachLifetimeGuards must bind the shutdown-cancel token";

    // The LM seam bundle must be co-owned too: an abandoned qualified-sign worker
    // derefs its signer seam's vtable + the engine it holds by reference on unblock,
    // so the seam object itself must outlive the zombie. The stateless read/cert
    // seams are co-owned uniformly (their statelessness is a margin, not the guard).
    EXPECT_NE(src.find("op.keepAlive(m_deps.ownedSigner)"), std::string::npos)
        << "attachLifetimeGuards must co-own the signing seam share (abandoned sign-worker keep-alive)";
    EXPECT_NE(src.find("op.keepAlive(m_deps.ownedReader)"), std::string::npos)
        << "attachLifetimeGuards must co-own the identity-reader seam share";
    EXPECT_NE(src.find("op.keepAlive(m_deps.ownedCertReader)"), std::string::npos)
        << "attachLifetimeGuards must co-own the certificate-reader seam share";

    // Every prompting op the CardObject spawns must run the guard helper: the raw
    // build call MUST be followed by attachLifetimeGuards(*op) (never a bare
    // `return buildXOperation(...)`). GetPhoto prompts on a cache miss, so it too
    // must attach — all four typed paths.
    std::size_t attaches = 0;
    for (std::size_t pos = src.find("attachLifetimeGuards(*op)"); pos != std::string::npos;
         pos = src.find("attachLifetimeGuards(*op)", pos + 1)) {
        ++attaches;
    }
    EXPECT_GE(attaches, 4u) << "Sign / ReadIdentity / ReadCertificates / GetPhoto must each attach the lifetime guards";
}

// Ordering guard: quiesce() stops the inbound monitor BEFORE severing the core
// presence observers, and severs before cancelling the pending prompt — so no
// observer can fire into a half-torn-down composition during teardown.
TEST(TransportTeardownGuard, QuiesceStopsInboundBeforeSeveringObservers)
{
    const std::string src = slurp(LIBRELINUX_AGENTSERVICE_CPP);
    ASSERT_FALSE(src.empty()) << "AgentService source path not wired";

    const auto stopPos = src.find("m_bridge->stop()");
    const auto severPos = src.find("setObservers({}, {}, {})");
    const auto cancelPos = src.find("cancelVia(");
    ASSERT_NE(stopPos, std::string::npos) << "quiesce() must stop the inbound monitor";
    ASSERT_NE(severPos, std::string::npos) << "quiesce() must sever the presence observers";
    ASSERT_NE(cancelPos, std::string::npos) << "quiesce() must cancel the pending prompt";
    EXPECT_LT(stopPos, severPos) << "the inbound monitor must be stopped before the core observers are severed";
    EXPECT_LT(severPos, cancelPos) << "the observers must be severed before the pending prompt is cancelled";
}
