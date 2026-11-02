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

// The worker hop (AgentFrontend::scheduleCardResolve) must obtain its post sink via the
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

// Co-own guard: an operation abandoned mid-prompt outlives the host's
// composition, so it must co-own the core members, the seams it drives and the
// bus connection its channel is exported on. The agent library's launcher
// attaches all three to every operation it builds; what this host owes it is the
// connection share, and one launcher for every card rather than a seam bundle of
// its own per card.
TEST(TypedOpKeepAliveGuard, TheFrontendLaunchesThroughOneLauncherThatCoOwnsTheConnection)
{
    const std::string src = slurp(LIBRELINUX_AGENTFRONTEND_CPP);
    ASSERT_FALSE(src.empty()) << "AgentFrontend source path not wired";

    EXPECT_NE(src.find("m_launcher(core, Operations::OperationSeams::production(core, pluginService), m_connection)"),
              std::string::npos)
        << "the frontend's launcher must run the production seams and co-own the agent bus connection";
    EXPECT_EQ(src.find("std::make_shared<Operations::Lm"), std::string::npos)
        << "the frontend must not build a seam bundle of its own";
    EXPECT_EQ(src.find("cryptoContext"), std::string::npos)
        << "the core members an operation co-owns are the launcher's to attach";
}

TEST(TypedOpKeepAliveGuard, EveryCardOperationGoesThroughTheLauncher)
{
    const std::string src = slurp(LIBRELINUX_CARDOBJECT_CPP);
    ASSERT_FALSE(src.empty()) << "CardObject source path not wired";

    // Nine operations, nine launches; nothing queued, assembled or kept alive by
    // hand beside them.
    std::size_t launches = 0;
    for (std::size_t pos = src.find("return launch("); pos != std::string::npos;
         pos = src.find("return launch(", pos + 1)) {
        ++launches;
    }
    EXPECT_EQ(launches, 9u) << "every Card1 / Credentials1 operation must be launched through the launcher";
    EXPECT_EQ(src.find(".publish("), std::string::npos) << "no operation may be queued around the launcher";
    EXPECT_EQ(src.find("::Deps"), std::string::npos) << "no operation's dependencies may be assembled here";
    EXPECT_EQ(src.find("keepAlive("), std::string::npos) << "the keep-alives are the launcher's to attach";
    EXPECT_EQ(src.find("bindShutdownToken("), std::string::npos) << "the shutdown binding is the launcher's to attach";
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
    const auto cancelPos = src.find("m_prompter->cancel(id)");
    ASSERT_NE(stopPos, std::string::npos) << "quiesce() must stop the inbound monitor";
    ASSERT_NE(severPos, std::string::npos) << "quiesce() must sever the presence observers";
    ASSERT_NE(cancelPos, std::string::npos) << "quiesce() must cancel the pending prompt";
    EXPECT_LT(stopPos, severPos) << "the inbound monitor must be stopped before the core observers are severed";
    EXPECT_LT(severPos, cancelPos) << "the observers must be severed before the pending prompt is cancelled";
}

// Startup guard: the agent must sweep the helper's orphan windows when it comes
// up. A helper outlives an agent restart, so without this a holder watches a
// dead dialog from the previous life count down for the rest of its entry time.
TEST(AgentStartupGuard, TheAgentSweepsThePrompterWhenItStarts)
{
    const std::string src = slurp(LIBRELINUX_AGENTSERVICE_CPP);
    ASSERT_FALSE(src.empty()) << "AgentService source path not wired";

    const auto constructPos = src.find("std::make_shared<PrompterClient>()");
    const auto resetPos = src.find("m_prompter->resetPrompter()");
    ASSERT_NE(constructPos, std::string::npos);
    ASSERT_NE(resetPos, std::string::npos) << "the agent never clears the helper's orphan windows at startup";
    EXPECT_LT(constructPos, resetPos) << "the sweep must follow the client it is issued through";
}
