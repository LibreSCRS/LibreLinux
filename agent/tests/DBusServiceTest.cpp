// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Conformance test: every path reported via ObjectManager must be a REAL
// exported D-Bus object that Properties.Get works on — phantom-payload
// designs would fail the second assertion. Runs under dbus-run-session so the
// session bus is private; uses a fake resolver so no PC/SC is required.

#include <LibreSCRS/Agent/backend/Authorizer.h>
#include <LibreSCRS/Agent/AgentCore.h>
#include <LibreSCRS/Agent/FeatureTokens.h>
#include "AgentCoreSeams.h"
#include "AgentFrontend.h"
#include "BusExporter.h"
#include <LibreSCRS/Agent/presence/CapabilityResolver.h>
#include <LibreSCRS/Agent/cache/CardReadCache.h>
#include <LibreSCRS/Agent/cache/CredentialCache.h>
#include <LibreSCRS/Agent/operations/LmSeams.h> // Operations::appearanceFontBytes (expected-bytes oracle)
#include <LibreSCRS/Agent/presence/ObjectRegistry.h>
#include <LibreSCRS/Agent/presence/PresenceModel.h>
#include <LibreSCRS/Agent/backend/PromptTypes.h>
#include <LibreSCRS/Agent/config/ConfigStore.h>
#include <LibreSCRS/Agent/operations/OperationManager.h>
#include <LibreSCRS/Agent/operations/PromptSerializer.h>
#include <LibreSCRS/Agent/backend/PrompterClientBase.h>
#include <LibreSCRS/Agent/operations/RateLimiter.h>
#include <LibreSCRS/Agent/operations/SigningEngineProvider.h>
#include <LibreSCRS/Agent/pkcs11/LeaseManager.h>

#include <LibreSCRS/Auth/ErrorKeys.h>
#include <LibreSCRS/Plugin/CardPlugin.h>
#include <sdbus-c++/sdbus-c++.h>
#include <gtest/gtest.h>
#include <unistd.h> // ::pread (reading GetAppearanceFont's returned fd)
#include <atomic>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <limits>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <span>
#include <string>
#include <thread>
#include <vector>

using namespace LibreSCRS::Agent;
using ManagedObjects = std::map<sdbus::ObjectPath, std::map<std::string, std::map<std::string, sdbus::Variant>>>;

namespace {

// Minimal CardPlugin stub that only declares capabilities + an id (mirrors the
// per-file stubs used elsewhere in the agent test suite).
class StubPlugin final : public LibreSCRS::Plugin::CardPlugin
{
public:
    StubPlugin(std::string id, LibreSCRS::Plugin::CardCapabilities caps) : m_caps(caps)
    {
        setIdentity(std::move(id), "stub", 0);
    }
    LibreSCRS::Plugin::CardCapabilities capabilities() const override
    {
        return m_caps;
    }
    std::span<const LibreSCRS::Plugin::Atr> supportedAtrs() const noexcept override
    {
        return {};
    }

protected:
    LibreSCRS::Plugin::ReadResult doReadCard(LibreSCRS::SmartCard::CardSession& /*session*/,
                                             GroupCallback /*onGroup*/) const override
    {
        return LibreSCRS::Plugin::ReadResult::communicationError(LibreSCRS::Auth::ErrorKeys::genericComm());
    }

private:
    LibreSCRS::Plugin::CardCapabilities m_caps;
};

class FakeResolver : public CapabilityResolver
{
public:
    // ATR-only capability resolution — opens no CardSession. PresenceModel uses
    // this on the monitor thread to publish Card1.Capabilities synchronously on
    // insert. No transient session-opening seam remains for BusExporter::onAdd or
    // PresenceModel to reach.
    std::shared_ptr<const LibreSCRS::Plugin::CardPlugin>
    resolvePlugin(std::span<const std::uint8_t> atr) const noexcept override
    {
        if (atr.empty()) {
            return nullptr;
        }
        return std::make_shared<StubPlugin>("fake", static_cast<LibreSCRS::Plugin::CardCapabilities>(0x3u));
    }
};

// Test prompter -- never invoked along these conformance paths (no
// ReadIdentity / GetPhoto call is issued).
class NopPrompter : public LibreSCRS::Agent::Operations::PrompterClientBase
{
public:
    PromptResult requestPin(const PromptOptions&) override
    {
        return {};
    }
    PromptResult requestCan(const PromptOptions&) override
    {
        return {};
    }
    PromptResult requestMrz(const PromptOptions&) override
    {
        return {};
    }
};

constexpr const char* kTestService = "org.librescrs.Agent.Test";
constexpr const char* kRootPath = "/org/librescrs/Agent";
// Single global opaque counter: the first reader added ("R0") mints id 1 ->
// reader/1, and its card mints id 2 -> card/2.
constexpr const char* kReader0Path = "/org/librescrs/Agent/reader/1";
constexpr const char* kCard0Path = "/org/librescrs/Agent/card/2";
constexpr const char* kCard1Iface = "org.librescrs.Agent.Card1";
constexpr const char* kReader1Iface = "org.librescrs.Agent.Reader1";

// ManagerObject now hosts Config1, so it needs a ConfigStore + Authorizer.
// These conformance tests don't exercise Config1; give each a throwaway temp
// store (no file is written unless a setter is called) + an allow-all gate.
std::filesystem::path testCfgDir(const char* tag)
{
    return std::filesystem::temp_directory_path() / (std::string{"ll-cfgtest-"} + tag);
}

} // namespace

TEST(DBusService, ExportsRealObjectsOverObjectManager)
{
    // Server connection: claims the name, hosts the objects.
    std::shared_ptr<sdbus::IConnection> serverConn = sdbus::createSessionBusConnection();
    ASSERT_NE(serverConn, nullptr) << "private session bus (run under dbus-run-session)";
    serverConn->requestName(sdbus::ServiceName{kTestService});

    ObjectRegistry registry;
    FakeResolver resolver;
    PresenceModel model(registry, resolver);
    LibreSCRS::Agent::Operations::OperationManager opManager; // bus-less; no ReadIdentity issued
    auto prompter = std::make_shared<NopPrompter>();
    auto serializer = std::make_shared<LibreSCRS::Agent::Operations::PromptSerializer>();
    auto credCache = std::make_shared<CredentialCache>();
    CardReadCache readCache;
    Config::ConfigStore cfg(testCfgDir("dbus1") / "agent.conf", testCfgDir("dbus1") / "cache");
    LibreSCRS::Agent::Operations::SigningEngineProvider signingEngine(cfg);
    AllowAllAuthorizer authz;
    LibreSCRS::Agent::Operations::RateLimiter rateLimiter;
    BusExporter exporter(*serverConn, registry);
    auto cryptoCtx = std::make_shared<CryptoWorkerContext>(
        CryptoWorkerContext{.prompter = prompter, .serializer = serializer, .credentials = credCache});
    AgentFrontend frontend(exporter, serverConn, opManager, cryptoCtx, readCache, signingEngine, authz, rateLimiter,
                           cfg, nullptr, "test-version");

    model.onReaderAdded("R0");
    model.onCardInserted("R0", {0x3B, 0x01});

    serverConn->enterEventLoopAsync();

    // Client connection: separate socket so sd-bus does not self-call (ELOOP).
    auto clientConn = sdbus::createSessionBusConnection();
    clientConn->enterEventLoopAsync();

    // (a) ObjectManager reports the tree.
    auto rootProxy = sdbus::createProxy(*clientConn, sdbus::ServiceName{kTestService}, sdbus::ObjectPath{kRootPath});
    ManagedObjects managed;
    rootProxy->callMethod("GetManagedObjects")
        .onInterface(sdbus::InterfaceName{"org.freedesktop.DBus.ObjectManager"})
        .storeResultsTo(managed);

    EXPECT_TRUE(managed.contains(sdbus::ObjectPath{kReader0Path})) << "ObjectManager did not report reader/0";
    EXPECT_TRUE(managed.contains(sdbus::ObjectPath{kCard0Path})) << "ObjectManager did not report card/0";
    ASSERT_TRUE(managed[sdbus::ObjectPath{kCard0Path}].contains(kCard1Iface));
    EXPECT_EQ(managed[sdbus::ObjectPath{kCard0Path}][kCard1Iface]["Capabilities"].get<std::uint32_t>(), 0x3u);

    // (b) Conformance: card/0 is a real exported object — Properties.Get works.
    auto cardProxy = sdbus::createProxy(*clientConn, sdbus::ServiceName{kTestService}, sdbus::ObjectPath{kCard0Path});
    sdbus::Variant caps;
    cardProxy->callMethod("Get")
        .onInterface(sdbus::InterfaceName{"org.freedesktop.DBus.Properties"})
        .withArguments(std::string{kCard1Iface}, std::string{"Capabilities"})
        .storeResultsTo(caps);
    EXPECT_EQ(caps.get<std::uint32_t>(), 0x3u) << "card/0 is not a real exported D-Bus object (phantom path?)";

    // Reader properties also accessible.
    auto readerProxy =
        sdbus::createProxy(*clientConn, sdbus::ServiceName{kTestService}, sdbus::ObjectPath{kReader0Path});
    sdbus::Variant name;
    readerProxy->callMethod("Get")
        .onInterface(sdbus::InterfaceName{"org.freedesktop.DBus.Properties"})
        .withArguments(std::string{kReader1Iface}, std::string{"Name"})
        .storeResultsTo(name);
    EXPECT_EQ(name.get<std::string>(), "R0");

    clientConn->leaveEventLoop();
    serverConn->leaveEventLoop();
}

// Regression guard for the single-card-session-per-reader invariant: a card
// insert exports a Card1 with full deps WITHOUT BusExporter::onAddCard opening a
// transient probe CardSession on the monitor thread. The per-reader worker-held
// session is the sole opener; onAddCard consults only the typed CardState
// PresenceModel already wrote. Drives onCardInserted (which synchronously fires
// onAddCard via the registry observer) and asserts the probe seams were never reached, and that
// the card still exports with its resolved capabilities (deps wired).
TEST(DBusService, OnAddDoesNotProbeTransientOpen)
{
    std::shared_ptr<sdbus::IConnection> serverConn = sdbus::createSessionBusConnection();
    ASSERT_NE(serverConn, nullptr) << "private session bus (run under dbus-run-session)";
    serverConn->requestName(sdbus::ServiceName{"org.librescrs.Agent.Test.NoProbe"});

    ObjectRegistry registry;
    FakeResolver resolver;
    PresenceModel model(registry, resolver);
    LibreSCRS::Agent::Operations::OperationManager opManager;
    auto prompter = std::make_shared<NopPrompter>();
    auto serializer = std::make_shared<LibreSCRS::Agent::Operations::PromptSerializer>();
    auto credCache = std::make_shared<CredentialCache>();
    CardReadCache readCache;
    Config::ConfigStore cfg(testCfgDir("dbus-noprobe") / "agent.conf", testCfgDir("dbus-noprobe") / "cache");
    LibreSCRS::Agent::Operations::SigningEngineProvider signingEngine(cfg);
    AllowAllAuthorizer authz;
    LibreSCRS::Agent::Operations::RateLimiter rateLimiter;
    BusExporter exporter(*serverConn, registry);
    auto cryptoCtx = std::make_shared<CryptoWorkerContext>(
        CryptoWorkerContext{.prompter = prompter, .serializer = serializer, .credentials = credCache});
    AgentFrontend frontend(exporter, serverConn, opManager, cryptoCtx, readCache, signingEngine, authz, rateLimiter,
                           cfg, nullptr, "test");

    // Card materialization fires synchronously inside m_registry.addCard() during onCardInserted.
    model.onReaderAdded("R0");                // reader id 1
    model.onCardInserted("R0", {0x3B, 0x01}); // card id 2

    // The card is exported without a probe-resolved plugin handle: onAddCard no
    // longer has a transient session-opening seam to reach (the deps are wired
    // from the worker-held candidates at op time).
    EXPECT_TRUE(registry.contains(ObjectId{2})) << "the inserted card must be registered";
}

TEST(DBusService, ManagerVersionReadableOverProperties)
{
    std::shared_ptr<sdbus::IConnection> serverConn = sdbus::createSessionBusConnection();
    ASSERT_NE(serverConn, nullptr);
    serverConn->requestName(sdbus::ServiceName{"org.librescrs.Agent.Test.Version"});

    ObjectRegistry registry;
    FakeResolver resolver;
    PresenceModel model(registry, resolver);
    LibreSCRS::Agent::Operations::OperationManager opManager;
    auto prompter = std::make_shared<NopPrompter>();
    auto serializer = std::make_shared<LibreSCRS::Agent::Operations::PromptSerializer>();
    auto credCache = std::make_shared<CredentialCache>();
    CardReadCache readCache;
    Config::ConfigStore cfg(testCfgDir("dbus2") / "agent.conf", testCfgDir("dbus2") / "cache");
    LibreSCRS::Agent::Operations::SigningEngineProvider signingEngine(cfg);
    AllowAllAuthorizer authz;
    LibreSCRS::Agent::Operations::RateLimiter rateLimiter;
    BusExporter exporter(*serverConn, registry);
    auto cryptoCtx = std::make_shared<CryptoWorkerContext>(
        CryptoWorkerContext{.prompter = prompter, .serializer = serializer, .credentials = credCache});
    AgentFrontend frontend(exporter, serverConn, opManager, cryptoCtx, readCache, signingEngine, authz, rateLimiter,
                           cfg, nullptr, "9.9.9-test");

    serverConn->enterEventLoopAsync();

    auto clientConn = sdbus::createSessionBusConnection();
    clientConn->enterEventLoopAsync();
    auto proxy = sdbus::createProxy(*clientConn, sdbus::ServiceName{"org.librescrs.Agent.Test.Version"},
                                    sdbus::ObjectPath{kRootPath});
    sdbus::Variant version;
    proxy->callMethod("Get")
        .onInterface(sdbus::InterfaceName{"org.freedesktop.DBus.Properties"})
        .withArguments(std::string{"org.librescrs.Agent.Manager1"}, std::string{"Version"})
        .storeResultsTo(version);
    EXPECT_EQ(version.get<std::string>(), "9.9.9-test");

    clientConn->leaveEventLoop();
    serverConn->leaveEventLoop();
}

// Feature discovery: Manager1.Features is served verbatim from
// LibreSCRS::Agent::kAgentFeatures (the single source of truth in LibreAgent
// core, also mirrored on the socket transport's HelloAck.features) — never
// re-derived or filtered by this repo.
TEST(DBusService, ManagerFeaturesReadableOverProperties)
{
    std::shared_ptr<sdbus::IConnection> serverConn = sdbus::createSessionBusConnection();
    ASSERT_NE(serverConn, nullptr);
    serverConn->requestName(sdbus::ServiceName{"org.librescrs.Agent.Test.Features"});

    ObjectRegistry registry;
    FakeResolver resolver;
    PresenceModel model(registry, resolver);
    LibreSCRS::Agent::Operations::OperationManager opManager;
    auto prompter = std::make_shared<NopPrompter>();
    auto serializer = std::make_shared<LibreSCRS::Agent::Operations::PromptSerializer>();
    auto credCache = std::make_shared<CredentialCache>();
    CardReadCache readCache;
    Config::ConfigStore cfg(testCfgDir("dbus-features") / "agent.conf", testCfgDir("dbus-features") / "cache");
    LibreSCRS::Agent::Operations::SigningEngineProvider signingEngine(cfg);
    AllowAllAuthorizer authz;
    LibreSCRS::Agent::Operations::RateLimiter rateLimiter;
    BusExporter exporter(*serverConn, registry);
    auto cryptoCtx = std::make_shared<CryptoWorkerContext>(
        CryptoWorkerContext{.prompter = prompter, .serializer = serializer, .credentials = credCache});
    AgentFrontend frontend(exporter, serverConn, opManager, cryptoCtx, readCache, signingEngine, authz, rateLimiter,
                           cfg, nullptr, "9.9.9-test");

    serverConn->enterEventLoopAsync();

    auto clientConn = sdbus::createSessionBusConnection();
    clientConn->enterEventLoopAsync();
    auto proxy = sdbus::createProxy(*clientConn, sdbus::ServiceName{"org.librescrs.Agent.Test.Features"},
                                    sdbus::ObjectPath{kRootPath});
    sdbus::Variant features;
    proxy->callMethod("Get")
        .onInterface(sdbus::InterfaceName{"org.freedesktop.DBus.Properties"})
        .withArguments(std::string{"org.librescrs.Agent.Manager1"}, std::string{"Features"})
        .storeResultsTo(features);
    const auto served = features.get<std::vector<std::string>>();
    const std::vector<std::string> expected(LibreSCRS::Agent::kAgentFeatures.begin(),
                                            LibreSCRS::Agent::kAgentFeatures.end());
    EXPECT_EQ(served, expected);

    clientConn->leaveEventLoop();
    serverConn->leaveEventLoop();
}

TEST(DBusService, HostsPkcs11InterfaceOnManagerPath)
{
    std::shared_ptr<sdbus::IConnection> serverConn = sdbus::createSessionBusConnection();
    ASSERT_NE(serverConn, nullptr);
    serverConn->requestName(sdbus::ServiceName{"org.librescrs.Agent.Test.Pkcs11"});

    ObjectRegistry registry;
    FakeResolver resolver;
    PresenceModel model(registry, resolver);
    LibreSCRS::Agent::Operations::OperationManager opManager;
    auto prompter = std::make_shared<NopPrompter>();
    auto serializer = std::make_shared<LibreSCRS::Agent::Operations::PromptSerializer>();
    auto credCache = std::make_shared<CredentialCache>();
    CardReadCache readCache;
    Config::ConfigStore cfg(testCfgDir("dbus-pkcs11") / "agent.conf", testCfgDir("dbus-pkcs11") / "cache");
    LibreSCRS::Agent::Operations::SigningEngineProvider signingEngine(cfg);
    AllowAllAuthorizer authz;
    LibreSCRS::Agent::Operations::RateLimiter rateLimiter;
    BusExporter exporter(*serverConn, registry);
    auto cryptoCtx = std::make_shared<CryptoWorkerContext>(
        CryptoWorkerContext{.prompter = prompter, .serializer = serializer, .credentials = credCache});
    AgentFrontend frontend(exporter, serverConn, opManager, cryptoCtx, readCache, signingEngine, authz, rateLimiter,
                           cfg, nullptr, "t");

    serverConn->enterEventLoopAsync();

    auto clientConn = sdbus::createSessionBusConnection();
    clientConn->enterEventLoopAsync();
    auto proxy = sdbus::createProxy(*clientConn, sdbus::ServiceName{"org.librescrs.Agent.Test.Pkcs11"},
                                    sdbus::ObjectPath{kRootPath});
    std::string introspection;
    proxy->callMethod("Introspect")
        .onInterface(sdbus::InterfaceName{"org.freedesktop.DBus.Introspectable"})
        .storeResultsTo(introspection);
    EXPECT_NE(introspection.find("org.librescrs.Agent.Pkcs11_1"), std::string::npos)
        << "Pkcs11_1 must be hosted on the manager path";

    clientConn->leaveEventLoop();
    serverConn->leaveEventLoop();
}

namespace {
// Minimal harness for the two Manager1 methods below: no card, no
// Operation, so unlike every OTHER test in this file none of these need a
// FakeResolver/PresenceModel at all -- ManagerObject answers directly.
struct ManagerHarness
{
    std::shared_ptr<sdbus::IConnection> serverConn;
    ObjectRegistry registry;
    FakeResolver resolver;
    PresenceModel model{registry, resolver}; // unused directly (no card in this corpus); mirrors every sibling test
    LibreSCRS::Agent::Operations::OperationManager opManager;
    std::shared_ptr<NopPrompter> prompter = std::make_shared<NopPrompter>();
    std::shared_ptr<LibreSCRS::Agent::Operations::PromptSerializer> serializer =
        std::make_shared<LibreSCRS::Agent::Operations::PromptSerializer>();
    std::shared_ptr<CredentialCache> credCache = std::make_shared<CredentialCache>();
    CardReadCache readCache;
    Config::ConfigStore cfg;
    LibreSCRS::Agent::Operations::SigningEngineProvider signingEngine;
    AllowAllAuthorizer authz;
    LibreSCRS::Agent::Operations::RateLimiter rateLimiter;
    std::unique_ptr<BusExporter> exporter;
    std::shared_ptr<CryptoWorkerContext> cryptoCtx;
    std::unique_ptr<AgentFrontend> frontend;

    explicit ManagerHarness(const std::string& serviceName, const char* cfgDirName)
        : serverConn(sdbus::createSessionBusConnection()),
          cfg(testCfgDir(cfgDirName) / "agent.conf", testCfgDir(cfgDirName) / "cache"), signingEngine(cfg)
    {
        serverConn->requestName(sdbus::ServiceName{serviceName});
        exporter = std::make_unique<BusExporter>(*serverConn, registry);
        cryptoCtx = std::make_shared<CryptoWorkerContext>(
            CryptoWorkerContext{.prompter = prompter, .serializer = serializer, .credentials = credCache});
        frontend = std::make_unique<AgentFrontend>(*exporter, serverConn, opManager, cryptoCtx, readCache,
                                                   signingEngine, authz, rateLimiter, cfg, nullptr, "t");
        serverConn->enterEventLoopAsync();
    }
};

std::vector<std::uint8_t> readAllFromFd(int fd)
{
    std::vector<std::uint8_t> out;
    std::array<std::uint8_t, 4096> buf{};
    off_t offset = 0;
    for (;;) {
        const ssize_t n = ::pread(fd, buf.data(), buf.size(), offset);
        if (n <= 0) {
            break;
        }
        out.insert(out.end(), buf.begin(), buf.begin() + n);
        offset += n;
    }
    return out;
}
} // namespace

// LayoutVisualSignature is card-independent and synchronous -- answers
// directly off ManagerObject, no Operation object minted. The served values
// must equal Operations::layoutVisualSignature's own output exactly (the
// SAME entry point this method calls through).
TEST(DBusService, ManagerLayoutVisualSignatureServesLmComputedLayout)
{
    ManagerHarness harness{"org.librescrs.Agent.Test.Layout", "dbus-layout"};

    auto clientConn = sdbus::createSessionBusConnection();
    clientConn->enterEventLoopAsync();
    auto proxy = sdbus::createProxy(*clientConn, sdbus::ServiceName{"org.librescrs.Agent.Test.Layout"},
                                    sdbus::ObjectPath{kRootPath});

    double fontSize = 0.0;
    double lineHeight = 0.0;
    std::vector<std::string> lines;
    bool clipped = false;
    proxy->callMethod("LayoutVisualSignature")
        .onInterface(sdbus::InterfaceName{"org.librescrs.Agent.Manager1"})
        .withArguments(std::string{"Signed by\nJohn Doe"}, 0.0, 0.0, 200.0, 50.0)
        .storeResultsTo(fontSize, lineHeight, lines, clipped);

    const auto expected =
        LibreSCRS::Agent::Operations::layoutVisualSignature("Signed by\nJohn Doe", {0.0, 0.0, 200.0, 50.0});
    EXPECT_DOUBLE_EQ(fontSize, expected.fontSize);
    EXPECT_DOUBLE_EQ(lineHeight, expected.lineHeight);
    EXPECT_EQ(lines, expected.lines);
    EXPECT_EQ(clipped, expected.clipped);
    EXPECT_FALSE(clipped) << "a plausible box must not be clipped";

    clientConn->leaveEventLoop();
    harness.serverConn->leaveEventLoop();
}

// The tiny-box floor case: `clipped` must arrive true over the real bus —
// the field's whole reason to ride the wire.
TEST(DBusService, ManagerLayoutVisualSignatureTinyBoxArrivesClipped)
{
    ManagerHarness harness{"org.librescrs.Agent.Test.LayoutClipped", "dbus-layout-clipped"};

    auto clientConn = sdbus::createSessionBusConnection();
    clientConn->enterEventLoopAsync();
    auto proxy = sdbus::createProxy(*clientConn, sdbus::ServiceName{"org.librescrs.Agent.Test.LayoutClipped"},
                                    sdbus::ObjectPath{kRootPath});

    double fontSize = 0.0;
    double lineHeight = 0.0;
    std::vector<std::string> lines;
    bool clipped = false;
    proxy->callMethod("LayoutVisualSignature")
        .onInterface(sdbus::InterfaceName{"org.librescrs.Agent.Manager1"})
        .withArguments(std::string{"Hello World"}, 0.0, 0.0, 4.0, 50.0)
        .storeResultsTo(fontSize, lineHeight, lines, clipped);
    EXPECT_TRUE(clipped);

    clientConn->leaveEventLoop();
    harness.serverConn->leaveEventLoop();
}

// Method-entry rejection: the SAME isValidLayoutRect gate Card1.Sign's
// visualSignature option uses (CardObjectOperationsTest.cpp's
// SignRejectsVisualSignatureWithNonFiniteWidth is the sibling RED vehicle for
// that call) -- a non-finite width must never reach LM's integer-narrowing
// cast.
TEST(DBusService, ManagerLayoutVisualSignatureRejectsNonFiniteWidth)
{
    ManagerHarness harness{"org.librescrs.Agent.Test.LayoutInvalid", "dbus-layout-invalid"};

    auto clientConn = sdbus::createSessionBusConnection();
    clientConn->enterEventLoopAsync();
    auto proxy = sdbus::createProxy(*clientConn, sdbus::ServiceName{"org.librescrs.Agent.Test.LayoutInvalid"},
                                    sdbus::ObjectPath{kRootPath});

    try {
        double fontSize = 0.0;
        double lineHeight = 0.0;
        std::vector<std::string> lines;
        bool clipped = false;
        proxy->callMethod("LayoutVisualSignature")
            .onInterface(sdbus::InterfaceName{"org.librescrs.Agent.Manager1"})
            .withArguments(std::string{"x"}, 0.0, 0.0, std::numeric_limits<double>::infinity(), 50.0)
            .storeResultsTo(fontSize, lineHeight, lines, clipped);
        ADD_FAILURE() << "expected a +inf width to be rejected";
    } catch (const sdbus::Error& e) {
        EXPECT_EQ(e.getName(), "org.librescrs.Agent.Error.InvalidRequest");
    }

    clientConn->leaveEventLoop();
    harness.serverConn->leaveEventLoop();
}

// GetAppearanceFont's sealed-memfd content must be byte-identical to
// Operations::appearanceFontBytes() (the same production entry point
// LibreDarwin's socket daemon serves from too).
TEST(DBusService, ManagerGetAppearanceFontServesLmEmbeddedFontBytes)
{
    ManagerHarness harness{"org.librescrs.Agent.Test.AppearanceFont", "dbus-appearance-font"};

    auto clientConn = sdbus::createSessionBusConnection();
    clientConn->enterEventLoopAsync();
    auto proxy = sdbus::createProxy(*clientConn, sdbus::ServiceName{"org.librescrs.Agent.Test.AppearanceFont"},
                                    sdbus::ObjectPath{kRootPath});

    sdbus::UnixFd fd;
    proxy->callMethod("GetAppearanceFont")
        .onInterface(sdbus::InterfaceName{"org.librescrs.Agent.Manager1"})
        .storeResultsTo(fd);
    ASSERT_TRUE(fd.isValid());

    const std::vector<std::uint8_t> received = readAllFromFd(fd.get());
    const std::vector<std::uint8_t> expected = LibreSCRS::Agent::Operations::appearanceFontBytes();
    EXPECT_FALSE(expected.empty());
    EXPECT_EQ(received, expected);

    clientConn->leaveEventLoop();
    harness.serverConn->leaveEventLoop();
}

// The card-touching Pkcs11_1 methods are sdbus-c++ ASYNC methods: the agent
// validates on the dispatch thread and fulfils a DEFERRED reply. This drives the
// full round-trip (generated async adaptor -> ManagerObject -> deferReply ->
// Pkcs11Broker::certDer validation -> Reply -> sdbus::Result) over a real bus for
// a reader with NO card: the agent must fulfil the deferred reply with the
// UnknownCard wire error, NOT hang the client and NOT return empty bytes. A
// hung/un-fulfilled deferred reply (the failure this conversion must avoid) would
// surface here as a method-call timeout rather than a clean error.
TEST(DBusService, Pkcs11AsyncCertDerFulfilsDeferredErrorReply)
{
    std::shared_ptr<sdbus::IConnection> serverConn = sdbus::createSessionBusConnection();
    ASSERT_NE(serverConn, nullptr);
    serverConn->requestName(sdbus::ServiceName{"org.librescrs.Agent.Test.AsyncReply"});

    // This test drives the real Pkcs11_1 -> broker -> UnknownCard path, so it wires
    // a FUNCTIONAL AgentCore-owned broker (the neutral aggregate builds the
    // production worker-hop seams from the transport's presence snapshot) rather
    // than the null broker the presence-only suites pass. CertDer on a card-less
    // reader must reach the broker's certDer seam, which resolves no card and
    // fulfils the deferred reply with UnknownCard.
    FakeResolver resolver;
    AllowAllAuthorizer authz;
    auto prompter = std::make_shared<NopPrompter>();
    BusExporter exporter(*serverConn);
    AgentCore core(resolver, exporter, authz, prompter, testCfgDir("dbus-async") / "agent.conf",
                   testCfgDir("dbus-async") / "cache", makeResolveReaderCard(exporter), makeResolveCardKey(exporter));
    exporter.observePresenceFrom(core.objectRegistry());
    AgentFrontend frontend(exporter, serverConn, core.operationManager(), core.sharedCryptoContext(),
                           core.cardReadCache(), core.signingEngineProvider(), core.authorizer(), core.rateLimiter(),
                           core.configStore(), &core.pkcs11(), "t");

    serverConn->enterEventLoopAsync();

    auto clientConn = sdbus::createSessionBusConnection();
    clientConn->enterEventLoopAsync();
    auto proxy = sdbus::createProxy(*clientConn, sdbus::ServiceName{"org.librescrs.Agent.Test.AsyncReply"},
                                    sdbus::ObjectPath{kRootPath});

    bool gotUnknownCard = false;
    try {
        std::vector<std::uint8_t> der;
        proxy->callMethod("CertDer")
            .onInterface(sdbus::InterfaceName{"org.librescrs.Agent.Pkcs11_1"})
            .withArguments(sdbus::ObjectPath{"/org/librescrs/Agent/reader/0"}, std::string{"deadbeef"})
            .storeResultsTo(der);
        FAIL() << "expected the deferred reply to carry Error.UnknownCard for a card-less reader";
    } catch (const sdbus::Error& e) {
        gotUnknownCard = (e.getName() == "org.librescrs.Agent.Error.UnknownCard");
    }
    EXPECT_TRUE(gotUnknownCard) << "async CertDer must fulfil the deferred reply with UnknownCard";

    clientConn->leaveEventLoop();
    serverConn->leaveEventLoop();
}

TEST(DBusService, MultipleReadersAndCardsAllExported)
{
    std::shared_ptr<sdbus::IConnection> serverConn = sdbus::createSessionBusConnection();
    ASSERT_NE(serverConn, nullptr);
    serverConn->requestName(sdbus::ServiceName{"org.librescrs.Agent.Test.Multi"});

    ObjectRegistry registry;
    FakeResolver resolver;
    PresenceModel model(registry, resolver);
    LibreSCRS::Agent::Operations::OperationManager opManager;
    auto prompter = std::make_shared<NopPrompter>();
    auto serializer = std::make_shared<LibreSCRS::Agent::Operations::PromptSerializer>();
    auto credCache = std::make_shared<CredentialCache>();
    CardReadCache readCache;
    Config::ConfigStore cfg(testCfgDir("dbus3") / "agent.conf", testCfgDir("dbus3") / "cache");
    LibreSCRS::Agent::Operations::SigningEngineProvider signingEngine(cfg);
    AllowAllAuthorizer authz;
    LibreSCRS::Agent::Operations::RateLimiter rateLimiter;
    BusExporter exporter(*serverConn, registry);
    auto cryptoCtx = std::make_shared<CryptoWorkerContext>(
        CryptoWorkerContext{.prompter = prompter, .serializer = serializer, .credentials = credCache});
    AgentFrontend frontend(exporter, serverConn, opManager, cryptoCtx, readCache, signingEngine, authz, rateLimiter,
                           cfg, nullptr, "test");

    model.onReaderAdded("R0");
    model.onReaderAdded("R1");
    model.onCardInserted("R0", {0x3B, 0x01});
    model.onCardInserted("R1", {0x3B, 0x02});

    serverConn->enterEventLoopAsync();

    auto clientConn = sdbus::createSessionBusConnection();
    clientConn->enterEventLoopAsync();
    auto root = sdbus::createProxy(*clientConn, sdbus::ServiceName{"org.librescrs.Agent.Test.Multi"},
                                   sdbus::ObjectPath{kRootPath});
    ManagedObjects managed;
    root->callMethod("GetManagedObjects")
        .onInterface(sdbus::InterfaceName{"org.freedesktop.DBus.ObjectManager"})
        .storeResultsTo(managed);

    // Single global opaque counter: R0=reader/1, R1=reader/2, R0's card=card/3,
    // R1's card=card/4 (readers minted before cards).
    EXPECT_TRUE(managed.contains(sdbus::ObjectPath{"/org/librescrs/Agent/reader/1"}));
    EXPECT_TRUE(managed.contains(sdbus::ObjectPath{"/org/librescrs/Agent/reader/2"}));
    EXPECT_TRUE(managed.contains(sdbus::ObjectPath{"/org/librescrs/Agent/card/3"}));
    EXPECT_TRUE(managed.contains(sdbus::ObjectPath{"/org/librescrs/Agent/card/4"}));

    // Properties.Get must work on EACH card individually (conformance, every path).
    for (const auto& path : {"/org/librescrs/Agent/card/3", "/org/librescrs/Agent/card/4"}) {
        auto cardProxy = sdbus::createProxy(*clientConn, sdbus::ServiceName{"org.librescrs.Agent.Test.Multi"},
                                            sdbus::ObjectPath{path});
        sdbus::Variant caps;
        cardProxy->callMethod("Get")
            .onInterface(sdbus::InterfaceName{"org.freedesktop.DBus.Properties"})
            .withArguments(std::string{kCard1Iface}, std::string{"Capabilities"})
            .storeResultsTo(caps);
        EXPECT_EQ(caps.get<std::uint32_t>(), 0x3u) << "Properties.Get failed for " << path;
    }

    clientConn->leaveEventLoop();
    serverConn->leaveEventLoop();
}

// --- Live ObjectManager signal path -----------------------------------------
//
// GetManagedObjects (the pull path) was covered above, but the ObjectManager
// contract ALSO requires that every object appearing in the tree is announced
// live via org.freedesktop.DBus.ObjectManager.InterfacesAdded and, on teardown,
// via InterfacesRemoved. sdbus-c++ serves GetManagedObjects automatically from
// its object registry but does NOT auto-emit these signals — the object must
// call emitInterfacesAddedSignal()/emitInterfacesRemovedSignal() itself. Without
// them a client that relies on live discovery (the LibreKDE plasmoid /
// AgentClient) never learns a freshly inserted card is reachable until it
// re-runs GetManagedObjects by hand. These tests exercise that signal path with
// a real client subscribed over a private bus.

namespace {
// Poll a predicate up to `timeout`, letting the async event loops make progress.
template <typename Pred>
bool waitFor(Pred pred, std::chrono::milliseconds timeout = std::chrono::milliseconds(2000))
{
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline) {
        if (pred()) {
            return true;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    return pred();
}
} // namespace

TEST(DBusService, EmitsInterfacesAddedWhenReaderMaterialises)
{
    std::shared_ptr<sdbus::IConnection> serverConn = sdbus::createSessionBusConnection();
    ASSERT_NE(serverConn, nullptr) << "private session bus (run under dbus-run-session)";
    serverConn->requestName(sdbus::ServiceName{"org.librescrs.Agent.Test.IfaceAddReader"});

    ObjectRegistry registry;
    FakeResolver resolver;
    PresenceModel model(registry, resolver);
    LibreSCRS::Agent::Operations::OperationManager opManager;
    auto prompter = std::make_shared<NopPrompter>();
    auto serializer = std::make_shared<LibreSCRS::Agent::Operations::PromptSerializer>();
    auto credCache = std::make_shared<CredentialCache>();
    CardReadCache readCache;
    Config::ConfigStore cfg(testCfgDir("dbus-ifadd-reader") / "agent.conf", testCfgDir("dbus-ifadd-reader") / "cache");
    LibreSCRS::Agent::Operations::SigningEngineProvider signingEngine(cfg);
    AllowAllAuthorizer authz;
    LibreSCRS::Agent::Operations::RateLimiter rateLimiter;
    BusExporter exporter(*serverConn, registry);
    auto cryptoCtx = std::make_shared<CryptoWorkerContext>(
        CryptoWorkerContext{.prompter = prompter, .serializer = serializer, .credentials = credCache});
    AgentFrontend frontend(exporter, serverConn, opManager, cryptoCtx, readCache, signingEngine, authz, rateLimiter,
                           cfg, nullptr, "test");
    serverConn->enterEventLoopAsync();

    auto clientConn = sdbus::createSessionBusConnection();
    clientConn->enterEventLoopAsync();
    auto rootProxy = sdbus::createProxy(*clientConn, sdbus::ServiceName{"org.librescrs.Agent.Test.IfaceAddReader"},
                                        sdbus::ObjectPath{kRootPath});

    std::mutex m;
    std::set<std::string> added;
    rootProxy->uponSignal(sdbus::SignalName{"InterfacesAdded"})
        .onInterface(sdbus::InterfaceName{"org.freedesktop.DBus.ObjectManager"})
        .call([&](const sdbus::ObjectPath& path, const std::map<std::string, std::map<std::string, sdbus::Variant>>&) {
            const std::lock_guard lk(m);
            added.insert(path);
        });

    // Synchronous round-trip AFTER subscribing: guarantees the AddMatch has been
    // processed by the bus before we drive the insert, so the emission below
    // cannot race the subscription.
    ManagedObjects seed;
    rootProxy->callMethod("GetManagedObjects")
        .onInterface(sdbus::InterfaceName{"org.freedesktop.DBus.ObjectManager"})
        .storeResultsTo(seed);

    model.onReaderAdded("R0"); // reader id 1 -> /org/librescrs/Agent/reader/1

    const bool sawReader = waitFor([&] {
        const std::lock_guard lk(m);
        return added.contains(kReader0Path);
    });
    EXPECT_TRUE(sawReader) << "InterfacesAdded was never emitted for the materialised reader";

    clientConn->leaveEventLoop();
    serverConn->leaveEventLoop();
}

TEST(DBusService, EmitsInterfacesAddedWhenCardMaterialises)
{
    std::shared_ptr<sdbus::IConnection> serverConn = sdbus::createSessionBusConnection();
    ASSERT_NE(serverConn, nullptr) << "private session bus (run under dbus-run-session)";
    serverConn->requestName(sdbus::ServiceName{"org.librescrs.Agent.Test.IfaceAddCard"});

    ObjectRegistry registry;
    FakeResolver resolver;
    PresenceModel model(registry, resolver);
    LibreSCRS::Agent::Operations::OperationManager opManager;
    auto prompter = std::make_shared<NopPrompter>();
    auto serializer = std::make_shared<LibreSCRS::Agent::Operations::PromptSerializer>();
    auto credCache = std::make_shared<CredentialCache>();
    CardReadCache readCache;
    Config::ConfigStore cfg(testCfgDir("dbus-ifadd-card") / "agent.conf", testCfgDir("dbus-ifadd-card") / "cache");
    LibreSCRS::Agent::Operations::SigningEngineProvider signingEngine(cfg);
    AllowAllAuthorizer authz;
    LibreSCRS::Agent::Operations::RateLimiter rateLimiter;
    BusExporter exporter(*serverConn, registry);
    auto cryptoCtx = std::make_shared<CryptoWorkerContext>(
        CryptoWorkerContext{.prompter = prompter, .serializer = serializer, .credentials = credCache});
    AgentFrontend frontend(exporter, serverConn, opManager, cryptoCtx, readCache, signingEngine, authz, rateLimiter,
                           cfg, nullptr, "test");
    serverConn->enterEventLoopAsync();

    auto clientConn = sdbus::createSessionBusConnection();
    clientConn->enterEventLoopAsync();
    auto rootProxy = sdbus::createProxy(*clientConn, sdbus::ServiceName{"org.librescrs.Agent.Test.IfaceAddCard"},
                                        sdbus::ObjectPath{kRootPath});

    std::mutex m;
    std::set<std::string> added;
    std::map<std::string, bool> hadCard1;
    rootProxy->uponSignal(sdbus::SignalName{"InterfacesAdded"})
        .onInterface(sdbus::InterfaceName{"org.freedesktop.DBus.ObjectManager"})
        .call([&](const sdbus::ObjectPath& path,
                  const std::map<std::string, std::map<std::string, sdbus::Variant>>& ifaces) {
            const std::lock_guard lk(m);
            added.insert(path);
            hadCard1[path] = ifaces.contains(kCard1Iface);
        });

    ManagedObjects seed;
    rootProxy->callMethod("GetManagedObjects")
        .onInterface(sdbus::InterfaceName{"org.freedesktop.DBus.ObjectManager"})
        .storeResultsTo(seed);

    model.onReaderAdded("R0");                // reader id 1
    model.onCardInserted("R0", {0x3B, 0x01}); // card id 2 -> /org/librescrs/Agent/card/2

    const bool sawCard = waitFor([&] {
        const std::lock_guard lk(m);
        return added.contains(kCard0Path);
    });
    ASSERT_TRUE(sawCard) << "InterfacesAdded was never emitted for the inserted card";
    {
        const std::lock_guard lk(m);
        EXPECT_TRUE(hadCard1[kCard0Path]) << "the card's InterfacesAdded payload must carry the Card1 interface";
    }

    clientConn->leaveEventLoop();
    serverConn->leaveEventLoop();
}

TEST(DBusService, EmitsInterfacesRemovedWhenCardWithdrawn)
{
    std::shared_ptr<sdbus::IConnection> serverConn = sdbus::createSessionBusConnection();
    ASSERT_NE(serverConn, nullptr) << "private session bus (run under dbus-run-session)";
    serverConn->requestName(sdbus::ServiceName{"org.librescrs.Agent.Test.IfaceRemoveCard"});

    ObjectRegistry registry;
    FakeResolver resolver;
    PresenceModel model(registry, resolver);
    LibreSCRS::Agent::Operations::OperationManager opManager;
    auto prompter = std::make_shared<NopPrompter>();
    auto serializer = std::make_shared<LibreSCRS::Agent::Operations::PromptSerializer>();
    auto credCache = std::make_shared<CredentialCache>();
    CardReadCache readCache;
    Config::ConfigStore cfg(testCfgDir("dbus-ifremove-card") / "agent.conf",
                            testCfgDir("dbus-ifremove-card") / "cache");
    LibreSCRS::Agent::Operations::SigningEngineProvider signingEngine(cfg);
    AllowAllAuthorizer authz;
    LibreSCRS::Agent::Operations::RateLimiter rateLimiter;
    BusExporter exporter(*serverConn, registry);
    auto cryptoCtx = std::make_shared<CryptoWorkerContext>(
        CryptoWorkerContext{.prompter = prompter, .serializer = serializer, .credentials = credCache});
    AgentFrontend frontend(exporter, serverConn, opManager, cryptoCtx, readCache, signingEngine, authz, rateLimiter,
                           cfg, nullptr, "test");
    serverConn->enterEventLoopAsync();

    auto clientConn = sdbus::createSessionBusConnection();
    clientConn->enterEventLoopAsync();
    auto rootProxy = sdbus::createProxy(*clientConn, sdbus::ServiceName{"org.librescrs.Agent.Test.IfaceRemoveCard"},
                                        sdbus::ObjectPath{kRootPath});

    std::mutex m;
    std::set<std::string> removed;
    rootProxy->uponSignal(sdbus::SignalName{"InterfacesRemoved"})
        .onInterface(sdbus::InterfaceName{"org.freedesktop.DBus.ObjectManager"})
        .call([&](const sdbus::ObjectPath& path, const std::vector<std::string>&) {
            const std::lock_guard lk(m);
            removed.insert(path);
        });

    // Insert the card first (synchronous materialisation), then confirm it is on
    // the bus, so the removal below is the isolated behaviour under test.
    model.onReaderAdded("R0");
    model.onCardInserted("R0", {0x3B, 0x01}); // card id 2
    ManagedObjects seed;
    rootProxy->callMethod("GetManagedObjects")
        .onInterface(sdbus::InterfaceName{"org.freedesktop.DBus.ObjectManager"})
        .storeResultsTo(seed);
    ASSERT_TRUE(seed.contains(sdbus::ObjectPath{kCard0Path})) << "precondition: the card must be exported";

    model.onCardRemoved("R0"); // withdraws the Card1 object -> InterfacesRemoved

    const bool sawRemoved = waitFor([&] {
        const std::lock_guard lk(m);
        return removed.contains(kCard0Path);
    });
    EXPECT_TRUE(sawRemoved) << "InterfacesRemoved was never emitted for the withdrawn card";

    clientConn->leaveEventLoop();
    serverConn->leaveEventLoop();
}

TEST(DBusService, NameConflictRequestNameThrows)
{
    constexpr const char* contestedName = "org.librescrs.Agent.Test.Contested";

    auto firstHolder = sdbus::createSessionBusConnection();
    ASSERT_NE(firstHolder, nullptr);
    firstHolder->requestName(sdbus::ServiceName{contestedName});
    firstHolder->enterEventLoopAsync();

    auto challenger = sdbus::createSessionBusConnection();
    EXPECT_THROW(challenger->requestName(sdbus::ServiceName{contestedName}), sdbus::Error)
        << "second request for an already-held name must surface a D-Bus error";

    firstHolder->leaveEventLoop();
}
