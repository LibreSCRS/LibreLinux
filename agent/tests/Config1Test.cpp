// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Config1 end-to-end over a private session bus (dbus-run-session): property
// reads, SetValue/Reset with the per-key mutability + polkit gate, the typed
// rejections (UnknownConfigKey / ReadOnlyConfig / InvalidConfigValue /
// NotAuthorized), the a(sbb) TslSources round-trip, and the Changed signal.
#include "AllowAllAuthorizer.h" // test support: grants every action
#include <LibreSCRS/Agent/backend/Authorizer.h>
#include <LibreSCRS/Agent/config/ConfigStore.h>
#include <LibreSCRS/Agent/operations/RateLimiter.h>
#include "dbus/ManagerObject.h"
#include <sdbus-c++/sdbus-c++.h>
#include <gtest/gtest.h>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <string>
#include <thread>
#include <tuple>
#include <vector>

using namespace LibreSCRS::Agent;
namespace fs = std::filesystem;

namespace {
constexpr const char* kRootPath = "/org/librescrs/Agent";
constexpr const char* kCfgIface = "org.librescrs.Agent.Config1";
constexpr const char* kProps = "org.freedesktop.DBus.Properties";

class DenyAuthorizer final : public Authorizer
{
public:
    AuthorizationOutcome authorize(std::string_view, const CallerToken&) override
    {
        return AuthorizationOutcome::Denied;
    }
};

fs::path uniqueCfgDir(const char* tag)
{
    return fs::temp_directory_path() / (std::string{"ll-config1test-"} + tag);
}

std::string getStrProp(sdbus::IProxy& proxy, const char* prop)
{
    sdbus::Variant v;
    proxy.callMethod("Get")
        .onInterface(sdbus::InterfaceName{kProps})
        .withArguments(std::string{kCfgIface}, std::string{prop})
        .storeResultsTo(v);
    return v.get<std::string>();
}

// Drive SetValue and capture the rejection error name (empty == no throw).
std::string setValueErrorName(sdbus::IProxy& proxy, const std::string& key, const sdbus::Variant& value)
{
    try {
        proxy.callMethod("SetValue").onInterface(sdbus::InterfaceName{kCfgIface}).withArguments(key, value);
        return {};
    } catch (const sdbus::Error& e) {
        return e.getName();
    }
}
} // namespace

TEST(Config1, GetSetResetAndValidation)
{
    const auto dir = uniqueCfgDir("main");
    fs::remove_all(dir);
    auto serverConn = sdbus::createSessionBusConnection();
    ASSERT_NE(serverConn, nullptr) << "run under dbus-run-session";
    const char* svc = "org.librescrs.Agent.Test.Config";
    serverConn->requestName(sdbus::ServiceName{svc});
    Config::ConfigStore cfg(dir / "agent.conf", dir / "cache");
    AllowAllAuthorizer authz;
    Operations::RateLimiter limiter;
    ManagerObject manager(*serverConn, sdbus::ObjectPath{kRootPath}, "t", cfg, authz, limiter, nullptr);
    serverConn->enterEventLoopAsync();

    auto clientConn = sdbus::createSessionBusConnection();
    clientConn->enterEventLoopAsync();
    auto proxy = sdbus::createProxy(*clientConn, sdbus::ServiceName{svc}, sdbus::ObjectPath{kRootPath});

    EXPECT_EQ(getStrProp(*proxy, "DefaultLevel"), "b-b");

    // Valid mutation.
    EXPECT_EQ(setValueErrorName(*proxy, "DefaultLevel", sdbus::Variant{std::string{"b-t"}}), "");
    EXPECT_EQ(getStrProp(*proxy, "DefaultLevel"), "b-t");

    // Invalid value + wrong variant type both -> InvalidConfigValue.
    EXPECT_EQ(setValueErrorName(*proxy, "DefaultLevel", sdbus::Variant{std::string{"nope"}}),
              "org.librescrs.Agent.Error.InvalidConfigValue");
    EXPECT_EQ(setValueErrorName(*proxy, "DefaultLevel", sdbus::Variant{std::uint32_t{42}}),
              "org.librescrs.Agent.Error.InvalidConfigValue");

    // File-only (TslCacheDir) + read-only (LastTsaUrl) -> ReadOnlyConfig.
    EXPECT_EQ(setValueErrorName(*proxy, "TslCacheDir", sdbus::Variant{std::string{"/evil/tsl"}}),
              "org.librescrs.Agent.Error.ReadOnlyConfig");
    EXPECT_EQ(setValueErrorName(*proxy, "LastTsaUrl", sdbus::Variant{std::string{"https://x"}}),
              "org.librescrs.Agent.Error.ReadOnlyConfig");
    // CscaCacheDir is file-only too, and it is rejected WITHOUT a branch of its
    // own anywhere in this repo: SetValue consults ConfigStore::mutability()
    // and throws before the dispatch chain below it ever compares key names.
    // The store's classification IS the implementation; this asserts that,
    // rather than a comment claiming it.
    EXPECT_EQ(setValueErrorName(*proxy, "CscaCacheDir", sdbus::Variant{std::string{"/evil/anchors"}}),
              "org.librescrs.Agent.Error.ReadOnlyConfig");
    // Reset() repeats the same guard, so it must refuse the key too.
    try {
        proxy->callMethod("Reset")
            .onInterface(sdbus::InterfaceName{kCfgIface})
            .withArguments(std::string{"CscaCacheDir"});
        ADD_FAILURE() << "expected ReadOnlyConfig on Reset(CscaCacheDir)";
    } catch (const sdbus::Error& e) {
        EXPECT_EQ(e.getName(), "org.librescrs.Agent.Error.ReadOnlyConfig");
    }

    // Unknown key.
    EXPECT_EQ(setValueErrorName(*proxy, "Bogus", sdbus::Variant{std::string{"x"}}),
              "org.librescrs.Agent.Error.UnknownConfigKey");

    // TslSources a(sbb) round-trip.
    std::vector<sdbus::Struct<std::string, bool, bool>> tsl{
        sdbus::Struct<std::string, bool, bool>{"https://tl/lotl", true, true}};
    EXPECT_EQ(setValueErrorName(*proxy, "TslSources", sdbus::Variant{tsl}), "");
    sdbus::Variant got;
    proxy->callMethod("Get")
        .onInterface(sdbus::InterfaceName{kProps})
        .withArguments(std::string{kCfgIface}, std::string{"TslSources"})
        .storeResultsTo(got);
    auto vec = got.get<std::vector<sdbus::Struct<std::string, bool, bool>>>();
    ASSERT_EQ(vec.size(), 1u);
    EXPECT_EQ(std::get<0>(vec[0]), "https://tl/lotl");
    EXPECT_TRUE(std::get<1>(vec[0]));
    EXPECT_TRUE(std::get<2>(vec[0]));

    // Reset returns to the default.
    proxy->callMethod("Reset").onInterface(sdbus::InterfaceName{kCfgIface}).withArguments(std::string{"DefaultLevel"});
    EXPECT_EQ(getStrProp(*proxy, "DefaultLevel"), "b-b");

    clientConn->leaveEventLoop();
    serverConn->leaveEventLoop();
    fs::remove_all(dir);
}

TEST(Config1, ChangedSignalFires)
{
    const auto dir = uniqueCfgDir("signal");
    fs::remove_all(dir);
    auto serverConn = sdbus::createSessionBusConnection();
    ASSERT_NE(serverConn, nullptr);
    const char* svc = "org.librescrs.Agent.Test.ConfigSig";
    serverConn->requestName(sdbus::ServiceName{svc});
    Config::ConfigStore cfg(dir / "agent.conf", dir / "cache");
    AllowAllAuthorizer authz;
    Operations::RateLimiter limiter;
    ManagerObject manager(*serverConn, sdbus::ObjectPath{kRootPath}, "t", cfg, authz, limiter, nullptr);
    // AgentService wires this in production; replicate so the mutation emits Changed.
    cfg.setOnChanged([&](const std::string& key) { manager.emitConfigChanged(key); });
    serverConn->enterEventLoopAsync();

    auto clientConn = sdbus::createSessionBusConnection();
    clientConn->enterEventLoopAsync();
    std::atomic<bool> got{false};
    std::string gotKey;
    auto proxy = sdbus::createProxy(*clientConn, sdbus::ServiceName{svc}, sdbus::ObjectPath{kRootPath});
    proxy->uponSignal("Changed").onInterface(sdbus::InterfaceName{kCfgIface}).call([&](const std::string& key) {
        gotKey = key;
        got.store(true, std::memory_order_release);
    });
    std::this_thread::sleep_for(std::chrono::milliseconds(100)); // let the match rule propagate

    proxy->callMethod("SetValue")
        .onInterface(sdbus::InterfaceName{kCfgIface})
        .withArguments(std::string{"DefaultReason"}, sdbus::Variant{std::string{"because"}});

    for (int i = 0; i < 100 && !got.load(std::memory_order_acquire); ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    EXPECT_TRUE(got.load(std::memory_order_acquire));
    EXPECT_EQ(gotKey, "DefaultReason");

    clientConn->leaveEventLoop();
    serverConn->leaveEventLoop();
    fs::remove_all(dir);
}

TEST(Config1, DeniedAuthorizerRejectsSetValueAndReset)
{
    const auto dir = uniqueCfgDir("deny");
    fs::remove_all(dir);
    auto serverConn = sdbus::createSessionBusConnection();
    ASSERT_NE(serverConn, nullptr);
    const char* svc = "org.librescrs.Agent.Test.ConfigDeny";
    serverConn->requestName(sdbus::ServiceName{svc});
    Config::ConfigStore cfg(dir / "agent.conf", dir / "cache");
    DenyAuthorizer deny;
    Operations::RateLimiter limiter;
    ManagerObject manager(*serverConn, sdbus::ObjectPath{kRootPath}, "t", cfg, deny, limiter, nullptr);
    serverConn->enterEventLoopAsync();

    auto clientConn = sdbus::createSessionBusConnection();
    clientConn->enterEventLoopAsync();
    auto proxy = sdbus::createProxy(*clientConn, sdbus::ServiceName{svc}, sdbus::ObjectPath{kRootPath});

    EXPECT_EQ(setValueErrorName(*proxy, "DefaultLevel", sdbus::Variant{std::string{"b-t"}}),
              "org.librescrs.Agent.Error.NotAuthorized");
    EXPECT_EQ(getStrProp(*proxy, "DefaultLevel"), "b-b"); // unchanged

    // Reset is gated the same way.
    try {
        proxy->callMethod("Reset")
            .onInterface(sdbus::InterfaceName{kCfgIface})
            .withArguments(std::string{"DefaultLevel"});
        ADD_FAILURE() << "expected NotAuthorized on Reset";
    } catch (const sdbus::Error& e) {
        EXPECT_EQ(e.getName(), "org.librescrs.Agent.Error.NotAuthorized");
    }

    clientConn->leaveEventLoop();
    serverConn->leaveEventLoop();
    fs::remove_all(dir);
}

// Locks the per-key polkit action mapping under the PRODUCTION default
// authorizer: the configure tier is allowed, the configure.trust tier
// (TsaUrls/TslSources) is fail-closed until real polkit arrives.
TEST(Config1, TrustTierFailsClosedUnderDefaultAuthorizer)
{
    const auto dir = uniqueCfgDir("trusttier");
    fs::remove_all(dir);
    auto serverConn = sdbus::createSessionBusConnection();
    ASSERT_NE(serverConn, nullptr);
    const char* svc = "org.librescrs.Agent.Test.ConfigTrust";
    serverConn->requestName(sdbus::ServiceName{svc});
    Config::ConfigStore cfg(dir / "agent.conf", dir / "cache");
    DefaultAuthorizer authz; // configure allowed, configure.trust denied
    Operations::RateLimiter limiter;
    ManagerObject manager(*serverConn, sdbus::ObjectPath{kRootPath}, "t", cfg, authz, limiter, nullptr);
    serverConn->enterEventLoopAsync();

    auto clientConn = sdbus::createSessionBusConnection();
    clientConn->enterEventLoopAsync();
    auto proxy = sdbus::createProxy(*clientConn, sdbus::ServiceName{svc}, sdbus::ObjectPath{kRootPath});

    // configure tier — allowed.
    EXPECT_EQ(setValueErrorName(*proxy, "DefaultLevel", sdbus::Variant{std::string{"b-t"}}), "");
    EXPECT_EQ(getStrProp(*proxy, "DefaultLevel"), "b-t");

    const auto readTslSources = [&proxy] {
        sdbus::Variant v;
        proxy->callMethod("Get")
            .onInterface(sdbus::InterfaceName{kProps})
            .withArguments(std::string{kCfgIface}, std::string{"TslSources"})
            .storeResultsTo(v);
        return v.get<std::vector<sdbus::Struct<std::string, bool, bool>>>();
    };
    const auto seeded = readTslSources();

    // configure.trust tier (TsaUrls/TslSources) — fail-closed.
    EXPECT_EQ(setValueErrorName(*proxy, "TsaUrls", sdbus::Variant{std::vector<std::string>{"https://tsa"}}),
              "org.librescrs.Agent.Error.NotAuthorized");
    std::vector<sdbus::Struct<std::string, bool, bool>> tsl{
        sdbus::Struct<std::string, bool, bool>{"https://tl", false, false}};
    EXPECT_EQ(setValueErrorName(*proxy, "TslSources", sdbus::Variant{tsl}), "org.librescrs.Agent.Error.NotAuthorized");
    // Refused before the value is looked at: a well-formed source set changes
    // nothing without the trust-tier grant.
    EXPECT_EQ(readTslSources(), seeded);
    // Reset is gated on the same action.
    try {
        proxy->callMethod("Reset")
            .onInterface(sdbus::InterfaceName{kCfgIface})
            .withArguments(std::string{"TslSources"});
        ADD_FAILURE() << "expected NotAuthorized on Reset(TslSources)";
    } catch (const sdbus::Error& e) {
        EXPECT_EQ(e.getName(), "org.librescrs.Agent.Error.NotAuthorized");
    }

    clientConn->leaveEventLoop();
    serverConn->leaveEventLoop();
    fs::remove_all(dir);
}
