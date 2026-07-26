// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// End-to-end: client -> Card1.ReadIdentity / GetPhoto.
//
// Covers the capability gate (UnsupportedOnThisCard when the IdentityData
// bit is clear) and the enqueue path (a valid Operation path is returned
// when the bit is set and seam deps are wired). The Operation that the
// enqueue path constructs is not exercised here -- the per-Operation flow
// has dedicated tests (ReadIdentityOperationTest, GetPhotoOperationTest)
// and CardOperationsIntegrationTest covers the run-through.

#include <LibreSCRS/Agent/backend/Authorizer.h>
#include "BusExporter.h"
#include <LibreSCRS/Agent/presence/CapabilityResolver.h>
#include <LibreSCRS/Agent/cache/CardReadCache.h>
#include <LibreSCRS/Agent/cache/CredentialCache.h>
#include <LibreSCRS/Agent/presence/ObjectRegistry.h>
#include <LibreSCRS/Agent/presence/PresenceModel.h>
#include <LibreSCRS/Agent/config/ConfigStore.h>
#include "dbus/CardObject.h"
#include <LibreSCRS/Agent/operations/BatchSignFlow.h> // isValidBatchDocumentCount
#include <LibreSCRS/Agent/operations/OperationManager.h>
#include <LibreSCRS/Agent/operations/PromptSerializer.h>
#include <LibreSCRS/Agent/operations/RateLimiter.h>
#include <LibreSCRS/Agent/operations/Seams.h>

#include <LibreSCRS/Plugin/PluginTypes.h>
#include <LibreSCRS/SmartCard/CardSession.h>

#include <sdbus-c++/sdbus-c++.h>
#include <gtest/gtest.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <limits>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>

using namespace LibreSCRS::Agent;
using namespace LibreSCRS::Agent::Operations;
using namespace std::chrono_literals;

namespace {

// Trivially-failing seams: the capability-gate test never reaches them; the
// enqueue test only needs them to be non-null for the dep-completeness check.
// The Operation that runs against these will finish in error, but that path
// is exercised in ReadIdentityOperationTest / GetPhotoOperationTest. Here we
// only assert that ReadIdentity / GetPhoto return a valid path -- meaning
// the capability gate passed and enqueueIdentity / enqueuePhoto returned.

class FailingReader final : public CardReader
{
public:
    ReadOutcome read(LibreSCRS::SmartCard::CardSession& /*session*/, const CandidateList& /*candidates*/,
                     LibreSCRS::CancelToken /*token*/, GroupReadCallback /*onGroup*/ = {}) override
    {
        return ReadOutcome{ReadOutcome::Status::CommunicationError, std::nullopt, "test"};
    }
    // Not exercised by this suite; a well-formed default keeps this class
    // non-abstract.
    GroupSnapshot readTokenInfo(LibreSCRS::SmartCard::CardSession& /*session*/, const CandidateList& /*candidates*/,
                                LibreSCRS::CancelToken /*token*/) override
    {
        return {};
    }
};

class NopPrompter final : public PrompterClientBase
{
public:
    PromptResult requestPin(const PromptOptions& /*options*/) override
    {
        return PromptResult{PromptStatus::Cancelled, {}, {}};
    }
    PromptResult requestCan(const PromptOptions& /*options*/) override
    {
        return PromptResult{PromptStatus::Cancelled, {}, {}};
    }
    PromptResult requestMrz(const PromptOptions& /*options*/) override
    {
        return PromptResult{PromptStatus::Cancelled, {}, {}};
    }
};

constexpr const char* kReaderPath = "/org/librescrs/Agent/reader/0";
constexpr const char* kCardPath = "/org/librescrs/Agent/card/0";
constexpr const char* kCard1Iface = "org.librescrs.Agent.Card1";

CardOperationDeps makeDeps(CardReader& reader, PrompterClientBase& prompter, PromptSerializer& serializer,
                           CredentialCache& credentials, CardReadCache& readCache)
{
    CardOperationDeps deps;
    deps.reader = &reader;
    deps.prompter = &prompter;
    deps.serializer = &serializer;
    deps.credentials = &credentials;
    deps.readCache = &readCache;
    deps.cardKey = kCardPath;
    deps.readerName = "R0";
    return deps;
}

// A Signer that records nothing and never runs: the Sign tests here exercise
// only the Card1.Sign method-entry resolution + scope gate, which reject (or
// accept-then-enqueue) BEFORE any signer call on the worker. It only needs to
// be non-null so hasSignSeams() passes.
class StubSigner final : public Signer
{
public:
    SignOutcome sign(const std::shared_ptr<LibreSCRS::SmartCard::CardSession>&, const SignParams& params,
                     const CandidateList&, LibreSCRS::Auth::CredentialProvider, LibreSCRS::CancelToken) override
    {
        captured = params;
        SignOutcome o;
        o.status = SignOutcome::Status::CommunicationError;
        return o;
    }

    // Captures the effective SignParams (incl. tsaUrl/visual) that
    // reached the Signer seam, so a test asserting Card1.Sign's method-entry
    // parsing built the right values does not need to touch LmSigner/LM at
    // all — mirrors SignFlowTest.cpp's own FakeSigner::captured.
    std::optional<SignParams> captured;
};

// Build a memfd holding @p bytes, rewound to offset 0 — a regular (seekable) fd
// the Sign method accepts (pipes/sockets are rejected as NotRegular).
int makeInputMemfd(std::string_view bytes)
{
    const int fd = ::memfd_create("librescrs-sign-input", MFD_CLOEXEC);
    if (fd < 0) {
        return -1;
    }
    std::size_t off = 0;
    while (off < bytes.size()) {
        const ssize_t n = ::write(fd, bytes.data() + off, bytes.size() - off);
        if (n <= 0) {
            ::close(fd);
            return -1;
        }
        off += static_cast<std::size_t>(n);
    }
    ::lseek(fd, 0, SEEK_SET);
    return fd;
}

// Full sign-seam bundle: the shared read plumbing plus the sign-only deps
// (signer + authorizer + rate-limiter + config SSOT). hasSignSeams() requires
// every one of these non-null.
CardOperationDeps makeSignDeps(CardReader& reader, PrompterClientBase& prompter, PromptSerializer& serializer,
                               CredentialCache& credentials, CardReadCache& readCache, Signer& signer,
                               Authorizer& authorizer, RateLimiter& rateLimiter, Config::ConfigStore& config)
{
    auto deps = makeDeps(reader, prompter, serializer, credentials, readCache);
    deps.signer = &signer;
    deps.authorizer = &authorizer;
    deps.rateLimiter = &rateLimiter;
    deps.config = &config;
    return deps;
}

} // namespace

TEST(CardObjectOperations, ReadIdentityWithoutCapabilityThrowsUnsupported)
{
    auto serverConn = sdbus::createSessionBusConnection();
    ASSERT_NE(serverConn, nullptr) << "run under dbus-run-session";
    serverConn->requestName(sdbus::ServiceName{"org.librescrs.Agent.Test.NoCapa"});

    OperationManager mgr(nullptr); // production (cleanup-grace) mode; no resolver
    FailingReader reader;
    NopPrompter prompter;
    CredentialCache credentials;
    CardReadCache readCache;
    PromptSerializer serializer;
    auto deps = makeDeps(reader, prompter, serializer, credentials, readCache);

    // capabilities == 0 -> IdentityData bit is clear -> gate must fire.
    CardObject card(*serverConn, sdbus::ObjectPath{kCardPath}, 0u, sdbus::ObjectPath{kReaderPath}, mgr,
                    std::move(deps));

    serverConn->enterEventLoopAsync();

    auto clientConn = sdbus::createSessionBusConnection();
    clientConn->enterEventLoopAsync();
    auto proxy = sdbus::createProxy(*clientConn, sdbus::ServiceName{"org.librescrs.Agent.Test.NoCapa"},
                                    sdbus::ObjectPath{kCardPath});
    sdbus::ObjectPath unused;
    try {
        proxy->callMethod("ReadIdentity").onInterface(sdbus::InterfaceName{kCard1Iface}).storeResultsTo(unused);
        FAIL() << "expected UnsupportedOnThisCard";
    } catch (const sdbus::Error& e) {
        EXPECT_EQ(e.getName(), "org.librescrs.Agent.Error.UnsupportedOnThisCard");
    }

    clientConn->leaveEventLoop();
    serverConn->leaveEventLoop();
}

TEST(CardObjectOperations, GetPhotoWithoutCapabilityThrowsUnsupported)
{
    auto serverConn = sdbus::createSessionBusConnection();
    ASSERT_NE(serverConn, nullptr);
    serverConn->requestName(sdbus::ServiceName{"org.librescrs.Agent.Test.NoCapa.Photo"});

    OperationManager mgr(nullptr); // production (cleanup-grace) mode; no resolver
    FailingReader reader;
    NopPrompter prompter;
    CredentialCache credentials;
    CardReadCache readCache;
    PromptSerializer serializer;
    auto deps = makeDeps(reader, prompter, serializer, credentials, readCache);

    CardObject card(*serverConn, sdbus::ObjectPath{kCardPath}, 0u, sdbus::ObjectPath{kReaderPath}, mgr,
                    std::move(deps));

    serverConn->enterEventLoopAsync();
    auto clientConn = sdbus::createSessionBusConnection();
    clientConn->enterEventLoopAsync();
    auto proxy = sdbus::createProxy(*clientConn, sdbus::ServiceName{"org.librescrs.Agent.Test.NoCapa.Photo"},
                                    sdbus::ObjectPath{kCardPath});
    sdbus::ObjectPath unused;
    try {
        proxy->callMethod("GetPhoto").onInterface(sdbus::InterfaceName{kCard1Iface}).storeResultsTo(unused);
        FAIL() << "expected UnsupportedOnThisCard";
    } catch (const sdbus::Error& e) {
        EXPECT_EQ(e.getName(), "org.librescrs.Agent.Error.UnsupportedOnThisCard");
    }

    clientConn->leaveEventLoop();
    serverConn->leaveEventLoop();
}

TEST(CardObjectOperations, ReadIdentityWithCapabilityReturnsOperationPath)
{
    auto serverConn = sdbus::createSessionBusConnection();
    ASSERT_NE(serverConn, nullptr);
    serverConn->requestName(sdbus::ServiceName{"org.librescrs.Agent.Test.WithCapa"});

    OperationManager mgr(nullptr); // production (cleanup-grace) mode; no resolver
    FailingReader reader;
    NopPrompter prompter;
    CredentialCache credentials;
    CardReadCache readCache;
    PromptSerializer serializer;
    auto deps = makeDeps(reader, prompter, serializer, credentials, readCache);

    // capabilities == IdentityData (bit 1) -> gate passes -> enqueue runs.
    constexpr std::uint32_t kIdentityBit =
        static_cast<std::uint32_t>(LibreSCRS::Plugin::CardCapabilities::IdentityData);
    CardObject card(*serverConn, sdbus::ObjectPath{kCardPath}, kIdentityBit, sdbus::ObjectPath{kReaderPath}, mgr,
                    std::move(deps));

    serverConn->enterEventLoopAsync();
    auto clientConn = sdbus::createSessionBusConnection();
    clientConn->enterEventLoopAsync();
    auto proxy = sdbus::createProxy(*clientConn, sdbus::ServiceName{"org.librescrs.Agent.Test.WithCapa"},
                                    sdbus::ObjectPath{kCardPath});

    sdbus::ObjectPath opPath;
    proxy->callMethod("ReadIdentity").onInterface(sdbus::InterfaceName{kCard1Iface}).storeResultsTo(opPath);

    // Path shape contract: /org/librescrs/Agent/op/<n>.
    const std::string s{opPath};
    EXPECT_TRUE(s.starts_with("/org/librescrs/Agent/op/")) << "got " << s;

    // Give the worker a moment to start + finish in error against the
    // failing seams so the Operation lifecycle exercise is exhausted before
    // we tear the manager down (no leak detector here, but the dtor will
    // join the worker either way).
    std::this_thread::sleep_for(50ms);

    clientConn->leaveEventLoop();
    serverConn->leaveEventLoop();
}

// Token info is PKI-adjacent (pkcs15), so it shares ReadCertificates' PKI
// gate bit — without it, ReadTokenInfo throws UnsupportedOnThisCard at
// method entry (no Operation minted).
TEST(CardObjectOperations, ReadTokenInfoWithoutPkiCapabilityThrowsUnsupported)
{
    auto serverConn = sdbus::createSessionBusConnection();
    ASSERT_NE(serverConn, nullptr) << "run under dbus-run-session";
    serverConn->requestName(sdbus::ServiceName{"org.librescrs.Agent.Test.NoCapa.TokenInfo"});

    OperationManager mgr(nullptr); // production (cleanup-grace) mode; no resolver
    FailingReader reader;
    NopPrompter prompter;
    CredentialCache credentials;
    CardReadCache readCache;
    PromptSerializer serializer;
    auto deps = makeDeps(reader, prompter, serializer, credentials, readCache);

    // capabilities == 0 -> PKI bit is clear -> gate must fire.
    CardObject card(*serverConn, sdbus::ObjectPath{kCardPath}, 0u, sdbus::ObjectPath{kReaderPath}, mgr,
                    std::move(deps));

    serverConn->enterEventLoopAsync();
    auto clientConn = sdbus::createSessionBusConnection();
    clientConn->enterEventLoopAsync();
    auto proxy = sdbus::createProxy(*clientConn, sdbus::ServiceName{"org.librescrs.Agent.Test.NoCapa.TokenInfo"},
                                    sdbus::ObjectPath{kCardPath});
    sdbus::ObjectPath unused;
    try {
        proxy->callMethod("ReadTokenInfo").onInterface(sdbus::InterfaceName{kCard1Iface}).storeResultsTo(unused);
        FAIL() << "expected UnsupportedOnThisCard";
    } catch (const sdbus::Error& e) {
        EXPECT_EQ(e.getName(), "org.librescrs.Agent.Error.UnsupportedOnThisCard");
    }

    clientConn->leaveEventLoop();
    serverConn->leaveEventLoop();
}

TEST(CardObjectOperations, ReadTokenInfoWithPkiCapabilityReturnsOperationPath)
{
    auto serverConn = sdbus::createSessionBusConnection();
    ASSERT_NE(serverConn, nullptr);
    serverConn->requestName(sdbus::ServiceName{"org.librescrs.Agent.Test.WithCapa.TokenInfo"});

    OperationManager mgr(nullptr); // production (cleanup-grace) mode; no resolver
    FailingReader reader;
    NopPrompter prompter;
    CredentialCache credentials;
    CardReadCache readCache;
    PromptSerializer serializer;
    auto deps = makeDeps(reader, prompter, serializer, credentials, readCache);

    // capabilities == PKI (bit 0) -> gate passes -> enqueue runs.
    constexpr std::uint32_t kPkiBit = static_cast<std::uint32_t>(LibreSCRS::Plugin::CardCapabilities::PKI);
    CardObject card(*serverConn, sdbus::ObjectPath{kCardPath}, kPkiBit, sdbus::ObjectPath{kReaderPath}, mgr,
                    std::move(deps));

    serverConn->enterEventLoopAsync();
    auto clientConn = sdbus::createSessionBusConnection();
    clientConn->enterEventLoopAsync();
    auto proxy = sdbus::createProxy(*clientConn, sdbus::ServiceName{"org.librescrs.Agent.Test.WithCapa.TokenInfo"},
                                    sdbus::ObjectPath{kCardPath});

    sdbus::ObjectPath opPath;
    proxy->callMethod("ReadTokenInfo").onInterface(sdbus::InterfaceName{kCard1Iface}).storeResultsTo(opPath);

    const std::string s{opPath};
    EXPECT_TRUE(s.starts_with("/org/librescrs/Agent/op/")) << "got " << s;

    // Give the worker a moment to start + finish in error against the
    // failing seam (FailingReader) before we tear the manager down.
    std::this_thread::sleep_for(50ms);

    clientConn->leaveEventLoop();
    serverConn->leaveEventLoop();
}

// The per-reader backlog cap now lives in the core as the neutral QueueFull
// exception (OperationManager::publish); the Linux backend (CardObject) maps it
// onto the RateLimited wire error. Flooding one reader past the cap must surface
// that wire error to the client — the behaviour-preserving replacement for the
// old typed-enqueue path that threw sdbus::Error{RateLimited} directly.
TEST(CardObjectOperations, ReadIdentityFloodTripsBacklogCapAsRateLimited)
{
    auto serverConn = sdbus::createSessionBusConnection();
    ASSERT_NE(serverConn, nullptr) << "run under dbus-run-session";
    serverConn->requestName(sdbus::ServiceName{"org.librescrs.Agent.Test.Backlog"});

    OperationManager mgr(nullptr); // production (cleanup-grace) mode; no resolver

    // Wedge the per-reader worker on its first op so the queue can only grow: a
    // blocking SessionFactory parks the worker inside doWork()'s acquire() until
    // the test releases it. Set BEFORE any enqueue so the worker's lazily-built
    // holder captures it. The shared Gate is captured by value so it outlives the
    // worker even if it were detached.
    struct Gate
    {
        std::mutex m;
        std::condition_variable cv;
        bool released{false};
    };
    auto gate = std::make_shared<Gate>();
    mgr.setSessionFactoryForTest(
        [gate](const std::string& r)
            -> std::expected<std::shared_ptr<LibreSCRS::SmartCard::CardSession>, LibreSCRS::SmartCard::OpenError> {
            std::unique_lock lk(gate->m);
            gate->cv.wait(lk, [&] { return gate->released; });
            return LibreSCRS::SmartCard::detail::makeDetachedCardSession(r);
        });

    FailingReader reader;
    NopPrompter prompter;
    CredentialCache credentials;
    CardReadCache readCache;
    PromptSerializer serializer;
    auto deps = makeDeps(reader, prompter, serializer, credentials, readCache);

    constexpr std::uint32_t kIdentityBit =
        static_cast<std::uint32_t>(LibreSCRS::Plugin::CardCapabilities::IdentityData);
    CardObject card(*serverConn, sdbus::ObjectPath{kCardPath}, kIdentityBit, sdbus::ObjectPath{kReaderPath}, mgr,
                    std::move(deps));

    serverConn->enterEventLoopAsync();
    auto clientConn = sdbus::createSessionBusConnection();
    clientConn->enterEventLoopAsync();
    auto proxy = sdbus::createProxy(*clientConn, sdbus::ServiceName{"org.librescrs.Agent.Test.Backlog"},
                                    sdbus::ObjectPath{kCardPath});

    // The wedged worker never drains, so within a bounded number of calls one
    // trips the per-reader backlog cap; the backend maps the core's neutral
    // QueueFull onto the RateLimited wire error (behaviour-preserving).
    bool sawRateLimited = false;
    for (std::size_t i = 0; i < kMaxQueuedOpsPerReader + 8 && !sawRateLimited; ++i) {
        try {
            sdbus::ObjectPath opPath;
            proxy->callMethod("ReadIdentity").onInterface(sdbus::InterfaceName{kCard1Iface}).storeResultsTo(opPath);
        } catch (const sdbus::Error& e) {
            EXPECT_EQ(e.getName(), "org.librescrs.Agent.Error.RateLimited")
                << "unexpected error before the backlog cap: " << e.getName();
            sawRateLimited = true;
        }
    }
    EXPECT_TRUE(sawRateLimited) << "flooding past the per-reader backlog cap must surface RateLimited";

    // Release the wedged worker so it drains the queued ops (each fails fast
    // against the failing reader) and can be JOINED cleanly at mgr teardown.
    {
        std::lock_guard lk(gate->m);
        gate->released = true;
    }
    gate->cv.notify_all();
    std::this_thread::sleep_for(100ms);

    clientConn->leaveEventLoop();
    serverConn->leaveEventLoop();
}

// ---- Card1.Sign method-entry resolution + scope gate (B-T wiring) ----
//
// These pin the wire behaviour of the relaxed scope gate and the per-request
// level handling: a PKI card with the sign seams wired admits b-b/b-t, rejects
// the not-yet-produced long-term family, and rejects a non-string "level"
// variant — all BEFORE any Operation is minted (no card, no signer call). The
// leaf resolvers are unit-tested in SignatureParamsTest; this is the D-Bus
// method composing them.

namespace {

// A PKI-capable CardObject with the full sign-seam bundle, an empty-TSA config
// (so b-b is the default and b-t is opt-in per request), and a permissive
// authorizer + a fresh rate-limiter. The temp config dir is unique per @p tag.
struct SignFixture
{
    FailingReader reader;
    NopPrompter prompter;
    CredentialCache credentials;
    CardReadCache readCache;
    PromptSerializer serializer;
    StubSigner signer;
    AllowAllAuthorizer authorizer;
    RateLimiter rateLimiter;
    Config::ConfigStore config;

    explicit SignFixture(const char* tag)
        : config(std::filesystem::temp_directory_path() / (std::string{"ll-cardsign-"} + tag) / "agent.conf",
                 std::filesystem::temp_directory_path() / (std::string{"ll-cardsign-"} + tag) / "cache")
    {}

    CardOperationDeps deps()
    {
        return makeSignDeps(reader, prompter, serializer, credentials, readCache, signer, authorizer, rateLimiter,
                            config);
    }
};

constexpr std::uint32_t kPkiBit = static_cast<std::uint32_t>(LibreSCRS::Plugin::CardCapabilities::PKI);

// Drive Card1.Sign with a CAdES/DER input (0x30 leading byte => format sniffs to
// "cades") and the given options; returns the proxy call so the caller asserts
// the result or the thrown error. The fd is consumed by the call.
sdbus::ObjectPath callSign(sdbus::IProxy& proxy, int inputFd, const std::map<std::string, sdbus::Variant>& options)
{
    sdbus::ObjectPath opPath;
    proxy.callMethod("Sign")
        .onInterface(sdbus::InterfaceName{kCard1Iface})
        .withArguments(std::string{"deadbeefcert"}, sdbus::UnixFd{inputFd}, options)
        .storeResultsTo(opPath);
    return opPath;
}

} // namespace

TEST(CardObjectOperations, SignAdmitsLongTermLevelsAtTheScopeGate)
{
    auto serverConn = sdbus::createSessionBusConnection();
    ASSERT_NE(serverConn, nullptr) << "run under dbus-run-session";
    serverConn->requestName(sdbus::ServiceName{"org.librescrs.Agent.Test.SignGate"});

    OperationManager mgr(nullptr); // production (cleanup-grace) mode; no resolver
    SignFixture fix{"longterm"};
    CardObject card(*serverConn, sdbus::ObjectPath{kCardPath}, kPkiBit, sdbus::ObjectPath{kReaderPath}, mgr,
                    fix.deps());
    serverConn->enterEventLoopAsync();

    auto clientConn = sdbus::createSessionBusConnection();
    clientConn->enterEventLoopAsync();
    auto proxy = sdbus::createProxy(*clientConn, sdbus::ServiceName{"org.librescrs.Agent.Test.SignGate"},
                                    sdbus::ObjectPath{kCardPath});

    // The long-term family is now produced by the LM (TL chain completion +
    // revocation, failing closed when unavailable), so the scope gate admits it
    // and mints an Operation rather than rejecting at method entry. The LM-side
    // ChainIncomplete / RevocationFetchFailed outcomes surface on the Operation,
    // not as a method-entry UnsupportedSignatureParameter.
    for (const char* level : {"b-lt", "b-lta"}) {
        const int fd = makeInputMemfd(std::string_view{"\x30\x82\x01\x00", 4});
        ASSERT_GE(fd, 0);
        const auto opPath = callSign(*proxy, fd, {{"level", sdbus::Variant{std::string{level}}}});
        EXPECT_TRUE(std::string{opPath}.starts_with("/org/librescrs/Agent/op/"))
            << "level=" << level << " got " << std::string{opPath};
    }

    clientConn->leaveEventLoop();
    serverConn->leaveEventLoop();
}

TEST(CardObjectOperations, SignRejectsNonStringLevelVariant)
{
    auto serverConn = sdbus::createSessionBusConnection();
    ASSERT_NE(serverConn, nullptr);
    serverConn->requestName(sdbus::ServiceName{"org.librescrs.Agent.Test.SignBadLevel"});

    OperationManager mgr(nullptr); // production (cleanup-grace) mode; no resolver
    SignFixture fix{"badlevel"};
    CardObject card(*serverConn, sdbus::ObjectPath{kCardPath}, kPkiBit, sdbus::ObjectPath{kReaderPath}, mgr,
                    fix.deps());
    serverConn->enterEventLoopAsync();

    auto clientConn = sdbus::createSessionBusConnection();
    clientConn->enterEventLoopAsync();
    auto proxy = sdbus::createProxy(*clientConn, sdbus::ServiceName{"org.librescrs.Agent.Test.SignBadLevel"},
                                    sdbus::ObjectPath{kCardPath});

    const int fd = makeInputMemfd(std::string_view{"\x30\x82\x01\x00", 4});
    ASSERT_GE(fd, 0);
    try {
        // "level" carried as a uint32 instead of a string.
        callSign(*proxy, fd, {{"level", sdbus::Variant{std::uint32_t{5}}}});
        ADD_FAILURE() << "expected a non-string level variant to be rejected";
    } catch (const sdbus::Error& e) {
        EXPECT_EQ(e.getName(), "org.librescrs.Agent.Error.UnsupportedSignatureParameter");
        EXPECT_NE(std::string{e.getMessage()}.find("level must be a string"), std::string::npos)
            << "got: " << e.getMessage();
    }

    clientConn->leaveEventLoop();
    serverConn->leaveEventLoop();
}

TEST(CardObjectOperations, SignAcceptsBtAndReturnsOperationPath)
{
    auto serverConn = sdbus::createSessionBusConnection();
    ASSERT_NE(serverConn, nullptr);
    serverConn->requestName(sdbus::ServiceName{"org.librescrs.Agent.Test.SignBt"});

    OperationManager mgr(nullptr); // production (cleanup-grace) mode; no resolver
    SignFixture fix{"bt"};
    CardObject card(*serverConn, sdbus::ObjectPath{kCardPath}, kPkiBit, sdbus::ObjectPath{kReaderPath}, mgr,
                    fix.deps());
    serverConn->enterEventLoopAsync();

    auto clientConn = sdbus::createSessionBusConnection();
    clientConn->enterEventLoopAsync();
    auto proxy = sdbus::createProxy(*clientConn, sdbus::ServiceName{"org.librescrs.Agent.Test.SignBt"},
                                    sdbus::ObjectPath{kCardPath});

    // An explicit b-t passes the gate (the implemented family is b-b + b-t), so
    // an Operation is minted and its path returned. The worker then finishes in
    // error against the stub signer, but that lifecycle is covered elsewhere.
    const int fd = makeInputMemfd(std::string_view{"\x30\x82\x01\x00", 4});
    ASSERT_GE(fd, 0);
    const auto opPath = callSign(*proxy, fd, {{"level", sdbus::Variant{std::string{"b-t"}}}});
    EXPECT_TRUE(std::string{opPath}.starts_with("/org/librescrs/Agent/op/")) << "got " << std::string{opPath};
    std::this_thread::sleep_for(50ms);

    clientConn->leaveEventLoop();
    serverConn->leaveEventLoop();
}

// ---- tsaUrl / visualSignature method-entry validation ----------------

TEST(CardObjectOperations, SignAcceptsTsaUrlOverrideAtTheTimestampedLevel)
{
    auto serverConn = sdbus::createSessionBusConnection();
    ASSERT_NE(serverConn, nullptr);
    serverConn->requestName(sdbus::ServiceName{"org.librescrs.Agent.Test.SignTsaUrl"});

    OperationManager mgr(nullptr);
    SignFixture fix{"tsaurl"};
    CardObject card(*serverConn, sdbus::ObjectPath{kCardPath}, kPkiBit, sdbus::ObjectPath{kReaderPath}, mgr,
                    fix.deps());
    serverConn->enterEventLoopAsync();

    auto clientConn = sdbus::createSessionBusConnection();
    clientConn->enterEventLoopAsync();
    auto proxy = sdbus::createProxy(*clientConn, sdbus::ServiceName{"org.librescrs.Agent.Test.SignTsaUrl"},
                                    sdbus::ObjectPath{kCardPath});

    // An https tsaUrl paired with an explicit b-t passes the method-entry
    // gate (mirrors SignAcceptsBtAndReturnsOperationPath): an Operation is
    // minted and its path returned. SignParams.tsaUrl's exact threading into
    // the LM signing request is unit-tested card-free in LibreAgent's
    // LmSigningRequestBuilderTest.cpp; this pins only the method-entry
    // acceptance, which this D-Bus test harness (no real session factory) is
    // positioned to exercise.
    const int fd = makeInputMemfd(std::string_view{"\x30\x82\x01\x00", 4});
    ASSERT_GE(fd, 0);
    const auto opPath = callSign(*proxy, fd,
                                 {{"level", sdbus::Variant{std::string{"b-t"}}},
                                  {"tsaUrl", sdbus::Variant{std::string{"https://tsa.example.com/ts"}}}});
    EXPECT_TRUE(std::string{opPath}.starts_with("/org/librescrs/Agent/op/")) << "got " << std::string{opPath};
    std::this_thread::sleep_for(50ms);

    clientConn->leaveEventLoop();
    serverConn->leaveEventLoop();
}

TEST(CardObjectOperations, SignRejectsANonHttpsTsaUrl)
{
    auto serverConn = sdbus::createSessionBusConnection();
    ASSERT_NE(serverConn, nullptr);
    serverConn->requestName(sdbus::ServiceName{"org.librescrs.Agent.Test.SignTsaUrlHttp"});

    OperationManager mgr(nullptr);
    SignFixture fix{"tsaurlhttp"};
    CardObject card(*serverConn, sdbus::ObjectPath{kCardPath}, kPkiBit, sdbus::ObjectPath{kReaderPath}, mgr,
                    fix.deps());
    serverConn->enterEventLoopAsync();

    auto clientConn = sdbus::createSessionBusConnection();
    clientConn->enterEventLoopAsync();
    auto proxy = sdbus::createProxy(*clientConn, sdbus::ServiceName{"org.librescrs.Agent.Test.SignTsaUrlHttp"},
                                    sdbus::ObjectPath{kCardPath});

    const int fd = makeInputMemfd(std::string_view{"\x30\x82\x01\x00", 4});
    ASSERT_GE(fd, 0);
    try {
        callSign(*proxy, fd,
                 {{"level", sdbus::Variant{std::string{"b-t"}}},
                  {"tsaUrl", sdbus::Variant{std::string{"http://tsa.example.com"}}}});
        ADD_FAILURE() << "expected a non-https tsaUrl to be rejected";
    } catch (const sdbus::Error& e) {
        EXPECT_EQ(e.getName(), "org.librescrs.Agent.Error.UnsupportedSignatureParameter");
        EXPECT_NE(std::string{e.getMessage()}.find("https"), std::string::npos) << "got: " << e.getMessage();
    }

    clientConn->leaveEventLoop();
    serverConn->leaveEventLoop();
}

TEST(CardObjectOperations, SignRejectsTsaUrlPairedWithTheBaselineLevel)
{
    auto serverConn = sdbus::createSessionBusConnection();
    ASSERT_NE(serverConn, nullptr);
    serverConn->requestName(sdbus::ServiceName{"org.librescrs.Agent.Test.SignTsaUrlBb"});

    OperationManager mgr(nullptr);
    // SignFixture's config has no TsaUrls configured, so an absent/defaulted
    // level resolves to "b-b" (SignatureParams::resolveSignLevel) -- exactly
    // the case a per-request tsaUrl override can never apply to.
    SignFixture fix{"tsaurlbb"};
    CardObject card(*serverConn, sdbus::ObjectPath{kCardPath}, kPkiBit, sdbus::ObjectPath{kReaderPath}, mgr,
                    fix.deps());
    serverConn->enterEventLoopAsync();

    auto clientConn = sdbus::createSessionBusConnection();
    clientConn->enterEventLoopAsync();
    auto proxy = sdbus::createProxy(*clientConn, sdbus::ServiceName{"org.librescrs.Agent.Test.SignTsaUrlBb"},
                                    sdbus::ObjectPath{kCardPath});

    const int fd = makeInputMemfd(std::string_view{"\x30\x82\x01\x00", 4});
    ASSERT_GE(fd, 0);
    try {
        callSign(*proxy, fd, {{"tsaUrl", sdbus::Variant{std::string{"https://tsa.example.com/ts"}}}});
        ADD_FAILURE() << "expected tsaUrl paired with the baseline (b-b) level to be rejected";
    } catch (const sdbus::Error& e) {
        EXPECT_EQ(e.getName(), "org.librescrs.Agent.Error.UnsupportedSignatureParameter");
    }

    clientConn->leaveEventLoop();
    serverConn->leaveEventLoop();
}

TEST(CardObjectOperations, SignAcceptsVisualSignatureOnPades)
{
    auto serverConn = sdbus::createSessionBusConnection();
    ASSERT_NE(serverConn, nullptr);
    serverConn->requestName(sdbus::ServiceName{"org.librescrs.Agent.Test.SignVisual"});

    OperationManager mgr(nullptr);
    SignFixture fix{"visual"};
    CardObject card(*serverConn, sdbus::ObjectPath{kCardPath}, kPkiBit, sdbus::ObjectPath{kReaderPath}, mgr,
                    fix.deps());
    serverConn->enterEventLoopAsync();

    auto clientConn = sdbus::createSessionBusConnection();
    clientConn->enterEventLoopAsync();
    auto proxy = sdbus::createProxy(*clientConn, sdbus::ServiceName{"org.librescrs.Agent.Test.SignVisual"},
                                    sdbus::ObjectPath{kCardPath});

    // %PDF magic bytes so format sniffs to "pades" without an explicit
    // option. A fully-populated, valid visualSignature passes the
    // method-entry gate — an Operation is minted. The exact field-for-field
    // mapping into LM's VisualSignatureParams is unit-tested card-free in
    // LibreAgent's LmSigningRequestBuilderTest.cpp.
    const int fd = makeInputMemfd(std::string_view{"%PDF-1.7", 8});
    ASSERT_GE(fd, 0);
    const std::map<std::string, sdbus::Variant> visual{{"page", sdbus::Variant{std::uint32_t{1}}},
                                                       {"x", sdbus::Variant{10.5}},
                                                       {"y", sdbus::Variant{20.25}},
                                                       {"width", sdbus::Variant{150.0}},
                                                       {"height", sdbus::Variant{60.0}},
                                                       {"text", sdbus::Variant{std::string{"Signed by {cn}"}}}};
    const auto opPath = callSign(*proxy, fd, {{"visualSignature", sdbus::Variant{visual}}});
    EXPECT_TRUE(std::string{opPath}.starts_with("/org/librescrs/Agent/op/")) << "got " << std::string{opPath};
    std::this_thread::sleep_for(50ms);

    clientConn->leaveEventLoop();
    serverConn->leaveEventLoop();
}

TEST(CardObjectOperations, SignRejectsVisualSignatureOnANonPadesFormat)
{
    auto serverConn = sdbus::createSessionBusConnection();
    ASSERT_NE(serverConn, nullptr);
    serverConn->requestName(sdbus::ServiceName{"org.librescrs.Agent.Test.SignVisualBadFormat"});

    OperationManager mgr(nullptr);
    SignFixture fix{"visualbadformat"};
    CardObject card(*serverConn, sdbus::ObjectPath{kCardPath}, kPkiBit, sdbus::ObjectPath{kReaderPath}, mgr,
                    fix.deps());
    serverConn->enterEventLoopAsync();

    auto clientConn = sdbus::createSessionBusConnection();
    clientConn->enterEventLoopAsync();
    auto proxy = sdbus::createProxy(*clientConn, sdbus::ServiceName{"org.librescrs.Agent.Test.SignVisualBadFormat"},
                                    sdbus::ObjectPath{kCardPath});

    // Sniffs to "cades" (0x30 leading byte), not "pades".
    const int fd = makeInputMemfd(std::string_view{"\x30\x82\x01\x00", 4});
    ASSERT_GE(fd, 0);
    const std::map<std::string, sdbus::Variant> visual{{"page", sdbus::Variant{std::uint32_t{0}}},
                                                       {"x", sdbus::Variant{0.0}},
                                                       {"y", sdbus::Variant{0.0}},
                                                       {"width", sdbus::Variant{100.0}},
                                                       {"height", sdbus::Variant{50.0}},
                                                       {"text", sdbus::Variant{std::string{"x"}}}};
    try {
        callSign(*proxy, fd, {{"visualSignature", sdbus::Variant{visual}}});
        ADD_FAILURE() << "expected visualSignature on a non-pades format to be rejected";
    } catch (const sdbus::Error& e) {
        EXPECT_EQ(e.getName(), "org.librescrs.Agent.Error.UnsupportedSignatureParameter");
        EXPECT_NE(std::string{e.getMessage()}.find("pades"), std::string::npos) << "got: " << e.getMessage();
    }

    clientConn->leaveEventLoop();
    serverConn->leaveEventLoop();
}

TEST(CardObjectOperations, SignRejectsVisualSignatureMissingARequiredField)
{
    auto serverConn = sdbus::createSessionBusConnection();
    ASSERT_NE(serverConn, nullptr);
    serverConn->requestName(sdbus::ServiceName{"org.librescrs.Agent.Test.SignVisualMissingField"});

    OperationManager mgr(nullptr);
    SignFixture fix{"visualmissingfield"};
    CardObject card(*serverConn, sdbus::ObjectPath{kCardPath}, kPkiBit, sdbus::ObjectPath{kReaderPath}, mgr,
                    fix.deps());
    serverConn->enterEventLoopAsync();

    auto clientConn = sdbus::createSessionBusConnection();
    clientConn->enterEventLoopAsync();
    auto proxy = sdbus::createProxy(*clientConn, sdbus::ServiceName{"org.librescrs.Agent.Test.SignVisualMissingField"},
                                    sdbus::ObjectPath{kCardPath});

    const int fd = makeInputMemfd(std::string_view{"%PDF-1.7", 8});
    ASSERT_GE(fd, 0);
    // "text" is missing.
    const std::map<std::string, sdbus::Variant> visual{{"page", sdbus::Variant{std::uint32_t{0}}},
                                                       {"x", sdbus::Variant{0.0}},
                                                       {"y", sdbus::Variant{0.0}},
                                                       {"width", sdbus::Variant{100.0}},
                                                       {"height", sdbus::Variant{50.0}}};
    try {
        callSign(*proxy, fd, {{"visualSignature", sdbus::Variant{visual}}});
        ADD_FAILURE() << "expected a visualSignature missing a required field to be rejected";
    } catch (const sdbus::Error& e) {
        EXPECT_EQ(e.getName(), "org.librescrs.Agent.Error.UnsupportedSignatureParameter");
    }

    clientConn->leaveEventLoop();
    serverConn->leaveEventLoop();
}

// A finite-guard on all four of visualSignature's x/y/width/height: D-Bus's
// `d` type (like CBOR on the socket transport) carries +-inf/NaN canonically,
// so a hostile/buggy caller can put one on the wire. Without a std::isfinite
// gate at method entry (SignatureParams::isValidVisualGeometry), such a value
// would sail past the plain positivity checks and reach LmSeams's
// `static_cast<int>(std::lround(...))` narrowing downstream -- lround on a
// non-finite double is unspecified, and the subsequent int narrowing of an
// out-of-range double is undefined behaviour. These three vectors (+inf
// width, NaN x, -inf y) must be rejected here, at the same method-entry gate
// and with the same error class as every other malformed-geometry rejection
// above -- this is the RED vehicle for D-Bus; the socket transport shares the
// identical fix via the same SignatureParams::isValidVisualGeometry helper.
TEST(CardObjectOperations, SignRejectsVisualSignatureWithNonFiniteWidth)
{
    auto serverConn = sdbus::createSessionBusConnection();
    ASSERT_NE(serverConn, nullptr);
    serverConn->requestName(sdbus::ServiceName{"org.librescrs.Agent.Test.SignVisualInfWidth"});

    OperationManager mgr(nullptr);
    SignFixture fix{"visualinfwidth"};
    CardObject card(*serverConn, sdbus::ObjectPath{kCardPath}, kPkiBit, sdbus::ObjectPath{kReaderPath}, mgr,
                    fix.deps());
    serverConn->enterEventLoopAsync();

    auto clientConn = sdbus::createSessionBusConnection();
    clientConn->enterEventLoopAsync();
    auto proxy = sdbus::createProxy(*clientConn, sdbus::ServiceName{"org.librescrs.Agent.Test.SignVisualInfWidth"},
                                    sdbus::ObjectPath{kCardPath});

    const int fd = makeInputMemfd(std::string_view{"%PDF-1.7", 8});
    ASSERT_GE(fd, 0);
    const std::map<std::string, sdbus::Variant> visual{
        {"page", sdbus::Variant{std::uint32_t{0}}},
        {"x", sdbus::Variant{0.0}},
        {"y", sdbus::Variant{0.0}},
        {"width", sdbus::Variant{std::numeric_limits<double>::infinity()}},
        {"height", sdbus::Variant{50.0}},
        {"text", sdbus::Variant{std::string{"x"}}}};
    try {
        callSign(*proxy, fd, {{"visualSignature", sdbus::Variant{visual}}});
        ADD_FAILURE() << "expected a +inf visualSignature width to be rejected";
    } catch (const sdbus::Error& e) {
        EXPECT_EQ(e.getName(), "org.librescrs.Agent.Error.UnsupportedSignatureParameter");
    }

    clientConn->leaveEventLoop();
    serverConn->leaveEventLoop();
}

TEST(CardObjectOperations, SignRejectsVisualSignatureWithNaNX)
{
    auto serverConn = sdbus::createSessionBusConnection();
    ASSERT_NE(serverConn, nullptr);
    serverConn->requestName(sdbus::ServiceName{"org.librescrs.Agent.Test.SignVisualNanX"});

    OperationManager mgr(nullptr);
    SignFixture fix{"visualnanx"};
    CardObject card(*serverConn, sdbus::ObjectPath{kCardPath}, kPkiBit, sdbus::ObjectPath{kReaderPath}, mgr,
                    fix.deps());
    serverConn->enterEventLoopAsync();

    auto clientConn = sdbus::createSessionBusConnection();
    clientConn->enterEventLoopAsync();
    auto proxy = sdbus::createProxy(*clientConn, sdbus::ServiceName{"org.librescrs.Agent.Test.SignVisualNanX"},
                                    sdbus::ObjectPath{kCardPath});

    const int fd = makeInputMemfd(std::string_view{"%PDF-1.7", 8});
    ASSERT_GE(fd, 0);
    const std::map<std::string, sdbus::Variant> visual{{"page", sdbus::Variant{std::uint32_t{0}}},
                                                       {"x", sdbus::Variant{std::numeric_limits<double>::quiet_NaN()}},
                                                       {"y", sdbus::Variant{0.0}},
                                                       {"width", sdbus::Variant{100.0}},
                                                       {"height", sdbus::Variant{50.0}},
                                                       {"text", sdbus::Variant{std::string{"x"}}}};
    try {
        callSign(*proxy, fd, {{"visualSignature", sdbus::Variant{visual}}});
        ADD_FAILURE() << "expected a NaN visualSignature x to be rejected";
    } catch (const sdbus::Error& e) {
        EXPECT_EQ(e.getName(), "org.librescrs.Agent.Error.UnsupportedSignatureParameter");
    }

    clientConn->leaveEventLoop();
    serverConn->leaveEventLoop();
}

TEST(CardObjectOperations, SignRejectsVisualSignatureWithNegativeInfinityY)
{
    auto serverConn = sdbus::createSessionBusConnection();
    ASSERT_NE(serverConn, nullptr);
    serverConn->requestName(sdbus::ServiceName{"org.librescrs.Agent.Test.SignVisualNegInfY"});

    OperationManager mgr(nullptr);
    SignFixture fix{"visualneginfy"};
    CardObject card(*serverConn, sdbus::ObjectPath{kCardPath}, kPkiBit, sdbus::ObjectPath{kReaderPath}, mgr,
                    fix.deps());
    serverConn->enterEventLoopAsync();

    auto clientConn = sdbus::createSessionBusConnection();
    clientConn->enterEventLoopAsync();
    auto proxy = sdbus::createProxy(*clientConn, sdbus::ServiceName{"org.librescrs.Agent.Test.SignVisualNegInfY"},
                                    sdbus::ObjectPath{kCardPath});

    const int fd = makeInputMemfd(std::string_view{"%PDF-1.7", 8});
    ASSERT_GE(fd, 0);
    const std::map<std::string, sdbus::Variant> visual{{"page", sdbus::Variant{std::uint32_t{0}}},
                                                       {"x", sdbus::Variant{0.0}},
                                                       {"y", sdbus::Variant{-std::numeric_limits<double>::infinity()}},
                                                       {"width", sdbus::Variant{100.0}},
                                                       {"height", sdbus::Variant{50.0}},
                                                       {"text", sdbus::Variant{std::string{"x"}}}};
    try {
        callSign(*proxy, fd, {{"visualSignature", sdbus::Variant{visual}}});
        ADD_FAILURE() << "expected a -inf visualSignature y to be rejected";
    } catch (const sdbus::Error& e) {
        EXPECT_EQ(e.getName(), "org.librescrs.Agent.Error.UnsupportedSignatureParameter");
    }

    clientConn->leaveEventLoop();
    serverConn->leaveEventLoop();
}

// ---- Card1.SignBatch method-entry resolution (entry-gate only — the full
// per-row/consent run-through lives in SignBatchOperationTest.cpp, mirroring
// how Card1.Sign's own tests above never wait for the worker to complete) ----

namespace {

// Build the a(sh) wire array from (displayName, fd) pairs. Mirrors callSign's
// convention of NOT closing the source fds afterward — sdbus::UnixFd{fd}
// (non-adopting) dups each fd for transmission and leaves the original open,
// same as every existing Sign test above.
sdbus::ObjectPath callSignBatch(sdbus::IProxy& proxy, const std::vector<std::pair<std::string, int>>& docs,
                                const std::map<std::string, sdbus::Variant>& options,
                                const std::string& certId = "deadbeefcert")
{
    std::vector<sdbus::Struct<std::string, sdbus::UnixFd>> wire;
    wire.reserve(docs.size());
    for (const auto& [name, fd] : docs) {
        wire.emplace_back(name, sdbus::UnixFd{fd});
    }
    sdbus::ObjectPath opPath;
    proxy.callMethod("SignBatch")
        .onInterface(sdbus::InterfaceName{kCard1Iface})
        .withArguments(wire, certId, options)
        .storeResultsTo(opPath);
    return opPath;
}

// @p count fresh CAdES-sniffing (0x30 leading byte) memfds, named
// "doc<N>.pdf".
std::vector<std::pair<std::string, int>> makeDocuments(std::size_t count)
{
    std::vector<std::pair<std::string, int>> out;
    out.reserve(count);
    for (std::size_t i = 0; i < count; ++i) {
        const int fd = makeInputMemfd(std::string_view{"\x30\x82\x01\x00", 4});
        out.emplace_back("doc" + std::to_string(i) + ".pdf", fd);
    }
    return out;
}

} // namespace

TEST(CardObjectOperations, SignBatchWithoutPkiCapabilityThrowsUnsupported)
{
    auto serverConn = sdbus::createSessionBusConnection();
    ASSERT_NE(serverConn, nullptr) << "run under dbus-run-session";
    serverConn->requestName(sdbus::ServiceName{"org.librescrs.Agent.Test.SignBatchNoCapa"});

    OperationManager mgr(nullptr);
    SignFixture fix{"batchnocapa"};
    CardObject card(*serverConn, sdbus::ObjectPath{kCardPath}, 0u /* no capability bits */,
                    sdbus::ObjectPath{kReaderPath}, mgr, fix.deps());
    serverConn->enterEventLoopAsync();

    auto clientConn = sdbus::createSessionBusConnection();
    clientConn->enterEventLoopAsync();
    auto proxy = sdbus::createProxy(*clientConn, sdbus::ServiceName{"org.librescrs.Agent.Test.SignBatchNoCapa"},
                                    sdbus::ObjectPath{kCardPath});

    try {
        callSignBatch(*proxy, makeDocuments(1), {});
        ADD_FAILURE() << "expected UnsupportedOnThisCard";
    } catch (const sdbus::Error& e) {
        EXPECT_EQ(e.getName(), "org.librescrs.Agent.Error.UnsupportedOnThisCard");
    }

    clientConn->leaveEventLoop();
    serverConn->leaveEventLoop();
}

TEST(CardObjectOperations, SignBatchRejectsEmptyCertId)
{
    auto serverConn = sdbus::createSessionBusConnection();
    ASSERT_NE(serverConn, nullptr);
    serverConn->requestName(sdbus::ServiceName{"org.librescrs.Agent.Test.SignBatchEmptyCert"});

    OperationManager mgr(nullptr);
    SignFixture fix{"batchemptycert"};
    CardObject card(*serverConn, sdbus::ObjectPath{kCardPath}, kPkiBit, sdbus::ObjectPath{kReaderPath}, mgr,
                    fix.deps());
    serverConn->enterEventLoopAsync();

    auto clientConn = sdbus::createSessionBusConnection();
    clientConn->enterEventLoopAsync();
    auto proxy = sdbus::createProxy(*clientConn, sdbus::ServiceName{"org.librescrs.Agent.Test.SignBatchEmptyCert"},
                                    sdbus::ObjectPath{kCardPath});

    try {
        callSignBatch(*proxy, makeDocuments(1), {}, /*certId=*/"");
        ADD_FAILURE() << "expected certId-required rejection";
    } catch (const sdbus::Error& e) {
        EXPECT_EQ(e.getName(), "org.librescrs.Agent.Error.UnsupportedSignatureParameter");
        EXPECT_NE(std::string{e.getMessage()}.find("certId"), std::string::npos) << "got: " << e.getMessage();
    }

    clientConn->leaveEventLoop();
    serverConn->leaveEventLoop();
}

TEST(CardObjectOperations, SignBatchRejectsZeroDocuments)
{
    auto serverConn = sdbus::createSessionBusConnection();
    ASSERT_NE(serverConn, nullptr);
    serverConn->requestName(sdbus::ServiceName{"org.librescrs.Agent.Test.SignBatchZeroDocs"});

    OperationManager mgr(nullptr);
    SignFixture fix{"batchzerodocs"};
    CardObject card(*serverConn, sdbus::ObjectPath{kCardPath}, kPkiBit, sdbus::ObjectPath{kReaderPath}, mgr,
                    fix.deps());
    serverConn->enterEventLoopAsync();

    auto clientConn = sdbus::createSessionBusConnection();
    clientConn->enterEventLoopAsync();
    auto proxy = sdbus::createProxy(*clientConn, sdbus::ServiceName{"org.librescrs.Agent.Test.SignBatchZeroDocs"},
                                    sdbus::ObjectPath{kCardPath});

    try {
        callSignBatch(*proxy, {}, {});
        ADD_FAILURE() << "expected InvalidRequest for zero documents";
    } catch (const sdbus::Error& e) {
        EXPECT_EQ(e.getName(), "org.librescrs.Agent.Error.InvalidRequest");
    }

    clientConn->leaveEventLoop();
    serverConn->leaveEventLoop();
}

// NOTE on the upper bound (13 documents): a LIVE 13-fd SignBatch call sits
// comfortably within this suite's dbus-run-session daemon's own relay
// ceiling (empirically ~16 fds per message before the bus connection drops —
// the SAME reference-daemon max_message_unix_fds default that justifies
// kMaxBatchDocuments=12 itself; see BatchSignFlow.h), so no live-transport
// obstacle forces this boundary to stay pure-only; it does so simply to
// mirror LibreAgent's own exhaustive unit coverage rather than duplicate it
// over the wire. The lower invalid boundary (0 documents, tested live above
// — needs no fds at all) already proves the dispatch-to-gate wiring is live
// and correctly reachable; isValidBatchDocumentCount's own boundary values
// (0/1/12/13) are exhaustively unit-tested pure (no bus, no fds) in
// LibreAgent's BatchSignFlowTest.cpp. This test pins that
// CardObject::SignBatch's method-entry gate calls the SAME shared predicate
// — not a parallel, driftable copy of the 1-12 range.
TEST(CardObjectOperations, SignBatchDocumentCountGateUsesTheSharedValidityPredicate)
{
    EXPECT_TRUE(Operations::isValidBatchDocumentCount(1));
    EXPECT_TRUE(Operations::isValidBatchDocumentCount(12));
    EXPECT_FALSE(Operations::isValidBatchDocumentCount(0));
    EXPECT_FALSE(Operations::isValidBatchDocumentCount(13));
}

TEST(CardObjectOperations, SignBatchAcceptsOneDocumentAndReturnsOperationPath)
{
    auto serverConn = sdbus::createSessionBusConnection();
    ASSERT_NE(serverConn, nullptr);
    serverConn->requestName(sdbus::ServiceName{"org.librescrs.Agent.Test.SignBatchOneDoc"});

    OperationManager mgr(nullptr);
    SignFixture fix{"batchonedoc"};
    CardObject card(*serverConn, sdbus::ObjectPath{kCardPath}, kPkiBit, sdbus::ObjectPath{kReaderPath}, mgr,
                    fix.deps());
    serverConn->enterEventLoopAsync();

    auto clientConn = sdbus::createSessionBusConnection();
    clientConn->enterEventLoopAsync();
    auto proxy = sdbus::createProxy(*clientConn, sdbus::ServiceName{"org.librescrs.Agent.Test.SignBatchOneDoc"},
                                    sdbus::ObjectPath{kCardPath});

    const auto opPath = callSignBatch(*proxy, makeDocuments(1), {});
    EXPECT_TRUE(std::string{opPath}.starts_with("/org/librescrs/Agent/op/")) << "got " << std::string{opPath};
    std::this_thread::sleep_for(50ms);

    clientConn->leaveEventLoop();
    serverConn->leaveEventLoop();
}

// Exercises a genuine MULTI-document batch through the live wire, at exactly
// kMaxBatchDocuments (12) — comfortably within this suite's dbus-run-session
// daemon's own empirical relay ceiling (~16 fds per message, see the comment
// on SignBatchDocumentCountGateUsesTheSharedValidityPredicate above), so
// unlike the old 64-document cap, the TRUE upper boundary is exercised live
// here, not just approximated. The entry gate does not special-case any
// value inside [1, kMaxBatchDocuments] — it is the ONE
// isValidBatchDocumentCount range check — so this, together with the
// 1-document and 0-document live cases above/below, covers the gate's live
// dispatch path; the exact 12/13 boundary values are additionally covered
// pure in BatchSignFlowTest.cpp and just above.
TEST(CardObjectOperations, SignBatchAcceptsAMultiDocumentBatchAndReturnsOperationPath)
{
    auto serverConn = sdbus::createSessionBusConnection();
    ASSERT_NE(serverConn, nullptr);
    serverConn->requestName(sdbus::ServiceName{"org.librescrs.Agent.Test.SignBatchMultiDoc"});

    OperationManager mgr(nullptr);
    SignFixture fix{"batchmultidoc"};
    CardObject card(*serverConn, sdbus::ObjectPath{kCardPath}, kPkiBit, sdbus::ObjectPath{kReaderPath}, mgr,
                    fix.deps());
    serverConn->enterEventLoopAsync();

    auto clientConn = sdbus::createSessionBusConnection();
    clientConn->enterEventLoopAsync();
    auto proxy = sdbus::createProxy(*clientConn, sdbus::ServiceName{"org.librescrs.Agent.Test.SignBatchMultiDoc"},
                                    sdbus::ObjectPath{kCardPath});

    const auto opPath = callSignBatch(*proxy, makeDocuments(12), {});
    EXPECT_TRUE(std::string{opPath}.starts_with("/org/librescrs/Agent/op/")) << "got " << std::string{opPath};
    std::this_thread::sleep_for(50ms);

    clientConn->leaveEventLoop();
    serverConn->leaveEventLoop();
}

// Proves SignBatch reuses the EXACT SAME options resolver Sign does (not a
// parallel, driftable copy): the identical non-https-tsaUrl rejection Sign
// already exercises above must fire here too.
TEST(CardObjectOperations, SignBatchRejectsANonHttpsTsaUrlViaTheSharedOptionsResolver)
{
    auto serverConn = sdbus::createSessionBusConnection();
    ASSERT_NE(serverConn, nullptr);
    serverConn->requestName(sdbus::ServiceName{"org.librescrs.Agent.Test.SignBatchTsaUrl"});

    OperationManager mgr(nullptr);
    SignFixture fix{"batchtsaurl"};
    CardObject card(*serverConn, sdbus::ObjectPath{kCardPath}, kPkiBit, sdbus::ObjectPath{kReaderPath}, mgr,
                    fix.deps());
    serverConn->enterEventLoopAsync();

    auto clientConn = sdbus::createSessionBusConnection();
    clientConn->enterEventLoopAsync();
    auto proxy = sdbus::createProxy(*clientConn, sdbus::ServiceName{"org.librescrs.Agent.Test.SignBatchTsaUrl"},
                                    sdbus::ObjectPath{kCardPath});

    try {
        callSignBatch(*proxy, makeDocuments(2),
                      {{"level", sdbus::Variant{std::string{"b-t"}}},
                       {"tsaUrl", sdbus::Variant{std::string{"http://tsa.example.com"}}}});
        ADD_FAILURE() << "expected a non-https tsaUrl to be rejected";
    } catch (const sdbus::Error& e) {
        EXPECT_EQ(e.getName(), "org.librescrs.Agent.Error.UnsupportedSignatureParameter");
        EXPECT_NE(std::string{e.getMessage()}.find("https"), std::string::npos) << "got: " << e.getMessage();
    }

    clientConn->leaveEventLoop();
    serverConn->leaveEventLoop();
}

// MANDATORY invariant (carried from the previous gate's review): the rate
// limiter charges ONE attempt per Card1.SignBatch dispatch, mirroring
// Card1.Sign's own entry charge — regardless of how many documents the batch
// carries. A 10-document batch call must cost exactly the SAME ONE charge a
// single Sign call would; charging per-document would exhaust the whole
// kMaxPerWindow=5 budget on this ONE call, which the 4 follow-up Sign calls
// below would then immediately disprove.
TEST(CardObjectOperations, SignBatchChargesTheRateLimiterExactlyOnceRegardlessOfDocumentCount)
{
    auto serverConn = sdbus::createSessionBusConnection();
    ASSERT_NE(serverConn, nullptr);
    serverConn->requestName(sdbus::ServiceName{"org.librescrs.Agent.Test.SignBatchOneCharge"});

    OperationManager mgr(nullptr);
    SignFixture fix{"batchonecharge"};
    CardObject card(*serverConn, sdbus::ObjectPath{kCardPath}, kPkiBit, sdbus::ObjectPath{kReaderPath}, mgr,
                    fix.deps());
    serverConn->enterEventLoopAsync();

    auto clientConn = sdbus::createSessionBusConnection();
    clientConn->enterEventLoopAsync();
    auto proxy = sdbus::createProxy(*clientConn, sdbus::ServiceName{"org.librescrs.Agent.Test.SignBatchOneCharge"},
                                    sdbus::ObjectPath{kCardPath});

    // ONE SignBatch call, 10 documents: costs exactly 1 of the 5-request
    // budget (RateLimiter::kMaxPerWindow).
    const auto batchPath = callSignBatch(*proxy, makeDocuments(10), {});
    EXPECT_TRUE(std::string{batchPath}.starts_with("/org/librescrs/Agent/op/"));

    // 4 more single Sign calls from the SAME caller must ALL still succeed —
    // proving only 1 (not 10) of the budget was consumed by the batch call.
    for (int i = 0; i < 4; ++i) {
        const int fd = makeInputMemfd(std::string_view{"\x30\x82\x01\x00", 4});
        ASSERT_GE(fd, 0);
        const auto p = callSign(*proxy, fd, {});
        EXPECT_TRUE(std::string{p}.starts_with("/org/librescrs/Agent/op/")) << "charge " << (i + 2) << " of 5";
    }

    // The 6th charge overall (1 batch + 4 Sign + this one) must trip
    // RateLimited — proving the limiter genuinely tracks state rather than
    // being silently bypassed for SignBatch.
    const int fd = makeInputMemfd(std::string_view{"\x30\x82\x01\x00", 4});
    ASSERT_GE(fd, 0);
    try {
        callSign(*proxy, fd, {});
        ADD_FAILURE() << "expected the 6th charge to trip RateLimited";
    } catch (const sdbus::Error& e) {
        EXPECT_EQ(e.getName(), "org.librescrs.Agent.Error.RateLimited");
    }

    std::this_thread::sleep_for(50ms);
    clientConn->leaveEventLoop();
    serverConn->leaveEventLoop();
}

// The rate-limit charge sits at method entry, BEFORE the document-count gate
// (and before any fd is read) — an exhausted caller must see RateLimited even
// for a request that ALSO carries an entry-invalid document count, proving
// the ordering (no Operation is minted either way, but the wire error must be
// the rate-limit one, not InvalidRequest).
TEST(CardObjectOperations, SignBatchRateLimitFiresBeforeTheDocumentCountGate)
{
    auto serverConn = sdbus::createSessionBusConnection();
    ASSERT_NE(serverConn, nullptr);
    serverConn->requestName(sdbus::ServiceName{"org.librescrs.Agent.Test.SignBatchOrderedGate"});

    OperationManager mgr(nullptr);
    SignFixture fix{"batchorderedgate"};
    CardObject card(*serverConn, sdbus::ObjectPath{kCardPath}, kPkiBit, sdbus::ObjectPath{kReaderPath}, mgr,
                    fix.deps());
    serverConn->enterEventLoopAsync();

    auto clientConn = sdbus::createSessionBusConnection();
    clientConn->enterEventLoopAsync();
    auto proxy = sdbus::createProxy(*clientConn, sdbus::ServiceName{"org.librescrs.Agent.Test.SignBatchOrderedGate"},
                                    sdbus::ObjectPath{kCardPath});

    // Exhaust the whole 5-request budget with single Sign calls.
    for (int i = 0; i < 5; ++i) {
        const int fd = makeInputMemfd(std::string_view{"\x30\x82\x01\x00", 4});
        ASSERT_GE(fd, 0);
        const auto p = callSign(*proxy, fd, {});
        ASSERT_TRUE(std::string{p}.starts_with("/org/librescrs/Agent/op/")) << "charge " << (i + 1) << " of 5";
    }

    // A SignBatch call with ZERO documents (otherwise an InvalidRequest) must
    // report RateLimited instead — the charge (and its refusal) happens
    // before the count is ever inspected.
    try {
        callSignBatch(*proxy, {}, {});
        ADD_FAILURE() << "expected RateLimited to fire ahead of the document-count gate";
    } catch (const sdbus::Error& e) {
        EXPECT_EQ(e.getName(), "org.librescrs.Agent.Error.RateLimited");
    }

    std::this_thread::sleep_for(50ms);
    clientConn->leaveEventLoop();
    serverConn->leaveEventLoop();
}
