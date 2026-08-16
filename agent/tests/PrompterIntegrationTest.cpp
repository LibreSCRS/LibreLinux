// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// End-to-end exercise of PrompterClient against a mock Prompter1 adaptor
// hosted in the same test process on a private session bus. Runs under
// dbus-run-session (see CMakeLists.txt) so no system bus / installed prompter
// is required, and uses two separate sdbus connections (server hosts, client
// proxies) so sd-bus does not self-call (ELOOP).

#include "PrompterClient.h"
#include "org.librescrs.Prompter1_adaptor.h"

#include "PrompterWire.h"       // shared kind / option-key / status vocabulary
#include "SealedMemfdCreator.h" // shared sealed-memfd creator

#include <LibreSCRS/Agent/cache/CredentialCache.h>
#include <LibreSCRS/Agent/operations/CardSessionHolder.h>
#include <LibreSCRS/Agent/operations/IdentityReadFlow.h>
#include <LibreSCRS/Agent/operations/PromptSerializer.h>
#include <LibreSCRS/Agent/operations/Seams.h>
#include <LibreSCRS/Auth/AuthRequirement.h>
#include <LibreSCRS/Auth/ErrorKeys.h>
#include <LibreSCRS/Auth/PaceSecretKind.h>
#include <LibreSCRS/CancelToken.h>
#include <LibreSCRS/LocalizedText.h>
#include <LibreSCRS/Plugin/CardPlugin.h>
#include <LibreSCRS/Plugin/PluginTypes.h>
#include <LibreSCRS/Plugin/ReadResult.h>
#include <LibreSCRS/SmartCard/AppletAid.h>
#include <LibreSCRS/SmartCard/CardMap.h>
#include <LibreSCRS/SmartCard/CardSession.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <span>
#include <sdbus-c++/AdaptorInterfaces.h>
#include <sdbus-c++/Error.h>
#include <sdbus-c++/IConnection.h>
#include <sdbus-c++/Types.h>
#include <gtest/gtest.h>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>
#include <vector>

using namespace LibreSCRS::Agent;

namespace {

// The alternative-kind rollout cases below spell every option key and status
// through this alias, never as literals: the absolute spellings are pinned in
// exactly one place (PrompterVocabularyPinTest.cpp) and nowhere else.
namespace wire = LibreLinux::PrompterWire;

// ICAO Doc 9303 specimen document (not a real credential): document number
// L898902C< with check digit 3, date of birth 690806/1, date of expiry
// 940623/6, in the prompter's canonical three-line payload shape.
constexpr std::string_view kSpecimenMrzPayload = "L898902C<3\n6908061\n9406236";

constexpr const char* kMockServiceName = "org.librescrs.Prompter1.Test";
constexpr const char* kMockObjectPath = "/org/librescrs/Prompter1";

// Build a sealed memfd containing @p bytes via the SAME shared creator the
// prompter + agent use (one definition of the seal-flag set, tree-wide).
int makeSealedMemfd(std::string_view bytes)
{
    return LibreLinux::Common::makeSealedMemfd(
        "librescrs-test-secret",
        std::span<const std::uint8_t>{reinterpret_cast<const std::uint8_t*>(bytes.data()), bytes.size()});
}

// Per-call scripted response: the mock consults this struct on every
// RequestSecret to decide what to return (and whether to throw).
struct MockBehavior
{
    bool throwSdbusError = false;
    std::string sdbusErrorName;
    std::string sdbusErrorMessage;
    std::string status;      // returned status string ("ok"/"cancelled"/"error")
    std::string secretBytes; // wrapped into a fresh sealed memfd on each call
    std::string userMessage;
};

// Captured (kind, options) tuple from the most recent RequestSecret invocation.
// Filled by the worker thread; read by the test thread after the synchronous
// client call has returned (happens-before via the D-Bus round trip plus the
// mutex below — covers either ordering even on weak-memory archs).
struct CapturedCall
{
    std::string kind;
    std::map<std::string, sdbus::Variant> options;
    bool seen = false;
};

class MockPrompter final : public sdbus::AdaptorInterfaces<org::librescrs::Prompter1_adaptor>
{
public:
    MockPrompter(sdbus::IConnection& connection, sdbus::ObjectPath path)
        : AdaptorInterfaces(connection, std::move(path))
    {
        registerAdaptor();
    }
    ~MockPrompter()
    {
        unregisterAdaptor();
    }

    MockPrompter(const MockPrompter&) = delete;
    MockPrompter& operator=(const MockPrompter&) = delete;
    MockPrompter(MockPrompter&&) = delete;
    MockPrompter& operator=(MockPrompter&&) = delete;

    void setBehavior(MockBehavior behavior)
    {
        const std::lock_guard lock{m_mutex};
        m_behavior = std::move(behavior);
    }

    CapturedCall captured() const
    {
        const std::lock_guard lock{m_mutex};
        return m_captured;
    }

private:
    std::tuple<std::string, sdbus::UnixFd, std::string>
    RequestSecret(const std::string& kind, const std::map<std::string, sdbus::Variant>& options) override
    {
        MockBehavior behavior;
        {
            const std::lock_guard lock{m_mutex};
            m_captured.kind = kind;
            m_captured.options = options;
            m_captured.seen = true;
            behavior = m_behavior;
        }

        if (behavior.throwSdbusError) {
            throw sdbus::Error{sdbus::Error::Name{behavior.sdbusErrorName}, behavior.sdbusErrorMessage};
        }

        const int fd = makeSealedMemfd(behavior.secretBytes);
        // adopt_fd: ownership transferred to UnixFd which closes on destruct.
        return std::make_tuple(behavior.status, sdbus::UnixFd{fd, sdbus::adopt_fd}, behavior.userMessage);
    }

    // Multi-secret variant — not scripted by this suite; a fixed "error"
    // reply with the zero-byte no-secret encoding on both fds satisfies the
    // regenerated adaptor's pure virtual.
    std::tuple<std::string, sdbus::UnixFd, sdbus::UnixFd, std::string>
    RequestSecrets(const std::string& /*kind*/, const std::map<std::string, sdbus::Variant>& /*options*/) override
    {
        return std::make_tuple(std::string{"error"}, sdbus::UnixFd{makeSealedMemfd(""), sdbus::adopt_fd},
                               sdbus::UnixFd{makeSealedMemfd(""), sdbus::adopt_fd},
                               std::string{"RequestSecrets not scripted in this mock"});
    }

    void CancelCurrent() override
    {
        // The mock does not host a real dialog; tests that exercise the
        // cancel path bind the behavior they want via setBehavior.
    }

    mutable std::mutex m_mutex;
    MockBehavior m_behavior;
    CapturedCall m_captured;
};

// Test fixture: spins up a fresh server + client connection per test so each
// case starts from a clean event-loop state. The mock claims its well-known
// name on the server connection; the client constructs a PrompterClient
// against a SEPARATE connection (sd-bus refuses to dispatch self-calls).
class PrompterIntegrationTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        m_serverConn = sdbus::createSessionBusConnection();
        ASSERT_NE(m_serverConn, nullptr) << "private session bus (run under dbus-run-session)";
        m_serverConn->requestName(sdbus::ServiceName{kMockServiceName});

        m_mock = std::make_unique<MockPrompter>(*m_serverConn, sdbus::ObjectPath{kMockObjectPath});
        m_serverConn->enterEventLoopAsync();

        m_clientConn = sdbus::createSessionBusConnection();
        m_clientConn->enterEventLoopAsync();
        m_client = std::make_unique<PrompterClient>(m_clientConn, kMockServiceName, kMockObjectPath);
    }

    void TearDown() override
    {
        m_client.reset();
        m_clientConn->leaveEventLoop();
        m_mock.reset();
        m_serverConn->leaveEventLoop();
    }

    std::unique_ptr<sdbus::IConnection> m_serverConn;
    // Shared so the PrompterClient can CO-OWN it (the client holds a shared_ptr).
    std::shared_ptr<sdbus::IConnection> m_clientConn;
    std::unique_ptr<MockPrompter> m_mock;
    std::unique_ptr<PrompterClient> m_client;
};

} // namespace

TEST_F(PrompterIntegrationTest, PinOkRoundTrip)
{
    m_mock->setBehavior(MockBehavior{.status = "ok", .secretBytes = "1234"});
    const auto result = m_client->requestPin(PromptOptions{});
    EXPECT_EQ(result.status, PromptStatus::Ok);
    ASSERT_TRUE(result.secret.has_value());
    EXPECT_EQ(result.secret->view(), "1234");
    EXPECT_TRUE(result.userMessage.empty());
}

TEST_F(PrompterIntegrationTest, CanOkRoundTrip)
{
    m_mock->setBehavior(MockBehavior{.status = "ok", .secretBytes = "123456"});
    const auto result = m_client->requestCan(PromptOptions{});
    EXPECT_EQ(result.status, PromptStatus::Ok);
    ASSERT_TRUE(result.secret.has_value());
    EXPECT_EQ(result.secret->view(), "123456");
    EXPECT_TRUE(result.userMessage.empty());
}

TEST_F(PrompterIntegrationTest, MrzOkRoundTrip)
{
    constexpr std::string_view mrz = "P<XXX1234567890";
    m_mock->setBehavior(MockBehavior{.status = "ok", .secretBytes = std::string{mrz}});
    const auto result = m_client->requestMrz(PromptOptions{});
    EXPECT_EQ(result.status, PromptStatus::Ok);
    ASSERT_TRUE(result.secret.has_value());
    EXPECT_EQ(result.secret->view(), mrz);
    EXPECT_TRUE(result.userMessage.empty());
}

TEST_F(PrompterIntegrationTest, CancelledMapsToCancelledStatus)
{
    m_mock->setBehavior(MockBehavior{.status = "cancelled", .userMessage = "user dismissed"});
    const auto result = m_client->requestPin(PromptOptions{});
    EXPECT_EQ(result.status, PromptStatus::Cancelled);
    EXPECT_FALSE(result.secret.has_value());
    EXPECT_EQ(result.userMessage, "user dismissed");
}

TEST_F(PrompterIntegrationTest, ErrorMapsToErrorStatus)
{
    m_mock->setBehavior(MockBehavior{.status = "error", .userMessage = "no display"});
    const auto result = m_client->requestPin(PromptOptions{});
    EXPECT_EQ(result.status, PromptStatus::Error);
    EXPECT_FALSE(result.secret.has_value());
    EXPECT_EQ(result.userMessage, "no display");
}

TEST_F(PrompterIntegrationTest, SdbusErrorIsCaughtAndReportedAsError)
{
    m_mock->setBehavior(MockBehavior{
        .throwSdbusError = true,
        .sdbusErrorName = "org.test.Failure",
        .sdbusErrorMessage = "boom",
    });
    // PrompterClient's public contract is no-throw — D-Bus errors must
    // collapse onto PromptStatus::Error with the sdbus::Error::getMessage()
    // appended to userMessage. We explicitly assert this rather than catch
    // around the call to keep the regression visible.
    PromptResult result;
    ASSERT_NO_THROW(result = m_client->requestPin(PromptOptions{}));
    EXPECT_EQ(result.status, PromptStatus::Error);
    EXPECT_FALSE(result.secret.has_value());
    EXPECT_NE(result.userMessage.find("boom"), std::string::npos)
        << "userMessage should carry the underlying sdbus error text: " << result.userMessage;
}

TEST_F(PrompterIntegrationTest, EmptySecretIsOkButZeroBytes)
{
    // Zero-byte secrets are a legitimate "ok with no bytes" per the
    // SecretMemfdReader contract — the engaged optional<Secure::String>
    // distinguishes this from the read-failure case (nullopt).
    m_mock->setBehavior(MockBehavior{.status = "ok", .secretBytes = ""});
    const auto result = m_client->requestPin(PromptOptions{});
    EXPECT_EQ(result.status, PromptStatus::Ok);
    ASSERT_TRUE(result.secret.has_value());
    EXPECT_TRUE(result.secret->empty());
    EXPECT_TRUE(result.userMessage.empty());
}

TEST_F(PrompterIntegrationTest, OptionsAreForwardedToPrompter)
{
    m_mock->setBehavior(MockBehavior{.status = "ok", .secretBytes = "1234"});

    PromptOptions opts;
    opts.title = "Unlock card";
    opts.requester = "TestRequester";
    opts.artifact = "doc.pdf";
    opts.minLength = 4U;
    opts.maxLength = 8U;
    // description deliberately left empty to confirm the absent-field path
    // (PrompterClient::buildOptionsDict only inserts non-empty entries).

    const auto result = m_client->requestPin(opts);
    ASSERT_EQ(result.status, PromptStatus::Ok);

    const auto captured = m_mock->captured();
    ASSERT_TRUE(captured.seen);
    EXPECT_EQ(captured.kind, "pin");

    ASSERT_TRUE(captured.options.contains("title"));
    EXPECT_EQ(captured.options.at("title").get<std::string>(), "Unlock card");

    ASSERT_TRUE(captured.options.contains("requester"));
    EXPECT_EQ(captured.options.at("requester").get<std::string>(), "TestRequester");

    ASSERT_TRUE(captured.options.contains("artifact"));
    EXPECT_EQ(captured.options.at("artifact").get<std::string>(), "doc.pdf");

    ASSERT_TRUE(captured.options.contains("min_length"));
    EXPECT_EQ(captured.options.at("min_length").get<std::uint32_t>(), 4U);

    ASSERT_TRUE(captured.options.contains("max_length"));
    EXPECT_EQ(captured.options.at("max_length").get<std::uint32_t>(), 8U);

    EXPECT_FALSE(captured.options.contains("description"))
        << "empty PromptOptions::description must be omitted from the wire dict";
}

// Consent-honesty wiring: a populated PromptOptions::artifacts (the
// BatchSignFlow consent's untrusted per-document display-name list) must
// marshal as the `artifacts` (as) option key, distinct from — and never
// folded into — the TRUSTED `artifact` singular.
TEST_F(PrompterIntegrationTest, ArtifactsListIsForwardedAsItsOwnOptionKey)
{
    m_mock->setBehavior(MockBehavior{.status = "ok", .secretBytes = "1234"});

    PromptOptions opts;
    opts.artifact = "signature-batch";
    opts.artifacts = {"a.pdf", "b.pdf", "c.pdf"};

    const auto result = m_client->requestPin(opts);
    ASSERT_EQ(result.status, PromptStatus::Ok);

    const auto captured = m_mock->captured();
    ASSERT_TRUE(captured.seen);

    ASSERT_TRUE(captured.options.contains("artifact"));
    EXPECT_EQ(captured.options.at("artifact").get<std::string>(), "signature-batch");

    ASSERT_TRUE(captured.options.contains("artifacts"));
    EXPECT_EQ(captured.options.at("artifacts").get<std::vector<std::string>>(),
              (std::vector<std::string>{"a.pdf", "b.pdf", "c.pdf"}));
}

TEST_F(PrompterIntegrationTest, EmptyArtifactsListIsOmittedFromTheWireDict)
{
    m_mock->setBehavior(MockBehavior{.status = "ok", .secretBytes = "1234"});

    // Every single-document (non-batch) prompt: artifacts stays default-empty.
    const auto result = m_client->requestPin(PromptOptions{});
    ASSERT_EQ(result.status, PromptStatus::Ok);

    const auto captured = m_mock->captured();
    ASSERT_TRUE(captured.seen);
    EXPECT_FALSE(captured.options.contains("artifacts"))
        << "an empty PromptOptions::artifacts must be omitted from the wire dict";
}

// Retry context (CredentialCache::applyRetryContext -> PromptOptions::attempt
// / lastError -> the wire's `attempt`/`last_error` RequestSecret options).

TEST_F(PrompterIntegrationTest, DefaultOptionsOmitRetryContextFromTheWireDict)
{
    m_mock->setBehavior(MockBehavior{.status = "ok", .secretBytes = "123456"});

    // The first-ever prompt for a card: PromptOptions::attempt/lastError stay
    // at their default (0 / empty).
    const auto result = m_client->requestCan(PromptOptions{});
    ASSERT_EQ(result.status, PromptStatus::Ok);

    const auto captured = m_mock->captured();
    ASSERT_TRUE(captured.seen);
    EXPECT_FALSE(captured.options.contains("attempt"))
        << "the first-ever prompt must not carry an attempt count on the wire";
    EXPECT_FALSE(captured.options.contains("last_error"))
        << "the first-ever prompt must not carry a last_error on the wire";
}

TEST_F(PrompterIntegrationTest, RetryContextIsForwardedAsItsOwnOptionKeys)
{
    m_mock->setBehavior(MockBehavior{.status = "ok", .secretBytes = "123456"});

    PromptOptions opts;
    opts.attempt = 2;
    opts.lastError = "librescrs.error.preRead.authFailed";

    const auto result = m_client->requestCan(opts);
    ASSERT_EQ(result.status, PromptStatus::Ok);

    const auto captured = m_mock->captured();
    ASSERT_TRUE(captured.seen);

    ASSERT_TRUE(captured.options.contains("attempt"));
    EXPECT_EQ(captured.options.at("attempt").get<std::uint32_t>(), 2U);

    ASSERT_TRUE(captured.options.contains("last_error"));
    EXPECT_EQ(captured.options.at("last_error").get<std::string>(), "librescrs.error.preRead.authFailed");
}

// --- Alternative-kind rollout matrix ---------------------------------------
//
// The `alt_kinds` option and the `ok_mrz` status are ONE additive growth of
// this boundary, so both rollout directions have to hold at once. The four
// direction-pairs are: new client x new prompter, new client x old prompter,
// old client x new (or hostile) prompter, and old x old — the last being, by
// name, the rest of this suite, which stays untouched and green.

TEST_F(PrompterIntegrationTest, AltKindsRideTheOptionsDict)
{
    m_mock->setBehavior(MockBehavior{.status = wire::kStatusOk, .secretBytes = "123456"});

    PromptOptions opts;
    opts.altKinds = {wire::kKindMrz};

    const auto result = m_client->requestCan(opts);
    ASSERT_EQ(result.status, PromptStatus::Ok);

    const auto captured = m_mock->captured();
    ASSERT_TRUE(captured.seen);
    EXPECT_EQ(captured.kind, wire::kKindCan);

    ASSERT_TRUE(captured.options.contains(wire::kOptAltKinds))
        << "a populated PromptOptions::altKinds must marshal as its own option key";
    EXPECT_EQ(captured.options.at(wire::kOptAltKinds).get<std::vector<std::string>>(),
              (std::vector<std::string>{wire::kKindMrz}));
}

// New client x OLD prompter: a backend that predates the option simply lifts
// the keys it knows, so the request degrades to an ordinary CAN prompt and the
// reply is the plain success status. The client must report exactly that — no
// chosen kind, secret intact.
TEST_F(PrompterIntegrationTest, OldPrompterIgnoresAltKindsAndPlainOkStillWorks)
{
    m_mock->setBehavior(MockBehavior{.status = wire::kStatusOk, .secretBytes = "123456"});

    PromptOptions opts;
    opts.altKinds = {wire::kKindMrz};

    const auto result = m_client->requestCan(opts);
    EXPECT_EQ(result.status, PromptStatus::Ok);
    ASSERT_TRUE(result.secret.has_value());
    EXPECT_EQ(result.secret->view(), "123456");
    EXPECT_FALSE(result.chosenKind.has_value())
        << "a plain success reply carries no chosen-kind, whatever the request offered";
}

// New client x new prompter: the user took the offered switch, so the reply
// carries the distinct status and an MRZ payload. The client reports success
// AND which credential it is actually holding.
TEST_F(PrompterIntegrationTest, OkMrzMapsToChosenKindWhenSent)
{
    m_mock->setBehavior(MockBehavior{.status = wire::kStatusOkMrz, .secretBytes = std::string{kSpecimenMrzPayload}});

    PromptOptions opts;
    opts.altKinds = {wire::kKindMrz};

    const auto result = m_client->requestCan(opts);
    EXPECT_EQ(result.status, PromptStatus::Ok);
    ASSERT_TRUE(result.secret.has_value());
    EXPECT_EQ(result.secret->view(), kSpecimenMrzPayload);
    ASSERT_TRUE(result.chosenKind.has_value());
    EXPECT_EQ(*result.chosenKind, LibreSCRS::Auth::PaceSecretKind::Mrz);
}

// OLD client x new (or hostile) prompter: the request never opted in, so the
// distinct status is unexpected vocabulary. It must fail closed exactly as any
// unknown status does — never a success carrying an MRZ payload the caller
// would deposit as a CAN.
TEST_F(PrompterIntegrationTest, OkMrzWithoutOptInCollapsesToError)
{
    m_mock->setBehavior(MockBehavior{.status = wire::kStatusOkMrz, .secretBytes = std::string{kSpecimenMrzPayload}});

    const auto result = m_client->requestCan(PromptOptions{});
    EXPECT_EQ(result.status, PromptStatus::Error);
    EXPECT_FALSE(result.secret.has_value()) << "no secret may surface on an unexpected status";
    EXPECT_FALSE(result.chosenKind.has_value());
}

// The option rides ANY kind's dictionary, so the requested-kind condition on
// the parse side is the only thing standing between a future flow bug and an
// MRZ payload landing in a PIN slot. Pin it: the same opted-in request on a
// non-CAN kind still fails closed.
TEST_F(PrompterIntegrationTest, OkMrzOnNonCanRequestWithAltKindsCollapsesToError)
{
    m_mock->setBehavior(MockBehavior{.status = wire::kStatusOkMrz, .secretBytes = std::string{kSpecimenMrzPayload}});

    PromptOptions opts;
    opts.altKinds = {wire::kKindMrz};

    const auto result = m_client->requestPin(opts);
    EXPECT_EQ(result.status, PromptStatus::Error);
    EXPECT_FALSE(result.secret.has_value()) << "no secret may surface on an unexpected status";
    EXPECT_FALSE(result.chosenKind.has_value());

    const auto captured = m_mock->captured();
    ASSERT_TRUE(captured.seen);
    EXPECT_EQ(captured.kind, wire::kKindPin);
    EXPECT_TRUE(captured.options.contains(wire::kOptAltKinds))
        << "the option is marshalled for any kind — hence the parse-side kind guard";
}

// --- The offer is real, end to end -----------------------------------------
//
// Everything above scripts PromptOptions by hand, so all of it stays green even
// if NOTHING in the production read path ever sets `altKinds`. This case closes
// that hole: it runs the SAME IdentityReadFlow both platform read operations
// run, against a card whose candidate declares travel-document crypto, with the
// REAL PrompterClient talking to the mock over the private bus — and asserts the
// request that lands on the wire is kind `can` carrying `alt_kinds == {"mrz"}`.
// Nothing here sets the offer flag or installs a choice sink; both come from the
// flow's own reading of its candidate list.
//
// Observation point, stated plainly: this drives the flow directly rather than
// ReadIdentity over Card1, because the middleware's CardSession exposes no
// accessor for an installed credential provider — so a hermetic CardReader
// double (which is what every through-the-operations harness in this suite
// uses) cannot model the middleware's own on-cache-miss provider callback from
// inside a read, and no prompt would ever be issued. The flow object is the
// closest seam at which the callback can be driven, and it is the whole of what
// the operations contribute to this decision: the operations pass deps, the flow
// computes the offer. The wire, the client, the capability predicate and the
// prompt-options marshalling are all the production ones.

namespace {

// A candidate declaring identity data AND travel-document crypto: the one
// family whose pre-read secret has a CAN/MRZ duality.
class TravelDocumentCandidate final : public LibreSCRS::Plugin::CardPlugin
{
public:
    TravelDocumentCandidate()
    {
        setIdentity("travel-doc-stub", "stub", 0);
    }
    LibreSCRS::Plugin::CardCapabilities capabilities() const override
    {
        using LibreSCRS::Plugin::CardCapabilities;
        return static_cast<CardCapabilities>(static_cast<std::uint32_t>(CardCapabilities::IdentityData) |
                                             static_cast<std::uint32_t>(CardCapabilities::EmrtdCrypto));
    }
    std::span<const LibreSCRS::Plugin::Atr> supportedAtrs() const noexcept override
    {
        return {};
    }

protected:
    LibreSCRS::Plugin::ReadResult doReadCard(LibreSCRS::SmartCard::CardSession&, GroupCallback) const override
    {
        return LibreSCRS::Plugin::ReadResult::communicationError(LibreSCRS::Auth::ErrorKeys::genericComm());
    }
};

// Reader double that invokes the credential provider the flow installed, the
// way the middleware invokes it from inside readCard on a channel cache miss.
class ProviderDrivingReader final : public Operations::CardReader
{
public:
    std::function<void()> onRead;
    Operations::ReadOutcome read(LibreSCRS::SmartCard::CardSession&, const Operations::CandidateList&,
                                 LibreSCRS::CancelToken, Operations::GroupReadCallback = {}) override
    {
        if (onRead) {
            onRead();
        }
        return Operations::ReadOutcome{Operations::ReadOutcome::Status::Cancelled, std::nullopt, "cancelled"};
    }
    GroupSnapshot readTokenInfo(LibreSCRS::SmartCard::CardSession&, const Operations::CandidateList&,
                                LibreSCRS::CancelToken) override
    {
        return {};
    }
};

class SilentPhaseSink final : public Operations::OperationPhaseSink
{
public:
    void setPhase(std::uint32_t) noexcept override {}
};

} // namespace

TEST_F(PrompterIntegrationTest, ProductionReadOnEmrtdCandidateOffersMrzAlternative)
{
    // The user dismisses the dialog: this case is about the REQUEST that goes
    // out, not about what comes back.
    m_mock->setBehavior(MockBehavior{.status = wire::kStatusCancelled});

    auto factory = [](const std::string& r)
        -> std::expected<std::shared_ptr<LibreSCRS::SmartCard::CardSession>, LibreSCRS::SmartCard::OpenError> {
        return LibreSCRS::SmartCard::detail::makeDetachedCardSession(r);
    };
    auto resolver = [](std::span<const std::uint8_t>, LibreSCRS::SmartCard::CardSession&) {
        return Operations::CandidateList{std::make_shared<TravelDocumentCandidate>()};
    };
    Operations::CardSessionHolder holder("FakeReader", std::move(factory), std::move(resolver),
                                         std::make_shared<LibreSCRS::SmartCard::CardMap>());

    ProviderDrivingReader reader;
    Operations::NullCredentialDepositor depositor;
    Operations::PromptSerializer serializer;
    CredentialCache credentials;
    SilentPhaseSink phaseSink;
    Operations::NullGroupSink groupSink;
    LibreSCRS::CancelSource cancelSource;

    Operations::IdentityReadFlow flow(Operations::IdentityReadFlowDeps{
        .holder = holder,
        .reader = reader,
        .prompter = *m_client,
        .serializer = serializer,
        .cache = credentials,
        .phaseSink = phaseSink,
        .groupSink = groupSink,
        .cardKey = "/org/librescrs/Agent/card/1",
        .requester = "integration-test",
        .artifact = "identity",
        .token = cancelSource.token(),
        .depositor = depositor,
    });
    reader.onRead = [&flow] {
        static_cast<void>(flow.credentialProvider()(LibreSCRS::Auth::AuthRequirement::forPaceSecret(
            LibreSCRS::SmartCard::AppletAid{}, LibreSCRS::Auth::PaceSecretKind::Can, std::nullopt,
            LibreSCRS::LocalizedText{})));
    };

    const auto result = flow.run();
    EXPECT_EQ(result.outcome, Operations::IdentityReadFlow::Outcome::Cancelled);

    const auto captured = m_mock->captured();
    ASSERT_TRUE(captured.seen) << "the production read must actually have prompted";
    EXPECT_EQ(captured.kind, wire::kKindCan);
    ASSERT_TRUE(captured.options.contains(wire::kOptAltKinds))
        << "a travel-document card's CAN prompt must offer the MRZ alternative";
    EXPECT_EQ(captured.options.at(wire::kOptAltKinds).get<std::vector<std::string>>(),
              (std::vector<std::string>{wire::kKindMrz}));
}
