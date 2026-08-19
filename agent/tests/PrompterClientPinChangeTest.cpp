// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// End-to-end exercise of PrompterClient::requestPinChange against a mock
// Prompter1 adaptor hosted in the same test process on a private session bus
// (dbus-run-session; see CMakeLists.txt). Sibling of PrompterIntegrationTest,
// but scripts the MULTI-secret RequestSecrets reply: two sealed fds (primary =
// current PIN, secondary = new PIN). The confirm re-entry never crosses the
// wire. Two separate sdbus connections (server hosts, client proxies) keep
// sd-bus from self-calling (ELOOP).
//
// The security-critical property under test: on a seal-verification failure of
// EITHER fd, NO partial secret escapes into PinChangePromptResult — a naive
// implementation that assigns the successfully-read PIN before validating the
// other fd is caught by SealFailureOnSecondaryFdLeaksNoPartialSecret.

#include "PrompterClient.h"
#include "org.librescrs.Prompter1_adaptor.h"

#include "SealedMemfdCreator.h" // shared sealed-memfd creator (matches the producer)

#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>

#include <sdbus-c++/AdaptorInterfaces.h>
#include <sdbus-c++/Error.h>
#include <sdbus-c++/IConnection.h>
#include <sdbus-c++/Types.h>
#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <span>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>

using namespace LibreSCRS::Agent;

namespace {

constexpr const char* kMockServiceName = "org.librescrs.Prompter1.Test";
constexpr const char* kMockObjectPath = "/org/librescrs/Prompter1";

// A correctly-sealed memfd, produced exactly as the prompter does (one seal-set
// definition tree-wide).
int makeSealedFd(std::string_view bytes)
{
    return LibreLinux::Common::makeSealedMemfd(
        "librescrs-test-secret",
        std::span<const std::uint8_t>{reinterpret_cast<const std::uint8_t*>(bytes.data()), bytes.size()});
}

// An UNSEALED memfd (same creation + write, F_ADD_SEALS deliberately skipped):
// the shape a rogue prompter could hand back to keep the fd writable/growable.
// SecretMemfdReader must reject it, so the change_pin client must treat it as a
// read failure and emit NO secret.
int makeUnsealedFd(std::string_view bytes)
{
    const int fd = ::memfd_create("librescrs-test-unsealed", MFD_CLOEXEC | MFD_ALLOW_SEALING);
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
    return fd;
}

// Per-call scripted response consulted on every RequestSecrets: which status to
// return, the two payloads, whether to seal each fd, and whether to throw.
struct MultiBehavior
{
    bool throwSdbusError = false;
    std::string sdbusErrorName;
    std::string sdbusErrorMessage;
    std::string status;         // returned status string ("ok"/"cancelled"/"error"/"unauthorized")
    std::string primaryBytes;   // wrapped into a fresh sealed memfd on each call (current PIN)
    std::string secondaryBytes; // wrapped into a fresh sealed memfd on each call (new PIN)
    bool sealPrimary = true;    // clear to hand back an unsealed primary fd
    bool sealSecondary = true;  // clear to hand back an unsealed secondary fd
    std::string userMessage;
};

// Captured (kind, options) from the most recent RequestSecrets invocation.
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

    void setBehavior(MultiBehavior behavior)
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
    static int makeFd(std::string_view bytes, bool sealed)
    {
        return sealed ? makeSealedFd(bytes) : makeUnsealedFd(bytes);
    }

    std::tuple<std::string, sdbus::UnixFd, sdbus::UnixFd, std::string>
    RequestSecrets(const std::string& kind, const std::map<std::string, sdbus::Variant>& options) override
    {
        MultiBehavior behavior;
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

        const int primary = makeFd(behavior.primaryBytes, behavior.sealPrimary);
        const int secondary = makeFd(behavior.secondaryBytes, behavior.sealSecondary);
        return std::make_tuple(behavior.status, sdbus::UnixFd{primary, sdbus::adopt_fd},
                               sdbus::UnixFd{secondary, sdbus::adopt_fd}, behavior.userMessage);
    }

    // Single-secret variant — not scripted by this suite; a fixed "error" reply
    // with the zero-byte no-secret encoding satisfies the adaptor's pure virtual.
    std::tuple<std::string, sdbus::UnixFd, std::string>
    RequestSecret(const std::string& /*kind*/, const std::map<std::string, sdbus::Variant>& /*options*/) override
    {
        return std::make_tuple(std::string{"error"}, sdbus::UnixFd{makeSealedFd(""), sdbus::adopt_fd},
                               std::string{"RequestSecret not scripted in this mock"});
    }

    void Cancel(const std::string& promptId) override
    {
        (void)promptId;
        // No live dialog in the mock; cancel is a no-op here.
    }

    mutable std::mutex m_mutex;
    MultiBehavior m_behavior;
    CapturedCall m_captured;
};

// Fixture: fresh server + client connection per test (clean event-loop state).
// The mock claims its well-known name on the server connection; the client
// proxies against a SEPARATE connection (sd-bus refuses to dispatch self-calls).
class PrompterClientPinChangeTest : public ::testing::Test
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
        m_client = std::make_unique<PrompterClient>(kMockServiceName, kMockObjectPath);
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

TEST_F(PrompterClientPinChangeTest, OkRoundTripReturnsBothSecrets)
{
    m_mock->setBehavior(MultiBehavior{.status = "ok", .primaryBytes = "1234", .secondaryBytes = "5678"});

    const auto result = m_client->requestPinChange(PromptOptions{});

    EXPECT_EQ(result.status, PromptStatus::Ok);
    ASSERT_TRUE(result.current.has_value());
    ASSERT_TRUE(result.newPin.has_value());
    EXPECT_EQ(result.current->view(), "1234");
    EXPECT_EQ(result.newPin->view(), "5678");
    EXPECT_TRUE(result.userMessage.empty());
}

TEST_F(PrompterClientPinChangeTest, OkWithEmptySecretsIsTolerated)
{
    // Zero-byte-but-sealed payloads are the legitimate "ok with empty entry"
    // encoding (engaged-but-empty Secure::String), mirroring the single-secret
    // reader contract. Not expected for change_pin in practice, but tolerated.
    m_mock->setBehavior(MultiBehavior{.status = "ok", .primaryBytes = "", .secondaryBytes = ""});

    const auto result = m_client->requestPinChange(PromptOptions{});

    EXPECT_EQ(result.status, PromptStatus::Ok);
    ASSERT_TRUE(result.current.has_value());
    ASSERT_TRUE(result.newPin.has_value());
    EXPECT_TRUE(result.current->empty());
    EXPECT_TRUE(result.newPin->empty());
}

TEST_F(PrompterClientPinChangeTest, CancelledYieldsNoSecrets)
{
    // cancelled => both fds are zero-length sealed memfds (the established
    // no-secret encoding); no secret is constructed.
    m_mock->setBehavior(MultiBehavior{
        .status = "cancelled", .primaryBytes = "", .secondaryBytes = "", .userMessage = "user dismissed"});

    const auto result = m_client->requestPinChange(PromptOptions{});

    EXPECT_EQ(result.status, PromptStatus::Cancelled);
    EXPECT_FALSE(result.current.has_value());
    EXPECT_FALSE(result.newPin.has_value());
    EXPECT_EQ(result.userMessage, "user dismissed");
}

TEST_F(PrompterClientPinChangeTest, UnauthorizedMapsToErrorAndZeroBytePairIsTolerated)
{
    // unauthorized is the prompter's fail-closed rejection of a non-agent
    // caller; it collapses to Error client-side and pairs with two zero-byte
    // sealed fds that must be tolerated (closed, no secret constructed).
    m_mock->setBehavior(MultiBehavior{
        .status = "unauthorized", .primaryBytes = "", .secondaryBytes = "", .userMessage = "not authorized"});

    const auto result = m_client->requestPinChange(PromptOptions{});

    EXPECT_EQ(result.status, PromptStatus::Error);
    EXPECT_FALSE(result.current.has_value());
    EXPECT_FALSE(result.newPin.has_value());
    EXPECT_EQ(result.userMessage, "not authorized");
}

TEST_F(PrompterClientPinChangeTest, ErrorStatusYieldsNoSecrets)
{
    m_mock->setBehavior(
        MultiBehavior{.status = "error", .primaryBytes = "", .secondaryBytes = "", .userMessage = "no display"});

    const auto result = m_client->requestPinChange(PromptOptions{});

    EXPECT_EQ(result.status, PromptStatus::Error);
    EXPECT_FALSE(result.current.has_value());
    EXPECT_FALSE(result.newPin.has_value());
    EXPECT_EQ(result.userMessage, "no display");
}

TEST_F(PrompterClientPinChangeTest, SealFailureOnPrimaryFdYieldsErrorNoSecret)
{
    // Status is ok but the primary fd is UNSEALED: SecretMemfdReader rejects it.
    // The whole change fails closed with Error and NEITHER secret escapes.
    m_mock->setBehavior(
        MultiBehavior{.status = "ok", .primaryBytes = "1234", .secondaryBytes = "5678", .sealPrimary = false});

    const auto result = m_client->requestPinChange(PromptOptions{});

    EXPECT_EQ(result.status, PromptStatus::Error);
    EXPECT_FALSE(result.current.has_value());
    EXPECT_FALSE(result.newPin.has_value());
    EXPECT_FALSE(result.userMessage.empty()) << "a transport diagnostic must be surfaced";
}

TEST_F(PrompterClientPinChangeTest, SealFailureOnSecondaryFdLeaksNoPartialSecret)
{
    // The discriminating case: the PRIMARY fd is validly sealed (its PIN reads
    // back fine) but the SECONDARY fd is unsealed and rejected. A naive client
    // that assigned result.current before validating the secondary would leak
    // the current PIN; the correct client scrubs both and emits NOTHING.
    m_mock->setBehavior(
        MultiBehavior{.status = "ok", .primaryBytes = "1234", .secondaryBytes = "5678", .sealSecondary = false});

    const auto result = m_client->requestPinChange(PromptOptions{});

    EXPECT_EQ(result.status, PromptStatus::Error);
    EXPECT_FALSE(result.current.has_value()) << "no partial secret may escape when the other fd is rejected";
    EXPECT_FALSE(result.newPin.has_value());
    EXPECT_FALSE(result.userMessage.empty()) << "a transport diagnostic must be surfaced";
}

TEST_F(PrompterClientPinChangeTest, SdbusErrorIsCaughtAndReportedAsError)
{
    // PrompterClient's public contract is no-throw: a D-Bus failure collapses
    // onto Error with the underlying message carried in userMessage.
    m_mock->setBehavior(
        MultiBehavior{.throwSdbusError = true, .sdbusErrorName = "org.test.Failure", .sdbusErrorMessage = "boom"});

    PinChangePromptResult result;
    ASSERT_NO_THROW(result = m_client->requestPinChange(PromptOptions{}));
    EXPECT_EQ(result.status, PromptStatus::Error);
    EXPECT_FALSE(result.current.has_value());
    EXPECT_FALSE(result.newPin.has_value());
    EXPECT_NE(result.userMessage.find("boom"), std::string::npos)
        << "userMessage should carry the underlying sdbus error text: " << result.userMessage;
}

TEST_F(PrompterClientPinChangeTest, OptionsMapOntoChangePinWireVocabulary)
{
    m_mock->setBehavior(MultiBehavior{.status = "ok", .primaryBytes = "1234", .secondaryBytes = "5678"});

    PromptOptions opts;
    opts.title = "Change card PIN";
    opts.requester = "TestRequester";
    opts.artifact = "eID";
    opts.cardLabel = "identity card";
    opts.pinLabel = "Signature PIN";
    opts.minLength = 4U;
    opts.maxLength = 8U;
    // description deliberately empty to confirm the absent-field path.

    const auto result = m_client->requestPinChange(opts);
    ASSERT_EQ(result.status, PromptStatus::Ok);

    const auto captured = m_mock->captured();
    ASSERT_TRUE(captured.seen);
    EXPECT_EQ(captured.kind, "change_pin");

    ASSERT_TRUE(captured.options.contains("title"));
    EXPECT_EQ(captured.options.at("title").get<std::string>(), "Change card PIN");
    ASSERT_TRUE(captured.options.contains("requester"));
    EXPECT_EQ(captured.options.at("requester").get<std::string>(), "TestRequester");
    ASSERT_TRUE(captured.options.contains("artifact"));
    EXPECT_EQ(captured.options.at("artifact").get<std::string>(), "eID");

    // The single seam bound pair maps onto BOTH per-role field bounds the
    // change_pin dialog exposes (current => primary_*, new/confirm => new_*).
    ASSERT_TRUE(captured.options.contains("primary_min_length"));
    EXPECT_EQ(captured.options.at("primary_min_length").get<std::uint32_t>(), 4U);
    ASSERT_TRUE(captured.options.contains("primary_max_length"));
    EXPECT_EQ(captured.options.at("primary_max_length").get<std::uint32_t>(), 8U);
    ASSERT_TRUE(captured.options.contains("new_min_length"));
    EXPECT_EQ(captured.options.at("new_min_length").get<std::uint32_t>(), 4U);
    ASSERT_TRUE(captured.options.contains("new_max_length"));
    EXPECT_EQ(captured.options.at("new_max_length").get<std::uint32_t>(), 8U);

    // The display-only labels the change_pin dialog consumes: the card the
    // change applies to and the PIN role being changed.
    ASSERT_TRUE(captured.options.contains("card_label"));
    EXPECT_EQ(captured.options.at("card_label").get<std::string>(), "identity card");
    ASSERT_TRUE(captured.options.contains("pin_label"));
    EXPECT_EQ(captured.options.at("pin_label").get<std::string>(), "Signature PIN");

    // The single-secret min_length/max_length keys are NOT used for change_pin.
    EXPECT_FALSE(captured.options.contains("min_length"));
    EXPECT_FALSE(captured.options.contains("max_length"));
    // Empty description must be omitted from the wire dict.
    EXPECT_FALSE(captured.options.contains("description"));
}

// The change modal's TITLE belongs to the prompter (its localized "Change PIN"
// action title): an empty title (the production PinChangeFlow shape) must be
// OMITTED from the dict — never sent as an empty string that would blank the
// dialog title — while the labels still cross.
TEST_F(PrompterClientPinChangeTest, EmptyTitleIsOmittedSoThePrompterOwnsTheActionTitle)
{
    m_mock->setBehavior(MultiBehavior{.status = "ok", .primaryBytes = "1234", .secondaryBytes = "5678"});

    PromptOptions opts;
    opts.cardLabel = "identity card";
    opts.pinLabel = "User PIN";

    const auto result = m_client->requestPinChange(opts);
    ASSERT_EQ(result.status, PromptStatus::Ok);

    const auto captured = m_mock->captured();
    ASSERT_TRUE(captured.seen);
    EXPECT_FALSE(captured.options.contains("title")) << "empty title must be omitted (prompter default applies)";
    ASSERT_TRUE(captured.options.contains("card_label"));
    ASSERT_TRUE(captured.options.contains("pin_label"));
}
