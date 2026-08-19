// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// End-to-end exercise of the headless environment-driven test prompter
// (EnvPrompterService) over a REAL private session bus: the same
// caller-identity trust gate as the production prompter (CallerAuthorizer,
// authorised here via the LIBRELINUX_TESTING env-override escape hatch, same
// convention as PrompterAuthIntegrationTest), answering RequestSecret from
// LIBRESCRS_TEST_PIN/CAN/MRZ, and the per-kind burn-through guard tripped by
// the wire's `attempt` retry-context option.
//
// No Qt/dialog involved (this prompter never shows UI), so unlike
// PrompterAuthIntegrationTest this needs no QApplication/event-loop dance —
// every call is synchronous and returns immediately. Runs under
// dbus-run-session (private bus); no display server needed at all.

#include "EnvPrompterService.h"

#include "org.librescrs.Prompter1_proxy.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <sdbus-c++/IConnection.h>
#include <sdbus-c++/IProxy.h>
#include <sdbus-c++/Types.h>

#include <gtest/gtest.h>

#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <map>
#include <memory>
#include <string>
#include <tuple>
#include <vector>

namespace {

constexpr const char* kServiceName = "org.librescrs.Prompter1.EnvTest";
constexpr const char* kObjectPath = "/org/librescrs/Prompter1";
constexpr const char* kPeerEnv = "LIBRESCRS_PROMPTER_EXPECTED_PEER";

// Canonical path of the running test executable -- the value the in-process
// caller's /proc/<pid>/exe resolves to (same technique as
// PrompterAuthIntegrationTest's selfExe()).
std::filesystem::path selfExe()
{
    std::error_code ec;
    auto p = std::filesystem::read_symlink("/proc/self/exe", ec);
    EXPECT_FALSE(ec) << "read /proc/self/exe failed: " << ec.message();
    return std::filesystem::weakly_canonical(p, ec);
}

// On-the-fly proxy over the generated Prompter1_proxy.
class Prompter1Client final : public sdbus::ProxyInterfaces<org::librescrs::Prompter1_proxy>
{
public:
    Prompter1Client(sdbus::IConnection& connection, std::string service, std::string path)
        : ProxyInterfaces(connection, sdbus::ServiceName{std::move(service)}, sdbus::ObjectPath{std::move(path)})
    {
        registerProxy();
    }
    ~Prompter1Client()
    {
        unregisterProxy();
    }
    Prompter1Client(const Prompter1Client&) = delete;
    Prompter1Client& operator=(const Prompter1Client&) = delete;
};

// Read the full contents of a (sealed, immutable) fd from the start.
std::string readAll(int fd)
{
    struct ::stat st{};
    if (fd < 0 || ::fstat(fd, &st) != 0) {
        return {};
    }
    std::string out(static_cast<std::size_t>(st.st_size), '\0');
    if (!out.empty()) {
        ::lseek(fd, 0, SEEK_SET);
        ssize_t got = ::read(fd, out.data(), out.size());
        if (got < 0 || static_cast<std::size_t>(got) != out.size()) {
            return {};
        }
    }
    return out;
}

std::map<std::string, sdbus::Variant> attemptOptions(std::uint32_t attempt)
{
    std::map<std::string, sdbus::Variant> opts;
    opts.emplace("attempt", sdbus::Variant{attempt});
    return opts;
}

class EnvPrompterServiceTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        ::setenv(kPeerEnv, selfExe().string().c_str(), 1);

        m_serverConn = sdbus::createSessionBusConnection();
        ASSERT_NE(m_serverConn, nullptr) << "private session bus (run under dbus-run-session)";
        m_serverConn->requestName(sdbus::ServiceName{kServiceName});
        m_service =
            std::make_unique<LibreLinux::Prompter::EnvPrompterService>(*m_serverConn, sdbus::ObjectPath{kObjectPath});
        m_serverConn->enterEventLoopAsync();

        m_clientConn = sdbus::createSessionBusConnection();
        m_clientConn->enterEventLoopAsync();
        m_client = std::make_unique<Prompter1Client>(*m_clientConn, kServiceName, kObjectPath);
    }

    void TearDown() override
    {
        m_client.reset();
        m_clientConn->leaveEventLoop();
        m_service.reset();
        m_serverConn->leaveEventLoop();
        ::unsetenv(kPeerEnv);
        ::unsetenv("LIBRESCRS_TEST_PIN");
        ::unsetenv("LIBRESCRS_TEST_CAN");
        ::unsetenv("LIBRESCRS_TEST_MRZ");
    }

    std::unique_ptr<sdbus::IConnection> m_serverConn;
    std::unique_ptr<sdbus::IConnection> m_clientConn;
    std::unique_ptr<LibreLinux::Prompter::EnvPrompterService> m_service;
    std::unique_ptr<Prompter1Client> m_client;
};

} // namespace

// --- First-ever request per kind: answers from the env, no retry context ---

TEST_F(EnvPrompterServiceTest, FirstPinRequestReturnsTheEnvSecret)
{
    ::setenv("LIBRESCRS_TEST_PIN", "1234", 1);
    auto result = m_client->RequestSecret("pin", {});
    EXPECT_EQ(std::get<0>(result), "ok");
    EXPECT_EQ(readAll(std::get<1>(result).get()), "1234");
    EXPECT_TRUE(std::get<2>(result).empty());
}

TEST_F(EnvPrompterServiceTest, FirstCanRequestReturnsTheEnvSecret)
{
    ::setenv("LIBRESCRS_TEST_CAN", "654321", 1);
    auto result = m_client->RequestSecret("can", {});
    EXPECT_EQ(std::get<0>(result), "ok");
    EXPECT_EQ(readAll(std::get<1>(result).get()), "654321");
}

TEST_F(EnvPrompterServiceTest, FirstMrzRequestReturnsTheEnvSecret)
{
    ::setenv("LIBRESCRS_TEST_MRZ", "P<UTOERIKSSON<<ANNA<MARIA", 1);
    auto result = m_client->RequestSecret("mrz", {});
    EXPECT_EQ(std::get<0>(result), "ok");
    EXPECT_EQ(readAll(std::get<1>(result).get()), "P<UTOERIKSSON<<ANNA<MARIA");
}

TEST_F(EnvPrompterServiceTest, UnrecognisedKindReturnsErrorWithNoSecret)
{
    auto result = m_client->RequestSecret("bogus", {});
    EXPECT_EQ(std::get<0>(result), "error");
    EXPECT_EQ(readAll(std::get<1>(result).get()), "");
}

TEST_F(EnvPrompterServiceTest, MissingEnvVarReturnsErrorNotASecret)
{
    // LIBRESCRS_TEST_CAN deliberately unset.
    auto result = m_client->RequestSecret("can", {});
    EXPECT_EQ(std::get<0>(result), "error");
    EXPECT_EQ(readAll(std::get<1>(result).get()), "");
}

// --- Burn-through guard: a retry-context request refuses, and TRIPS the
// guard so every LATER request for that same kind also refuses -- mirroring
// g_pinFailed's "never present the secret again" discipline for whichever
// kind actually carries `attempt`. In a real agent-driven run that is ONLY
// CAN/MRZ (CredentialCache::applyRetryContext); the PIN case below
// hand-injects `attempt` purely to exercise the same mechanism uniformly --
// the real agent never attaches `attempt` to a PIN request (see
// EnvPrompterService.h), so this scenario cannot occur from genuine agent
// traffic. Real PIN burn-through protection is the harness's own
// g_pinFailed/SKIP_IF_PIN_FAILED discipline, not this guard. ---

TEST_F(EnvPrompterServiceTest, RetryContextRequestIsRefusedAndTripsTheGuardForThatKind)
{
    ::setenv("LIBRESCRS_TEST_PIN", "1234", 1);

    // NOTE: attemptOptions(2) below is a HAND-INJECTED retry signal to
    // exercise the guard mechanism on "pin" -- it does not model how the real
    // agent talks to this prompter (PIN prompts never carry `attempt`; see
    // EnvPrompterService.h). Any kind would do here; PIN is used only for
    // parallelism with the CAN/MRZ cases above.
    //
    // A re-prompt (attempt > 0): the previous "1234" was rejected by the
    // card. The service must refuse rather than hand it out again.
    auto retry = m_client->RequestSecret("pin", attemptOptions(2));
    EXPECT_EQ(std::get<0>(retry), "error");
    EXPECT_EQ(readAll(std::get<1>(retry).get()), "");

    // A LATER request for the SAME kind, even one that looks like a fresh
    // first-ever ask (no attempt option), must still be refused: the guard
    // is per-process, not per-request, exactly like g_pinFailed.
    auto again = m_client->RequestSecret("pin", {});
    EXPECT_EQ(std::get<0>(again), "error") << "the burn-through guard must persist past the tripping request";
    EXPECT_EQ(readAll(std::get<1>(again).get()), "");
}

TEST_F(EnvPrompterServiceTest, BurnThroughGuardIsPerKindNotGlobal)
{
    ::setenv("LIBRESCRS_TEST_PIN", "1234", 1);
    ::setenv("LIBRESCRS_TEST_CAN", "654321", 1);

    // Trip the PIN guard.
    auto pinRetry = m_client->RequestSecret("pin", attemptOptions(2));
    EXPECT_EQ(std::get<0>(pinRetry), "error");

    // A fresh CAN request is UNAFFECTED -- the guard is scoped per secret
    // kind, matching the header's documented per-kind atomics.
    auto can = m_client->RequestSecret("can", {});
    EXPECT_EQ(std::get<0>(can), "ok");
    EXPECT_EQ(readAll(std::get<1>(can).get()), "654321");
}

// --- change_pin is out of scope: always refuses -----------------------------

TEST_F(EnvPrompterServiceTest, RequestSecretsAlwaysRefuses)
{
    auto result = m_client->RequestSecrets("change_pin", {});
    EXPECT_EQ(std::get<0>(result), "error");
    EXPECT_EQ(readAll(std::get<1>(result).get()), "");
    EXPECT_EQ(readAll(std::get<2>(result).get()), "");
}

// --- Cancel: nothing to dismiss, must never throw ---------------------------

TEST_F(EnvPrompterServiceTest, CancelIsANoOpAndNeverThrows)
{
    EXPECT_NO_THROW(m_client->Cancel("nonce:1"));
}

// --- Same trust boundary as the production prompter -------------------------

TEST_F(EnvPrompterServiceTest, UnauthorizedCallerGetsUnauthorizedStatus)
{
    ::setenv(kPeerEnv, "/usr/bin/true", 1); // re-point: our own exe no longer matches
    ::setenv("LIBRESCRS_TEST_PIN", "1234", 1);

    auto result = m_client->RequestSecret("pin", {});
    EXPECT_EQ(std::get<0>(result), "unauthorized");
    EXPECT_EQ(readAll(std::get<1>(result).get()), "") << "an unauthorized caller must never receive the env secret";
}
