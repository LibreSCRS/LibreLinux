// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Interactive prompts are answered at HUMAN speed. The regression under test:
// PrompterClient's RequestSecret ran on the D-Bus DEFAULT method timeout
// (~25 s), so any entry slower than that — reading the MRZ off a lifted
// passport, calendar date entry, careful PIN typing — aborted the call while
// the user was still typing: the agent logged "Connection timed out", the
// dialog stayed up, and the eventual submit had no consumer. Observed on real
// hardware with the MRZ form; latent for every interactive kind.
//
// The mock prompter here answers only after a delay LONGER than the D-Bus
// default timeout. The client must still receive the reply: interactive
// requests carry an explicit generous budget, and prompt teardown is
// event-driven (CancelCurrent), never wall-clock-driven. Deliberately a slow
// test (~half a minute) — it is the only honest end-to-end proof.

#include "PrompterClient.h"
#include "org.librescrs.Prompter1_adaptor.h"

#include "SealedMemfdCreator.h"

#include <sdbus-c++/AdaptorInterfaces.h>
#include <sdbus-c++/IConnection.h>
#include <sdbus-c++/Types.h>
#include <gtest/gtest.h>

#include <chrono>
#include <cstdint>
#include <map>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <thread>
#include <tuple>
#include <utility>

using namespace LibreSCRS::Agent;

namespace {

constexpr const char* kMockServiceName = "org.librescrs.Prompter1.BudgetTest";
constexpr const char* kMockObjectPath = "/org/librescrs/Prompter1";

// Longer than the sd-bus default method timeout (25 s) by a safe margin, so
// the pre-fix client deterministically times out and the post-fix client
// deterministically survives.
constexpr std::chrono::seconds kReplyDelay{27};

constexpr std::string_view kSecretBytes = "L898902C36\n7408122\n1204159";

int makeSealedFd(std::string_view bytes)
{
    return LibreLinux::Common::makeSealedMemfd(
        "librescrs-test-secret",
        std::span<const std::uint8_t>{reinterpret_cast<const std::uint8_t*>(bytes.data()), bytes.size()});
}

// Prompter that behaves like a real human-paced dialog: the reply arrives
// well after the D-Bus default method timeout has elapsed.
class SlowMockPrompter final : public sdbus::AdaptorInterfaces<org::librescrs::Prompter1_adaptor>
{
public:
    SlowMockPrompter(sdbus::IConnection& connection, sdbus::ObjectPath path)
        : AdaptorInterfaces(connection, std::move(path))
    {
        registerAdaptor();
    }
    ~SlowMockPrompter()
    {
        unregisterAdaptor();
    }

    SlowMockPrompter(const SlowMockPrompter&) = delete;
    SlowMockPrompter& operator=(const SlowMockPrompter&) = delete;
    SlowMockPrompter(SlowMockPrompter&&) = delete;
    SlowMockPrompter& operator=(SlowMockPrompter&&) = delete;

private:
    std::tuple<std::string, sdbus::UnixFd, std::string>
    RequestSecret(const std::string& /*kind*/, const std::map<std::string, sdbus::Variant>& /*options*/) override
    {
        // Blocking the adaptor's event-loop thread is exactly the shape of a
        // modal dialog waiting on the user.
        std::this_thread::sleep_for(kReplyDelay);
        return std::make_tuple(std::string{"ok"}, sdbus::UnixFd{makeSealedFd(kSecretBytes), sdbus::adopt_fd},
                               std::string{});
    }

    std::tuple<std::string, sdbus::UnixFd, sdbus::UnixFd, std::string>
    RequestSecrets(const std::string& /*kind*/, const std::map<std::string, sdbus::Variant>& /*options*/) override
    {
        return std::make_tuple(std::string{"error"}, sdbus::UnixFd{makeSealedFd(""), sdbus::adopt_fd},
                               sdbus::UnixFd{makeSealedFd(""), sdbus::adopt_fd},
                               std::string{"RequestSecrets not scripted in this mock"});
    }

    void CancelCurrent() override
    {
        // No live dialog in the mock; cancel is a no-op here.
    }
};

} // namespace

TEST(PrompterClientInteractiveBudget, SurvivesHumanPacedReplyBeyondDbusDefaultTimeout)
{
    auto serverConn = sdbus::createSessionBusConnection();
    ASSERT_NE(serverConn, nullptr) << "private session bus (run under dbus-run-session)";
    serverConn->requestName(sdbus::ServiceName{kMockServiceName});
    SlowMockPrompter mock{*serverConn, sdbus::ObjectPath{kMockObjectPath}};
    serverConn->enterEventLoopAsync();

    std::shared_ptr<sdbus::IConnection> clientConn = sdbus::createSessionBusConnection();
    clientConn->enterEventLoopAsync();
    PrompterClient client{clientConn, kMockServiceName, kMockObjectPath};

    const auto result = client.requestMrz({});

    EXPECT_EQ(result.status, PromptStatus::Ok)
        << "a reply slower than the D-Bus default method timeout must still be received: " << result.userMessage;
    ASSERT_TRUE(result.secret.has_value());
    EXPECT_EQ(result.secret->view(), kSecretBytes);

    clientConn->leaveEventLoop();
    serverConn->leaveEventLoop();
}
