// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Two credential windows at once, over a REAL session bus.
//
// This is the case the whole redesign exists for: a CAN entry on one reader and
// a PIN entry on another, standing side by side, each dismissable on its own.
// It was unreachable before, on three counts that this pins one at a time —
// the handler held the GUI thread inside a nested modal loop so a second
// request could not even be built; the window was application-modal so it would
// have stacked; and there was one dialog slot, so a dismissal closed whichever
// dialog was current rather than the one it meant.
//
// The focus rule is here too, and it is security-relevant rather than cosmetic:
// a window that took focus would collect the rest of a PIN the holder was
// typing into ANOTHER card's field. The observed effect needs a desk, but the
// MECHANISM is assertable offscreen and that is what is asserted.
//
// Runs under dbus-run-session (private bus) + QT_QPA_PLATFORM=offscreen.

#include "PromptDialog.h"
#include "PromptRegistry.h"
#include "PrompterService.h"
#include "PrompterWire.h"

#include "org.librescrs.Prompter1_proxy.h"

#include <QApplication>
#include <QTimer>

#include <unistd.h> // getpid

#include <sdbus-c++/IConnection.h>
#include <sdbus-c++/IProxy.h>
#include <sdbus-c++/Types.h>

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <map>
#include <memory>
#include <string>
#include <thread>
#include <tuple>

using LibreLinux::Prompter::PromptDialog;
using LibreLinux::Prompter::PrompterService;

namespace {

constexpr const char* kServiceName = "org.librescrs.Prompter1.ConcurrentTest";
constexpr const char* kObjectPath = "/org/librescrs/Prompter1";
constexpr const char* kPeerEnv = "LIBRESCRS_PROMPTER_EXPECTED_PEER";

namespace wire = LibreLinux::PrompterWire;

std::filesystem::path selfExe()
{
    std::error_code ec;
    auto p = std::filesystem::read_symlink("/proc/self/exe", ec);
    EXPECT_FALSE(ec) << "read /proc/self/exe failed: " << ec.message();
    return std::filesystem::weakly_canonical(p, ec);
}

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

std::map<std::string, sdbus::Variant> optionsWithId(const char* promptId)
{
    return {{wire::kOptPromptId, sdbus::Variant{std::string{promptId}}}};
}

// Pump the Qt event loop on THIS thread until @p pred holds or @p budget
// elapses. The windows are raised by functors posted to this thread, so
// spinning without pumping would wait for something that cannot happen.
template <class Pred>
bool pumpUntil(Pred pred, std::chrono::milliseconds budget)
{
    const auto deadline = std::chrono::steady_clock::now() + budget;
    while (std::chrono::steady_clock::now() < deadline) {
        if (pred()) {
            return true;
        }
        QCoreApplication::processEvents(QEventLoop::AllEvents, 5);
        std::this_thread::sleep_for(std::chrono::milliseconds{2});
    }
    QCoreApplication::processEvents(QEventLoop::AllEvents, 5);
    return pred();
}

PromptDialog* windowNamed(const std::string& promptId)
{
    auto& registry = PrompterService::registryForTest();
    const auto handle = registry.findByPromptId(promptId);
    if (!handle) {
        return nullptr;
    }
    const auto entry = registry.find(*handle);
    return entry ? entry->window : nullptr;
}

// A request driven from its own thread and connection, exactly as two reader
// workers would: each blocks on its own reply while the other proceeds.
struct DrivenRequest
{
    std::unique_ptr<sdbus::IConnection> connection;
    std::unique_ptr<Prompter1Client> client;
    std::thread driver;
    std::tuple<std::string, sdbus::UnixFd, std::string> reply;
    std::atomic<bool> answered{false};

    void start(const char* kind, const char* promptId)
    {
        connection = sdbus::createSessionBusConnection();
        connection->enterEventLoopAsync();
        client = std::make_unique<Prompter1Client>(*connection, kServiceName, kObjectPath);
        driver = std::thread([this, kind, promptId] {
            reply = client->RequestSecret(kind, optionsWithId(promptId));
            answered.store(true, std::memory_order_release);
        });
    }

    void join()
    {
        if (driver.joinable()) {
            driver.join();
        }
        client.reset();
        if (connection) {
            connection->leaveEventLoop();
        }
    }
};

class PrompterConcurrentWindowsTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        // "The caller IS the configured agent": the in-process caller's
        // /proc/self/exe is what the trust gate is pointed at.
        ::setenv(kPeerEnv, selfExe().c_str(), 1);

        m_serverConn = sdbus::createSessionBusConnection();
        ASSERT_NE(m_serverConn, nullptr) << "private session bus (run under dbus-run-session)";
        m_serverConn->requestName(sdbus::ServiceName{kServiceName});
        m_service = std::make_unique<PrompterService>(*m_serverConn, sdbus::ObjectPath{kObjectPath});
        m_serverConn->enterEventLoopAsync();

        m_cancelConn = sdbus::createSessionBusConnection();
        m_cancelConn->enterEventLoopAsync();
        m_cancelClient = std::make_unique<Prompter1Client>(*m_cancelConn, kServiceName, kObjectPath);
    }

    void TearDown() override
    {
        m_cancelClient.reset();
        m_cancelConn->leaveEventLoop();
        m_service.reset();
        m_serverConn->leaveEventLoop();
        static_cast<void>(PrompterService::registryForTest().takeAll());
        ::unsetenv(kPeerEnv);
    }

    std::unique_ptr<sdbus::IConnection> m_serverConn;
    std::unique_ptr<sdbus::IConnection> m_cancelConn;
    std::unique_ptr<PrompterService> m_service;
    std::unique_ptr<Prompter1Client> m_cancelClient;
};

} // namespace

TEST_F(PrompterConcurrentWindowsTest, TwoReadersGetTwoWindowsAtOnce)
{
    DrivenRequest pin;
    DrivenRequest can;
    pin.start(wire::kKindPin, "nonce:pin");
    ASSERT_TRUE(pumpUntil([] { return PrompterService::registryForTest().size() == 1; }, std::chrono::seconds{5}))
        << "the first window never appeared";

    // THE claim: a second request is served while the first window still
    // stands. A handler that held its thread could not even be dispatched here.
    can.start(wire::kKindCan, "nonce:can");
    EXPECT_TRUE(pumpUntil([] { return PrompterService::registryForTest().size() == 2; }, std::chrono::seconds{5}))
        << "the second reader's prompt was never served while the first window stood";

    EXPECT_FALSE(pin.answered.load(std::memory_order_acquire));
    EXPECT_FALSE(can.answered.load(std::memory_order_acquire));

    m_cancelClient->Cancel("nonce:pin");
    m_cancelClient->Cancel("nonce:can");
    static_cast<void>(pumpUntil(
        [&] { return pin.answered.load(std::memory_order_acquire) && can.answered.load(std::memory_order_acquire); },
        std::chrono::seconds{5}));
    pin.join();
    can.join();
}

TEST_F(PrompterConcurrentWindowsTest, ADismissalClosesOnlyTheWindowItNames)
{
    // THREE windows, and the one dismissed is the MIDDLE one. Two is not
    // enough: an implementation that closes "the first live window" or "the
    // last" would be right by luck against a pair, and both were tried. Nothing
    // positional picks the middle.
    DrivenRequest pin;
    DrivenRequest can;
    DrivenRequest mrz;
    pin.start(wire::kKindPin, "nonce:pin");
    can.start(wire::kKindCan, "nonce:can");
    mrz.start(wire::kKindMrz, "nonce:mrz");
    ASSERT_TRUE(pumpUntil([] { return PrompterService::registryForTest().size() == 3; }, std::chrono::seconds{5}));
    ASSERT_NE(windowNamed("nonce:can"), nullptr);

    m_cancelClient->Cancel("nonce:can");

    ASSERT_TRUE(pumpUntil([&] { return can.answered.load(std::memory_order_acquire); }, std::chrono::seconds{5}))
        << "the named window never closed";
    EXPECT_EQ(std::get<0>(can.reply), wire::kStatusCancelled);
    EXPECT_FALSE(pin.answered.load(std::memory_order_acquire)) << "the dismissal closed another reader's window";
    EXPECT_FALSE(mrz.answered.load(std::memory_order_acquire)) << "the dismissal closed another reader's window";
    EXPECT_EQ(PrompterService::registryForTest().size(), 2u);
    EXPECT_EQ(windowNamed("nonce:can"), nullptr);
    EXPECT_NE(windowNamed("nonce:pin"), nullptr);
    EXPECT_NE(windowNamed("nonce:mrz"), nullptr);

    m_cancelClient->Cancel("nonce:pin");
    m_cancelClient->Cancel("nonce:mrz");
    static_cast<void>(pumpUntil(
        [&] { return pin.answered.load(std::memory_order_acquire) && mrz.answered.load(std::memory_order_acquire); },
        std::chrono::seconds{5}));
    EXPECT_TRUE(PrompterService::registryForTest().empty());
    pin.join();
    can.join();
    mrz.join();
}

TEST_F(PrompterConcurrentWindowsTest, AWindowIsNeitherModalNorFocusStealing)
{
    // Security-relevant, not cosmetic: a window that grabbed focus while the
    // holder was mid-PIN on another reader would collect the remaining digits
    // into this card's field. The effect needs a desk; the mechanism does not.
    DrivenRequest pin;
    pin.start(wire::kKindPin, "nonce:pin");
    ASSERT_TRUE(pumpUntil([] { return PrompterService::registryForTest().size() == 1; }, std::chrono::seconds{5}));

    PromptDialog* window = windowNamed("nonce:pin");
    ASSERT_NE(window, nullptr);
    EXPECT_TRUE(window->testAttribute(Qt::WA_ShowWithoutActivating));
    EXPECT_FALSE(window->isModal());
    EXPECT_EQ(window->windowModality(), Qt::NonModal);
    EXPECT_TRUE(window->isVisible()) << "the window must be shown, not exec'd";

    m_cancelClient->Cancel("nonce:pin");
    static_cast<void>(pumpUntil([&] { return pin.answered.load(std::memory_order_acquire); }, std::chrono::seconds{5}));
    pin.join();
}

TEST_F(PrompterConcurrentWindowsTest, AWindowAnnouncesItselfWithoutTakingFocus)
{
    // Because it does not steal focus, a window can open behind others. Without
    // an announcement it would run its whole entry deadline in silence and read
    // to the holder as "nothing happened".
    DrivenRequest pin;
    pin.start(wire::kKindPin, "nonce:pin");
    ASSERT_TRUE(pumpUntil([] { return PrompterService::registryForTest().size() == 1; }, std::chrono::seconds{5}));

    PromptDialog* window = windowNamed("nonce:pin");
    ASSERT_NE(window, nullptr);
    EXPECT_GE(window->announcementsRequested(), 1);

    m_cancelClient->Cancel("nonce:pin");
    static_cast<void>(pumpUntil([&] { return pin.answered.load(std::memory_order_acquire); }, std::chrono::seconds{5}));
    pin.join();
}

TEST_F(PrompterConcurrentWindowsTest, ADismissalNamingNoLiveWindowIsASilentNoOp)
{
    DrivenRequest pin;
    pin.start(wire::kKindPin, "nonce:pin");
    ASSERT_TRUE(pumpUntil([] { return PrompterService::registryForTest().size() == 1; }, std::chrono::seconds{5}));

    EXPECT_NO_THROW(m_cancelClient->Cancel("nonce:nobody"));
    EXPECT_NO_THROW(m_cancelClient->Cancel(""));
    static_cast<void>(pumpUntil([] { return false; }, std::chrono::milliseconds{200}));
    EXPECT_FALSE(pin.answered.load(std::memory_order_acquire)) << "an unrelated id closed a live window";
    EXPECT_EQ(PrompterService::registryForTest().size(), 1u);

    m_cancelClient->Cancel("nonce:pin");
    static_cast<void>(pumpUntil([&] { return pin.answered.load(std::memory_order_acquire); }, std::chrono::seconds{5}));
    pin.join();
}

int main(int argc, char** argv)
{
    // A QApplication (not QCoreApplication): the windows are real widgets, and
    // the offscreen platform plugin gives them somewhere to live without a
    // display server.
    QApplication app(argc, argv);
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
