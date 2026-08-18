// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// End-to-end exercise of the Prompter1 trust-boundary gate over a REAL
// session bus. Unlike CallerAuthorizerTest (which pins the pure CallerAuthorizer
// /proc seam in isolation) this drives the actual D-Bus glue added to
// PrompterService: authorizeCaller(), the
// getCurrentlyProcessedMessage().getCredsPid() creds augmentation, the
// unauthorized zero-byte/"unauthorized" reply, the authorized dialog path, and
// the CancelCurrent identity gate. The ownership gate (a DIFFERENT
// agent-authenticated caller may not cancel) is pinned by a pure-predicate unit
// below — two same-user binaries share this test process's PID, so a second
// authenticated caller with a distinct PID is unreachable in-process.
//
// The real PrompterService is hosted on a server connection; a generated
// Prompter1 proxy calls it on SEPARATE client connections (sd-bus refuses to
// dispatch self-calls). Both live in this one test process, so the
// kernel-validated caller PID resolves to /proc/self/exe. We model "the caller
// IS the configured agent" by pointing LIBRESCRS_PROMPTER_EXPECTED_PEER at
// /proc/self/exe and "a rogue same-user caller" by pointing it at an unrelated
// binary. No installed agent is needed.
//
// Harness note: a synchronous RequestSecret handler blocks the single sd-bus
// dispatcher thread for the dialog's lifetime (it marshals to the Qt main
// thread under BlockingQueuedConnection). A bus-issued CancelCurrent therefore
// cannot be dispatched until the prompt resolves, so the authorized path here
// asserts via the live dialog + its recorded owner PID and unwinds the prompt
// through the in-process reject() seam rather than a self-deadlocking bus
// cancel. Runs under dbus-run-session (private bus) + QT_QPA_PLATFORM=offscreen.

#include "PromptDialog.h"
#include "PrompterService.h"
#include "PrompterWire.h"

#include "org.librescrs.Prompter1_proxy.h"

#include <QApplication>
#include <QDialogButtonBox>
#include <QDate>
#include <QDateEdit>
#include <QLineEdit>
#include <QMetaObject>
#include <QPushButton>
#include <QTimer>

#include <sys/stat.h>
#include <unistd.h> // getpid, read, lseek

#include <sdbus-c++/IConnection.h>
#include <sdbus-c++/IProxy.h>
#include <sdbus-c++/Types.h>

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdlib>
#include <filesystem>
#include <functional>
#include <map>
#include <memory>
#include <string>
#include <thread>
#include <tuple>
#include <vector>

namespace {

constexpr const char* kServiceName = "org.librescrs.Prompter1.AuthTest";
constexpr const char* kObjectPath = "/org/librescrs/Prompter1";
constexpr const char* kPeerEnv = "LIBRESCRS_PROMPTER_EXPECTED_PEER";

// Canonical path of the running test executable — the value the in-process
// caller's /proc/<pid>/exe resolves to.
std::filesystem::path selfExe()
{
    std::error_code ec;
    auto p = std::filesystem::read_symlink("/proc/self/exe", ec);
    EXPECT_FALSE(ec) << "read /proc/self/exe failed: " << ec.message();
    return std::filesystem::weakly_canonical(p, ec);
}

// On-the-fly proxy over the generated Prompter1_proxy: the codegen emits a
// mixin expecting a concrete sdbus::IProxy; this binds it to a live proxy on
// the given connection.
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

// Byte length of an fd's backing file (the sealed memfd). -1 on fstat failure.
off_t fdSize(int fd)
{
    struct ::stat st{};
    if (::fstat(fd, &st) != 0) {
        return -1;
    }
    return st.st_size;
}

// Read back a sealed memfd's contents for assertion (house helper, mirrored
// from PrompterMultiFieldTest). The caller owns the fd.
std::string readMemfd(int fd)
{
    if (fd < 0) {
        return {};
    }
    const off_t size = ::lseek(fd, 0, SEEK_END);
    if (size <= 0) {
        return {};
    }
    ::lseek(fd, 0, SEEK_SET);
    std::string out(static_cast<std::size_t>(size), '\0');
    std::size_t off = 0;
    while (off < out.size()) {
        const auto n = ::read(fd, out.data() + off, out.size() - off);
        if (n <= 0) {
            break;
        }
        off += static_cast<std::size_t>(n);
    }
    return out;
}

// ICAO 9303 SPECIMEN values (the published example document), not a real
// travel document. The human enters the document number WITHOUT its check
// digit and picks the dates; the widget computes the check digits, so the
// captured payload carries them.
constexpr const char* kSpecimenDocNumber = "L898902C3";
const QDate kSpecimenDateOfBirth(1974, 8, 12);
const QDate kSpecimenDateOfExpiry(2012, 4, 15);
constexpr const char* kSpecimenPayload = "L898902C36\n7408122\n1204159";

QPushButton* okButtonOf(LibreLinux::Prompter::PromptDialog& dlg)
{
    auto* box = dlg.findChild<QDialogButtonBox*>();
    return box != nullptr ? box->button(QDialogButtonBox::Ok) : nullptr;
}

QPushButton* switchButtonOf(LibreLinux::Prompter::PromptDialog& dlg)
{
    return dlg.findChild<QPushButton*>(QStringLiteral("switchToMrzButton"));
}

// Fill the MRZ form with the specimen values, addressed by object name (the
// two date entries are QDateEdits, whose internal line edits would make
// positional findChildren<QLineEdit*>() ambiguous) — the convention
// InputWidgetValidationTest uses.
void fillMrzSpecimen(QWidget& root)
{
    auto* doc = root.findChild<QLineEdit*>(QStringLiteral("mrzDocumentNumber"));
    auto* dob = root.findChild<QDateEdit*>(QStringLiteral("mrzDateOfBirth"));
    auto* expiry = root.findChild<QDateEdit*>(QStringLiteral("mrzDateOfExpiry"));
    ASSERT_NE(doc, nullptr) << "the MRZ form must expose its document-number entry";
    ASSERT_NE(dob, nullptr);
    ASSERT_NE(expiry, nullptr);
    doc->setText(QString::fromLatin1(kSpecimenDocNumber));
    dob->setDate(kSpecimenDateOfBirth);
    expiry->setDate(kSpecimenDateOfExpiry);
}

// True once the prompter has published a live dialog.
bool dialogIsLive()
{
    return LibreLinux::Prompter::PrompterService::s_activeDialog.load() != nullptr;
}

// Spin until @p pred() holds or @p budget elapses; returns pred()'s final value.
template <class Pred>
bool spinUntil(Pred pred, std::chrono::milliseconds budget)
{
    const auto deadline = std::chrono::steady_clock::now() + budget;
    while (std::chrono::steady_clock::now() < deadline) {
        if (pred()) {
            return true;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds{2});
    }
    return pred();
}

// Fixture: a real PrompterService on a server connection + proxy clients on
// separate connections, all pumping async event loops. The Qt main thread
// owns the dialog; client calls run on worker threads so the dialog's nested
// event loop can run on main.
class PrompterAuthIntegrationTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        m_serverConn = sdbus::createSessionBusConnection();
        ASSERT_NE(m_serverConn, nullptr) << "private session bus (run under dbus-run-session)";
        m_serverConn->requestName(sdbus::ServiceName{kServiceName});
        m_service =
            std::make_unique<LibreLinux::Prompter::PrompterService>(*m_serverConn, sdbus::ObjectPath{kObjectPath});
        m_serverConn->enterEventLoopAsync();

        m_clientConn = sdbus::createSessionBusConnection();
        m_clientConn->enterEventLoopAsync();
        m_client = std::make_unique<Prompter1Client>(*m_clientConn, kServiceName, kObjectPath);

        // A SECOND client connection used for CancelCurrent, modelling a
        // distinct cancel-issuing peer and keeping the cancel off the connection
        // a blocking RequestSecret would hold for a dialog's lifetime.
        m_cancelConn = sdbus::createSessionBusConnection();
        m_cancelConn->enterEventLoopAsync();
        m_cancelClient = std::make_unique<Prompter1Client>(*m_cancelConn, kServiceName, kObjectPath);
    }

    void TearDown() override
    {
        m_cancelClient.reset();
        m_cancelConn->leaveEventLoop();
        m_client.reset();
        m_clientConn->leaveEventLoop();
        m_service.reset();
        m_serverConn->leaveEventLoop();
        // Defensive: a failed authorized-path test could leave the static slots
        // populated; reset so subsequent cases start clean.
        LibreLinux::Prompter::PrompterService::s_activeDialog.store(nullptr);
        LibreLinux::Prompter::PrompterService::s_activeOwnerPid.store(0);
        ::unsetenv(kPeerEnv);
    }

    // Run @p onDialog (GUI thread, queued onto the live dialog) while a worker
    // drives RequestSecret(kind, options); returns the reply tuple. The
    // scripted-dialog harness of PrompterMultiFieldTest's
    // PrompterMultiFieldBusTest::driveRequestSecrets, for the single-secret
    // method: the sd-bus dispatcher blocks inside RequestSecret for the
    // dialog's lifetime, so the script has to reach the dialog in-process while
    // this thread runs the Qt event loop the dialog needs.
    std::tuple<std::string, sdbus::UnixFd, std::string>
    driveRequestSecret(const std::string& kind, const std::map<std::string, sdbus::Variant>& options,
                       const std::function<void(LibreLinux::Prompter::PromptDialog*)>& onDialog)
    {
        std::tuple<std::string, sdbus::UnixFd, std::string> reply;
        std::atomic<bool> returned{false};
        std::thread driver([&] {
            reply = m_client->RequestSecret(kind, options);
            returned.store(true);
        });

        std::thread watcher([&] {
            if (!spinUntil(dialogIsLive, std::chrono::seconds{10})) {
                return; // no dialog appeared; the caller's assertions fail below
            }
            auto* dlg = LibreLinux::Prompter::PrompterService::s_activeDialog.load();
            if (dlg != nullptr) {
                QMetaObject::invokeMethod(dlg, [dlg, &onDialog]() { onDialog(dlg); }, Qt::QueuedConnection);
            }
        });

        QTimer quitPoll;
        quitPoll.setInterval(5);
        QObject::connect(&quitPoll, &QTimer::timeout, [&] {
            if (returned.load()) {
                QApplication::instance()->quit();
            }
        });
        quitPoll.start();
        QTimer::singleShot(15000, QApplication::instance(), []() { QApplication::instance()->quit(); });
        QApplication::instance()->exec();
        driver.join();
        watcher.join();
        EXPECT_TRUE(returned.load()) << "RequestSecret never returned (test wedged)";
        return reply;
    }

    std::unique_ptr<sdbus::IConnection> m_serverConn;
    std::unique_ptr<sdbus::IConnection> m_clientConn;
    std::unique_ptr<sdbus::IConnection> m_cancelConn;
    std::unique_ptr<LibreLinux::Prompter::PrompterService> m_service;
    std::unique_ptr<Prompter1Client> m_client;
    std::unique_ptr<Prompter1Client> m_cancelClient;
};

} // namespace

// --- Unauthorized RequestSecret -------------------------------------------

TEST_F(PrompterAuthIntegrationTest, UnauthorizedRequestSecretReturnsZeroByteUnauthorized)
{
    // Model a rogue same-user caller: the expected peer is some OTHER binary,
    // so our /proc/self/exe fails the binary-identity gate. RequestSecret must
    // reject fail-closed BEFORE any dialog — no Qt event loop is even entered.
    ::setenv(kPeerEnv, "/usr/bin/true", 1);

    int argc = 1;
    const char* argv[] = {"prompter-auth-test"};
    QApplication app(argc, const_cast<char**>(argv));

    auto result = m_client->RequestSecret("pin", {});
    const std::string status = std::get<0>(result);
    const int fd = std::get<1>(result).get();

    EXPECT_EQ(status, "unauthorized") << "a non-agent caller must be rejected";
    ASSERT_GE(fd, 0) << "the wire signature still carries a real fd";
    EXPECT_EQ(fdSize(fd), 0) << "the rejection fd must be a zero-byte sealed memfd (no secret)";
    EXPECT_EQ(LibreLinux::Prompter::PrompterService::s_activeDialog.load(), nullptr)
        << "no dialog may be constructed for an unauthorized caller";
}

// --- Authorized RequestSecret, unrecognized kind --------------------------

TEST_F(PrompterAuthIntegrationTest, AuthorizedRequestSecretUnknownKindReturnsErrorWithEmptyUserMessage)
{
    // An authorized caller asking for an unrecognized kind is a typed error with
    // no dialog and no secret bytes. The user_message slot must stay EMPTY — the
    // status is already "error" and clients map their own taxonomy; a hardcoded
    // English literal there would be permanently untranslatable.
    ::setenv(kPeerEnv, selfExe().string().c_str(), 1);

    auto result = m_client->RequestSecret("bogus-kind", {});
    EXPECT_EQ(std::get<0>(result), "error");
    ASSERT_GE(std::get<1>(result).get(), 0) << "the wire signature still carries a real fd";
    EXPECT_EQ(fdSize(std::get<1>(result).get()), 0) << "no secret bytes for an unknown kind";
    EXPECT_TRUE(std::get<2>(result).empty()) << "user_message must not carry a bare English literal";
    EXPECT_EQ(LibreLinux::Prompter::PrompterService::s_activeDialog.load(), nullptr) << "no dialog for an unknown kind";
}

// --- Unauthorized CancelCurrent -------------------------------------------

TEST_F(PrompterAuthIntegrationTest, UnauthorizedCancelCurrentIsRejectedNoop)
{
    // A non-agent CancelCurrent must be a silent no-op (no throw, no effect):
    // it must not be a usable cancel-injection DoS. The authorizeCaller gate
    // returns 0 and the method returns BEFORE ever consulting s_activeOwnerPid
    // or dispatching reject(). Driven over the real bus against an idle
    // prompter, which also exercises the getCredsPid() augmentation on the
    // CancelCurrent path (the rejection is logged with the resolved PID).
    ::setenv(kPeerEnv, "/usr/bin/true", 1);

    int argc = 1;
    const char* argv[] = {"prompter-auth-test"};
    QApplication app(argc, const_cast<char**>(argv));

    EXPECT_NO_THROW(m_cancelClient->CancelCurrent())
        << "an unauthorized CancelCurrent must be a clean no-op, never an error";
    EXPECT_EQ(LibreLinux::Prompter::PrompterService::s_activeDialog.load(), nullptr);
    EXPECT_EQ(LibreLinux::Prompter::PrompterService::s_activeOwnerPid.load(), 0);
}

// --- Authorized caller -----------------------------------------------------

TEST_F(PrompterAuthIntegrationTest, AuthorizedRequestSecretRunsDialogWithCallerAsOwner)
{
    // Authorized end to end: the caller's exe matches the expected peer, so
    // RequestSecret actually CONSTRUCTS and exec()s a dialog (proving the
    // getCredsPid() augmentation resolves a live caller PID at runtime) and
    // records THIS process as the prompt owner — i.e. the authorized request is
    // NOT rejected by the trust gate; the status is a real dialog outcome, never
    // "unauthorized". The prompt is then unwound via the in-process reject()
    // seam (see the deadlock note below). The peer override is set once up-front
    // and never mutated, so authorisation is race-free.
    ::setenv(kPeerEnv, selfExe().string().c_str(), 1);

    int argc = 1;
    const char* argv[] = {"prompter-auth-test"};
    QApplication app(argc, const_cast<char**>(argv));

    std::string status;
    std::atomic<bool> returned{false};
    std::thread driver([&] {
        auto result = m_client->RequestSecret("pin", {});
        status = std::get<0>(result);
        returned.store(true);
    });

    std::atomic<bool> sawDialog{false};
    std::atomic<pid_t> ownerWhileLive{0};
    std::thread watcher([&] {
        if (!spinUntil(dialogIsLive, std::chrono::seconds{10})) {
            return; // dialog never appeared; main asserts on sawDialog==false
        }
        // A live dialog proves the authorized path reached UI construction;
        // capture the owner PID the prompter recorded for the in-flight prompt.
        ownerWhileLive.store(LibreLinux::Prompter::PrompterService::s_activeOwnerPid.load());
        sawDialog.store(true);
        // Unwind the in-flight RequestSecret. A bus-issued CancelCurrent cannot
        // be processed here: the single sd-bus dispatcher thread is blocked
        // inside RequestSecret (it marshals to the Qt main thread under
        // BlockingQueuedConnection), so a CancelCurrent reply would never arrive
        // until the prompt resolved -> deadlock. We instead dispatch reject()
        // straight to the dialog via the in-process seam; the bus-level
        // CancelCurrent identity gate is covered by the unauthorized-cancel
        // case and the ownership gate by the ownership-predicate units.
        LibreLinux::Prompter::PrompterService::cancelCurrentForTest();
    });

    // Quit from WITHIN the main loop once RequestSecret has unwound: poll the
    // completion flag on a main-thread timer. (A cross-thread app.quit() is
    // not relied upon here.) The 15 s single-shot is a wedge safety valve so a
    // hang fails the test instead of stalling the suite.
    QTimer quitPoll;
    quitPoll.setInterval(5);
    QObject::connect(&quitPoll, &QTimer::timeout, [&] {
        if (returned.load()) {
            app.quit();
        }
    });
    quitPoll.start();
    QTimer::singleShot(15000, &app, [&app] { app.quit(); });
    app.exec();
    driver.join();
    watcher.join();

    ASSERT_TRUE(returned.load()) << "authorized RequestSecret never returned (test wedged)";
    ASSERT_TRUE(sawDialog.load()) << "authorized RequestSecret must construct a real dialog";
    EXPECT_EQ(ownerWhileLive.load(), ::getpid())
        << "the in-flight prompt's owner PID must be the caller's (this process)";
    EXPECT_NE(status, "unauthorized") << "an authorized caller must reach the dialog, not the auth-reject path";
    // Slots cleared after the dialog unwinds.
    EXPECT_EQ(LibreLinux::Prompter::PrompterService::s_activeDialog.load(), nullptr);
    EXPECT_EQ(LibreLinux::Prompter::PrompterService::s_activeOwnerPid.load(), 0);
}

// --- The alternative-kind opt-in and the status it can mint -----------------
//
// The service decides ONCE, in the RequestSecret handler where both the kind
// and the lifted options are in scope, whether a switch is offered; that same
// decision gates the distinct status. Offered and minted therefore cannot
// diverge, and every caller that does not opt in keeps today's vocabulary
// byte-identically.

TEST_F(PrompterAuthIntegrationTest, OkMrzMintedOnlyWhenOfferedAndChosen)
{
    ::setenv(kPeerEnv, selfExe().string().c_str(), 1);

    int argc = 1;
    const char* argv[] = {"prompter-auth-test"};
    QApplication app(argc, const_cast<char**>(argv));

    namespace wire = LibreLinux::PrompterWire;
    const std::map<std::string, sdbus::Variant> options{
        {wire::kOptAltKinds, sdbus::Variant{std::vector<std::string>{wire::kKindMrz}}},
    };

    auto reply = driveRequestSecret(wire::kKindCan, options, [](LibreLinux::Prompter::PromptDialog* dlg) {
        auto* button = switchButtonOf(*dlg);
        ASSERT_NE(button, nullptr) << "the opt-in must reach the dialog as a switch affordance";
        button->click();
        fillMrzSpecimen(*dlg);
        auto* ok = okButtonOf(*dlg);
        ASSERT_NE(ok, nullptr);
        ASSERT_TRUE(ok->isEnabled());
        ok->click();
    });

    EXPECT_EQ(std::get<0>(reply), wire::kStatusOkMrz)
        << "a CAN request that opted in and whose user switched must answer with the distinct status";
    const int fd = std::get<1>(reply).get();
    ASSERT_GE(fd, 0);
    EXPECT_EQ(readMemfd(fd), std::string(kSpecimenPayload)) << "the fd must carry the MRZ payload, not a CAN";
    EXPECT_TRUE(std::get<2>(reply).empty());
}

TEST_F(PrompterAuthIntegrationTest, PlainOkWhenOptedInButUserStaysOnCan)
{
    ::setenv(kPeerEnv, selfExe().string().c_str(), 1);

    int argc = 1;
    const char* argv[] = {"prompter-auth-test"};
    QApplication app(argc, const_cast<char**>(argv));

    namespace wire = LibreLinux::PrompterWire;
    const std::map<std::string, sdbus::Variant> options{
        {wire::kOptAltKinds, sdbus::Variant{std::vector<std::string>{wire::kKindMrz}}},
    };

    // The affordance is offered but declined: the user fills the CAN form the
    // request actually asked for.
    auto reply = driveRequestSecret(wire::kKindCan, options, [](LibreLinux::Prompter::PromptDialog* dlg) {
        ASSERT_NE(switchButtonOf(*dlg), nullptr);
        auto* edit = dlg->findChild<QLineEdit*>();
        ASSERT_NE(edit, nullptr);
        edit->setText(QStringLiteral("123456"));
        auto* ok = okButtonOf(*dlg);
        ASSERT_NE(ok, nullptr);
        ok->click();
    });

    EXPECT_EQ(std::get<0>(reply), wire::kStatusOk) << "opting in must not by itself change the answered status";
    EXPECT_EQ(readMemfd(std::get<1>(reply).get()), std::string("123456"));
}

TEST_F(PrompterAuthIntegrationTest, AltKindsIgnoredForNonCanKinds)
{
    ::setenv(kPeerEnv, selfExe().string().c_str(), 1);

    int argc = 1;
    const char* argv[] = {"prompter-auth-test"};
    QApplication app(argc, const_cast<char**>(argv));

    namespace wire = LibreLinux::PrompterWire;
    const std::map<std::string, sdbus::Variant> options{
        {wire::kOptAltKinds, sdbus::Variant{std::vector<std::string>{wire::kKindMrz}}},
    };

    // Kind "pin": the option is CAN-scoped, so no affordance and no new status.
    std::atomic<bool> pinSawSwitch{true};
    auto pinReply = driveRequestSecret(wire::kKindPin, options, [&](LibreLinux::Prompter::PromptDialog* dlg) {
        pinSawSwitch.store(switchButtonOf(*dlg) != nullptr);
        auto* edit = dlg->findChild<QLineEdit*>();
        ASSERT_NE(edit, nullptr);
        edit->setText(QStringLiteral("1234"));
        auto* ok = okButtonOf(*dlg);
        ASSERT_NE(ok, nullptr);
        ok->click();
    });
    EXPECT_FALSE(pinSawSwitch.load()) << "the option is CAN-scoped; a PIN prompt must render no switch";
    EXPECT_EQ(std::get<0>(pinReply), wire::kStatusOk);

    // Kind "mrz": the dialog IS the MRZ form, but the request never offered a
    // choice — the reply must stay on today's vocabulary, so a flow bug can
    // never deliver an MRZ payload under the distinct status to a slot that
    // asked for something else.
    std::atomic<bool> mrzSawSwitch{true};
    auto mrzReply = driveRequestSecret(wire::kKindMrz, options, [&](LibreLinux::Prompter::PromptDialog* dlg) {
        mrzSawSwitch.store(switchButtonOf(*dlg) != nullptr);
        fillMrzSpecimen(*dlg);
        auto* ok = okButtonOf(*dlg);
        ASSERT_NE(ok, nullptr);
        ok->click();
    });
    EXPECT_FALSE(mrzSawSwitch.load()) << "an MRZ prompt has nothing to switch to";
    EXPECT_EQ(std::get<0>(mrzReply), wire::kStatusOk) << "only a CAN request that opted in may mint the new status";
    EXPECT_EQ(readMemfd(std::get<1>(mrzReply).get()), std::string(kSpecimenPayload));
}

TEST_F(PrompterAuthIntegrationTest, AltKindsValueHygiene)
{
    ::setenv(kPeerEnv, selfExe().string().c_str(), 1);

    int argc = 1;
    const char* argv[] = {"prompter-auth-test"};
    QApplication app(argc, const_cast<char**>(argv));

    namespace wire = LibreLinux::PrompterWire;

    // A member that is NOT the alternative this dialog can offer buys nothing.
    std::atomic<bool> sawSwitchForUnknownMember{true};
    auto unknownReply = driveRequestSecret(
        wire::kKindCan, {{wire::kOptAltKinds, sdbus::Variant{std::vector<std::string>{wire::kKindPin}}}},
        [&](LibreLinux::Prompter::PromptDialog* dlg) {
            sawSwitchForUnknownMember.store(switchButtonOf(*dlg) != nullptr);
            auto* edit = dlg->findChild<QLineEdit*>();
            ASSERT_NE(edit, nullptr);
            edit->setText(QStringLiteral("123456"));
            okButtonOf(*dlg)->click();
        });
    EXPECT_FALSE(sawSwitchForUnknownMember.load()) << "only the alternative the dialog can actually offer counts";
    EXPECT_EQ(std::get<0>(unknownReply), wire::kStatusOk);

    // An empty list is an opt-in to nothing.
    std::atomic<bool> sawSwitchForEmptyList{true};
    auto emptyReply =
        driveRequestSecret(wire::kKindCan, {{wire::kOptAltKinds, sdbus::Variant{std::vector<std::string>{}}}},
                           [&](LibreLinux::Prompter::PromptDialog* dlg) {
                               sawSwitchForEmptyList.store(switchButtonOf(*dlg) != nullptr);
                               auto* edit = dlg->findChild<QLineEdit*>();
                               ASSERT_NE(edit, nullptr);
                               edit->setText(QStringLiteral("123456"));
                               okButtonOf(*dlg)->click();
                           });
    EXPECT_FALSE(sawSwitchForEmptyList.load()) << "an empty list offers nothing";
    EXPECT_EQ(std::get<0>(emptyReply), wire::kStatusOk);

    // The known member alongside junk still offers exactly ONE switch; the
    // junk members are ignored, never rendered as further affordances.
    std::atomic<int> switchCount{-1};
    auto mixedReply = driveRequestSecret(
        wire::kKindCan,
        {{wire::kOptAltKinds,
          sdbus::Variant{std::vector<std::string>{"nonsense", wire::kKindMrz, "another-unknown-kind"}}}},
        [&](LibreLinux::Prompter::PromptDialog* dlg) {
            switchCount.store(
                static_cast<int>(dlg->findChildren<QPushButton*>(QStringLiteral("switchToMrzButton")).size()));
            auto* button = switchButtonOf(*dlg);
            ASSERT_NE(button, nullptr);
            button->click();
            fillMrzSpecimen(*dlg);
            okButtonOf(*dlg)->click();
        });
    EXPECT_EQ(switchCount.load(), 1) << "unknown members must not render additional affordances";
    EXPECT_EQ(std::get<0>(mixedReply), wire::kStatusOkMrz);
}

TEST_F(PrompterAuthIntegrationTest, MistypedAltKindsIsTreatedAsAbsent)
{
    ::setenv(kPeerEnv, selfExe().string().c_str(), 1);

    int argc = 1;
    const char* argv[] = {"prompter-auth-test"};
    QApplication app(argc, const_cast<char**>(argv));

    namespace wire = LibreLinux::PrompterWire;
    // Wrong variant type (a plain string where an array of strings belongs):
    // dropped exactly like an unknown key — no switch, no error, today's
    // status. The lift must neither throw nor half-apply.
    const std::map<std::string, sdbus::Variant> options{
        {wire::kOptAltKinds, sdbus::Variant{std::string{"mrz"}}},
    };

    std::atomic<bool> sawSwitch{true};
    auto reply = driveRequestSecret(wire::kKindCan, options, [&](LibreLinux::Prompter::PromptDialog* dlg) {
        sawSwitch.store(switchButtonOf(*dlg) != nullptr);
        auto* edit = dlg->findChild<QLineEdit*>();
        ASSERT_NE(edit, nullptr);
        edit->setText(QStringLiteral("123456"));
        auto* ok = okButtonOf(*dlg);
        ASSERT_NE(ok, nullptr);
        ok->click();
    });

    EXPECT_FALSE(sawSwitch.load()) << "a mistyped option must behave exactly like a caller that never sent it";
    EXPECT_EQ(std::get<0>(reply), wire::kStatusOk);
    EXPECT_EQ(readMemfd(std::get<1>(reply).get()), std::string("123456"));
    EXPECT_TRUE(std::get<2>(reply).empty()) << "a mistyped option is not an error";
}

// --- Ownership gate (pure predicate) ---------------------------------------
//
// The "a DIFFERENT agent-authenticated caller may not cancel" branch cannot be
// driven over a real in-process bus: two same-user binaries share this test
// process's PID, so a second authenticated caller with a distinct PID is
// unreachable here. The decision is the pure predicate CancelCurrent consults
// AFTER the identity gate; we pin it directly.

TEST(PrompterOwnershipGate, RejectsCancelFromDifferentAuthenticatedCaller)
{
    using LibreLinux::Prompter::PrompterService;
    const pid_t owner = 4242;
    const pid_t otherAgent = 4243; // also identity-authorized, but not the owner
    EXPECT_FALSE(PrompterService::isActivePromptOwner(owner, otherAgent))
        << "a cancel from an authenticated peer that does not own the prompt must be rejected";
}

TEST(PrompterOwnershipGate, AcceptsCancelFromOwner)
{
    using LibreLinux::Prompter::PrompterService;
    const pid_t owner = 4242;
    EXPECT_TRUE(PrompterService::isActivePromptOwner(owner, owner))
        << "the originating caller may cancel its own prompt";
}

TEST(PrompterOwnershipGate, RejectsCancelAgainstIdlePrompter)
{
    using LibreLinux::Prompter::PrompterService;
    // ownerPid == 0 means idle; no caller (even a matching 0) may cancel.
    EXPECT_FALSE(PrompterService::isActivePromptOwner(0, 0)) << "an idle prompter (no owner) has nothing to cancel";
    EXPECT_FALSE(PrompterService::isActivePromptOwner(0, 4242));
}
