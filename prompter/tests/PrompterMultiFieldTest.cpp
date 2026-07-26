// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Multi-field secret collection (kind "change_pin"): the three-field dialog
// page (current + new + confirm) and the RequestSecrets service method.
//
// Dialog-level cases run offscreen with no bus: per-role bounds (the current
// field validates against the primary bounds, the new AND confirm fields
// against the new bounds), the confirm-mismatch inline error that blocks
// accept, the two-sealed-fd capture whose seal set is identical to the
// single-secret path, the read-then-hide ordering (every secret read precedes
// any hide/disable — recorded by a widget subclass injected via the dialog's
// change-pin widget factory), and the confirm-containment guarantees (the
// dialog result type carries exactly two values; the confirm value is
// consumed by local validation only, never by payload assembly).
//
// Service-level cases host the REAL PrompterService on a private session bus
// (dbus-run-session) exactly like PrompterAuthIntegrationTest: unauthorized
// and unknown-kind rejections, cancel -> "cancelled" + BOTH fds zero-length,
// and the authorized accept round trip returning the current + new secrets.

#include <algorithm>

#include "ChangePinInputWidget.h"
#include "PromptDialog.h"
#include "PrompterService.h"
#include "PrompterWire.h"
#include "SecretMemfd.h"

#include "org.librescrs.Prompter1_proxy.h"

#include <QApplication>
#include <QDialogButtonBox>
#include <QEvent>
#include <QLabel>
#include <QLineEdit>
#include <QMetaObject>
#include <QPushButton>
#include <QTimer>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <sdbus-c++/IConnection.h>
#include <sdbus-c++/IProxy.h>
#include <sdbus-c++/Types.h>

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <map>
#include <memory>
#include <string>
#include <thread>
#include <tuple>
#include <vector>

namespace {

using LibreLinux::Prompter::ChangePinInputWidget;
using LibreLinux::Prompter::PromptDialog;
using LibreLinux::Prompter::PrompterService;

constexpr const char* kServiceName = "org.librescrs.Prompter1.MultiFieldTest";
constexpr const char* kObjectPath = "/org/librescrs/Prompter1";
constexpr const char* kPeerEnv = "LIBRESCRS_PROMPTER_EXPECTED_PEER";

// ----- shared helpers -------------------------------------------------------

// Read back a sealed memfd's contents into a std::string for assertion.
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

// Byte length of an fd's backing file (the sealed memfd). -1 on fstat failure.
off_t fdSize(int fd)
{
    struct ::stat st{};
    if (::fstat(fd, &st) != 0) {
        return -1;
    }
    return st.st_size;
}

// The seal set applied to a fd; -1 on failure.
int sealsOf(int fd)
{
    return ::fcntl(fd, F_GET_SEALS);
}

// The reference seal set of the SINGLE-secret path: whatever
// makeSealedSecretFd applies is the tree-wide contract both fds of the
// multi-secret path must match exactly.
int singleSecretPathSeals()
{
    const int fd = LibreLinux::Prompter::makeSealedSecretFd("x");
    EXPECT_GE(fd, 0);
    const int seals = sealsOf(fd);
    ::close(fd);
    return seals;
}

QLineEdit* editNamed(QWidget& root, const char* name)
{
    return root.findChild<QLineEdit*>(QString::fromLatin1(name));
}

QPushButton* okButtonOf(PromptDialog& dlg)
{
    auto* box = dlg.findChild<QDialogButtonBox*>();
    return box != nullptr ? box->button(QDialogButtonBox::Ok) : nullptr;
}

QPushButton* cancelButtonOf(PromptDialog& dlg)
{
    auto* box = dlg.findChild<QDialogButtonBox*>();
    return box != nullptr ? box->button(QDialogButtonBox::Cancel) : nullptr;
}

PromptDialog::Options multiOptions()
{
    PromptDialog::Options opts;
    opts.primaryMinLength = 4;
    opts.primaryMaxLength = 8;
    opts.newMinLength = 6;
    opts.newMaxLength = 12;
    return opts;
}

void fillChangePin(QWidget& root, const char* current, const char* newPin, const char* confirm)
{
    QLineEdit* cur = editNamed(root, "currentPinEdit");
    QLineEdit* nxt = editNamed(root, "newPinEdit");
    QLineEdit* cnf = editNamed(root, "confirmPinEdit");
    ASSERT_NE(cur, nullptr);
    ASSERT_NE(nxt, nullptr);
    ASSERT_NE(cnf, nullptr);
    cur->setText(QString::fromLatin1(current));
    nxt->setText(QString::fromLatin1(newPin));
    cnf->setText(QString::fromLatin1(confirm));
}

// ----- recorders (injected via the dialog's change-pin widget factory) ------

// Ordering recorder: logs every secret-value read (via the protected
// field-read seams) and every hide/disable observed on itself AND on its
// window (the dialog) — children receive no Hide when only the ancestor
// hides, so the recorder watches the dialog through an event filter it
// installs when it is parented in.
class OrderingRecorderWidget final : public ChangePinInputWidget
{
public:
    OrderingRecorderWidget(std::vector<std::string>* log, int currentMin, int currentMax, int newMin, int newMax)
        : ChangePinInputWidget(currentMin, currentMax, newMin, newMax, QString{}), m_log(log)
    {
        installEventFilter(this); // own hide/disable
    }

protected:
    QString readCurrentFieldValue() const override
    {
        m_log->push_back("read:current");
        return ChangePinInputWidget::readCurrentFieldValue();
    }
    QString readNewFieldValue() const override
    {
        m_log->push_back("read:new");
        return ChangePinInputWidget::readNewFieldValue();
    }
    QString readConfirmFieldValue() const override
    {
        m_log->push_back("read:confirm");
        return ChangePinInputWidget::readConfirmFieldValue();
    }

    bool event(QEvent* ev) override
    {
        if (ev->type() == QEvent::ParentChange && window() != nullptr && window() != this) {
            window()->installEventFilter(this); // dialog-level hide/disable
        }
        return ChangePinInputWidget::event(ev);
    }

    bool eventFilter(QObject* watched, QEvent* ev) override
    {
        if (ev->type() == QEvent::Hide) {
            m_log->push_back("hide");
        } else if (ev->type() == QEvent::EnabledChange) {
            auto* w = qobject_cast<QWidget*>(watched);
            if (w != nullptr && !w->isEnabled()) {
                m_log->push_back("disable");
            }
        }
        return ChangePinInputWidget::eventFilter(watched, ev);
    }

private:
    std::vector<std::string>* m_log;
};

// Counting recorder: tallies which field-read seam served each consumer so
// the test can prove the confirm value is consumed by local validation ONLY.
class CountingRecorderWidget final : public ChangePinInputWidget
{
public:
    CountingRecorderWidget(int currentMin, int currentMax, int newMin, int newMax)
        : ChangePinInputWidget(currentMin, currentMax, newMin, newMax, QString{})
    {}

    mutable int currentReads = 0;
    mutable int newReads = 0;
    mutable int confirmReads = 0;

protected:
    QString readCurrentFieldValue() const override
    {
        ++currentReads;
        return ChangePinInputWidget::readCurrentFieldValue();
    }
    QString readNewFieldValue() const override
    {
        ++newReads;
        return ChangePinInputWidget::readNewFieldValue();
    }
    QString readConfirmFieldValue() const override
    {
        ++confirmReads;
        return ChangePinInputWidget::readConfirmFieldValue();
    }
};

} // namespace

// ----- role label rendering -------------------------------------------------

// A "pin_<digits>" label is the agent's synthesized selector for records
// without a card-profile label — a machine identifier that must never be
// rendered as the PIN role name. Real labels render verbatim.
TEST(ChangePinWidget, SyntheticSelectorLabelRendersGenericRole)
{
    const auto rowTexts = [](const ChangePinInputWidget& w) {
        QStringList out;
        for (const QLabel* label : w.findChildren<QLabel*>()) {
            out.append(label->text());
        }
        return out;
    };

    ChangePinInputWidget synthetic(4, 8, 4, 8, QStringLiteral("pin_4"));
    for (const QString& text : rowTexts(synthetic)) {
        EXPECT_FALSE(text.contains(QStringLiteral("pin_4")))
            << "machine selector leaked into the dialog: " << text.toStdString();
    }

    ChangePinInputWidget real(4, 8, 4, 8, QStringLiteral("Signature PIN"));
    EXPECT_TRUE(std::any_of(rowTexts(real).cbegin(), rowTexts(real).cend(), [](const QString& text) {
        return text.contains(QStringLiteral("Signature PIN"));
    })) << "a genuine card label must render verbatim";
}

// ----- per-role bounds ------------------------------------------------------

TEST(ChangePinWidget, EnforcesPerRoleBounds)
{
    ChangePinInputWidget w(4, 8, 6, 12, QString{});
    QLineEdit* cur = editNamed(w, "currentPinEdit");
    QLineEdit* nxt = editNamed(w, "newPinEdit");
    QLineEdit* cnf = editNamed(w, "confirmPinEdit");
    ASSERT_NE(cur, nullptr);
    ASSERT_NE(nxt, nullptr);
    ASSERT_NE(cnf, nullptr);

    // Primary bounds drive the current field; new bounds drive BOTH the new
    // and the confirm fields.
    EXPECT_EQ(cur->maxLength(), 8);
    EXPECT_EQ(nxt->maxLength(), 12);
    EXPECT_EQ(cnf->maxLength(), 12);

    cur->setText(QStringLiteral("1234"));
    nxt->setText(QStringLiteral("123456"));
    cnf->setText(QStringLiteral("123456"));
    EXPECT_TRUE(w.isValid());

    cur->setText(QStringLiteral("123")); // below primary min
    EXPECT_FALSE(w.isValid()) << "current field must honour the primary min length";
    cur->setText(QStringLiteral("1234"));

    nxt->setText(QStringLiteral("12345")); // below new min
    EXPECT_FALSE(w.isValid()) << "new field must honour the new min length";
    nxt->setText(QStringLiteral("123456"));

    cnf->setText(QStringLiteral("12345")); // below new min
    EXPECT_FALSE(w.isValid()) << "confirm field must honour the NEW bounds, not the primary ones";
    cnf->setText(QStringLiteral("1234")); // valid per PRIMARY bounds only
    EXPECT_FALSE(w.isValid()) << "a confirm entry valid only per primary bounds must not validate";

    cnf->setText(QStringLiteral("123456"));
    EXPECT_TRUE(w.isValid());

    nxt->setText(QStringLiteral("12345a")); // non-digit
    EXPECT_FALSE(w.isValid()) << "non-digit input must not validate";
}

// ----- confirm mismatch blocks accept ---------------------------------------

TEST(ChangePinDialog, ConfirmMismatchBlocksAcceptWithInlineError)
{
    PromptDialog dlg(PromptDialog::Kind::ChangePin, multiOptions());
    dlg.show();
    fillChangePin(dlg, "1234", "123456", "123457"); // confirm differs

    QPushButton* ok = okButtonOf(dlg);
    ASSERT_NE(ok, nullptr);
    EXPECT_TRUE(ok->isEnabled()) << "bounds-valid input must enable OK (mismatch is an accept-time check)";

    ok->click();
    EXPECT_NE(dlg.result(), QDialog::Accepted) << "a confirm mismatch must block accept";
    EXPECT_TRUE(dlg.isVisible()) << "the dialog must stay open for correction";

    auto* error = dlg.findChild<QLabel*>(QStringLiteral("confirmMismatchError"));
    ASSERT_NE(error, nullptr) << "the mismatch must surface as an inline error label";
    EXPECT_TRUE(error->isVisible());
    EXPECT_FALSE(error->text().isEmpty()) << "the inline error must carry a localized message";

    // Correcting the confirm entry clears the error and unblocks accept.
    editNamed(dlg, "confirmPinEdit")->setText(QStringLiteral("123456"));
    EXPECT_FALSE(error->isVisible()) << "editing the fields must clear the stale mismatch error";
    ok->click();
    EXPECT_EQ(dlg.result(), QDialog::Accepted);

    const auto pair = dlg.takeSecretFdPair();
    ::close(pair.primaryFd);
    ::close(pair.secondaryFd);
}

// ----- accept captures two sealed fds ---------------------------------------

TEST(ChangePinDialog, AcceptCapturesTwoSealedFdsWithSecretBytes)
{
    PromptDialog dlg(PromptDialog::Kind::ChangePin, multiOptions());
    dlg.show();
    fillChangePin(dlg, "4321", "654321", "654321");

    QPushButton* ok = okButtonOf(dlg);
    ASSERT_NE(ok, nullptr);
    ok->click();
    ASSERT_EQ(dlg.result(), QDialog::Accepted);

    const auto pair = dlg.takeSecretFdPair();
    ASSERT_GE(pair.primaryFd, 0);
    ASSERT_GE(pair.secondaryFd, 0);
    EXPECT_EQ(readMemfd(pair.primaryFd), "4321") << "primary fd must carry the CURRENT secret";
    EXPECT_EQ(readMemfd(pair.secondaryFd), "654321") << "secondary fd must carry the NEW secret";

    // Seal set identical to the single-secret path.
    const int reference = singleSecretPathSeals();
    ASSERT_GE(reference, 0);
    EXPECT_EQ(sealsOf(pair.primaryFd), reference);
    EXPECT_EQ(sealsOf(pair.secondaryFd), reference);

    // The seals actually block writes.
    const char extra = '!';
    EXPECT_LT(::write(pair.primaryFd, &extra, 1), 0) << "sealed memfd accepted a write";
    EXPECT_LT(::write(pair.secondaryFd, &extra, 1), 0) << "sealed memfd accepted a write";

    ::close(pair.primaryFd);
    ::close(pair.secondaryFd);

    // Ownership transfers on take: a second take has nothing to hand out.
    const auto second = dlg.takeSecretFdPair();
    EXPECT_EQ(second.primaryFd, -1);
    EXPECT_EQ(second.secondaryFd, -1);
}

// ----- re-entrant accept must not orphan the first secret-bearing fd pair ----

TEST(ChangePinDialog, ReentrantAcceptDoesNotOrphanFirstSecretPair)
{
    PromptDialog dlg(PromptDialog::Kind::ChangePin, multiOptions());
    dlg.show();
    fillChangePin(dlg, "4321", "654321", "654321");

    // First accept captures the two REAL secrets while the edits are populated.
    dlg.accept();
    ASSERT_EQ(dlg.result(), QDialog::Accepted);

    // A second (re-entrant) accept — modelling a doubly-queued
    // QDialogButtonBox::accepted delivered before exec() unwinds — must be
    // idempotent. Without the guard it re-reads the now-scrubbed (empty) edits
    // and OVERWRITES m_captured, orphaning the first, real, secret-bearing fd
    // pair (a leaked descriptor holding the actual PIN).
    dlg.accept();

    const auto pair = dlg.takeSecretFdPair();
    ASSERT_GE(pair.primaryFd, 0);
    ASSERT_GE(pair.secondaryFd, 0);
    // The FIRST capture's real secrets must survive the re-accept (the leaked
    // second capture would carry empty bytes read from the scrubbed edits).
    EXPECT_EQ(readMemfd(pair.primaryFd), "4321") << "the first capture's CURRENT secret must survive re-accept";
    EXPECT_EQ(readMemfd(pair.secondaryFd), "654321") << "the first capture's NEW secret must survive re-accept";

    ::close(pair.primaryFd);
    ::close(pair.secondaryFd);
}

// ----- reject captures nothing ----------------------------------------------

TEST(ChangePinDialog, RejectCapturesNoSecrets)
{
    PromptDialog dlg(PromptDialog::Kind::ChangePin, multiOptions());
    dlg.show();
    fillChangePin(dlg, "4321", "654321", "654321");

    QPushButton* cancel = cancelButtonOf(dlg);
    ASSERT_NE(cancel, nullptr);
    cancel->click();
    EXPECT_EQ(dlg.result(), QDialog::Rejected);

    const auto pair = dlg.takeSecretFdPair();
    EXPECT_EQ(pair.primaryFd, -1) << "a rejected dialog must capture no secret";
    EXPECT_EQ(pair.secondaryFd, -1) << "a rejected dialog must capture no secret";
}

// ----- confirm containment: compile-level result-type guarantee -------------

TEST(ChangePinDialog, ResultTypeExposesExactlyTwoSecrets)
{
    using SecretFdPair = PromptDialog::SecretFdPair;
    // A structured binding with exactly two names compiles ONLY while the
    // result type has exactly two non-static data members — adding a third
    // slot (e.g. for the confirm value) turns this test into a compile error.
    SecretFdPair pair{};
    auto [primaryFd, secondaryFd] = pair;
    EXPECT_EQ(primaryFd, -1);
    EXPECT_EQ(secondaryFd, -1);
    static_assert(sizeof(SecretFdPair) == 2 * sizeof(int),
                  "SecretFdPair must carry exactly the two secret fds (current + new)");
}

// ----- read-then-hide ordering ----------------------------------------------

TEST(ChangePinDialog, AllSecretReadsPrecedeAnyHideOrDisable)
{
    std::vector<std::string> log;
    PromptDialog dlg(PromptDialog::Kind::ChangePin, multiOptions(), nullptr, [&log](const PromptDialog::Options& opts) {
        return new OrderingRecorderWidget(&log, opts.primaryMinLength, opts.primaryMaxLength, opts.newMinLength,
                                          opts.newMaxLength);
    });
    dlg.show();
    fillChangePin(dlg, "4321", "654321", "654321");
    log.clear(); // discard construction/show noise; the accept path is under test

    QPushButton* ok = okButtonOf(dlg);
    ASSERT_NE(ok, nullptr);
    ok->click();
    ASSERT_EQ(dlg.result(), QDialog::Accepted);
    // Collect the pair BEFORE scanning the log — the take is part of the
    // accept/collection path (the service performs it right after exec()
    // unwinds), so a lazy post-hide capture hiding inside it must be seen.
    const auto pair = dlg.takeSecretFdPair();
    ASSERT_GE(pair.primaryFd, 0);
    ASSERT_GE(pair.secondaryFd, 0);
    ::close(pair.primaryFd);
    ::close(pair.secondaryFd);

    // There must be secret reads AND a dialog hide in the accept path.
    std::ptrdiff_t lastRead = -1;
    std::ptrdiff_t firstTeardown = -1;
    for (std::ptrdiff_t i = 0; i < static_cast<std::ptrdiff_t>(log.size()); ++i) {
        const std::string& entry = log[static_cast<std::size_t>(i)];
        if (entry.rfind("read:", 0) == 0) {
            lastRead = i;
        } else if (firstTeardown < 0) {
            firstTeardown = i; // "hide" or "disable"
        }
    }
    ASSERT_GE(lastRead, 0) << "the accept path must read the secret values";
    ASSERT_GE(firstTeardown, 0) << "accepting must eventually hide the dialog";
    EXPECT_LT(lastRead, firstTeardown) << "EVERY secret read must precede ANY hide/disable (read-then-hide); log: "
                                       << ::testing::PrintToString(log);
}

// ----- confirm containment: consumption accounting --------------------------

TEST(ChangePinWidget, ConfirmValueConsumedByLocalValidationOnly)
{
    CountingRecorderWidget w(4, 8, 6, 12);
    fillChangePin(w, "4321", "654321", "654321");

    // Local validation is the ONLY legitimate confirm consumer.
    EXPECT_TRUE(w.confirmMatchesNew());
    EXPECT_EQ(w.confirmReads, 1);
    const int confirmReadsAfterValidation = w.confirmReads;

    // Payload assembly (the two capture calls) must consume current + new and
    // NEVER the confirm value.
    const int primaryFd = w.captureSecretFd();
    const int secondaryFd = w.captureNewSecretFd();
    ASSERT_GE(primaryFd, 0);
    ASSERT_GE(secondaryFd, 0);
    EXPECT_GE(w.currentReads, 1);
    EXPECT_GE(w.newReads, 2); // one validation read + one capture read
    EXPECT_EQ(w.confirmReads, confirmReadsAfterValidation) << "payload assembly must never consume the confirm value";

    EXPECT_EQ(readMemfd(primaryFd), "4321");
    EXPECT_EQ(readMemfd(secondaryFd), "654321");
    ::close(primaryFd);
    ::close(secondaryFd);
}

TEST(ChangePinDialog, AcceptFlowReadsConfirmOnlyDuringValidation)
{
    CountingRecorderWidget* recorder = nullptr;
    PromptDialog dlg(PromptDialog::Kind::ChangePin, multiOptions(), nullptr,
                     [&recorder](const PromptDialog::Options& opts) {
                         recorder = new CountingRecorderWidget(opts.primaryMinLength, opts.primaryMaxLength,
                                                               opts.newMinLength, opts.newMaxLength);
                         return recorder;
                     });
    ASSERT_NE(recorder, nullptr);
    dlg.show();
    fillChangePin(dlg, "4321", "654321", "654321");

    QPushButton* ok = okButtonOf(dlg);
    ASSERT_NE(ok, nullptr);
    ok->click();
    ASSERT_EQ(dlg.result(), QDialog::Accepted);

    // Collect first — the take is part of the accept/collection path and the
    // containment claim covers the WHOLE of it.
    const auto pair = dlg.takeSecretFdPair();
    ASSERT_GE(pair.primaryFd, 0);
    ASSERT_GE(pair.secondaryFd, 0);
    EXPECT_EQ(readMemfd(pair.primaryFd), "4321");
    EXPECT_EQ(readMemfd(pair.secondaryFd), "654321");
    ::close(pair.primaryFd);
    ::close(pair.secondaryFd);

    EXPECT_EQ(recorder->confirmReads, 1)
        << "the full accept+collect flow must read the confirm value exactly once — in the mismatch validation";
    EXPECT_GE(recorder->currentReads, 1);
    EXPECT_GE(recorder->newReads, 2);
}

// ----- service level (real bus) ---------------------------------------------

namespace {

// Canonical path of the running test executable — what the in-process
// caller's /proc/<pid>/exe resolves to (PrompterAuthIntegrationTest pattern).
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

bool dialogIsLive()
{
    return PrompterService::s_activeDialog.load() != nullptr;
}

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

// Fixture: the real PrompterService on a server connection + a proxy client
// on a separate connection (sd-bus refuses self-calls); both pump async
// loops. Authorized dialog paths additionally need the Qt main thread to run
// an event loop — those tests drive the proxy from a worker thread.
class PrompterMultiFieldBusTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        m_serverConn = sdbus::createSessionBusConnection();
        ASSERT_NE(m_serverConn, nullptr) << "private session bus (run under dbus-run-session)";
        m_serverConn->requestName(sdbus::ServiceName{kServiceName});
        m_service = std::make_unique<PrompterService>(*m_serverConn, sdbus::ObjectPath{kObjectPath});
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
        PrompterService::s_activeDialog.store(nullptr);
        PrompterService::s_activeOwnerPid.store(0);
        ::unsetenv(kPeerEnv);
    }

    // Run @p onDialog (GUI thread, queued onto the live dialog) while a worker
    // drives RequestSecrets(kind, options); returns the reply tuple.
    std::tuple<std::string, sdbus::UnixFd, sdbus::UnixFd, std::string>
    driveRequestSecrets(const std::string& kind, const std::map<std::string, sdbus::Variant>& options,
                        void (*onDialog)(PromptDialog*))
    {
        std::tuple<std::string, sdbus::UnixFd, sdbus::UnixFd, std::string> reply;
        std::atomic<bool> returned{false};
        std::thread driver([&] {
            reply = m_client->RequestSecrets(kind, options);
            returned.store(true);
        });

        std::thread watcher([&] {
            if (!spinUntil(dialogIsLive, std::chrono::seconds{10})) {
                return; // no dialog appeared; the caller's assertions fail below
            }
            auto* dlg = PrompterService::s_activeDialog.load();
            if (dlg != nullptr && onDialog != nullptr) {
                QMetaObject::invokeMethod(dlg, [dlg, onDialog]() { onDialog(dlg); }, Qt::QueuedConnection);
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
        EXPECT_TRUE(returned.load()) << "RequestSecrets never returned (test wedged)";
        return reply;
    }

    std::unique_ptr<sdbus::IConnection> m_serverConn;
    std::unique_ptr<sdbus::IConnection> m_clientConn;
    std::unique_ptr<PrompterService> m_service;
    std::unique_ptr<Prompter1Client> m_client;
};

} // namespace

TEST_F(PrompterMultiFieldBusTest, UnauthorizedRequestSecretsReturnsBothZeroByteFds)
{
    // A non-agent caller is rejected fail-closed BEFORE any dialog, with the
    // "unauthorized" status and BOTH fds zero-length (the established
    // zero-byte-memfd no-secret encoding).
    ::setenv(kPeerEnv, "/usr/bin/true", 1);

    auto reply = m_client->RequestSecrets(LibreLinux::PrompterWire::kKindChangePin, {});
    EXPECT_EQ(std::get<0>(reply), "unauthorized");
    const int primary = std::get<1>(reply).get();
    const int secondary = std::get<2>(reply).get();
    ASSERT_GE(primary, 0) << "the wire signature still carries real fds";
    ASSERT_GE(secondary, 0);
    EXPECT_EQ(fdSize(primary), 0);
    EXPECT_EQ(fdSize(secondary), 0);
    EXPECT_EQ(PrompterService::s_activeDialog.load(), nullptr) << "no dialog for an unauthorized caller";
}

TEST_F(PrompterMultiFieldBusTest, UnknownKindReturnsErrorWithBothZeroByteFds)
{
    // RequestSecrets accepts the multi-field kinds only; a single-secret kind
    // (or garbage) is a typed error with no dialog and no secret bytes.
    ::setenv(kPeerEnv, selfExe().string().c_str(), 1);

    auto reply = m_client->RequestSecrets("pin", {});
    EXPECT_EQ(std::get<0>(reply), "error");
    EXPECT_EQ(fdSize(std::get<1>(reply).get()), 0);
    EXPECT_EQ(fdSize(std::get<2>(reply).get()), 0);
    // user_message must NOT carry a hardcoded English sentence: the status is
    // already "error" and clients map their own taxonomy. Empty, not "unknown kind".
    EXPECT_TRUE(std::get<3>(reply).empty()) << "user_message must not carry a bare English literal";
    EXPECT_EQ(PrompterService::s_activeDialog.load(), nullptr);
}

TEST_F(PrompterMultiFieldBusTest, CancelledChangePinReturnsCancelledWithBothZeroLengthFds)
{
    ::setenv(kPeerEnv, selfExe().string().c_str(), 1);

    std::tuple<std::string, sdbus::UnixFd, sdbus::UnixFd, std::string> reply;
    std::atomic<bool> returned{false};
    std::thread driver([&] {
        reply = m_client->RequestSecrets(LibreLinux::PrompterWire::kKindChangePin, {});
        returned.store(true);
    });
    std::thread watcher([&] {
        if (spinUntil(dialogIsLive, std::chrono::seconds{10})) {
            PrompterService::cancelCurrentForTest();
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

    ASSERT_TRUE(returned.load()) << "cancelled RequestSecrets never returned (test wedged)";
    EXPECT_EQ(std::get<0>(reply), "cancelled");
    const int primary = std::get<1>(reply).get();
    const int secondary = std::get<2>(reply).get();
    ASSERT_GE(primary, 0);
    ASSERT_GE(secondary, 0);
    EXPECT_EQ(fdSize(primary), 0) << "cancellation must never carry secret bytes";
    EXPECT_EQ(fdSize(secondary), 0) << "cancellation must never carry secret bytes";
    // Even the empty carriers are sealed like the single-secret path.
    const int reference = singleSecretPathSeals();
    EXPECT_EQ(sealsOf(primary), reference);
    EXPECT_EQ(sealsOf(secondary), reference);
}

namespace {

// GUI-thread accept driver for the authorized round trip: verifies the
// wire-supplied per-role bounds landed on the right fields, then fills and
// accepts.
void fillAndAccept(PromptDialog* dlg)
{
    QLineEdit* cur = editNamed(*dlg, "currentPinEdit");
    QLineEdit* nxt = editNamed(*dlg, "newPinEdit");
    QLineEdit* cnf = editNamed(*dlg, "confirmPinEdit");
    ASSERT_NE(cur, nullptr);
    ASSERT_NE(nxt, nullptr);
    ASSERT_NE(cnf, nullptr);
    // Bounds mapping: primary_* -> current, new_* -> new AND confirm.
    EXPECT_EQ(cur->maxLength(), 8);
    EXPECT_EQ(nxt->maxLength(), 12);
    EXPECT_EQ(cnf->maxLength(), 12);
    cur->setText(QStringLiteral("4321"));
    nxt->setText(QStringLiteral("654321"));
    cnf->setText(QStringLiteral("654321"));
    auto* box = dlg->findChild<QDialogButtonBox*>();
    ASSERT_NE(box, nullptr);
    ASSERT_NE(box->button(QDialogButtonBox::Ok), nullptr);
    box->button(QDialogButtonBox::Ok)->click();
}

} // namespace

TEST_F(PrompterMultiFieldBusTest, AcceptedChangePinReturnsCurrentAndNewSecrets)
{
    ::setenv(kPeerEnv, selfExe().string().c_str(), 1);

    namespace wire = LibreLinux::PrompterWire;
    const std::map<std::string, sdbus::Variant> options{
        {wire::kOptPrimaryMinLength, sdbus::Variant{std::uint32_t{4}}},
        {wire::kOptPrimaryMaxLength, sdbus::Variant{std::uint32_t{8}}},
        {wire::kOptNewMinLength, sdbus::Variant{std::uint32_t{6}}},
        {wire::kOptNewMaxLength, sdbus::Variant{std::uint32_t{12}}},
        {wire::kOptPinLabel, sdbus::Variant{std::string{"Signature PIN"}}},
    };

    auto reply = driveRequestSecrets(wire::kKindChangePin, options, &fillAndAccept);

    EXPECT_EQ(std::get<0>(reply), "ok");
    const int primary = std::get<1>(reply).get();
    const int secondary = std::get<2>(reply).get();
    ASSERT_GE(primary, 0);
    ASSERT_GE(secondary, 0);
    EXPECT_EQ(readMemfd(primary), "4321") << "primary_fd must carry the CURRENT secret";
    EXPECT_EQ(readMemfd(secondary), "654321") << "secondary_fd must carry the NEW secret";
    const int reference = singleSecretPathSeals();
    EXPECT_EQ(sealsOf(primary), reference) << "multi-secret seal set must match the single-secret path";
    EXPECT_EQ(sealsOf(secondary), reference) << "multi-secret seal set must match the single-secret path";
    EXPECT_EQ(std::get<3>(reply), "");
    // Slots cleared after the dialog unwinds.
    EXPECT_EQ(PrompterService::s_activeDialog.load(), nullptr);
    EXPECT_EQ(PrompterService::s_activeOwnerPid.load(), 0);
}

// ----- main -----------------------------------------------------------------

int main(int argc, char** argv)
{
    QApplication app(argc, argv);
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
