// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Pins the opt-in CAN -> MRZ switch affordance on the credential dialog: a CAN
// prompt whose caller declared it can also consume an MRZ (Options::
// offerMrzSwitch) renders one switch button between the input widget and
// the button box; clicking it swaps CanInputWidget <-> MrzInputWidget IN PLACE
// (same layout index, old widget destroyed so its destructor scrubs its
// buffers) and RE-FRAMES the dialog for the new kind (window title, the
// kind hint line, the stale retry-context error line, and the entry rules that
// gate OK).
//
// The structural half of the additive rollout contract lives here: WITHOUT the
// opt-in no switch button exists at all, so the distinct "user chose MRZ"
// status the service mints off mrzChosen() is unmintable by construction for
// every caller that never asked for the choice.
//
// Runs under QT_QPA_PLATFORM=offscreen so no display server is required.

#include "CanInputWidget.h"
#include "MrzInputWidget.h"
#include "PromptDialog.h"

#include <QApplication>
#include <QDate>
#include <QDateEdit>
#include <QDialogButtonBox>
#include <QEvent>
#include <QLabel>
#include <QLineEdit>
#include <QPointer>
#include <QPushButton>
#include <QTimer>
#include <QVBoxLayout>

#include <unistd.h> // read, lseek, close

#include <gtest/gtest.h>

#include <chrono>
#include <cstddef>
#include <string>

using LibreLinux::Prompter::CanInputWidget;
using LibreLinux::Prompter::MrzInputWidget;
using LibreLinux::Prompter::PromptDialog;

namespace {

// ICAO 9303 SPECIMEN values (the published example document), not a real
// travel document: document number + check digit, date of birth + check digit,
// date of expiry + check digit. Their concatenation is the canonical three-line
// payload MrzInputWidget::captureSecretFd emits.
// User-facing specimen entry (ICAO 9303 worked example): the human types the
// document number WITHOUT its check digit and picks the two dates; the widget
// computes the check digits, so the captured payload below carries them.
constexpr const char* kSpecimenDocNumber = "L898902C3";
const QDate kSpecimenDateOfBirth(1974, 8, 12);
const QDate kSpecimenDateOfExpiry(2012, 4, 15);
constexpr const char* kSpecimenPayload = "L898902C36\n7408122\n1204159";

PromptDialog::Options switchableCanOptions()
{
    PromptDialog::Options opts;
    opts.offerMrzSwitch = true;
    return opts;
}

QPushButton* switchButtonOf(PromptDialog& dlg)
{
    return dlg.findChild<QPushButton*>(QStringLiteral("switchToMrzButton"));
}

// The window's entry clock. The dialog owns exactly two timers -- the one-shot
// that closes the window and the repeating one that only repaints the label --
// so single-shot identifies it; assert that here rather than trust it, or a
// third timer added later would silently re-point every assertion below.
QTimer* deadlineTimerOf(PromptDialog& dlg)
{
    QTimer* found = nullptr;
    for (QTimer* timer : dlg.findChildren<QTimer*>()) {
        if (timer->isSingleShot()) {
            EXPECT_EQ(found, nullptr) << "more than one one-shot timer: the clock is no longer identifiable";
            found = timer;
        }
    }
    return found;
}

QPushButton* okButtonOf(PromptDialog& dlg)
{
    auto* box = dlg.findChild<QDialogButtonBox*>();
    return box != nullptr ? box->button(QDialogButtonBox::Ok) : nullptr;
}

QVBoxLayout* layoutOf(PromptDialog& dlg)
{
    return qobject_cast<QVBoxLayout*>(dlg.layout());
}

// Flush the deferred deletions the in-place swap schedules, without entering a
// nested event loop (these tests never exec() the dialog).
void flushDeferredDeletes()
{
    QCoreApplication::sendPostedEvents(nullptr, QEvent::DeferredDelete);
}

// Fill the MRZ form with the specimen values. The fields are addressed by
// object name (the two date entries are QDateEdits, whose internal line edits
// would make positional findChildren<QLineEdit*>() ambiguous) — the same
// convention InputWidgetValidationTest uses.
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

// Read back a sealed memfd's contents for assertion (house helper, mirrored
// from InputWidgetValidationTest). The caller owns the fd.
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

} // namespace

// ----- no opt-in, no affordance ---------------------------------------------

TEST(PromptDialogAltKinds, NoSwitchAffordanceWithoutOptIn)
{
    int argc = 1;
    const char* argv[] = {"alt-kinds-test"};
    QApplication app(argc, const_cast<char**>(argv));

    // Default Options: offerMrzSwitch == false — the shape EVERY caller that
    // does not opt in produces. No affordance may exist, so the "user chose
    // MRZ" outcome the service keys its distinct status off is structurally
    // unreachable for such a caller.
    PromptDialog dlg(PromptDialog::Kind::Can, PromptDialog::Options{}, nullptr);
    EXPECT_EQ(switchButtonOf(dlg), nullptr) << "a CAN prompt without the opt-in must render no switch button";
    EXPECT_NE(dlg.findChild<CanInputWidget*>(), nullptr);
    EXPECT_EQ(dlg.findChild<MrzInputWidget*>(), nullptr);
    EXPECT_FALSE(dlg.mrzChosen());
}

// ----- opt-in renders the affordance, still on the CAN form -----------------

TEST(PromptDialogAltKinds, SwitchAffordancePresentWithOptIn)
{
    int argc = 1;
    const char* argv[] = {"alt-kinds-test"};
    QApplication app(argc, const_cast<char**>(argv));

    PromptDialog dlg(PromptDialog::Kind::Can, switchableCanOptions(), nullptr);

    auto* button = switchButtonOf(dlg);
    ASSERT_NE(button, nullptr) << "the opt-in must render the switch affordance";
    EXPECT_FALSE(button->text().isEmpty()) << "the switch must carry a localized label";
    // Breeze draws NO frame on a flat button until the pointer is over it, so
    // a flat switch reads as centred text and was not recognised as clickable
    // on a real desk. It must look like a button.
    EXPECT_FALSE(button->isFlat()) << "a flat switch is invisible as an affordance under Breeze";
    // Still not a second primary action, which is what flatness was standing in
    // for: Return accepts the dialog and must never swap the form out from
    // under someone who has already typed.
    EXPECT_FALSE(button->isDefault()) << "the switch must not be the dialog's default button";
    EXPECT_FALSE(button->autoDefault()) << "the switch must not become default by focus";

    // Opting in does NOT pre-select the alternative: the dialog still shows the
    // requested CAN form until the user asks for the other one.
    auto* canWidget = dlg.findChild<CanInputWidget*>();
    ASSERT_NE(canWidget, nullptr);
    EXPECT_EQ(dlg.findChild<MrzInputWidget*>(), nullptr);
    EXPECT_FALSE(dlg.mrzChosen());

    // Positioned between the input widget and the button box.
    auto* layout = layoutOf(dlg);
    ASSERT_NE(layout, nullptr);
    auto* box = dlg.findChild<QDialogButtonBox*>();
    ASSERT_NE(box, nullptr);
    EXPECT_GT(layout->indexOf(button), layout->indexOf(canWidget));
    EXPECT_LT(layout->indexOf(button), layout->indexOf(box));
}

// ----- the swap itself ------------------------------------------------------

TEST(PromptDialogAltKinds, SwitchSwapsToMrzFormInPlace)
{
    int argc = 1;
    const char* argv[] = {"alt-kinds-test"};
    QApplication app(argc, const_cast<char**>(argv));

    PromptDialog dlg(PromptDialog::Kind::Can, switchableCanOptions(), nullptr);
    auto* layout = layoutOf(dlg);
    ASSERT_NE(layout, nullptr);

    QPointer<CanInputWidget> canWidget = dlg.findChild<CanInputWidget*>();
    ASSERT_FALSE(canWidget.isNull());
    const int slot = layout->indexOf(canWidget);
    ASSERT_GE(slot, 0);

    auto* button = switchButtonOf(dlg);
    ASSERT_NE(button, nullptr);
    button->click();

    auto* mrzWidget = dlg.findChild<MrzInputWidget*>();
    ASSERT_NE(mrzWidget, nullptr) << "clicking the switch must install the MRZ form";
    EXPECT_EQ(layout->indexOf(mrzWidget), slot) << "the new form must occupy the SAME layout slot";
    EXPECT_TRUE(dlg.mrzChosen());

    // The old widget must be gone, not merely detached: its destructor is the
    // disposal path that scrubs whatever the user had already typed.
    flushDeferredDeletes();
    EXPECT_TRUE(canWidget.isNull()) << "the replaced CAN widget must be destroyed, not orphaned";

    // Window title re-framed for the new kind: identical to a dialog built for
    // the MRZ kind outright.
    PromptDialog reference(PromptDialog::Kind::Mrz, PromptDialog::Options{}, nullptr);
    EXPECT_EQ(dlg.windowTitle(), reference.windowTitle());
}

// ----- re-framing the rest of the dialog ------------------------------------

TEST(PromptDialogAltKinds, SwitchReframesDialogForTheNewKind)
{
    int argc = 1;
    const char* argv[] = {"alt-kinds-test"};
    QApplication app(argc, const_cast<char**>(argv));

    PromptDialog::Options opts = switchableCanOptions();
    // A re-prompt after the card rejected the CAN collected last time, with
    // CAN-side entry bounds supplied by the caller.
    opts.attempt = 2;
    opts.lastError = QStringLiteral("librescrs.error.preRead.authFailed");
    opts.minLength = 6;
    opts.maxLength = 6;
    PromptDialog dlg(PromptDialog::Kind::Can, opts, nullptr);

    auto* hint = dlg.findChild<QLabel*>(QStringLiteral("kindHintLabel"));
    ASSERT_NE(hint, nullptr) << "a switchable prompt must say which credential the visible form takes";
    const QString canHint = hint->text();
    EXPECT_FALSE(canHint.isEmpty());
    ASSERT_NE(dlg.findChild<QLabel*>(QStringLiteral("retryErrorLabel")), nullptr)
        << "precondition: the re-prompt shows the retry-context error line";

    switchButtonOf(dlg)->click();

    // The description line now reads for the MRZ kind.
    auto* hintAfter = dlg.findChild<QLabel*>(QStringLiteral("kindHintLabel"));
    ASSERT_NE(hintAfter, nullptr);
    EXPECT_FALSE(hintAfter->text().isEmpty());
    EXPECT_NE(hintAfter->text(), canHint) << "the kind hint must be re-rendered for the form now shown";

    // The retry-context error described the CAN attempt — it must not survive
    // the swap and accuse the freshly-offered MRZ entry.
    EXPECT_EQ(dlg.findChild<QLabel*>(QStringLiteral("retryErrorLabel")), nullptr)
        << "the stale retry-context error must be cleared by the swap";

    // The caller's CAN entry bounds no longer gate OK: the MRZ form carries its
    // own per-field validators and a valid MRZ entry enables acceptance.
    auto* ok = okButtonOf(dlg);
    ASSERT_NE(ok, nullptr);
    fillMrzSpecimen(dlg);
    EXPECT_TRUE(ok->isEnabled()) << "after the swap only the MRZ form's own rules may gate OK";
}

// ----- toggling back --------------------------------------------------------

TEST(PromptDialogAltKinds, SwitchTogglesBack)
{
    int argc = 1;
    const char* argv[] = {"alt-kinds-test"};
    QApplication app(argc, const_cast<char**>(argv));

    PromptDialog dlg(PromptDialog::Kind::Can, switchableCanOptions(), nullptr);
    auto* layout = layoutOf(dlg);
    ASSERT_NE(layout, nullptr);
    const int slot = layout->indexOf(dlg.findChild<CanInputWidget*>());

    auto* button = switchButtonOf(dlg);
    ASSERT_NE(button, nullptr);
    const QString toMrzText = button->text();
    button->click();
    ASSERT_TRUE(dlg.mrzChosen());
    EXPECT_NE(button->text(), toMrzText) << "the switch must offer the return direction once switched";

    QPointer<MrzInputWidget> mrzWidget = dlg.findChild<MrzInputWidget*>();
    ASSERT_FALSE(mrzWidget.isNull());

    button->click();
    auto* canWidget = dlg.findChild<CanInputWidget*>();
    ASSERT_NE(canWidget, nullptr) << "a second click must restore the CAN form";
    EXPECT_EQ(layout->indexOf(canWidget), slot) << "the restored form must occupy the SAME layout slot";
    EXPECT_FALSE(dlg.mrzChosen());
    EXPECT_EQ(button->text(), toMrzText) << "the switch label must return to the outbound direction";

    flushDeferredDeletes();
    EXPECT_TRUE(mrzWidget.isNull()) << "the replaced MRZ widget must be destroyed, not orphaned";

    // The CAN entry rule applies again to the restored form.
    auto* ok = okButtonOf(dlg);
    ASSERT_NE(ok, nullptr);
    auto* edit = canWidget->findChild<QLineEdit*>();
    ASSERT_NE(edit, nullptr);
    edit->setText(QStringLiteral("12345"));
    EXPECT_FALSE(ok->isEnabled()) << "the restored CAN form must re-apply its own entry rule";
    edit->setText(QStringLiteral("123456"));
    EXPECT_TRUE(ok->isEnabled());
}

// ----- validity re-wiring ---------------------------------------------------

TEST(PromptDialogAltKinds, OkDisabledUntilMrzValid)
{
    int argc = 1;
    const char* argv[] = {"alt-kinds-test"};
    QApplication app(argc, const_cast<char**>(argv));

    PromptDialog dlg(PromptDialog::Kind::Can, switchableCanOptions(), nullptr);
    switchButtonOf(dlg)->click();

    auto* ok = okButtonOf(dlg);
    ASSERT_NE(ok, nullptr);
    EXPECT_FALSE(ok->isEnabled()) << "an empty MRZ form must not be acceptable";

    auto* doc = dlg.findChild<QLineEdit*>(QStringLiteral("mrzDocumentNumber"));
    auto* dob = dlg.findChild<QDateEdit*>(QStringLiteral("mrzDateOfBirth"));
    auto* expiry = dlg.findChild<QDateEdit*>(QStringLiteral("mrzDateOfExpiry"));
    ASSERT_NE(doc, nullptr);
    ASSERT_NE(dob, nullptr);
    ASSERT_NE(expiry, nullptr);
    doc->setText(QString::fromLatin1(kSpecimenDocNumber));
    EXPECT_FALSE(ok->isEnabled()) << "a partially filled MRZ form must not be acceptable";
    dob->setDate(kSpecimenDateOfBirth);
    EXPECT_FALSE(ok->isEnabled()) << "an untouched expiry date must keep the form unacceptable";
    expiry->setDate(kSpecimenDateOfExpiry);
    EXPECT_TRUE(ok->isEnabled()) << "validity must be re-wired to the swapped-in widget";
}

// ----- the payload the swapped-in form captures -----------------------------

TEST(PromptDialogAltKinds, AcceptOnMrzCapturesCanonicalPayload)
{
    int argc = 1;
    const char* argv[] = {"alt-kinds-test"};
    QApplication app(argc, const_cast<char**>(argv));

    PromptDialog dlg(PromptDialog::Kind::Can, switchableCanOptions(), nullptr);
    dlg.show();
    switchButtonOf(dlg)->click();
    fillMrzSpecimen(dlg);

    auto* ok = okButtonOf(dlg);
    ASSERT_NE(ok, nullptr);
    ok->click();
    ASSERT_EQ(dlg.result(), QDialog::Accepted);
    EXPECT_TRUE(dlg.mrzChosen());

    // Same capture the plain MRZ prompt performs — the swap adds no second
    // capture path, so the payload shape cannot drift between the two.
    const int fd = dlg.captureSecretFd();
    ASSERT_GE(fd, 0);
    EXPECT_EQ(readMemfd(fd), std::string(kSpecimenPayload));
    ::close(fd);
}

// ----- the clock follows the form the holder is actually filling in ---------
//
// Two halves, deliberately measured apart. The ARITHMETIC (what the new
// remaining time must be) is exact and belongs to a pure function; the WIRING
// (the running clock actually got re-armed) is measured on the live QTimer,
// whose default coarse type may report up to 5% ABOVE its nominal interval --
// a 120 s timer answered 120147 ms here. Every widget-level bound below is
// therefore far outside that slop, and none of them tries to tell a re-based
// clock from a restarted one: that distinction is the pure function's job.

// The trap the whole change exists around: a switch must NOT hand the holder a
// fresh copy of the alternative's budget. 110 s already spent plus a fresh
// 300 s is 410 s of window, and the transport carrying the prompt is pinned to
// outlive 300 s, not 410.
TEST(PromptDialogAltKinds, RebasedRemainingSubtractsWhatTheWindowAlreadySpent)
{
    using namespace std::chrono_literals;
    const auto rebased = &PromptDialog::rebasedRemaining;

    // The case from the desk: switched at 1:50 into a 2:00 CAN window.
    EXPECT_EQ(rebased(120'000ms, 300'000ms, 110'000ms), 190'000ms)
        << "the alternative's budget runs from the window, not from the switch";
    // Switched the instant it appeared: the whole alternative budget is left.
    EXPECT_EQ(rebased(120'000ms, 300'000ms, 0ms), 300'000ms);
    // An alternative worth no more than what is already armed changes nothing,
    // which is also what switching BACK to the shorter form must do.
    EXPECT_EQ(rebased(300'000ms, 120'000ms, 10'000ms), 0ms);
    EXPECT_EQ(rebased(300'000ms, 300'000ms, 10'000ms), 0ms);
    // Past even the longer budget: never a negative interval, which a QTimer
    // would read as "fire immediately" and close the window on the switch.
    EXPECT_EQ(rebased(120'000ms, 300'000ms, 310'000ms), 0ms);
    // No alternative offered at all.
    EXPECT_EQ(rebased(120'000ms, 0ms, 10'000ms), 0ms);
}

// The wiring: taking the offer re-arms the LIVE clock, not just a member. The
// two budgets are an order of magnitude apart so no coarse-timer slop can
// account for the difference.
TEST(PromptDialogAltKinds, SwitchingToTheAlternativeRebasesTheClockOnItsBudget)
{
    int argc = 1;
    const char* argv[] = {"alt-kinds-test"};
    QApplication app(argc, const_cast<char**>(argv));

    PromptDialog dlg(PromptDialog::Kind::Can, switchableCanOptions(), nullptr);
    dlg.setEntryDeadline(std::chrono::milliseconds{20'000});
    dlg.setAlternateEntryDeadline(std::chrono::milliseconds{300'000});
    dlg.show();

    auto* clock = deadlineTimerOf(dlg);
    ASSERT_NE(clock, nullptr);
    ASSERT_TRUE(clock->isActive()) << "the clock starts when the window is shown";
    ASSERT_LT(clock->remainingTime(), 30'000) << "armed on the requested form's budget";

    switchButtonOf(dlg)->click();

    EXPECT_GT(clock->remainingTime(), 200'000) << "the alternative's budget has to reach the running clock";
}

// Switching back is not a punishment: a holder who looked at the MRZ form and
// thought better of it must not find their window closing sooner than before
// they looked.
TEST(PromptDialogAltKinds, SwitchingBackNeverTakesBackTimeAlreadyGranted)
{
    int argc = 1;
    const char* argv[] = {"alt-kinds-test"};
    QApplication app(argc, const_cast<char**>(argv));

    PromptDialog dlg(PromptDialog::Kind::Can, switchableCanOptions(), nullptr);
    dlg.setEntryDeadline(std::chrono::milliseconds{20'000});
    dlg.setAlternateEntryDeadline(std::chrono::milliseconds{300'000});
    dlg.show();

    auto* clock = deadlineTimerOf(dlg);
    ASSERT_NE(clock, nullptr);
    switchButtonOf(dlg)->click();
    ASSERT_GT(clock->remainingTime(), 200'000);

    switchButtonOf(dlg)->click(); // back to the CAN form
    EXPECT_GT(clock->remainingTime(), 200'000) << "returning to the shorter form must not shorten the window";
}

// The additive half: an agent that predates the option sends no alternative
// budget, and such a window must behave exactly as it does today -- the switch
// still works, the clock simply stays on what it was armed with.
TEST(PromptDialogAltKinds, WithoutAnAlternativeBudgetTheClockIsUntouched)
{
    int argc = 1;
    const char* argv[] = {"alt-kinds-test"};
    QApplication app(argc, const_cast<char**>(argv));

    PromptDialog dlg(PromptDialog::Kind::Can, switchableCanOptions(), nullptr);
    dlg.setEntryDeadline(std::chrono::milliseconds{20'000});
    dlg.show();

    auto* clock = deadlineTimerOf(dlg);
    ASSERT_NE(clock, nullptr);
    switchButtonOf(dlg)->click();
    EXPECT_LT(clock->remainingTime(), 30'000) << "no alternative budget, no re-base";
    EXPECT_GT(clock->remainingTime(), 0);
}

// A window with no clock at all (deadline 0 -- the "unset" sentinel) must not
// grow one just because a switch was offered.
TEST(PromptDialogAltKinds, AnAlternativeBudgetNeverArmsAWindowThatHasNoClock)
{
    int argc = 1;
    const char* argv[] = {"alt-kinds-test"};
    QApplication app(argc, const_cast<char**>(argv));

    PromptDialog dlg(PromptDialog::Kind::Can, switchableCanOptions(), nullptr);
    dlg.setEntryDeadline(std::chrono::milliseconds::zero());
    dlg.setAlternateEntryDeadline(std::chrono::milliseconds{300'000});
    dlg.show();

    switchButtonOf(dlg)->click();
    EXPECT_EQ(deadlineTimerOf(dlg), nullptr) << "an unset deadline stays unset";
}
