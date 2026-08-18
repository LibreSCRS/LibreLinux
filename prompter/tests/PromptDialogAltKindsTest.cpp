// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Pins the opt-in CAN -> MRZ switch affordance on the credential dialog: a CAN
// prompt whose caller declared it can also consume an MRZ (Options::
// offerMrzSwitch) renders one flat switch button between the input widget and
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
#include <QVBoxLayout>

#include <unistd.h> // read, lseek, close

#include <gtest/gtest.h>

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
    EXPECT_TRUE(button->isFlat()) << "the switch is a flat inline affordance, not a second primary action";

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
