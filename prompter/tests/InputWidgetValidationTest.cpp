// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Offscreen Qt unit tests for the credential-capture widgets. Drives the
// validator logic directly via setText() — no event dispatch, no real
// display server. ICAO 9303 sample data is recomputed in-test (the
// Python helper used to generate the expected values is recorded in the
// implementation notes).
//
// This intentionally does NOT exercise the D-Bus RequestSecret flow; an
// integration test will plug a private session bus + dbus-run-session
// once the agent-side PrompterClient lands.

#include "CanInputWidget.h"
#include "MrzInputWidget.h"
#include "PinInputWidget.h"
#include "SecretMemfd.h"

#include <gtest/gtest.h>

#include <QApplication>
#include <QLineEdit>
#include <QSignalSpy>

#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <cstring>
#include <string>
#include <vector>

namespace {

// One QApplication for the whole test binary — Qt forbids more than one
// per process. Constructed in main; tests look it up via instance().
QApplication* qappForTests = nullptr;

QLineEdit* firstLineEdit(QWidget* parent)
{
    return parent->findChild<QLineEdit*>();
}

std::vector<QLineEdit*> allLineEdits(QWidget* parent)
{
    // Qt6 dropped QList::toStdVector() — copy via the iterator range.
    const auto list = parent->findChildren<QLineEdit*>();
    return std::vector<QLineEdit*>(list.begin(), list.end());
}

// Read back a sealed memfd's contents into a std::string for assertion.
// Tests own the returned fd lifecycle.
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

// ----- SecretMemfd ----------------------------------------------------------

TEST(SecretMemfd, EmptyIsValidZeroByteFd)
{
    int fd = LibreLinux::Prompter::makeEmptySealedFd();
    ASSERT_GE(fd, 0);
    EXPECT_EQ(::lseek(fd, 0, SEEK_END), 0);
    ::close(fd);
}

TEST(SecretMemfd, RoundTripsBytesAndAppliesSeals)
{
    constexpr const char kSample[] = "012345";
    const int fd = LibreLinux::Prompter::makeSealedSecretFd({kSample, std::strlen(kSample)});
    ASSERT_GE(fd, 0);
    EXPECT_EQ(readMemfd(fd), std::string(kSample));

    const int seals = ::fcntl(fd, F_GET_SEALS);
    ASSERT_GE(seals, 0);
    EXPECT_TRUE(seals & F_SEAL_WRITE) << "F_SEAL_WRITE not applied";
    EXPECT_TRUE(seals & F_SEAL_GROW) << "F_SEAL_GROW not applied";
    EXPECT_TRUE(seals & F_SEAL_SHRINK) << "F_SEAL_SHRINK not applied";

    // Confirm the seal actually blocks further writes.
    const char extra = '!';
    const auto rc = ::write(fd, &extra, 1);
    EXPECT_LT(rc, 0) << "sealed memfd accepted a write (should EPERM)";
    ::close(fd);
}

// ----- PIN validator --------------------------------------------------------

TEST(PinInputWidget, RejectsNonDigit)
{
    LibreLinux::Prompter::PinInputWidget w(4, 8);
    QLineEdit* edit = firstLineEdit(&w);
    ASSERT_NE(edit, nullptr);
    // The validator's setMaxLength(8) prevents over-length entry; the
    // regexp validator rejects non-digits. setText() bypasses keystroke
    // filtering but hasAcceptableInput() still consults the validator.
    edit->setText(QStringLiteral("12a4"));
    EXPECT_FALSE(w.isValid()) << "non-digit input must not validate";
}

TEST(PinInputWidget, EnforcesMinLength)
{
    LibreLinux::Prompter::PinInputWidget w(4, 8);
    QLineEdit* edit = firstLineEdit(&w);
    edit->setText(QStringLiteral("123"));
    EXPECT_FALSE(w.isValid()) << "shorter than min must not validate";
    edit->setText(QStringLiteral("1234"));
    EXPECT_TRUE(w.isValid());
}

TEST(PinInputWidget, EnforcesMaxLength)
{
    LibreLinux::Prompter::PinInputWidget w(4, 8);
    QLineEdit* edit = firstLineEdit(&w);
    // QLineEdit::setMaxLength enforced by the widget; setText still
    // truncates to maxLength.
    EXPECT_EQ(edit->maxLength(), 8);
    edit->setText(QStringLiteral("12345678"));
    EXPECT_TRUE(w.isValid());
    // Direct truncation check — setText accepts whatever fits.
    edit->setText(QStringLiteral("123456789"));
    EXPECT_EQ(edit->text().size(), 8);
}

TEST(PinInputWidget, AcceptsConfiguredCustomRange)
{
    LibreLinux::Prompter::PinInputWidget w(6, 12);
    QLineEdit* edit = firstLineEdit(&w);
    EXPECT_EQ(edit->maxLength(), 12);
    edit->setText(QStringLiteral("12345"));
    EXPECT_FALSE(w.isValid());
    edit->setText(QStringLiteral("123456"));
    EXPECT_TRUE(w.isValid());
    edit->setText(QStringLiteral("123456789012"));
    EXPECT_TRUE(w.isValid());
}

TEST(PinInputWidget, CaptureWritesEnteredBytes)
{
    LibreLinux::Prompter::PinInputWidget w(4, 8);
    firstLineEdit(&w)->setText(QStringLiteral("12345678"));
    ASSERT_TRUE(w.isValid());
    const int fd = w.captureSecretFd();
    ASSERT_GE(fd, 0);
    EXPECT_EQ(readMemfd(fd), "12345678");
    ::close(fd);
}

// ----- CAN validator --------------------------------------------------------

TEST(CanInputWidget, RequiresExactlySixDigits)
{
    LibreLinux::Prompter::CanInputWidget w;
    QLineEdit* edit = firstLineEdit(&w);
    edit->setText(QStringLiteral("12345"));
    EXPECT_FALSE(w.isValid());
    edit->setText(QStringLiteral("1234567")); // QLineEdit clamps to 6
    EXPECT_EQ(edit->text().size(), 6);
    EXPECT_TRUE(w.isValid()); // first 6 chars are "123456" — valid
}

TEST(CanInputWidget, RejectsNonDigit)
{
    LibreLinux::Prompter::CanInputWidget w;
    firstLineEdit(&w)->setText(QStringLiteral("12345a"));
    EXPECT_FALSE(w.isValid());
}

TEST(CanInputWidget, AcceptsSixDigits)
{
    LibreLinux::Prompter::CanInputWidget w;
    firstLineEdit(&w)->setText(QStringLiteral("987654"));
    EXPECT_TRUE(w.isValid());
}

TEST(CanInputWidget, CaptureWritesEnteredBytes)
{
    LibreLinux::Prompter::CanInputWidget w;
    firstLineEdit(&w)->setText(QStringLiteral("987654"));
    const int fd = w.captureSecretFd();
    ASSERT_GE(fd, 0);
    EXPECT_EQ(readMemfd(fd), "987654");
    ::close(fd);
}

// ----- MRZ check-digit logic + widget validity ------------------------------

TEST(MrzCheckDigit, KnownGoodSamples)
{
    // ICAO 9303 — recomputed via the cyclic 7-3-1 weight scheme.
    EXPECT_TRUE(LibreLinux::Prompter::MrzInputWidget::checkDigitOk(QStringLiteral("L898902C<"), QChar(u'3')));
    EXPECT_TRUE(LibreLinux::Prompter::MrzInputWidget::checkDigitOk(QStringLiteral("690806"), QChar(u'1')));
    EXPECT_TRUE(LibreLinux::Prompter::MrzInputWidget::checkDigitOk(QStringLiteral("940623"), QChar(u'6')));
}

TEST(MrzCheckDigit, KnownBadSamples)
{
    // Off-by-one on each — should all fail.
    EXPECT_FALSE(LibreLinux::Prompter::MrzInputWidget::checkDigitOk(QStringLiteral("L898902C<"), QChar(u'4')));
    EXPECT_FALSE(LibreLinux::Prompter::MrzInputWidget::checkDigitOk(QStringLiteral("690806"), QChar(u'0')));
    EXPECT_FALSE(LibreLinux::Prompter::MrzInputWidget::checkDigitOk(QStringLiteral("940623"), QChar(u'5')));
}

TEST(MrzCheckDigit, NonDigitCheckCharIsAlwaysInvalid)
{
    // The check character must be a decimal digit; anything else fails.
    EXPECT_FALSE(LibreLinux::Prompter::MrzInputWidget::checkDigitOk(QStringLiteral("690806"), QChar(u'X')));
    EXPECT_FALSE(LibreLinux::Prompter::MrzInputWidget::checkDigitOk(QStringLiteral("690806"), QChar(u'<')));
}

TEST(MrzInputWidget, ValidatesEachFieldIndependently)
{
    LibreLinux::Prompter::MrzInputWidget w;
    auto edits = allLineEdits(&w);
    ASSERT_EQ(edits.size(), 3u);
    edits[0]->setText(QStringLiteral("L898902C<3"));
    edits[1]->setText(QStringLiteral("6908061"));
    edits[2]->setText(QStringLiteral("9406236"));
    EXPECT_TRUE(w.isValid());

    // Flip ONE digit in the document number's check digit — must invalidate.
    edits[0]->setText(QStringLiteral("L898902C<4"));
    EXPECT_FALSE(w.isValid());
}

TEST(MrzInputWidget, RejectsShortField)
{
    LibreLinux::Prompter::MrzInputWidget w;
    auto edits = allLineEdits(&w);
    // The regex enforces exact field widths; shorter than 10/7/7 must
    // hasAcceptableInput()==false, regardless of check-digit math.
    edits[0]->setText(QStringLiteral("L898902C"));
    edits[1]->setText(QStringLiteral("6908061"));
    edits[2]->setText(QStringLiteral("9406236"));
    EXPECT_FALSE(w.isValid());
}

TEST(MrzInputWidget, CaptureJoinsWithNewlineSeparator)
{
    LibreLinux::Prompter::MrzInputWidget w;
    auto edits = allLineEdits(&w);
    edits[0]->setText(QStringLiteral("L898902C<3"));
    edits[1]->setText(QStringLiteral("6908061"));
    edits[2]->setText(QStringLiteral("9406236"));
    const int fd = w.captureSecretFd();
    ASSERT_GE(fd, 0);
    EXPECT_EQ(readMemfd(fd), "L898902C<3\n6908061\n9406236");
    ::close(fd);
}

// ----- main -----------------------------------------------------------------

int main(int argc, char** argv)
{
    QApplication app(argc, argv);
    qappForTests = &app;
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
