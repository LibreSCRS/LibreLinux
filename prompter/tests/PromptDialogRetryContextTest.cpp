// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Pins the retry-context inline error: a re-prompt after the card rejected
// the CAN/MRZ collected last time for the SAME card (opts.attempt > 0) shows
// a localized error line immediately above the input widget; the first-ever
// prompt for a card (opts.attempt == 0, the default) shows nothing. No
// attempts counter is ever rendered -- parity with the GUI's own inline
// error bar, which re-enables entry for retry without displaying a count.
//
// Runs under QT_QPA_PLATFORM=offscreen so no display server is required.

#include "PromptDialog.h"

#include <QApplication>
#include <QLabel>
#include <QVBoxLayout>

#include <gtest/gtest.h>

using LibreLinux::Prompter::PromptDialog;

TEST(PromptDialogRetryContext, NoRetryErrorLabelOnFirstPrompt)
{
    int argc = 1;
    const char* argv[] = {"retry-context-test"};
    QApplication app(argc, const_cast<char**>(argv));

    // Default Options: attempt == 0 -- the first-ever prompt for a card.
    PromptDialog dlg(PromptDialog::Kind::Can, PromptDialog::Options{}, nullptr);
    EXPECT_EQ(dlg.findChild<QLabel*>(QStringLiteral("retryErrorLabel")), nullptr)
        << "the first-ever prompt must not show a retry error line";
}

TEST(PromptDialogRetryContext, RetryErrorLabelShownAboveTheInputOnRePrompt)
{
    int argc = 1;
    const char* argv[] = {"retry-context-test"};
    QApplication app(argc, const_cast<char**>(argv));

    PromptDialog::Options opts;
    opts.attempt = 2;
    opts.lastError = QStringLiteral("librescrs.error.preRead.authFailed");
    PromptDialog dlg(PromptDialog::Kind::Can, opts, nullptr);

    auto* retryError = dlg.findChild<QLabel*>(QStringLiteral("retryErrorLabel"));
    ASSERT_NE(retryError, nullptr) << "a re-prompt (attempt > 0) must show a retry error line";
    EXPECT_FALSE(retryError->text().isEmpty());
    EXPECT_EQ(retryError->textFormat(), Qt::PlainText);
    // No attempts counter anywhere in the rendered text -- the "2" only
    // selects presence, it never appears as a number in the line itself.
    EXPECT_FALSE(retryError->text().contains(QStringLiteral("2")));
    // The raw wire msgKey must never leak into the rendered text.
    EXPECT_FALSE(retryError->text().contains(QStringLiteral("librescrs.error")));

    // Positioned immediately above the input widget: the retry label's index
    // in the dialog's top-level QVBoxLayout precedes the input widget's.
    auto* layout = qobject_cast<QVBoxLayout*>(dlg.layout());
    ASSERT_NE(layout, nullptr);
    const int errorIndex = layout->indexOf(retryError);
    ASSERT_GE(errorIndex, 0);
    // Every widget after the retry label up to the button box is the input
    // widget; simplest robust check available without exposing m_widget: the
    // retry label is not the LAST widget before the buttons (i.e. something
    // widget-shaped still follows it before QDialogButtonBox).
    ASSERT_LT(errorIndex + 1, layout->count()) << "the retry label must not be the last item in the layout";
}

TEST(PromptDialogRetryContext, UnrecognisedLastErrorKeyStillShowsAGenericLineNotTheRawKey)
{
    int argc = 1;
    const char* argv[] = {"retry-context-test"};
    QApplication app(argc, const_cast<char**>(argv));

    PromptDialog::Options opts;
    opts.attempt = 2;
    opts.lastError = QStringLiteral("some.future.msgKey.never.seen.before");
    PromptDialog dlg(PromptDialog::Kind::Mrz, opts, nullptr);

    auto* retryError = dlg.findChild<QLabel*>(QStringLiteral("retryErrorLabel"));
    ASSERT_NE(retryError, nullptr);
    EXPECT_FALSE(retryError->text().isEmpty());
    EXPECT_FALSE(retryError->text().contains(QStringLiteral("some.future.msgKey")))
        << "an unrecognised wire msgKey must never leak into the rendered text";
}
