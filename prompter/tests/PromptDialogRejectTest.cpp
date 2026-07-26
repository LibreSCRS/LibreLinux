// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Pins the reject-from-outside affordance PrompterService::CancelCurrent
// relies on. Two checks:
//   1. The slot-availability regression: reject() must remain reachable by
//      name through Qt's meta-object system. A future PromptDialog override
//      that hides the QDialog slot would silently break the cancel path;
//      this test catches it at build time.
//   2. The behaviour regression: an externally-fired reject (via the same
//      QueuedConnection dispatch CancelCurrent uses) closes the dialog with
//      QDialog::Rejected.
//
// Runs under QT_QPA_PLATFORM=offscreen so no display server is required.

#include "PromptDialog.h"

#include <QApplication>
#include <QDialog>
#include <QMetaObject>
#include <QTimer>

#include <gtest/gtest.h>

using LibreLinux::Prompter::PromptDialog;

TEST(PromptDialogReject, ExternalRejectIsAvailableAsSlot)
{
    int argc = 1;
    const char* argv[] = {"dialog-test"};
    QApplication app(argc, const_cast<char**>(argv));
    PromptDialog dlg(PromptDialog::Kind::Pin, PromptDialog::Options{}, nullptr);
    const int methodIdx = dlg.metaObject()->indexOfSlot("reject()");
    ASSERT_NE(methodIdx, -1) << "reject() must remain a slot the QueuedConnection cancel path can invoke";
}

TEST(PromptDialogReject, ExternalRejectViaQueuedConnectionClosesDialog)
{
    int argc = 1;
    const char* argv[] = {"dialog-test"};
    QApplication app(argc, const_cast<char**>(argv));
    PromptDialog dlg(PromptDialog::Kind::Pin, PromptDialog::Options{}, nullptr);
    // After a brief event-loop quiescence, fire reject via queued invocation
    // — the same dispatch shape PrompterService::CancelCurrent uses.
    QTimer::singleShot(100, &dlg, [&dlg] { QMetaObject::invokeMethod(&dlg, "reject", Qt::QueuedConnection); });
    const int code = dlg.exec();
    EXPECT_EQ(code, QDialog::Rejected);
}
