// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Exercises PrompterService::CancelCurrent against an in-process prompter.
// Runs offscreen (QT_QPA_PLATFORM=offscreen) so no display is required.
//
// The "no active dialog" path is the documented no-op: a CancelCurrent that
// races past every active prompter dialog (or arrives at an idle prompter)
// must complete silently with no side-effect and no crash. This pins that
// contract.

#include "PrompterService.h"

#include <QApplication>

#include <gtest/gtest.h>

TEST(PrompterCancel, CancelCurrentWithNoActiveDialogIsNoop)
{
    int argc = 1;
    const char* argv[] = {"prompter-test"};
    QApplication app(argc, const_cast<char**>(argv));
    // Direct call (no D-Bus) — verify the method is callable + idempotent
    // against an idle prompter. Calling it again must also be safe.
    LibreLinux::Prompter::PrompterService::cancelCurrentForTest();
    LibreLinux::Prompter::PrompterService::cancelCurrentForTest();
    SUCCEED();
}
