// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Exercises PrompterService::CancelCurrent against an in-process prompter.
// Runs offscreen (QT_QPA_PLATFORM=offscreen) so no display is required.
//
// The "names no live prompt" path is the documented no-op: a dismissal that
// races past the dialog it meant (or arrives at an idle prompter, or names an
// id nothing answers to) must complete silently with no side-effect and no
// crash. This pins that contract.

#include "PrompterService.h"

#include <QApplication>

#include <gtest/gtest.h>

#include <string>

TEST(PrompterCancel, CancelNamingNoLivePromptIsNoop)
{
    int argc = 1;
    const char* argv[] = {"prompter-test"};
    QApplication app(argc, const_cast<char**>(argv));
    // Direct call (no D-Bus) — verify the method is callable + idempotent
    // against an idle prompter. Calling it again must also be safe.
    LibreLinux::Prompter::PrompterService::cancelForTest("nonce:1");
    LibreLinux::Prompter::PrompterService::cancelForTest("nonce:1");
    // An id nothing answers to is equally inert.
    LibreLinux::Prompter::PrompterService::cancelForTest("");
    SUCCEED();
}
