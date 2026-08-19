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

// --- addressing ------------------------------------------------------------
//
// The id counterpart of the ownership gate, unit-tested for the same reason it
// was factored out: dismissing the wrong window is invisible in a bus test that
// only ever has one dialog, and is exactly the failure this replaces.

TEST(PrompterCancel, ADismissalMatchingTheLivePromptIsAccepted)
{
    EXPECT_TRUE(LibreLinux::Prompter::PrompterService::isNamedPrompt("nonce:7", "nonce:7"));
}

TEST(PrompterCancel, ADismissalNamingADifferentPromptIsRefused)
{
    EXPECT_FALSE(LibreLinux::Prompter::PrompterService::isNamedPrompt("nonce:7", "nonce:8"));
}

TEST(PrompterCancel, AnUnaddressablePromptIsNeverDismissedByName)
{
    // A caller that sent no id left nothing to distinguish its window from any
    // other; refusing is correct, and a prompt in that state is what the
    // capability guard exists to stop being raised at all.
    EXPECT_FALSE(LibreLinux::Prompter::PrompterService::isNamedPrompt("", ""));
    EXPECT_FALSE(LibreLinux::Prompter::PrompterService::isNamedPrompt("", "nonce:7"));
}
