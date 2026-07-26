// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Unit coverage for the Linux caller-identity resolver: the best-effort,
// pidfd-pinned live resolution of a PID to a display label against this test
// process. The pure label-shaping helpers (basename extraction + untrusted-
// text sanitisation) are the platform-neutral core's (util/CallerLabel.h) and
// are covered by the core's CallerLabelTest.

#include "CallerIdentity.h"

#include <gtest/gtest.h>
#include <unistd.h> // getpid

#include <string>

using LibreSCRS::Agent::CallerIdentity;

TEST(CallerIdentity, ResolveRequesterLabelForSelfYieldsTestBinary)
{
    // Live, best-effort path against our own PID — must resolve to a non-empty
    // label (this test binary's basename) without throwing. PID-reuse pinning
    // succeeds because the process (us) is alive for the whole call.
    const std::string label = CallerIdentity::resolveRequesterLabel(::getpid());
    EXPECT_FALSE(label.empty());
}

TEST(CallerIdentity, ResolveRequesterLabelEmptyForInvalidPid)
{
    EXPECT_TRUE(CallerIdentity::resolveRequesterLabel(0).empty());
    EXPECT_TRUE(CallerIdentity::resolveRequesterLabel(-1).empty());
}
