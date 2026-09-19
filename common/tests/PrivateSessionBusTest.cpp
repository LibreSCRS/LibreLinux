// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Compiled into every test binary ctest runs on a private session bus.
//
// The bus is private because a suite that claims a well-known name must not see
// the previous suite's claim; that isolation is semantics, not decoration. It is
// arranged by a target property (CROSSCOMPILING_EMULATOR), and a property can
// stop being read: GoogleTest's discovery module consults it only while policy
// CMP0158 is unset or OLD, so the first bump of cmake_minimum_required to 3.29
// or later silently stops wrapping these binaries and they go to whatever bus
// the runner happens to be on. Nothing about the build would change, and a
// suite that then passes or fails does so for a reason that is not the code.
//
// A cmake_policy() line cannot fail. This can. ctest hands the test a sentinel
// address in both DBUS_SESSION_BUS_ADDRESS and LIBRESCRS_OUTER_BUS; the wrapper,
// when it runs, replaces the first with the address of the bus it just started.
// So the two differ exactly when the wrapper ran, and are equal — pointing at a
// socket that does not exist — when it did not.
#include <gtest/gtest.h>

#include <cstdlib>

#ifndef LIBRESCRS_PRIVATE_BUS_SUITE
#error "LIBRESCRS_PRIVATE_BUS_SUITE must name this binary's suite"
#endif

TEST(LIBRESCRS_PRIVATE_BUS_SUITE, TheAddressIsNotTheOneCtestHandedUs)
{
    const char* handedIn = std::getenv("LIBRESCRS_OUTER_BUS");
    ASSERT_NE(handedIn, nullptr) << "LIBRESCRS_OUTER_BUS is unset: the test's ENVIRONMENT property did not "
                                    "reach it, so this assertion has nothing to compare against";

    const char* mine = std::getenv("DBUS_SESSION_BUS_ADDRESS");
    ASSERT_NE(mine, nullptr) << "DBUS_SESSION_BUS_ADDRESS is unset: this binary has no session bus at all";

    EXPECT_STRNE(mine, handedIn) << "this suite is on the address ctest handed it, not on a bus of its own: "
                                    "the dbus-run-session wrapper did not run";
}
