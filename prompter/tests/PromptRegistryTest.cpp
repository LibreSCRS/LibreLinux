// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// The prompter used to keep ONE dialog slot, so "dismiss the current modal" was
// the only thing it could mean. With more than one credential window on screen
// that dismisses another reader's dialog. These pin the addressing rules the
// registry replaces it with -- pure, no bus, no display.

#include "PromptRegistry.h"

#include <gtest/gtest.h>

#include <string>

using LibreLinux::Prompter::PromptDialog;
using LibreLinux::Prompter::PromptRegistry;

namespace {

// The registry never dereferences the window; these stand in for two distinct
// dialogs without needing a Qt application.
PromptDialog* windowA()
{
    return reinterpret_cast<PromptDialog*>(0x1);
}
PromptDialog* windowB()
{
    return reinterpret_cast<PromptDialog*>(0x2);
}

} // namespace

TEST(PromptRegistry, HoldsTwoWindowsAtOnce)
{
    PromptRegistry registry;
    ASSERT_TRUE(registry.add(windowA(), 4242, "nonce:1").has_value());
    ASSERT_TRUE(registry.add(windowB(), 4242, "nonce:2").has_value());
    EXPECT_EQ(registry.size(), 2u);
}

TEST(PromptRegistry, ADismissalReachesTheWindowItNamesAndNoOther)
{
    PromptRegistry registry;
    const auto a = registry.add(windowA(), 4242, "nonce:1");
    const auto b = registry.add(windowB(), 4242, "nonce:2");
    ASSERT_TRUE(a.has_value());
    ASSERT_TRUE(b.has_value());

    const auto found = registry.findByPromptId("nonce:2");
    ASSERT_TRUE(found.has_value());
    EXPECT_EQ(*found, *b);
    ASSERT_TRUE(registry.find(*found).has_value());
    EXPECT_EQ(registry.find(*found)->window, windowB());
}

TEST(PromptRegistry, TakingOneWindowLeavesTheOtherStanding)
{
    PromptRegistry registry;
    const auto a = registry.add(windowA(), 4242, "nonce:1");
    const auto b = registry.add(windowB(), 4242, "nonce:2");
    ASSERT_TRUE(a.has_value() && b.has_value());

    const auto taken = registry.take(*a);
    ASSERT_TRUE(taken.has_value());
    EXPECT_EQ(taken->window, windowA());
    EXPECT_EQ(registry.size(), 1u);
    EXPECT_FALSE(registry.findByPromptId("nonce:1").has_value());
    ASSERT_TRUE(registry.findByPromptId("nonce:2").has_value());
}

TEST(PromptRegistry, ExactlyOneCallerEverAnswersAPrompt)
{
    // The reply and the fd belong to whoever takes the entry. A second take
    // must find nothing, or a window could be answered twice and its descriptor
    // handed out twice.
    PromptRegistry registry;
    const auto a = registry.add(windowA(), 4242, "nonce:1");
    ASSERT_TRUE(a.has_value());
    EXPECT_TRUE(registry.take(*a).has_value());
    EXPECT_FALSE(registry.take(*a).has_value());
}

TEST(PromptRegistry, RemembersWhoRaisedEachWindow)
{
    // Today's "only the caller that raised this prompt may dismiss it" gate has
    // to survive PER WINDOW rather than globally.
    PromptRegistry registry;
    const auto a = registry.add(windowA(), 4242, "nonce:1");
    const auto b = registry.add(windowB(), 4243, "nonce:2");
    ASSERT_TRUE(a.has_value() && b.has_value());
    EXPECT_EQ(registry.find(*a)->ownerPid, 4242);
    EXPECT_EQ(registry.find(*b)->ownerPid, 4243);
}

TEST(PromptRegistry, TwoWindowsMayNotAnswerToOneName)
{
    // Ambiguity is the defect being removed, so it is refused at the door
    // rather than resolved by a guess later.
    PromptRegistry registry;
    ASSERT_TRUE(registry.add(windowA(), 4242, "nonce:1").has_value());
    EXPECT_FALSE(registry.add(windowB(), 4242, "nonce:1").has_value());
    EXPECT_EQ(registry.size(), 1u);
}

TEST(PromptRegistry, AnUnaddressableWindowIsOwnedButUnreachableByName)
{
    // A caller that sent no id still gets a window that is answered and cleaned
    // up; it simply cannot be dismissed by name, and several of them do not
    // collide with each other.
    PromptRegistry registry;
    const auto a = registry.add(windowA(), 4242, "");
    const auto b = registry.add(windowB(), 4242, "");
    ASSERT_TRUE(a.has_value());
    ASSERT_TRUE(b.has_value());
    EXPECT_NE(*a, *b);
    EXPECT_EQ(registry.size(), 2u);
    EXPECT_FALSE(registry.findByPromptId("").has_value());
}

TEST(PromptRegistry, AnUnknownNameDismissesNothing)
{
    PromptRegistry registry;
    ASSERT_TRUE(registry.add(windowA(), 4242, "nonce:1").has_value());
    EXPECT_FALSE(registry.findByPromptId("nonce:9").has_value());
    EXPECT_EQ(registry.size(), 1u);
}

TEST(PromptRegistry, EveryLiveWindowIsReachableForAWholeRegistrySweep)
{
    // An orphan's owner is a process that no longer exists, so the startup sweep
    // cannot go by owner -- it needs every handle.
    PromptRegistry registry;
    const auto a = registry.add(windowA(), 4242, "nonce:1");
    const auto b = registry.add(windowB(), 9999, "");
    ASSERT_TRUE(a.has_value() && b.has_value());

    const auto all = registry.handles();
    ASSERT_EQ(all.size(), 2u);
    EXPECT_EQ(all[0], *a);
    EXPECT_EQ(all[1], *b);
}
