// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// The prompter is a long-lived user unit and survives an agent restart
// (measured: one had been running since the previous night and outlived the
// agent), so a new agent routinely meets an older helper. A helper that does not
// understand a dismissal by name loses every cancellation silently and leaves
// windows hanging -- the exact defect this work removes, returning through a
// mismatched pair. These pin the refusal.

#include "PrompterCapability.h"

#include <gtest/gtest.h>

#include <optional>

using LibreSCRS::Agent::PrompterCapability::kRequiredVersion;
using LibreSCRS::Agent::PrompterCapability::usable;

TEST(PrompterCapability, AHelperThatPublishesNoVersionIsRefused)
{
    // What an older helper looks like from here: the property does not exist,
    // so the read fails and nothing is reported.
    EXPECT_FALSE(usable(std::nullopt));
}

TEST(PrompterCapability, AHelperOnThisContractIsAccepted)
{
    EXPECT_TRUE(usable(kRequiredVersion));
}

TEST(PrompterCapability, AnOlderContractIsRefused)
{
    EXPECT_FALSE(usable(kRequiredVersion - 1));
    EXPECT_FALSE(usable(0));
}

TEST(PrompterCapability, ANewerContractIsAccepted)
{
    // The agent uses only what it knows about. Refusing forward would strand a
    // session on the older half of an upgrade for no benefit.
    EXPECT_TRUE(usable(kRequiredVersion + 1));
    EXPECT_TRUE(usable(kRequiredVersion + 100));
}

// The refusal is a decision about a version, so it must be evaluable without a
// bus -- which is what makes the case above testable at all.
static_assert(usable(kRequiredVersion));
static_assert(!usable(std::nullopt));
