// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// The host's half of "which reader is this dialog for": the card object path is
// minted here, so only this side can invert it to a reader. The LABELLING is the
// agent core's (readerIdentities) and stays there; this seam only does the
// lookup, and these tests drive the same function production does.

#include "AgentCoreSeams.h"

#include <gtest/gtest.h>

#include <string>
#include <vector>

using LibreSCRS::Agent::BusExporter;
using LibreSCRS::Agent::identityForCardIn;
using LibreSCRS::Agent::ReaderIdentity;
using LibreSCRS::Agent::ReaderInterface;

namespace {

// The three names as pcsc-lite reports them on the owner's desk. The two
// OMNIKEY slots SHARE a serial: only the bracketed product string and the slot
// number separate them, which is what a naive shortening collapses into two
// identical dialogs.
BusExporter::PresenceRoster deskRoster()
{
    BusExporter::PresenceRoster roster;
    roster.readerNames = {
        "Gemalto PC Twin Reader (69988A87) 02 00",
        "HID Global OMNIKEY 5422 Smartcard Reader [OMNIKEY 5422 Smartcard Reader] (IM0O2C00NF10456904) 01 00",
        "HID Global OMNIKEY 5422 Smartcard Reader [OMNIKEY 5422CL Smartcard Reader] (IM0O2C00NF10456904) 00 00"};
    roster.cardPaths = {"/org/librescrs/Card/1", "", "/org/librescrs/Card/3"};
    return roster;
}

} // namespace

TEST(ReaderIdentitySeam, ResolvesTheSlotThatActuallyHoldsTheCard)
{
    const auto roster = deskRoster();

    const ReaderIdentity contactless = identityForCardIn(roster, "/org/librescrs/Card/3");
    const ReaderIdentity gemalto = identityForCardIn(roster, "/org/librescrs/Card/1");

    EXPECT_EQ(contactless.full, roster.readerNames[2]);
    EXPECT_EQ(gemalto.full, roster.readerNames[0]);
    EXPECT_NE(contactless.model, gemalto.model);
}

TEST(ReaderIdentitySeam, DistinguishesTheTwoSlotsOfADualInterfaceUnit)
{
    // Requires the whole roster: whether a unit is dual-interface is only
    // decidable across the set, which is why the derivation takes the list.
    const auto roster = deskRoster();

    const ReaderIdentity contactless = identityForCardIn(roster, "/org/librescrs/Card/3");

    EXPECT_EQ(contactless.iface, ReaderInterface::Contactless);
    EXPECT_FALSE(contactless.model.empty());
}

TEST(ReaderIdentitySeam, AnUnknownCardKeyResolvesToAnEmptyIdentity)
{
    EXPECT_EQ(identityForCardIn(deskRoster(), "/org/librescrs/Card/9"), ReaderIdentity{});
}

TEST(ReaderIdentitySeam, AnEmptyCardKeyNeverMatchesAReaderHoldingNoCard)
{
    // A reader with no card carries an empty card path in the snapshot. An empty
    // key must not match it, or every unresolvable prompt would be labelled with
    // whichever empty reader happened to come first.
    EXPECT_EQ(identityForCardIn(deskRoster(), ""), ReaderIdentity{});
}
