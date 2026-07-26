// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Wire-shape pin for the module side of the agent contract. The module hand-
// declares the Certificates1.Result entry tuple (CertResultWire.h) and shares it
// with its own test fake — so the fake can never disagree with the consumer, but
// BOTH could silently drift from the agent's XML. This pins the marshalled D-Bus
// signature to the frozen a(sba{sa{s(ssv)}}uasasu); if the agent grows/reorders a
// Certificates1 field and this type is not updated in lockstep, this fails. It is
// the module-side counterpart of the agent's Certificates1XmlCodegenTest.

#include "CertResultWire.h"

#include <sdbus-c++/sdbus-c++.h>

#include <gtest/gtest.h>

#include <string>
#include <vector>

TEST(CertResultWire, ResultSignatureFrozen)
{
    // Certificates1.Result is a(<entry>); pin the whole array signature.
    constexpr auto sig = sdbus::signature_of_v<std::vector<LibreSCRS::Pkcs11Agent::CertResultEntry>>;
    const std::string actual(sig.begin(), sig.end());
    EXPECT_EQ(actual, "a(sba{sa{s(ssv)}}uasasu)")
        << "module CertResultEntry drifted from the agent's Certificates1 XML wire shape";
}
