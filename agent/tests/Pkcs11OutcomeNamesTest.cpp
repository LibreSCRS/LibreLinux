// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// The backend Outcome->wire-name mapping (dbus/Pkcs11OutcomeNames) must
// reproduce EVERY historical org.librescrs.Agent.Error.* name byte-identically —
// the wire NAME is the only contract the PKCS#11 module branches on. This pins
// each value so a future enum edit that silently drops or renames a wire name
// fails here rather than degrading a client to a generic error.
#include "dbus/Pkcs11OutcomeNames.h"
#include <LibreSCRS/Agent/pkcs11/Pkcs11Broker.h>
#include <gtest/gtest.h>

using namespace LibreSCRS::Agent;

TEST(Pkcs11OutcomeNames, CryptoOutcomeMapsToWireNames)
{
    using CO = Pkcs11Broker::CryptoOutcome;
    EXPECT_STREQ(errorNameFor(CO::UnknownCard), "org.librescrs.Agent.Error.UnknownCard");
    EXPECT_STREQ(errorNameFor(CO::KeyNotFound), "org.librescrs.Agent.Error.KeyNotFound");
    EXPECT_STREQ(errorNameFor(CO::AuthFailed), "org.librescrs.Agent.Error.AuthFailed");
    EXPECT_STREQ(errorNameFor(CO::NotSupported), "org.librescrs.Agent.Error.NotSupported");
    EXPECT_STREQ(errorNameFor(CO::UserNotLoggedIn), "org.librescrs.Agent.Error.UserNotLoggedIn");
    EXPECT_STREQ(errorNameFor(CO::RateLimited), "org.librescrs.Agent.Error.RateLimited");
    EXPECT_STREQ(errorNameFor(CO::Cancelled), "org.librescrs.Agent.Error.Cancelled");
    EXPECT_STREQ(errorNameFor(CO::CardError), "org.librescrs.Agent.Error.CommunicationError");
    // Ok is not an error; it fails closed to the device (communication) error.
    EXPECT_STREQ(errorNameFor(CO::Ok), "org.librescrs.Agent.Error.CommunicationError");
}

TEST(Pkcs11OutcomeNames, LoginOutcomeMapsToWireNames)
{
    using LO = Pkcs11Broker::LoginOutcome;
    EXPECT_STREQ(errorNameFor(LO::Cancelled), "org.librescrs.Agent.Error.Cancelled");
    EXPECT_STREQ(errorNameFor(LO::NotAuthorizedByCard), "org.librescrs.Agent.Error.AuthFailed");
    EXPECT_STREQ(errorNameFor(LO::CardError), "org.librescrs.Agent.Error.CommunicationError");
    EXPECT_STREQ(errorNameFor(LO::UnknownCard), "org.librescrs.Agent.Error.UnknownCard");
    EXPECT_STREQ(errorNameFor(LO::NotAuthorized), "org.librescrs.Agent.Error.NotAuthorized");
    // Ok fails closed to the device (communication) error.
    EXPECT_STREQ(errorNameFor(LO::Ok), "org.librescrs.Agent.Error.CommunicationError");
}
