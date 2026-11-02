// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// The org.librescrs.Agent.Error.* name each refusal reaches this bus with: the
// agent library's toSyncError, spelled by dbus/SyncErrorBusName. The wire NAME
// is the only contract the PKCS#11 module and every client branch on, so each
// value is pinned against the table they map back from (common/
// AgentErrorNames.h) -- a rename on either side fails here rather than
// degrading a client to a generic error.
#include "dbus/SyncErrorBusName.h"
#include "AgentErrorNames.h" // the names the module maps back
#include <LibreSCRS/Agent/pkcs11/Pkcs11Broker.h>
#include <LibreSCRS/Agent/value/CredentialRecord.h>
#include <LibreSCRS/Agent/value/SyncErrorTaxonomy.h>
#include <gtest/gtest.h>

using namespace LibreSCRS::Agent;
namespace wire = LibreLinux::AgentWire;

namespace {
template <typename Refusal>
std::string busName(Refusal refusal)
{
    return syncErrorBusName(toSyncError(refusal));
}
} // namespace

TEST(SyncErrorBusName, ABrokerCryptoOutcomeReachesTheBusUnderItsName)
{
    using CO = Pkcs11Broker::CryptoOutcome;
    EXPECT_EQ(busName(CO::UnknownCard), wire::kErrUnknownCard);
    EXPECT_EQ(busName(CO::KeyNotFound), wire::kErrKeyNotFound);
    EXPECT_EQ(busName(CO::AuthFailed), wire::kErrAuthFailed);
    EXPECT_EQ(busName(CO::NotSupported), wire::kErrNotSupported);
    EXPECT_EQ(busName(CO::UserNotLoggedIn), wire::kErrUserNotLoggedIn);
    EXPECT_EQ(busName(CO::RateLimited), wire::kErrRateLimited);
    EXPECT_EQ(busName(CO::Cancelled), wire::kErrCancelled);
    EXPECT_EQ(busName(CO::CardError), wire::kErrCommunication);
    // A request the key refuses before any prompt is the caller's.
    EXPECT_EQ(busName(CO::InvalidInput), wire::kErrInvalidRequest);
    // Ok is not an error; it fails closed to the device (communication) error.
    EXPECT_EQ(busName(CO::Ok), wire::kErrCommunication);
}

TEST(SyncErrorBusName, ABrokerLoginOutcomeReachesTheBusUnderItsName)
{
    using LO = Pkcs11Broker::LoginOutcome;
    EXPECT_EQ(busName(LO::Cancelled), wire::kErrCancelled);
    EXPECT_EQ(busName(LO::NotAuthorizedByCard), wire::kErrAuthFailed);
    EXPECT_EQ(busName(LO::CardError), wire::kErrCommunication);
    EXPECT_EQ(busName(LO::UnknownCard), wire::kErrUnknownCard);
    EXPECT_EQ(busName(LO::NotAuthorized), wire::kErrNotAuthorized);
    EXPECT_EQ(busName(LO::Ok), wire::kErrCommunication);
}

// Credentials1.ManagePin entry refusals: an unlisted pinId is its own name, so a
// client re-lists instead of rewriting its request; everything else -- a label
// that is not unique among them -- is the request's fault.
TEST(SyncErrorBusName, ACredentialEntryErrorReachesTheBusUnderItsName)
{
    EXPECT_EQ(busName(EntryError::UnknownCredential), wire::kErrUnknownCredential);
    for (const auto err : {EntryError::UnknownVerb, EntryError::UnknownOption, EntryError::InvalidCombination,
                           EntryError::AmbiguousCredential}) {
        EXPECT_EQ(busName(err), wire::kErrInvalidRequest) << static_cast<int>(err);
    }
}
