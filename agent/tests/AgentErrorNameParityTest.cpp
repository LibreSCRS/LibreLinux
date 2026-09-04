// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// The D-Bus error-name table in common/AgentErrorNames.h and the agent wire's
// own SyncError vocabulary are two spellings of one set of refusals. Moving
// the backend onto the wire's spelling would mean the Qt-free PKCS#11 module
// linking LibreAgent::Wire — and qcbor with it — for the sake of twelve
// strings. So the table stays where it is, and this pins it instead.
//
// A drift here is not cosmetic: the module maps these names back to a Status,
// and a name that stops matching degrades silently to the generic error.
#include "AgentErrorNames.h"

#include <LibreSCRS/Agent/wire/SyncError.h>

#include <gtest/gtest.h>

#include <string>
#include <string_view>

namespace {

using LibreSCRS::Agent::Wire::SyncError;
using LibreSCRS::Agent::Wire::syncErrorName;

constexpr std::string_view kPrefix = "org.librescrs.Agent.Error.";

std::string qualified(SyncError e)
{
    return std::string(kPrefix) + std::string(syncErrorName(e));
}

} // namespace

// Each constant, against the wire name of the enumerator it means. Spelled out
// pair by pair rather than generated from either side: a table built from one
// of the two would agree with that one no matter what it said.
TEST(AgentErrorNameParityTest, EveryNameMatchesItsWireEnumerator)
{
    EXPECT_EQ(LibreLinux::AgentWire::kErrUnknownCard, qualified(SyncError::UnknownCard));
    EXPECT_EQ(LibreLinux::AgentWire::kErrKeyNotFound, qualified(SyncError::KeyNotFound));
    EXPECT_EQ(LibreLinux::AgentWire::kErrNotAuthorized, qualified(SyncError::NotAuthorized));
    EXPECT_EQ(LibreLinux::AgentWire::kErrRateLimited, qualified(SyncError::RateLimited));
    EXPECT_EQ(LibreLinux::AgentWire::kErrUserNotLoggedIn, qualified(SyncError::UserNotLoggedIn));
    EXPECT_EQ(LibreLinux::AgentWire::kErrAuthFailed, qualified(SyncError::AuthFailed));
    EXPECT_EQ(LibreLinux::AgentWire::kErrNotSupported, qualified(SyncError::NotSupported));
    EXPECT_EQ(LibreLinux::AgentWire::kErrCommunication, qualified(SyncError::CommunicationError));
    EXPECT_EQ(LibreLinux::AgentWire::kErrUnsupportedOnThisCard, qualified(SyncError::UnsupportedOnThisCard));
    EXPECT_EQ(LibreLinux::AgentWire::kErrInvalidRequest, qualified(SyncError::InvalidRequest));
    EXPECT_EQ(LibreLinux::AgentWire::kErrUnknownCredential, qualified(SyncError::UnknownCredential));
}

// The one name in the table with no counterpart, pinned as such.
//
// The bus vocabulary carries a Cancelled refusal; the wire vocabulary does
// not, and a caller on the wire learns of a cancellation another way. That
// asymmetry is a fact about the two contracts, not an oversight in this table
// — but it is exactly the kind of fact that gets "tidied" by someone adding
// the enumerator and assuming the name already matched. If SyncError ever
// gains Cancelled, this test fails and the pair above gains a line.
TEST(AgentErrorNameParityTest, CancelledHasNoWireEnumeratorAndThatIsDeliberate)
{
    const std::string cancelled = std::string(kPrefix) + "Cancelled";
    EXPECT_EQ(LibreLinux::AgentWire::kErrCancelled, cancelled);

    for (int raw = 0; raw <= static_cast<int>(SyncError::MasterListReplayed); ++raw) {
        EXPECT_NE(qualified(static_cast<SyncError>(raw)), cancelled)
            << "SyncError gained a Cancelled enumerator; pair it above and delete this loop";
    }
}

// The table is a SUBSET of the wire vocabulary, never a superset of what the
// producer can raise. Counted so that a constant added here without a wire
// name is loud.
TEST(AgentErrorNameParityTest, TheTableIsASubsetOfTheWireVocabulary)
{
    int matched = 0;
    for (int raw = 0; raw <= static_cast<int>(SyncError::MasterListReplayed); ++raw) {
        const std::string name = qualified(static_cast<SyncError>(raw));
        for (const char* constant :
             {LibreLinux::AgentWire::kErrUnknownCard, LibreLinux::AgentWire::kErrKeyNotFound,
              LibreLinux::AgentWire::kErrNotAuthorized, LibreLinux::AgentWire::kErrRateLimited,
              LibreLinux::AgentWire::kErrUserNotLoggedIn, LibreLinux::AgentWire::kErrAuthFailed,
              LibreLinux::AgentWire::kErrNotSupported, LibreLinux::AgentWire::kErrCommunication,
              LibreLinux::AgentWire::kErrUnsupportedOnThisCard, LibreLinux::AgentWire::kErrInvalidRequest,
              LibreLinux::AgentWire::kErrUnknownCredential}) {
            if (name == constant) {
                ++matched;
            }
        }
    }
    EXPECT_EQ(matched, 11) << "a name in the table stopped matching a wire enumerator";
}
