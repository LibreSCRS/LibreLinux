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

using LibreSCRS::Agent::Wire::decodeSyncError;
using LibreSCRS::Agent::Wire::SyncError;
using LibreSCRS::Agent::Wire::syncErrorName;

constexpr std::string_view kPrefix = "org.librescrs.Agent.Error.";

std::string qualified(SyncError e)
{
    return std::string(kPrefix) + std::string(syncErrorName(e));
}

// How many enumerators the wire vocabulary has, measured rather than named.
//
// The walk below used to stop at a hard-coded last enumerator, and that made
// this file blind to precisely what it exists to catch: a name appended AFTER
// that one fell outside the walk, so the case that was supposed to notice an
// append stayed green through one. The edge is derived instead --
// syncErrorName() answers a value past the end with its unreachable fallback,
// which does not round-trip back to the value asked about, and that is the
// boundary. The enum's storage is uint8_t, so every probe below is a
// representable value.
int syncErrorCount()
{
    int n = 0;
    while (n < 256) {
        const auto e = static_cast<SyncError>(n);
        if (decodeSyncError(syncErrorName(e)) != e) {
            break;
        }
        ++n;
    }
    return n;
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
    EXPECT_EQ(LibreLinux::AgentWire::kErrCancelled, qualified(SyncError::Cancelled));
}

// The table used to carry exactly one name the wire vocabulary had no
// enumerator for, and a case here pinned that asymmetry so nobody would tidy it
// away by adding the enumerator and assuming the name already matched. The
// enumerator has now been added deliberately, so the claim is inverted: the
// name is carried by BOTH vocabularies, and the two transports can be held to
// one answer about a dismissed prompt.
//
// The round trip is asserted as well as the spelling. A token the decoder does
// not recognise degrades silently to CommunicationError rather than failing, so
// a name that matched by spelling alone would still reach a caller as the
// generic failure this pairing exists to stop it being.
TEST(AgentErrorNameParityTest, CancelledIsCarriedByBothVocabularies)
{
    const std::string cancelled = std::string(kPrefix) + "Cancelled";
    EXPECT_EQ(LibreLinux::AgentWire::kErrCancelled, cancelled);
    EXPECT_EQ(qualified(SyncError::Cancelled), cancelled);
    EXPECT_EQ(decodeSyncError("Cancelled"), SyncError::Cancelled)
        << "the wire decoder degrades this token instead of recognising it";
}

// The table is a SUBSET of the wire vocabulary, never a superset of what the
// producer can raise. Counted so that a constant added here without a wire
// name is loud.
TEST(AgentErrorNameParityTest, TheTableIsASubsetOfTheWireVocabulary)
{
    int matched = 0;
    for (int raw = 0; raw < syncErrorCount(); ++raw) {
        const std::string name = qualified(static_cast<SyncError>(raw));
        for (const char* constant :
             {LibreLinux::AgentWire::kErrUnknownCard, LibreLinux::AgentWire::kErrKeyNotFound,
              LibreLinux::AgentWire::kErrNotAuthorized, LibreLinux::AgentWire::kErrRateLimited,
              LibreLinux::AgentWire::kErrUserNotLoggedIn, LibreLinux::AgentWire::kErrAuthFailed,
              LibreLinux::AgentWire::kErrNotSupported, LibreLinux::AgentWire::kErrCommunication,
              LibreLinux::AgentWire::kErrUnsupportedOnThisCard, LibreLinux::AgentWire::kErrInvalidRequest,
              LibreLinux::AgentWire::kErrUnknownCredential, LibreLinux::AgentWire::kErrCancelled}) {
            if (name == constant) {
                ++matched;
            }
        }
    }
    EXPECT_EQ(matched, 12) << "a name in the table stopped matching a wire enumerator";
}
