// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Unit test for the backend's ObjectId <-> D-Bus object-path bijection
// (AgentObjectPath.h). Focus: objectIdFromPath must recover exactly what
// agentObjectPath composed, and must fail closed to an INVALID ObjectId{} for
// anything it did not compose — in particular a numeric tail that overflows
// uint64 (the pre-hardening value*10+digit accumulation silently WRAPPED to a
// valid-looking but wrong id).

#include "AgentObjectPath.h"

#include <gtest/gtest.h>

#include <cstdint>
#include <string>

using LibreSCRS::Agent::agentObjectPath;
using LibreSCRS::Agent::ObjectId;
using LibreSCRS::Agent::objectIdFromPath;

namespace {

TEST(AgentObjectPath, RoundTripsComposedIds)
{
    for (std::uint64_t v : {std::uint64_t{1}, std::uint64_t{2}, std::uint64_t{42}, std::uint64_t{1000000},
                            std::uint64_t{18446744073709551615ULL /* UINT64_MAX boundary */}}) {
        const auto reader = objectIdFromPath(agentObjectPath("reader", ObjectId{v}));
        const auto card = objectIdFromPath(agentObjectPath("card", ObjectId{v}));
        EXPECT_TRUE(reader.valid());
        EXPECT_EQ(reader.value(), v);
        EXPECT_TRUE(card.valid());
        EXPECT_EQ(card.value(), v);
    }
}

TEST(AgentObjectPath, OverflowingTailIsRejectedNotWrapped)
{
    // 26 nines: far beyond UINT64_MAX (20 digits). The old accumulation wrapped
    // this to some in-range value and returned a bogus-but-"valid" ObjectId; the
    // std::from_chars parse reports result_out_of_range -> invalid ObjectId{}.
    EXPECT_FALSE(objectIdFromPath("/org/librescrs/Agent/reader/99999999999999999999999999").valid());
    // One past UINT64_MAX (…615 -> …616).
    EXPECT_FALSE(objectIdFromPath("/org/librescrs/Agent/reader/18446744073709551616").valid());
}

TEST(AgentObjectPath, NonNumericOrJunkTailIsRejected)
{
    EXPECT_FALSE(objectIdFromPath("/org/librescrs/Agent/reader/abc").valid());
    EXPECT_FALSE(objectIdFromPath("/org/librescrs/Agent/reader/12x").valid());  // trailing junk after digits
    EXPECT_FALSE(objectIdFromPath("/org/librescrs/Agent/reader/0x1f").valid()); // hex prefix is not a base-10 tail
    EXPECT_FALSE(objectIdFromPath("/org/librescrs/Agent/reader/-5").valid());   // sign not valid for unsigned tail
    EXPECT_FALSE(objectIdFromPath("/org/librescrs/Agent/reader/+5").valid());
    EXPECT_FALSE(objectIdFromPath("/org/librescrs/Agent/reader/ 5").valid()); // leading space is not a digit
}

TEST(AgentObjectPath, MissingOrEmptyTailIsRejected)
{
    EXPECT_FALSE(objectIdFromPath("/org/librescrs/Agent/reader/").valid()); // empty tail after the slash
    EXPECT_FALSE(objectIdFromPath("/").valid());
    EXPECT_FALSE(objectIdFromPath("noslash").valid());
    EXPECT_FALSE(objectIdFromPath("").valid());
}

} // namespace
