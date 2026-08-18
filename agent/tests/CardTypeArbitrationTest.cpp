// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Unit test for the Card1.CardType arbitration rule (CardTypeArbitration.h).
//
// The held-session candidate list is priority-ordered, and a real card
// routinely matches MORE THAN ONE plugin: the family driver plus one or both
// of the two generic PKI drivers, or -- on a card no family driver claims --
// the two generic drivers alone. The earlier rule typed the card only when the
// list held EXACTLY ONE entry, so any card that two generic drivers both
// claimed stayed permanently untyped over the bus even though the candidate
// order already named an unambiguous winner.
//
// The rule under test: the candidate with the strictly smallest probe priority
// wins ("lower numbers win", CardPlugin::probePriority). A tie at the smallest
// value is genuinely ambiguous and stays empty, because nothing in the
// candidate list distinguishes the tied plugins.
//
// Priorities used below mirror the shipped drivers so the cases are the real
// ones: family driver 100, travel-document and one generic driver 800, the
// second generic driver 900.

#include "CardTypeArbitration.h"

#include <LibreSCRS/Plugin/CardPlugin.h>

#include <gtest/gtest.h>

#include <memory>
#include <string>
#include <vector>

using LibreSCRS::Agent::arbitrateCardType;

namespace {

// Minimal CardPlugin double: identity + priority only. Arbitration reads
// nothing but pluginId() and probePriority(); the rest are the base class's
// pure virtuals, stubbed to the emptiest legal answer.
class PriorityStubPlugin final : public LibreSCRS::Plugin::CardPlugin
{
public:
    PriorityStubPlugin(std::string id, int priority)
    {
        setIdentity(std::move(id), "stub", priority);
    }
    LibreSCRS::Plugin::CardCapabilities capabilities() const override
    {
        return LibreSCRS::Plugin::CardCapabilities::PKI;
    }
    std::span<const LibreSCRS::Plugin::Atr> supportedAtrs() const noexcept override
    {
        return {};
    }

protected:
    LibreSCRS::Plugin::ReadResult doReadCard(LibreSCRS::SmartCard::CardSession& /*session*/,
                                             GroupCallback /*onGroup*/) const override
    {
        return LibreSCRS::Plugin::ReadResult::ok(LibreSCRS::Plugin::CardData{});
    }
};

using CandidateList = std::vector<std::shared_ptr<const LibreSCRS::Plugin::CardPlugin>>;

std::shared_ptr<const LibreSCRS::Plugin::CardPlugin> plugin(std::string id, int priority)
{
    return std::make_shared<const PriorityStubPlugin>(std::move(id), priority);
}

// The defect this rule fixes: a card claimed by BOTH generic PKI drivers. The
// candidate list is unambiguous (800 beats 900) but the size()==1 rule typed
// nothing, so the bus reported an empty CardType for a perfectly identified
// card and no client could dispatch on it.
TEST(CardTypeArbitration, TwoGenericCandidatesResolveToTheHigherPriorityPlugin)
{
    const CandidateList candidates{plugin("opensc", 800), plugin("pkcs15", 900)};
    EXPECT_EQ(arbitrateCardType(candidates), "opensc");
}

// Same shape, reversed input order: arbitration reads the priority value, it
// does not trust the list to be sorted. The registry sorts ATR matches and AID
// probes in two independent runs, so a lower-priority AID match CAN sit behind
// a higher-priority ATR match in the same list.
TEST(CardTypeArbitration, WinnerIsIndependentOfCandidateOrder)
{
    const CandidateList candidates{plugin("pkcs15", 900), plugin("opensc", 800)};
    EXPECT_EQ(arbitrateCardType(candidates), "opensc");
}

// A family driver ahead of both generics: the family driver names the card.
TEST(CardTypeArbitration, FamilyDriverBeatsBothGenericDrivers)
{
    const CandidateList candidates{plugin("rs-eid", 100), plugin("opensc", 800), plugin("pkcs15", 900)};
    EXPECT_EQ(arbitrateCardType(candidates), "rs-eid");
}

// Two drivers tied at the smallest priority: nothing in the list picks between
// them, so the property stays empty and a later authoritative read resolves it.
TEST(CardTypeArbitration, AmbiguousEqualPriorityStaysUnresolved)
{
    const CandidateList candidates{plugin("emrtd", 800), plugin("opensc", 800)};
    EXPECT_EQ(arbitrateCardType(candidates), "");
}

// A tie BEHIND a strict winner is not ambiguity -- the winner still wins.
TEST(CardTypeArbitration, TieBehindTheWinnerDoesNotBlockResolution)
{
    const CandidateList candidates{plugin("rs-eid", 100), plugin("emrtd", 800), plugin("opensc", 800)};
    EXPECT_EQ(arbitrateCardType(candidates), "rs-eid");
}

// Regression pin: the single-candidate case that already worked must keep
// resolving to exactly the same string it resolved to before.
TEST(CardTypeArbitration, SingleCandidateStillResolvesToItsPluginId)
{
    const CandidateList candidates{plugin("rs-eid", 100)};
    EXPECT_EQ(arbitrateCardType(candidates), "rs-eid");
}

// No candidates: "not known", the pinned empty-until-known default.
TEST(CardTypeArbitration, NoCandidatesStaysEmpty)
{
    EXPECT_EQ(arbitrateCardType(CandidateList{}), "");
}

// Null entries are skipped, never dereferenced: the candidate list is a vector
// of shared_ptr and a null slot must not decide -- nor crash -- the arbitration.
TEST(CardTypeArbitration, NullCandidatesAreIgnored)
{
    EXPECT_EQ(arbitrateCardType(CandidateList{nullptr}), "");
    EXPECT_EQ(arbitrateCardType(CandidateList{nullptr, plugin("pkcs15", 900)}), "pkcs15");
    EXPECT_EQ(arbitrateCardType(CandidateList{plugin("opensc", 800), nullptr}), "opensc");
}

} // namespace
