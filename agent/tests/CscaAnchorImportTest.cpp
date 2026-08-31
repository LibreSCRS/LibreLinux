// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// The country-signing anchor import, away from D-Bus: what the agent believes
// after each import, and which of them it refuses.
//
// The two properties this file exists for:
//
//   * TRUST ON FIRST IMPORT, THEN PIN. Nothing can be chained to before the
//     first list arrives — a master list is what supplies anchors — so the
//     first accepted list establishes the signer, and every later one has to
//     be that signer or descend from an authority the PREVIOUS list carried.
//     The anchors a rotation is judged against come from the list already
//     trusted, never from the list being imported; a check against the
//     incoming list's own contents proves internal consistency and nothing
//     about authenticity. RotationJudgedAgainstThePreviouslyTrustedAnchors is
//     the test that fails if that is ever inverted.
//   * A LINK CERTIFICATE IS AN ANCHOR. See LinkCertificateSurvivesImport.
//   * A LIST MAY NOT BE ROLLED BACK. See the replay section at the foot of this
//     file, which has a case for each cell of the rule's table.

#include "SyntheticMasterList.h"
#include "trust/CscaAnchorImport.h"

#include <LibreSCRS/Plugin/CardPluginService.h>

#include <gtest/gtest.h>

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>

namespace fs = std::filesystem;
using namespace LibreSCRS::Agent;
using LibreSCRS::Agent::Test::makeCsca;
using LibreSCRS::Agent::Test::makeIndependentSigner;
using LibreSCRS::Agent::Test::makeLinkCertificate;
using LibreSCRS::Agent::Test::makeSignedNonMasterList;
using LibreSCRS::Agent::Test::makeSignerIssuedBy;
using LibreSCRS::Agent::Test::signMasterList;
using LibreSCRS::Agent::Test::signMasterListDated;
using LibreSCRS::Agent::Test::tamperWithSignedContent;

namespace {

constexpr std::int64_t kNow = 1'790'000'000;

// Two instants a publisher might have signed at, an hour apart. Deliberately
// unrelated to kNow: when a list was signed and when this agent took it in are
// different facts, and a test that let them share a value could not tell an
// implementation that confused them apart.
constexpr std::int64_t kSignedEarlier = 1'700'000'000;
constexpr std::int64_t kSignedLater = 1'700'003'600;

// A cache directory of its own per test, removed on the way in and out.
class CacheDir
{
public:
    explicit CacheDir(const char* tag) : m_path(fs::temp_directory_path() / (std::string{"ll-csca-"} + tag))
    {
        fs::remove_all(m_path);
    }
    ~CacheDir()
    {
        fs::remove_all(m_path);
    }
    CacheDir(const CacheDir&) = delete;
    CacheDir& operator=(const CacheDir&) = delete;

    [[nodiscard]] const fs::path& path() const
    {
        return m_path;
    }

private:
    fs::path m_path;
};

bool holds(const std::vector<std::vector<std::uint8_t>>& haystack, const std::vector<std::uint8_t>& needle)
{
    return std::find(haystack.begin(), haystack.end(), needle) != haystack.end();
}

} // namespace

// --- trust on first import -------------------------------------------------

TEST(CscaAnchorImport, FirstImportEstablishesTheSigner)
{
    const CacheDir dir("first-import");
    Trust::AnchorCache cache(dir.path());
    ASSERT_FALSE(cache.state().present) << "an untouched cache must believe nothing";

    const auto list = signMasterList({makeCsca("CSCA A", "AA"), makeCsca("CSCA B", "BB")}, makeIndependentSigner());
    const auto accepted = Trust::importMasterList(list.der, cache, kNow);

    ASSERT_TRUE(accepted.has_value()) << "the first list is trusted on import";
    EXPECT_EQ(accepted->signer, list.signerSpkiSha256);
    EXPECT_EQ(accepted->anchorCount, 2u);
    EXPECT_EQ(accepted->issuerCount, 2u);
    EXPECT_EQ(accepted->acceptedAt, kNow);

    // The pin survives into the cache, and so do the anchors themselves.
    const Trust::AnchorState stored = cache.state();
    EXPECT_TRUE(stored.present);
    EXPECT_EQ(stored.signer, list.signerSpkiSha256);
    const auto anchors = cache.anchors();
    ASSERT_EQ(anchors.size(), 2u);
    for (const auto& a : list.anchors) {
        EXPECT_TRUE(holds(anchors, a)) << "an anchor the list carried is missing from the cache";
    }
}

TEST(CscaAnchorImport, SameSignerReimportsSilently)
{
    const CacheDir dir("same-signer");
    Trust::AnchorCache cache(dir.path());

    const auto signer = makeIndependentSigner();
    const auto first = signMasterList({makeCsca("CSCA A", "AA")}, signer);
    ASSERT_TRUE(Trust::importMasterList(first.der, cache, kNow).has_value());

    // The same publisher, a wider list. Nothing is asked of the caller.
    const auto second = signMasterList({makeCsca("CSCA B", "BB"), makeCsca("CSCA C", "CC")}, signer);
    const auto accepted = Trust::importMasterList(second.der, cache, kNow + 60);

    ASSERT_TRUE(accepted.has_value());
    EXPECT_EQ(accepted->signer, first.signerSpkiSha256) << "the same key signed both";
    EXPECT_EQ(accepted->anchorCount, 2u);
    // The import REPLACES the anchor set rather than merging into it.
    const auto anchors = cache.anchors();
    ASSERT_EQ(anchors.size(), 2u);
    EXPECT_FALSE(holds(anchors, first.anchors.front())) << "the previous anchor set was not replaced";
}

TEST(CscaAnchorImport, UnknownSignerIsRefusedAndAnchorsAreUntouched)
{
    const CacheDir dir("unknown-signer");
    Trust::AnchorCache cache(dir.path());

    const auto first = signMasterList({makeCsca("CSCA A", "AA")}, makeIndependentSigner());
    ASSERT_TRUE(Trust::importMasterList(first.der, cache, kNow).has_value());

    // A different publisher, chaining to nothing the agent holds. A lawful
    // rotation and an attack look identical from here, so this is refused.
    const auto stranger = signMasterList({makeCsca("CSCA X", "XX")}, makeIndependentSigner());
    const auto refused = Trust::importMasterList(stranger.der, cache, kNow + 60);

    ASSERT_FALSE(refused.has_value());
    EXPECT_EQ(refused.error().reason, Trust::ImportRefusal::SignerChanged);
    // BOTH fingerprints come back, because that is what a person needs shown.
    ASSERT_TRUE(refused.error().seenSigner.has_value());
    ASSERT_TRUE(refused.error().trustedSigner.has_value());
    EXPECT_EQ(*refused.error().seenSigner, stranger.signerSpkiSha256);
    EXPECT_EQ(*refused.error().trustedSigner, first.signerSpkiSha256);

    // A refused import changes nothing.
    EXPECT_EQ(cache.state().signer, first.signerSpkiSha256);
    const auto anchors = cache.anchors();
    ASSERT_EQ(anchors.size(), 1u);
    EXPECT_TRUE(holds(anchors, first.anchors.front()));
}

TEST(CscaAnchorImport, RotatedSignerIsAcceptedWhenItChainsToTheTrustedAnchors)
{
    const CacheDir dir("rotation-ok");
    Trust::AnchorCache cache(dir.path());

    const auto anchorA = makeCsca("CSCA A", "AA");
    const auto first = signMasterList({anchorA, makeCsca("CSCA B", "BB")}, makeIndependentSigner());
    ASSERT_TRUE(Trust::importMasterList(first.der, cache, kNow).has_value());

    // The publisher rotated its key. The new signer was issued by CSCA A, which
    // the list already trusted carried, so no person has to compare
    // fingerprints out of band.
    const auto rotated = makeSignerIssuedBy(anchorA);
    const auto second = signMasterList({anchorA, makeCsca("CSCA C", "CC")}, rotated);
    const auto accepted = Trust::importMasterList(second.der, cache, kNow + 60);

    ASSERT_TRUE(accepted.has_value()) << "a signer descending from a trusted anchor is followed automatically";
    EXPECT_EQ(accepted->signer, second.signerSpkiSha256) << "the pin moves to the new key";
    EXPECT_EQ(cache.state().signer, second.signerSpkiSha256);
    // The rotation was JUDGED — against anchors the agent already held — rather
    // than merely observed, so it is not a trust-on-first-import.
    EXPECT_TRUE(accepted->signerPinned);
}

TEST(CscaAnchorImport, RotationJudgedAgainstThePreviouslyTrustedAnchors)
{
    const CacheDir dir("rotation-circular");
    Trust::AnchorCache cache(dir.path());

    const auto first = signMasterList({makeCsca("CSCA A", "AA")}, makeIndependentSigner());
    ASSERT_TRUE(Trust::importMasterList(first.der, cache, kNow).has_value());

    // The forgery: a list of the attacker's own anchors, signed by a key the
    // attacker issued from one of THOSE anchors. It is internally consistent —
    // the signer chains perfectly to an anchor inside the very list being
    // imported — and it must still be refused, because the only anchors that
    // may vouch for a new signer are the ones already trusted.
    const auto plantedAnchor = makeCsca("CSCA Planted", "ZZ");
    const auto plantedSigner = makeSignerIssuedBy(plantedAnchor);
    const auto forgery = signMasterList({plantedAnchor}, plantedSigner);
    const auto refused = Trust::importMasterList(forgery.der, cache, kNow + 60);

    ASSERT_FALSE(refused.has_value()) << "a list that vouches for its own signer is circular, not authentic";
    EXPECT_EQ(refused.error().reason, Trust::ImportRefusal::SignerChanged);
    EXPECT_EQ(cache.anchors().size(), 1u);
    EXPECT_TRUE(holds(cache.anchors(), first.anchors.front()));
}

TEST(CscaAnchorImport, TrustOnFirstImportIsRecordedAsUnchecked)
{
    const CacheDir dir("unchecked");
    Trust::AnchorCache cache(dir.path());

    const auto list = signMasterList({makeCsca("CSCA A", "AA")}, makeIndependentSigner());
    const auto accepted = Trust::importMasterList(list.der, cache, kNow);

    ASSERT_TRUE(accepted.has_value());
    // Nothing was compared: somebody signed this list and the agent cannot say
    // who. A surface that claims otherwise claims more than was measured.
    EXPECT_FALSE(accepted->signerPinned);
}

// --- link certificates -----------------------------------------------------

TEST(CscaAnchorImport, LinkCertificateSurvivesImport)
{
    const CacheDir dir("link-cert");
    Trust::AnchorCache cache(dir.path());

    // A country that has rotated its root publishes three things: the outgoing
    // self-signed CSCA, the incoming self-signed CSCA, and the LINK
    // certificate — the incoming subject and key signed by the OUTGOING key, so
    // a verifier holding only the old root can still reach the new one. The
    // link certificate is NOT self-signed, and a "keep only self-signed
    // certificates" filter would silently drop it: such a filter passes every
    // single-root country and breaks every country that has rotated.
    const auto outgoing = makeCsca("CSCA Outgoing", "RR");
    const auto incoming = makeCsca("CSCA Incoming", "RR");
    const auto link = makeLinkCertificate(outgoing, incoming);

    const auto list = signMasterList({outgoing, incoming, link}, makeIndependentSigner());
    const auto accepted = Trust::importMasterList(list.der, cache, kNow);

    ASSERT_TRUE(accepted.has_value());
    EXPECT_EQ(accepted->anchorCount, 3u) << "all three are anchors; the link certificate is not an extra";

    const auto anchors = cache.anchors();
    ASSERT_EQ(anchors.size(), 3u);
    EXPECT_TRUE(holds(anchors, outgoing));
    EXPECT_TRUE(holds(anchors, incoming));
    EXPECT_TRUE(holds(anchors, link)) << "the link certificate was filtered out of the cache";
}

TEST(CscaAnchorImport, IssuerCountIsDistinctCountriesNotAnchors)
{
    const CacheDir dir("issuer-count");
    Trust::AnchorCache cache(dir.path());

    // Two generations for one country plus one for another: three anchors, two
    // issuers. Reporting three would tell a person their trust store covers
    // three countries when it covers two.
    const auto list =
        signMasterList({makeCsca("CSCA One Old", "AA"), makeCsca("CSCA One New", "AA"), makeCsca("CSCA Two", "BB")},
                       makeIndependentSigner());
    const auto accepted = Trust::importMasterList(list.der, cache, kNow);

    ASSERT_TRUE(accepted.has_value());
    EXPECT_EQ(accepted->anchorCount, 3u);
    EXPECT_EQ(accepted->issuerCount, 2u);
}

// --- refusals --------------------------------------------------------------

TEST(CscaAnchorImport, GarbageIsNotAMasterList)
{
    const CacheDir dir("garbage");
    Trust::AnchorCache cache(dir.path());

    const std::vector<std::uint8_t> garbage{0x01, 0x02, 0x03, 0x04};
    const auto refused = Trust::importMasterList(garbage, cache, kNow);
    ASSERT_FALSE(refused.has_value());
    EXPECT_EQ(refused.error().reason, Trust::ImportRefusal::NotAMasterList);

    const auto empty = Trust::importMasterList({}, cache, kNow);
    ASSERT_FALSE(empty.has_value());
    EXPECT_EQ(empty.error().reason, Trust::ImportRefusal::NotAMasterList);
}

TEST(CscaAnchorImport, ASignedObjectThatIsNotAMasterListIsRefused)
{
    const CacheDir dir("wrong-content-type");
    Trust::AnchorCache cache(dir.path());

    // Properly signed, verifies perfectly, carries a different content type.
    // Without this case, "not a master list" is only ever tested with bytes
    // that fail to decode, so an importer that never looks would pass.
    const auto refused = Trust::importMasterList(makeSignedNonMasterList(), cache, kNow);
    ASSERT_FALSE(refused.has_value());
    EXPECT_EQ(refused.error().reason, Trust::ImportRefusal::NotAMasterList);
}

TEST(CscaAnchorImport, TamperedContentFailsTheSignature)
{
    const CacheDir dir("tampered");
    Trust::AnchorCache cache(dir.path());

    const auto list = signMasterList({makeCsca("CSCA A", "AA"), makeCsca("CSCA B", "BB")}, makeIndependentSigner());
    // One byte flipped inside the signed content, every length left alone.
    const auto tampered = tamperWithSignedContent(list);
    ASSERT_NE(tampered, list.der) << "the perturbation changed nothing";

    const auto refused = Trust::importMasterList(tampered, cache, kNow);
    ASSERT_FALSE(refused.has_value()) << "a flipped content byte must bring the list down";
    EXPECT_EQ(refused.error().reason, Trust::ImportRefusal::BadSignature);

    // And the untampered original still passes, so the perturbation is what
    // failed rather than the fixture.
    EXPECT_TRUE(Trust::importMasterList(list.der, cache, kNow).has_value());
}

TEST(CscaAnchorImport, AnEmptyListIsNotAValidTrustState)
{
    const CacheDir dir("empty-list");
    Trust::AnchorCache cache(dir.path());

    const auto list = signMasterList({}, makeIndependentSigner());
    const auto refused = Trust::importMasterList(list.der, cache, kNow);
    ASSERT_FALSE(refused.has_value());
    EXPECT_EQ(refused.error().reason, Trust::ImportRefusal::Empty);
    EXPECT_FALSE(cache.state().present);
}

TEST(CscaAnchorImport, AnUnwritableCacheIsRefusedRatherThanIgnored)
{
    const CacheDir dir("unwritable");
    // A regular FILE where the cache directory should be: nothing can be
    // created under it, and the refusal has to say so rather than report a
    // successful import that stored nothing.
    fs::create_directories(dir.path().parent_path());
    {
        std::FILE* f = std::fopen(dir.path().c_str(), "wb");
        ASSERT_NE(f, nullptr);
        std::fclose(f);
    }

    Trust::AnchorCache cache(dir.path());
    const auto list = signMasterList({makeCsca("CSCA A", "AA")}, makeIndependentSigner());
    const auto refused = Trust::importMasterList(list.der, cache, kNow);

    ASSERT_FALSE(refused.has_value());
    EXPECT_EQ(refused.error().reason, Trust::ImportRefusal::CacheNotWritable);
}

// --- replay: a list may not be rolled back ---------------------------------
//
// The rule, one case per cell:
//
//   accepted   incoming   outcome
//   dated      dated      accept only if STRICTLY newer
//   dated      undated    REFUSE
//   undated    dated      accept
//   undated    undated    accept
//
// Row two is the asymmetric one and it is the point of the whole rule. A CMS
// signingTime is optional, so refusing every undated list could turn the feature
// off for a publisher that never dates anything — but letting an undated list
// replace a dated one hands an attacker a way to STRIP a protection the
// installation already had. The rule never refuses for a property the ecosystem
// may not provide, and never lets one be taken away.
//
// Every case below asserts on the PRESENCE of the recorded date, not on a value
// that happens to be zero: an implementation that never fills the field would
// otherwise pass the two undated rows without doing anything at all.

TEST(CscaAnchorImport, TheFixtureDatesAListOnlyWhenAskedTo)
{
    // The guard that keeps the rest of this section from passing vacuously. CMS
    // stamps a signingTime on everything it signs unless it is stopped, so an
    // "undated" fixture that quietly carried one would make every absent-date
    // assertion below meaningless — and an importer that never read a date at
    // all would sail through them.
    const CacheDir undatedDir("fixture-undated");
    Trust::AnchorCache undatedCache(undatedDir.path());
    const auto undated = signMasterList({makeCsca("CSCA A", "AA")}, makeIndependentSigner());
    EXPECT_FALSE(undated.signingTime.has_value()) << "the fixture dated a list nobody asked it to date";
    const auto afterUndated = Trust::importMasterList(undated.der, undatedCache, kNow);
    ASSERT_TRUE(afterUndated.has_value());
    EXPECT_FALSE(afterUndated->signedAt.has_value()) << "a date was invented for a list that carries none";
    EXPECT_FALSE(afterUndated->replayRefusalActive());

    const CacheDir datedDir("fixture-dated");
    Trust::AnchorCache datedCache(datedDir.path());
    const auto dated = signMasterListDated({makeCsca("CSCA B", "BB")}, makeIndependentSigner(), kSignedEarlier);
    ASSERT_TRUE(dated.signingTime.has_value());
    EXPECT_EQ(*dated.signingTime, kSignedEarlier);
    const auto afterDated = Trust::importMasterList(dated.der, datedCache, kNow);
    ASSERT_TRUE(afterDated.has_value());
    ASSERT_TRUE(afterDated->signedAt.has_value()) << "the list's own signing time was not carried through";
    EXPECT_EQ(*afterDated->signedAt, kSignedEarlier);
    EXPECT_NE(afterDated->signedAt, afterDated->acceptedAt)
        << "when it was signed and when it was accepted are different facts";
    EXPECT_TRUE(afterDated->replayRefusalActive());
    // And it survives into the cache, which is where the next import reads it.
    const Trust::AnchorState stored = datedCache.state();
    ASSERT_TRUE(stored.signedAt.has_value()) << "the signing time was not persisted";
    EXPECT_EQ(*stored.signedAt, kSignedEarlier);
}

// Row 1, the accepting half: dated over dated, strictly newer.
TEST(CscaAnchorImport, ADatedListIsAcceptedWhenItIsStrictlyNewer)
{
    const CacheDir dir("replay-newer");
    Trust::AnchorCache cache(dir.path());

    const auto signer = makeIndependentSigner();
    const auto first = signMasterListDated({makeCsca("CSCA A", "AA")}, signer, kSignedEarlier);
    ASSERT_TRUE(Trust::importMasterList(first.der, cache, kNow).has_value());

    const auto second = signMasterListDated({makeCsca("CSCA B", "BB")}, signer, kSignedLater);
    const auto accepted = Trust::importMasterList(second.der, cache, kNow + 60);

    ASSERT_TRUE(accepted.has_value()) << "a newer list from the same publisher must be installable";
    ASSERT_TRUE(accepted->signedAt.has_value());
    EXPECT_EQ(*accepted->signedAt, kSignedLater) << "the stored date must move forward with the list";
    EXPECT_TRUE(accepted->replayRefusalActive());
}

// Row 1, the refusing half. Both an OLDER list and a list dated exactly as the
// accepted one: "strictly newer" is the rule, so re-offering the same instant
// buys nothing.
TEST(CscaAnchorImport, ADatedListIsRefusedWhenItIsNotStrictlyNewer)
{
    const CacheDir dir("replay-older");
    Trust::AnchorCache cache(dir.path());

    const auto signer = makeIndependentSigner();
    const auto anchorA = makeCsca("CSCA A", "AA");
    const auto first = signMasterListDated({anchorA}, signer, kSignedLater);
    ASSERT_TRUE(Trust::importMasterList(first.der, cache, kNow).has_value());

    // The replay: the publisher's own earlier list, correctly signed, complete
    // and authentic. Accepting it would silently withdraw every anchor added
    // between the two.
    const auto older = signMasterListDated({makeCsca("CSCA Withdrawn", "ZZ")}, signer, kSignedEarlier);
    const auto refused = Trust::importMasterList(older.der, cache, kNow + 60);

    ASSERT_FALSE(refused.has_value()) << "an older list from the trusted publisher rolled the anchors back";
    EXPECT_EQ(refused.error().reason, Trust::ImportRefusal::Replayed);
    // BOTH dates come back, so a person can see which way round it is.
    ASSERT_TRUE(refused.error().seenSignedAt.has_value());
    ASSERT_TRUE(refused.error().trustedSignedAt.has_value());
    EXPECT_EQ(*refused.error().seenSignedAt, kSignedEarlier);
    EXPECT_EQ(*refused.error().trustedSignedAt, kSignedLater);

    // The refusal changed nothing.
    const auto anchors = cache.anchors();
    ASSERT_EQ(anchors.size(), 1u);
    EXPECT_TRUE(holds(anchors, anchorA));
    ASSERT_TRUE(cache.state().signedAt.has_value());
    EXPECT_EQ(*cache.state().signedAt, kSignedLater);

    // Equal is not newer either.
    const auto sameInstant = signMasterListDated({makeCsca("CSCA C", "CC")}, signer, kSignedLater);
    const auto alsoRefused = Trust::importMasterList(sameInstant.der, cache, kNow + 120);
    ASSERT_FALSE(alsoRefused.has_value()) << "a list dated exactly as the accepted one is not newer";
    EXPECT_EQ(alsoRefused.error().reason, Trust::ImportRefusal::Replayed);
}

// Row 2, the asymmetric one: an undated list may not replace a dated one.
TEST(CscaAnchorImport, AnUndatedListCannotReplaceADatedOne)
{
    const CacheDir dir("replay-strip");
    Trust::AnchorCache cache(dir.path());

    const auto signer = makeIndependentSigner();
    const auto anchorA = makeCsca("CSCA A", "AA");
    const auto first = signMasterListDated({anchorA}, signer, kSignedLater);
    ASSERT_TRUE(Trust::importMasterList(first.der, cache, kNow).has_value());

    // Signed by the very publisher the agent follows, and carrying no date at
    // all. It cannot be shown to be newer, and accepting it would additionally
    // TAKE AWAY the ability to refuse anything afterwards — the installation
    // would go from protected to unprotected on an attacker's say-so.
    const auto undated = signMasterList({makeCsca("CSCA Withdrawn", "ZZ")}, signer);
    ASSERT_FALSE(undated.signingTime.has_value()) << "the fixture dated the list this case is about";
    const auto refused = Trust::importMasterList(undated.der, cache, kNow + 60);

    ASSERT_FALSE(refused.has_value()) << "an undated list stripped the replay protection off a dated one";
    EXPECT_EQ(refused.error().reason, Trust::ImportRefusal::Replayed);
    EXPECT_FALSE(refused.error().seenSignedAt.has_value()) << "the offered list has no date to report";
    ASSERT_TRUE(refused.error().trustedSignedAt.has_value());
    EXPECT_EQ(*refused.error().trustedSignedAt, kSignedLater);

    // Nothing moved, and the protection is still on.
    const auto anchors = cache.anchors();
    ASSERT_EQ(anchors.size(), 1u);
    EXPECT_TRUE(holds(anchors, anchorA));
    EXPECT_TRUE(cache.state().replayRefusalActive());
}

// Row 3: a dated list may follow an undated one, and switches the protection on.
TEST(CscaAnchorImport, ADatedListMayFollowAnUndatedOne)
{
    const CacheDir dir("replay-undated-then-dated");
    Trust::AnchorCache cache(dir.path());

    const auto signer = makeIndependentSigner();
    const auto first = signMasterList({makeCsca("CSCA A", "AA")}, signer);
    const auto initial = Trust::importMasterList(first.der, cache, kNow);
    ASSERT_TRUE(initial.has_value());
    EXPECT_FALSE(initial->signedAt.has_value());
    EXPECT_FALSE(initial->replayRefusalActive()) << "nothing to compare against is not the same as safe";

    // Nothing is refused for a property the accepted list did not have.
    const auto second = signMasterListDated({makeCsca("CSCA B", "BB")}, signer, kSignedEarlier);
    const auto accepted = Trust::importMasterList(second.der, cache, kNow + 60);

    ASSERT_TRUE(accepted.has_value()) << "an undated installation must not refuse a dated list";
    ASSERT_TRUE(accepted->signedAt.has_value());
    EXPECT_EQ(*accepted->signedAt, kSignedEarlier);
    EXPECT_TRUE(accepted->replayRefusalActive()) << "the protection turns on the moment there is a date to hold";
}

// Row 4: undated over undated, which is a publisher that dates nothing.
TEST(CscaAnchorImport, AnUndatedListMayFollowAnUndatedOne)
{
    const CacheDir dir("replay-undated-twice");
    Trust::AnchorCache cache(dir.path());

    const auto signer = makeIndependentSigner();
    const auto first = signMasterList({makeCsca("CSCA A", "AA")}, signer);
    const auto initial = Trust::importMasterList(first.der, cache, kNow);
    ASSERT_TRUE(initial.has_value());
    EXPECT_FALSE(initial->signedAt.has_value());

    // Refusing here would turn the feature off outright for a publisher that
    // never dates its lists, and there is no ICAO sample in hand proving they do.
    const auto second = signMasterList({makeCsca("CSCA B", "BB")}, signer);
    ASSERT_FALSE(second.signingTime.has_value()) << "the fixture dated the list this case is about";
    const auto accepted = Trust::importMasterList(second.der, cache, kNow + 60);

    ASSERT_TRUE(accepted.has_value()) << "an undated publisher must not be locked out after its first list";
    EXPECT_FALSE(accepted->signedAt.has_value()) << "a date was invented for a list that carries none";
    EXPECT_FALSE(accepted->replayRefusalActive());
    EXPECT_FALSE(cache.state().replayRefusalActive());
    // And the anchors really were replaced, so this is an acceptance rather than
    // a refusal that happened to leave a usable store behind.
    const auto anchors = cache.anchors();
    ASSERT_EQ(anchors.size(), 1u);
    EXPECT_TRUE(holds(anchors, second.anchors.front()));
}

// The rule is about the LIST, not about the key that signed it: a publisher that
// rotates its key does not get to roll the anchors back on the way through.
TEST(CscaAnchorImport, ARotationCannotCarryAnOlderListIn)
{
    const CacheDir dir("replay-rotation");
    Trust::AnchorCache cache(dir.path());

    const auto anchorA = makeCsca("CSCA A", "AA");
    const auto first = signMasterListDated({anchorA}, makeIndependentSigner(), kSignedLater);
    ASSERT_TRUE(Trust::importMasterList(first.der, cache, kNow).has_value());

    // A lawful rotation — the new signer descends from an anchor the accepted
    // list carried — offering an older list.
    const auto rotated = makeSignerIssuedBy(anchorA);
    const auto older = signMasterListDated({anchorA, makeCsca("CSCA C", "CC")}, rotated, kSignedEarlier);
    const auto refused = Trust::importMasterList(older.der, cache, kNow + 60);

    ASSERT_FALSE(refused.has_value()) << "a key rotation was a way around the replay rule";
    EXPECT_EQ(refused.error().reason, Trust::ImportRefusal::Replayed);
    EXPECT_EQ(cache.state().signer, first.signerSpkiSha256) << "a refused import must not move the pin";
}

// --- who is told where the anchors are -------------------------------------
//
// The two below close a gap that a real passport on a dogfood machine found.
// A person had imported a master list; this file's subject accepted it and
// wrote five certificates into the cache; the agent's own state property said
// five anchors, one issuer. The badge on the document still read "no country
// signing certificates have been imported", because the card plugin that
// judges a document was never told the directory existed. Every test in three
// repositories was green: each half was tested against itself, and nothing
// tested the seam between them — which did not exist.

// The directory the agent publishes to its plugins is the one an import really
// wrote into. Asserted against the FILES, not against a second spelling of the
// layout: two constants that agree is what this already had.
TEST(CscaAnchorPublication, ThePublishedDirectoryIsWhereAnImportReallyWrote)
{
    const CacheDir dir("publish-agreement");
    Trust::AnchorCache cache(dir.path());

    const auto anchorA = makeCsca("CSCA A", "AA");
    const auto anchorB = makeCsca("CSCA B", "BB");
    const auto list = signMasterList({anchorA, anchorB}, makeIndependentSigner());
    const auto accepted = Trust::importMasterList(list.der, cache, kNow);
    ASSERT_TRUE(accepted.has_value());
    ASSERT_EQ(accepted->anchorCount, 2u);

    // No plugin directory here, so the registry loads nothing — this is about
    // the VALUE that gets published. Which plugin receives it, and what it does
    // with it, is settled where the plugin lives.
    LibreSCRS::Plugin::CardPluginService plugins{fs::path{dir.path() / "no-plugins-here"}};
    const fs::path published = Trust::publishAnchorDirectory(plugins, dir.path());

    EXPECT_EQ(published, cache.anchorsDirectory());
    ASSERT_TRUE(fs::is_directory(published)) << "the published path is not a directory that exists: " << published;

    std::vector<fs::path> written;
    for (const auto& entry : fs::directory_iterator(published)) {
        if (entry.is_regular_file()) {
            written.push_back(entry.path());
        }
    }
    EXPECT_EQ(written.size(), 2u) << "the import's certificates are not in the directory the agent publishes";

    // And the bytes really are the anchors, so a directory of two unrelated
    // files could not pass.
    const auto held = cache.anchors();
    ASSERT_EQ(held.size(), 2u);
    EXPECT_TRUE(holds(held, anchorA));
    EXPECT_TRUE(holds(held, anchorB));
}

// The composition root really makes the call, and makes it with the CONFIGURED
// cache directory rather than one rebuilt from the cache root. Read off the
// shipped source, the way this repository's other composition-root guards are:
// AgentService::registerOnBus needs a session bus and a PC/SC monitor that CI
// has not got, so there is no way to drive it here — but a wiring line that
// silently goes missing is the whole defect this closes, and the guard is a
// good deal better than nothing watching it at all.
//
// The configured value matters and is asserted for itself: CscaCacheDir is a
// settable key, so an installation that has set it imports into one directory,
// and a path rebuilt from the cache root would have the plugins read another.
TEST(CscaAnchorPublication, TheAgentPublishesTheConfiguredDirectoryAtStartup)
{
    std::ifstream in(LIBRELINUX_AGENTSERVICE_CPP, std::ios::binary);
    ASSERT_TRUE(in) << "AgentService source path not wired";
    const std::string src{std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
    ASSERT_FALSE(src.empty());

    EXPECT_NE(src.find("publishAnchorDirectory("), std::string::npos)
        << "nothing hands the card plugins the anchors this agent holds";
    EXPECT_NE(src.find("configStore().cscaCacheDir()"), std::string::npos)
        << "the published directory must come from the CONFIGURED cache dir, not one rebuilt from the cache root";
}
