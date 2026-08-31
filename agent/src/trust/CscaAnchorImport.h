// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once

// Turning a signed ICAO country-signing master list into the agent's trust
// anchors, and deciding whether to believe it.
//
// WHY THERE IS A DECISION TO MAKE. A master list is signed by a key that chains
// to a country's own authority, and the list is what supplies the anchors that
// authority would be checked against — so at the very first import there is
// nothing to check it with. Verifying a list against anchors carried INSIDE
// that same list proves internal consistency and says nothing whatever about
// authenticity; it must never be presented as a check.
//
// WHAT THIS DOES INSTEAD. The first list is trusted on import and its signer is
// remembered. Every later list must be signed by that same key — or by a signer
// whose certificate chains to an anchor the PREVIOUSLY ACCEPTED list carried,
// which is how a publisher's lawful key rotation is followed without a person
// having to compare fingerprints out of band. Anything else is refused, both
// fingerprints are reported, and the stored anchors are left alone. A lawful
// rotation and an attack look identical from here, so accepting one silently
// would accept the other.
//
// THE ROTATING SIGNER'S CERTIFICATE COMES OUT OF THE LIST, and specifically out
// of the signer a successful verification RESOLVED — never out of the CMS
// certificate bag, which is unauthenticated and which anybody may drop anybody's
// certificate into. Nothing has to be handed in beside the file: the certificate
// the path build needs is inside the bytes the caller already supplied.
//
// NO CRYPTO LIVES HERE. Every cryptographic judgement is made by the published
// LibreMiddleware trust API — the parse-and-verify, the fingerprint and the
// path build. In particular the fingerprint is NEVER recomputed locally: it is
// a hash of the re-encoded SubjectPublicKeyInfo, and the two plausible
// alternatives (hashing the certificate, or hashing the SubjectPublicKeyInfo
// slice as carried) both produce values that look right and never match.

#include <array>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

// Forward decl — only a reference appears below, in publishAnchorDirectory.
namespace LibreSCRS::Plugin {
class CardPluginService;
}

namespace LibreSCRS::Agent::Trust {

// The largest master list the agent will ingest. A published ICAO list runs to a
// few megabytes; this leaves generous room and still bounds the synchronous read
// that a client can ask the bus thread to perform.
inline constexpr std::size_t kMaxMasterListBytes = 32ull * 1024 * 1024;

// SHA-256 over the DER of a signer's SubjectPublicKeyInfo.
inline constexpr std::size_t kSignerFingerprintSize = 32;
using SignerFingerprint = std::array<std::uint8_t, kSignerFingerprintSize>;

// What the agent remembers between imports, and what a client reads in order to
// have something to say about the trust store.
struct AnchorState
{
    bool present{false};        ///< false until a list has been accepted
    SignerFingerprint signer{}; ///< the publisher the agent follows
    /// Whether the accepting import ESTABLISHED the signer's identity — matched
    /// it against the pin, or built a path from it to an anchor already held —
    /// as opposed to merely observing it. False on a trust-on-first-import, and
    /// a surface that says "authenticity verified" over a false here claims more
    /// than was measured.
    bool signerPinned{false};
    /// Anchors held. Counts link certificates, which are anchors like any
    /// other — this is not a count of self-signed roots.
    std::uint32_t anchorCount{0};
    /// Distinct issuing countries among those anchors, by the subject's country
    /// attribute. Anchors that carry none, or that do not parse, share one
    /// bucket rather than each inventing an issuer.
    std::uint32_t issuerCount{0};
    std::int64_t acceptedAt{0};   ///< seconds since the epoch
    std::string origin{"import"}; ///< where the anchors came from
    /// When the accepted list said it was SIGNED, from the CMS signingTime
    /// signed attribute. Empty when the list carried none, which CMS permits.
    /// Distinct from @ref acceptedAt, which is when this agent took it in and is
    /// therefore under no publisher's control.
    std::optional<std::int64_t> signedAt;

    /// Whether a later import can be refused for being a replay.
    ///
    /// True exactly when the accepted list carried a signing time. With nothing
    /// to compare against, "is this list older than the one installed" is not a
    /// question that can be answered at all, and a surface that stays silent
    /// about it leaves a person unable to tell "this is safe" from "this cannot
    /// be checked".
    [[nodiscard]] bool replayRefusalActive() const noexcept
    {
        return signedAt.has_value();
    }
};

// Why an import was refused. Every value leaves the stored anchors untouched.
enum class ImportRefusal : std::uint8_t {
    /// Not a master list: undecodable, or a signed object of some other content
    /// type. Empty input lands here too.
    NotAMasterList,
    /// A master list that verified and carries no anchor. An empty trust store
    /// is not a valid state to import into one.
    Empty,
    /// A master list whose content cannot be read.
    Malformed,
    /// The signature over the list does not hold.
    BadSignature,
    /// The list is signed by a key the agent does not follow, and that key's
    /// certificate does not chain to any anchor the accepted list carried.
    SignerChanged,
    /// The list is authentic and is not newer than the one already accepted:
    /// either it is dated no later, or it carries no date at all while the
    /// accepted one does. Installing it would withdraw anchors.
    Replayed,
    /// The anchors verified but could not be stored. Reported rather than
    /// swallowed: an import that silently kept nothing would leave a person
    /// believing anchors were installed.
    CacheNotWritable,
};

struct Refusal
{
    ImportRefusal reason{ImportRefusal::NotAMasterList};
    /// The signer of the list that was offered, when one could be read. Shown
    /// beside @ref trustedSigner so a person can tell a rotation from an
    /// attack; the agent cannot.
    std::optional<SignerFingerprint> seenSigner;
    /// The signer the agent follows, when it follows one.
    std::optional<SignerFingerprint> trustedSigner;
    /// For @ref ImportRefusal::Replayed: when the offered list says it was
    /// signed, empty when it does not say. Empty here beside a filled
    /// @ref trustedSignedAt is the strip attempt rather than the rollback.
    std::optional<std::int64_t> seenSignedAt;
    /// For @ref ImportRefusal::Replayed: when the ACCEPTED list said it was
    /// signed — the value the offered one had to beat.
    std::optional<std::int64_t> trustedSignedAt;
};

// The anchors and the trust state on disk, under the agent's configured
// country-signing cache directory.
//
// Anchors are stored one encoded certificate per file, exactly as the list
// carried them. Nothing is filtered on the way in: an ICAO master list carries
// CSCA link certificates beside the self-signed roots, and a
// "keep only self-signed" filter would pass every single-root country and break
// every country that has rotated its root.
class AnchorCache
{
public:
    explicit AnchorCache(std::filesystem::path dir);

    // Where the anchor FILES are, under the cache directory this was built
    // with — the directory something outside this process has to be handed if
    // it is to judge a document against what was imported.
    //
    // A method rather than a name spelled again at each call site, and the
    // reason is a defect that reached a person's desk: the import wrote five
    // certificates here, a card plugin was never told the directory existed,
    // and the badge on a real passport read "no country signing certificates
    // have been imported" while five of them sat on disk. Two halves that each
    // knew the layout, and no seam where they had to agree.
    [[nodiscard]] std::filesystem::path anchorsDirectory() const;

    // Absent or unreadable state reads as "believes nothing", never as an error:
    // a first run and a wiped cache are the same situation.
    [[nodiscard]] AnchorState state() const;

    // The anchors currently held, in stored order. Empty when nothing has been
    // imported.
    [[nodiscard]] std::vector<std::vector<std::uint8_t>> anchors() const;

    // Whether the cache holds AT LEAST ONE anchor. Stops at the first one and
    // reads no bytes — the question is whether anything is here, not whether
    // what is here still verifies, and re-verifying a store to answer it would
    // put a full trust pass in the startup path. A missing or unreadable
    // directory answers false, for the same reason @ref state does: a first run
    // and a wiped cache are the same situation.
    [[nodiscard]] bool holdsAnchor() const;

    // REPLACES the anchor set — a master list is a complete statement of what a
    // publisher vouches for, so merging would keep anchors it has withdrawn.
    // Returns false if anything could not be written, in which case the previous
    // contents may be gone: the state file is written last and only on success,
    // so a torn write leaves the agent believing nothing rather than believing
    // the wrong thing.
    [[nodiscard]] bool replace(const std::vector<std::vector<std::uint8_t>>& anchors, const AnchorState& state);

private:
    std::filesystem::path m_dir;
};

// Verify @p der, decide whether to believe it, and on acceptance replace the
// cached anchors.
//
// @param der the bytes of a signed master list, as published. Everything the
//        decision needs is in here, the rotating signer's certificate included.
// @param now seconds since the epoch, injected rather than read, so the record
//        an import writes is testable.
[[nodiscard]] std::expected<AnchorState, Refusal> importMasterList(const std::vector<std::uint8_t>& der,
                                                                   AnchorCache& cache, std::int64_t now);

// Lowercase hex, for showing a fingerprint to a person or putting one on the wire.
[[nodiscard]] std::string toHex(const SignerFingerprint& fingerprint);

// Tell every card plugin @p plugins loaded where this agent keeps the country
// signing certificates it has imported, and answer with the directory that was
// published.
//
// WHY THE AGENT HAS TO SAY IT. A plugin verifying a travel document's passive
// authentication needs country signing certificates, and it is not allowed to
// go looking for them: the directory used to be named by an environment
// variable, which anything running as the person at the keyboard can set, so a
// forged document could be reported as chaining to a national authority on the
// say-so of whoever set it. That read was removed and nothing replaced it —
// which is why anchors a person really had imported were reported as absent.
// The path has to arrive from the process that holds them, which is this one.
//
// @param cacheDir the agent's configured country-signing cache directory,
//        i.e. ConfigStore::cscaCacheDir(). The SAME value the import writes
//        under: pass the configured one and never a path rebuilt from the
//        cache root, or an installation that has set CscaCacheDir imports into
//        one directory and reads from another with nothing to say so.
// @return the directory published, which is @ref AnchorCache::anchorsDirectory
//         for @p cacheDir. Returned so a caller can log it and a test can
//         compare it against where an import really landed.
std::filesystem::path publishAnchorDirectory(LibreSCRS::Plugin::CardPluginService& plugins,
                                             const std::filesystem::path& cacheDir);

} // namespace LibreSCRS::Agent::Trust
