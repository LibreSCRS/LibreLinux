// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once

// Signed ICAO country-signing master lists, built in the test process rather
// than shipped as bytes. A real list may not live in this repository (its terms
// of use forbid redistribution) and a redacted one would prove less than a
// synthetic one, because the format itself is what these tests are about.
//
// Every certificate is minted here with the system OpenSSL. That is the TEST
// side only: the agent itself has no OpenSSL dependency and must not grow one —
// it consumes the published LibreMiddleware trust API and nothing else.
//
// The generator is deliberately awkward in two places and each awkwardness
// closes a way a convenient fixture would let a broken importer pass:
//
//   * a master-list signer is issued by a CA of its own that appears in NO
//     list, unless a caller explicitly asks for one issued by an anchor. A
//     signer that always chained to the list it signs would make the circular
//     check — "verify a list against its own contents" — pass every test here,
//     and that check is exactly what the import path must never do.
//   * anchors are sorted into DER SET OF order rather than trusted to arrive in
//     it. An unsorted SET is not DER and would only ever parse against the
//     encoder that produced it.
//   * a list is UNDATED unless a caller asks for a date. CMS stamps a
//     signingTime of the signing moment on every SignerInfo unless it is
//     stopped, so a fixture that took the default would hand every test a date
//     nobody chose — two lists signed in the same second would then compare
//     equal, and a test about replay would be measuring the wall clock. The
//     undated form constrains nothing, which is what a test that is not about
//     dates should be handed.

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace LibreSCRS::Agent::Test {

// The certificate that signs a master list, plus the key behind it (remembered
// in a process-lifetime registry keyed on the certificate's own encoding, so
// the handle stays copyable and carries no OpenSSL type into test code).
struct MasterListSigner
{
    std::vector<std::uint8_t> certificateDer;
};

// A signed master list together with what a correct reader should make of it.
struct SyntheticMasterList
{
    std::vector<std::uint8_t> der;                   ///< CMS SignedData over CscaMasterList
    std::vector<std::vector<std::uint8_t>> anchors;  ///< the anchors it CARRIES, in DER SET OF order
    std::array<std::uint8_t, 32> signerSpkiSha256{}; ///< SHA-256 over the signer's SubjectPublicKeyInfo
    std::vector<std::uint8_t> signerCertificateDer;  ///< the certificate that signed it
    /// The signingTime the list ACTUALLY carries, empty when it carries none.
    /// Reported rather than assumed so a test asserting on an absent date is
    /// checking the fixture as well as the code under test: a generator that
    /// quietly dated everything would make every such assertion vacuous.
    std::optional<std::int64_t> signingTime;
};

// A self-signed country signing CA. @p country lands in the subject's C
// attribute, which is what an importer counts distinct issuers by.
[[nodiscard]] std::vector<std::uint8_t> makeCsca(const std::string& commonName, const std::string& country);

// A CSCA link certificate: the subject name and public key of @p incoming,
// signed by @p outgoing's key. NOT self-signed — that is the whole point of it,
// and the property no other certificate here has. Both arguments must be
// certificates this process minted, because the outgoing key is needed to sign.
[[nodiscard]] std::vector<std::uint8_t> makeLinkCertificate(const std::vector<std::uint8_t>& outgoingCscaDer,
                                                            const std::vector<std::uint8_t>& incomingCscaDer);

// A master-list signer issued by a freshly minted CA that appears in no list.
[[nodiscard]] MasterListSigner makeIndependentSigner();

// A master-list signer ISSUED BY @p issuerCscaDer — the shape of a publisher
// rotation a previously trusted list is able to vouch for. @p issuerCscaDer
// must be a CA this process minted.
[[nodiscard]] MasterListSigner makeSignerIssuedBy(const std::vector<std::uint8_t>& issuerCscaDer);

// Sign @p anchors into a master list carrying NO signingTime attribute — a
// perfectly valid CMS object, and the one a caller gets unless it asks for a
// date. @p anchors is sorted here, so a caller may pass them in any order; the
// result reports the order the list encodes.
[[nodiscard]] SyntheticMasterList signMasterList(std::vector<std::vector<std::uint8_t>> anchors,
                                                 const MasterListSigner& signer);

// The same, with a signingTime SIGNED attribute reading exactly
// @p signingTimeEpochSeconds. Signed, so the signature covers it: the same
// attribute among the unsigned ones would be whatever the last hand to touch the
// file chose, which is worse than no date at all.
[[nodiscard]] SyntheticMasterList signMasterListDated(std::vector<std::vector<std::uint8_t>> anchors,
                                                      const MasterListSigner& signer,
                                                      std::int64_t signingTimeEpochSeconds);

// A properly signed CMS carrying a DIFFERENT eContentType (id-data). Without
// it, "not a master list" is only ever tested with garbage that fails to
// decode, so an importer that never looks at the content type would pass.
[[nodiscard]] std::vector<std::uint8_t> makeSignedNonMasterList();

// @p list with one byte flipped inside the signed content, so the signature no
// longer holds over bytes that are otherwise a well-formed list.
[[nodiscard]] std::vector<std::uint8_t> tamperWithSignedContent(const SyntheticMasterList& list);

} // namespace LibreSCRS::Agent::Test
