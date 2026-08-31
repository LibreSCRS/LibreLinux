// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#include "SyntheticMasterList.h"

#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/cms.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <algorithm>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>

namespace LibreSCRS::Agent::Test {
namespace {

// ICAO 9303-12 id-icao-cscaMasterList.
constexpr const char* kCscaMasterListOid = "2.23.136.1.1.2";

// Every certificate is backdated fifteen years, the window a real country
// signing CA carries, so a chain can also be built at a past date.
constexpr long kBackdate = 15L * 365 * 24 * 3600;

// An arbitrary fixed instant for objects whose date nothing reads.
constexpr std::int64_t kNotAMasterListSigningTime = 1'700'000'000;

constexpr long kForwardValidity = 365L * 24 * 3600;

[[noreturn]] void fail(const char* what)
{
    throw std::runtime_error(std::string{"SyntheticMasterList: "} + what);
}

struct X509Deleter
{
    void operator()(X509* p) const noexcept
    {
        X509_free(p);
    }
};
struct PKeyDeleter
{
    void operator()(EVP_PKEY* p) const noexcept
    {
        EVP_PKEY_free(p);
    }
};
struct CmsDeleter
{
    void operator()(CMS_ContentInfo* p) const noexcept
    {
        CMS_ContentInfo_free(p);
    }
};
struct BioDeleter
{
    void operator()(BIO* p) const noexcept
    {
        BIO_free(p);
    }
};
struct Asn1ObjDeleter
{
    void operator()(ASN1_OBJECT* p) const noexcept
    {
        ASN1_OBJECT_free(p);
    }
};
struct BnDeleter
{
    void operator()(BIGNUM* p) const noexcept
    {
        BN_free(p);
    }
};
struct MdCtxDeleter
{
    void operator()(EVP_MD_CTX* p) const noexcept
    {
        EVP_MD_CTX_free(p);
    }
};
struct Asn1TimeDeleter
{
    void operator()(ASN1_TIME* p) const noexcept
    {
        ASN1_TIME_free(p);
    }
};
struct PubKeyDeleter
{
    void operator()(X509_PUBKEY* p) const noexcept
    {
        X509_PUBKEY_free(p);
    }
};

using X509Ptr = std::unique_ptr<X509, X509Deleter>;
using PKeyPtr = std::unique_ptr<EVP_PKEY, PKeyDeleter>;
using CmsPtr = std::unique_ptr<CMS_ContentInfo, CmsDeleter>;
using BioPtr = std::unique_ptr<BIO, BioDeleter>;
using Asn1ObjPtr = std::unique_ptr<ASN1_OBJECT, Asn1ObjDeleter>;
using BnPtr = std::unique_ptr<BIGNUM, BnDeleter>;
using Asn1TimePtr = std::unique_ptr<ASN1_TIME, Asn1TimeDeleter>;
using MdCtxPtr = std::unique_ptr<EVP_MD_CTX, MdCtxDeleter>;
using PubKeyPtr = std::unique_ptr<X509_PUBKEY, PubKeyDeleter>;

// A certificate together with the key that goes with it.
struct Cert
{
    X509Ptr x;
    PKeyPtr key;
};

std::string randomHex(int bytes)
{
    std::vector<unsigned char> buf(static_cast<std::size_t>(bytes));
    if (RAND_bytes(buf.data(), bytes) != 1) {
        fail("RAND_bytes failed");
    }
    static constexpr char kDigits[] = "0123456789abcdef";
    std::string out;
    for (unsigned char b : buf) {
        out.push_back(kDigits[b >> 4]);
        out.push_back(kDigits[b & 0x0F]);
    }
    return out;
}

std::vector<std::uint8_t> certDer(X509* cert)
{
    unsigned char* der = nullptr;
    const int len = i2d_X509(cert, &der);
    if (len <= 0 || der == nullptr) {
        fail("i2d_X509 failed");
    }
    std::vector<std::uint8_t> out(der, der + len);
    OPENSSL_free(der);
    return out;
}

std::array<std::uint8_t, 32> spkiSha256(X509* cert)
{
    // The SubjectPublicKeyInfo RE-ENCODED, not the slice the certificate
    // carries: the published pin function does the same, and hashing the
    // carried slice would fingerprint one key differently under two encodings.
    EVP_PKEY* pub = X509_get0_pubkey(cert);
    if (pub == nullptr) {
        fail("X509_get0_pubkey failed");
    }
    X509_PUBKEY* raw = nullptr; // X509_PUBKEY_set allocates when handed a null
    if (X509_PUBKEY_set(&raw, pub) != 1 || raw == nullptr) {
        fail("X509_PUBKEY_set failed");
    }
    PubKeyPtr spki(raw);

    unsigned char* der = nullptr;
    const int len = i2d_X509_PUBKEY(spki.get(), &der);
    if (len <= 0 || der == nullptr) {
        fail("i2d_X509_PUBKEY failed");
    }
    std::array<std::uint8_t, 32> out{};
    SHA256(der, static_cast<std::size_t>(len), out.data());
    OPENSSL_free(der);
    return out;
}

// --- the minted-key registry ----------------------------------------------
//
// A link certificate has to be SIGNED by the outgoing CA, and a signer has to
// be ISSUED by an anchor, but the fixture API hands certificates around as
// bytes. The generator therefore remembers the key of everything it mints,
// keyed on that certificate's own encoding. Process-lifetime state in a test
// fixture, nowhere near a shipped surface.

std::mutex& registryMutex()
{
    static std::mutex mutex;
    return mutex;
}

std::map<std::vector<std::uint8_t>, PKeyPtr>& registry()
{
    static std::map<std::vector<std::uint8_t>, PKeyPtr> keys;
    return keys;
}

void remember(const std::vector<std::uint8_t>& der, EVP_PKEY* key)
{
    if (EVP_PKEY_up_ref(key) != 1) {
        fail("EVP_PKEY_up_ref failed");
    }
    const std::lock_guard<std::mutex> lock(registryMutex());
    registry().insert_or_assign(der, PKeyPtr(key));
}

// The certificate and the key behind it, for something this process minted.
Cert recall(const std::vector<std::uint8_t>& der)
{
    Cert out;
    const unsigned char* p = der.data();
    out.x.reset(d2i_X509(nullptr, &p, static_cast<long>(der.size())));
    if (!out.x) {
        fail("d2i_X509 failed on a certificate the fixture was handed");
    }
    const std::lock_guard<std::mutex> lock(registryMutex());
    const auto it = registry().find(der);
    if (it == registry().end()) {
        fail("no key remembered for this certificate: it was not minted in this process");
    }
    if (EVP_PKEY_up_ref(it->second.get()) != 1) {
        fail("EVP_PKEY_up_ref failed");
    }
    out.key.reset(it->second.get());
    return out;
}

void addExtension(X509* cert, X509* issuer, int nid, const char* value)
{
    X509V3_CTX ctx;
    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, issuer, cert, nullptr, nullptr, 0);
    X509_EXTENSION* ext = X509V3_EXT_conf_nid(nullptr, &ctx, nid, value);
    if (ext == nullptr) {
        fail("X509V3_EXT_conf_nid failed");
    }
    const int added = X509_add_ext(cert, ext, -1);
    X509_EXTENSION_free(ext);
    if (added != 1) {
        fail("X509_add_ext failed");
    }
}

void setRandomSerial(X509* cert)
{
    BnPtr bn(BN_new());
    if (!bn || BN_rand(bn.get(), 119, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ANY) != 1) {
        fail("BN_rand failed");
    }
    if (BN_to_ASN1_INTEGER(bn.get(), X509_get_serialNumber(cert)) == nullptr) {
        fail("BN_to_ASN1_INTEGER failed");
    }
}

struct CertRequest
{
    std::string commonName;
    std::string country = "XX";
    bool ca = false;
    const Cert* issuer = nullptr; ///< nullptr: self-signed with its own key
    std::string keyUsage;
    /// nullptr: mint a fresh key. Otherwise this is a LINK CERTIFICATE for that
    /// certificate and takes BOTH its subject name and its public key, so the
    /// two are interchangeable to a path builder.
    const Cert* sameSubjectAndKeyAs = nullptr;
};

Cert makeCert(const CertRequest& req)
{
    Cert out;
    if (req.sameSubjectAndKeyAs != nullptr) {
        if (EVP_PKEY_up_ref(req.sameSubjectAndKeyAs->key.get()) != 1) {
            fail("EVP_PKEY_up_ref failed");
        }
        out.key.reset(req.sameSubjectAndKeyAs->key.get());
    } else {
        out.key.reset(EVP_EC_gen("P-256"));
    }
    out.x.reset(X509_new());
    if (!out.key || !out.x) {
        fail("key or certificate allocation failed");
    }

    X509_set_version(out.x.get(), 2); // v3
    setRandomSerial(out.x.get());
    X509_gmtime_adj(X509_getm_notBefore(out.x.get()), -kBackdate);
    X509_gmtime_adj(X509_getm_notAfter(out.x.get()), kForwardValidity);

    if (X509_set_pubkey(out.x.get(), out.key.get()) != 1) {
        fail("X509_set_pubkey failed");
    }

    if (req.sameSubjectAndKeyAs != nullptr) {
        // Copied whole rather than rebuilt from parts: the two subjects have to
        // compare equal under X509_NAME_cmp, which a re-entered name would not
        // guarantee if the string types ever differed.
        if (X509_set_subject_name(out.x.get(), X509_get_subject_name(req.sameSubjectAndKeyAs->x.get())) != 1) {
            fail("X509_set_subject_name failed");
        }
    } else {
        X509_NAME* subject = X509_get_subject_name(out.x.get());
        X509_NAME_add_entry_by_txt(subject, "C", MBSTRING_ASC,
                                   reinterpret_cast<const unsigned char*>(req.country.c_str()), -1, -1, 0);
        X509_NAME_add_entry_by_txt(subject, "CN", MBSTRING_ASC,
                                   reinterpret_cast<const unsigned char*>(req.commonName.c_str()), -1, -1, 0);
    }

    X509* issuerCert = req.issuer != nullptr ? req.issuer->x.get() : out.x.get();
    if (X509_set_issuer_name(out.x.get(), X509_get_subject_name(issuerCert)) != 1) {
        fail("X509_set_issuer_name failed");
    }

    addExtension(out.x.get(), issuerCert, NID_basic_constraints, req.ca ? "critical,CA:TRUE" : "critical,CA:FALSE");
    if (!req.keyUsage.empty()) {
        addExtension(out.x.get(), issuerCert, NID_key_usage, req.keyUsage.c_str());
    }

    EVP_PKEY* signingKey = req.issuer != nullptr ? req.issuer->key.get() : out.key.get();
    if (X509_sign(out.x.get(), signingKey, EVP_sha256()) == 0) {
        fail("X509_sign failed");
    }
    return out;
}

std::vector<std::uint8_t> derWrap(std::uint8_t tag, const std::vector<std::uint8_t>& body)
{
    std::vector<std::uint8_t> out{tag};
    const std::size_t len = body.size();
    if (len < 0x80) {
        out.push_back(static_cast<std::uint8_t>(len));
    } else {
        std::vector<std::uint8_t> lenBytes;
        for (std::size_t v = len; v != 0; v >>= 8) {
            lenBytes.insert(lenBytes.begin(), static_cast<std::uint8_t>(v & 0xFF));
        }
        out.push_back(static_cast<std::uint8_t>(0x80 | lenBytes.size()));
        out.insert(out.end(), lenBytes.begin(), lenBytes.end());
    }
    out.insert(out.end(), body.begin(), body.end());
    return out;
}

// CscaMasterList ::= SEQUENCE { version INTEGER, certificates SET OF Certificate }
// Assembled by hand: OpenSSL has no ASN1_ITEM for it.
// @p sortedCerts must already be in ascending encoding order — DER SET OF
// demands it, and an unsorted SET would only parse against its own producer.
std::vector<std::uint8_t> buildMasterListContent(const std::vector<std::vector<std::uint8_t>>& sortedCerts)
{
    std::vector<std::uint8_t> certsBlob;
    for (const std::vector<std::uint8_t>& cert : sortedCerts) {
        certsBlob.insert(certsBlob.end(), cert.begin(), cert.end());
    }
    std::vector<std::uint8_t> body{0x02, 0x01, 0x00}; // version v0
    const std::vector<std::uint8_t> certSet = derWrap(0x31, certsBlob);
    body.insert(body.end(), certSet.begin(), certSet.end());
    return derWrap(0x30, body);
}

// Remove the signingTime attribute a finished SignerInfo carries, and re-sign
// over what is left.
//
// It has to happen AFTER the signature, not before: CMS adds a signingTime of
// the signing moment to every SignerInfo it finalises unless one is already
// there, and there is no flag that suppresses only that attribute. Suppressing
// the signed attributes wholesale (CMS_NOATTR) is not the same object — it also
// drops the signed contentType, and a master list without one is refused, which
// was measured before this was written rather than assumed.
//
// So the signature is recomputed here by hand over the remaining attributes,
// encoded as the SET OF a verifier will rebuild: ascending by encoding, the
// shorter of two sharing a prefix first, which is what DER demands and what
// std::vector's ordering already is.
void stripSigningTime(CMS_SignerInfo* si, const Cert& signer)
{
    const int idx = CMS_signed_get_attr_by_NID(si, NID_pkcs9_signingTime, -1);
    if (idx < 0) {
        fail("no signingTime to strip: the CMS default changed under this fixture");
    }
    X509_ATTRIBUTE_free(CMS_signed_delete_attr(si, idx));

    std::vector<std::vector<std::uint8_t>> attributes;
    for (int i = 0; i < CMS_signed_get_attr_count(si); ++i) {
        unsigned char* der = nullptr;
        const int len = i2d_X509_ATTRIBUTE(CMS_signed_get_attr(si, i), &der);
        if (len <= 0 || der == nullptr) {
            fail("i2d_X509_ATTRIBUTE failed");
        }
        attributes.emplace_back(der, der + len);
        OPENSSL_free(der);
    }
    std::sort(attributes.begin(), attributes.end());
    std::vector<std::uint8_t> blob;
    for (const auto& attribute : attributes) {
        blob.insert(blob.end(), attribute.begin(), attribute.end());
    }
    const std::vector<std::uint8_t> setOf = derWrap(0x31, blob);

    MdCtxPtr mctx(EVP_MD_CTX_new());
    std::size_t siglen = 0;
    if (!mctx || EVP_DigestSignInit(mctx.get(), nullptr, EVP_sha256(), nullptr, signer.key.get()) != 1 ||
        EVP_DigestSign(mctx.get(), nullptr, &siglen, setOf.data(), setOf.size()) != 1) {
        fail("EVP_DigestSignInit failed");
    }
    std::vector<unsigned char> signature(siglen);
    if (EVP_DigestSign(mctx.get(), signature.data(), &siglen, setOf.data(), setOf.size()) != 1) {
        fail("EVP_DigestSign failed");
    }
    if (ASN1_STRING_set(CMS_SignerInfo_get0_signature(si), signature.data(), static_cast<int>(siglen)) != 1) {
        fail("ASN1_STRING_set failed");
    }
}

// @p eContentTypeOid nullptr keeps the CMS default, id-data. @p signingTime
// empty produces an object carrying no signingTime attribute at all.
std::vector<std::uint8_t> signCms(const Cert& signer, const std::vector<std::uint8_t>& content,
                                  const char* eContentTypeOid, std::optional<std::int64_t> signingTime)
{
    BioPtr bio(BIO_new_mem_buf(content.data(), static_cast<int>(content.size())));
    if (!bio) {
        fail("BIO_new_mem_buf failed");
    }

    // CMS_PARTIAL is mandatory: without it CMS_sign finalises at once,
    // CMS_set1_eContentType no longer has any effect, and nothing could tell a
    // master list from anything else. The contentType SIGNED attribute is copied
    // from the eContentType at CMS_final time, so setting it in between is what
    // makes the two agree — which is the very thing the importer's parser
    // cross-checks. It is also the window in which the signingTime can be
    // chosen, for the same reason: after CMS_final there is nothing to choose.
    CmsPtr cms(
        CMS_sign(signer.x.get(), signer.key.get(), nullptr, bio.get(), CMS_BINARY | CMS_NOSMIMECAP | CMS_PARTIAL));
    if (!cms) {
        fail("CMS_sign failed");
    }
    if (eContentTypeOid != nullptr) {
        Asn1ObjPtr oid(OBJ_txt2obj(eContentTypeOid, 1));
        if (!oid || CMS_set1_eContentType(cms.get(), oid.get()) != 1) {
            fail("CMS_set1_eContentType failed");
        }
    }

    STACK_OF(CMS_SignerInfo)* signers = CMS_get0_SignerInfos(cms.get());
    if (signers == nullptr || sk_CMS_SignerInfo_num(signers) != 1) {
        fail("expected exactly one SignerInfo");
    }
    CMS_SignerInfo* si = sk_CMS_SignerInfo_value(signers, 0);

    if (signingTime) {
        // Seeded BEFORE CMS_final, which adds one only when none is present.
        Asn1TimePtr when(ASN1_TIME_adj(nullptr, static_cast<time_t>(*signingTime), 0, 0));
        if (!when ||
            CMS_signed_add1_attr_by_NID(si, NID_pkcs9_signingTime, ASN1_STRING_type(when.get()), when.get(), -1) != 1) {
            fail("adding the signingTime attribute failed");
        }
    }
    if (CMS_final(cms.get(), bio.get(), nullptr, CMS_BINARY) != 1) {
        fail("CMS_final failed");
    }
    if (!signingTime) {
        stripSigningTime(si, signer);
    }

    unsigned char* der = nullptr;
    const int len = i2d_CMS_ContentInfo(cms.get(), &der);
    if (len <= 0 || der == nullptr) {
        fail("i2d_CMS_ContentInfo failed");
    }
    std::vector<std::uint8_t> out(der, der + len);
    OPENSSL_free(der);
    return out;
}

} // namespace

std::vector<std::uint8_t> makeCsca(const std::string& commonName, const std::string& country)
{
    // The random suffix keeps two CSCAs minted in one test process from sharing
    // a subject DN, which would make a path lookup ambiguous.
    const Cert csca = makeCert({.commonName = commonName + " " + randomHex(4),
                                .country = country,
                                .ca = true,
                                .issuer = nullptr,
                                .keyUsage = "critical,keyCertSign,cRLSign",
                                .sameSubjectAndKeyAs = nullptr});
    std::vector<std::uint8_t> der = certDer(csca.x.get());
    remember(der, csca.key.get());
    return der;
}

std::vector<std::uint8_t> makeLinkCertificate(const std::vector<std::uint8_t>& outgoingCscaDer,
                                              const std::vector<std::uint8_t>& incomingCscaDer)
{
    const Cert outgoing = recall(outgoingCscaDer);
    const Cert incoming = recall(incomingCscaDer);
    const Cert link = makeCert({.commonName = {},
                                .country = {},
                                .ca = true,
                                .issuer = &outgoing,
                                .keyUsage = "critical,keyCertSign,cRLSign",
                                .sameSubjectAndKeyAs = &incoming});
    std::vector<std::uint8_t> der = certDer(link.x.get());
    // The SAME key under a second encoding, deliberately: a signer issued "from
    // the link certificate" is issued by the incoming CSCA, because they are
    // one key.
    remember(der, link.key.get());
    return der;
}

MasterListSigner makeIndependentSigner()
{
    // The signer's CA is NOT an anchor in any list. This is the property that
    // must not be relaxed: were every signer to chain into the list it signs,
    // an importer that verified a list against its own contents would pass.
    const Cert root = makeCert({.commonName = "Synthetic Master List CA " + randomHex(4),
                                .country = "XX",
                                .ca = true,
                                .issuer = nullptr,
                                .keyUsage = "critical,keyCertSign,cRLSign",
                                .sameSubjectAndKeyAs = nullptr});
    const Cert signer = makeCert({.commonName = "Synthetic Master List Signer " + randomHex(4),
                                  .country = "XX",
                                  .ca = false,
                                  .issuer = &root,
                                  .keyUsage = "critical,digitalSignature",
                                  .sameSubjectAndKeyAs = nullptr});
    MasterListSigner out;
    out.certificateDer = certDer(signer.x.get());
    remember(out.certificateDer, signer.key.get());
    return out;
}

MasterListSigner makeSignerIssuedBy(const std::vector<std::uint8_t>& issuerCscaDer)
{
    const Cert issuer = recall(issuerCscaDer);
    const Cert signer = makeCert({.commonName = "Synthetic Rotated Master List Signer " + randomHex(4),
                                  .country = "XX",
                                  .ca = false,
                                  .issuer = &issuer,
                                  .keyUsage = "critical,digitalSignature",
                                  .sameSubjectAndKeyAs = nullptr});
    MasterListSigner out;
    out.certificateDer = certDer(signer.x.get());
    remember(out.certificateDer, signer.key.get());
    return out;
}

namespace {

SyntheticMasterList buildSignedList(std::vector<std::vector<std::uint8_t>> anchors, const MasterListSigner& signer,
                                    std::optional<std::int64_t> signingTime)
{
    std::sort(anchors.begin(), anchors.end());
    const Cert signerCert = recall(signer.certificateDer);

    SyntheticMasterList out;
    out.der = signCms(signerCert, buildMasterListContent(anchors), kCscaMasterListOid, signingTime);
    out.anchors = std::move(anchors);
    out.signerSpkiSha256 = spkiSha256(signerCert.x.get());
    out.signerCertificateDer = signer.certificateDer;
    out.signingTime = signingTime;
    return out;
}

} // namespace

SyntheticMasterList signMasterList(std::vector<std::vector<std::uint8_t>> anchors, const MasterListSigner& signer)
{
    return buildSignedList(std::move(anchors), signer, std::nullopt);
}

SyntheticMasterList signMasterListDated(std::vector<std::vector<std::uint8_t>> anchors, const MasterListSigner& signer,
                                        std::int64_t signingTimeEpochSeconds)
{
    return buildSignedList(std::move(anchors), signer, signingTimeEpochSeconds);
}

namespace {

// RFC 4648 base64, which is what an LDIF `::` value carries.
std::string base64(const std::vector<std::uint8_t>& bytes)
{
    static constexpr char kAlphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    out.reserve(((bytes.size() + 2) / 3) * 4);
    std::size_t i = 0;
    for (; i + 3 <= bytes.size(); i += 3) {
        const std::uint32_t triple = (static_cast<std::uint32_t>(bytes[i]) << 16) |
                                     (static_cast<std::uint32_t>(bytes[i + 1]) << 8) |
                                     static_cast<std::uint32_t>(bytes[i + 2]);
        out.push_back(kAlphabet[(triple >> 18) & 0x3F]);
        out.push_back(kAlphabet[(triple >> 12) & 0x3F]);
        out.push_back(kAlphabet[(triple >> 6) & 0x3F]);
        out.push_back(kAlphabet[triple & 0x3F]);
    }
    if (i < bytes.size()) {
        const bool two = (bytes.size() - i) == 2;
        const std::uint32_t triple =
            (static_cast<std::uint32_t>(bytes[i]) << 16) | (two ? (static_cast<std::uint32_t>(bytes[i + 1]) << 8) : 0U);
        out.push_back(kAlphabet[(triple >> 18) & 0x3F]);
        out.push_back(kAlphabet[(triple >> 12) & 0x3F]);
        out.push_back(two ? kAlphabet[(triple >> 6) & 0x3F] : '=');
        out.push_back('=');
    }
    return out;
}

// One attribute line, FOLDED: RFC 2849 continues a logical line by starting the
// next physical one with a single space. The portal's file is folded, so a
// fixture that emitted one 1.7-megabyte line would be exercising a parser the
// real input never reaches.
void appendFolded(std::string& out, const std::string& description, const std::string& encoded)
{
    constexpr std::size_t kWidth = 78;
    std::string line = description + ":: ";
    std::size_t at = 0;
    while (at < encoded.size()) {
        const std::size_t room = kWidth - line.size();
        const std::size_t take = std::min(room, encoded.size() - at);
        line.append(encoded, at, take);
        at += take;
        out += line;
        out += "\n";
        line = " "; // the continuation marker, and the next line's first octet
    }
    if (line.size() > 1) {
        out += line;
        out += "\n";
    }
}

} // namespace

std::vector<std::uint8_t> makeLdifCollection(const std::vector<std::vector<std::uint8_t>>& lists,
                                             bool strayBase64Attribute)
{
    std::string out = "version: 1\n\n";
    out += "dn: dc=data,dc=download,dc=pkd,dc=icao,dc=int\n";
    out += "dc: data\n";
    out += "objectclass: top\n";
    out += "objectclass: domain\n\n";

    for (std::size_t i = 0; i < lists.size(); ++i) {
        char country[3] = {static_cast<char>('A' + static_cast<char>(i / 26)),
                           static_cast<char>('A' + static_cast<char>(i % 26)), '\0'};
        out += std::string{"dn: o=csca-ml,c="} + country + ",dc=data,dc=download,dc=pkd,dc=icao,dc=int\n";
        out += "objectclass: inetOrgPerson\n";
        out += std::string{"sn: "} + country + "\n";
        if (strayBase64Attribute) {
            // Base64, and NOT a signed object. The portal encodes its `cn` this
            // way whenever the value would otherwise need escaping.
            const std::string label = std::string{"CSCA Master List "} + country;
            out += "cn:: " + base64(std::vector<std::uint8_t>(label.begin(), label.end())) + "\n";
        }
        out += "pkdVersion: 528\n";
        appendFolded(out, "pkdMasterListContent;binary", base64(lists[i]));
        out += "\n";
    }
    return std::vector<std::uint8_t>(out.begin(), out.end());
}

std::vector<std::uint8_t> makeSignedNonMasterList()
{
    const MasterListSigner signer = makeIndependentSigner();
    const Cert signerCert = recall(signer.certificateDer);
    const std::vector<std::uint8_t> content{0x04, 0x03, 0x01, 0x02, 0x03};
    // Dated, because the date is beside the point here: what makes this object
    // interesting is the content type, and stripping an attribute it does not
    // need would only add a way for the fixture to fail.
    return signCms(signerCert, content, nullptr, kNotAMasterListSigningTime);
}

std::vector<std::uint8_t> tamperWithSignedContent(const SyntheticMasterList& list)
{
    if (list.anchors.empty()) {
        fail("tamperWithSignedContent needs a list carrying at least one anchor");
    }
    // CMS_BINARY plus a definite-length i2d embeds the eContent as one
    // contiguous OCTET STRING, so the signed bytes appear verbatim and can be
    // found. The flipped byte sits inside the first anchor, which keeps every
    // length unchanged: a byte flipped in a length would make the list
    // MALFORMED, and the test would then prove the wrong rejection.
    const std::vector<std::uint8_t> content = buildMasterListContent(list.anchors);
    const auto at = std::search(list.der.begin(), list.der.end(), content.begin(), content.end());
    if (at == list.der.end()) {
        fail("the signed content is not embedded in the CMS encoding");
    }
    std::vector<std::uint8_t> out = list.der;
    const auto offset = static_cast<std::size_t>(std::distance(list.der.begin(), at));
    // Well inside the first anchor's body, past every length octet at the head.
    out[offset + content.size() - 1] ^= 0x01;
    return out;
}

} // namespace LibreSCRS::Agent::Test
