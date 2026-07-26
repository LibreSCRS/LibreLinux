// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Pure mapping tests: an agent snapshot (readers/cards/certs + per-cert
// capability flags) -> PKCS#11 slots/tokens/objects/mechanisms. No D-Bus.
//
// The mechanism table is CAPABILITY-ADVERTISED, never card-type-hardcoded:
//  - a PKS-style token (certs with signingCapable + canDecrypt) advertises
//    ONLY raw CKM_RSA_PKCS (covering both sign and decrypt) — the combined
//    CKM_SHAxxx_RSA_PKCS mechanisms are NOT advertised because the
//    libcrypto-free module cannot compute the digest they require;
//  - a NAM-style hash-on-card token (canSign + signsHashOnCard, decrypt off)
//    advertises ONLY the combined CKM_SHA256_RSA_PKCS sign mechanism (the card
//    computes the digest from the raw message) and its key carries CKA_SIGN but
//    not CKA_DECRYPT;
//  - a fully capability-gated token (canSign == canDecrypt == false) advertises
//    NO mechanisms and its key carries neither CKA_SIGN nor CKA_DECRYPT.
// PSS / ECDSA are never advertised (SR cards are RSA PKCS#1 v1.5 only).

#include "ObjectModel.h"
#include "pkcs11.h"

#include <algorithm>
#include <gtest/gtest.h>

using namespace LibreSCRS::Pkcs11Agent;

namespace {

AgentSnapshot oneCardOneCert()
{
    ReaderState r;
    r.readerPath = "/org/librescrs/Agent/reader/0";
    r.hasCard = true;
    r.tokenLabel = "LibreSCRS PKS";
    CertEntry c;
    c.certId = "abc123";
    c.label = "Sign";
    c.ckaId = {0x01};
    c.signingCapable = true;
    c.canSign = true;    // PKS: CardPlugin::sign works
    c.canDecrypt = true; // PKS: CardPlugin::decipher works (keyUsage permits)
    c.modulusBits = 2048;
    r.certs.push_back(c);
    return AgentSnapshot{.readers = {r}};
}

// NAM-style hash-on-card SSCD (IAS-ECC): the agent drives on-card SHA-256 RSA
// signing (canSign + signsHashOnCard) but decrypt is not supported (no on-card
// MSE-CT/PSO-DECIPHER). The card computes the digest, so the proxy advertises
// CKM_SHA256_RSA_PKCS (sign-only), not the DigestInfo CKM_RSA_PKCS.
AgentSnapshot namCard()
{
    ReaderState r;
    r.readerPath = "/org/librescrs/Agent/reader/1";
    r.hasCard = true;
    r.tokenLabel = "LibreSCRS NAM";
    CertEntry c;
    c.certId = "nam999";
    c.label = "Qualified Signature";
    c.ckaId = {0x02};
    c.signingCapable = true;
    c.canSign = true;         // the agent supplies the eSign PIN + drives on-card sign
    c.signsHashOnCard = true; // IAS-ECC hashes the raw message on-card
    c.canDecrypt = false;     // decrypt is not supported on this card
    c.modulusBits = 3072;
    r.certs.push_back(c);
    return AgentSnapshot{.readers = {r}};
}

// A capability-gated card: a signing cert is present, but the agent can drive
// NEITHER on-card sign nor decrypt (canSign == canDecrypt == false). Fail-closed:
// no mechanisms, and a key with neither CKA_SIGN nor CKA_DECRYPT.
AgentSnapshot gatedCard()
{
    AgentSnapshot s = namCard();
    s.readers[0].certs[0].canSign = false;
    s.readers[0].certs[0].signsHashOnCard = false;
    s.readers[0].certs[0].canDecrypt = false;
    return s;
}

bool hasMech(const std::vector<CK_MECHANISM_TYPE>& mechs, CK_MECHANISM_TYPE t)
{
    return std::find(mechs.begin(), mechs.end(), t) != mechs.end();
}

} // namespace

TEST(ObjectModel, SlotPerReaderTokenPresentWhenCard)
{
    auto m = ObjectModel::build(oneCardOneCert());
    ASSERT_EQ(m.slots.size(), 1u);
    EXPECT_TRUE(m.slots[0].tokenPresent);
    EXPECT_TRUE(m.slots[0].protectedAuthPath); // CKF_PROTECTED_AUTHENTICATION_PATH
    EXPECT_EQ(m.slots[0].readerPath, "/org/librescrs/Agent/reader/0");
}

TEST(ObjectModel, ThreeObjectsPerSigningCert)
{
    auto m = ObjectModel::build(oneCardOneCert());
    ASSERT_EQ(m.slots.size(), 1u);
    const auto& objs = m.slots[0].objects;
    int cert = 0, pub = 0, priv = 0;
    for (const auto& o : objs) {
        if (o.cls == CKO_CERTIFICATE) {
            ++cert;
            EXPECT_EQ(o.ckaId, std::vector<std::uint8_t>{0x01});
        }
        if (o.cls == CKO_PUBLIC_KEY)
            ++pub;
        if (o.cls == CKO_PRIVATE_KEY) {
            ++priv;
            EXPECT_TRUE(o.sign);
            EXPECT_TRUE(o.decrypt);
            EXPECT_EQ(o.ckaId, std::vector<std::uint8_t>{0x01});
            EXPECT_EQ(o.certId, "abc123");
        }
    }
    EXPECT_EQ(cert, 1);
    EXPECT_EQ(pub, 1);
    EXPECT_EQ(priv, 1);
}

TEST(ObjectModel, MechanismsAreRawRsaPkcsOnly_NoHashCombosNoPssNoEcdsa)
{
    auto m = ObjectModel::build(oneCardOneCert());
    const auto& mechs = m.slots[0].mechanisms;
    EXPECT_TRUE(hasMech(mechs, CKM_RSA_PKCS));
    // The combined hash-RSA mechanisms are NOT advertised: the libcrypto-free
    // module cannot hash, so it would sign a never-hashed message no verifier
    // accepts. Callers supply a complete DigestInfo to CKM_RSA_PKCS instead.
    EXPECT_FALSE(hasMech(mechs, CKM_SHA256_RSA_PKCS));
    EXPECT_FALSE(hasMech(mechs, CKM_SHA384_RSA_PKCS));
    EXPECT_FALSE(hasMech(mechs, CKM_SHA512_RSA_PKCS));
    EXPECT_FALSE(hasMech(mechs, CKM_RSA_PKCS_PSS)); // SR cards do not advertise PSS
    EXPECT_FALSE(hasMech(mechs, CKM_ECDSA));        // SR cards are RSA-only
    // Exactly one advertised mechanism.
    EXPECT_EQ(mechs.size(), 1u);
}

TEST(ObjectModel, NoTokenWhenNoCard)
{
    AgentSnapshot s = oneCardOneCert();
    s.readers[0].hasCard = false;
    s.readers[0].certs.clear();
    auto m = ObjectModel::build(s);
    ASSERT_EQ(m.slots.size(), 1u);
    EXPECT_FALSE(m.slots[0].tokenPresent);
    EXPECT_TRUE(m.slots[0].objects.empty());
    EXPECT_TRUE(m.slots[0].mechanisms.empty());
}

// ---- NAM: hash-on-card sign-only (decrypt gated) ---------------------------

TEST(ObjectModel, NamHashOnCardTokenAdvertisesSha256RsaPkcsSignOnly)
{
    auto m = ObjectModel::build(namCard());
    ASSERT_EQ(m.slots.size(), 1u);
    EXPECT_TRUE(m.slots[0].tokenPresent);
    const auto& mechs = m.slots[0].mechanisms;
    // The card hashes on-card, so the proxy offers the combined
    // CKM_SHA256_RSA_PKCS (sign-only) and NOT the DigestInfo CKM_RSA_PKCS.
    EXPECT_EQ(mechs.size(), 1u);
    EXPECT_TRUE(hasMech(mechs, CKM_SHA256_RSA_PKCS));
    EXPECT_FALSE(hasMech(mechs, CKM_RSA_PKCS));
}

TEST(ObjectModel, NamPrivateKeyObjectSignsButDoesNotDecrypt)
{
    auto m = ObjectModel::build(namCard());
    ASSERT_EQ(m.slots.size(), 1u);
    bool sawPriv = false;
    for (const auto& o : m.slots[0].objects) {
        if (o.cls == CKO_PRIVATE_KEY) {
            sawPriv = true;
            EXPECT_TRUE(o.sign) << "NAM key signs on-card";
            EXPECT_FALSE(o.decrypt) << "NAM key does not decrypt";
        }
    }
    EXPECT_TRUE(sawPriv);
}

TEST(ObjectModel, FullyGatedTokenAdvertisesNoMechanismsNorKeyFlags)
{
    auto m = ObjectModel::build(gatedCard());
    ASSERT_EQ(m.slots.size(), 1u);
    EXPECT_TRUE(m.slots[0].tokenPresent);
    EXPECT_TRUE(m.slots[0].mechanisms.empty()) << "a card the agent cannot drive advertises nothing";
    bool sawPriv = false;
    for (const auto& o : m.slots[0].objects) {
        if (o.cls == CKO_PRIVATE_KEY) {
            sawPriv = true;
            EXPECT_FALSE(o.sign);
            EXPECT_FALSE(o.decrypt);
        }
    }
    // The cert + public key + a capability-less private key are still present.
    EXPECT_TRUE(sawPriv);
}

TEST(ObjectModel, SignOnlyCardOmitsDecryptMechanism)
{
    // A card whose key signs but cannot decrypt (keyUsage without
    // dataEncipherment) advertises CKM_RSA_PKCS sign but the key has no
    // CKA_DECRYPT. The mechanism CKM_RSA_PKCS still appears (it covers sign);
    // CKA_DECRYPT on the key is what gates decrypt per-object.
    AgentSnapshot s = oneCardOneCert();
    s.readers[0].certs[0].canDecrypt = false;
    auto m = ObjectModel::build(s);
    const auto& mechs = m.slots[0].mechanisms;
    EXPECT_TRUE(hasMech(mechs, CKM_RSA_PKCS));
    for (const auto& o : m.slots[0].objects) {
        if (o.cls == CKO_PRIVATE_KEY) {
            EXPECT_TRUE(o.sign);
            EXPECT_FALSE(o.decrypt);
        }
    }
}

TEST(ObjectModel, NonSigningCertProducesNoKeyObjects)
{
    // A cert without a usable signing key (signingCapable=false) yields no
    // PKCS#11 objects (the proxy only surfaces signing certs).
    AgentSnapshot s = oneCardOneCert();
    s.readers[0].certs[0].signingCapable = false;
    auto m = ObjectModel::build(s);
    EXPECT_TRUE(m.slots[0].objects.empty());
}
