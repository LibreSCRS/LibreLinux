// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Env-gated, libcrypto-LINKING faithful real-card crypto verification for the
// agent-proxy PKCS#11 module. SKIPPED unless LIBRESCRS_HW_SMOKE=1, so the normal
// suite NEVER touches a card. It dlopens the REAL built module against the REAL
// running agent against a REAL card over the live session bus and asserts
// CRYPTOGRAPHIC CORRECTNESS (not just SW=9000): a verifier must accept what the
// card produced, and a decrypt must reproduce the exact plaintext we encrypted.
//
// This is the deliberately SEPARATE companion to RealCardSmokeTest.cpp: that TU
// stays libcrypto-FREE (it mirrors the module's own no-crypto policy and only
// checks the operation is reachable + well-shaped); THIS TU links OpenSSL so it
// can do the real arithmetic. Keeping them apart preserves the smoke TU's
// no-libcrypto guarantee.
//
// WHAT IT PROVES (PKS / owner card):
//   1. DECRYPT round-trip — encrypt a known plaintext under the card's RSA
//      public key (read from CKA_MODULUS / CKA_PUBLIC_EXPONENT on the matching
//      public-key object whose private key carries CKA_DECRYPT — the ENC/kxc
//      key), then C_Decrypt (single-part AND multi-part) and assert the
//      recovered plaintext is byte-equal. This is the headline: PKS decrypt
//      works end to end through the proxy -> agent -> card.
//   2. SIGN + verify — C_Sign with raw CKM_RSA_PKCS over a complete SHA-256
//      DigestInfo (the only advertised mechanism), then EVP_PKEY_verify against
//      the public key. Must stay green after the hash-RSA combos were withdrawn.
//   3. C_SignInit(CKM_SHA256_RSA_PKCS) must be CKR_MECHANISM_INVALID — the
//      withdrawn combo is gone (the module is libcrypto-free; it cannot hash).
//
// CREDENTIAL SAFETY: the PIN/CAN are NEVER
// hardcoded and never touch this module (CKF_PROTECTED_AUTHENTICATION_PATH — the
// agent prompter is the only PIN sink). On the FIRST not-OK login/sign/decrypt a
// process-global g_pinFailed latches and every later test SKIPs — no retry storm
// that could burn the card's irreversible counter.
//
// Manual run (PKS, contact, PIN — slot 0 is the owner card):
//   LIBRESCRS_HW_SMOKE=1 \
//   LIBRESCRS_SMOKE_MODULE=$PREFIX/lib/pkcs11/librescrs-pkcs11-agent.so \
//   ctest --test-dir build -R RealCardCryptoVerify --output-on-failure

#include "pkcs11.h"

#include <dlfcn.h>
#include <gtest/gtest.h>

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <openssl/rsa.h>

#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

namespace {

bool g_pinFailed = false;

bool hwEnabled()
{
    const char* v = std::getenv("LIBRESCRS_HW_SMOKE");
    return v && std::string(v) == "1";
}

#define SKIP_IF_NO_HW()                                                                                                \
    do {                                                                                                               \
        if (!hwEnabled())                                                                                              \
            GTEST_SKIP() << "set LIBRESCRS_HW_SMOKE=1 (+ a live agent/prompter + a card) to run";                      \
    } while (0)

#define SKIP_IF_PIN_FAILED()                                                                                           \
    do {                                                                                                               \
        if (g_pinFailed)                                                                                               \
            GTEST_SKIP() << "a prior PIN/login attempt failed; skipping to protect the card retry counter";            \
    } while (0)

const char* moduleP11Path()
{
    if (const char* env = std::getenv("LIBRESCRS_SMOKE_MODULE"))
        return env;
    return LIBRESCRS_PKCS11_MODULE_PATH; // the just-built .so
}

struct LoadedModule
{
    void* handle = nullptr;
    CK_FUNCTION_LIST_PTR fn = nullptr;

    LoadedModule()
    {
        handle = dlopen(moduleP11Path(), RTLD_NOW | RTLD_LOCAL);
        if (!handle)
            return;
        auto getList = reinterpret_cast<CK_C_GetFunctionList>(dlsym(handle, "C_GetFunctionList"));
        if (getList)
            getList(&fn);
    }
    ~LoadedModule()
    {
        if (fn)
            fn->C_Finalize(nullptr);
        if (handle)
            dlclose(handle);
    }
};

bool firstPresentSlot(CK_FUNCTION_LIST_PTR fn, CK_SLOT_ID* out)
{
    CK_SLOT_ID slots[16];
    CK_ULONG n = 16;
    if (fn->C_GetSlotList(CK_TRUE, slots, &n) != CKR_OK || n == 0)
        return false;
    *out = slots[0];
    return true;
}

// True if the token in @p slot advertises CKM_RSA_PKCS (a PKS DigestInfo token;
// a hash-on-card NAM advertises CKM_SHA256_RSA_PKCS instead).
bool tokenAdvertisesRsaPkcs(CK_FUNCTION_LIST_PTR fn, CK_SLOT_ID slot)
{
    CK_MECHANISM_TYPE mechs[32];
    CK_ULONG mn = 32;
    if (fn->C_GetMechanismList(slot, mechs, &mn) != CKR_OK)
        return false;
    for (CK_ULONG i = 0; i < mn; ++i)
        if (mechs[i] == CKM_RSA_PKCS)
            return true;
    return false;
}

// All private-key handles in the session.
std::vector<CK_OBJECT_HANDLE> findPrivateKeys(CK_FUNCTION_LIST_PTR fn, CK_SESSION_HANDLE session)
{
    CK_OBJECT_CLASS cls = CKO_PRIVATE_KEY;
    CK_ATTRIBUTE tmpl[] = {{CKA_CLASS, &cls, sizeof(cls)}};
    std::vector<CK_OBJECT_HANDLE> out;
    if (fn->C_FindObjectsInit(session, tmpl, 1) != CKR_OK)
        return out;
    CK_OBJECT_HANDLE objs[16];
    CK_ULONG n = 0;
    if (fn->C_FindObjects(session, objs, 16, &n) == CKR_OK)
        out.assign(objs, objs + n);
    fn->C_FindObjectsFinal(session);
    return out;
}

// Read a CK_BBOOL attribute; defaults to CK_FALSE if absent.
bool boolAttr(CK_FUNCTION_LIST_PTR fn, CK_SESSION_HANDLE session, CK_OBJECT_HANDLE obj, CK_ATTRIBUTE_TYPE type)
{
    CK_BBOOL v = CK_FALSE;
    CK_ATTRIBUTE a[] = {{type, &v, sizeof(v)}};
    if (fn->C_GetAttributeValue(session, obj, a, 1) != CKR_OK)
        return false;
    return v == CK_TRUE;
}

// Read a variable-length byte attribute (CKA_ID / CKA_MODULUS / ...).
std::vector<std::uint8_t> bytesAttr(CK_FUNCTION_LIST_PTR fn, CK_SESSION_HANDLE session, CK_OBJECT_HANDLE obj,
                                    CK_ATTRIBUTE_TYPE type)
{
    CK_ATTRIBUTE a[] = {{type, nullptr, 0}};
    if (fn->C_GetAttributeValue(session, obj, a, 1) != CKR_OK || a[0].ulValueLen == CK_UNAVAILABLE_INFORMATION)
        return {};
    std::vector<std::uint8_t> buf(a[0].ulValueLen);
    a[0].pValue = buf.data();
    if (fn->C_GetAttributeValue(session, obj, a, 1) != CKR_OK)
        return {};
    buf.resize(a[0].ulValueLen);
    return buf;
}

// The public-key object whose CKA_ID matches @p ckaId (pairs with the private key).
CK_OBJECT_HANDLE publicKeyForId(CK_FUNCTION_LIST_PTR fn, CK_SESSION_HANDLE session,
                                const std::vector<std::uint8_t>& ckaId)
{
    CK_OBJECT_CLASS cls = CKO_PUBLIC_KEY;
    CK_ATTRIBUTE tmpl[] = {{CKA_CLASS, &cls, sizeof(cls)},
                           {CKA_ID, const_cast<std::uint8_t*>(ckaId.data()), static_cast<CK_ULONG>(ckaId.size())}};
    if (fn->C_FindObjectsInit(session, tmpl, 2) != CKR_OK)
        return CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE objs[4];
    CK_ULONG n = 0;
    fn->C_FindObjects(session, objs, 4, &n);
    fn->C_FindObjectsFinal(session);
    return n > 0 ? objs[0] : CK_INVALID_HANDLE;
}

// Build an OpenSSL RSA EVP_PKEY from a big-endian modulus + exponent.
EVP_PKEY* makeRsaPubKey(const std::vector<std::uint8_t>& mod, const std::vector<std::uint8_t>& exp)
{
    BIGNUM* n = BN_bin2bn(mod.data(), static_cast<int>(mod.size()), nullptr);
    BIGNUM* e = BN_bin2bn(exp.data(), static_cast<int>(exp.size()), nullptr);
    if (!n || !e) {
        BN_free(n);
        BN_free(e);
        return nullptr;
    }
    OSSL_PARAM_BLD* bld = OSSL_PARAM_BLD_new();
    EVP_PKEY* pkey = nullptr;
    if (bld && OSSL_PARAM_BLD_push_BN(bld, "n", n) && OSSL_PARAM_BLD_push_BN(bld, "e", e)) {
        OSSL_PARAM* params = OSSL_PARAM_BLD_to_param(bld);
        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_name(nullptr, "RSA", nullptr);
        if (ctx && params) {
            if (EVP_PKEY_fromdata_init(ctx) <= 0 || EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_PUBLIC_KEY, params) <= 0)
                pkey = nullptr;
        }
        OSSL_PARAM_free(params);
        EVP_PKEY_CTX_free(ctx);
    }
    OSSL_PARAM_BLD_free(bld);
    BN_free(n);
    BN_free(e);
    return pkey;
}

// RSA PKCS#1 v1.5 public-key encrypt of @p plain under @p pkey.
std::vector<std::uint8_t> rsaEncryptPkcs1(EVP_PKEY* pkey, const std::vector<std::uint8_t>& plain)
{
    std::vector<std::uint8_t> out;
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, nullptr);
    if (!ctx)
        return out;
    if (EVP_PKEY_encrypt_init(ctx) > 0 && EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) > 0) {
        std::size_t len = 0;
        if (EVP_PKEY_encrypt(ctx, nullptr, &len, plain.data(), plain.size()) > 0) {
            out.resize(len);
            if (EVP_PKEY_encrypt(ctx, out.data(), &len, plain.data(), plain.size()) > 0)
                out.resize(len);
            else
                out.clear();
        }
    }
    EVP_PKEY_CTX_free(ctx);
    return out;
}

} // namespace

// PKS DECRYPT round-trip (the headline): encrypt a known plaintext under the
// card's ENC/kxc public key (the CKA_DECRYPT key), then C_Decrypt single-part AND
// multi-part through the proxy -> agent -> card and assert byte-equal recovery.
TEST(RealCardCryptoVerify, PksDecryptRoundTripByteEqual)
{
    SKIP_IF_NO_HW();
    SKIP_IF_PIN_FAILED();
    LoadedModule m;
    ASSERT_NE(m.fn, nullptr);
    ASSERT_EQ(m.fn->C_Initialize(nullptr), CKR_OK);

    CK_SLOT_ID slot = 0;
    ASSERT_TRUE(firstPresentSlot(m.fn, &slot)) << "no present token";
    if (!tokenAdvertisesRsaPkcs(m.fn, slot))
        GTEST_SKIP()
            << "token advertises no CKM_RSA_PKCS (e.g. a hash-on-card NAM token offers CKM_SHA256_RSA_PKCS instead)";

    CK_SESSION_HANDLE session = 0;
    ASSERT_EQ(m.fn->C_OpenSession(slot, CKF_SERIAL_SESSION, nullptr, nullptr, &session), CKR_OK);

    // Find the private key that carries CKA_DECRYPT (the ENC/kxc key, id 01).
    CK_OBJECT_HANDLE decKey = CK_INVALID_HANDLE;
    std::vector<std::uint8_t> decId;
    for (CK_OBJECT_HANDLE k : findPrivateKeys(m.fn, session)) {
        if (boolAttr(m.fn, session, k, CKA_DECRYPT)) {
            decKey = k;
            decId = bytesAttr(m.fn, session, k, CKA_ID);
            break;
        }
    }
    ASSERT_NE(decKey, CK_INVALID_HANDLE) << "no private key with CKA_DECRYPT (the ENC/kxc key)";

    // Read its public modulus + exponent from the paired public-key object.
    CK_OBJECT_HANDLE pub = publicKeyForId(m.fn, session, decId);
    ASSERT_NE(pub, CK_INVALID_HANDLE) << "no public key paired with the decrypt key's CKA_ID";
    auto mod = bytesAttr(m.fn, session, pub, CKA_MODULUS);
    auto exp = bytesAttr(m.fn, session, pub, CKA_PUBLIC_EXPONENT);
    ASSERT_FALSE(mod.empty());
    ASSERT_FALSE(exp.empty());

    EVP_PKEY* pkey = makeRsaPubKey(mod, exp);
    ASSERT_NE(pkey, nullptr) << "could not build the RSA public key from CKA_MODULUS/EXP";

    // A fixed known plaintext + the ciphertext we will ask the card to recover.
    const std::vector<std::uint8_t> plaintext = {'L',  'i',  'b',  'r',  'e',  'S',  'C',  'R',  'S',  '-',
                                                 'd',  'e',  'c',  'r',  'y',  'p',  't',  '-',  'r',  't',
                                                 0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x42, 0x99, 0x01, 0x7F, 0x10};
    const std::vector<std::uint8_t> ct = rsaEncryptPkcs1(pkey, plaintext);
    EVP_PKEY_free(pkey);
    ASSERT_FALSE(ct.empty()) << "host-side RSA PKCS#1 encrypt failed";

    // Login (prompter is the auth path). Latch on any auth failure.
    const CK_RV loginRv = m.fn->C_Login(session, CKU_USER, nullptr, 0);
    if (loginRv != CKR_OK) {
        g_pinFailed = true;
        FAIL() << "C_Login failed (rv=" << loginRv << "); latching to protect the card";
    }

    // --- single-part C_Decrypt ---------------------------------------------
    CK_MECHANISM dmech{CKM_RSA_PKCS, nullptr, 0};
    ASSERT_EQ(m.fn->C_DecryptInit(session, &dmech, decKey), CKR_OK);
    CK_BYTE out[1024];
    CK_ULONG outLen = sizeof(out);
    const CK_RV decRv =
        m.fn->C_Decrypt(session, const_cast<CK_BYTE*>(ct.data()), static_cast<CK_ULONG>(ct.size()), out, &outLen);
    if (decRv == CKR_PIN_INCORRECT) {
        g_pinFailed = true;
        FAIL() << "C_Decrypt auth failure; latching to protect the card";
    }
    ASSERT_EQ(decRv, CKR_OK) << "single-part C_Decrypt failed (rv=" << decRv << ")";
    std::vector<std::uint8_t> got(out, out + outLen);
    EXPECT_EQ(got, plaintext) << "single-part decrypt did not reproduce the plaintext byte-for-byte";

    // --- multi-part C_DecryptUpdate + C_DecryptFinal ------------------------
    ASSERT_EQ(m.fn->C_DecryptInit(session, &dmech, decKey), CKR_OK);
    const CK_ULONG half = static_cast<CK_ULONG>(ct.size() / 2);
    CK_BYTE upd[1024];
    CK_ULONG updLen = sizeof(upd);
    ASSERT_EQ(m.fn->C_DecryptUpdate(session, const_cast<CK_BYTE*>(ct.data()), half, upd, &updLen), CKR_OK);
    updLen = sizeof(upd);
    ASSERT_EQ(m.fn->C_DecryptUpdate(session, const_cast<CK_BYTE*>(ct.data()) + half,
                                    static_cast<CK_ULONG>(ct.size()) - half, upd, &updLen),
              CKR_OK);
    CK_BYTE fin[1024];
    CK_ULONG finLen = sizeof(fin);
    const CK_RV finRv = m.fn->C_DecryptFinal(session, fin, &finLen);
    ASSERT_EQ(finRv, CKR_OK) << "multi-part C_DecryptFinal failed (rv=" << finRv << ")";
    std::vector<std::uint8_t> gotMulti(fin, fin + finLen);
    EXPECT_EQ(gotMulti, plaintext) << "multi-part decrypt did not reproduce the plaintext byte-for-byte";
}

// PKS SIGN + verify: C_Sign raw CKM_RSA_PKCS over a SHA-256 DigestInfo, then
// EVP_PKEY_verify against the public key. Must stay green after withdrawing the
// hash-RSA combos.
TEST(RealCardCryptoVerify, PksSignRsaPkcsVerifies)
{
    SKIP_IF_NO_HW();
    SKIP_IF_PIN_FAILED();
    LoadedModule m;
    ASSERT_NE(m.fn, nullptr);
    ASSERT_EQ(m.fn->C_Initialize(nullptr), CKR_OK);

    CK_SLOT_ID slot = 0;
    ASSERT_TRUE(firstPresentSlot(m.fn, &slot));
    if (!tokenAdvertisesRsaPkcs(m.fn, slot))
        GTEST_SKIP()
            << "token advertises no CKM_RSA_PKCS (e.g. a hash-on-card NAM token offers CKM_SHA256_RSA_PKCS instead)";

    CK_SESSION_HANDLE session = 0;
    ASSERT_EQ(m.fn->C_OpenSession(slot, CKF_SERIAL_SESSION, nullptr, nullptr, &session), CKR_OK);

    // Prefer the CKA_SIGN key; fall back to any private key (PKS keys all sign).
    CK_OBJECT_HANDLE signKey = CK_INVALID_HANDLE;
    std::vector<std::uint8_t> signId;
    for (CK_OBJECT_HANDLE k : findPrivateKeys(m.fn, session)) {
        if (boolAttr(m.fn, session, k, CKA_SIGN)) {
            signKey = k;
            signId = bytesAttr(m.fn, session, k, CKA_ID);
            break;
        }
    }
    ASSERT_NE(signKey, CK_INVALID_HANDLE) << "no private key with CKA_SIGN";

    CK_OBJECT_HANDLE pub = publicKeyForId(m.fn, session, signId);
    ASSERT_NE(pub, CK_INVALID_HANDLE);
    auto mod = bytesAttr(m.fn, session, pub, CKA_MODULUS);
    auto exp = bytesAttr(m.fn, session, pub, CKA_PUBLIC_EXPONENT);
    ASSERT_FALSE(mod.empty());
    ASSERT_FALSE(exp.empty());

    // The message + its real SHA-256 digest, wrapped in a complete DigestInfo —
    // exactly what a CKM_RSA_PKCS caller supplies.
    const std::vector<std::uint8_t> message = {'h', 'e', 'l', 'l', 'o', '-', 'p', 'k', 's'};
    std::uint8_t digest[EVP_MAX_MD_SIZE];
    unsigned int digestLen = 0;
    ASSERT_EQ(EVP_Digest(message.data(), message.size(), digest, &digestLen, EVP_sha256(), nullptr), 1);
    std::vector<std::uint8_t> digestInfo = {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
                                            0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20};
    digestInfo.insert(digestInfo.end(), digest, digest + digestLen);

    const CK_RV loginRv = m.fn->C_Login(session, CKU_USER, nullptr, 0);
    if (loginRv != CKR_OK) {
        g_pinFailed = true;
        FAIL() << "C_Login failed (rv=" << loginRv << "); latching to protect the card";
    }

    CK_MECHANISM mech{CKM_RSA_PKCS, nullptr, 0};
    ASSERT_EQ(m.fn->C_SignInit(session, &mech, signKey), CKR_OK);
    CK_BYTE sig[1024];
    CK_ULONG sigLen = sizeof(sig);
    const CK_RV signRv =
        m.fn->C_Sign(session, digestInfo.data(), static_cast<CK_ULONG>(digestInfo.size()), sig, &sigLen);
    if (signRv == CKR_PIN_INCORRECT || signRv == CKR_FUNCTION_FAILED) {
        g_pinFailed = true;
        FAIL() << "C_Sign auth failure (rv=" << signRv << "); latching to protect the card";
    }
    ASSERT_EQ(signRv, CKR_OK);

    // Verify the signature against the public key: SHA-256 PKCS#1 v1.5 over the
    // original message. A faithful crypto check, not a SW=9000 rubber stamp.
    EVP_PKEY* pkey = makeRsaPubKey(mod, exp);
    ASSERT_NE(pkey, nullptr);
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    ASSERT_NE(ctx, nullptr);
    ASSERT_EQ(EVP_DigestVerifyInit(ctx, nullptr, EVP_sha256(), nullptr, pkey), 1);
    const int vr = EVP_DigestVerify(ctx, sig, sigLen, message.data(), message.size());
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    EXPECT_EQ(vr, 1) << "EVP_DigestVerify rejected the card's RSA PKCS#1 signature";
}

// The withdrawn hash-RSA combo must be rejected: the module is libcrypto-free and
// cannot hash, so it advertises only raw CKM_RSA_PKCS.
TEST(RealCardCryptoVerify, SignInitSha256RsaPkcsIsMechanismInvalid)
{
    SKIP_IF_NO_HW();
    LoadedModule m;
    ASSERT_NE(m.fn, nullptr);
    ASSERT_EQ(m.fn->C_Initialize(nullptr), CKR_OK);

    CK_SLOT_ID slot = 0;
    ASSERT_TRUE(firstPresentSlot(m.fn, &slot));
    if (!tokenAdvertisesRsaPkcs(m.fn, slot))
        GTEST_SKIP()
            << "token advertises no CKM_RSA_PKCS (e.g. a hash-on-card NAM token offers CKM_SHA256_RSA_PKCS instead)";

    CK_SESSION_HANDLE session = 0;
    ASSERT_EQ(m.fn->C_OpenSession(slot, CKF_SERIAL_SESSION, nullptr, nullptr, &session), CKR_OK);
    auto keys = findPrivateKeys(m.fn, session);
    ASSERT_FALSE(keys.empty());

    CK_MECHANISM mech{CKM_SHA256_RSA_PKCS, nullptr, 0};
    EXPECT_EQ(m.fn->C_SignInit(session, &mech, keys[0]), CKR_MECHANISM_INVALID);
}
