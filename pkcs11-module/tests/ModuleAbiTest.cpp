// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Drive the full C_* ABI of the built module against a fake agent on a private
// session bus (dbus-run-session). The module connects to the same session bus
// the fake claims, so dlopen + C_Initialize wires them together.

#include "FakeAgent.h"
#include "pkcs11.h"

#include <dlfcn.h>
#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <future>
#include <string>
#include <thread>
#include <vector>

using namespace librescrs_pkcs11_testfake;

namespace {

struct LoadedModule
{
    void* handle = nullptr;
    CK_FUNCTION_LIST_PTR fn = nullptr;

    LoadedModule()
    {
        handle = dlopen(LIBRESCRS_PKCS11_MODULE_PATH, RTLD_NOW | RTLD_LOCAL);
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

// Find the single private-key object on the slot's first session.
CK_OBJECT_HANDLE findPrivateKey(CK_FUNCTION_LIST_PTR fn, CK_SESSION_HANDLE session)
{
    CK_OBJECT_CLASS cls = CKO_PRIVATE_KEY;
    CK_ATTRIBUTE tmpl[] = {{CKA_CLASS, &cls, sizeof(cls)}};
    EXPECT_EQ(fn->C_FindObjectsInit(session, tmpl, 1), CKR_OK);
    CK_OBJECT_HANDLE objs[8];
    CK_ULONG n = 0;
    EXPECT_EQ(fn->C_FindObjects(session, objs, 8, &n), CKR_OK);
    EXPECT_EQ(fn->C_FindObjectsFinal(session), CKR_OK);
    return n > 0 ? objs[0] : CK_INVALID_HANDLE;
}

CK_SLOT_ID firstPresentSlot(CK_FUNCTION_LIST_PTR fn)
{
    CK_SLOT_ID slots[8];
    CK_ULONG n = 8;
    EXPECT_EQ(fn->C_GetSlotList(CK_TRUE, slots, &n), CKR_OK);
    EXPECT_GE(n, 1u);
    return slots[0];
}

CK_OBJECT_HANDLE findOne(CK_FUNCTION_LIST_PTR fn, CK_SESSION_HANDLE session, CK_OBJECT_CLASS cls)
{
    CK_ATTRIBUTE tmpl[] = {{CKA_CLASS, &cls, sizeof(cls)}};
    EXPECT_EQ(fn->C_FindObjectsInit(session, tmpl, 1), CKR_OK);
    CK_OBJECT_HANDLE objs[8];
    CK_ULONG n = 0;
    EXPECT_EQ(fn->C_FindObjects(session, objs, 8, &n), CKR_OK);
    EXPECT_EQ(fn->C_FindObjectsFinal(session), CKR_OK);
    return n > 0 ? objs[0] : CK_INVALID_HANDLE;
}

} // namespace

TEST(ModuleAbi, GetTokenInfoReportsProtectedAuthPathAndPresent)
{
    BusFixture bus;
    LoadedModule m;
    ASSERT_NE(m.fn, nullptr);
    ASSERT_EQ(m.fn->C_Initialize(nullptr), CKR_OK);

    CK_SLOT_ID slot = firstPresentSlot(m.fn);
    CK_TOKEN_INFO ti{};
    ASSERT_EQ(m.fn->C_GetTokenInfo(slot, &ti), CKR_OK);
    EXPECT_TRUE(ti.flags & CKF_PROTECTED_AUTHENTICATION_PATH);
    EXPECT_TRUE(ti.flags & CKF_LOGIN_REQUIRED);

    CK_SLOT_INFO si{};
    ASSERT_EQ(m.fn->C_GetSlotInfo(slot, &si), CKR_OK);
    EXPECT_TRUE(si.flags & CKF_TOKEN_PRESENT);
}

TEST(ModuleAbi, MechanismListHasRawRsaPkcsOnly_NoHashCombosNoPss)
{
    BusFixture bus;
    LoadedModule m;
    ASSERT_EQ(m.fn->C_Initialize(nullptr), CKR_OK);
    CK_SLOT_ID slot = firstPresentSlot(m.fn);

    CK_MECHANISM_TYPE mechs[16];
    CK_ULONG n = 16;
    ASSERT_EQ(m.fn->C_GetMechanismList(slot, mechs, &n), CKR_OK);
    bool rsa = false, sha256 = false, pss = false;
    for (CK_ULONG i = 0; i < n; ++i) {
        if (mechs[i] == CKM_RSA_PKCS)
            rsa = true;
        if (mechs[i] == CKM_SHA256_RSA_PKCS)
            sha256 = true;
        if (mechs[i] == CKM_RSA_PKCS_PSS)
            pss = true;
    }
    EXPECT_TRUE(rsa);
    EXPECT_FALSE(sha256) << "the libcrypto-free module must not advertise hash-RSA combos";
    EXPECT_FALSE(pss);
    EXPECT_EQ(n, 1u) << "only raw CKM_RSA_PKCS is advertised";

    // The withdrawn combos report CKR_MECHANISM_INVALID from C_GetMechanismInfo.
    CK_MECHANISM_INFO info{};
    EXPECT_EQ(m.fn->C_GetMechanismInfo(slot, CKM_SHA256_RSA_PKCS, &info), CKR_MECHANISM_INVALID);
    ASSERT_EQ(m.fn->C_GetMechanismInfo(slot, CKM_RSA_PKCS, &info), CKR_OK);
    EXPECT_TRUE(info.flags & CKF_SIGN);
    EXPECT_TRUE(info.flags & CKF_DECRYPT);
}

TEST(ModuleAbi, FindAttributesLoginSignDecryptFlow)
{
    BusFixture bus;
    LoadedModule m;
    ASSERT_EQ(m.fn->C_Initialize(nullptr), CKR_OK);
    CK_SLOT_ID slot = firstPresentSlot(m.fn);

    CK_SESSION_HANDLE session = 0;
    ASSERT_EQ(m.fn->C_OpenSession(slot, CKF_SERIAL_SESSION, nullptr, nullptr, &session), CKR_OK);

    CK_OBJECT_HANDLE key = findPrivateKey(m.fn, session);
    ASSERT_NE(key, CK_INVALID_HANDLE);

    // CKA_CLASS + CKA_ID + CKA_SIGN.
    CK_OBJECT_CLASS cls = 0;
    CK_BBOOL canSign = CK_FALSE;
    CK_ATTRIBUTE attrs[] = {{CKA_CLASS, &cls, sizeof(cls)}, {CKA_SIGN, &canSign, sizeof(canSign)}};
    ASSERT_EQ(m.fn->C_GetAttributeValue(session, key, attrs, 2), CKR_OK);
    EXPECT_EQ(cls, CKO_PRIVATE_KEY);
    EXPECT_EQ(canSign, CK_TRUE);

    // C_Login(CKU_USER, NULL, 0): pPin ignored, agent prompter is the auth path.
    EXPECT_EQ(m.fn->C_Login(session, CKU_USER, nullptr, 0), CKR_OK);

    // Sign with raw CKM_RSA_PKCS: the caller supplies a COMPLETE DigestInfo
    // block; the module passes it through VERBATIM (no hashing, no prefix added).
    const std::vector<std::uint8_t> digestInfo = {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65,
                                                  0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20,
                                                  // 32-byte digest payload:
                                                  1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
                                                  21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32};
    CK_MECHANISM mech{CKM_RSA_PKCS, nullptr, 0};
    ASSERT_EQ(m.fn->C_SignInit(session, &mech, key), CKR_OK);
    CK_BYTE sig[512];
    CK_ULONG sigLen = sizeof(sig);
    ASSERT_EQ(m.fn->C_Sign(session, const_cast<CK_BYTE*>(digestInfo.data()), static_cast<CK_ULONG>(digestInfo.size()),
                           sig, &sigLen),
              CKR_OK);
    std::vector<std::uint8_t> got(sig, sig + sigLen);
    EXPECT_EQ(got, kCannedSig);
    // The agent received the block VERBATIM — the module added no prefix.
    EXPECT_EQ(bus.fake->lastSignInput(), digestInfo);

    // Decrypt (single-part) with CKM_RSA_PKCS.
    CK_MECHANISM dmech{CKM_RSA_PKCS, nullptr, 0};
    ASSERT_EQ(m.fn->C_DecryptInit(session, &dmech, key), CKR_OK);
    std::vector<CK_BYTE> ct(256, 0x01);
    CK_BYTE plain[512];
    CK_ULONG plainLen = sizeof(plain);
    ASSERT_EQ(m.fn->C_Decrypt(session, ct.data(), ct.size(), plain, &plainLen), CKR_OK);
    std::vector<std::uint8_t> gotPlain(plain, plain + plainLen);
    EXPECT_EQ(gotPlain, kCannedPlain);

    // Decrypt (multi-part) with CKM_RSA_PKCS: C_DecryptUpdate buffers, the one
    // on-card decrypt runs at C_DecryptFinal. Update yields no intermediate
    // plaintext (RSA is single-block); Final returns the canned plaintext.
    ASSERT_EQ(m.fn->C_DecryptInit(session, &dmech, key), CKR_OK);
    CK_BYTE upd[512];
    CK_ULONG updLen = sizeof(upd);
    ASSERT_EQ(m.fn->C_DecryptUpdate(session, ct.data(), 128, upd, &updLen), CKR_OK);
    EXPECT_EQ(updLen, 0u);
    updLen = sizeof(upd);
    ASSERT_EQ(m.fn->C_DecryptUpdate(session, ct.data() + 128, 128, upd, &updLen), CKR_OK);
    EXPECT_EQ(updLen, 0u);
    CK_BYTE last[512];
    CK_ULONG lastLen = sizeof(last);
    ASSERT_EQ(m.fn->C_DecryptFinal(session, last, &lastLen), CKR_OK);
    std::vector<std::uint8_t> gotMulti(last, last + lastLen);
    EXPECT_EQ(gotMulti, kCannedPlain);

    EXPECT_EQ(m.fn->C_CloseSession(session), CKR_OK);
}

TEST(ModuleAbi, SignInitRejectsPss)
{
    BusFixture bus;
    LoadedModule m;
    ASSERT_EQ(m.fn->C_Initialize(nullptr), CKR_OK);
    CK_SLOT_ID slot = firstPresentSlot(m.fn);
    CK_SESSION_HANDLE session = 0;
    ASSERT_EQ(m.fn->C_OpenSession(slot, CKF_SERIAL_SESSION, nullptr, nullptr, &session), CKR_OK);
    CK_OBJECT_HANDLE key = findPrivateKey(m.fn, session);
    ASSERT_NE(key, CK_INVALID_HANDLE);

    CK_MECHANISM mech{CKM_RSA_PKCS_PSS, nullptr, 0};
    EXPECT_EQ(m.fn->C_SignInit(session, &mech, key), CKR_MECHANISM_INVALID);
}

TEST(ModuleAbi, SignSizeQueryReturnsModulusBytes)
{
    BusFixture bus;
    LoadedModule m;
    ASSERT_EQ(m.fn->C_Initialize(nullptr), CKR_OK);
    CK_SLOT_ID slot = firstPresentSlot(m.fn);
    CK_SESSION_HANDLE session = 0;
    ASSERT_EQ(m.fn->C_OpenSession(slot, CKF_SERIAL_SESSION, nullptr, nullptr, &session), CKR_OK);
    CK_OBJECT_HANDLE key = findPrivateKey(m.fn, session);
    ASSERT_NE(key, CK_INVALID_HANDLE);

    // The fake cert reports no modulusBits (0) -> size query falls through to a
    // real SignRaw and returns the canned-signature length. Either way, a
    // NULL-buffer size query must not error.
    CK_MECHANISM mech{CKM_RSA_PKCS, nullptr, 0};
    ASSERT_EQ(m.fn->C_SignInit(session, &mech, key), CKR_OK);
    std::vector<CK_BYTE> data(32, 0x11);
    CK_ULONG sigLen = 0;
    EXPECT_EQ(m.fn->C_Sign(session, data.data(), data.size(), nullptr, &sigLen), CKR_OK);
    EXPECT_GT(sigLen, 0u);
}

TEST(ModuleAbi, NotLoggedInSurfacedFromSign)
{
    BusFixture bus(true, "None", [](FakeAgent& f) { f.setSignError("org.librescrs.Agent.Error.UserNotLoggedIn"); });
    LoadedModule m;
    ASSERT_EQ(m.fn->C_Initialize(nullptr), CKR_OK);
    CK_SLOT_ID slot = firstPresentSlot(m.fn);
    CK_SESSION_HANDLE session = 0;
    ASSERT_EQ(m.fn->C_OpenSession(slot, CKF_SERIAL_SESSION, nullptr, nullptr, &session), CKR_OK);
    CK_OBJECT_HANDLE key = findPrivateKey(m.fn, session);
    ASSERT_NE(key, CK_INVALID_HANDLE);

    CK_MECHANISM mech{CKM_RSA_PKCS, nullptr, 0};
    ASSERT_EQ(m.fn->C_SignInit(session, &mech, key), CKR_OK);
    std::vector<CK_BYTE> data(32, 0x11);
    CK_BYTE sig[512];
    CK_ULONG sigLen = sizeof(sig);
    // The agent reports the lease expired -> NSS will transparently re-C_Login.
    EXPECT_EQ(m.fn->C_Sign(session, data.data(), data.size(), sig, &sigLen), CKR_USER_NOT_LOGGED_IN);
}

TEST(ModuleAbi, RateLimitedSurfacedFromSign)
{
    BusFixture bus(true, "None", [](FakeAgent& f) { f.setSignError("org.librescrs.Agent.Error.RateLimited"); });
    LoadedModule m;
    ASSERT_EQ(m.fn->C_Initialize(nullptr), CKR_OK);
    CK_SLOT_ID slot = firstPresentSlot(m.fn);
    CK_SESSION_HANDLE session = 0;
    ASSERT_EQ(m.fn->C_OpenSession(slot, CKF_SERIAL_SESSION, nullptr, nullptr, &session), CKR_OK);
    CK_OBJECT_HANDLE key = findPrivateKey(m.fn, session);
    ASSERT_NE(key, CK_INVALID_HANDLE);

    CK_MECHANISM mech{CKM_RSA_PKCS, nullptr, 0};
    ASSERT_EQ(m.fn->C_SignInit(session, &mech, key), CKR_OK);
    std::vector<CK_BYTE> data(32, 0x11);
    CK_BYTE sig[512];
    CK_ULONG sigLen = sizeof(sig);
    // The agent's PIN-prompt / sign throttle tripped -> the consent-surface
    // rejection surfaces as CKR_FUNCTION_REJECTED, never a generic error.
    EXPECT_EQ(m.fn->C_Sign(session, data.data(), data.size(), sig, &sigLen), CKR_FUNCTION_REJECTED);
}

TEST(ModuleAbi, NamHashOnCardOffersSha256RsaPkcsSignOnly)
{
    // Can (hash-on-card / IAS-ECC SSCD) card: it hashes the RAW message
    // on-card, so the proxy advertises CKM_SHA256_RSA_PKCS (sign-only) and NOT
    // CKM_RSA_PKCS (the card rejects a caller-built DigestInfo). Decrypt stays
    // gated (the pkcs15 plugin has no decipher primitive).
    BusFixture bus(true, "Can");
    LoadedModule m;
    ASSERT_EQ(m.fn->C_Initialize(nullptr), CKR_OK);
    CK_SLOT_ID slot = firstPresentSlot(m.fn);

    // Mechanism list: exactly {CKM_SHA256_RSA_PKCS}.
    CK_MECHANISM_TYPE mechs[8];
    CK_ULONG n = 8;
    ASSERT_EQ(m.fn->C_GetMechanismList(slot, mechs, &n), CKR_OK);
    ASSERT_EQ(n, 1u) << "hash-on-card token advertises exactly one sign mechanism";
    EXPECT_EQ(mechs[0], CKM_SHA256_RSA_PKCS);

    // C_GetMechanismInfo: SIGN only, never DECRYPT; CKM_RSA_PKCS not advertised.
    CK_MECHANISM_INFO info{};
    ASSERT_EQ(m.fn->C_GetMechanismInfo(slot, CKM_SHA256_RSA_PKCS, &info), CKR_OK);
    EXPECT_TRUE((info.flags & CKF_SIGN) != 0);
    EXPECT_TRUE((info.flags & CKF_DECRYPT) == 0) << "hash-on-card sign is sign-only";
    EXPECT_EQ(m.fn->C_GetMechanismInfo(slot, CKM_RSA_PKCS, &info), CKR_MECHANISM_INVALID);

    CK_SESSION_HANDLE session = 0;
    ASSERT_EQ(m.fn->C_OpenSession(slot, CKF_SERIAL_SESSION, nullptr, nullptr, &session), CKR_OK);
    CK_OBJECT_HANDLE key = findPrivateKey(m.fn, session);
    ASSERT_NE(key, CK_INVALID_HANDLE);

    // C_SignInit rejects the DigestInfo mechanism (the card cannot sign a
    // caller-supplied DigestInfo). A failed init leaves no active operation, so
    // assert the rejection FIRST, then the acceptance of the hash-on-card one.
    CK_MECHANISM raw{CKM_RSA_PKCS, nullptr, 0};
    EXPECT_EQ(m.fn->C_SignInit(session, &raw, key), CKR_MECHANISM_INVALID);
    CK_MECHANISM sha{CKM_SHA256_RSA_PKCS, nullptr, 0};
    EXPECT_EQ(m.fn->C_SignInit(session, &sha, key), CKR_OK);
}

TEST(ModuleAbi, CertValueFetchedLazily)
{
    BusFixture bus;
    LoadedModule m;
    ASSERT_EQ(m.fn->C_Initialize(nullptr), CKR_OK);
    CK_SLOT_ID slot = firstPresentSlot(m.fn);
    CK_SESSION_HANDLE session = 0;
    ASSERT_EQ(m.fn->C_OpenSession(slot, CKF_SERIAL_SESSION, nullptr, nullptr, &session), CKR_OK);

    CK_OBJECT_CLASS cls = CKO_CERTIFICATE;
    CK_ATTRIBUTE tmpl[] = {{CKA_CLASS, &cls, sizeof(cls)}};
    ASSERT_EQ(m.fn->C_FindObjectsInit(session, tmpl, 1), CKR_OK);
    CK_OBJECT_HANDLE objs[4];
    CK_ULONG n = 0;
    ASSERT_EQ(m.fn->C_FindObjects(session, objs, 4, &n), CKR_OK);
    ASSERT_EQ(m.fn->C_FindObjectsFinal(session), CKR_OK);
    ASSERT_EQ(n, 1u);

    CK_ATTRIBUTE val[] = {{CKA_VALUE, nullptr, 0}};
    ASSERT_EQ(m.fn->C_GetAttributeValue(session, objs[0], val, 1), CKR_OK);
    EXPECT_EQ(val[0].ulValueLen, kCannedDer.size());
}

// ssh-pkcs11 builds the RSA public key from CKA_MODULUS + CKA_PUBLIC_EXPONENT
// on the key objects; if these are absent it skips the key. The crypto-free
// module serves them from the agent's Pkcs11_1.PublicKey bytes.
TEST(ModuleAbi, PublicKeyServesModulusAndExponent)
{
    BusFixture bus;
    LoadedModule m;
    ASSERT_EQ(m.fn->C_Initialize(nullptr), CKR_OK);
    CK_SLOT_ID slot = firstPresentSlot(m.fn);
    CK_SESSION_HANDLE session = 0;
    ASSERT_EQ(m.fn->C_OpenSession(slot, CKF_SERIAL_SESSION, nullptr, nullptr, &session), CKR_OK);

    const auto expectMod = cannedModulus();

    for (CK_OBJECT_CLASS cls : {CKO_PUBLIC_KEY, CKO_PRIVATE_KEY}) {
        CK_OBJECT_HANDLE key = findOne(m.fn, session, cls);
        ASSERT_NE(key, CK_INVALID_HANDLE);

        // Size query first (pValue==NULL must return the lengths).
        CK_ATTRIBUTE sizeq[] = {{CKA_MODULUS, nullptr, 0}, {CKA_PUBLIC_EXPONENT, nullptr, 0}};
        ASSERT_EQ(m.fn->C_GetAttributeValue(session, key, sizeq, 2), CKR_OK);
        EXPECT_EQ(sizeq[0].ulValueLen, expectMod.size());
        EXPECT_EQ(sizeq[1].ulValueLen, kCannedExponent.size());

        std::vector<CK_BYTE> mod(sizeq[0].ulValueLen);
        std::vector<CK_BYTE> exp(sizeq[1].ulValueLen);
        CK_ATTRIBUTE get[] = {{CKA_MODULUS, mod.data(), (CK_ULONG)mod.size()},
                              {CKA_PUBLIC_EXPONENT, exp.data(), (CK_ULONG)exp.size()}};
        ASSERT_EQ(m.fn->C_GetAttributeValue(session, key, get, 2), CKR_OK);
        std::vector<std::uint8_t> gotMod(mod.begin(), mod.end());
        std::vector<std::uint8_t> gotExp(exp.begin(), exp.end());
        EXPECT_EQ(gotMod, expectMod) << "class " << cls;
        EXPECT_EQ(gotExp, kCannedExponent) << "class " << cls;
    }

    // CKA_MODULUS_BITS belongs to the public key and is derived from the fetched
    // modulus length (256 B -> 2048).
    CK_OBJECT_HANDLE pub = findOne(m.fn, session, CKO_PUBLIC_KEY);
    ASSERT_NE(pub, CK_INVALID_HANDLE);
    CK_ULONG bits = 0;
    CK_ATTRIBUTE bitsAttr[] = {{CKA_MODULUS_BITS, &bits, sizeof(bits)}};
    ASSERT_EQ(m.fn->C_GetAttributeValue(session, pub, bitsAttr, 1), CKR_OK);
    EXPECT_EQ(bits, 2048u);

    EXPECT_EQ(m.fn->C_CloseSession(session), CKR_OK);
}

// NSS/Firefox use CKA_ALWAYS_AUTHENTICATE to re-authenticate before each
// private-key op; paired with CKR_USER_NOT_LOGGED_IN-on-expiry this gives a
// clean per-signature re-prompt.
TEST(ModuleAbi, PrivateKeyAlwaysAuthenticate)
{
    BusFixture bus;
    LoadedModule m;
    ASSERT_EQ(m.fn->C_Initialize(nullptr), CKR_OK);
    CK_SLOT_ID slot = firstPresentSlot(m.fn);
    CK_SESSION_HANDLE session = 0;
    ASSERT_EQ(m.fn->C_OpenSession(slot, CKF_SERIAL_SESSION, nullptr, nullptr, &session), CKR_OK);
    CK_OBJECT_HANDLE key = findPrivateKey(m.fn, session);
    ASSERT_NE(key, CK_INVALID_HANDLE);

    CK_BBOOL always = CK_FALSE;
    CK_ATTRIBUTE attr[] = {{CKA_ALWAYS_AUTHENTICATE, &always, sizeof(always)}};
    ASSERT_EQ(m.fn->C_GetAttributeValue(session, key, attr, 1), CKR_OK);
    EXPECT_EQ(always, CK_TRUE) << "private key must require per-op re-authentication";
}

// The module must NOT hold the global lock across the blocking
// agent RPC. With a sign parked on a slow fake SignRaw, an unrelated
// C_GetSlotList (served from the snapshot cache) must still proceed promptly.
TEST(ModuleAbi, NoAppWideStallWhileSignParked)
{
    BusFixture bus;
    LoadedModule m;
    ASSERT_EQ(m.fn->C_Initialize(nullptr), CKR_OK);
    CK_SLOT_ID slot = firstPresentSlot(m.fn); // first enumeration -> cache warm
    CK_SESSION_HANDLE session = 0;
    ASSERT_EQ(m.fn->C_OpenSession(slot, CKF_SERIAL_SESSION, nullptr, nullptr, &session), CKR_OK);
    CK_OBJECT_HANDLE key = findPrivateKey(m.fn, session);
    ASSERT_NE(key, CK_INVALID_HANDLE);
    ASSERT_EQ(m.fn->C_Login(session, CKU_USER, nullptr, 0), CKR_OK);

    // Park a sign on a slow SignRaw (3s).
    bus.fake->setSignDelayMs(3000);
    CK_MECHANISM mech{CKM_RSA_PKCS, nullptr, 0};
    ASSERT_EQ(m.fn->C_SignInit(session, &mech, key), CKR_OK);
    std::vector<CK_BYTE> data(32, 0x11);
    auto signFut = std::async(std::launch::async, [&] {
        CK_BYTE sig[512];
        CK_ULONG sigLen = sizeof(sig);
        return m.fn->C_Sign(session, data.data(), data.size(), sig, &sigLen);
    });

    // Give the worker time to enter the parked SignRaw.
    std::this_thread::sleep_for(std::chrono::milliseconds(300));

    // C_GetSlotList (cache path: no agent round-trip) must return well within the
    // parked sign's 3s. If the module held g_mutex across the RPC it would block
    // here for ~3s.
    const auto t0 = std::chrono::steady_clock::now();
    CK_SLOT_ID slots[8];
    CK_ULONG n = 8;
    EXPECT_EQ(m.fn->C_GetSlotList(CK_TRUE, slots, &n), CKR_OK);
    const auto elapsed = std::chrono::steady_clock::now() - t0;
    EXPECT_LT(std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count(), 1500)
        << "C_GetSlotList stalled behind the parked sign -> lock not narrowed";

    EXPECT_EQ(signFut.get(), CKR_OK);
}

// A slow (>25s) interactive op must NOT spuriously map to
// CKR_DEVICE_REMOVED — sd-bus's ~25s default would otherwise raise NoReply. The
// module sets a generous timeout on the interactive Pkcs11_1 calls.
TEST(ModuleAbi, SlowSignDoesNotMapToDeviceRemoved)
{
    BusFixture bus;
    LoadedModule m;
    ASSERT_EQ(m.fn->C_Initialize(nullptr), CKR_OK);
    CK_SLOT_ID slot = firstPresentSlot(m.fn);
    CK_SESSION_HANDLE session = 0;
    ASSERT_EQ(m.fn->C_OpenSession(slot, CKF_SERIAL_SESSION, nullptr, nullptr, &session), CKR_OK);
    CK_OBJECT_HANDLE key = findPrivateKey(m.fn, session);
    ASSERT_NE(key, CK_INVALID_HANDLE);
    ASSERT_EQ(m.fn->C_Login(session, CKU_USER, nullptr, 0), CKR_OK);

    // 27s > sd-bus's ~25s default; with the module's larger timeout the call
    // completes normally instead of NoReply -> CKR_DEVICE_REMOVED.
    bus.fake->setSignDelayMs(27000);
    CK_MECHANISM mech{CKM_RSA_PKCS, nullptr, 0};
    ASSERT_EQ(m.fn->C_SignInit(session, &mech, key), CKR_OK);
    std::vector<CK_BYTE> data(32, 0x11);
    CK_BYTE sig[512];
    CK_ULONG sigLen = sizeof(sig);
    const CK_RV rv = m.fn->C_Sign(session, data.data(), data.size(), sig, &sigLen);
    EXPECT_NE(rv, CKR_DEVICE_REMOVED) << "slow op spuriously timed out to CKR_DEVICE_REMOVED";
    EXPECT_EQ(rv, CKR_OK);
}

// A CKA_VALUE (cert DER) fetch failure must map to the bus-state CKR_*
// (CKR_DEVICE_ERROR for a CommunicationError), not the generic CKR_FUNCTION_FAILED.
TEST(ModuleAbi, CertValueFetchFailureMapsToDeviceError)
{
    BusFixture bus(true, "None",
                   [](FakeAgent& f) { f.setCertDerError("org.librescrs.Agent.Error.CommunicationError"); });
    LoadedModule m;
    ASSERT_EQ(m.fn->C_Initialize(nullptr), CKR_OK);
    CK_SLOT_ID slot = firstPresentSlot(m.fn);
    CK_SESSION_HANDLE session = 0;
    ASSERT_EQ(m.fn->C_OpenSession(slot, CKF_SERIAL_SESSION, nullptr, nullptr, &session), CKR_OK);
    CK_OBJECT_HANDLE cert = findOne(m.fn, session, CKO_CERTIFICATE);
    ASSERT_NE(cert, CK_INVALID_HANDLE);

    CK_ATTRIBUTE val[] = {{CKA_VALUE, nullptr, 0}};
    EXPECT_EQ(m.fn->C_GetAttributeValue(session, cert, val, 1), CKR_DEVICE_ERROR);
}

// A second C_Login while already logged in returns CKR_USER_ALREADY_LOGGED_IN.
TEST(ModuleAbi, SecondLoginReturnsAlreadyLoggedIn)
{
    BusFixture bus;
    LoadedModule m;
    ASSERT_EQ(m.fn->C_Initialize(nullptr), CKR_OK);
    CK_SLOT_ID slot = firstPresentSlot(m.fn);
    CK_SESSION_HANDLE session = 0;
    ASSERT_EQ(m.fn->C_OpenSession(slot, CKF_SERIAL_SESSION, nullptr, nullptr, &session), CKR_OK);

    EXPECT_EQ(m.fn->C_Login(session, CKU_USER, nullptr, 0), CKR_OK);
    EXPECT_EQ(m.fn->C_Login(session, CKU_USER, nullptr, 0), CKR_USER_ALREADY_LOGGED_IN);
}

// PKCS#11 §5.6.6: every private key advertises CKA_ALWAYS_AUTHENTICATE, so
// consumers (ssh-pkcs11, NSS, Firefox) re-authenticate per signing operation via
// C_Login(CKU_CONTEXT_SPECIFIC) between C_SignInit and C_Sign. That re-auth must
// SUCCEED (lease refresh) even while already CKU_USER-logged-in — NOT be rejected
// the way a repeat CKU_USER login is (cf. SecondLoginReturnsAlreadyLoggedIn).
// Without this, third-party PKCS#11 signing fails outright.
TEST(ModuleAbi, ContextSpecificLoginAcceptedForReauth)
{
    BusFixture bus;
    LoadedModule m;
    ASSERT_EQ(m.fn->C_Initialize(nullptr), CKR_OK);
    CK_SLOT_ID slot = firstPresentSlot(m.fn);
    CK_SESSION_HANDLE session = 0;
    ASSERT_EQ(m.fn->C_OpenSession(slot, CKF_SERIAL_SESSION, nullptr, nullptr, &session), CKR_OK);

    EXPECT_EQ(m.fn->C_Login(session, CKU_USER, nullptr, 0), CKR_OK);
    EXPECT_EQ(m.fn->C_Login(session, CKU_CONTEXT_SPECIFIC, nullptr, 0), CKR_OK);
    EXPECT_EQ(m.fn->C_Login(session, CKU_CONTEXT_SPECIFIC, nullptr, 0), CKR_OK)
        << "repeated per-operation re-auth must keep succeeding";
}

// The widened userType check must NOT become a blanket accept: CKU_SO
// (security officer) is not a supported role for this token.
TEST(ModuleAbi, UnsupportedLoginUserTypeRejected)
{
    BusFixture bus;
    LoadedModule m;
    ASSERT_EQ(m.fn->C_Initialize(nullptr), CKR_OK);
    CK_SLOT_ID slot = firstPresentSlot(m.fn);
    CK_SESSION_HANDLE session = 0;
    ASSERT_EQ(m.fn->C_OpenSession(slot, CKF_SERIAL_SESSION, nullptr, nullptr, &session), CKR_OK);

    EXPECT_EQ(m.fn->C_Login(session, CKU_SO, nullptr, 0), CKR_USER_TYPE_INVALID);
}

TEST(ModuleAbi, LiveSlotUpdateOnCardRemoveAndInsert)
{
    // Card present -> 1 present slot. Remove the card + emit InterfacesRemoved
    // -> the next C_GetSlotList(present) drops it. Re-insert -> it returns.
    // ObjectManager signals invalidate the module's snapshot cache.
    BusFixture bus;
    LoadedModule m;
    ASSERT_EQ(m.fn->C_Initialize(nullptr), CKR_OK);

    CK_SLOT_ID slots[8];
    CK_ULONG n = 8;
    ASSERT_EQ(m.fn->C_GetSlotList(CK_TRUE, slots, &n), CKR_OK);
    EXPECT_EQ(n, 1u);

    bus.fake->removeCard();
    std::this_thread::sleep_for(std::chrono::milliseconds(150));
    n = 8;
    ASSERT_EQ(m.fn->C_GetSlotList(CK_TRUE, slots, &n), CKR_OK);
    EXPECT_EQ(n, 0u) << "card removal must drop the present-slot count";

    bus.fake->insertCard(*bus.serverConn);
    std::this_thread::sleep_for(std::chrono::milliseconds(150));
    n = 8;
    ASSERT_EQ(m.fn->C_GetSlotList(CK_TRUE, slots, &n), CKR_OK);
    EXPECT_EQ(n, 1u) << "card re-insertion must restore the present slot";
}

// C_Finalize concurrent with an in-flight blocking RPC must NOT destroy
// the library (g_lib.reset()) while the RPC thread is still inside signRaw on
// it — that is a use-after-free (the narrowing that released g_mutex across the
// RPC introduced it). C_Finalize must DRAIN the in-flight RPC count before the
// reset. With the fix the parked sign completes with CKR_OK (the library lived
// through the whole call) and C_Finalize returns CKR_OK only after the drain.
// Run under ASan (CTest 'asan' suite) to prove no UAF; the racer is otherwise
// never exercised by the suite.
TEST(ModuleAbi, FinalizeDrainsInFlightRpcNoUaf)
{
    BusFixture bus;
    LoadedModule m;
    ASSERT_NE(m.fn, nullptr);
    ASSERT_EQ(m.fn->C_Initialize(nullptr), CKR_OK);
    CK_SLOT_ID slot = firstPresentSlot(m.fn);
    CK_SESSION_HANDLE session = 0;
    ASSERT_EQ(m.fn->C_OpenSession(slot, CKF_SERIAL_SESSION, nullptr, nullptr, &session), CKR_OK);
    CK_OBJECT_HANDLE key = findPrivateKey(m.fn, session);
    ASSERT_NE(key, CK_INVALID_HANDLE);
    ASSERT_EQ(m.fn->C_Login(session, CKU_USER, nullptr, 0), CKR_OK);

    // Park a sign on a slow SignRaw: the RPC thread sits inside
    // g_lib->client.signRaw with g_mutex RELEASED for ~2s.
    bus.fake->setSignDelayMs(2000);
    CK_MECHANISM mech{CKM_RSA_PKCS, nullptr, 0};
    ASSERT_EQ(m.fn->C_SignInit(session, &mech, key), CKR_OK);
    std::vector<CK_BYTE> data(32, 0x11);
    std::atomic<CK_RV> signRv{CKR_VENDOR_DEFINED};
    std::thread signThread([&] {
        CK_BYTE sig[512];
        CK_ULONG sigLen = sizeof(sig);
        signRv.store(m.fn->C_Sign(session, data.data(), data.size(), sig, &sigLen));
    });

    // Let the worker enter the parked SignRaw (g_lib in use, lock released).
    std::this_thread::sleep_for(std::chrono::milliseconds(400));

    // C_Finalize NOW, mid-RPC. It must wait for the RPC to drain before
    // g_lib.reset() — so the call blocks ~the rest of the 2s, then returns OK.
    // Without the drain it would reset g_lib under the RPC thread -> UAF.
    const auto t0 = std::chrono::steady_clock::now();
    const CK_RV finRv = m.fn->C_Finalize(nullptr);
    const auto elapsedMs =
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    EXPECT_EQ(finRv, CKR_OK);
    EXPECT_GE(elapsedMs, 800) << "C_Finalize returned before the in-flight RPC drained";

    signThread.join();
    // The parked sign ran to completion against a live library (no UAF).
    EXPECT_EQ(signRv.load(), CKR_OK) << "the in-flight sign must complete against a live library";

    // We already finalized; the LoadedModule dtor's second C_Finalize is a
    // harmless NOT_INITIALIZED. Re-init is unnecessary.
}
