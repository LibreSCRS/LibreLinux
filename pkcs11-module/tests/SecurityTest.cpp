// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Module-side security properties, driven over the real C_* ABI of the
// built .so against a fake agent on a private session bus:
//   - C_Login ignores any pPin the app passes (CKF_PROTECTED_AUTHENTICATION_PATH
//     means the agent prompter is the only PIN sink; the Pkcs11_1 wire has NO pin
//     arg, so no PIN byte can cross — asserted structurally + by inspecting the
//     bytes the fake agent received);
//   - PSS / ECDSA / hash-RSA-combo mechanisms are rejected with
//     CKR_MECHANISM_INVALID (the module is libcrypto-free: it cannot hash, so it
//     never honours CKM_SHAxxx_RSA_PKCS — only raw CKM_RSA_PKCS);
//   - private keys report CKA_EXTRACTABLE = CK_FALSE (and CKA_SENSITIVE = TRUE);
//   - a NAM (Can) hash-on-card token advertises CKM_SHA256_RSA_PKCS sign
//     (CKA_SIGN) but no decrypt (CKA_DECRYPT off, no decrypt mechanism), so
//     C_DecryptInit is rejected.

#include "FakeAgent.h"
#include "pkcs11.h"

#include <dlfcn.h>
#include <gtest/gtest.h>

#include <algorithm>
#include <cstring>
#include <string>
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

CK_SLOT_ID firstPresentSlot(CK_FUNCTION_LIST_PTR fn)
{
    CK_SLOT_ID slots[8];
    CK_ULONG n = 8;
    EXPECT_EQ(fn->C_GetSlotList(CK_TRUE, slots, &n), CKR_OK);
    EXPECT_GE(n, 1u);
    return slots[0];
}

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

bool containsSub(const std::vector<std::uint8_t>& hay, const std::vector<std::uint8_t>& needle)
{
    if (needle.empty() || needle.size() > hay.size())
        return false;
    return std::search(hay.begin(), hay.end(), needle.begin(), needle.end()) != hay.end();
}

} // namespace

TEST(Security, LoginIgnoresAppSuppliedPinAndNoPinBytesCrossTheWire)
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

    // An app that (wrongly) passes a PIN to C_Login: the module is a protected
    // auth path, so it MUST ignore the buffer and still succeed (the agent
    // prompter is the auth path). The byte pattern below is the canary.
    const std::vector<CK_BYTE> appPin{'1', '3', '3', '7', 's', 'e', 'c', 'r', 'e', 't'};
    EXPECT_EQ(
        m.fn->C_Login(session, CKU_USER, const_cast<CK_BYTE*>(appPin.data()), static_cast<CK_ULONG>(appPin.size())),
        CKR_OK);

    // Drive a sign so the fake agent records exactly what bytes it received over
    // the Pkcs11_1 wire. The canary PIN must appear NOWHERE in that input.
    CK_MECHANISM mech{CKM_RSA_PKCS, nullptr, 0};
    ASSERT_EQ(m.fn->C_SignInit(session, &mech, key), CKR_OK);
    std::vector<CK_BYTE> digest(32, 0x42);
    CK_BYTE sig[512];
    CK_ULONG sigLen = sizeof(sig);
    ASSERT_EQ(m.fn->C_Sign(session, digest.data(), digest.size(), sig, &sigLen), CKR_OK);

    const auto wire = bus.fake->lastSignInput();
    const std::vector<std::uint8_t> canary(appPin.begin(), appPin.end());
    EXPECT_FALSE(containsSub(wire, canary)) << "app-supplied PIN bytes leaked onto the Pkcs11_1 wire";
}

TEST(Security, SignInitRejectsPss)
{
    BusFixture bus;
    LoadedModule m;
    ASSERT_EQ(m.fn->C_Initialize(nullptr), CKR_OK);
    CK_SLOT_ID slot = firstPresentSlot(m.fn);
    CK_SESSION_HANDLE session = 0;
    ASSERT_EQ(m.fn->C_OpenSession(slot, CKF_SERIAL_SESSION, nullptr, nullptr, &session), CKR_OK);
    CK_OBJECT_HANDLE key = findPrivateKey(m.fn, session);
    ASSERT_NE(key, CK_INVALID_HANDLE);

    CK_MECHANISM pss{CKM_RSA_PKCS_PSS, nullptr, 0};
    EXPECT_EQ(m.fn->C_SignInit(session, &pss, key), CKR_MECHANISM_INVALID);
    CK_MECHANISM sha256pss{CKM_SHA256_RSA_PKCS_PSS, nullptr, 0};
    EXPECT_EQ(m.fn->C_SignInit(session, &sha256pss, key), CKR_MECHANISM_INVALID);
}

TEST(Security, SignInitRejectsWithdrawnHashRsaCombos)
{
    // The libcrypto-free module cannot compute a digest, so the combined
    // CKM_SHAxxx_RSA_PKCS mechanisms are NOT advertised and C_SignInit rejects
    // them with CKR_MECHANISM_INVALID — only raw CKM_RSA_PKCS (caller-supplied
    // DigestInfo) is honoured.
    BusFixture bus;
    LoadedModule m;
    ASSERT_EQ(m.fn->C_Initialize(nullptr), CKR_OK);
    CK_SLOT_ID slot = firstPresentSlot(m.fn);
    CK_SESSION_HANDLE session = 0;
    ASSERT_EQ(m.fn->C_OpenSession(slot, CKF_SERIAL_SESSION, nullptr, nullptr, &session), CKR_OK);
    CK_OBJECT_HANDLE key = findPrivateKey(m.fn, session);
    ASSERT_NE(key, CK_INVALID_HANDLE);

    for (CK_MECHANISM_TYPE combo : {CKM_SHA256_RSA_PKCS, CKM_SHA384_RSA_PKCS, CKM_SHA512_RSA_PKCS}) {
        CK_MECHANISM mech{combo, nullptr, 0};
        EXPECT_EQ(m.fn->C_SignInit(session, &mech, key), CKR_MECHANISM_INVALID) << "combo=" << combo;
    }
    // Raw CKM_RSA_PKCS is still accepted.
    CK_MECHANISM raw{CKM_RSA_PKCS, nullptr, 0};
    EXPECT_EQ(m.fn->C_SignInit(session, &raw, key), CKR_OK);
}

TEST(Security, SignInitRejectsEcdsa)
{
    BusFixture bus;
    LoadedModule m;
    ASSERT_EQ(m.fn->C_Initialize(nullptr), CKR_OK);
    CK_SLOT_ID slot = firstPresentSlot(m.fn);
    CK_SESSION_HANDLE session = 0;
    ASSERT_EQ(m.fn->C_OpenSession(slot, CKF_SERIAL_SESSION, nullptr, nullptr, &session), CKR_OK);
    CK_OBJECT_HANDLE key = findPrivateKey(m.fn, session);
    ASSERT_NE(key, CK_INVALID_HANDLE);

    CK_MECHANISM ecdsa{CKM_ECDSA, nullptr, 0};
    EXPECT_EQ(m.fn->C_SignInit(session, &ecdsa, key), CKR_MECHANISM_INVALID);
}

TEST(Security, PrivateKeyIsNotExtractableAndIsSensitive)
{
    BusFixture bus;
    LoadedModule m;
    ASSERT_EQ(m.fn->C_Initialize(nullptr), CKR_OK);
    CK_SLOT_ID slot = firstPresentSlot(m.fn);
    CK_SESSION_HANDLE session = 0;
    ASSERT_EQ(m.fn->C_OpenSession(slot, CKF_SERIAL_SESSION, nullptr, nullptr, &session), CKR_OK);
    CK_OBJECT_HANDLE key = findPrivateKey(m.fn, session);
    ASSERT_NE(key, CK_INVALID_HANDLE);

    CK_BBOOL extractable = CK_TRUE;
    CK_BBOOL sensitive = CK_FALSE;
    CK_ATTRIBUTE attrs[] = {{CKA_EXTRACTABLE, &extractable, sizeof(extractable)},
                            {CKA_SENSITIVE, &sensitive, sizeof(sensitive)}};
    ASSERT_EQ(m.fn->C_GetAttributeValue(session, key, attrs, 2), CKR_OK);
    EXPECT_EQ(extractable, CK_FALSE) << "private key must never be extractable";
    EXPECT_EQ(sensitive, CK_TRUE) << "private key must be sensitive";
}

TEST(Security, NamTokenGatesDecryptButAllowsHashOnCardSign)
{
    // Can (NAM / IAS-ECC SSCD) card: sign IS allowed, but ONLY on-card
    // (CKM_SHA256_RSA_PKCS, sign-only — the card hashes the raw message). The
    // key carries CKA_SIGN but NOT CKA_DECRYPT (decrypt stays gated — the pkcs15
    // plugin has no decipher primitive). The DigestInfo CKM_RSA_PKCS mechanism
    // is not advertised (the card rejects a caller-built DigestInfo), so both
    // C_DecryptInit and a CKM_RSA_PKCS C_SignInit fail CKR_MECHANISM_INVALID.
    BusFixture bus(true, "Can");
    LoadedModule m;
    ASSERT_EQ(m.fn->C_Initialize(nullptr), CKR_OK);
    CK_SLOT_ID slot = firstPresentSlot(m.fn);

    CK_MECHANISM_TYPE mechs[8];
    CK_ULONG n = 8;
    ASSERT_EQ(m.fn->C_GetMechanismList(slot, mechs, &n), CKR_OK);
    ASSERT_EQ(n, 1u) << "hash-on-card token advertises exactly CKM_SHA256_RSA_PKCS";
    EXPECT_EQ(mechs[0], CKM_SHA256_RSA_PKCS);

    CK_SESSION_HANDLE session = 0;
    ASSERT_EQ(m.fn->C_OpenSession(slot, CKF_SERIAL_SESSION, nullptr, nullptr, &session), CKR_OK);
    CK_OBJECT_HANDLE key = findPrivateKey(m.fn, session);
    ASSERT_NE(key, CK_INVALID_HANDLE);

    CK_BBOOL canSign = CK_FALSE;
    CK_BBOOL canDecrypt = CK_TRUE;
    CK_ATTRIBUTE attrs[] = {{CKA_SIGN, &canSign, sizeof(canSign)}, {CKA_DECRYPT, &canDecrypt, sizeof(canDecrypt)}};
    ASSERT_EQ(m.fn->C_GetAttributeValue(session, key, attrs, 2), CKR_OK);
    EXPECT_EQ(canSign, CK_TRUE) << "NAM signs on-card";
    EXPECT_EQ(canDecrypt, CK_FALSE) << "NAM decrypt stays gated";

    // Decrypt is gated; the DigestInfo sign mechanism is not advertised. A failed
    // C_SignInit leaves no active op, so assert the rejections, then acceptance.
    CK_MECHANISM dmech{CKM_RSA_PKCS, nullptr, 0};
    EXPECT_EQ(m.fn->C_DecryptInit(session, &dmech, key), CKR_MECHANISM_INVALID);
    CK_MECHANISM rawSign{CKM_RSA_PKCS, nullptr, 0};
    EXPECT_EQ(m.fn->C_SignInit(session, &rawSign, key), CKR_MECHANISM_INVALID);
    CK_MECHANISM shaSign{CKM_SHA256_RSA_PKCS, nullptr, 0};
    EXPECT_EQ(m.fn->C_SignInit(session, &shaSign, key), CKR_OK);
}
