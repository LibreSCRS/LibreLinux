// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Env-gated MANUAL real-card smoke for the agent-proxy PKCS#11 module.
// SKIPPED unless LIBRESCRS_HW_SMOKE=1, so the normal suite NEVER touches a card.
// It drives the REAL built module (dlopen) against the REAL running agent against
// a REAL card over the live session bus — the deployment-(a) in-process path that
// a deployed app uses.
//
// PREREQUISITES for a manual run:
//   - a live `librescrs-agent` (systemctl --user start librescrs-agent), and a
//     running prompter (the agent raises it on C_Login to collect the PIN/CAN);
//   - a card in a reader.
//
// CREDENTIAL SAFETY: the PIN/CAN are NEVER hardcoded
// and never touch this module (CKF_PROTECTED_AUTHENTICATION_PATH — the agent
// prompter is the only PIN sink). The smoke only TRIGGERS the prompter; the human
// (or, in an automated lab, the test prompter wired to LIBRESCRS_TEST_PIN /
// LIBRESCRS_TEST_CAN) supplies the secret. A wrong signing PIN decrements an
// irreversible card counter, so on the FIRST not-OK login/sign the smoke sets a
// process-global g_pinFailed and every later test SKIPs — no retry storm.
//
// Manual run (PKS, contact, PIN):
//   LIBRESCRS_HW_SMOKE=1 \
//   LIBRESCRS_SMOKE_MODULE=$PREFIX/lib/pkcs11/librescrs-pkcs11-agent.so \
//   ctest --test-dir build -R RealCardSmoke --output-on-failure
// (A hash-on-card NAM token advertises CKM_SHA256_RSA_PKCS, not the DigestInfo
//  CKM_RSA_PKCS — see RealCardSmoke.NamHashOnCardAdvertisesSha256RsaPkcsSignOnly;
//  a PKS token advertises CKM_RSA_PKCS.)
//
// SIGNATURE VERIFICATION: this TU is libcrypto-free by policy, so it asserts the
// signature is well-formed (present, modulus-length) rather than verifying it
// cryptographically. Cryptographic verification against the cert public key is a
// documented step in the manual-smoke doc (openssl / a separate tool).

#include "pkcs11.h"

#include <dlfcn.h>
#include <gtest/gtest.h>

#include <cstdlib>
#include <string>
#include <vector>

namespace {

// Process-global irreversible-failure latch: once a PIN/login fails on a real
// card, every subsequent HW test SKIPs so we never burn the retry counter.
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

// First slot with a present token, or CK_UNAVAILABLE_INFORMATION if none.
CK_SLOT_ID firstPresentSlot(CK_FUNCTION_LIST_PTR fn, bool* found)
{
    *found = false;
    CK_SLOT_ID slots[16];
    CK_ULONG n = 16;
    if (fn->C_GetSlotList(CK_TRUE, slots, &n) != CKR_OK || n == 0)
        return 0;
    *found = true;
    return slots[0];
}

CK_OBJECT_HANDLE findPrivateKey(CK_FUNCTION_LIST_PTR fn, CK_SESSION_HANDLE session)
{
    CK_OBJECT_CLASS cls = CKO_PRIVATE_KEY;
    CK_ATTRIBUTE tmpl[] = {{CKA_CLASS, &cls, sizeof(cls)}};
    if (fn->C_FindObjectsInit(session, tmpl, 1) != CKR_OK)
        return CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE objs[16];
    CK_ULONG n = 0;
    fn->C_FindObjects(session, objs, 16, &n);
    fn->C_FindObjectsFinal(session);
    return n > 0 ? objs[0] : CK_INVALID_HANDLE;
}

} // namespace

// Stage 0 (no PIN): the module loads, the agent answers, a card is present and a
// private key + cert enumerate. Validates the whole RPC plumbing before any PIN.
TEST(RealCardSmoke, EnumerateTokenAndObjects)
{
    SKIP_IF_NO_HW();
    LoadedModule m;
    ASSERT_NE(m.fn, nullptr) << "module did not load / no C_GetFunctionList";
    ASSERT_EQ(m.fn->C_Initialize(nullptr), CKR_OK) << "no live agent on the session bus?";

    bool found = false;
    CK_SLOT_ID slot = firstPresentSlot(m.fn, &found);
    ASSERT_TRUE(found) << "no present token — insert a card and start the agent";

    CK_TOKEN_INFO ti{};
    ASSERT_EQ(m.fn->C_GetTokenInfo(slot, &ti), CKR_OK);
    EXPECT_TRUE(ti.flags & CKF_PROTECTED_AUTHENTICATION_PATH);
    EXPECT_TRUE(ti.flags & CKF_LOGIN_REQUIRED);

    CK_SESSION_HANDLE session = 0;
    ASSERT_EQ(m.fn->C_OpenSession(slot, CKF_SERIAL_SESSION, nullptr, nullptr, &session), CKR_OK);
    EXPECT_NE(findPrivateKey(m.fn, session), CK_INVALID_HANDLE) << "no private key object enumerated";
}

// PKS (contact, PIN): login (prompter collects the PIN) + sign a complete
// SHA-256 DigestInfo block with raw CKM_RSA_PKCS (the only advertised mechanism;
// the module is libcrypto-free so it cannot honour the hash-RSA combos). Aborts
// permanently on the first auth failure. Cryptographic verification of the
// signature is done in the libcrypto-linking RealCardCryptoVerify TU.
TEST(RealCardSmoke, PksLoginAndSign)
{
    SKIP_IF_NO_HW();
    SKIP_IF_PIN_FAILED();
    LoadedModule m;
    ASSERT_NE(m.fn, nullptr);
    ASSERT_EQ(m.fn->C_Initialize(nullptr), CKR_OK);

    bool found = false;
    CK_SLOT_ID slot = firstPresentSlot(m.fn, &found);
    ASSERT_TRUE(found);
    CK_SESSION_HANDLE session = 0;
    ASSERT_EQ(m.fn->C_OpenSession(slot, CKF_SERIAL_SESSION, nullptr, nullptr, &session), CKR_OK);
    CK_OBJECT_HANDLE key = findPrivateKey(m.fn, session);
    ASSERT_NE(key, CK_INVALID_HANDLE);

    // A hash-on-card NAM token advertises CKM_SHA256_RSA_PKCS, not raw
    // CKM_RSA_PKCS — only run this PKS DigestInfo sign where the token
    // advertises raw CKM_RSA_PKCS. Skip gracefully otherwise.
    CK_MECHANISM_TYPE mechs[32];
    CK_ULONG mn = 32;
    ASSERT_EQ(m.fn->C_GetMechanismList(slot, mechs, &mn), CKR_OK);
    bool canRsa = false;
    for (CK_ULONG i = 0; i < mn; ++i)
        if (mechs[i] == CKM_RSA_PKCS)
            canRsa = true;
    if (!canRsa)
        GTEST_SKIP() << "present token advertises no CKM_RSA_PKCS (e.g. a hash-on-card NAM token offers "
                        "CKM_SHA256_RSA_PKCS instead)";

    // C_Login(NULL pin): the agent prompter is the auth path. A non-OK return is
    // a (possibly wrong-PIN) auth failure -> latch and never retry.
    const CK_RV loginRv = m.fn->C_Login(session, CKU_USER, nullptr, 0);
    if (loginRv != CKR_OK) {
        g_pinFailed = true;
        FAIL() << "C_Login failed (rv=" << loginRv << "); latching to protect the card";
    }

    // A complete SHA-256 DigestInfo (prefix || 32-byte digest) — the full block
    // CKM_RSA_PKCS expects the caller to supply.
    std::vector<CK_BYTE> digestInfo = {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
                                       0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20};
    digestInfo.insert(digestInfo.end(), 32, 0x5A);
    CK_MECHANISM mech{CKM_RSA_PKCS, nullptr, 0};
    ASSERT_EQ(m.fn->C_SignInit(session, &mech, key), CKR_OK);
    CK_BYTE sig[1024];
    CK_ULONG sigLen = sizeof(sig);
    const CK_RV signRv = m.fn->C_Sign(session, digestInfo.data(), digestInfo.size(), sig, &sigLen);
    if (signRv == CKR_PIN_INCORRECT || signRv == CKR_FUNCTION_FAILED) {
        g_pinFailed = true;
        FAIL() << "C_Sign auth failure (rv=" << signRv << "); latching to protect the card";
    }
    ASSERT_EQ(signRv, CKR_OK);
    EXPECT_GE(sigLen, 128u) << "RSA-1024+ signature should be >= 128 bytes";
}

// NAM (hash-on-card IAS-ECC SSCD): the token advertises CKM_SHA256_RSA_PKCS
// (sign-only — the card hashes the raw message) and NOT the DigestInfo
// CKM_RSA_PKCS. Mechanism-advertisement check only: no PIN, no card counter
// touched. Skips for a PKS token (which advertises CKM_RSA_PKCS).
TEST(RealCardSmoke, NamHashOnCardAdvertisesSha256RsaPkcsSignOnly)
{
    SKIP_IF_NO_HW();
    LoadedModule m;
    ASSERT_NE(m.fn, nullptr);
    ASSERT_EQ(m.fn->C_Initialize(nullptr), CKR_OK);
    bool found = false;
    CK_SLOT_ID slot = firstPresentSlot(m.fn, &found);
    ASSERT_TRUE(found);

    CK_MECHANISM_TYPE mechs[32];
    CK_ULONG mn = 32;
    ASSERT_EQ(m.fn->C_GetMechanismList(slot, mechs, &mn), CKR_OK);
    bool hasSha256 = false, hasRaw = false;
    for (CK_ULONG i = 0; i < mn; ++i) {
        if (mechs[i] == CKM_SHA256_RSA_PKCS)
            hasSha256 = true;
        if (mechs[i] == CKM_RSA_PKCS)
            hasRaw = true;
    }
    if (!hasSha256)
        GTEST_SKIP() << "present token does not advertise CKM_SHA256_RSA_PKCS (e.g. a PKS DigestInfo token)";
    // Hash-on-card: SHA256-RSA only, never the DigestInfo CKM_RSA_PKCS.
    EXPECT_FALSE(hasRaw) << "a hash-on-card NAM token must not advertise CKM_RSA_PKCS";
    CK_MECHANISM_INFO info{};
    EXPECT_EQ(m.fn->C_GetMechanismInfo(slot, CKM_SHA256_RSA_PKCS, &info), CKR_OK);
    EXPECT_TRUE(info.flags & CKF_SIGN) << "the advertised mechanism must permit sign";
}
