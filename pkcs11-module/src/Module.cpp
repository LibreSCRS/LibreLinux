// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// librescrs-pkcs11-agent.so — a standalone, Qt-free, libcrypto-free PKCS#11
// v2.40 module that implements the C_* ABI by brokering to the per-user
// librescrs-agent over D-Bus (sdbus-c++). It holds NO card connection and NO
// secret: every real crypto operation is performed on-card by the agent.
//
// PIN/CAN are collected by the agent's prompter, so every token advertises
// CKF_PROTECTED_AUTHENTICATION_PATH and the application PIN passed to C_Login is
// IGNORED — it is NEVER placed on the wire. The only secret-ish bytes the module
// touches are sign/decrypt I/O, which pass straight through to/from the agent
// and are NEVER logged.
//
// Layout: this file owns the C ABI surface + the static function-list table;
// SessionState owns the session/object/cursor bookkeeping; AgentClient is the
// bus proxy; ObjectModel is the pure slot/token/object/mechanism mapping.

#include "AgentClient.h"
#include "ObjectModel.h"
#include "SessionState.h"
#include "pkcs11.h"

#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstring>
#include <memory>
#include <mutex>
#include <optional>
#include <string>

namespace {

using namespace LibreSCRS::Pkcs11Agent;

// PKCS#11 is a C API — C++ exceptions must never cross the boundary.
#define PKCS11_TRY try {
#define PKCS11_CATCH                                                                                                   \
    }                                                                                                                  \
    catch (...)                                                                                                        \
    {                                                                                                                  \
        return CKR_DEVICE_ERROR;                                                                                       \
    }

// --- File-scoped library state --------------------------------------------
struct Library
{
    AgentClient client;
    SessionState state;
};

std::mutex g_mutex;
std::unique_ptr<Library> g_lib;

// In-flight blocking-RPC accounting. The interactive C_* paths
// (Login/Sign/Decrypt) release g_mutex across the blocking agent RPC so an
// unrelated C_* is not stalled behind a human-paced PIN prompt. That narrowing
// means a concurrent C_Finalize could run g_lib.reset() — destroying the
// AgentClient the RPC thread is still inside — a use-after-free. We therefore
// count threads currently parked in an RPC (incremented under g_mutex BEFORE the
// release, decremented under g_mutex AFTER the re-take, via the RAII guard
// below) and have C_Finalize WAIT for the count to drain to zero before the
// reset. g_rpcDrained is notified on each decrement; C_Finalize bounds its wait
// and refuses (via the standard path) if the count cannot drain.
int g_rpcInFlight = 0;                // guarded by g_mutex
std::condition_variable g_rpcDrained; // notified when g_rpcInFlight hits 0

// RAII for the per-session rpcInFlight flag AND the global in-flight RPC count.
// Constructed UNDER g_mutex with the flag set + the count incremented; cleared on
// destruction by RE-TAKING g_mutex (the blocking RPC runs with the lock
// released in between). This guarantees both the session flag and the global
// count are cleared on EVERY exit path — including a std::bad_alloc thrown by the
// input-buffer build between the set and the RPC. A null session pointer is
// tolerated (the session may have been closed during the RPC); only the global
// count is then adjusted.
class RpcInFlightGuard
{
public:
    // PRECONDITION: g_mutex is held by the caller, @p s is validated, and the
    // session's rpcInFlight was NOT already set (the caller checked + refused
    // CKR_OPERATION_ACTIVE). Sets the flag + bumps the global count.
    explicit RpcInFlightGuard(Session* s) : m_session(s)
    {
        if (m_session) {
            m_session->rpcInFlight = true;
        }
        ++g_rpcInFlight;
    }

    RpcInFlightGuard(const RpcInFlightGuard&) = delete;
    RpcInFlightGuard& operator=(const RpcInFlightGuard&) = delete;

    ~RpcInFlightGuard()
    {
        std::lock_guard lk(g_mutex);
        // Re-resolve the session by handle: it may have been closed during the
        // RPC, in which case only the global count is adjusted. The owner clears
        // rpcInFlight here on the live session (mirrors the prior manual reset).
        if (m_session && g_lib) {
            if (Session* s = g_lib->state.session(m_handle)) {
                s->rpcInFlight = false;
            }
        }
        if (--g_rpcInFlight == 0) {
            g_rpcDrained.notify_all();
        }
    }

    // Record the handle so the dtor can re-resolve the (possibly recreated)
    // Session* rather than trusting a pointer that may have dangled.
    void setHandle(CK_SESSION_HANDLE h) noexcept
    {
        m_handle = h;
    }

private:
    Session* m_session = nullptr;
    CK_SESSION_HANDLE m_handle = 0;
};

// Pull a fresh snapshot from the agent into the session state. Called on every
// slot/token query so live reader/card changes are reflected.
void refreshModel()
{
    g_lib->state.setModel(ObjectModel::build(g_lib->client.snapshot()));
}

// Map an AgentClient::Status to a CKR_* for a sign/decrypt/login outcome.
CK_RV ckrFromStatus(Status s)
{
    switch (s) {
    case Status::Ok:
        return CKR_OK;
    case Status::UserNotLoggedIn:
        // Surfaced so NSS transparently re-C_Login when the agent lease expired.
        return CKR_USER_NOT_LOGGED_IN;
    case Status::NotAuthorized:
        return CKR_PIN_INCORRECT;
    case Status::AuthFailed:
        return CKR_PIN_INCORRECT;
    case Status::Cancelled:
        return CKR_FUNCTION_CANCELED;
    case Status::KeyNotFound:
        return CKR_KEY_HANDLE_INVALID;
    case Status::UnknownCard:
        return CKR_TOKEN_NOT_PRESENT;
    case Status::NotSupported:
        return CKR_FUNCTION_NOT_SUPPORTED;
    case Status::RateLimited:
        return CKR_FUNCTION_REJECTED;
    case Status::Communication:
        return CKR_DEVICE_ERROR;
    case Status::DeviceRemoved:
        return CKR_DEVICE_REMOVED;
    case Status::GeneralError:
    default:
        return CKR_GENERAL_ERROR;
    }
}

// Copy a padded C-string field (CK_TOKEN_INFO / CK_SLOT_INFO are space-padded,
// NOT null-terminated). Truncates to the field length.
void padField(CK_UTF8CHAR* dst, std::size_t len, const std::string& src)
{
    std::memset(dst, ' ', len);
    const std::size_t n = src.size() < len ? src.size() : len;
    std::memcpy(dst, src.data(), n);
}

// Copy the caller's ready-to-sign block into the wire buffer VERBATIM. The
// module is libcrypto-free and performs NO hashing and prepends NO DigestInfo
// prefix for EITHER advertised mechanism — the caller's data already has the
// right form per the slot's single advertised mechanism: a complete pre-built
// DigestInfo for CKM_RSA_PKCS (DigestInfo cards), or the RAW message for
// CKM_SHA256_RSA_PKCS (hash-on-card cards, where the CARD computes SHA-256).
// The copy is kept as a distinct helper so the std::bad_alloc it can throw
// lands on the RpcInFlightGuard's every-exit-path cleanup in doSign, not inside
// the guarded region.
std::vector<std::uint8_t> buildSignInput(const std::uint8_t* data, std::size_t len)
{
    return std::vector<std::uint8_t>(data, data + len);
}

// True if @p mech is in the slot's advertised mechanism table.
bool slotHasMechanism(const Slot& slot, CK_MECHANISM_TYPE mech)
{
    for (const auto m : slot.mechanisms)
        if (m == mech)
            return true;
    return false;
}

} // namespace

// ===========================================================================
// General-purpose
// ===========================================================================

CK_DECLARE_FUNCTION(CK_RV, C_Initialize)(CK_VOID_PTR pInitArgs)
{
    PKCS11_TRY
    std::lock_guard lk(g_mutex);
    if (g_lib)
        return CKR_CRYPTOKI_ALREADY_INITIALIZED;
    if (pInitArgs != NULL_PTR) {
        auto* args = static_cast<CK_C_INITIALIZE_ARGS_PTR>(pInitArgs);
        if (args->pReserved != NULL_PTR)
            return CKR_ARGUMENTS_BAD;
        const bool hasCustomMutex = (args->CreateMutex != NULL_PTR || args->DestroyMutex != NULL_PTR ||
                                     args->LockMutex != NULL_PTR || args->UnlockMutex != NULL_PTR);
        if (hasCustomMutex && !(args->flags & CKF_OS_LOCKING_OK))
            return CKR_CANT_LOCK;
    }
    g_lib = std::make_unique<Library>();
    return CKR_OK;
    PKCS11_CATCH
}

CK_DECLARE_FUNCTION(CK_RV, C_Finalize)(CK_VOID_PTR pReserved)
{
    PKCS11_TRY
    std::unique_lock lk(g_mutex);
    if (!g_lib)
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (pReserved != NULL_PTR)
        return CKR_ARGUMENTS_BAD;
    // a well-behaved app quiesces before C_Finalize (PKCS#11 §5.6), but the
    // narrowed locking means a misbehaving (or simply racing) app could leave a
    // blocking RPC in flight on another thread. Destroying the library now would
    // be a use-after-free on that thread. Wait (bounded) for the in-flight RPC
    // count to drain to zero before the reset; the wait releases g_mutex so the
    // RPC threads can re-take it to decrement. If it cannot drain within the
    // bound (a genuinely wedged op), refuse via the standard path rather than
    // free memory out from under a live RPC.
    constexpr auto kDrainBudget = std::chrono::seconds{30};
    if (!g_rpcDrained.wait_for(lk, kDrainBudget, [] { return g_rpcInFlight == 0; }))
        return CKR_FUNCTION_FAILED; // could not quiesce; leave the library intact
    g_lib.reset();
    return CKR_OK;
    PKCS11_CATCH
}

CK_DECLARE_FUNCTION(CK_RV, C_GetInfo)(CK_INFO_PTR pInfo)
{
    PKCS11_TRY
    if (pInfo == NULL_PTR)
        return CKR_ARGUMENTS_BAD;
    *pInfo = CK_INFO{};
    pInfo->cryptokiVersion = {2, 40};
    padField(pInfo->manufacturerID, sizeof(pInfo->manufacturerID), "LibreSCRS");
    padField(pInfo->libraryDescription, sizeof(pInfo->libraryDescription), "LibreSCRS agent-proxy PKCS#11");
    pInfo->flags = 0;
    pInfo->libraryVersion = {0, 1};
    return CKR_OK;
    PKCS11_CATCH
}

// C_GetFunctionList is defined at the end of this file (needs the table).

// ===========================================================================
// Slot and token management
// ===========================================================================

CK_DECLARE_FUNCTION(CK_RV, C_GetSlotList)(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList, CK_ULONG_PTR pulCount)
{
    PKCS11_TRY
    std::lock_guard lk(g_mutex);
    if (!g_lib)
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (pulCount == NULL_PTR)
        return CKR_ARGUMENTS_BAD;

    refreshModel();
    const auto ids = g_lib->state.slotIds(tokenPresent == CK_TRUE);

    if (pSlotList == NULL_PTR) {
        *pulCount = static_cast<CK_ULONG>(ids.size());
        return CKR_OK;
    }
    if (*pulCount < ids.size()) {
        *pulCount = static_cast<CK_ULONG>(ids.size());
        return CKR_BUFFER_TOO_SMALL;
    }
    for (std::size_t i = 0; i < ids.size(); ++i)
        pSlotList[i] = ids[i];
    *pulCount = static_cast<CK_ULONG>(ids.size());
    return CKR_OK;
    PKCS11_CATCH
}

CK_DECLARE_FUNCTION(CK_RV, C_GetSlotInfo)(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo)
{
    PKCS11_TRY
    std::lock_guard lk(g_mutex);
    if (!g_lib)
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (pInfo == NULL_PTR)
        return CKR_ARGUMENTS_BAD;
    refreshModel();
    const Slot* slot = g_lib->state.slotById(slotID);
    if (!slot)
        return CKR_SLOT_ID_INVALID;

    *pInfo = CK_SLOT_INFO{};
    padField(pInfo->slotDescription, sizeof(pInfo->slotDescription), slot->readerPath);
    padField(pInfo->manufacturerID, sizeof(pInfo->manufacturerID), "LibreSCRS");
    pInfo->flags = CKF_REMOVABLE_DEVICE | CKF_HW_SLOT;
    if (slot->tokenPresent)
        pInfo->flags |= CKF_TOKEN_PRESENT;
    pInfo->hardwareVersion = {0, 1};
    pInfo->firmwareVersion = {0, 1};
    return CKR_OK;
    PKCS11_CATCH
}

CK_DECLARE_FUNCTION(CK_RV, C_GetTokenInfo)(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo)
{
    PKCS11_TRY
    std::lock_guard lk(g_mutex);
    if (!g_lib)
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (pInfo == NULL_PTR)
        return CKR_ARGUMENTS_BAD;
    refreshModel();
    const Slot* slot = g_lib->state.slotById(slotID);
    if (!slot)
        return CKR_SLOT_ID_INVALID;
    if (!slot->tokenPresent)
        return CKR_TOKEN_NOT_PRESENT;

    *pInfo = CK_TOKEN_INFO{};
    padField(pInfo->label, sizeof(pInfo->label), slot->tokenLabel.empty() ? "LibreSCRS Token" : slot->tokenLabel);
    padField(pInfo->manufacturerID, sizeof(pInfo->manufacturerID), "LibreSCRS");
    padField(pInfo->model, sizeof(pInfo->model), "agent-proxy");
    padField(pInfo->serialNumber, sizeof(pInfo->serialNumber), "");
    // The agent prompter is the protected authentication path; login is required
    // before any private-key op. Token present is implicit (checked above).
    pInfo->flags = CKF_TOKEN_INITIALIZED | CKF_LOGIN_REQUIRED | CKF_PROTECTED_AUTHENTICATION_PATH;
    pInfo->ulMaxSessionCount = CK_EFFECTIVELY_INFINITE;
    pInfo->ulSessionCount = CK_UNAVAILABLE_INFORMATION;
    pInfo->ulMaxRwSessionCount = CK_EFFECTIVELY_INFINITE;
    pInfo->ulRwSessionCount = CK_UNAVAILABLE_INFORMATION;
    pInfo->ulMaxPinLen = 0; // PIN is collected by the agent prompter, not here.
    pInfo->ulMinPinLen = 0;
    pInfo->ulTotalPublicMemory = CK_UNAVAILABLE_INFORMATION;
    pInfo->ulFreePublicMemory = CK_UNAVAILABLE_INFORMATION;
    pInfo->ulTotalPrivateMemory = CK_UNAVAILABLE_INFORMATION;
    pInfo->ulFreePrivateMemory = CK_UNAVAILABLE_INFORMATION;
    pInfo->hardwareVersion = {0, 1};
    pInfo->firmwareVersion = {0, 1};
    return CKR_OK;
    PKCS11_CATCH
}

CK_DECLARE_FUNCTION(CK_RV, C_GetMechanismList)
(CK_SLOT_ID slotID, CK_MECHANISM_TYPE_PTR pMechanismList, CK_ULONG_PTR pulCount)
{
    PKCS11_TRY
    std::lock_guard lk(g_mutex);
    if (!g_lib)
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (pulCount == NULL_PTR)
        return CKR_ARGUMENTS_BAD;
    refreshModel();
    const Slot* slot = g_lib->state.slotById(slotID);
    if (!slot)
        return CKR_SLOT_ID_INVALID;

    const auto& mechs = slot->mechanisms;
    if (pMechanismList == NULL_PTR) {
        *pulCount = static_cast<CK_ULONG>(mechs.size());
        return CKR_OK;
    }
    if (*pulCount < mechs.size()) {
        *pulCount = static_cast<CK_ULONG>(mechs.size());
        return CKR_BUFFER_TOO_SMALL;
    }
    for (std::size_t i = 0; i < mechs.size(); ++i)
        pMechanismList[i] = mechs[i];
    *pulCount = static_cast<CK_ULONG>(mechs.size());
    return CKR_OK;
    PKCS11_CATCH
}

CK_DECLARE_FUNCTION(CK_RV, C_GetMechanismInfo)(CK_SLOT_ID slotID, CK_MECHANISM_TYPE type, CK_MECHANISM_INFO_PTR pInfo)
{
    PKCS11_TRY
    std::lock_guard lk(g_mutex);
    if (!g_lib)
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (pInfo == NULL_PTR)
        return CKR_ARGUMENTS_BAD;
    refreshModel();
    const Slot* slot = g_lib->state.slotById(slotID);
    if (!slot)
        return CKR_SLOT_ID_INVALID;
    if (!slotHasMechanism(*slot, type))
        return CKR_MECHANISM_INVALID;

    *pInfo = CK_MECHANISM_INFO{};
    // RSA key-size bounds (bits). SR cards are 2048/4096.
    pInfo->ulMinKeySize = 2048;
    pInfo->ulMaxKeySize = 4096;
    pInfo->flags = CKF_HW;
    // Per-mechanism flags (slotHasMechanism gated the type above):
    //   * CKM_RSA_PKCS — DigestInfo family: raw RSA PKCS#1 v1.5 sign AND decrypt.
    //   * CKM_SHA256_RSA_PKCS — hash-on-card family: SIGN ONLY (no decrypt; the
    //     pkcs15 plugin has no decipher primitive).
    if (type == CKM_SHA256_RSA_PKCS)
        pInfo->flags |= CKF_SIGN;
    else
        pInfo->flags |= CKF_SIGN | CKF_DECRYPT;
    return CKR_OK;
    PKCS11_CATCH
}

CK_DECLARE_FUNCTION(CK_RV, C_InitToken)
(CK_SLOT_ID slotID, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen, CK_UTF8CHAR_PTR pLabel)
{
    (void)slotID;
    (void)pPin;
    (void)ulPinLen;
    (void)pLabel;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DECLARE_FUNCTION(CK_RV, C_InitPIN)(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen)
{
    (void)hSession;
    (void)pPin;
    (void)ulPinLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DECLARE_FUNCTION(CK_RV, C_SetPIN)
(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pOldPin, CK_ULONG ulOldLen, CK_UTF8CHAR_PTR pNewPin, CK_ULONG ulNewLen)
{
    (void)hSession;
    (void)pOldPin;
    (void)ulOldLen;
    (void)pNewPin;
    (void)ulNewLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

// ===========================================================================
// Session management
// ===========================================================================

CK_DECLARE_FUNCTION(CK_RV, C_OpenSession)
(CK_SLOT_ID slotID, CK_FLAGS flags, CK_VOID_PTR pApplication, CK_NOTIFY Notify, CK_SESSION_HANDLE_PTR phSession)
{
    PKCS11_TRY(void) pApplication;
    (void)Notify;
    std::lock_guard lk(g_mutex);
    if (!g_lib)
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (phSession == NULL_PTR)
        return CKR_ARGUMENTS_BAD;
    if (!(flags & CKF_SERIAL_SESSION))
        return CKR_SESSION_PARALLEL_NOT_SUPPORTED;
    refreshModel();
    const Slot* slot = g_lib->state.slotById(slotID);
    if (!slot)
        return CKR_SLOT_ID_INVALID;
    if (!slot->tokenPresent)
        return CKR_TOKEN_NOT_PRESENT;
    *phSession = g_lib->state.openSession(slotID, flags);
    return CKR_OK;
    PKCS11_CATCH
}

CK_DECLARE_FUNCTION(CK_RV, C_CloseSession)(CK_SESSION_HANDLE hSession)
{
    PKCS11_TRY
    std::lock_guard lk(g_mutex);
    if (!g_lib)
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    Session* s = g_lib->state.session(hSession);
    if (!s)
        return CKR_SESSION_HANDLE_INVALID;
    const CK_SLOT_ID slot = s->slot;
    g_lib->state.closeSession(hSession);
    // On the last session for a slot, drop the agent lease (idempotent).
    if (!g_lib->state.slotHasSessions(slot)) {
        if (const Slot* sl = g_lib->state.slotById(slot); sl)
            (void)g_lib->client.logout(sl->readerPath);
    }
    return CKR_OK;
    PKCS11_CATCH
}

CK_DECLARE_FUNCTION(CK_RV, C_CloseAllSessions)(CK_SLOT_ID slotID)
{
    PKCS11_TRY
    std::lock_guard lk(g_mutex);
    if (!g_lib)
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    g_lib->state.closeAllSessions(slotID);
    if (const Slot* sl = g_lib->state.slotById(slotID); sl)
        (void)g_lib->client.logout(sl->readerPath);
    return CKR_OK;
    PKCS11_CATCH
}

CK_DECLARE_FUNCTION(CK_RV, C_GetSessionInfo)(CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo)
{
    PKCS11_TRY
    std::lock_guard lk(g_mutex);
    if (!g_lib)
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (pInfo == NULL_PTR)
        return CKR_ARGUMENTS_BAD;
    Session* s = g_lib->state.session(hSession);
    if (!s)
        return CKR_SESSION_HANDLE_INVALID;
    *pInfo = CK_SESSION_INFO{};
    pInfo->slotID = s->slot;
    if (s->loggedIn)
        pInfo->state = (s->flags & CKF_RW_SESSION) ? CKS_RW_USER_FUNCTIONS : CKS_RO_USER_FUNCTIONS;
    else
        pInfo->state = (s->flags & CKF_RW_SESSION) ? CKS_RW_PUBLIC_SESSION : CKS_RO_PUBLIC_SESSION;
    pInfo->flags = s->flags;
    pInfo->ulDeviceError = 0;
    return CKR_OK;
    PKCS11_CATCH
}

CK_DECLARE_FUNCTION(CK_RV, C_GetOperationState)
(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState, CK_ULONG_PTR pulOperationStateLen)
{
    (void)hSession;
    (void)pOperationState;
    (void)pulOperationStateLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DECLARE_FUNCTION(CK_RV, C_SetOperationState)
(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState, CK_ULONG ulOperationStateLen, CK_OBJECT_HANDLE hEncryptionKey,
 CK_OBJECT_HANDLE hAuthenticationKey)
{
    (void)hSession;
    (void)pOperationState;
    (void)ulOperationStateLen;
    (void)hEncryptionKey;
    (void)hAuthenticationKey;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DECLARE_FUNCTION(CK_RV, C_Login)
(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen)
{
    PKCS11_TRY
        // pPin / ulPinLen are DELIBERATELY IGNORED: the agent prompter is the
        // protected authentication path (CKF_PROTECTED_AUTHENTICATION_PATH). The
        // application PIN, if any, is NEVER read and NEVER placed on the wire.
        (void) pPin;
    (void)ulPinLen;

    // --- under lock: validate + capture the reader; mark in-flight ---
    std::string reader;
    std::optional<RpcInFlightGuard> guard;
    {
        std::lock_guard lk(g_mutex);
        if (!g_lib)
            return CKR_CRYPTOKI_NOT_INITIALIZED;
        // CKU_USER: the normal per-card login. CKU_CONTEXT_SPECIFIC (PKCS#11
        // §5.6.6): the per-operation re-authentication a consumer (ssh-pkcs11,
        // NSS, Firefox) issues between C_SignInit and C_Sign because every
        // private key advertises CKA_ALWAYS_AUTHENTICATE — without accepting it
        // those apps cannot sign at all. Both refresh the agent login lease via
        // the prompter (protected authentication path); CKU_SO is unsupported.
        if (userType != CKU_USER && userType != CKU_CONTEXT_SPECIFIC)
            return CKR_USER_TYPE_INVALID;
        Session* s = g_lib->state.session(hSession);
        if (!s)
            return CKR_SESSION_HANDLE_INVALID;
        if (s->rpcInFlight)
            return CKR_OPERATION_ACTIVE;
        // A repeat CKU_USER login is an error; a CKU_CONTEXT_SPECIFIC re-auth is
        // EXPECTED while USER-logged-in (it re-confirms consent for the pending
        // operation), so it must fall through and refresh the lease.
        if (userType == CKU_USER && s->loggedIn)
            return CKR_USER_ALREADY_LOGGED_IN; // spec conformance (benign for NSS)
        const Slot* slot = g_lib->state.slotById(s->slot);
        if (!slot || !slot->tokenPresent)
            return CKR_TOKEN_NOT_PRESENT;
        if (slot->objects.empty())
            return CKR_KEY_HANDLE_INVALID;
        // Login is per-card (the lease is (caller, card)-scoped, not per-cert).
        reader = slot->readerPath;
        // Arm the in-flight guard (sets s->rpcInFlight + bumps the global count)
        // so C_Finalize cannot reset the library mid-RPC, and the flag is cleared
        // on every exit path (including a throw before the RPC).
        guard.emplace(s);
        guard->setHandle(hSession);
    }

    // --- lock RELEASED: the agent prompts for the PIN (human-paced) here, so no
    //     other C_* (even unrelated slots) is blocked app-wide. ---
    const auto res = g_lib->client.login(reader);

    // --- re-take the lock: record the outcome. The session may have been closed
    //     meanwhile; re-resolve by handle. The guard clears rpcInFlight + the
    //     global count on scope exit. ---
    {
        std::lock_guard lk(g_mutex);
        if (g_lib && res.status == Status::Ok) {
            if (Session* s = g_lib->state.session(hSession))
                s->loggedIn = true;
        }
    }
    if (res.status != Status::Ok)
        return ckrFromStatus(res.status);
    return CKR_OK;
    PKCS11_CATCH
}

CK_DECLARE_FUNCTION(CK_RV, C_Logout)(CK_SESSION_HANDLE hSession)
{
    PKCS11_TRY
    std::lock_guard lk(g_mutex);
    if (!g_lib)
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    Session* s = g_lib->state.session(hSession);
    if (!s)
        return CKR_SESSION_HANDLE_INVALID;
    const Slot* slot = g_lib->state.slotById(s->slot);
    if (slot)
        (void)g_lib->client.logout(slot->readerPath);
    s->loggedIn = false;
    return CKR_OK;
    PKCS11_CATCH
}

// ===========================================================================
// Object management
// ===========================================================================

CK_DECLARE_FUNCTION(CK_RV, C_CreateObject)
(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phObject)
{
    (void)hSession;
    (void)pTemplate;
    (void)ulCount;
    (void)phObject;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DECLARE_FUNCTION(CK_RV, C_CopyObject)
(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount,
 CK_OBJECT_HANDLE_PTR phNewObject)
{
    (void)hSession;
    (void)hObject;
    (void)pTemplate;
    (void)ulCount;
    (void)phNewObject;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DECLARE_FUNCTION(CK_RV, C_DestroyObject)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject)
{
    (void)hSession;
    (void)hObject;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DECLARE_FUNCTION(CK_RV, C_GetObjectSize)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ULONG_PTR pulSize)
{
    (void)hSession;
    (void)hObject;
    (void)pulSize;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

namespace {

// Serve one attribute for an object. Returns CKR_OK (filled / sized) or
// CKR_ATTRIBUTE_TYPE_INVALID. Implements the buffer-size protocol:
// pValue==NULL -> set ulValueLen; small buffer -> ulValueLen = -1 +
// CKR_BUFFER_TOO_SMALL.
CK_RV serveAttribute(const Slot& slot, const Object& obj, CK_ATTRIBUTE& attr)
{
    auto give = [&](const void* src, std::size_t len) -> CK_RV {
        if (attr.pValue == NULL_PTR) {
            attr.ulValueLen = static_cast<CK_ULONG>(len);
            return CKR_OK;
        }
        if (attr.ulValueLen < len) {
            attr.ulValueLen = CK_UNAVAILABLE_INFORMATION;
            return CKR_BUFFER_TOO_SMALL;
        }
        std::memcpy(attr.pValue, src, len);
        attr.ulValueLen = static_cast<CK_ULONG>(len);
        return CKR_OK;
    };

    const CK_BBOOL ckTrue = CK_TRUE;
    const CK_BBOOL ckFalse = CK_FALSE;

    // Fetch the cert's RSA public key (lazy, agent-served — the module holds no
    // crypto) and map the fetch status onto the PKCS#11 attribute protocol:
    // KeyNotFound -> CKR_KEY_HANDLE_INVALID, anything else non-Ok (NotSupported /
    // non-RSA / bus error) -> the attribute is absent (CKR_ATTRIBUTE_TYPE_INVALID).
    // On success @p out holds the key and the helper returns CKR_OK so the caller
    // serves its own field. Shared by the CKA_MODULUS / CKA_PUBLIC_EXPONENT /
    // CKA_MODULUS_BITS arms (each independently served, no extra round-trip — the
    // AgentClient caches the key per certId).
    auto fetchPubKeyOr = [&](PublicKeyResult& out) -> CK_RV {
        out = g_lib->client.publicKey(slot.readerPath, obj.certId);
        if (out.status == Status::KeyNotFound)
            return CKR_KEY_HANDLE_INVALID;
        if (out.status != Status::Ok)
            return CKR_ATTRIBUTE_TYPE_INVALID;
        return CKR_OK;
    };

    switch (attr.type) {
    case CKA_CLASS:
        return give(&obj.cls, sizeof(obj.cls));
    case CKA_ID:
        return give(obj.ckaId.data(), obj.ckaId.size());
    case CKA_LABEL:
        return give(obj.label.data(), obj.label.size());
    case CKA_TOKEN:
        return give(&ckTrue, sizeof(ckTrue));
    case CKA_PRIVATE:
        return give(obj.cls == CKO_PRIVATE_KEY ? &ckTrue : &ckFalse, sizeof(CK_BBOOL));
    case CKA_KEY_TYPE: {
        if (obj.cls == CKO_PUBLIC_KEY || obj.cls == CKO_PRIVATE_KEY) {
            const CK_KEY_TYPE kt = CKK_RSA;
            return give(&kt, sizeof(kt));
        }
        return CKR_ATTRIBUTE_TYPE_INVALID;
    }
    case CKA_CERTIFICATE_TYPE: {
        if (obj.cls == CKO_CERTIFICATE) {
            const CK_CERTIFICATE_TYPE ct = CKC_X_509;
            return give(&ct, sizeof(ct));
        }
        return CKR_ATTRIBUTE_TYPE_INVALID;
    }
    case CKA_SIGN:
        if (obj.cls != CKO_PRIVATE_KEY)
            return CKR_ATTRIBUTE_TYPE_INVALID;
        return give(obj.sign ? &ckTrue : &ckFalse, sizeof(CK_BBOOL));
    case CKA_DECRYPT:
        if (obj.cls != CKO_PRIVATE_KEY)
            return CKR_ATTRIBUTE_TYPE_INVALID;
        return give(obj.decrypt ? &ckTrue : &ckFalse, sizeof(CK_BBOOL));
    case CKA_EXTRACTABLE:
        if (obj.cls != CKO_PRIVATE_KEY)
            return CKR_ATTRIBUTE_TYPE_INVALID;
        return give(&ckFalse, sizeof(ckFalse)); // always false
    case CKA_SENSITIVE:
        if (obj.cls != CKO_PRIVATE_KEY)
            return CKR_ATTRIBUTE_TYPE_INVALID;
        return give(&ckTrue, sizeof(ckTrue));
    case CKA_ALWAYS_AUTHENTICATE:
        // NSS/Firefox re-authenticate before each private-key op when this is
        // set; paired with the agent's CKR_USER_NOT_LOGGED_IN-on-expiry this
        // yields a clean per-signature re-prompt.
        if (obj.cls != CKO_PRIVATE_KEY)
            return CKR_ATTRIBUTE_TYPE_INVALID;
        return give(&ckTrue, sizeof(ckTrue));
    case CKA_MODULUS: {
        // RSA modulus (big-endian, unpadded) for key objects. Fetched lazily
        // from the agent — the module holds no crypto.
        if (obj.cls != CKO_PUBLIC_KEY && obj.cls != CKO_PRIVATE_KEY)
            return CKR_ATTRIBUTE_TYPE_INVALID;
        PublicKeyResult pk;
        if (const CK_RV rv = fetchPubKeyOr(pk); rv != CKR_OK)
            return rv;
        return give(pk.modulus.data(), pk.modulus.size());
    }
    case CKA_PUBLIC_EXPONENT: {
        if (obj.cls != CKO_PUBLIC_KEY && obj.cls != CKO_PRIVATE_KEY)
            return CKR_ATTRIBUTE_TYPE_INVALID;
        PublicKeyResult pk;
        if (const CK_RV rv = fetchPubKeyOr(pk); rv != CKR_OK)
            return rv;
        return give(pk.exponent.data(), pk.exponent.size());
    }
    case CKA_MODULUS_BITS: {
        // CKA_MODULUS_BITS belongs to the public key object. Derive it from the
        // fetched modulus length (no stale modulusBits==0 wart).
        if (obj.cls != CKO_PUBLIC_KEY)
            return CKR_ATTRIBUTE_TYPE_INVALID;
        PublicKeyResult pk;
        if (const CK_RV rv = fetchPubKeyOr(pk); rv != CKR_OK)
            return rv;
        if (pk.modulus.empty())
            return CKR_ATTRIBUTE_TYPE_INVALID;
        const CK_ULONG bits = static_cast<CK_ULONG>(pk.modulus.size()) * 8;
        return give(&bits, sizeof(bits));
    }
    case CKA_VALUE: {
        // Certificate DER, fetched lazily from the agent (public data).
        if (obj.cls != CKO_CERTIFICATE)
            return CKR_ATTRIBUTE_TYPE_INVALID;
        auto der = g_lib->client.certDer(slot.readerPath, obj.certId);
        if (der.status != Status::Ok)
            return ckrFromStatus(der.status); // CKR_DEVICE_ERROR / _REMOVED per bus state
        return give(der.bytes.data(), der.bytes.size());
    }
    default:
        return CKR_ATTRIBUTE_TYPE_INVALID;
    }
}

} // namespace

CK_DECLARE_FUNCTION(CK_RV, C_GetAttributeValue)
(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
    PKCS11_TRY
    std::lock_guard lk(g_mutex);
    if (!g_lib)
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (pTemplate == NULL_PTR)
        return CKR_ARGUMENTS_BAD;
    Session* s = g_lib->state.session(hSession);
    if (!s)
        return CKR_SESSION_HANDLE_INVALID;
    const Slot* slot = g_lib->state.slotById(s->slot);
    if (!slot)
        return CKR_SESSION_HANDLE_INVALID;
    const Object* obj = g_lib->state.resolveObject(s->slot, hObject);
    if (!obj)
        return CKR_OBJECT_HANDLE_INVALID;

    CK_RV overall = CKR_OK;
    for (CK_ULONG i = 0; i < ulCount; ++i) {
        const CK_RV rv = serveAttribute(*slot, *obj, pTemplate[i]);
        if (rv == CKR_ATTRIBUTE_TYPE_INVALID) {
            pTemplate[i].ulValueLen = CK_UNAVAILABLE_INFORMATION;
            overall = CKR_ATTRIBUTE_TYPE_INVALID;
        } else if (rv != CKR_OK) {
            overall = rv; // buffer-too-small / failure
        }
    }
    return overall;
    PKCS11_CATCH
}

CK_DECLARE_FUNCTION(CK_RV, C_SetAttributeValue)
(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
    (void)hSession;
    (void)hObject;
    (void)pTemplate;
    (void)ulCount;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DECLARE_FUNCTION(CK_RV, C_FindObjectsInit)(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
    PKCS11_TRY
    std::lock_guard lk(g_mutex);
    if (!g_lib)
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    Session* s = g_lib->state.session(hSession);
    if (!s)
        return CKR_SESSION_HANDLE_INVALID;
    if (s->find.active)
        return CKR_OPERATION_ACTIVE;
    s->find.matches = g_lib->state.findMatches(s->slot, pTemplate, ulCount);
    s->find.next = 0;
    s->find.active = true;
    return CKR_OK;
    PKCS11_CATCH
}

CK_DECLARE_FUNCTION(CK_RV, C_FindObjects)
(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE_PTR phObject, CK_ULONG ulMaxObjectCount, CK_ULONG_PTR pulObjectCount)
{
    PKCS11_TRY
    std::lock_guard lk(g_mutex);
    if (!g_lib)
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (phObject == NULL_PTR || pulObjectCount == NULL_PTR)
        return CKR_ARGUMENTS_BAD;
    Session* s = g_lib->state.session(hSession);
    if (!s)
        return CKR_SESSION_HANDLE_INVALID;
    if (!s->find.active)
        return CKR_OPERATION_NOT_INITIALIZED;
    CK_ULONG n = 0;
    while (n < ulMaxObjectCount && s->find.next < s->find.matches.size())
        phObject[n++] = s->find.matches[s->find.next++];
    *pulObjectCount = n;
    return CKR_OK;
    PKCS11_CATCH
}

CK_DECLARE_FUNCTION(CK_RV, C_FindObjectsFinal)(CK_SESSION_HANDLE hSession)
{
    PKCS11_TRY
    std::lock_guard lk(g_mutex);
    if (!g_lib)
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    Session* s = g_lib->state.session(hSession);
    if (!s)
        return CKR_SESSION_HANDLE_INVALID;
    if (!s->find.active)
        return CKR_OPERATION_NOT_INITIALIZED;
    s->find = FindCursor{};
    return CKR_OK;
    PKCS11_CATCH
}

// ===========================================================================
// Encryption (deferred — the module never encrypts; no libcrypto linked)
// ===========================================================================

CK_DECLARE_FUNCTION(CK_RV, C_EncryptInit)
(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
    (void)hSession;
    (void)pMechanism;
    (void)hKey;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DECLARE_FUNCTION(CK_RV, C_Encrypt)
(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pEncryptedData,
 CK_ULONG_PTR pulEncryptedDataLen)
{
    (void)hSession;
    (void)pData;
    (void)ulDataLen;
    (void)pEncryptedData;
    (void)pulEncryptedDataLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DECLARE_FUNCTION(CK_RV, C_EncryptUpdate)
(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart,
 CK_ULONG_PTR pulEncryptedPartLen)
{
    (void)hSession;
    (void)pPart;
    (void)ulPartLen;
    (void)pEncryptedPart;
    (void)pulEncryptedPartLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DECLARE_FUNCTION(CK_RV, C_EncryptFinal)
(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastEncryptedPart, CK_ULONG_PTR pulLastEncryptedPartLen)
{
    (void)hSession;
    (void)pLastEncryptedPart;
    (void)pulLastEncryptedPartLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

// ===========================================================================
// Decryption -> agent Decrypt (RSA PKCS#1 v1.5)
// ===========================================================================

CK_DECLARE_FUNCTION(CK_RV, C_DecryptInit)
(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
    PKCS11_TRY
    std::lock_guard lk(g_mutex);
    if (!g_lib)
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (pMechanism == NULL_PTR)
        return CKR_ARGUMENTS_BAD;
    Session* s = g_lib->state.session(hSession);
    if (!s)
        return CKR_SESSION_HANDLE_INVALID;
    if (s->decrypt.active)
        return CKR_OPERATION_ACTIVE;
    const Slot* slot = g_lib->state.slotById(s->slot);
    if (!slot)
        return CKR_SESSION_HANDLE_INVALID;
    // Only CKM_RSA_PKCS decrypt; reject anything else (incl. when the slot does
    // not advertise it, e.g. NAM v1 -> CKR_MECHANISM_INVALID).
    if (pMechanism->mechanism != CKM_RSA_PKCS || !slotHasMechanism(*slot, CKM_RSA_PKCS))
        return CKR_MECHANISM_INVALID;
    const Object* obj = g_lib->state.resolveObject(s->slot, hKey);
    if (!obj || obj->cls != CKO_PRIVATE_KEY)
        return CKR_KEY_HANDLE_INVALID;
    if (!obj->decrypt)
        return CKR_KEY_FUNCTION_NOT_PERMITTED;
    s->decrypt = DecryptCursor{};
    s->decrypt.active = true;
    s->decrypt.reader = slot->readerPath;
    s->decrypt.certId = obj->certId;
    return CKR_OK;
    PKCS11_CATCH
}

namespace {

// Drive one C_Decrypt / C_DecryptFinal. @p ct/ctLen is the full ciphertext block
// (single-part: the C_Decrypt argument; multi-part: the C_DecryptUpdate buffer
// snapshotted under lock and passed via @p useAccumulated). RSA is a single
// public-key block, so the agent's existing single-part Decrypt RPC services
// both: multi-part is just a deferred single-part. The blocking on-card decrypt
// runs with g_mutex RELEASED (it waits on the same PIN lease as a sign), so the
// lock is held only to validate the session + capture the cursor, then again to
// record the outcome. Re-entrant blocking ops on the same session are refused.
CK_RV doDecrypt(CK_SESSION_HANDLE hSession, const std::uint8_t* ct, std::size_t ctLen, bool useAccumulated,
                CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen)
{
    if (pulDataLen == NULL_PTR)
        return CKR_ARGUMENTS_BAD;

    // --- under lock: validate + capture (reader, certId), mark in-flight ----
    std::string reader;
    std::string certId;
    std::vector<std::uint8_t> accumulated; // the C_DecryptFinal multi-part buffer
    std::optional<RpcInFlightGuard> guard;
    {
        std::lock_guard lk(g_mutex);
        if (!g_lib)
            return CKR_CRYPTOKI_NOT_INITIALIZED;
        Session* s = g_lib->state.session(hSession);
        if (!s)
            return CKR_SESSION_HANDLE_INVALID;
        if (!s->decrypt.active)
            return CKR_OPERATION_NOT_INITIALIZED;
        if (s->rpcInFlight)
            return CKR_OPERATION_ACTIVE;
        reader = s->decrypt.reader;
        certId = s->decrypt.certId;
        if (useAccumulated)
            accumulated = s->decrypt.accumulated; // snapshot before releasing the lock
        // RAII: sets s->rpcInFlight + bumps the global in-flight count; cleared on
        // EVERY exit path, including a std::bad_alloc thrown by the ciphertext
        // buffer build below — otherwise the flag would leak and wedge the
        // session at CKR_OPERATION_ACTIVE.
        guard.emplace(s);
        guard->setHandle(hSession);
    }
    if (useAccumulated) {
        ct = accumulated.data();
        ctLen = accumulated.size();
    }

    // Cursor management only (the guard owns rpcInFlight + the global count).
    auto clearCursorIf = [&](bool clearCursor) {
        if (!clearCursor)
            return;
        std::lock_guard lk(g_mutex);
        if (!g_lib)
            return;
        if (Session* s = g_lib->state.session(hSession))
            s->decrypt = DecryptCursor{};
    };

    // --- lock RELEASED for the blocking on-card decrypt ----------------------
    std::vector<std::uint8_t> ciphertext(ct, ct + ctLen);
    auto res = g_lib->client.decrypt(reader, certId, ciphertext);
    if (res.status != Status::Ok) {
        clearCursorIf(/*clearCursor=*/true);
        return ckrFromStatus(res.status);
    }
    if (pData == NULL_PTR) {
        *pulDataLen = static_cast<CK_ULONG>(res.bytes.size());
        clearCursorIf(/*clearCursor=*/false); // size query keeps the operation active
        return CKR_OK;
    }
    if (*pulDataLen < res.bytes.size()) {
        *pulDataLen = static_cast<CK_ULONG>(res.bytes.size());
        clearCursorIf(/*clearCursor=*/false);
        return CKR_BUFFER_TOO_SMALL;
    }
    std::memcpy(pData, res.bytes.data(), res.bytes.size());
    *pulDataLen = static_cast<CK_ULONG>(res.bytes.size());
    clearCursorIf(/*clearCursor=*/true);
    return CKR_OK;
}

} // namespace

CK_DECLARE_FUNCTION(CK_RV, C_Decrypt)
(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedData, CK_ULONG ulEncryptedDataLen, CK_BYTE_PTR pData,
 CK_ULONG_PTR pulDataLen)
{
    PKCS11_TRY
    return doDecrypt(hSession, pEncryptedData, ulEncryptedDataLen, /*useAccumulated=*/false, pData, pulDataLen);
    PKCS11_CATCH
}

// Multi-part decrypt buffers the ciphertext across C_DecryptUpdate calls (RSA is
// a single public-key block, so this is a small bounded buffer) and runs the one
// on-card decrypt at C_DecryptFinal. Standard tools (pkcs11-tool, NSS) drive this
// path. C_DecryptUpdate yields NO intermediate plaintext — for RSA all output
// emerges at C_DecryptFinal — so it always reports zero output bytes.
CK_DECLARE_FUNCTION(CK_RV, C_DecryptUpdate)
(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart,
 CK_ULONG_PTR pulPartLen)
{
    PKCS11_TRY
    std::lock_guard lk(g_mutex);
    if (!g_lib)
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    Session* s = g_lib->state.session(hSession);
    if (!s)
        return CKR_SESSION_HANDLE_INVALID;
    if (!s->decrypt.active)
        return CKR_OPERATION_NOT_INITIALIZED;
    if (s->rpcInFlight)
        return CKR_OPERATION_ACTIVE;
    if (pEncryptedPart != NULL_PTR && ulEncryptedPartLen > 0)
        s->decrypt.accumulated.insert(s->decrypt.accumulated.end(), pEncryptedPart,
                                      pEncryptedPart + ulEncryptedPartLen);
    // No intermediate plaintext for RSA; report zero output. pPart is ignored —
    // for a single-block cipher the plaintext only emerges at C_DecryptFinal.
    (void)pPart;
    if (pulPartLen != NULL_PTR)
        *pulPartLen = 0;
    return CKR_OK;
    PKCS11_CATCH
}

CK_DECLARE_FUNCTION(CK_RV, C_DecryptFinal)
(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastPart, CK_ULONG_PTR pulLastPartLen)
{
    PKCS11_TRY
    return doDecrypt(hSession, nullptr, 0, /*useAccumulated=*/true, pLastPart, pulLastPartLen);
    PKCS11_CATCH
}

// ===========================================================================
// Message digesting (deferred — no libcrypto)
// ===========================================================================

CK_DECLARE_FUNCTION(CK_RV, C_DigestInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism)
{
    (void)hSession;
    (void)pMechanism;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DECLARE_FUNCTION(CK_RV, C_Digest)
(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen)
{
    (void)hSession;
    (void)pData;
    (void)ulDataLen;
    (void)pDigest;
    (void)pulDigestLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DECLARE_FUNCTION(CK_RV, C_DigestUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
    (void)hSession;
    (void)pPart;
    (void)ulPartLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DECLARE_FUNCTION(CK_RV, C_DigestKey)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey)
{
    (void)hSession;
    (void)hKey;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DECLARE_FUNCTION(CK_RV, C_DigestFinal)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen)
{
    (void)hSession;
    (void)pDigest;
    (void)pulDigestLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

// ===========================================================================
// Signing -> agent SignRaw (raw RSA PKCS#1 v1.5; caller supplies the DigestInfo)
// ===========================================================================

CK_DECLARE_FUNCTION(CK_RV, C_SignInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
    PKCS11_TRY
    std::lock_guard lk(g_mutex);
    if (!g_lib)
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (pMechanism == NULL_PTR)
        return CKR_ARGUMENTS_BAD;
    Session* s = g_lib->state.session(hSession);
    if (!s)
        return CKR_SESSION_HANDLE_INVALID;
    if (s->sign.active)
        return CKR_OPERATION_ACTIVE;
    const Slot* slot = g_lib->state.slotById(s->slot);
    if (!slot)
        return CKR_SESSION_HANDLE_INVALID;
    const CK_MECHANISM_TYPE mech = pMechanism->mechanism;
    // Two per-card RSA sign mechanisms, gated by slotHasMechanism so a slot only
    // ever accepts the one it advertised (never both):
    //   * CKM_RSA_PKCS  — DigestInfo family (opensc/PKS): caller supplies the
    //     complete pre-built DigestInfo; the card runs the raw private-key op.
    //   * CKM_SHA256_RSA_PKCS — hash-on-card family (pkcs15/NAM IAS-ECC SSCD):
    //     caller supplies the RAW message; the CARD computes SHA-256 and signs.
    //     The module stays libcrypto-free either way — it never hashes, it
    //     forwards the caller's bytes verbatim (the card or caller owns the
    //     digest). PSS / ECDSA / a slot's non-advertised mechanism all fall
    //     through to CKR_MECHANISM_INVALID.
    if ((mech != CKM_RSA_PKCS && mech != CKM_SHA256_RSA_PKCS) || !slotHasMechanism(*slot, mech))
        return CKR_MECHANISM_INVALID;
    const Object* obj = g_lib->state.resolveObject(s->slot, hKey);
    if (!obj || obj->cls != CKO_PRIVATE_KEY)
        return CKR_KEY_HANDLE_INVALID;
    if (!obj->sign)
        return CKR_KEY_FUNCTION_NOT_PERMITTED;

    s->sign = SignCursor{};
    s->sign.active = true;
    s->sign.reader = slot->readerPath;
    s->sign.certId = obj->certId;
    s->sign.modulusBits = obj->modulusBits;
    return CKR_OK;
    PKCS11_CATCH
}

namespace {

// Drive one C_Sign / C_SignFinal. @p data/len is the digest-or-block to sign.
// The blocking publicKey/signRaw RPCs run with g_mutex RELEASED (a sign waits on
// a human-paced PIN prompt), so the global lock is held only to validate the
// session + capture the cursor, then again to record the outcome. Re-entrant
// blocking ops on the same session are refused.
CK_RV doSign(CK_SESSION_HANDLE hSession, const std::uint8_t* data, std::size_t len, bool useAccumulated,
             CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
    if (pulSignatureLen == NULL_PTR)
        return CKR_ARGUMENTS_BAD;

    // --- under lock: validate + capture the cursor, mark in-flight ----------
    std::string reader;
    std::string certId;
    std::uint32_t modulusBits = 0;
    std::vector<std::uint8_t> accumulated; // the C_SignFinal multi-part buffer
    std::optional<RpcInFlightGuard> guard;
    {
        std::lock_guard lk(g_mutex);
        if (!g_lib)
            return CKR_CRYPTOKI_NOT_INITIALIZED;
        Session* s = g_lib->state.session(hSession);
        if (!s)
            return CKR_SESSION_HANDLE_INVALID;
        if (!s->sign.active)
            return CKR_OPERATION_NOT_INITIALIZED;
        if (s->rpcInFlight)
            return CKR_OPERATION_ACTIVE;
        reader = s->sign.reader;
        certId = s->sign.certId;
        modulusBits = s->sign.modulusBits;
        if (useAccumulated)
            accumulated = s->sign.accumulated; // snapshot before releasing the lock
        // RAII: sets s->rpcInFlight + bumps the global in-flight count; cleared on
        // EVERY exit path, including a std::bad_alloc thrown by buildSignInput
        // below — otherwise the flag would leak + wedge the session.
        guard.emplace(s);
        guard->setHandle(hSession);
    }
    if (useAccumulated) {
        data = accumulated.data();
        len = accumulated.size();
    }

    // Cursor management only (the guard owns rpcInFlight + the global count).
    auto clearCursorIf = [&](bool clearCursor) {
        if (!clearCursor)
            return;
        std::lock_guard lk(g_mutex);
        if (!g_lib)
            return;
        if (Session* s = g_lib->state.session(hSession))
            s->sign = SignCursor{};
    };

    // --- lock RELEASED for the blocking RPCs --------------------------------
    // Size query: derive the signature length from the modulus (RSA sig == k).
    // Prefer the cursor's modulusBits; otherwise fetch the public-key modulus
    // (public data, cached) so a size query NEVER triggers a real on-card sign.
    if (pSignature == NULL_PTR) {
        if (modulusBits == 0) {
            auto pk = g_lib->client.publicKey(reader, certId);
            if (pk.status == Status::Ok && !pk.modulus.empty())
                modulusBits = static_cast<std::uint32_t>(pk.modulus.size()) * 8;
        }
        if (modulusBits != 0) {
            *pulSignatureLen = (modulusBits + 7) / 8;
            // Persist the learned size; keep the operation active (the guard
            // clears rpcInFlight + the count on return).
            {
                std::lock_guard lk(g_mutex);
                if (g_lib)
                    if (Session* s = g_lib->state.session(hSession))
                        s->sign.modulusBits = modulusBits;
            }
            return CKR_OK;
        }
        // Modulus unavailable (non-RSA / error): fall through to a real call.
    }

    std::vector<std::uint8_t> input = buildSignInput(data, len);
    auto res = g_lib->client.signRaw(reader, certId, input);
    if (res.status != Status::Ok) {
        clearCursorIf(/*clearCursor=*/true);
        return ckrFromStatus(res.status);
    }
    if (pSignature == NULL_PTR) {
        *pulSignatureLen = static_cast<CK_ULONG>(res.bytes.size());
        clearCursorIf(/*clearCursor=*/false); // size query keeps the op active
        return CKR_OK;
    }
    if (*pulSignatureLen < res.bytes.size()) {
        *pulSignatureLen = static_cast<CK_ULONG>(res.bytes.size());
        clearCursorIf(/*clearCursor=*/false);
        return CKR_BUFFER_TOO_SMALL;
    }
    std::memcpy(pSignature, res.bytes.data(), res.bytes.size());
    *pulSignatureLen = static_cast<CK_ULONG>(res.bytes.size());
    clearCursorIf(/*clearCursor=*/true);
    return CKR_OK;
}

} // namespace

CK_DECLARE_FUNCTION(CK_RV, C_Sign)
(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature,
 CK_ULONG_PTR pulSignatureLen)
{
    PKCS11_TRY
    return doSign(hSession, pData, ulDataLen, /*useAccumulated=*/false, pSignature, pulSignatureLen);
    PKCS11_CATCH
}

CK_DECLARE_FUNCTION(CK_RV, C_SignUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
    PKCS11_TRY
    std::lock_guard lk(g_mutex);
    if (!g_lib)
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    Session* s = g_lib->state.session(hSession);
    if (!s)
        return CKR_SESSION_HANDLE_INVALID;
    if (!s->sign.active)
        return CKR_OPERATION_NOT_INITIALIZED;
    s->sign.accumulated.insert(s->sign.accumulated.end(), pPart, pPart + ulPartLen);
    return CKR_OK;
    PKCS11_CATCH
}

CK_DECLARE_FUNCTION(CK_RV, C_SignFinal)
(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
    PKCS11_TRY
    return doSign(hSession, nullptr, 0, /*useAccumulated=*/true, pSignature, pulSignatureLen);
    PKCS11_CATCH
}

CK_DECLARE_FUNCTION(CK_RV, C_SignRecoverInit)
(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
    (void)hSession;
    (void)pMechanism;
    (void)hKey;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DECLARE_FUNCTION(CK_RV, C_SignRecover)
(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature,
 CK_ULONG_PTR pulSignatureLen)
{
    (void)hSession;
    (void)pData;
    (void)ulDataLen;
    (void)pSignature;
    (void)pulSignatureLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

// ===========================================================================
// Verifying (deferred — no libcrypto linked)
// ===========================================================================

CK_DECLARE_FUNCTION(CK_RV, C_VerifyInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
    (void)hSession;
    (void)pMechanism;
    (void)hKey;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DECLARE_FUNCTION(CK_RV, C_Verify)
(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen)
{
    (void)hSession;
    (void)pData;
    (void)ulDataLen;
    (void)pSignature;
    (void)ulSignatureLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DECLARE_FUNCTION(CK_RV, C_VerifyUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
    (void)hSession;
    (void)pPart;
    (void)ulPartLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DECLARE_FUNCTION(CK_RV, C_VerifyFinal)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen)
{
    (void)hSession;
    (void)pSignature;
    (void)ulSignatureLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DECLARE_FUNCTION(CK_RV, C_VerifyRecoverInit)
(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
    (void)hSession;
    (void)pMechanism;
    (void)hKey;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DECLARE_FUNCTION(CK_RV, C_VerifyRecover)
(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen, CK_BYTE_PTR pData,
 CK_ULONG_PTR pulDataLen)
{
    (void)hSession;
    (void)pSignature;
    (void)ulSignatureLen;
    (void)pData;
    (void)pulDataLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

// ===========================================================================
// Dual-function (deferred)
// ===========================================================================

CK_DECLARE_FUNCTION(CK_RV, C_DigestEncryptUpdate)
(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart,
 CK_ULONG_PTR pulEncryptedPartLen)
{
    (void)hSession;
    (void)pPart;
    (void)ulPartLen;
    (void)pEncryptedPart;
    (void)pulEncryptedPartLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DECLARE_FUNCTION(CK_RV, C_DecryptDigestUpdate)
(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart,
 CK_ULONG_PTR pulPartLen)
{
    (void)hSession;
    (void)pEncryptedPart;
    (void)ulEncryptedPartLen;
    (void)pPart;
    (void)pulPartLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DECLARE_FUNCTION(CK_RV, C_SignEncryptUpdate)
(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart,
 CK_ULONG_PTR pulEncryptedPartLen)
{
    (void)hSession;
    (void)pPart;
    (void)ulPartLen;
    (void)pEncryptedPart;
    (void)pulEncryptedPartLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DECLARE_FUNCTION(CK_RV, C_DecryptVerifyUpdate)
(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart,
 CK_ULONG_PTR pulPartLen)
{
    (void)hSession;
    (void)pEncryptedPart;
    (void)ulEncryptedPartLen;
    (void)pPart;
    (void)pulPartLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

// ===========================================================================
// Key management (out of scope)
// ===========================================================================

CK_DECLARE_FUNCTION(CK_RV, C_GenerateKey)
(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount,
 CK_OBJECT_HANDLE_PTR phKey)
{
    (void)hSession;
    (void)pMechanism;
    (void)pTemplate;
    (void)ulCount;
    (void)phKey;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DECLARE_FUNCTION(CK_RV, C_GenerateKeyPair)
(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pPublicKeyTemplate,
 CK_ULONG ulPublicKeyAttributeCount, CK_ATTRIBUTE_PTR pPrivateKeyTemplate, CK_ULONG ulPrivateKeyAttributeCount,
 CK_OBJECT_HANDLE_PTR phPublicKey, CK_OBJECT_HANDLE_PTR phPrivateKey)
{
    (void)hSession;
    (void)pMechanism;
    (void)pPublicKeyTemplate;
    (void)ulPublicKeyAttributeCount;
    (void)pPrivateKeyTemplate;
    (void)ulPrivateKeyAttributeCount;
    (void)phPublicKey;
    (void)phPrivateKey;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DECLARE_FUNCTION(CK_RV, C_WrapKey)
(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hWrappingKey, CK_OBJECT_HANDLE hKey,
 CK_BYTE_PTR pWrappedKey, CK_ULONG_PTR pulWrappedKeyLen)
{
    (void)hSession;
    (void)pMechanism;
    (void)hWrappingKey;
    (void)hKey;
    (void)pWrappedKey;
    (void)pulWrappedKeyLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DECLARE_FUNCTION(CK_RV, C_UnwrapKey)
(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hUnwrappingKey, CK_BYTE_PTR pWrappedKey,
 CK_ULONG ulWrappedKeyLen, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey)
{
    (void)hSession;
    (void)pMechanism;
    (void)hUnwrappingKey;
    (void)pWrappedKey;
    (void)ulWrappedKeyLen;
    (void)pTemplate;
    (void)ulAttributeCount;
    (void)phKey;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DECLARE_FUNCTION(CK_RV, C_DeriveKey)
(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hBaseKey, CK_ATTRIBUTE_PTR pTemplate,
 CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey)
{
    (void)hSession;
    (void)pMechanism;
    (void)hBaseKey;
    (void)pTemplate;
    (void)ulAttributeCount;
    (void)phKey;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

// ===========================================================================
// Random (deferred)
// ===========================================================================

CK_DECLARE_FUNCTION(CK_RV, C_SeedRandom)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSeed, CK_ULONG ulSeedLen)
{
    (void)hSession;
    (void)pSeed;
    (void)ulSeedLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DECLARE_FUNCTION(CK_RV, C_GenerateRandom)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR RandomData, CK_ULONG ulRandomLen)
{
    (void)hSession;
    (void)RandomData;
    (void)ulRandomLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

// ===========================================================================
// Parallel function management (legacy)
// ===========================================================================

CK_DECLARE_FUNCTION(CK_RV, C_GetFunctionStatus)(CK_SESSION_HANDLE hSession)
{
    (void)hSession;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DECLARE_FUNCTION(CK_RV, C_CancelFunction)(CK_SESSION_HANDLE hSession)
{
    (void)hSession;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

// ===========================================================================
// Slot event (live updates handled by re-snapshot in C_GetSlotList)
// ===========================================================================

CK_DECLARE_FUNCTION(CK_RV, C_WaitForSlotEvent)(CK_FLAGS flags, CK_SLOT_ID_PTR pSlot, CK_VOID_PTR pReserved)
{
    (void)flags;
    (void)pSlot;
    (void)pReserved;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

// ===========================================================================
// Function list table + C_GetFunctionList
// ===========================================================================

// Advertise PKCS#11 v2.40 for maximum loader compatibility (Java SunPKCS11 does
// not support v3.x and rejects a 3.x version in the function list). Mirrors the
// LibreMiddleware native module.
static CK_FUNCTION_LIST function_list = {
    {2, 40},
    C_Initialize,
    C_Finalize,
    C_GetInfo,
    C_GetFunctionList,
    C_GetSlotList,
    C_GetSlotInfo,
    C_GetTokenInfo,
    C_GetMechanismList,
    C_GetMechanismInfo,
    C_InitToken,
    C_InitPIN,
    C_SetPIN,
    C_OpenSession,
    C_CloseSession,
    C_CloseAllSessions,
    C_GetSessionInfo,
    C_GetOperationState,
    C_SetOperationState,
    C_Login,
    C_Logout,
    C_CreateObject,
    C_CopyObject,
    C_DestroyObject,
    C_GetObjectSize,
    C_GetAttributeValue,
    C_SetAttributeValue,
    C_FindObjectsInit,
    C_FindObjects,
    C_FindObjectsFinal,
    C_EncryptInit,
    C_Encrypt,
    C_EncryptUpdate,
    C_EncryptFinal,
    C_DecryptInit,
    C_Decrypt,
    C_DecryptUpdate,
    C_DecryptFinal,
    C_DigestInit,
    C_Digest,
    C_DigestUpdate,
    C_DigestKey,
    C_DigestFinal,
    C_SignInit,
    C_Sign,
    C_SignUpdate,
    C_SignFinal,
    C_SignRecoverInit,
    C_SignRecover,
    C_VerifyInit,
    C_Verify,
    C_VerifyUpdate,
    C_VerifyFinal,
    C_VerifyRecoverInit,
    C_VerifyRecover,
    C_DigestEncryptUpdate,
    C_DecryptDigestUpdate,
    C_SignEncryptUpdate,
    C_DecryptVerifyUpdate,
    C_GenerateKey,
    C_GenerateKeyPair,
    C_WrapKey,
    C_UnwrapKey,
    C_DeriveKey,
    C_SeedRandom,
    C_GenerateRandom,
    C_GetFunctionStatus,
    C_CancelFunction,
    C_WaitForSlotEvent,
};

extern "C" CK_DECLARE_FUNCTION(CK_RV, C_GetFunctionList)(CK_FUNCTION_LIST_PTR_PTR ppFunctionList)
{
    if (ppFunctionList == NULL_PTR)
        return CKR_ARGUMENTS_BAD;
    *ppFunctionList = &function_list;
    return CKR_OK;
}
