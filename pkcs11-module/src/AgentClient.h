// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// AgentClient — the sdbus-c++ proxy the module uses to talk to the per-user
// librescrs-agent. It enumerates readers/cards via the agent's ObjectManager,
// drives the per-card ReadCertificates operation to learn the signing certs +
// their capabilities, and brokers the low-level Pkcs11_1 primitives
// (CertDer / Login / Logout / SignRaw / Decrypt).
//
// The module holds NO secret: sign/decrypt I/O passes straight through and is
// NEVER logged. Agent D-Bus error names are mapped to a Status enum the C_*
// layer translates to CKR_*. No crypto here, no Qt.

#pragma once

#include "ObjectModel.h"

#include <cstdint>
#include <memory>
#include <mutex>
#include <span>
#include <string>
#include <vector>

namespace sdbus {
class IConnection;
class IProxy;
} // namespace sdbus

namespace LibreSCRS::Pkcs11Agent {

/// @brief Outcome of an AgentClient call, mapped from agent D-Bus error names.
enum class Status : std::uint8_t {
    Ok,
    UserNotLoggedIn, ///< org.librescrs.Agent.Error.UserNotLoggedIn  -> CKR_USER_NOT_LOGGED_IN
    NotAuthorized,   ///< Error.NotAuthorized                        -> CKR_PIN_INCORRECT / FUNCTION_FAILED
    AuthFailed,      ///< Error.AuthFailed (card rejected the PIN)   -> CKR_PIN_INCORRECT
    Cancelled,       ///< Error.Cancelled (user cancelled)           -> CKR_FUNCTION_CANCELED
    KeyNotFound,     ///< Error.KeyNotFound                          -> CKR_KEY_HANDLE_INVALID
    UnknownCard,     ///< Error.UnknownCard (no card on reader)      -> CKR_TOKEN_NOT_PRESENT
    NotSupported,    ///< Error.NotSupported                         -> CKR_FUNCTION_NOT_SUPPORTED
    RateLimited,     ///< Error.RateLimited                          -> CKR_FUNCTION_REJECTED
    Communication,   ///< Error.CommunicationError                   -> CKR_DEVICE_ERROR
    DeviceRemoved,   ///< connection lost / no agent                 -> CKR_DEVICE_REMOVED
    GeneralError,    ///< anything else                              -> CKR_GENERAL_ERROR
};

/// @brief A login lease handle returned by login().
struct LoginResult
{
    Status status = Status::GeneralError;
    std::uint32_t idleTimeoutSecs = 0;
};

/// @brief A bytes-or-status result for sign / decrypt / certDer.
struct BytesResult
{
    Status status = Status::GeneralError;
    std::vector<std::uint8_t> bytes;
};

/// @brief The RSA public key (modulus + public exponent) for a signing cert.
///        Both are unpadded big-endian (PKCS#11 CKA_* convention) exactly as the
///        agent returns them. The module serves CKA_MODULUS / CKA_PUBLIC_EXPONENT
///        from these without any crypto of its own.
struct PublicKeyResult
{
    Status status = Status::GeneralError;
    std::vector<std::uint8_t> modulus;
    std::vector<std::uint8_t> exponent;
};

/// @brief Maps an agent D-Bus error name (org.librescrs.Agent.Error.*) to a
///        Status. Pure + exposed for unit testing.
[[nodiscard]] Status mapErrorName(const std::string& errorName) noexcept;

/// @brief Brokers all D-Bus traffic to the agent over the session bus.
class AgentClient
{
public:
    /// @brief Connect to the session bus + the agent's well-known name.
    ///        Throws nothing fatal on a missing agent: connected() reports it
    ///        and subsequent calls return DeviceRemoved.
    AgentClient();
    ~AgentClient();

    AgentClient(const AgentClient&) = delete;
    AgentClient& operator=(const AgentClient&) = delete;

    /// @brief True once a session-bus connection exists (agent may still be off).
    [[nodiscard]] bool connected() const noexcept;

    /// @brief Enumerate readers/cards + per-card signing certs into a snapshot.
    ///        Cached: re-enumerates from the bus only when the cache is dirty
    ///        (first call, or after an ObjectManager InterfacesAdded/Removed
    ///        signal flipped a reader/card). Live presence changes therefore
    ///        surface on the next C_GetSlotList without a per-call ReadCertificates.
    [[nodiscard]] AgentSnapshot snapshot();

    /// @brief Public cert DER for (reader, certId). No consent, no lease.
    [[nodiscard]] BytesResult certDer(const std::string& reader, const std::string& certId);

    /// @brief RSA public key (modulus + public exponent) for (reader, certId).
    ///        Public data (no consent, no lease). Lazily fetched + cached per
    ///        certId — the second call for the same key serves the cache. The
    ///        module serves CKA_MODULUS / CKA_PUBLIC_EXPONENT from these.
    [[nodiscard]] PublicKeyResult publicKey(const std::string& reader, const std::string& certId);

    /// @brief Establish/refresh the login lease (raises the agent prompter).
    ///        The lease is (caller, card)-scoped (C_Login is per-token), so no
    ///        certId is passed.
    [[nodiscard]] LoginResult login(const std::string& reader);

    /// @brief Drop the lease for (caller, card). Idempotent.
    Status logout(const std::string& reader);

    /// @brief Raw RSA PKCS#1 v1.5 sign over @p input (DigestInfo-or-raw bytes).
    [[nodiscard]] BytesResult signRaw(const std::string& reader, const std::string& certId,
                                      std::span<const std::uint8_t> input);

    /// @brief Raw RSA PKCS#1 v1.5 decrypt of @p ciphertext.
    [[nodiscard]] BytesResult decrypt(const std::string& reader, const std::string& certId,
                                      std::span<const std::uint8_t> ciphertext);

private:
    /// @brief Do the actual ObjectManager + ReadCertificates enumeration (no cache).
    [[nodiscard]] AgentSnapshot enumerate();

    struct Impl;
    std::unique_ptr<Impl> m_impl;
};

} // namespace LibreSCRS::Pkcs11Agent
