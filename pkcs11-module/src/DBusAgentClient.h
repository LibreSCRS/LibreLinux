// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// DBusAgentClient — the sdbus-c++ implementation of AgentClient. It enumerates
// readers/cards via the agent's ObjectManager, drives the per-card
// ReadCertificates operation to learn the signing certs + their capabilities,
// and brokers the low-level Pkcs11_1 primitives (CertDer / Login / Logout /
// SignRaw / Decrypt) over the session bus.
//
// The agent's D-Bus error names are this transport's vocabulary and are mapped
// to the interface's Status here, not in the interface.

#pragma once

#include <LibreSCRS/Agent/pkcs11/AgentClient.h>

#include <memory>

namespace sdbus {
class IConnection;
class IProxy;
} // namespace sdbus

namespace LibreSCRS::Pkcs11Agent {

/// @brief Maps an agent D-Bus error name (org.librescrs.Agent.Error.*) to a
///        Status. Pure + exposed for unit testing.
[[nodiscard]] Status mapErrorName(const std::string& errorName) noexcept;

/// @brief Brokers all D-Bus traffic to the agent over the session bus.
class DBusAgentClient final : public AgentClient
{
public:
    /// @brief Connect to the session bus + the agent's well-known name.
    ///        Throws nothing fatal on a missing agent: connected() reports it
    ///        and subsequent calls return DeviceRemoved.
    DBusAgentClient();
    ~DBusAgentClient() override;

    [[nodiscard]] bool connected() const noexcept override;

    /// @brief Cached: re-enumerates from the bus only when the cache is dirty
    ///        (first call, or after an ObjectManager InterfacesAdded/Removed
    ///        signal flipped a reader/card). Live presence changes therefore
    ///        surface on the next C_GetSlotList without a per-call
    ///        ReadCertificates.
    [[nodiscard]] AgentSnapshot snapshot() override;

    [[nodiscard]] BytesResult certDer(const std::string& reader, const std::string& certId) override;

    /// @brief Lazily fetched + cached per certId — the second call for the same
    ///        key serves the cache.
    [[nodiscard]] PublicKeyResult publicKey(const std::string& reader, const std::string& certId) override;

    [[nodiscard]] LoginResult login(const std::string& reader) override;

    Status logout(const std::string& reader) override;

    [[nodiscard]] BytesResult signRaw(const std::string& reader, const std::string& certId,
                                      std::span<const std::uint8_t> input) override;

    [[nodiscard]] BytesResult decrypt(const std::string& reader, const std::string& certId,
                                      std::span<const std::uint8_t> ciphertext) override;

private:
    /// @brief Do the actual ObjectManager + ReadCertificates enumeration (no cache).
    [[nodiscard]] AgentSnapshot enumerate();

    struct Impl;
    std::unique_ptr<Impl> m_impl;
};

} // namespace LibreSCRS::Pkcs11Agent
