// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Test-only fake librescrs-agent on a private session bus. Hosts:
//   - built-in ObjectManager on /org/librescrs/Agent
//   - org.librescrs.Agent.Pkcs11_1 (CertDer/Login/Logout/SignRaw/Decrypt)
//   - a Reader1 child + (when hasCard) a Card1 child with ReadCertificates that
//     emits Certificates1.Result then Operation1.Finished(Ok)
// Used by AgentClientTest (proxy-level) and ModuleAbiTest (dlopen C_* level).

#pragma once

#include "AgentInterfaceNames.h" // shared service/path/interface names
#include "CertResultWire.h"      // shared CertResultEntry — no drift from the consumer

#include <sdbus-c++/sdbus-c++.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <thread>
#include <vector>

namespace librescrs_pkcs11_testfake {

// Service / path / interface names come from common/AgentInterfaceNames.h
// (LibreLinux::AgentWire), shared with the production proxy so the fake cannot
// disagree with what the module addresses.
using LibreLinux::AgentWire::kCardIface;
using LibreLinux::AgentWire::kCertificatesIface;
using LibreLinux::AgentWire::kOperation1Iface;
using LibreLinux::AgentWire::kPkcs11Iface;
using LibreLinux::AgentWire::kReaderIface;
using LibreLinux::AgentWire::kRootPath;
using LibreLinux::AgentWire::kServiceName;

// Object paths specific to this fake's tree (not part of the shared contract).
inline constexpr const char* kReader0 = "/org/librescrs/Agent/reader/0";
inline constexpr const char* kCard0 = "/org/librescrs/Agent/card/0";
inline constexpr const char* kOp0 = "/org/librescrs/Agent/op/0";

// One definition, shared with the production consumer (src/AgentClient.cpp), so
// the fake's Result shape can never drift from what the module demarshals.
using LibreSCRS::Pkcs11Agent::CertFieldGroups;
using LibreSCRS::Pkcs11Agent::CertResultEntry;

inline const std::vector<std::uint8_t> kCannedSig = {0xAA, 0xBB, 0xCC, 0xDD};
inline const std::vector<std::uint8_t> kCannedPlain = {0x11, 0x22, 0x33};
inline const std::vector<std::uint8_t> kCannedDer = {0x30, 0x82, 0x01};
inline constexpr const char* kCertId = "cert-abc";

// A known RSA public key the fake serves over Pkcs11_1.PublicKey: a 256-byte
// (2048-bit) big-endian modulus whose top byte is non-zero (the CKA_* unpadded
// convention) + the canonical F4 exponent 0x010001.
inline const std::vector<std::uint8_t> kCannedExponent = {0x01, 0x00, 0x01};
inline std::vector<std::uint8_t> cannedModulus()
{
    std::vector<std::uint8_t> n(256, 0x00);
    n[0] = 0xC4; // non-zero MSB => 2048-bit unpadded modulus
    for (std::size_t i = 1; i < n.size(); ++i)
        n[i] = static_cast<std::uint8_t>(i & 0xFF);
    return n;
}

class FakeAgent
{
public:
    FakeAgent(sdbus::IConnection& conn, bool hasCard, const std::string& preRead)
        : m_hasCard(hasCard), m_preRead(preRead)
    {
        m_root = sdbus::createObject(conn, sdbus::ObjectPath{kRootPath});
        m_root->addObjectManager();
        m_root
            ->addVTable(
                sdbus::registerMethod("CertDer")
                    .implementedAs([this](sdbus::ObjectPath, std::string) -> std::vector<std::uint8_t> {
                        if (!m_certDerError.empty())
                            throw sdbus::Error{sdbus::Error::Name{m_certDerError}, "certder err"};
                        return kCannedDer;
                    })
                    .withInputParamNames("reader", "certId")
                    .withOutputParamNames("der"),
                sdbus::registerMethod("PublicKey")
                    .implementedAs([this](sdbus::ObjectPath, std::string)
                                       -> std::tuple<std::vector<std::uint8_t>, std::vector<std::uint8_t>> {
                        if (!m_publicKeyError.empty())
                            throw sdbus::Error{sdbus::Error::Name{m_publicKeyError}, "pubkey err"};
                        return {cannedModulus(), kCannedExponent};
                    })
                    .withInputParamNames("reader", "certId")
                    .withOutputParamNames("modulus", "exponent"),
                sdbus::registerMethod("Login")
                    .implementedAs([this](sdbus::ObjectPath) -> std::uint32_t {
                        if (!m_loginError.empty())
                            throw sdbus::Error{sdbus::Error::Name{m_loginError}, "login err"};
                        return 600;
                    })
                    .withInputParamNames("reader")
                    .withOutputParamNames("idleTimeoutSecs"),
                sdbus::registerMethod("Logout").implementedAs([](sdbus::ObjectPath) {}).withInputParamNames("reader"),
                sdbus::registerMethod("SignRaw")
                    .implementedAs([this](sdbus::ObjectPath, std::string,
                                          std::vector<std::uint8_t> input) -> std::vector<std::uint8_t> {
                        if (!m_signError.empty())
                            throw sdbus::Error{sdbus::Error::Name{m_signError}, "sign err"};
                        // Simulate a slow, human-paced on-card sign (PIN
                        // prompt). The agent stays blocked here; the
                        // module must NOT hold its global lock meanwhile.
                        if (const auto d = m_signDelayMs.load(); d > 0)
                            std::this_thread::sleep_for(std::chrono::milliseconds(d));
                        m_lastSignInput = input;
                        return kCannedSig;
                    })
                    .withInputParamNames("reader", "certId", "input")
                    .withOutputParamNames("signature"),
                sdbus::registerMethod("Decrypt")
                    .implementedAs(
                        [this](sdbus::ObjectPath, std::string, std::vector<std::uint8_t>) -> std::vector<std::uint8_t> {
                            if (!m_decryptError.empty())
                                throw sdbus::Error{sdbus::Error::Name{m_decryptError}, "dec err"};
                            return kCannedPlain;
                        })
                    .withInputParamNames("reader", "certId", "ciphertext")
                    .withOutputParamNames("plaintext"))
            .forInterface(sdbus::InterfaceName{kPkcs11Iface});

        m_reader = sdbus::createObject(conn, sdbus::ObjectPath{kReader0});
        m_reader
            ->addVTable(sdbus::registerProperty("Name").withGetter([] { return std::string{"FakeReader"}; }),
                        sdbus::registerProperty("HasCard").withGetter([this] { return m_hasCard.load(); }),
                        sdbus::registerProperty("Card").withGetter(
                            [this] { return m_hasCard ? sdbus::ObjectPath{kCard0} : sdbus::ObjectPath{"/"}; }))
            .forInterface(sdbus::InterfaceName{kReaderIface});

        if (m_hasCard) {
            m_card = sdbus::createObject(conn, sdbus::ObjectPath{kCard0});
            m_card
                ->addVTable(sdbus::registerProperty("Capabilities").withGetter([] { return std::uint32_t{0x3}; }),
                            sdbus::registerProperty("Reader").withGetter([] { return sdbus::ObjectPath{kReader0}; }),
                            sdbus::registerProperty("PreReadAuthMethod").withGetter([this] { return m_preRead; }),
                            sdbus::registerMethod("ReadCertificates")
                                .implementedAs([this] { return readCertificates(); })
                                .withOutputParamNames("operation"))
                .forInterface(sdbus::InterfaceName{kCardIface});
        }

        m_op = sdbus::createObject(conn, sdbus::ObjectPath{kOp0});
        m_op->addVTable(sdbus::registerSignal("Result").withParameters<std::vector<CertResultEntry>>("certificates"))
            .forInterface(sdbus::InterfaceName{kCertificatesIface});
        m_op->addVTable(sdbus::registerSignal("Finished")
                            .withParameters<std::uint32_t, std::uint32_t, std::string, std::string>(
                                "status", "errorCode", "msgKey", "msgFallback"))
            .forInterface(sdbus::InterfaceName{kOperation1Iface});
    }

    // Live-update support: insert/remove the card at runtime and emit the
    // matching ObjectManager signal so a subscribed client invalidates its cache.
    // Requires the connection so a Card1 object can be (re)created.
    void insertCard(sdbus::IConnection& conn)
    {
        if (m_card)
            return;
        m_hasCard = true;
        m_card = sdbus::createObject(conn, sdbus::ObjectPath{kCard0});
        m_card
            ->addVTable(sdbus::registerProperty("Capabilities").withGetter([] { return std::uint32_t{0x3}; }),
                        sdbus::registerProperty("Reader").withGetter([] { return sdbus::ObjectPath{kReader0}; }),
                        sdbus::registerProperty("PreReadAuthMethod").withGetter([this] { return m_preRead; }),
                        sdbus::registerMethod("ReadCertificates")
                            .implementedAs([this] { return readCertificates(); })
                            .withOutputParamNames("operation"))
            .forInterface(sdbus::InterfaceName{kCardIface});
        m_root->emitSignal(sdbus::SignalName{"InterfacesAdded"})
            .onInterface(sdbus::InterfaceName{"org.freedesktop.DBus.ObjectManager"})
            .withArguments(sdbus::ObjectPath{kCard0},
                           std::map<std::string, std::map<std::string, sdbus::Variant>>{{std::string{kCardIface}, {}}});
    }
    void removeCard()
    {
        if (!m_card)
            return;
        m_hasCard = false;
        m_card.reset();
        m_root->emitSignal(sdbus::SignalName{"InterfacesRemoved"})
            .onInterface(sdbus::InterfaceName{"org.freedesktop.DBus.ObjectManager"})
            .withArguments(sdbus::ObjectPath{kCard0}, std::vector<std::string>{std::string{kCardIface}});
    }

    void setSignError(const std::string& name)
    {
        m_signError = name;
    }
    void setDecryptError(const std::string& name)
    {
        m_decryptError = name;
    }
    void setLoginError(const std::string& name)
    {
        m_loginError = name;
    }
    void setPublicKeyError(const std::string& name)
    {
        m_publicKeyError = name;
    }
    void setCertDerError(const std::string& name)
    {
        m_certDerError = name;
    }
    // Make SignRaw block for @p ms before replying (simulate a human-paced PIN
    // prompt / slow on-card op). Thread-safe to set from the test thread.
    void setSignDelayMs(int ms)
    {
        m_signDelayMs.store(ms);
    }
    [[nodiscard]] std::vector<std::uint8_t> lastSignInput() const
    {
        return m_lastSignInput;
    }

private:
    sdbus::ObjectPath readCertificates()
    {
        std::thread([this] {
            std::this_thread::sleep_for(std::chrono::milliseconds(80));
            CertResultEntry e{std::string{kCertId},       true,
                              CertFieldGroups{},          std::uint32_t{0x0C} /*keyEnc|dataEnc*/,
                              std::vector<std::string>{}, std::vector<std::string>{},
                              std::uint32_t{255}};
            std::vector<CertResultEntry> certs{e};
            m_op->emitSignal(sdbus::SignalName{"Result"})
                .onInterface(sdbus::InterfaceName{kCertificatesIface})
                .withArguments(certs);
            m_op->emitSignal(sdbus::SignalName{"Finished"})
                .onInterface(sdbus::InterfaceName{kOperation1Iface})
                .withArguments(std::uint32_t{0}, std::uint32_t{0}, std::string{}, std::string{});
        }).detach();
        return sdbus::ObjectPath{kOp0};
    }

    std::unique_ptr<sdbus::IObject> m_root;
    std::unique_ptr<sdbus::IObject> m_reader;
    std::unique_ptr<sdbus::IObject> m_card;
    std::unique_ptr<sdbus::IObject> m_op;
    std::atomic<bool> m_hasCard;
    std::string m_preRead;
    std::string m_signError;
    std::string m_decryptError;
    std::string m_loginError;
    std::string m_publicKeyError;
    std::string m_certDerError;
    std::atomic<int> m_signDelayMs{0};
    std::vector<std::uint8_t> m_lastSignInput;
};

// Stand up the fake on a private session bus and claim the agent's well-known
// name. Construct inside a dbus-run-session test.
struct BusFixture
{
    std::unique_ptr<sdbus::IConnection> serverConn;
    std::unique_ptr<FakeAgent> fake;

    explicit BusFixture(bool hasCard = true, const std::string& preRead = "None",
                        const std::function<void(FakeAgent&)>& cfg = {})
    {
        serverConn = sdbus::createSessionBusConnection();
        fake = std::make_unique<FakeAgent>(*serverConn, hasCard, preRead);
        if (cfg)
            cfg(*fake);
        serverConn->requestName(sdbus::ServiceName{kServiceName});
        serverConn->enterEventLoopAsync();
    }
    ~BusFixture()
    {
        if (serverConn)
            serverConn->leaveEventLoop();
    }
};

} // namespace librescrs_pkcs11_testfake
