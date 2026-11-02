// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "DBusAgentClient.h"

#include "AgentInterfaceNames.h" // shared service/path/interface names
#include "CertResultWire.h"
#include "CertificateRead.h" // the one way a certificate read is collected

#include "AgentErrorNames.h" // shared wire error-name table (LibreLinux::AgentWire)

#include <sdbus-c++/sdbus-c++.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <map>
#include <mutex>
#include <set>
#include <string>
#include <utility>
#include <variant>
#include <vector>

namespace LibreSCRS::Pkcs11Agent {

namespace {

// Service / path / interface names live in common/AgentInterfaceNames.h (shared
// with the agent producer and the test fake so none can drift).
using LibreLinux::AgentWire::kCardIface;
using LibreLinux::AgentWire::kObjectManagerIface;
using LibreLinux::AgentWire::kPkcs11Iface;
using LibreLinux::AgentWire::kReaderIface;
using LibreLinux::AgentWire::kRootPath;
using LibreLinux::AgentWire::kServiceName;

// sd-bus's default method-call timeout is ~25s, which a human-paced PIN prompt
// routinely exceeds; a timeout would surface as NoReply -> CKR_DEVICE_REMOVED
// while the agent is still prompting. The budgets are the module's, the same
// on every transport (pkcs11/AgentClient.h).
constexpr std::chrono::seconds kInteractiveTimeout{kInteractiveTimeoutSecs};
constexpr std::chrono::seconds kPublicDataTimeout{kPublicDataTimeoutSecs};
constexpr std::chrono::seconds kLoginStateTimeout{kLoginStateTimeoutSecs};

// Card1.PreReadAuthMethod as the agent spells it. A method this module does
// not know asks for a secret before reading, like an MRZ: no key on such a card
// signs or decrypts through this module (certEntryFrom decides what does).
LibreSCRS::Agent::Wire::PreReadAuth preReadAuthFromToken(const std::string& token) noexcept
{
    using LibreSCRS::Agent::Wire::PreReadAuth;
    if (token == "None")
        return PreReadAuth::None;
    if (token == "Can")
        return PreReadAuth::Can;
    return PreReadAuth::Mrz;
}

// The ObjectManager GetManagedObjects return type.
using ManagedObjects = std::map<sdbus::ObjectPath, std::map<std::string, std::map<std::string, sdbus::Variant>>>;

// CertFieldGroups + CertResultEntry (the Certificates1.Result tuple) live in
// CertResultWire.h — one definition shared with the test fake.

} // namespace

Status mapErrorName(const std::string& errorName) noexcept
{
    // Error-name strings come from the shared wire table (common/AgentErrorNames.h),
    // the same one the agent producer raises — no hand-duplicated literals here.
    namespace W = LibreLinux::AgentWire;
    if (errorName == W::kErrUserNotLoggedIn)
        return Status::UserNotLoggedIn;
    if (errorName == W::kErrNotAuthorized)
        return Status::NotAuthorized;
    if (errorName == W::kErrAuthFailed)
        return Status::AuthFailed;
    if (errorName == W::kErrCancelled)
        return Status::Cancelled;
    if (errorName == W::kErrKeyNotFound)
        return Status::KeyNotFound;
    if (errorName == W::kErrUnknownCard)
        return Status::UnknownCard;
    if (errorName == W::kErrNotSupported)
        return Status::NotSupported;
    if (errorName == W::kErrRateLimited)
        return Status::RateLimited;
    if (errorName == W::kErrCommunication)
        return Status::Communication;
    if (errorName == W::kErrInvalidRequest)
        return Status::InvalidInput;
    return Status::GeneralError;
}

struct DBusAgentClient::Impl
{
    std::unique_ptr<sdbus::IConnection> conn;
    std::unique_ptr<sdbus::IProxy> rootProxy; // GetManagedObjects + ObjectManager signals
    bool ok = false;

    std::mutex cacheMtx;
    AgentSnapshot cached;
    std::atomic<bool> dirty{true}; // first snapshot() always enumerates

    // Cards whose last read ended in a way asking again would repeat
    // (CertificateRead::settled), kept until the next ObjectManager signal.
    // Another card's failed read re-enumerates; it must not re-read these,
    // or a CAN window the holder cancelled comes back on every slot query.
    // A read started before a signal is not recorded after it (generation).
    std::mutex settledMtx;
    std::set<std::string> settledCards;
    std::uint64_t generation = 0;

    // Public-key cache keyed by certId. A cert's public key is immutable, so
    // once fetched it is served from here (ssh/NSS read CKA_MODULUS /
    // CKA_PUBLIC_EXPONENT or CKA_EC_POINT repeatedly). Only successful fetches
    // are cached; an error is retried on the next call.
    std::mutex pubKeyMtx;
    std::map<std::string, LibreSCRS::Agent::Operations::CertPublicKey> pubKeyCache;

    Impl()
    {
        try {
            conn = sdbus::createSessionBusConnection();
            rootProxy = sdbus::createProxy(*conn, sdbus::ServiceName{kServiceName}, sdbus::ObjectPath{kRootPath});

            // Live slot updates: any reader/card add or remove on the
            // agent's ObjectManager invalidates the cache so the next snapshot()
            // re-enumerates -> C_GetSlotList reflects current CKF_TOKEN_PRESENT.
            rootProxy->uponSignal(sdbus::SignalName{"InterfacesAdded"})
                .onInterface(sdbus::InterfaceName{kObjectManagerIface})
                .call([this](const sdbus::ObjectPath&,
                             const std::map<std::string, std::map<std::string, sdbus::Variant>>&) {
                    forgetSettled();
                    dirty.store(true, std::memory_order_release);
                });
            rootProxy->uponSignal(sdbus::SignalName{"InterfacesRemoved"})
                .onInterface(sdbus::InterfaceName{kObjectManagerIface})
                .call([this](const sdbus::ObjectPath&, const std::vector<std::string>&) {
                    forgetSettled();
                    dirty.store(true, std::memory_order_release);
                    // Hygiene: a card-remove invalidates the per-certId public
                    // keys too. Public data, so no leak, but a removed card's key
                    // must not be served from the cache after the card is gone.
                    std::lock_guard lk(pubKeyMtx);
                    pubKeyCache.clear();
                });

            conn->enterEventLoopAsync();
            ok = true;
        } catch (...) {
            ok = false;
        }
    }

    ~Impl()
    {
        if (conn)
            conn->leaveEventLoop();
    }

    // Map a thrown sdbus::Error into a Status; a non-D-Bus failure is treated
    // as a lost connection (device removed).
    static Status statusFromException()
    {
        try {
            throw;
        } catch (const sdbus::Error& e) {
            const std::string name = e.getName();
            if (name.rfind("org.librescrs.Agent.Error.", 0) == 0)
                return mapErrorName(name);
            // Service unknown / no reply / disconnected -> the agent is gone.
            if (name == "org.freedesktop.DBus.Error.ServiceUnknown" || name == "org.freedesktop.DBus.Error.NoReply" ||
                name == "org.freedesktop.DBus.Error.Disconnected" ||
                name == "org.freedesktop.DBus.Error.NameHasNoOwner")
                return Status::DeviceRemoved;
            return Status::GeneralError;
        } catch (...) {
            return Status::DeviceRemoved;
        }
    }

    void forgetSettled()
    {
        const std::lock_guard lk(settledMtx);
        settledCards.clear();
        ++generation;
    }
    [[nodiscard]] std::uint64_t currentGeneration()
    {
        const std::lock_guard lk(settledMtx);
        return generation;
    }
    [[nodiscard]] bool isSettled(const std::string& card)
    {
        const std::lock_guard lk(settledMtx);
        return settledCards.contains(card);
    }
    void settle(const std::string& card, std::uint64_t readGeneration)
    {
        const std::lock_guard lk(settledMtx);
        if (readGeneration == generation)
            settledCards.insert(card);
    }

    enum class ReadOutcome {
        Read,     // the certificates are in out
        Settled,  // no certificates, and asking again would end the same way
        AskAgain, // failed on the way to the card; the snapshot is not kept
    };

    // Drive a per-card ReadCertificates operation and collect its
    // certificates once it has finished.
    ReadOutcome readCerts(const sdbus::ObjectPath& cardPath, std::vector<CertResultEntry>& out)
    {
        try {
            auto read = readCertificates(*conn, cardPath);
            if (read.ok()) {
                out = std::move(read.certificates);
                return ReadOutcome::Read;
            }
            return read.settled() ? ReadOutcome::Settled : ReadOutcome::AskAgain;
        } catch (const sdbus::Error& e) {
            return refusalSettles(e.getName()) ? ReadOutcome::Settled : ReadOutcome::AskAgain;
        } catch (...) {
            return ReadOutcome::AskAgain;
        }
    }
};

DBusAgentClient::DBusAgentClient() : m_impl(std::make_unique<Impl>()) {}
DBusAgentClient::~DBusAgentClient() = default;

bool DBusAgentClient::connected() const noexcept
{
    return m_impl && m_impl->ok;
}

AgentSnapshot DBusAgentClient::snapshot()
{
    if (!connected())
        return {};

    // Serve the cache unless an ObjectManager signal (or the first call) marked
    // it dirty. This keeps C_GetSlotList cheap while still reflecting live
    // reader/card changes.
    if (!m_impl->dirty.exchange(false, std::memory_order_acq_rel)) {
        std::lock_guard lk(m_impl->cacheMtx);
        return m_impl->cached;
    }

    bool complete = false;
    AgentSnapshot snap = enumerate(complete);
    {
        std::lock_guard lk(m_impl->cacheMtx);
        m_impl->cached = snap;
    }
    // A snapshot that failed on the way anywhere -- the agent restarting, a
    // read that timed out or was refused as busy -- is served this once and
    // asked for again next time, not kept until a reader or card happens to
    // change. A read that ended for good does not make it incomplete.
    if (!complete)
        m_impl->dirty.store(true, std::memory_order_release);
    return snap;
}

AgentSnapshot DBusAgentClient::enumerate(bool& complete)
{
    AgentSnapshot snap;
    complete = false;
    if (!connected())
        return snap;

    const auto readGeneration = m_impl->currentGeneration();
    ManagedObjects managed;
    try {
        m_impl->rootProxy->callMethod("GetManagedObjects")
            .onInterface(sdbus::InterfaceName{kObjectManagerIface})
            .storeResultsTo(managed);
    } catch (...) {
        return snap; // agent gone -> empty snapshot (no slots)
    }
    complete = true;

    // First pass: collect readers (one slot each) and their card path / pre-read.
    for (const auto& [path, ifaces] : managed) {
        auto rit = ifaces.find(kReaderIface);
        if (rit == ifaces.end())
            continue;

        ReaderState reader;
        reader.readerPath = path;

        const auto& props = rit->second;
        if (auto hc = props.find("HasCard"); hc != props.end())
            reader.hasCard = hc->second.get<bool>();
        // Reader1.Name: display only (slot description, token label fallback).
        try {
            if (auto n = props.find("Name"); n != props.end())
                reader.readerName = n->second.get<std::string>();
        } catch (...) {
        }

        sdbus::ObjectPath cardPath;
        bool haveCardPath = false;
        if (auto c = props.find("Card"); c != props.end()) {
            cardPath = c->second.get<sdbus::ObjectPath>();
            haveCardPath = !std::string{cardPath}.empty();
        }

        if (reader.hasCard && haveCardPath) {
            // PreReadAuthMethod tells the two signing families apart; what the
            // module may do with each key is decided once, by certEntryFrom().
            std::string preRead = "None";
            try {
                auto cardIt = managed.find(cardPath);
                if (cardIt != managed.end()) {
                    auto ci = cardIt->second.find(kCardIface);
                    if (ci != cardIt->second.end()) {
                        if (auto p = ci->second.find("PreReadAuthMethod"); p != ci->second.end())
                            preRead = p->second.get<std::string>();
                    }
                }
            } catch (...) {
            }
            const auto preAuth = preReadAuthFromToken(preRead);

            std::vector<CertResultEntry> certs;
            const std::string card{cardPath};
            const auto outcome =
                m_impl->isSettled(card) ? Impl::ReadOutcome::Settled : m_impl->readCerts(cardPath, certs);
            if (outcome == Impl::ReadOutcome::AskAgain) {
                complete = false;
            } else if (outcome == Impl::ReadOutcome::Settled) {
                m_impl->settle(card, readGeneration);
            } else {
                for (const auto& e : certs) {
                    NeutralCert cert;
                    cert.certId = e.get<0>();
                    cert.signingCapable = e.get<1>();
                    cert.keyUsageBits = e.get<3>();
                    cert.alwaysAuthenticate = e.get<7>();
                    cert.keyId = e.get<8>();
                    cert.keyType = LibreSCRS::Agent::keyTypeFromToken(e.get<9>());
                    cert.keyBits = e.get<10>();
                    cert.canDerive = e.get<11>();
                    const auto& fields = e.get<2>();
                    if (auto sg = fields.find("subject"); sg != fields.end()) {
                        if (auto cn = sg->second.find("cn"); cn != sg->second.end())
                            cert.subjectCn = cn->second.get<2>().get<std::string>();
                    }
                    if (auto entry = certEntryFrom(cert, preAuth))
                        reader.certs.push_back(std::move(*entry));
                }
            }
            // What a loader shows for the token, and what tells two of them
            // apart: the same derivation the socket transport uses.
            reader.tokenLabel = tokenLabelFor(reader.certs, reader.readerName);
            reader.tokenSerial = tokenSerialFor(std::string{cardPath});
        }

        snap.readers.push_back(std::move(reader));
    }

    return snap;
}

namespace {

// One Pkcs11_1 proxy per call: the manager path hosts the interface.
std::unique_ptr<sdbus::IProxy> pkcs11Proxy(sdbus::IConnection& conn)
{
    return sdbus::createProxy(conn, sdbus::ServiceName{kServiceName}, sdbus::ObjectPath{kRootPath});
}

} // namespace

BytesResult DBusAgentClient::certDer(const std::string& reader, const std::string& certId)
{
    BytesResult r;
    if (!connected()) {
        r.status = Status::DeviceRemoved;
        return r;
    }
    try {
        auto proxy = pkcs11Proxy(*m_impl->conn);
        std::vector<std::uint8_t> der;
        proxy->callMethod("CertDer")
            .onInterface(sdbus::InterfaceName{kPkcs11Iface})
            .withTimeout(kPublicDataTimeout)
            .withArguments(sdbus::ObjectPath{reader}, certId)
            .storeResultsTo(der);
        r.status = Status::Ok;
        r.bytes = std::move(der);
    } catch (...) {
        r.status = Impl::statusFromException();
    }
    return r;
}

PublicKeyResult DBusAgentClient::publicKey(const std::string& reader, const std::string& certId,
                                           LibreSCRS::Agent::KeyType keyType)
{
    using LibreSCRS::Agent::KeyType;
    namespace Ops = LibreSCRS::Agent::Operations;
    if (!connected()) {
        return std::unexpected(Status::DeviceRemoved);
    }

    // Serve a cached success without another round-trip. The cache holds the
    // key the agent served; a request for another family is answered as an
    // uncached one would be.
    {
        std::lock_guard lk(m_impl->pubKeyMtx);
        if (auto it = m_impl->pubKeyCache.find(certId); it != m_impl->pubKeyCache.end()) {
            const KeyType cached = std::holds_alternative<Ops::EcPublicKey>(it->second) ? KeyType::Ec : KeyType::Rsa;
            if (cached != keyType) {
                return std::unexpected(Status::NotSupported);
            }
            return it->second;
        }
    }

    Ops::CertPublicKey key;
    try {
        auto proxy = pkcs11Proxy(*m_impl->conn);
        if (keyType == KeyType::Rsa) {
            Ops::RsaPublicKey rsa;
            proxy->callMethod("PublicKey")
                .onInterface(sdbus::InterfaceName{kPkcs11Iface})
                .withTimeout(kPublicDataTimeout)
                .withArguments(sdbus::ObjectPath{reader}, certId)
                .storeResultsTo(rsa.modulus, rsa.exponent);
            key = std::move(rsa);
        } else if (keyType == KeyType::Ec) {
            Ops::EcPublicKey ec;
            proxy->callMethod("EcPublicKey")
                .onInterface(sdbus::InterfaceName{kPkcs11Iface})
                .withTimeout(kPublicDataTimeout)
                .withArguments(sdbus::ObjectPath{reader}, certId)
                .storeResultsTo(ec.crv, ec.x, ec.y);
            key = std::move(ec);
        } else {
            // No wire method serves an Other key, and none is modelled.
            return std::unexpected(Status::NotSupported);
        }
    } catch (...) {
        return std::unexpected(Impl::statusFromException()); // do NOT cache errors
    }

    {
        std::lock_guard lk(m_impl->pubKeyMtx);
        m_impl->pubKeyCache[certId] = key;
    }
    return key;
}

LoginResult DBusAgentClient::login(const std::string& reader)
{
    LoginResult r;
    if (!connected()) {
        r.status = Status::DeviceRemoved;
        return r;
    }
    try {
        auto proxy = pkcs11Proxy(*m_impl->conn);
        std::uint32_t idle = 0;
        proxy->callMethod("Login")
            .onInterface(sdbus::InterfaceName{kPkcs11Iface})
            .withTimeout(kInteractiveTimeout)
            .withArguments(sdbus::ObjectPath{reader})
            .storeResultsTo(idle);
        r.status = Status::Ok;
        r.idleTimeoutSecs = idle;
    } catch (...) {
        r.status = Impl::statusFromException();
    }
    return r;
}

std::optional<bool> DBusAgentClient::loginActive(const std::string& reader)
{
    if (!connected())
        return std::nullopt;
    try {
        auto proxy = pkcs11Proxy(*m_impl->conn);
        bool active = false;
        proxy->callMethod("LoginState")
            .onInterface(sdbus::InterfaceName{kPkcs11Iface})
            .withTimeout(kLoginStateTimeout)
            .withArguments(sdbus::ObjectPath{reader})
            .storeResultsTo(active);
        return active;
    } catch (...) {
        // No agent, an agent from before this method (UnknownMethod), or no
        // answer in time: the module keeps what it knew.
        return std::nullopt;
    }
}

Status DBusAgentClient::logout(const std::string& reader)
{
    if (!connected())
        return Status::DeviceRemoved;
    try {
        auto proxy = pkcs11Proxy(*m_impl->conn);
        proxy->callMethod("Logout")
            .onInterface(sdbus::InterfaceName{kPkcs11Iface})
            .withArguments(sdbus::ObjectPath{reader});
        return Status::Ok;
    } catch (...) {
        return Impl::statusFromException();
    }
}

BytesResult DBusAgentClient::signRaw(const std::string& reader, const std::string& certId,
                                     LibreSCRS::Agent::Mechanism mechanism, std::span<const std::uint8_t> input)
{
    BytesResult r;
    // Only a signing mechanism of this wire is sent as a signature. The token
    // alone does not decide it: RsaPkcs1Decrypt spells the same "rsa-pkcs" as
    // RsaPkcs1Sign, and a mechanism with no token has nothing to send.
    const std::string token{LibreSCRS::Agent::mechanismToken(mechanism)};
    if (token.empty() || LibreSCRS::Agent::signMechanismFromToken(token) != mechanism) {
        r.status = Status::NotSupported;
        return r;
    }
    if (!connected()) {
        r.status = Status::DeviceRemoved;
        return r;
    }
    try {
        // The input (DigestInfo, raw message or digest) and the returned
        // signature pass straight through and are NEVER logged.
        auto proxy = pkcs11Proxy(*m_impl->conn);
        std::vector<std::uint8_t> sig;
        proxy->callMethod("SignRaw")
            .onInterface(sdbus::InterfaceName{kPkcs11Iface})
            .withTimeout(kInteractiveTimeout)
            .withArguments(sdbus::ObjectPath{reader}, certId, token,
                           std::vector<std::uint8_t>{input.begin(), input.end()})
            .storeResultsTo(sig);
        r.status = Status::Ok;
        r.bytes = std::move(sig);
    } catch (...) {
        r.status = Impl::statusFromException();
    }
    return r;
}

BytesResult DBusAgentClient::decrypt(const std::string& reader, const std::string& certId,
                                     std::span<const std::uint8_t> ciphertext)
{
    BytesResult r;
    if (!connected()) {
        r.status = Status::DeviceRemoved;
        return r;
    }
    try {
        auto proxy = pkcs11Proxy(*m_impl->conn);
        // The plaintext is moved, never copied: nothing is left in this frame
        // for the caller to miss when it wipes r.bytes.
        std::vector<std::uint8_t> plain;
        proxy->callMethod("Decrypt")
            .onInterface(sdbus::InterfaceName{kPkcs11Iface})
            .withTimeout(kInteractiveTimeout)
            .withArguments(sdbus::ObjectPath{reader}, certId,
                           std::string{LibreSCRS::Agent::mechanismToken(LibreSCRS::Agent::Mechanism::RsaPkcs1Decrypt)},
                           std::vector<std::uint8_t>{ciphertext.begin(), ciphertext.end()})
            .storeResultsTo(plain);
        r.status = Status::Ok;
        r.bytes = std::move(plain);
    } catch (...) {
        r.status = Impl::statusFromException();
    }
    return r;
}

BytesResult DBusAgentClient::derive(const std::string& reader, const std::string& certId,
                                    std::span<const std::uint8_t> peerPoint)
{
    BytesResult r;
    if (!connected()) {
        r.status = Status::DeviceRemoved;
        return r;
    }
    try {
        // The peer's point is public; the secret Z the agent answers is moved
        // into the result, never copied, and the caller wipes it.
        auto proxy = pkcs11Proxy(*m_impl->conn);
        std::vector<std::uint8_t> z;
        proxy->callMethod("Derive")
            .onInterface(sdbus::InterfaceName{kPkcs11Iface})
            .withTimeout(kInteractiveTimeout)
            .withArguments(sdbus::ObjectPath{reader}, certId,
                           std::vector<std::uint8_t>{peerPoint.begin(), peerPoint.end()})
            .storeResultsTo(z);
        r.status = Status::Ok;
        r.bytes = std::move(z);
    } catch (...) {
        r.status = Impl::statusFromException();
    }
    return r;
}

} // namespace LibreSCRS::Pkcs11Agent
