// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "AgentClient.h"

#include "AgentInterfaceNames.h" // shared service/path/interface names
#include "CertResultWire.h"

#include "AgentErrorNames.h" // shared wire error-name table (LibreLinux::AgentWire)

#include <sdbus-c++/sdbus-c++.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <map>
#include <mutex>

namespace LibreSCRS::Pkcs11Agent {

namespace {

// Service / path / interface names live in common/AgentInterfaceNames.h (shared
// with the agent producer and the test fake so none can drift).
using LibreLinux::AgentWire::kCardIface;
using LibreLinux::AgentWire::kCertificatesIface;
using LibreLinux::AgentWire::kObjectManagerIface;
using LibreLinux::AgentWire::kOperation1Iface;
using LibreLinux::AgentWire::kPkcs11Iface;
using LibreLinux::AgentWire::kReaderIface;
using LibreLinux::AgentWire::kRootPath;
using LibreLinux::AgentWire::kServiceName;

// sd-bus's default method-call timeout is ~25s. A human-paced PIN prompt (and
// the on-card op behind it) routinely exceeds that, and a timeout surfaces as
// org.freedesktop.DBus.Error.NoReply -> CKR_DEVICE_REMOVED while the agent is
// still prompting. Give the human-interactive calls (Login/SignRaw/Decrypt) a
// very generous budget; the public-data fetches (CertDer/PublicKey) a smaller
// one (mirrors the 60s readCerts wait).
constexpr std::chrono::seconds kInteractiveTimeout{600}; // PIN prompt + on-card op
constexpr std::chrono::seconds kPublicDataTimeout{60};   // CertDer / PublicKey

// RFC 5280 §4.2.1.3 KeyUsage bit ordinals (== the agent's frozen
// Certificates1 keyUsageBits mask). Decrypt needs keyEncipherment OR
// dataEncipherment.
constexpr std::uint32_t kKeyEnciphermentBit = 1U << 2;
constexpr std::uint32_t kDataEnciphermentBit = 1U << 3;

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
    return Status::GeneralError;
}

struct AgentClient::Impl
{
    std::unique_ptr<sdbus::IConnection> conn;
    std::unique_ptr<sdbus::IProxy> rootProxy; // GetManagedObjects + ObjectManager signals
    bool ok = false;

    std::mutex cacheMtx;
    AgentSnapshot cached;
    std::atomic<bool> dirty{true}; // first snapshot() always enumerates

    // Public-key cache keyed by certId. The RSA public key is immutable for a
    // given cert, so once fetched it is served from here (ssh/NSS read
    // CKA_MODULUS / CKA_PUBLIC_EXPONENT repeatedly). Only successful fetches are
    // cached; an error is retried on the next call.
    std::mutex pubKeyMtx;
    std::map<std::string, PublicKeyResult> pubKeyCache;

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
                    dirty.store(true, std::memory_order_release);
                });
            rootProxy->uponSignal(sdbus::SignalName{"InterfacesRemoved"})
                .onInterface(sdbus::InterfaceName{kObjectManagerIface})
                .call([this](const sdbus::ObjectPath&, const std::vector<std::string>&) {
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

    // Drive a per-card ReadCertificates operation and collect its
    // Certificates1.Result entries (waits for Operation1.Finished). Returns
    // false on any failure (the snapshot then carries no certs for that card).
    bool readCerts(const sdbus::ObjectPath& cardPath, std::vector<CertResultEntry>& out)
    {
        try {
            auto cardProxy = sdbus::createProxy(*conn, sdbus::ServiceName{kServiceName}, cardPath);
            sdbus::ObjectPath opPath;
            cardProxy->callMethod("ReadCertificates")
                .onInterface(sdbus::InterfaceName{kCardIface})
                .storeResultsTo(opPath);

            auto opProxy = sdbus::createProxy(*conn, sdbus::ServiceName{kServiceName}, opPath);

            std::mutex mtx;
            std::condition_variable cv;
            bool finished = false;
            std::uint32_t status = 2; // default Error
            std::vector<CertResultEntry> entries;

            opProxy->uponSignal(sdbus::SignalName{"Result"})
                .onInterface(sdbus::InterfaceName{kCertificatesIface})
                .call([&](const std::vector<CertResultEntry>& certs) {
                    std::lock_guard lk(mtx);
                    entries = certs;
                });
            opProxy->uponSignal(sdbus::SignalName{"Finished"})
                .onInterface(sdbus::InterfaceName{kOperation1Iface})
                .call([&](std::uint32_t st, std::uint32_t, const std::string&, const std::string&) {
                    std::lock_guard lk(mtx);
                    status = st;
                    finished = true;
                    cv.notify_all();
                });

            std::unique_lock lk(mtx);
            const bool done = cv.wait_for(lk, std::chrono::seconds(60), [&] { return finished; });
            if (!done || status != 0 /*Ok*/)
                return false;
            out = std::move(entries);
            return true;
        } catch (...) {
            return false;
        }
    }
};

AgentClient::AgentClient() : m_impl(std::make_unique<Impl>()) {}
AgentClient::~AgentClient() = default;

bool AgentClient::connected() const noexcept
{
    return m_impl && m_impl->ok;
}

AgentSnapshot AgentClient::snapshot()
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

    AgentSnapshot snap = enumerate();
    {
        std::lock_guard lk(m_impl->cacheMtx);
        m_impl->cached = snap;
    }
    return snap;
}

AgentSnapshot AgentClient::enumerate()
{
    AgentSnapshot snap;
    if (!connected())
        return snap;

    ManagedObjects managed;
    try {
        m_impl->rootProxy->callMethod("GetManagedObjects")
            .onInterface(sdbus::InterfaceName{kObjectManagerIface})
            .storeResultsTo(managed);
    } catch (...) {
        return snap; // agent gone -> empty snapshot (no slots)
    }

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

        sdbus::ObjectPath cardPath;
        bool haveCardPath = false;
        if (auto c = props.find("Card"); c != props.end()) {
            cardPath = c->second.get<sdbus::ObjectPath>();
            haveCardPath = !std::string{cardPath}.empty();
        }

        if (reader.hasCard && haveCardPath) {
            // PreReadAuthMethod is the capability signal the wire surface
            // exposes to distinguish the two signing families: "None"
            // (opensc/PKS — the agent supplies the signing PIN and the card
            // signs a caller-built DigestInfo) from "Can" (NAM/IAS-ECC SSCD
            // — the card hashes on-card and the agent drives the eSign PIN
            // through the pkcs15 plugin). It is a behavioural capability gate,
            // not a card-name check.
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
            // Sign is now driveable for BOTH families: "None" (opensc/PKS:
            // agent supplies the PIN, card signs a caller-built DigestInfo) and
            // "Can" (NAM/IAS-ECC SSCD: card hashes on-card and signs the RAW
            // message, agent drives the eSign PIN through the pkcs15 plugin).
            // Decrypt stays gated to "None" only — the pkcs15 plugin has no
            // decipher primitive, so advertising decrypt for NAM would be
            // advertise-and-fail. cardHashesOnCard selects the advertised
            // mechanism (CKM_SHA256_RSA_PKCS vs CKM_RSA_PKCS).
            const bool agentCanDriveSigningCredential = (preRead == "None" || preRead == "Can");
            const bool agentCanDriveDecryptCredential = (preRead == "None");
            const bool cardHashesOnCard = (preRead == "Can");

            std::vector<CertResultEntry> certs;
            if (m_impl->readCerts(cardPath, certs)) {
                std::uint8_t ckaId = 1;
                for (const auto& e : certs) {
                    CertEntry ce;
                    ce.certId = e.get<0>();
                    ce.signingCapable = e.get<1>();
                    if (!ce.signingCapable)
                        continue;
                    // CKA_ID: a stable per-card index (CKA_VALUE/cert DER and the
                    // certId carry identity; CKA_ID just pairs cert<->key).
                    ce.ckaId = {ckaId++};
                    // Label: prefer the subject CN field if present.
                    ce.label = ce.certId;
                    const auto& fields = e.get<2>();
                    if (auto sg = fields.find("subject"); sg != fields.end()) {
                        if (auto cn = sg->second.find("cn"); cn != sg->second.end())
                            ce.label = cn->second.get<2>().get<std::string>();
                    }
                    const std::uint32_t keyUsage = e.get<3>();
                    const bool keyUsagePermitsDecrypt = (keyUsage & (kKeyEnciphermentBit | kDataEnciphermentBit)) != 0;

                    ce.canSign = agentCanDriveSigningCredential;
                    ce.canDecrypt = agentCanDriveDecryptCredential && keyUsagePermitsDecrypt;
                    ce.signsHashOnCard = cardHashesOnCard;
                    reader.certs.push_back(std::move(ce));
                }
            }
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

BytesResult AgentClient::certDer(const std::string& reader, const std::string& certId)
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

PublicKeyResult AgentClient::publicKey(const std::string& reader, const std::string& certId)
{
    PublicKeyResult r;
    if (!connected()) {
        r.status = Status::DeviceRemoved;
        return r;
    }

    // Serve a cached success without another round-trip.
    {
        std::lock_guard lk(m_impl->pubKeyMtx);
        if (auto it = m_impl->pubKeyCache.find(certId); it != m_impl->pubKeyCache.end())
            return it->second;
    }

    try {
        auto proxy = pkcs11Proxy(*m_impl->conn);
        std::vector<std::uint8_t> modulus;
        std::vector<std::uint8_t> exponent;
        proxy->callMethod("PublicKey")
            .onInterface(sdbus::InterfaceName{kPkcs11Iface})
            .withTimeout(kPublicDataTimeout)
            .withArguments(sdbus::ObjectPath{reader}, certId)
            .storeResultsTo(modulus, exponent);
        r.status = Status::Ok;
        r.modulus = std::move(modulus);
        r.exponent = std::move(exponent);
    } catch (...) {
        r.status = Impl::statusFromException();
        return r; // do NOT cache errors
    }

    {
        std::lock_guard lk(m_impl->pubKeyMtx);
        m_impl->pubKeyCache[certId] = r;
    }
    return r;
}

LoginResult AgentClient::login(const std::string& reader)
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

Status AgentClient::logout(const std::string& reader)
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

BytesResult AgentClient::signRaw(const std::string& reader, const std::string& certId,
                                 std::span<const std::uint8_t> input)
{
    BytesResult r;
    if (!connected()) {
        r.status = Status::DeviceRemoved;
        return r;
    }
    try {
        // The input (DigestInfo-or-raw block) and the returned signature are the
        // only secret-ish bytes the module touches; they pass straight through
        // and are NEVER logged.
        auto proxy = pkcs11Proxy(*m_impl->conn);
        std::vector<std::uint8_t> sig;
        proxy->callMethod("SignRaw")
            .onInterface(sdbus::InterfaceName{kPkcs11Iface})
            .withTimeout(kInteractiveTimeout)
            .withArguments(sdbus::ObjectPath{reader}, certId, std::vector<std::uint8_t>{input.begin(), input.end()})
            .storeResultsTo(sig);
        r.status = Status::Ok;
        r.bytes = std::move(sig);
    } catch (...) {
        r.status = Impl::statusFromException();
    }
    return r;
}

BytesResult AgentClient::decrypt(const std::string& reader, const std::string& certId,
                                 std::span<const std::uint8_t> ciphertext)
{
    BytesResult r;
    if (!connected()) {
        r.status = Status::DeviceRemoved;
        return r;
    }
    try {
        auto proxy = pkcs11Proxy(*m_impl->conn);
        std::vector<std::uint8_t> plain;
        proxy->callMethod("Decrypt")
            .onInterface(sdbus::InterfaceName{kPkcs11Iface})
            .withTimeout(kInteractiveTimeout)
            .withArguments(sdbus::ObjectPath{reader}, certId,
                           std::vector<std::uint8_t>{ciphertext.begin(), ciphertext.end()})
            .storeResultsTo(plain);
        r.status = Status::Ok;
        r.bytes = std::move(plain);
    } catch (...) {
        r.status = Impl::statusFromException();
    }
    return r;
}

} // namespace LibreSCRS::Pkcs11Agent
