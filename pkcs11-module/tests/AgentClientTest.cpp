// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// AgentClient against a fake agent on a private session bus (dbus-run-session).
// The fake hosts:
//   - org.freedesktop.DBus.ObjectManager on /org/librescrs/Agent (reader+card)
//   - org.librescrs.Agent.Pkcs11_1 on the same path (CertDer/Login/Logout/
//     SignRaw/Decrypt) returning canned bytes or a chosen Error name
//   - org.librescrs.Agent.Card1.ReadCertificates -> an Operation1 that emits
//     Certificates1.Result then Operation1.Finished(Ok)
// so AgentClient::snapshot() can enumerate a card's signing certs end to end.

#include "AgentClient.h"
#include "AgentInterfaceNames.h" // shared service/path/interface names
#include "CertResultWire.h"      // shared CertResultEntry — no drift from the consumer

#include <sdbus-c++/sdbus-c++.h>
#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

using namespace LibreSCRS::Pkcs11Agent;
using namespace LibreLinux::AgentWire;

namespace {

// Service / path / interface names come from common/AgentInterfaceNames.h
// (LibreLinux::AgentWire, visible via the using-namespace above) — shared with
// the production proxy. Only this fake's specific object paths are local.
constexpr const char* kReader0 = "/org/librescrs/Agent/reader/0";
constexpr const char* kCard0 = "/org/librescrs/Agent/card/0";
constexpr const char* kOp0 = "/org/librescrs/Agent/op/0";

using ManagedObjects = std::map<sdbus::ObjectPath, std::map<std::string, std::map<std::string, sdbus::Variant>>>;
// CertFieldGroups + CertResultEntry come from CertResultWire.h (shared), via the
// using-namespace above.

const std::vector<std::uint8_t> kCannedSig = {0xAA, 0xBB, 0xCC, 0xDD};
const std::vector<std::uint8_t> kCannedPlain = {0x11, 0x22, 0x33};
const std::vector<std::uint8_t> kCannedDer = {0x30, 0x82, 0x01};
const std::vector<std::uint8_t> kCannedModulus = {0xC4, 0x07, 0x19, 0x2A, 0x3B, 0x4C}; // non-zero MSB
const std::vector<std::uint8_t> kCannedExponent = {0x01, 0x00, 0x01};

// Configurable fake agent. Each Pkcs11_1 method returns its canned bytes or, if
// a non-empty error name is set, throws it.
class FakeAgent
{
public:
    explicit FakeAgent(sdbus::IConnection& conn, bool hasCard, const std::string& preRead)
        : m_hasCard(hasCard), m_preRead(preRead)
    {
        m_root = sdbus::createObject(conn, sdbus::ObjectPath{kRootPath});
        // Built-in ObjectManager auto-enumerates the reader/card child objects
        // exported below (matches the real agent's GetManagedObjects shape).
        m_root->addObjectManager();

        m_root
            ->addVTable(
                sdbus::registerMethod("CertDer")
                    .implementedAs([](sdbus::ObjectPath, std::string) { return kCannedDer; })
                    .withInputParamNames("reader", "certId")
                    .withOutputParamNames("der"),
                sdbus::registerMethod("PublicKey")
                    .implementedAs([this](sdbus::ObjectPath, std::string)
                                       -> std::tuple<std::vector<std::uint8_t>, std::vector<std::uint8_t>> {
                        if (!m_publicKeyError.empty())
                            throw sdbus::Error{sdbus::Error::Name{m_publicKeyError}, "pubkey err"};
                        ++m_publicKeyCalls;
                        std::lock_guard lk(m_modMtx);
                        return {m_modulus, kCannedExponent};
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
                    .implementedAs(
                        [this](sdbus::ObjectPath, std::string, std::vector<std::uint8_t>) -> std::vector<std::uint8_t> {
                            if (!m_signError.empty())
                                throw sdbus::Error{sdbus::Error::Name{m_signError}, "sign err"};
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

        // Reader1 child object — properties read by GetManagedObjects.
        m_reader = sdbus::createObject(conn, sdbus::ObjectPath{kReader0});
        m_reader
            ->addVTable(sdbus::registerProperty("Name").withGetter([] { return std::string{"FakeReader"}; }),
                        sdbus::registerProperty("HasCard").withGetter([this] { return m_hasCard.load(); }),
                        sdbus::registerProperty("Card").withGetter(
                            [this] { return m_hasCard ? sdbus::ObjectPath{kCard0} : sdbus::ObjectPath{"/"}; }))
            .forInterface(sdbus::InterfaceName{kReaderIface});

        if (m_hasCard) {
            // Card1 child object — Card1 properties + ReadCertificates.
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
    // Populate the subject-CN field group in the next Certificates1.Result, built
    // in the EXACT a{sa{s(ssv)}} shape the agent marshals (the value rides in the
    // Variant, member 2 of the (ssv) struct). Used to exercise the CN demarshal
    // path the empty-fields default never covers.
    void setSubjectCn(const std::string& cn)
    {
        m_subjectCn = cn;
    }

    // Swap the modulus the next PublicKey call returns (tests that the client's
    // pubKeyCache is/ isn't refreshed).
    void setModulus(std::vector<std::uint8_t> mod)
    {
        std::lock_guard lk(m_modMtx);
        m_modulus = std::move(mod);
    }
    [[nodiscard]] int publicKeyCalls() const
    {
        return m_publicKeyCalls.load();
    }

    // Emit ObjectManager.InterfacesRemoved for the card path — exactly what the
    // agent does on a card-remove. The client must drop its caches (snapshot +
    // pubKey) so a later fetch re-enumerates.
    void emitInterfacesRemoved()
    {
        m_root->emitSignal(sdbus::SignalName{"InterfacesRemoved"})
            .onInterface(sdbus::InterfaceName{kObjectManagerIface})
            .withArguments(sdbus::ObjectPath{kCard0}, std::vector<std::string>{std::string{kCardIface}});
    }

private:
    sdbus::ObjectPath readCertificates()
    {
        // Emit Result then Finished shortly after the method returns, so the
        // client has installed its match rules by the time the signals fire.
        std::thread([this, cn = m_subjectCn] {
            std::this_thread::sleep_for(std::chrono::milliseconds(80));
            CertFieldGroups fields;
            if (!cn.empty()) {
                // fields["subject"]["cn"] = (labelKey, fallback, Variant{cn})
                fields["subject"]["cn"] =
                    sdbus::Struct{std::string{"label.subject.cn"}, std::string{"CN"}, sdbus::Variant{cn}};
            }
            CertResultEntry e{std::string{"cert-abc"},
                              true,
                              fields,
                              std::uint32_t{0x0C} /*keyEnc|dataEnc*/,
                              std::vector<std::string>{},
                              std::vector<std::string>{},
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
    std::string m_subjectCn;
    std::mutex m_modMtx;
    std::vector<std::uint8_t> m_modulus = kCannedModulus;
    std::atomic<int> m_publicKeyCalls{0};
};

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

} // namespace

TEST(AgentClient, MapErrorNamePure)
{
    EXPECT_EQ(mapErrorName("org.librescrs.Agent.Error.UserNotLoggedIn"), Status::UserNotLoggedIn);
    EXPECT_EQ(mapErrorName("org.librescrs.Agent.Error.NotSupported"), Status::NotSupported);
    EXPECT_EQ(mapErrorName("org.librescrs.Agent.Error.Cancelled"), Status::Cancelled);
    EXPECT_EQ(mapErrorName("org.librescrs.Agent.Error.AuthFailed"), Status::AuthFailed);
    EXPECT_EQ(mapErrorName("org.librescrs.Agent.Error.KeyNotFound"), Status::KeyNotFound);
    EXPECT_EQ(mapErrorName("org.librescrs.Agent.Error.RateLimited"), Status::RateLimited);
    EXPECT_EQ(mapErrorName("org.librescrs.Agent.Error.CommunicationError"), Status::Communication);
    EXPECT_EQ(mapErrorName("org.example.Other"), Status::GeneralError);
}

TEST(AgentClient, SignRawReturnsCannedSignature)
{
    BusFixture bus;
    AgentClient client;
    ASSERT_TRUE(client.connected());
    const std::vector<std::uint8_t> input{0x01, 0x02};
    auto r = client.signRaw(kReader0, "cert-abc", input);
    EXPECT_EQ(r.status, Status::Ok);
    EXPECT_EQ(r.bytes, kCannedSig);
}

TEST(AgentClient, DecryptReturnsCannedPlaintext)
{
    BusFixture bus;
    AgentClient client;
    const std::vector<std::uint8_t> input{0x09};
    auto r = client.decrypt(kReader0, "cert-abc", input);
    EXPECT_EQ(r.status, Status::Ok);
    EXPECT_EQ(r.bytes, kCannedPlain);
}

TEST(AgentClient, LoginReturnsIdleTimeout)
{
    BusFixture bus;
    AgentClient client;
    auto r = client.login(kReader0);
    EXPECT_EQ(r.status, Status::Ok);
    EXPECT_EQ(r.idleTimeoutSecs, 600u);
}

TEST(AgentClient, CertDerReturnsBytes)
{
    BusFixture bus;
    AgentClient client;
    auto r = client.certDer(kReader0, "cert-abc");
    EXPECT_EQ(r.status, Status::Ok);
    EXPECT_EQ(r.bytes, kCannedDer);
}

TEST(AgentClient, PublicKeyReturnsModulusAndExponent)
{
    BusFixture bus;
    AgentClient client;
    auto r = client.publicKey(kReader0, "cert-abc");
    EXPECT_EQ(r.status, Status::Ok);
    EXPECT_EQ(r.modulus, kCannedModulus);
    EXPECT_EQ(r.exponent, kCannedExponent);
}

TEST(AgentClient, PublicKeyServesFromCacheOnSecondCall)
{
    // The RSA public key is immutable for a cert, so the second fetch is served
    // from the client's pubKeyCache without a second round-trip (the modulus the
    // fake swaps in between is NOT observed).
    BusFixture bus;
    AgentClient client;
    auto r1 = client.publicKey(kReader0, "cert-abc");
    ASSERT_EQ(r1.status, Status::Ok);
    EXPECT_EQ(r1.modulus, kCannedModulus);
    EXPECT_EQ(bus.fake->publicKeyCalls(), 1);

    bus.fake->setModulus({0xDE, 0xAD, 0xBE, 0xEF});
    auto r2 = client.publicKey(kReader0, "cert-abc");
    EXPECT_EQ(r2.modulus, kCannedModulus) << "second call served from cache, not re-fetched";
    EXPECT_EQ(bus.fake->publicKeyCalls(), 1) << "no second round-trip";
}

TEST(AgentClient, PublicKeyCacheClearedOnCardRemove)
{
    // Hygiene: a card-remove (ObjectManager InterfacesRemoved) must clear the
    // pubKeyCache so a later fetch re-enumerates rather than serving the removed
    // card's stale public key. Observable: after the signal, the fake's swapped
    // modulus IS returned (a fresh round-trip happened).
    BusFixture bus;
    AgentClient client;
    auto r1 = client.publicKey(kReader0, "cert-abc");
    ASSERT_EQ(r1.status, Status::Ok);
    EXPECT_EQ(r1.modulus, kCannedModulus);
    EXPECT_EQ(bus.fake->publicKeyCalls(), 1);

    // The card is pulled; the agent emits InterfacesRemoved.
    const std::vector<std::uint8_t> swapped = {0xDE, 0xAD, 0xBE, 0xEF};
    bus.fake->setModulus(swapped);
    bus.fake->emitInterfacesRemoved();
    // Let the client's async event loop dispatch the signal + clear the cache.
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    auto r2 = client.publicKey(kReader0, "cert-abc");
    ASSERT_EQ(r2.status, Status::Ok);
    EXPECT_EQ(r2.modulus, swapped) << "card-remove must clear the pubKeyCache (stale key served otherwise)";
    EXPECT_EQ(bus.fake->publicKeyCalls(), 2) << "a fresh round-trip happened after the cache clear";
}

TEST(AgentClient, PublicKeyKeyNotFoundMapped)
{
    BusFixture bus(true, "None", [](FakeAgent& f) { f.setPublicKeyError("org.librescrs.Agent.Error.KeyNotFound"); });
    AgentClient client;
    auto r = client.publicKey(kReader0, "cert-abc");
    EXPECT_EQ(r.status, Status::KeyNotFound);
}

TEST(AgentClient, PublicKeyNotSupportedMapped)
{
    BusFixture bus(true, "None", [](FakeAgent& f) { f.setPublicKeyError("org.librescrs.Agent.Error.NotSupported"); });
    AgentClient client;
    auto r = client.publicKey(kReader0, "cert-abc");
    EXPECT_EQ(r.status, Status::NotSupported);
}

TEST(AgentClient, NotLoggedInErrorMapped)
{
    BusFixture bus(true, "None", [](FakeAgent& f) { f.setSignError("org.librescrs.Agent.Error.UserNotLoggedIn"); });
    AgentClient client;
    const std::vector<std::uint8_t> input{0x01};
    auto r = client.signRaw(kReader0, "cert-abc", input);
    EXPECT_EQ(r.status, Status::UserNotLoggedIn);
}

TEST(AgentClient, NotSupportedErrorMapped)
{
    BusFixture bus(true, "None", [](FakeAgent& f) { f.setSignError("org.librescrs.Agent.Error.NotSupported"); });
    AgentClient client;
    const std::vector<std::uint8_t> input{0x01};
    auto r = client.signRaw(kReader0, "cert-abc", input);
    EXPECT_EQ(r.status, Status::NotSupported);
}

TEST(AgentClient, CancelErrorMapped)
{
    BusFixture bus(true, "None", [](FakeAgent& f) { f.setLoginError("org.librescrs.Agent.Error.Cancelled"); });
    AgentClient client;
    auto r = client.login(kReader0);
    EXPECT_EQ(r.status, Status::Cancelled);
}

TEST(AgentClient, SnapshotEnumeratesReaderCardAndCerts)
{
    BusFixture bus; // PreReadAuthMethod="None" -> sign/decrypt capable
    AgentClient client;
    auto snap = client.snapshot();
    ASSERT_EQ(snap.readers.size(), 1u);
    EXPECT_EQ(snap.readers[0].readerPath, kReader0);
    EXPECT_TRUE(snap.readers[0].hasCard);
    ASSERT_EQ(snap.readers[0].certs.size(), 1u);
    const auto& c = snap.readers[0].certs[0];
    EXPECT_EQ(c.certId, "cert-abc");
    EXPECT_TRUE(c.signingCapable);
    EXPECT_TRUE(c.canSign);    // PreRead None + signingCapable
    EXPECT_TRUE(c.canDecrypt); // keyUsage has keyEnc|dataEnc
}

TEST(AgentClient, SnapshotDemarshalsSubjectCnLabel)
{
    // The default Certificates1.Result carries empty fields, so the CN-label
    // demarshal (the a{sa{s(ssv)}} -> get<2>().get<std::string>() path) was only
    // tested empty. Populate fields["subject"]["cn"] in the agent's OWN marshal
    // shape and assert the snapshot label is the CN, not the certId fallback.
    BusFixture bus(true, "None", [](FakeAgent& f) { f.setSubjectCn("Pera Perić"); });
    AgentClient client;
    auto snap = client.snapshot();
    ASSERT_EQ(snap.readers.size(), 1u);
    ASSERT_EQ(snap.readers[0].certs.size(), 1u);
    EXPECT_EQ(snap.readers[0].certs[0].label, "Pera Perić");
}

TEST(AgentClient, SnapshotCanCardSignsHashOnCardDecryptGated)
{
    // A Can (NAM / IAS-ECC SSCD) card: the agent drives the eSign PIN
    // through the pkcs15 plugin and the card hashes on-card, so the snapshot
    // reports canSign=true AND signsHashOnCard=true (-> ObjectModel advertises
    // CKM_SHA256_RSA_PKCS). canDecrypt stays false — the pkcs15 plugin has no
    // decipher primitive, so advertising decrypt would be advertise-and-fail.
    BusFixture bus(true, "Can");
    AgentClient client;
    auto snap = client.snapshot();
    ASSERT_EQ(snap.readers.size(), 1u);
    ASSERT_EQ(snap.readers[0].certs.size(), 1u);
    const auto& c = snap.readers[0].certs[0];
    EXPECT_TRUE(c.signingCapable);
    EXPECT_TRUE(c.canSign);
    EXPECT_TRUE(c.signsHashOnCard);
    EXPECT_FALSE(c.canDecrypt);
}

TEST(AgentClient, SnapshotNoCardNoCerts)
{
    BusFixture bus(false);
    AgentClient client;
    auto snap = client.snapshot();
    ASSERT_EQ(snap.readers.size(), 1u);
    EXPECT_FALSE(snap.readers[0].hasCard);
    EXPECT_TRUE(snap.readers[0].certs.empty());
}
