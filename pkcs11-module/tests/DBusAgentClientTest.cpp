// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// DBusAgentClient against a fake agent on a private session bus (dbus-run-session).
// The fake hosts:
//   - org.freedesktop.DBus.ObjectManager on /org/librescrs/Agent (reader+card)
//   - org.librescrs.Agent.Pkcs11_1 on the same path (CertDer/PublicKey/Login/
//     Logout/SignRaw/Decrypt) returning canned bytes or a chosen Error name
//   - org.librescrs.Agent.Card1.ReadCertificates -> an Operation1 that emits
//     Certificates1.Result then Operation1.Finished(Ok)
// so DBusAgentClient::snapshot() can enumerate a card's signing certs end to end.

#include "DBusAgentClient.h"
#include "AgentErrorNames.h"     // shared wire error names
#include "AgentInterfaceNames.h" // shared service/path/interface names
#include "CertResultWire.h"      // shared CertResultEntry — no drift from the consumer
#include "CertificateRead.h"

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
#include <variant>
#include <vector>

using namespace LibreSCRS::Pkcs11Agent;
using namespace LibreLinux::AgentWire;
using LibreSCRS::Agent::ErrorCode;
using LibreSCRS::Agent::Operations::OperationStatus;

namespace {

// Service / path / interface names come from common/AgentInterfaceNames.h
// (LibreLinux::AgentWire, visible via the using-namespace above) — shared with
// the production proxy. Only this fake's specific object paths are local.
constexpr const char* kReader0 = "/org/librescrs/Agent/reader/0";
constexpr const char* kCard0 = "/org/librescrs/Agent/card/0";
constexpr const char* kOp0 = "/org/librescrs/Agent/op/0";
constexpr const char* kReader1 = "/org/librescrs/Agent/reader/1";
constexpr const char* kCard1 = "/org/librescrs/Agent/card/1";

using ManagedObjects = std::map<sdbus::ObjectPath, std::map<std::string, std::map<std::string, sdbus::Variant>>>;
// CertFieldGroups + CertResultEntry come from CertResultWire.h (shared), via the
// using-namespace above.

const std::vector<std::uint8_t> kCannedSig = {0xAA, 0xBB, 0xCC, 0xDD};
const std::vector<std::uint8_t> kCannedPlain = {0x11, 0x22, 0x33};
const std::vector<std::uint8_t> kCannedDer = {0x30, 0x82, 0x01};
const std::vector<std::uint8_t> kCannedModulus = {0xC4, 0x07, 0x19, 0x2A, 0x3B, 0x4C}; // non-zero MSB
const std::vector<std::uint8_t> kCannedExponent = {0x01, 0x00, 0x01};

// The RSA key of a successful publicKey(); a test that reached here asserted has_value().
const LibreSCRS::Agent::Operations::RsaPublicKey& rsaOf(const PublicKeyResult& r)
{
    return std::get<LibreSCRS::Agent::Operations::RsaPublicKey>(*r);
}

// Configurable fake agent. Each Pkcs11_1 method returns its canned bytes or, if
// a non-empty error name is set, throws it.
// MIRROR-OF: LibreAgent/client/qt/tests/fakes/FakeAgent.h - a third fake of
// the same agent, kept because this one is scripted per test case with canned
// bytes and thrown error names rather than driven as a shared fixture.
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
                    .implementedAs([this](sdbus::ObjectPath, std::string, std::string,
                                          std::vector<std::uint8_t>) -> std::vector<std::uint8_t> {
                        if (!m_signError.empty())
                            throw sdbus::Error{sdbus::Error::Name{m_signError}, "sign err"};
                        return kCannedSig;
                    })
                    .withInputParamNames("reader", "certId", "mech", "input")
                    .withOutputParamNames("signature"),
                sdbus::registerMethod("Decrypt")
                    .implementedAs([this](sdbus::ObjectPath, std::string, std::string,
                                          std::vector<std::uint8_t>) -> std::vector<std::uint8_t> {
                        if (!m_decryptError.empty())
                            throw sdbus::Error{sdbus::Error::Name{m_decryptError}, "dec err"};
                        return kCannedPlain;
                    })
                    .withInputParamNames("reader", "certId", "mech", "ciphertext")
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
                                .implementedAs([this] {
                                    ++m_readCalls;
                                    return readCertificates();
                                })
                                .withOutputParamNames("operation"))
                .forInterface(sdbus::InterfaceName{kCardIface});
        }

        m_op = sdbus::createObject(conn, sdbus::ObjectPath{kOp0});
        m_op->addVTable(sdbus::registerSignal("Result").withParameters<std::vector<CertResultEntry>>("certificates"),
                        sdbus::registerMethod("GetResult")
                            .implementedAs([this]() -> std::vector<CertResultEntry> {
                                const std::lock_guard lk(m_resultMtx);
                                if (!m_completed)
                                    throw sdbus::Error{sdbus::Error::Name{"org.librescrs.Agent.Error.NoResult"},
                                                       "no result"};
                                ++m_getResultCalls;
                                return m_lastResult;
                            })
                            .withOutputParamNames("certificates"))
            .forInterface(sdbus::InterfaceName{kCertificatesIface});
        m_op->addVTable(sdbus::registerSignal("Finished")
                            .withParameters<std::uint32_t, std::uint32_t, std::string, std::string>(
                                "status", "errorCode", "msgKey", "msgFallback"),
                        sdbus::registerProperty("Completed").withGetter([this] {
                            const std::lock_guard lk(m_resultMtx);
                            return m_completed;
                        }),
                        sdbus::registerProperty("Status").withGetter([this] { return m_finishStatus.load(); }),
                        sdbus::registerProperty("ErrorCode").withGetter([this] { return m_finishErrorCode.load(); }),
                        sdbus::registerMethod("Cancel").implementedAs([this] { ++m_cancelCalls; }))
            .forInterface(sdbus::InterfaceName{kOperation1Iface});
    }

    // Emit Result and Finished before ReadCertificates replies, as the agent
    // does for a read it answers from its cache.
    void emitBeforeReply()
    {
        m_emitBeforeReply = true;
    }
    // Emit Result before ReadCertificates replies but mark the op complete
    // and emit Finished only afterwards: the agent's worker between its
    // Result and its completion when the client subscribes.
    void emitResultBeforeReplyFinishLater()
    {
        m_resultBeforeReplyFinishLater = true;
    }
    // Refuse the next ReadCertificates, as an agent that is busy or restarting does.
    void refuseNextRead()
    {
        m_refuseNextRead = true;
    }
    // Refuse every ReadCertificates with @p errorName.
    void refuseReadsWith(std::string errorName)
    {
        m_refuseReadsWith = std::move(errorName);
    }
    // End every read with Operation1 @p status and @p errorCode and no
    // certificates: the holder closing the CAN window ends it Cancelled.
    void finishReadsWith(LibreSCRS::Agent::Operations::OperationStatus status,
                         LibreSCRS::Agent::ErrorCode errorCode = LibreSCRS::Agent::ErrorCode::None)
    {
        m_finishStatus = static_cast<std::uint32_t>(status);
        m_finishErrorCode = static_cast<std::uint32_t>(errorCode);
    }
    // A second reader holding a card whose every read the agent refuses as
    // busy: the snapshot is never complete while it is seated.
    void seatABusySecondCard(sdbus::IConnection& conn)
    {
        m_reader1 = sdbus::createObject(conn, sdbus::ObjectPath{kReader1});
        m_reader1
            ->addVTable(sdbus::registerProperty("Name").withGetter([] { return std::string{"FakeReader 1"}; }),
                        sdbus::registerProperty("HasCard").withGetter([] { return true; }),
                        sdbus::registerProperty("Card").withGetter([] { return sdbus::ObjectPath{kCard1}; }))
            .forInterface(sdbus::InterfaceName{kReaderIface});
        m_card1 = sdbus::createObject(conn, sdbus::ObjectPath{kCard1});
        m_card1
            ->addVTable(sdbus::registerProperty("Capabilities").withGetter([] { return std::uint32_t{0x3}; }),
                        sdbus::registerProperty("Reader").withGetter([] { return sdbus::ObjectPath{kReader1}; }),
                        sdbus::registerProperty("PreReadAuthMethod").withGetter([] { return std::string{"None"}; }),
                        sdbus::registerMethod("ReadCertificates")
                            .implementedAs([this]() -> sdbus::ObjectPath {
                                ++m_secondCardReadCalls;
                                throw sdbus::Error{sdbus::Error::Name{kErrCommunication}, "busy"};
                            })
                            .withOutputParamNames("operation"))
            .forInterface(sdbus::InterfaceName{kCardIface});
    }
    // Start every read and never end it: a CAN window nobody answers.
    void neverFinishReads()
    {
        m_neverFinishReads = true;
    }
    [[nodiscard]] int readCalls() const
    {
        return m_readCalls.load();
    }
    [[nodiscard]] int secondCardReadCalls() const
    {
        return m_secondCardReadCalls.load();
    }
    [[nodiscard]] int cancelCalls() const
    {
        return m_cancelCalls.load();
    }
    [[nodiscard]] int getResultCalls() const
    {
        return m_getResultCalls.load();
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
        if (m_refuseNextRead.exchange(false))
            throw sdbus::Error{sdbus::Error::Name{"org.librescrs.Agent.Error.CommunicationError"}, "busy"};
        if (!m_refuseReadsWith.empty())
            throw sdbus::Error{sdbus::Error::Name{m_refuseReadsWith}, "refused"};
        {
            const std::lock_guard lk(m_resultMtx);
            m_completed = false;
        }
        if (m_neverFinishReads)
            return sdbus::ObjectPath{kOp0};
        if (m_emitBeforeReply) {
            finishRead(m_subjectCn);
            return sdbus::ObjectPath{kOp0};
        }
        if (m_resultBeforeReplyFinishLater) {
            const auto certs = certificates(m_subjectCn);
            {
                const std::lock_guard lk(m_resultMtx);
                m_lastResult = certs;
            }
            m_op->emitSignal(sdbus::SignalName{"Result"})
                .onInterface(sdbus::InterfaceName{kCertificatesIface})
                .withArguments(certs);
            std::thread([this] {
                std::this_thread::sleep_for(std::chrono::milliseconds(80));
                {
                    const std::lock_guard lk(m_resultMtx);
                    m_completed = true;
                }
                emitFinished();
            }).detach();
            return sdbus::ObjectPath{kOp0};
        }
        // Otherwise finish shortly after the method returns, so the client has
        // installed its match rules by the time the signals fire.
        std::thread([this, cn = m_subjectCn] {
            std::this_thread::sleep_for(std::chrono::milliseconds(80));
            finishRead(cn);
        }).detach();
        return sdbus::ObjectPath{kOp0};
    }

    static std::vector<CertResultEntry> certificates(const std::string& cn)
    {
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
                          std::uint32_t{255},
                          false,
                          std::vector<std::uint8_t>{0x01},
                          std::string{"RSA"},
                          std::uint32_t{2048},
                          false};
        return {e};
    }

    void emitFinished()
    {
        m_op->emitSignal(sdbus::SignalName{"Finished"})
            .onInterface(sdbus::InterfaceName{kOperation1Iface})
            .withArguments(m_finishStatus.load(), m_finishErrorCode.load(), std::string{}, std::string{});
    }

    // The agent's order: the result is kept and the op marked complete, then
    // Result and Finished go out. A read that did not end Ok has no result.
    void finishRead(const std::string& cn)
    {
        if (m_finishStatus.load() != 0) {
            {
                const std::lock_guard lk(m_resultMtx);
                m_lastResult.clear();
                m_completed = true;
            }
            emitFinished();
            return;
        }
        const auto certs = certificates(cn);
        {
            const std::lock_guard lk(m_resultMtx);
            m_lastResult = certs;
            m_completed = true;
        }
        m_op->emitSignal(sdbus::SignalName{"Result"})
            .onInterface(sdbus::InterfaceName{kCertificatesIface})
            .withArguments(certs);
        emitFinished();
    }

    std::unique_ptr<sdbus::IObject> m_root;
    std::unique_ptr<sdbus::IObject> m_reader;
    std::unique_ptr<sdbus::IObject> m_card;
    std::unique_ptr<sdbus::IObject> m_op;
    std::unique_ptr<sdbus::IObject> m_reader1;
    std::unique_ptr<sdbus::IObject> m_card1;
    std::atomic<bool> m_hasCard;
    std::string m_preRead;
    std::string m_refuseReadsWith;
    std::atomic<std::uint32_t> m_finishStatus{0};
    std::atomic<std::uint32_t> m_finishErrorCode{0};
    std::atomic<int> m_readCalls{0};
    std::atomic<int> m_secondCardReadCalls{0};
    std::atomic<int> m_cancelCalls{0};
    std::atomic<bool> m_neverFinishReads{false};
    std::string m_signError;
    std::string m_decryptError;
    std::string m_loginError;
    std::string m_publicKeyError;
    std::string m_subjectCn;
    std::mutex m_modMtx;
    std::vector<std::uint8_t> m_modulus = kCannedModulus;
    std::atomic<int> m_publicKeyCalls{0};
    std::atomic<bool> m_emitBeforeReply{false};
    std::atomic<bool> m_resultBeforeReplyFinishLater{false};
    std::atomic<bool> m_refuseNextRead{false};
    std::atomic<int> m_getResultCalls{0};
    std::mutex m_resultMtx;
    bool m_completed = false;
    std::vector<CertResultEntry> m_lastResult;
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

TEST(DBusAgentClient, MapErrorNamePure)
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

TEST(DBusAgentClient, SignRawReturnsCannedSignature)
{
    BusFixture bus;
    DBusAgentClient client;
    ASSERT_TRUE(client.connected());
    const std::vector<std::uint8_t> input{0x01, 0x02};
    auto r = client.signRaw(kReader0, "cert-abc", LibreSCRS::Agent::Mechanism::RsaPkcs1Sign, input);
    EXPECT_EQ(r.status, Status::Ok);
    EXPECT_EQ(r.bytes, kCannedSig);
}

TEST(DBusAgentClient, DecryptReturnsCannedPlaintext)
{
    BusFixture bus;
    DBusAgentClient client;
    const std::vector<std::uint8_t> input{0x09};
    auto r = client.decrypt(kReader0, "cert-abc", input);
    EXPECT_EQ(r.status, Status::Ok);
    EXPECT_EQ(r.bytes, kCannedPlain);
}

TEST(DBusAgentClient, LoginReturnsIdleTimeout)
{
    BusFixture bus;
    DBusAgentClient client;
    auto r = client.login(kReader0);
    EXPECT_EQ(r.status, Status::Ok);
    EXPECT_EQ(r.idleTimeoutSecs, 600u);
}

TEST(DBusAgentClient, CertDerReturnsBytes)
{
    BusFixture bus;
    DBusAgentClient client;
    auto r = client.certDer(kReader0, "cert-abc");
    EXPECT_EQ(r.status, Status::Ok);
    EXPECT_EQ(r.bytes, kCannedDer);
}

TEST(DBusAgentClient, PublicKeyReturnsModulusAndExponent)
{
    BusFixture bus;
    DBusAgentClient client;
    auto r = client.publicKey(kReader0, "cert-abc", LibreSCRS::Agent::KeyType::Rsa);
    ASSERT_TRUE(r.has_value()) << static_cast<int>(r.error());
    EXPECT_EQ(rsaOf(r).modulus, kCannedModulus);
    EXPECT_EQ(rsaOf(r).exponent, kCannedExponent);
}

TEST(DBusAgentClient, PublicKeyServesFromCacheOnSecondCall)
{
    // The RSA public key is immutable for a cert, so the second fetch is served
    // from the client's pubKeyCache without a second round-trip (the modulus the
    // fake swaps in between is NOT observed).
    BusFixture bus;
    DBusAgentClient client;
    auto r1 = client.publicKey(kReader0, "cert-abc", LibreSCRS::Agent::KeyType::Rsa);
    ASSERT_TRUE(r1.has_value());
    EXPECT_EQ(rsaOf(r1).modulus, kCannedModulus);
    EXPECT_EQ(bus.fake->publicKeyCalls(), 1);

    bus.fake->setModulus({0xDE, 0xAD, 0xBE, 0xEF});
    auto r2 = client.publicKey(kReader0, "cert-abc", LibreSCRS::Agent::KeyType::Rsa);
    ASSERT_TRUE(r2.has_value());
    EXPECT_EQ(rsaOf(r2).modulus, kCannedModulus) << "second call served from cache, not re-fetched";
    EXPECT_EQ(bus.fake->publicKeyCalls(), 1) << "no second round-trip";
}

TEST(DBusAgentClient, PublicKeyCacheClearedOnCardRemove)
{
    // Hygiene: a card-remove (ObjectManager InterfacesRemoved) must clear the
    // pubKeyCache so a later fetch re-enumerates rather than serving the removed
    // card's stale public key. Observable: after the signal, the fake's swapped
    // modulus IS returned (a fresh round-trip happened).
    BusFixture bus;
    DBusAgentClient client;
    auto r1 = client.publicKey(kReader0, "cert-abc", LibreSCRS::Agent::KeyType::Rsa);
    ASSERT_TRUE(r1.has_value());
    EXPECT_EQ(rsaOf(r1).modulus, kCannedModulus);
    EXPECT_EQ(bus.fake->publicKeyCalls(), 1);

    // The card is pulled; the agent emits InterfacesRemoved.
    const std::vector<std::uint8_t> swapped = {0xDE, 0xAD, 0xBE, 0xEF};
    bus.fake->setModulus(swapped);
    bus.fake->emitInterfacesRemoved();
    // Let the client's async event loop dispatch the signal + clear the cache.
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    auto r2 = client.publicKey(kReader0, "cert-abc", LibreSCRS::Agent::KeyType::Rsa);
    ASSERT_TRUE(r2.has_value());
    EXPECT_EQ(rsaOf(r2).modulus, swapped) << "card-remove must clear the pubKeyCache (stale key served otherwise)";
    EXPECT_EQ(bus.fake->publicKeyCalls(), 2) << "a fresh round-trip happened after the cache clear";
}

TEST(DBusAgentClient, PublicKeyKeyNotFoundMapped)
{
    BusFixture bus(true, "None", [](FakeAgent& f) { f.setPublicKeyError("org.librescrs.Agent.Error.KeyNotFound"); });
    DBusAgentClient client;
    auto r = client.publicKey(kReader0, "cert-abc", LibreSCRS::Agent::KeyType::Rsa);
    ASSERT_FALSE(r.has_value());
    EXPECT_EQ(r.error(), Status::KeyNotFound);
}

TEST(DBusAgentClient, PublicKeyNotSupportedMapped)
{
    BusFixture bus(true, "None", [](FakeAgent& f) { f.setPublicKeyError("org.librescrs.Agent.Error.NotSupported"); });
    DBusAgentClient client;
    auto r = client.publicKey(kReader0, "cert-abc", LibreSCRS::Agent::KeyType::Rsa);
    ASSERT_FALSE(r.has_value());
    EXPECT_EQ(r.error(), Status::NotSupported);
}

TEST(DBusAgentClient, NotLoggedInErrorMapped)
{
    BusFixture bus(true, "None", [](FakeAgent& f) { f.setSignError("org.librescrs.Agent.Error.UserNotLoggedIn"); });
    DBusAgentClient client;
    const std::vector<std::uint8_t> input{0x01};
    auto r = client.signRaw(kReader0, "cert-abc", LibreSCRS::Agent::Mechanism::RsaPkcs1Sign, input);
    EXPECT_EQ(r.status, Status::UserNotLoggedIn);
}

TEST(DBusAgentClient, NotSupportedErrorMapped)
{
    BusFixture bus(true, "None", [](FakeAgent& f) { f.setSignError("org.librescrs.Agent.Error.NotSupported"); });
    DBusAgentClient client;
    const std::vector<std::uint8_t> input{0x01};
    auto r = client.signRaw(kReader0, "cert-abc", LibreSCRS::Agent::Mechanism::RsaPkcs1Sign, input);
    EXPECT_EQ(r.status, Status::NotSupported);
}

TEST(DBusAgentClient, CancelErrorMapped)
{
    BusFixture bus(true, "None", [](FakeAgent& f) { f.setLoginError("org.librescrs.Agent.Error.Cancelled"); });
    DBusAgentClient client;
    auto r = client.login(kReader0);
    EXPECT_EQ(r.status, Status::Cancelled);
}

TEST(DBusAgentClient, SnapshotEnumeratesReaderCardAndCerts)
{
    BusFixture bus; // PreReadAuthMethod="None" -> sign/decrypt capable
    DBusAgentClient client;
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

TEST(DBusAgentClient, SnapshotDemarshalsSubjectCnLabel)
{
    // The default Certificates1.Result carries empty fields, so the CN-label
    // demarshal (the a{sa{s(ssv)}} -> get<2>().get<std::string>() path) was only
    // tested empty. Populate fields["subject"]["cn"] in the agent's OWN marshal
    // shape and assert the snapshot label is the CN, not the certId fallback.
    BusFixture bus(true, "None", [](FakeAgent& f) { f.setSubjectCn("Pera Perić"); });
    DBusAgentClient client;
    auto snap = client.snapshot();
    ASSERT_EQ(snap.readers.size(), 1u);
    ASSERT_EQ(snap.readers[0].certs.size(), 1u);
    EXPECT_EQ(snap.readers[0].certs[0].label, "Pera Perić");
}

TEST(DBusAgentClient, SnapshotCanCardSignsHashOnCardDecryptGated)
{
    // A Can (NAM / IAS-ECC SSCD) card: the agent drives the eSign PIN
    // through the pkcs15 plugin and the card hashes on-card, so the snapshot
    // reports canSign=true AND signsHashOnCard=true (-> ObjectModel advertises
    // CKM_SHA256_RSA_PKCS). canDecrypt stays false — the pkcs15 plugin has no
    // decipher primitive, so advertising decrypt would be advertise-and-fail.
    BusFixture bus(true, "Can");
    DBusAgentClient client;
    auto snap = client.snapshot();
    ASSERT_EQ(snap.readers.size(), 1u);
    ASSERT_EQ(snap.readers[0].certs.size(), 1u);
    const auto& c = snap.readers[0].certs[0];
    EXPECT_TRUE(c.signingCapable);
    EXPECT_TRUE(c.canSign);
    EXPECT_TRUE(c.signsHashOnCard);
    EXPECT_FALSE(c.canDecrypt);
}

TEST(DBusAgentClient, SnapshotNoCardNoCerts)
{
    BusFixture bus(false);
    DBusAgentClient client;
    auto snap = client.snapshot();
    ASSERT_EQ(snap.readers.size(), 1u);
    EXPECT_FALSE(snap.readers[0].hasCard);
    EXPECT_TRUE(snap.readers[0].certs.empty());
}

// The token is named after the holder the signing certificate names, through
// the same CN demarshal the certificate's own label uses, and the card path's
// tail tells it apart from any other.
TEST(DBusAgentClient, SnapshotNamesTheTokenAfterTheCertificateHolder)
{
    BusFixture bus(true, "None", [](FakeAgent& f) { f.setSubjectCn("Pera Perić"); });
    DBusAgentClient client;
    auto snap = client.snapshot();
    ASSERT_EQ(snap.readers.size(), 1u);
    EXPECT_EQ(snap.readers[0].tokenLabel, "Pera Perić");
    EXPECT_EQ(snap.readers[0].tokenSerial, "0"); // kCard0's tail
}

TEST(DBusAgentClient, SnapshotEmptyReaderNamesNoToken)
{
    BusFixture bus(false);
    DBusAgentClient client;
    auto snap = client.snapshot();
    ASSERT_EQ(snap.readers.size(), 1u);
    EXPECT_TRUE(snap.readers[0].tokenLabel.empty());
    EXPECT_TRUE(snap.readers[0].tokenSerial.empty());
    EXPECT_EQ(snap.readers[0].readerName, "FakeReader") << "an empty reader still describes its slot";
}

// A read the agent answers from its cache finishes before its reply leaves the
// agent: Result and Finished pass before this client has subscribed to the op.
// The client recovers the outcome from the op's terminal state and GetResult
// instead of waiting for signals that already went by.
TEST(DBusAgentClient, ACachedReadThatFinishedBeforeItsReplyStillYieldsTheCertificates)
{
    BusFixture bus(true, "None", [](FakeAgent& f) { f.emitBeforeReply(); });
    DBusAgentClient client;
    const auto started = std::chrono::steady_clock::now();
    auto snap = client.snapshot();
    const auto took = std::chrono::steady_clock::now() - started;
    ASSERT_EQ(snap.readers.size(), 1u);
    ASSERT_EQ(snap.readers[0].certs.size(), 1u) << "the certificates the agent already served";
    EXPECT_EQ(snap.readers[0].certs[0].certId, "cert-abc");
    EXPECT_LT(took, std::chrono::seconds(5)) << "no wait for signals that already passed";
    EXPECT_EQ(bus.fake->getResultCalls(), 1);
}

// A read that finishes after the client subscribed is collected once its
// Finished arrives.
TEST(DBusAgentClient, AReadThatFinishesLaterIsCollectedWhenItFinishes)
{
    BusFixture bus;
    DBusAgentClient client;
    auto snap = client.snapshot();
    ASSERT_EQ(snap.readers.size(), 1u);
    ASSERT_EQ(snap.readers[0].certs.size(), 1u);
    EXPECT_EQ(bus.fake->getResultCalls(), 1);
}

// The agent emits Result before it marks the read complete. A client that
// subscribes between the two misses Result, finds the read not complete yet
// and catches only Finished(Ok): the certificates must still come back, not
// an empty token that is then kept as complete.
TEST(DBusAgentClient, AReadWhoseResultPassedBeforeItsFinishedStillYieldsTheCertificates)
{
    BusFixture bus(true, "None", [](FakeAgent& f) { f.emitResultBeforeReplyFinishLater(); });
    DBusAgentClient client;
    auto snap = client.snapshot();
    ASSERT_EQ(snap.readers.size(), 1u);
    ASSERT_EQ(snap.readers[0].certs.size(), 1u) << "the certificates whose Result passed before the subscription";
    EXPECT_EQ(snap.readers[0].certs[0].certId, "cert-abc");
}

// A snapshot that failed somewhere is not the truth until a reader or card
// next changes: the next call asks the agent again.
TEST(DBusAgentClient, AFailedReadIsAskedForAgainNotCached)
{
    BusFixture bus(true, "None", [](FakeAgent& f) { f.refuseNextRead(); });
    DBusAgentClient client;
    auto first = client.snapshot();
    ASSERT_EQ(first.readers.size(), 1u);
    EXPECT_TRUE(first.readers[0].certs.empty()) << "the refused read yields no certificates";

    auto second = client.snapshot(); // no InterfacesAdded/Removed in between
    ASSERT_EQ(second.readers.size(), 1u);
    EXPECT_EQ(second.readers[0].certs.size(), 1u) << "the next snapshot reads the card again";
}

// A read the holder ended -- the CAN window closed with "Cancel" -- ends the
// same way when asked again, and asking again raises the window again. It
// stands until a reader or card changes; the next slot query does not read.
TEST(DBusAgentClient, AReadTheHolderCancelledIsNotAskedForAgain)
{
    BusFixture bus(true, "Can", [](FakeAgent& f) { f.finishReadsWith(OperationStatus::Cancelled); });
    DBusAgentClient client;
    auto first = client.snapshot();
    ASSERT_EQ(first.readers.size(), 1u);
    EXPECT_TRUE(first.readers[0].certs.empty());

    auto second = client.snapshot(); // no InterfacesAdded/Removed in between
    ASSERT_EQ(second.readers.size(), 1u);
    EXPECT_TRUE(second.readers[0].certs.empty());
    EXPECT_EQ(bus.fake->readCalls(), 1) << "a cancelled read must not raise the window again";
}

// The holder's entry time running out is the holder's answer too.
TEST(DBusAgentClient, AReadWhoseEntryWindowExpiredIsNotAskedForAgain)
{
    BusFixture bus(true, "Can",
                   [](FakeAgent& f) { f.finishReadsWith(OperationStatus::Error, ErrorCode::EntryExpired); });
    DBusAgentClient client;
    (void)client.snapshot();
    (void)client.snapshot();
    EXPECT_EQ(bus.fake->readCalls(), 1);
}

// A prompter the agent could not reach is a broken install, not a race: the
// next slot query would end the same way, so it does not ask again.
TEST(DBusAgentClient, AReadWhosePrompterCouldNotBeReachedIsNotAskedForAgain)
{
    BusFixture bus(true, "Can",
                   [](FakeAgent& f) { f.finishReadsWith(OperationStatus::Error, ErrorCode::PrompterError); });
    DBusAgentClient client;
    (void)client.snapshot();
    (void)client.snapshot();
    EXPECT_EQ(bus.fake->readCalls(), 1);
}

// A card without certificates the agent can read is refused at the method;
// that refusal does not change while the card stays seated.
TEST(DBusAgentClient, ACardTheAgentHasNoCertificatesForIsNotAskedForAgain)
{
    BusFixture bus(true, "None", [](FakeAgent& f) { f.refuseReadsWith(kErrUnsupportedOnThisCard); });
    DBusAgentClient client;
    auto first = client.snapshot();
    ASSERT_EQ(first.readers.size(), 1u);
    EXPECT_TRUE(first.readers[0].certs.empty());
    (void)client.snapshot();
    EXPECT_EQ(bus.fake->readCalls(), 1);
}

// A read that failed on the way to the card says nothing about the card: the
// next slot query asks again.
TEST(DBusAgentClient, AReadThatFailedOnTheWayToTheCardIsAskedForAgain)
{
    BusFixture bus(true, "None",
                   [](FakeAgent& f) { f.finishReadsWith(OperationStatus::Error, ErrorCode::CommunicationError); });
    DBusAgentClient client;
    (void)client.snapshot();
    (void)client.snapshot();
    EXPECT_EQ(bus.fake->readCalls(), 2);
}

// A settled read stands only until a reader or card changes.
TEST(DBusAgentClient, ACancelledReadIsAskedForAgainOnceACardChanges)
{
    BusFixture bus(true, "Can", [](FakeAgent& f) { f.finishReadsWith(OperationStatus::Cancelled); });
    DBusAgentClient client;
    (void)client.snapshot();
    ASSERT_EQ(bus.fake->readCalls(), 1);

    bus.fake->emitInterfacesRemoved();
    std::this_thread::sleep_for(std::chrono::milliseconds(200)); // the client's loop dispatches it
    (void)client.snapshot();
    EXPECT_EQ(bus.fake->readCalls(), 2);
}

// Another card's read failing on the way is asked for again on the next slot
// query; that must not re-read a card whose read the holder already ended.
TEST(DBusAgentClient, ACancelledReadStaysSettledWhileAnotherCardIsAskedForAgain)
{
    BusFixture bus(true, "Can", [](FakeAgent& f) { f.finishReadsWith(OperationStatus::Cancelled); });
    bus.fake->seatABusySecondCard(*bus.serverConn);
    DBusAgentClient client;
    for (int i = 0; i < 3; ++i) {
        auto snap = client.snapshot();
        ASSERT_EQ(snap.readers.size(), 2u);
    }
    EXPECT_EQ(bus.fake->secondCardReadCalls(), 3) << "the busy card is asked for again on every query";
    EXPECT_EQ(bus.fake->readCalls(), 1) << "the cancelled card is not";
}

// A read that does not end within its budget is given up, and the agent is
// told so: a CAN window it raised must not stay open with nobody to answer to.
TEST(DBusAgentClient, AReadThatOutlastsItsBudgetIsCancelledAtTheAgent)
{
    BusFixture bus(true, "Can", [](FakeAgent& f) { f.neverFinishReads(); });
    auto conn = sdbus::createSessionBusConnection();
    conn->enterEventLoopAsync();
    const auto read = readCertificates(*conn, sdbus::ObjectPath{kCard0}, std::chrono::seconds(1));
    EXPECT_TRUE(read.timedOut);
    EXPECT_FALSE(read.settled()) << "a read nobody saw end is asked for again";
    for (int i = 0; i < 40 && bus.fake->cancelCalls() == 0; ++i)
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    EXPECT_EQ(bus.fake->cancelCalls(), 1);
    conn->leaveEventLoop();
}
