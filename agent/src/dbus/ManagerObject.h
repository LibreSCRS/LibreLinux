// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include "org.librescrs.Agent.Config1_adaptor.h"
#include "org.librescrs.Agent.Manager1_adaptor.h"
#include "org.librescrs.Agent.Pkcs11_1_adaptor.h"
#include <sdbus-c++/AdaptorInterfaces.h>
#include <sdbus-c++/IConnection.h>
#include <sdbus-c++/StandardInterfaces.h>
#include <sdbus-c++/Types.h>
#include <cstdint>
#include <map>
#include <string>
#include <tuple>
#include <vector>
namespace LibreSCRS::Agent {
namespace Config {
class ConfigStore;
}
namespace Operations {
class RateLimiter;
}
class Authorizer;
class Pkcs11Broker;

// Root object at /org/librescrs/Agent: Manager1 (version) + Config1 (agent-owned
// signing config, the SSOT for signing defaults) + freedesktop ObjectManager.
// Config1 is composed here (sdbus-c++ hosts one IObject per path) so the agent's
// control surface lives at a single well-known path. Heavy validation/persistence
// lives in ConfigStore; this object only does the D-Bus mapping: typed property
// getters, the SetValue/Reset routing with the per-key mutability + polkit gate,
// and the Changed signal.
class ManagerObject final
    : public sdbus::AdaptorInterfaces<org::librescrs::Agent::Manager1_adaptor, org::librescrs::Agent::Config1_adaptor,
                                      org::librescrs::Agent::Pkcs11_1_adaptor, sdbus::ObjectManager_adaptor>
{
public:
    // config + authorizer + pkcs11 MUST outlive this object (enforced by
    // AgentService member declaration order). @p pkcs11 is the logic delegate
    // for the Pkcs11_1 interface composed on this same path (sdbus-c++ hosts a
    // single IObject per path, so the low-level PKCS#11 broker rides here next
    // to Manager1 + Config1). May be null in conformance tests that never
    // exercise the Pkcs11_1 methods.
    // @p rateLimiter is a REFERENCE rather than a nullable pointer like @p
    // pkcs11: it is the flood bound on ImportCscaMasterList, and a surface that
    // could be wired without one would be wired without one.
    ManagerObject(sdbus::IConnection& connection, sdbus::ObjectPath path, std::string version,
                  Config::ConfigStore& config, Authorizer& authorizer, Operations::RateLimiter& rateLimiter,
                  Pkcs11Broker* pkcs11);
    ~ManagerObject();
    ManagerObject(const ManagerObject&) = delete;
    ManagerObject& operator=(const ManagerObject&) = delete;

    // Wired by AgentService into ConfigStore::setOnChanged so a config mutation
    // (D-Bus or agent-internal) emits Config1.Changed. noexcept: a D-Bus emit
    // failure is logged, never propagated to the worker that triggered it.
    void emitConfigChanged(const std::string& key) noexcept;

private:
    // Manager1
    std::string Version() override;
    std::vector<std::string> Features() override;
    // Card-independent, synchronous visible-signature layout preview — no
    // card, no Operation object, no deferred sdbus::Result (unlike the async
    // Pkcs11_1 methods below): the agent-side computation is pure CPU
    // (LibreMiddleware's word-wrap/clipping algorithm via
    // Operations::layoutVisualSignature, LmSeams.h) and answers immediately.
    // Throws Error.InvalidRequest for a non-finite or non-positive box (the
    // SAME entry gate Card1.Sign's visualSignature option uses,
    // SignatureParams::isValidLayoutRect).
    std::tuple<double, double, std::vector<std::string>, bool> LayoutVisualSignature(const std::string& text,
                                                                                     const double& x, const double& y,
                                                                                     const double& width,
                                                                                     const double& height) override;
    // The embedded appearance font (Liberation Sans Regular TTF), sealed into
    // a fresh memfd per call (Operations::appearanceFontBytes, LmSeams.h).
    sdbus::UnixFd GetAppearanceFont() override;
    // Config1 — property getters
    std::string DefaultLevel() override;
    std::vector<std::string> TsaUrls() override;
    std::string LastTsaUrl() override;
    std::vector<sdbus::Struct<std::string, bool, bool>> TslSources() override;
    std::string TslCacheDir() override;
    std::string AiaCacheDir() override;
    std::vector<sdbus::Struct<std::string, bool>> CscaSources() override;
    // The report an accepted import recorded in the store, served the way
    // LastTsaUrl is. Empty dict until a master list has been accepted; see the
    // XML for the keys.
    std::map<std::string, sdbus::Variant> CscaAnchorState() override;
    std::string DefaultReason() override;
    std::string DefaultLocation() override;
    std::string PluginDir() override;
    // Config1 — mutation (throws sdbus::Error on rejection)
    void SetValue(const std::string& key, const sdbus::Variant& value) override;
    void Reset(const std::string& key) override;
    // Config1 — install country-signing anchors from a signed ICAO master list.
    // Authorise, then rate-limit, THEN read the descriptor: a refused caller
    // must not be able to make the agent read anything.
    std::map<std::string, sdbus::Variant> ImportCscaMasterList(const sdbus::UnixFd& masterList) override;
    std::tuple<uint64_t, bool> ForgetCscaAnchors() override;

    // Pkcs11_1 — low-level PKCS#11 broker. The card-touching methods are sdbus-c++
    // ASYNC methods (org.freedesktop.DBus.Method.Async): each resolves the caller
    // (bus name + pidfd label) from the in-flight message, wraps the deferred
    // sdbus::Result into a Pkcs11Broker::Reply, and forwards to m_pkcs11, which
    // validates on this (the bus dispatch) thread then hands the card I/O to the
    // per-reader worker and RELEASES the dispatch thread — the worker fulfils the
    // Result on completion. Logout stays synchronous (pure lease bookkeeping).
    void CertDer(sdbus::Result<std::vector<std::uint8_t>>&& result, sdbus::ObjectPath reader,
                 std::string certId) override;
    void PublicKey(sdbus::Result<std::vector<std::uint8_t>, std::vector<std::uint8_t>>&& result,
                   sdbus::ObjectPath reader, std::string certId) override;
    void Login(sdbus::Result<std::uint32_t>&& result, sdbus::ObjectPath reader) override;
    void Logout(const sdbus::ObjectPath& reader) override;
    void SignRaw(sdbus::Result<std::vector<std::uint8_t>>&& result, sdbus::ObjectPath reader, std::string certId,
                 std::vector<std::uint8_t> input) override;
    void Decrypt(sdbus::Result<std::vector<std::uint8_t>>&& result, sdbus::ObjectPath reader, std::string certId,
                 std::vector<std::uint8_t> ciphertext) override;

    // Requesting client's unique D-Bus name from the in-flight message (reuse-
    // immune polkit-subject handle); empty on failure.
    [[nodiscard]] std::string callerBusName() const noexcept;
    // Sanitised human label for the in-flight caller (pidfd-pinned); audit/
    // display only. Empty on any resolution failure.
    [[nodiscard]] std::string callerLabel() const noexcept;

    std::string m_version;
    Config::ConfigStore& m_config;
    Authorizer& m_authorizer;
    Operations::RateLimiter& m_rateLimiter;
    Pkcs11Broker* m_pkcs11;
};
} // namespace LibreSCRS::Agent
