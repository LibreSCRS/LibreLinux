// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#include "dbus/ManagerObject.h"
#include <LibreSCRS/Agent/backend/Authorizer.h>
#include <LibreSCRS/Agent/FeatureTokens.h>
#include "AgentErrorNames.h" // shared wire error-name table (kErrInvalidRequest)
#include "CallerIdentity.h"
#include <LibreSCRS/Agent/backend/Logging.h>
#include <LibreSCRS/Agent/config/ConfigStore.h>
#include <LibreSCRS/Agent/crypto/Mechanism.h>
#include "dbus/Pkcs11OutcomeNames.h"
#include <LibreSCRS/Agent/operations/LmSeams.h>         // Operations::layoutVisualSignature/appearanceFontBytes
#include <LibreSCRS/Agent/operations/SignatureParams.h> // isValidLayoutRect
#include <LibreSCRS/Agent/pkcs11/Pkcs11Broker.h>
#include <LibreSCRS/Agent/Reply.h>
#include "SealedMemfdCreator.h" // shared sealed-memfd creator (matches the producer)
#include <sdbus-c++/Error.h>
#include <sdbus-c++/IObject.h>
#include <sdbus-c++/Message.h>
#include <sys/types.h> // pid_t
#include <exception>
#include <memory>
#include <tuple>
#include <utility>
#include <vector>

namespace LibreSCRS::Agent {

namespace {
// polkit action ids live in Authorizer.h (kActionConfigure[.Trust]) — shared
// with the Authorizer implementations so the strings cannot drift.
// SetValue/Reset rejection error names.
constexpr const char* kErrUnknownKey = "org.librescrs.Agent.Error.UnknownConfigKey";
constexpr const char* kErrReadOnly = "org.librescrs.Agent.Error.ReadOnlyConfig";
constexpr const char* kErrNotAuthorized = "org.librescrs.Agent.Error.NotAuthorized";
constexpr const char* kErrInvalidValue = "org.librescrs.Agent.Error.InvalidConfigValue";

const char* actionFor(Config::Mutability m) noexcept
{
    return (m == Config::Mutability::DbusMutableTrust) ? kActionConfigureTrust : kActionConfigure;
}
} // namespace

ManagerObject::ManagerObject(sdbus::IConnection& connection, sdbus::ObjectPath path, std::string version,
                             Config::ConfigStore& config, Authorizer& authorizer, Pkcs11Broker* pkcs11)
    : AdaptorInterfaces(connection, std::move(path)), m_version(std::move(version)), m_config(config),
      m_authorizer(authorizer), m_pkcs11(pkcs11)
{
    registerAdaptor();
}

ManagerObject::~ManagerObject()
{
    unregisterAdaptor();
}

std::string ManagerObject::Version()
{
    return m_version;
}

std::vector<std::string> ManagerObject::Features()
{
    // Served verbatim from the single source of truth in LibreAgent core —
    // never re-derived or filtered here, so this repo and the socket
    // transport (LibreDarwin) can never drift on which tokens are live.
    return std::vector<std::string>(LibreSCRS::Agent::kAgentFeatures.begin(), LibreSCRS::Agent::kAgentFeatures.end());
}

// --- Card-independent visual-signature layout preview ------------------

std::tuple<double, double, std::vector<std::string>, bool>
ManagerObject::LayoutVisualSignature(const std::string& text, const double& x, const double& y, const double& width,
                                     const double& height)
{
    namespace sp = Operations::SignatureParams;
    // Method-entry rejection for a non-finite or non-positive box — the SAME
    // gate Card1.Sign's visualSignature option runs, before narrowing to LM's
    // integer Rect (see SignatureParams::isValidLayoutRect's own comment for
    // the UB this avoids).
    if (!sp::isValidLayoutRect(x, y, width, height)) {
        throw sdbus::Error{sdbus::Error::Name{LibreLinux::AgentWire::kErrInvalidRequest},
                           "LayoutVisualSignature requires a finite box with a positive width/height"};
    }
    const Operations::VisualLayoutResult result =
        Operations::layoutVisualSignature(text, Operations::LayoutBox{x, y, width, height});
    return {result.fontSize, result.lineHeight, result.lines, result.clipped};
}

sdbus::UnixFd ManagerObject::GetAppearanceFont()
{
    const std::vector<std::uint8_t> bytes = Operations::appearanceFontBytes();
    // The label "librescrs-font" is visible in /proc — generic, no PII.
    const int fd = LibreLinux::Common::makeSealedMemfd("librescrs-font", bytes);
    if (fd < 0) {
        throw sdbus::Error{sdbus::Error::Name{LibreLinux::AgentWire::kErrCommunication},
                           "failed to seal the appearance font into a memfd"};
    }
    return sdbus::UnixFd{fd, sdbus::adopt_fd};
}

// --- Config1 property getters (delegate to the store) ---------------------

std::string ManagerObject::DefaultLevel()
{
    return m_config.defaultLevel();
}
std::vector<std::string> ManagerObject::TsaUrls()
{
    return m_config.tsaUrls();
}
std::string ManagerObject::LastTsaUrl()
{
    return m_config.lastTsaUrl();
}
std::vector<sdbus::Struct<std::string, bool, bool>> ManagerObject::TslSources()
{
    std::vector<sdbus::Struct<std::string, bool, bool>> out;
    const auto sources = m_config.tslSources();
    out.reserve(sources.size());
    for (const auto& s : sources) {
        out.emplace_back(s.url, s.isLotl, s.eager);
    }
    return out;
}
std::string ManagerObject::TslCacheDir()
{
    return m_config.tslCacheDir();
}
std::string ManagerObject::AiaCacheDir()
{
    return m_config.aiaCacheDir();
}
std::vector<sdbus::Struct<std::string, bool>> ManagerObject::CscaSources()
{
    std::vector<sdbus::Struct<std::string, bool>> out;
    const auto sources = m_config.cscaSources();
    out.reserve(sources.size());
    for (const auto& s : sources) {
        out.emplace_back(s.uri, s.eager);
    }
    return out;
}
std::string ManagerObject::DefaultReason()
{
    return m_config.defaultReason();
}
std::string ManagerObject::DefaultLocation()
{
    return m_config.defaultLocation();
}
std::string ManagerObject::PluginDir()
{
    return m_config.pluginDir();
}

std::string ManagerObject::callerBusName() const noexcept
{
    try {
        const auto msg = getObject().getCurrentlyProcessedMessage();
        if (const char* sender = msg.getSender(); sender != nullptr) {
            return std::string{sender};
        }
    } catch (...) {
        // Empty -> the authorizer treats it as an unidentified caller.
    }
    return {};
}

std::string ManagerObject::callerLabel() const noexcept
{
    try {
        const auto msg = getObject().getCurrentlyProcessedMessage();
        const pid_t pid = msg.getCredsPid();
        return CallerIdentity::resolveRequesterLabel(pid);
    } catch (...) {
        return {};
    }
}

// --- Pkcs11_1 forwarders --------------------------------------------------
// Each resolves the caller WHILE the in-flight message is current, then
// delegates to the Pkcs11Broker logic. m_pkcs11 is null only in conformance
// tests that never call these (a defensive throw keeps them well-defined).

namespace {
constexpr const char* kErrInternalPkcs11 = "org.librescrs.Agent.Error.Internal";
Pkcs11Broker::Caller resolveCaller(const std::string& busName, const std::string& label)
{
    return Pkcs11Broker::Caller{.busName = CallerToken{busName}, .label = label};
}

// Bind a move-only sdbus::Result<Results...> into a copyable, sdbus-free
// Reply<Outcome, Results...> the (wire-name-free) Pkcs11Broker logic fulfils.
// The Result is shared so the ok / err continuations (which the worker thread
// may run after this method returns) can each reach it; the Reply's own latch
// guarantees exactly-once dispatch, and its fail-closed destructor replies with
// @p fallback if the worker op is torn down unfulfilled. This is the ONLY place
// the neutral broker Outcome is bound to an org.librescrs.Agent.Error.* wire
// name (via errorNameFor) — the broker names no wire string.
template <typename Outcome, typename... Results>
Reply<Outcome, Results...> deferReply(sdbus::Result<Results...>&& result, Outcome fallback)
{
    // Teardown safety relies on the sdbus message refcount: the moved-in
    // sdbus::Result owns the in-flight method-call sd_bus_message, which holds its
    // OWN reference on the underlying sd_bus. So the fail-closed reply the Reply
    // destructor sends at zombie drain still lands even after AgentService's
    // IConnection object is destroyed — the deferred raw-crypto path (SyncProbeOp)
    // therefore needs no connection co-own of its own, unlike the typed ops.
    auto shared = std::make_shared<sdbus::Result<Results...>>(std::move(result));
    return Reply<Outcome, Results...>{
        [shared](const Results&... values) { shared->returnResults(values...); },
        [shared](Outcome oc) {
            shared->returnError(sdbus::Error{sdbus::Error::Name{errorNameFor(oc)}, "pkcs11 operation failed"});
        },
        fallback};
}

// A null-m_pkcs11 (conformance tests) fails the deferred reply immediately.
template <typename... Results>
void failNoPkcs11(sdbus::Result<Results...>&& result)
{
    result.returnError(sdbus::Error{sdbus::Error::Name{kErrInternalPkcs11}, "PKCS#11 surface not wired"});
}
} // namespace

void ManagerObject::CertDer(sdbus::Result<std::vector<std::uint8_t>>&& result, sdbus::ObjectPath reader,
                            std::string certId)
{
    if (!m_pkcs11) {
        failNoPkcs11(std::move(result));
        return;
    }
    // Resolve the caller WHILE the in-flight message is current (before any hop),
    // then hand off — m_pkcs11 validates here and defers the card I/O to the
    // worker, which fulfils the bound Result. Returns the dispatch thread at once.
    m_pkcs11->certDer(reader, certId, resolveCaller(callerBusName(), callerLabel()),
                      deferReply(std::move(result), Pkcs11Broker::CryptoOutcome::CardError));
}

void ManagerObject::PublicKey(sdbus::Result<std::vector<std::uint8_t>, std::vector<std::uint8_t>>&& result,
                              sdbus::ObjectPath reader, std::string certId)
{
    if (!m_pkcs11) {
        failNoPkcs11(std::move(result));
        return;
    }
    m_pkcs11->publicKey(reader, certId, resolveCaller(callerBusName(), callerLabel()),
                        deferReply(std::move(result), Pkcs11Broker::CryptoOutcome::CardError));
}

void ManagerObject::Login(sdbus::Result<std::uint32_t>&& result, sdbus::ObjectPath reader)
{
    if (!m_pkcs11) {
        failNoPkcs11(std::move(result));
        return;
    }
    m_pkcs11->login(reader, resolveCaller(callerBusName(), callerLabel()),
                    deferReply(std::move(result), Pkcs11Broker::LoginOutcome::CardError));
}

void ManagerObject::Logout(const sdbus::ObjectPath& reader)
{
    if (!m_pkcs11) {
        throw sdbus::Error{sdbus::Error::Name{kErrInternalPkcs11}, "PKCS#11 surface not wired"};
    }
    m_pkcs11->logout(reader, resolveCaller(callerBusName(), callerLabel()));
}

void ManagerObject::SignRaw(sdbus::Result<std::vector<std::uint8_t>>&& result, sdbus::ObjectPath reader,
                            std::string certId, std::vector<std::uint8_t> input)
{
    if (!m_pkcs11) {
        failNoPkcs11(std::move(result));
        return;
    }
    m_pkcs11->signRaw(reader, certId, Mechanism::RsaPkcs1Sign, MechParamsEmpty{}, input,
                      resolveCaller(callerBusName(), callerLabel()),
                      deferReply(std::move(result), Pkcs11Broker::CryptoOutcome::CardError));
}

void ManagerObject::Decrypt(sdbus::Result<std::vector<std::uint8_t>>&& result, sdbus::ObjectPath reader,
                            std::string certId, std::vector<std::uint8_t> ciphertext)
{
    if (!m_pkcs11) {
        failNoPkcs11(std::move(result));
        return;
    }
    m_pkcs11->decrypt(reader, certId, Mechanism::RsaPkcs1Decrypt, MechParamsEmpty{}, ciphertext,
                      resolveCaller(callerBusName(), callerLabel()),
                      deferReply(std::move(result), Pkcs11Broker::CryptoOutcome::CardError));
}

void ManagerObject::SetValue(const std::string& key, const sdbus::Variant& value)
{
    const auto m = Config::ConfigStore::mutability(key);
    if (!m) {
        throw sdbus::Error{sdbus::Error::Name{kErrUnknownKey}, "Unknown config key: " + key};
    }
    if (*m == Config::Mutability::FileOnly || *m == Config::Mutability::ReadOnly) {
        throw sdbus::Error{sdbus::Error::Name{kErrReadOnly}, "Config key not settable over D-Bus: " + key};
    }
    if (!m_authorizer.authorize(actionFor(*m), CallerToken{callerBusName()})) {
        throw sdbus::Error{sdbus::Error::Name{kErrNotAuthorized}, "Not authorized to set " + key};
    }
    Config::ConfigStore::SetResult r{false, kErrUnknownKey, "No setter for config key: " + key};
    try {
        if (key == "DefaultLevel") {
            r = m_config.setDefaultLevel(value.get<std::string>());
        } else if (key == "TsaUrls") {
            r = m_config.setTsaUrls(value.get<std::vector<std::string>>());
        } else if (key == "TslSources") {
            std::vector<Config::TslSource> sources;
            for (const auto& s : value.get<std::vector<sdbus::Struct<std::string, bool, bool>>>()) {
                sources.push_back(Config::TslSource{std::get<0>(s), std::get<1>(s), std::get<2>(s)});
            }
            r = m_config.setTslSources(std::move(sources));
        } else if (key == "CscaSources") {
            // Same trust tier as TsaUrls/TslSources (actionFor already picked
            // kActionConfigureTrust above from the store's Mutability) — the
            // set of country-signing anchors is a trust decision, not a
            // preference, so it needs no polkit action of its own.
            std::vector<Config::CscaSource> sources;
            for (const auto& s : value.get<std::vector<sdbus::Struct<std::string, bool>>>()) {
                sources.push_back(Config::CscaSource{std::get<0>(s), std::get<1>(s)});
            }
            r = m_config.setCscaSources(std::move(sources));
        } else if (key == "DefaultReason") {
            r = m_config.setDefaultReason(value.get<std::string>());
        } else if (key == "DefaultLocation") {
            r = m_config.setDefaultLocation(value.get<std::string>());
        }
    } catch (const sdbus::Error&) {
        // value.get<T>() threw -> the variant did not hold the expected type.
        throw sdbus::Error{sdbus::Error::Name{kErrInvalidValue}, "Wrong value type for config key: " + key};
    }
    if (!r.ok) {
        throw sdbus::Error{sdbus::Error::Name{r.errorName}, r.message};
    }
}

void ManagerObject::Reset(const std::string& key)
{
    const auto m = Config::ConfigStore::mutability(key);
    if (!m) {
        throw sdbus::Error{sdbus::Error::Name{kErrUnknownKey}, "Unknown config key: " + key};
    }
    if (*m == Config::Mutability::FileOnly || *m == Config::Mutability::ReadOnly) {
        throw sdbus::Error{sdbus::Error::Name{kErrReadOnly}, "Config key not settable over D-Bus: " + key};
    }
    if (!m_authorizer.authorize(actionFor(*m), CallerToken{callerBusName()})) {
        throw sdbus::Error{sdbus::Error::Name{kErrNotAuthorized}, "Not authorized to reset " + key};
    }
    const auto r = m_config.resetKey(key, /*fromDbus=*/true);
    if (!r.ok) {
        throw sdbus::Error{sdbus::Error::Name{r.errorName}, r.message};
    }
}

void ManagerObject::emitConfigChanged(const std::string& key) noexcept
{
    try {
        emitChanged(key);
    } catch (const std::exception& e) {
        log::warnf("config: failed to emit Changed({}): {}", key, e.what());
    } catch (...) {
        log::warn("config: failed to emit Changed (unknown error)");
    }
}

} // namespace LibreSCRS::Agent
