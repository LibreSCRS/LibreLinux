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
#include <LibreSCRS/Agent/operations/LmSeams.h> // Operations::layoutVisualSignature/appearanceFontBytes
#include <LibreSCRS/Agent/operations/RateLimiter.h>
#include <LibreSCRS/Agent/operations/SignatureParams.h> // isValidLayoutRect
#include <LibreSCRS/Agent/pkcs11/Pkcs11Broker.h>
#include <LibreSCRS/Agent/Reply.h>
#include "SealedMemfdCreator.h" // shared sealed-memfd creator (matches the producer)
#include <LibreSCRS/Agent/trust/CscaAnchorImport.h>
#include <sys/stat.h>
#include <unistd.h>
#include <array>
#include <cerrno>
#include <chrono>
#include <cstddef>
#include <map>
#include <sdbus-c++/Error.h>
#include <sdbus-c++/IObject.h>
#include <sdbus-c++/Message.h>
#include <sys/types.h> // pid_t
#include <exception>
#include <memory>
#include <optional>
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

// ImportCscaMasterList rejections. The master-list refusals are distinct names
// rather than one generic failure because a client has to be able to tell
// "this file is not a master list" from "it is one, and it is empty" — the two
// need different words in front of a person.
constexpr const char* kErrInvalidRequest = LibreLinux::AgentWire::kErrInvalidRequest;
constexpr const char* kErrRateLimited = LibreLinux::AgentWire::kErrRateLimited;
constexpr const char* kErrInputTooLarge = "org.librescrs.Agent.Error.InputTooLarge";
constexpr const char* kErrNotAMasterList = "org.librescrs.Agent.Error.NotAMasterList";
constexpr const char* kErrEmptyMasterList = "org.librescrs.Agent.Error.EmptyMasterList";
constexpr const char* kErrMalformedMasterList = "org.librescrs.Agent.Error.MalformedMasterList";
constexpr const char* kErrBadMasterListSignature = "org.librescrs.Agent.Error.BadMasterListSignature";
constexpr const char* kErrMasterListSignerChanged = "org.librescrs.Agent.Error.MasterListSignerChanged";
constexpr const char* kErrMasterListReplayed = "org.librescrs.Agent.Error.MasterListReplayed";
constexpr const char* kErrAnchorCacheNotWritable = "org.librescrs.Agent.Error.AnchorCacheNotWritable";

enum class ReadStatus : std::uint8_t { Ok, TooLarge, Error, NotRegular };
struct ReadInput
{
    ReadStatus status{ReadStatus::Error};
    std::vector<std::uint8_t> bytes;
};

// Read the whole input off @p fd, capping at @p cap bytes. The fd MUST be a
// regular file or memfd: a pipe/socket/char fd would let a client stall a
// blocking ::read() indefinitely on the single bus thread (whole-agent DoS), so
// non-regular fds are rejected up-front via fstat. Same shape and same reason as
// the document read behind Card1.Sign.
ReadInput readInput(int fd, std::size_t cap)
{
    if (fd < 0) {
        return {ReadStatus::Error, {}};
    }
    struct stat st{};
    if (::fstat(fd, &st) != 0) {
        return {ReadStatus::Error, {}};
    }
    if (!S_ISREG(st.st_mode)) {
        return {ReadStatus::NotRegular, {}};
    }
    std::vector<std::uint8_t> out;
    std::array<std::uint8_t, 64 * 1024> buf{};
    for (;;) {
        const ssize_t n = ::read(fd, buf.data(), buf.size());
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return {ReadStatus::Error, {}};
        }
        if (n == 0) {
            return {ReadStatus::Ok, std::move(out)};
        }
        if (out.size() + static_cast<std::size_t>(n) > cap) {
            return {ReadStatus::TooLarge, {}};
        }
        out.insert(out.end(), buf.data(), buf.data() + n);
    }
}

// What an accepted import leaves in the agent's own configuration.
//
// The import reply answers the client that performed the import. A client that
// has only just connected has no reply to read, so the outcome is REMEMBERED
// here rather than left to the caller — the same standing a recorded
// LastTsaUrl has, and read-only for a stronger reason: a client able to write
// it would be claiming what passports are checked against without installing a
// single anchor.
//
// AN IMPORT NOW TAKES IN SEVERAL PUBLISHERS. What the directory serves is a
// collection: dozens of master lists, each published and signed by a different
// country, and an import that admits them holds one record per publisher. The
// three members below that were written for ONE publisher therefore have to
// describe many, and each is resolved the same way — report what is true of the
// WHOLE, and where the whole has no answer, say nothing rather than pick a
// winner out of the parts.
//
//   * `signer` and `signedAt` are filled only when the agent follows EXACTLY
//     ONE publisher, which is every single published list and was the only case
//     that ever existed before. With several there is no such thing as "the
//     publisher" or "the date", and naming one of them would be a SPECIFIC
//     false statement rather than a vague one. The refusal path already reports
//     its fingerprints under exactly this rule.
//   * `signerPinned` is the AGGREGATE, and deliberately the weakest of its
//     parts: true only when EVERY accepted publisher was established. For one
//     publisher that is the identical statement it always made. For several it
//     is the only reading a surface may render "authenticity verified" over.
//     The discipline replayRefusalActive is already defined with, for the same
//     reason.
//
// WHAT IS NOT REPORTED, and is absent rather than approximated: HOW MANY
// publishers were taken in, and how many of those were established. Both are
// honest things to say and neither can be said from here — this record is the
// only thing that survives a restart, it has no member able to carry a count,
// and a key present in the import reply but gone from the property a moment
// later would be worse than the silence. Those numbers go to the log instead,
// where they cost no interface.
Config::CscaAnchorState toRecordedState(const Trust::AnchorState& state)
{
    // Exactly one publisher: everything the single-publisher vocabulary was
    // written to say is true of it, so all of it is said.
    const Trust::AcceptedSigner* only = state.signers.size() == 1 ? &state.signers.front() : nullptr;

    Config::CscaAnchorState out;
    out.anchors = state.anchorCount;
    out.issuers = state.issuerCount;
    out.replayRefusalActive = state.replayRefusalActive();
    out.signer = only != nullptr ? Trust::toHex(only->fingerprint) : std::string{};
    out.signerPinned = state.everyPublisherEstablished();
    out.acceptedAt = state.acceptedAt;
    out.signedAt = only != nullptr ? only->signedAt : std::nullopt;
    out.origin = state.origin;
    return out;
}

// The dict both the import reply and the CscaAnchorState property serve, built
// from the one value the agent records, so the two can never describe the same
// state differently.
std::map<std::string, sdbus::Variant> anchorStateDict(const std::optional<Config::CscaAnchorState>& state)
{
    std::map<std::string, sdbus::Variant> out;
    if (!state) {
        return out; // nothing imported: an empty dict, not a dict full of zeros
    }
    out["anchors"] = sdbus::Variant{state->anchors};
    out["issuers"] = sdbus::Variant{state->issuers};
    if (!state->signer.empty()) {
        // ABSENT when the import took in several publishers, because there is
        // then no publisher for this to name. A client written before
        // collections existed reads a missing key and shows nothing, which is
        // what is true. That same client handed one fingerprint out of
        // twenty-eight would show it under a label its dialog renders as "the
        // publisher" — and on a trust surface a wrong answer and no answer are
        // not failures of the same size.
        out["signer"] = sdbus::Variant{state->signer};
    }
    // ALWAYS present, and now an aggregate: true only when EVERY publisher the
    // import took in was established. Unchanged in meaning for the single
    // publisher it used to describe, and for several the only reading that
    // cannot overstate — see toRecordedState.
    out["signerPinned"] = sdbus::Variant{state->signerPinned};
    if (state->acceptedAt) {
        out["acceptedAt"] = sdbus::Variant{*state->acceptedAt};
    }
    // ALWAYS present, because its false is the interesting value: an
    // installation whose anchors cannot be checked for rollback has to be able
    // to find that out, and a missing key would read as "no problem here".
    out["replayRefusalActive"] = sdbus::Variant{state->replayRefusalActive};
    if (state->signedAt) {
        // Omitted rather than zeroed when the list carried no date: a sentinel
        // would be indistinguishable from a list signed at the epoch. Omitted
        // for a second reason since collections — several publishers sign at
        // several times and no one of them is the collection's — and the two
        // read alike to a client on purpose, because absence has always meant
        // "there is no one date to show here".
        out["signedAt"] = sdbus::Variant{*state->signedAt};
    }
    out["origin"] = sdbus::Variant{state->origin};
    return out;
}

[[noreturn]] void throwRefusal(const Trust::Refusal& refusal)
{
    switch (refusal.reason) {
    case Trust::ImportRefusal::NotAMasterList:
        throw sdbus::Error{sdbus::Error::Name{kErrNotAMasterList}, "The file is not an ICAO master list"};
    case Trust::ImportRefusal::Empty:
        throw sdbus::Error{sdbus::Error::Name{kErrEmptyMasterList},
                           "The master list carries no country signing certificate"};
    case Trust::ImportRefusal::Malformed:
        throw sdbus::Error{sdbus::Error::Name{kErrMalformedMasterList}, "The master list's content cannot be read"};
    case Trust::ImportRefusal::BadSignature:
        throw sdbus::Error{sdbus::Error::Name{kErrBadMasterListSignature},
                           "The signature over the master list does not verify"};
    case Trust::ImportRefusal::CacheNotWritable:
        throw sdbus::Error{sdbus::Error::Name{kErrAnchorCacheNotWritable},
                           "The master list verified but the anchors could not be stored"};
    case Trust::ImportRefusal::Replayed: {
        // Both dates travel with the refusal, and the two shapes read
        // differently on purpose: a missing offered date is the STRIP attempt,
        // a smaller one is the rollback.
        std::string replay = "The master list is not newer than the one already installed";
        if (refusal.trustedSignedAt) {
            replay += "; installed list signed at " + std::to_string(*refusal.trustedSignedAt);
        }
        replay += refusal.seenSignedAt ? "; offered list signed at " + std::to_string(*refusal.seenSignedAt)
                                       : "; the offered list carries no signing time at all";
        throw sdbus::Error{sdbus::Error::Name{kErrMasterListReplayed}, replay};
    }
    case Trust::ImportRefusal::SignerChanged:
        break;
    }
    // BOTH fingerprints travel with the refusal. Telling a lawful rotation from
    // an attack needs a person who can recognise the publisher; the agent has
    // nothing to decide it with, so it must not pretend to.
    std::string message = "The master list is signed by a publisher this agent does not follow";
    if (refusal.trustedSigner) {
        message += "; trusted signer " + Trust::toHex(*refusal.trustedSigner);
    }
    if (refusal.seenSigner) {
        message += "; offered signer " + Trust::toHex(*refusal.seenSigner);
    }
    throw sdbus::Error{sdbus::Error::Name{kErrMasterListSignerChanged}, message};
}
} // namespace

ManagerObject::ManagerObject(sdbus::IConnection& connection, sdbus::ObjectPath path, std::string version,
                             Config::ConfigStore& config, Authorizer& authorizer, Operations::RateLimiter& rateLimiter,
                             Pkcs11Broker* pkcs11)
    : AdaptorInterfaces(connection, std::move(path)), m_version(std::move(version)), m_config(config),
      m_authorizer(authorizer), m_rateLimiter(rateLimiter), m_pkcs11(pkcs11)
{
    // Reconcile before the object exists on the bus. This is the agent's
    // startup — the store has just been loaded from its file, and
    // AgentService::registerOnBus builds this object while the event loop is
    // only entered afterwards in run(), so no client can have read the stale
    // report and none can read it after. WHEN to do it belongs to the object
    // that SERVES the property rather than to the composition root: not
    // serving a report known to be stale is this object's own obligation.
    //
    // WHAT it does is the shared library's, and deliberately not ours: the
    // decision reads the configuration store and the anchor cache and touches
    // no bus, so a copy of it here would have been a second implementation of
    // a trust-policy rule for every other host to diverge from. See
    // Trust::discardStaleAnchorReport's own header for the rule and for why
    // absence rather than a zeroed report is the honest spelling.
    Trust::discardStaleAnchorReport(m_config);
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

std::map<std::string, sdbus::Variant> ManagerObject::CscaAnchorState()
{
    // Served from the store, exactly as LastTsaUrl above is: agent-internal
    // state the agent recorded, not a preference a client handed it. Empty
    // until an import has been accepted — a zeroed report and an accepted list
    // that vouched for nothing mean opposite things.
    return anchorStateDict(m_config.cscaAnchorState());
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

std::map<std::string, sdbus::Variant> ManagerObject::ImportCscaMasterList(const sdbus::UnixFd& masterList)
{
    // ORDER, and it is the whole point of this preamble: AUTHORISE the client,
    // then apply the per-caller flood bound, and only THEN touch the
    // descriptor. Both gates are keyed on the caller's unique bus name, which
    // the kernel validates and which cannot be reused for the life of the
    // connection. A rejected caller must never be able to make the agent read
    // (up to the cap off) an fd it handed over — the same discipline, and the
    // same reasoning, as the document ingest behind Card1.Sign.
    //
    // The polkit action is the trust one, shared with CscaSources: an import is
    // a larger trust change than naming a source, not a smaller one.
    const std::string sender = callerBusName();
    if (!m_authorizer.authorize(kActionConfigureTrust, CallerToken{sender})) {
        throw sdbus::Error{sdbus::Error::Name{kErrNotAuthorized}, "Not authorized to import country signing anchors"};
    }
    if (!m_rateLimiter.allow(CallerToken{sender})) {
        throw sdbus::Error{sdbus::Error::Name{kErrRateLimited}, "Too many anchor imports; try again shortly"};
    }

    // A PLAIN descriptor, deliberately: a master list is public data, and the
    // sealed memfd this agent uses elsewhere is its vocabulary for secrets.
    // Reading it here on the bus thread is bounded by the fstat regular-file
    // rejection and by the cap, exactly as the sign path is.
    auto input = readInput(masterList.get(), Trust::kMaxMasterListBytes);
    if (input.status == ReadStatus::NotRegular) {
        throw sdbus::Error{sdbus::Error::Name{kErrInvalidRequest},
                           "The master list must be a regular file or memfd (no pipes/sockets)"};
    }
    if (input.status == ReadStatus::TooLarge) {
        throw sdbus::Error{sdbus::Error::Name{kErrInputTooLarge}, "The master list exceeds the size limit"};
    }
    if (input.status == ReadStatus::Error) {
        throw sdbus::Error{sdbus::Error::Name{kErrInvalidRequest}, "The master list could not be read"};
    }

    Trust::AnchorCache cache(m_config.cscaCacheDir());
    const auto now =
        std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
    auto imported = Trust::importMasterList(input.bytes, cache, now);
    if (!imported) {
        throwRefusal(imported.error());
    }

    // Deliberately says what was DONE, not that anything was proved: on a first
    // import nothing is established, and a client that renders "authenticity
    // verified" over that is claiming more than the agent measured.
    //
    // The counts the WIRE cannot carry live here. How many publishers the file
    // was taken in from, how many of those were established, and how many of
    // its lists contributed nothing are the numbers that explain a smaller
    // anchor count than a person expected — the recorded state has no member to
    // put them in, and a log line costs no interface.
    std::size_t established = 0;
    for (const Trust::AcceptedSigner& signer : imported->signers) {
        established += signer.identityEstablished ? 1U : 0U;
    }
    log::infof("country signing anchors imported: anchors={} issuers={} publishers={} established={} lists={} "
               "refused={}",
               imported->anchorCount, imported->issuerCount, imported->signers.size(), established,
               imported->listsOffered, imported->refusedLists.size());

    // Remember it. The reply below tells THIS client what it just installed;
    // the record is what tells the next client to connect, which has no reply
    // to read. The store persists it and fires Changed("CscaAnchorState")
    // itself — the path a recorded LastTsaUrl already takes — so there is no
    // explicit emit here, and no second signal for one import.
    const auto recorded = toRecordedState(*imported);
    m_config.recordCscaAnchorState(recorded);
    return anchorStateDict(recorded);
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
