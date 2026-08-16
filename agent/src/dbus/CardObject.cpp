// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#include "dbus/CardObject.h"
#include "AgentErrorNames.h" // shared wire error-name table (hoisted UnsupportedOnThisCard + credential errors)
#include "AgentObjectPath.h" // objectIdFromPath (reader path -> ObjectId)
#include <LibreSCRS/Agent/CryptoWorkerContext.h>
#include <LibreSCRS/Agent/backend/Authorizer.h>
#include <LibreSCRS/Agent/backend/Logging.h>
#include "CallerIdentity.h"
#include <LibreSCRS/Agent/cache/CredentialSnapshotCache.h>
#include <LibreSCRS/Agent/config/ConfigStore.h>
#include "dbus/ObjectManagerSignals.h" // emitObjectManagerAdded/Removed
#include "dbus/OperationAdaptorFactory.h"
#include "dbus/OperationPath.h"
#include "operations/ActivateSigningKeyOperation.h"
#include "operations/GetPhotoOperation.h"
#include "operations/ListCredentialsOperation.h"
#include "operations/ManagePinOperation.h"
#include <LibreSCRS/Agent/operations/OperationManager.h>
#include <LibreSCRS/Agent/operations/PinChangeFlow.h> // PinManageRequest, validatePinManageRequest
#include <LibreSCRS/Agent/operations/PromptSerializer.h>
#include <LibreSCRS/Agent/operations/RateLimiter.h>
#include "operations/ReadCertificatesOperation.h"
#include "operations/ReadIdentityOperation.h"
#include "operations/ReadTokenInfoOperation.h"
#include <LibreSCRS/Agent/operations/BatchSignFlow.h> // isValidBatchDocumentCount, BatchDocumentInput
#include "operations/SignOperation.h"
#include <LibreSCRS/Agent/operations/SignatureParams.h>
#include <LibreSCRS/Agent/util/CallerLabel.h>       // sanitizeLabel (neutral core)
#include <LibreSCRS/Agent/value/CredentialRecord.h> // CredentialSnapshot, EntryError
#include <LibreSCRS/Plugin/PluginTypes.h>
#include <sdbus-c++/Error.h>
#include <sdbus-c++/IObject.h>
#include <sdbus-c++/Message.h>
#include <unistd.h>    // read, close
#include <sys/stat.h>  // fstat, S_ISREG
#include <sys/types.h> // pid_t, ssize_t
#include <array>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace LibreSCRS::Agent {

namespace {

// IdentityData bit; the named constant keeps the source of truth in the
// consumer header rather than a literal sprinkled across the agent.
constexpr std::uint32_t kIdentityCapBit = static_cast<std::uint32_t>(LibreSCRS::Plugin::CardCapabilities::IdentityData);
constexpr std::uint32_t kPkiCapBit = static_cast<std::uint32_t>(LibreSCRS::Plugin::CardCapabilities::PKI);
constexpr std::uint32_t kPinManagementCapBit =
    static_cast<std::uint32_t>(LibreSCRS::Plugin::CardCapabilities::PinManagement);

// The wire error NAMES now live in common/AgentErrorNames.h (the hoisted
// UnsupportedOnThisCard + the two new credential errors) so the Plan-C / macOS
// mirrors share one spelling with this producer.
constexpr const char* kUnsupportedErrName = LibreLinux::AgentWire::kErrUnsupportedOnThisCard;
constexpr const char* kInvalidRequestErrName = LibreLinux::AgentWire::kErrInvalidRequest;
constexpr const char* kUnknownCredentialErrName = LibreLinux::AgentWire::kErrUnknownCredential;
constexpr const char* kInternalErrName = "org.librescrs.Agent.Error.Internal";
constexpr const char* kBadParamErrName = "org.librescrs.Agent.Error.UnsupportedSignatureParameter";
constexpr const char* kInputTooLargeErrName = "org.librescrs.Agent.Error.InputTooLarge";
// RateLimited / NotAuthorized are part of the shared credential contract, so
// they are sourced directly from common/AgentErrorNames.h at each call site
// (no hand-spelled local copy to drift from the producer/consumer spelling).

// The read/photo flows take the deposit seam by REFERENCE, so a wiring site
// that has no plugin registry to resolve deposit targets from still has to hand
// them something. This shared no-op stands in there, exactly as NullGroupSink
// stands in for a wiring site with no Group signal to emit: the renegotiation
// then deposits nothing and the re-run fails auth truthfully, instead of the
// deps struct carrying an optional reference nobody can honour. Stateless, so
// one instance serves every card.
Operations::CredentialDepositor& depositorOrNoOp(Operations::CredentialDepositor* wired) noexcept
{
    static Operations::NullCredentialDepositor noDeposit;
    return wired != nullptr ? *wired : noDeposit;
}

// Artifact labels surfaced in the consent prompt — WHAT the client is about
// to read. Domain-blind, no card specifics. Stable, lower-case identifiers a
// future polkit action / CTK binding can also key off.
constexpr const char* kArtifactIdentity = "identity";
constexpr const char* kArtifactPhoto = "photo";
constexpr const char* kArtifactCertificates = "certificates";
constexpr const char* kArtifactTokenInfo = "token";
constexpr const char* kArtifactCredentials = "credentials";
// Card1.SignBatch's TRUSTED, agent-owned consent category token (never
// client-supplied — mirrors kArtifactIdentity/kArtifactPhoto/etc.'s closed
// vocabulary). Recorded here for the same discoverability/registry purpose
// as its siblings; the flow that actually builds the consent prompt
// (operations/BatchSignFlow.cpp, in the LibreAgent core) hardcodes this SAME
// literal directly (a different repo/library, so it cannot reference this
// constant) — kept in sync by convention/review, not by a shared header. A
// single Sign's own "signature" token has no CardObject.cpp entry either,
// for the identical reason: SignFlow.cpp hardcodes it the same way.
constexpr const char* kArtifactSignatureBatch = "signature-batch";

// The closed options-key set for Credentials1.ManagePin (all non-secret). Any
// other key at method entry is an undefined-option InvalidRequest.
constexpr const char* kOptionActivateKey = "activateKey";

// Document input cap — oversize is rejected at method entry.
constexpr std::size_t kMaxInputBytes = 256ull * 1024 * 1024;

enum class ReadStatus { Ok, TooLarge, Error, NotRegular };
struct ReadDoc
{
    ReadStatus status{ReadStatus::Error};
    std::vector<std::uint8_t> bytes;
};

// Read the whole document off @p fd (a read-only client fd/memfd), capping at
// @p cap bytes. The fd MUST be a regular file or memfd: a pipe/socket/char fd
// would let a client stall a blocking ::read() indefinitely on the single bus
// thread (whole-agent DoS), so non-regular fds are rejected up-front via fstat.
// A regular file / memfd is finite and bounded by the cap.
ReadDoc readDocument(int fd, std::size_t cap)
{
    if (fd < 0) {
        return {ReadStatus::Error, {}};
    }
    struct stat st{};
    if (::fstat(fd, &st) != 0) {
        return {ReadStatus::Error, {}};
    }
    if (!S_ISREG(st.st_mode)) {
        // FIFO/socket/char/block/dir: not a bounded, seekable document source.
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

// Read a client-supplied string option, defaulting when absent or mistyped.
std::string optString(const std::map<std::string, sdbus::Variant>& options, const std::string& key,
                      std::string fallback)
{
    auto it = options.find(key);
    if (it == options.end()) {
        return fallback;
    }
    try {
        return it->second.get<std::string>();
    } catch (const sdbus::Error&) {
        return fallback;
    }
}

bool optBool(const std::map<std::string, sdbus::Variant>& options, const std::string& key, bool fallback)
{
    auto it = options.find(key);
    if (it == options.end()) {
        return fallback;
    }
    try {
        return it->second.get<bool>();
    } catch (const sdbus::Error&) {
        return fallback;
    }
}

// Read a nested a{sv} option (visualSignature). Absent, or present but
// not itself an a{sv}, both answer nullopt — the caller's own field-by-field
// extraction is what turns a genuinely malformed value into the precise
// UnsupportedSignatureParameter rejection.
std::optional<std::map<std::string, sdbus::Variant>> optNestedMap(const std::map<std::string, sdbus::Variant>& options,
                                                                  const std::string& key)
{
    auto it = options.find(key);
    if (it == options.end()) {
        return std::nullopt;
    }
    try {
        return it->second.get<std::map<std::string, sdbus::Variant>>();
    } catch (const sdbus::Error&) {
        return std::nullopt;
    }
}

// Read a numeric field out of a nested a{sv} map (visualSignature's
// page/x/y/width/height), tolerant of whichever D-Bus numeric variant type
// the caller's binding happened to choose. Unlike the top-level `options`
// argument (bound against this method's own fixed a{sv} signature by every
// binding), this nested map has no XML signature forcing one exact wire
// type — a caller building it (Qt's QVariantMap -> a{sv}, most commonly)
// may reasonably send an int32 for what is conceptually a whole number.
// Absent, or present but not any of these numeric types, answers nullopt.
std::optional<double> optNestedNumber(const std::map<std::string, sdbus::Variant>& m, const std::string& key)
{
    const auto it = m.find(key);
    if (it == m.end()) {
        return std::nullopt;
    }
    const sdbus::Variant& v = it->second;
    try {
        return v.get<double>();
    } catch (const sdbus::Error&) {
    }
    try {
        return static_cast<double>(v.get<std::int32_t>());
    } catch (const sdbus::Error&) {
    }
    try {
        return static_cast<double>(v.get<std::uint32_t>());
    } catch (const sdbus::Error&) {
    }
    try {
        return static_cast<double>(v.get<std::int64_t>());
    } catch (const sdbus::Error&) {
    }
    try {
        return static_cast<double>(v.get<std::uint64_t>());
    } catch (const sdbus::Error&) {
    }
    return std::nullopt;
}

// Method-entry-resolved signature options, shared verbatim by Sign and
// SignBatch -- everything from Sign's own options vocabulary EXCEPT
// certId/inputDocument/displayName, which differ per call shape (one
// document vs N, one displayName option vs a per-document name).
struct ResolvedSignOptions
{
    std::string format;
    std::string level;
    std::string packaging;
    bool allowExpired{false};
    std::string reason;
    std::string location;
    std::string tsaUrl;
    std::optional<Operations::VisualParams> visual;
};

// Resolve + validate the options vocabulary Sign and SignBatch share
// (format/level/packaging/allowExpired/reason/location/tsaUrl/
// visualSignature) against @p options -- extracted VERBATIM from Sign's own
// method-entry logic so the two entries can never drift apart. @p
// sniffSource supplies the bytes format=auto sniffs against when the format
// option is absent/auto: Sign passes its own single document; SignBatch
// passes the FIRST document only -- the whole batch shares ONE resolved
// format/level/packaging (not a per-document resolution), so auto-detection
// picks a single representative. Throws the SAME sdbus::Error taxonomy every
// Sign method-entry rejection already used (kBadParamErrName ==
// UnsupportedSignatureParameter).
ResolvedSignOptions resolveSignOptions(const std::map<std::string, sdbus::Variant>& options,
                                       const std::vector<std::uint8_t>& sniffSource, Config::ConfigStore& config)
{
    namespace sp = Operations::SignatureParams;

    std::string format = optString(options, "format", "auto");
    if (format == "auto" || format.empty()) {
        const auto sniffed = sp::sniffFormat(sniffSource);
        if (!sniffed) {
            throw sdbus::Error{sdbus::Error::Name{kBadParamErrName}, "Could not infer the signature format"};
        }
        format = *sniffed;
    }
    if (!sp::isKnownFormat(format)) {
        throw sdbus::Error{sdbus::Error::Name{kBadParamErrName}, "Unsupported signature format"};
    }

    // tsaUrl overrides the configured TSA for THIS sign only -- https +
    // non-empty host. Read and validated BEFORE the level is resolved, because
    // it counts toward "a timestamp authority is available" below: doing it in
    // this order means a malformed URL is rejected on its own terms instead of
    // first lifting the level it is about to be rejected against. Whether the
    // RESOLVED level admits a tsaUrl at all is checked further down, once there
    // is a level to check it against.
    std::string tsaUrl;
    if (const auto it = options.find("tsaUrl"); it != options.end()) {
        try {
            tsaUrl = it->second.get<std::string>();
        } catch (const sdbus::Error&) {
            throw sdbus::Error{sdbus::Error::Name{kBadParamErrName}, "tsaUrl must be a string"};
        }
        if (!sp::isValidTsaUrl(tsaUrl)) {
            throw sdbus::Error{sdbus::Error::Name{kBadParamErrName},
                               "tsaUrl must be an https URL with a non-empty host"};
        }
    }

    // Resolve the effective level per request: an explicit option always wins;
    // a request that DEFERS -- an absent key, or the "auto" sentinel the other
    // two option vocabularies already accepted -- takes the configured default,
    // and a defaulted "b-b" upgrades to "b-t" when a timestamp authority is
    // available. The `try` still wraps only the extraction, so a non-string
    // level keeps its own specific rejection.
    std::optional<std::string> requestedLevel;
    if (const auto it = options.find("level"); it != options.end()) {
        try {
            requestedLevel = sp::requestedLevelFrom(it->second.get<std::string>());
        } catch (const sdbus::Error&) {
            throw sdbus::Error{sdbus::Error::Name{kBadParamErrName}, "level must be a string"};
        }
    }
    // A per-request tsaUrl counts toward "a timestamp authority is available",
    // so a DEFAULTED baseline lifts to b-t instead of resolving to b-b and then
    // being rejected for carrying a tsaUrl at all.
    const bool hasTsa = !config.tsaUrls().empty() || !tsaUrl.empty();
    std::string level = sp::resolveSignLevel(requestedLevel, config.defaultLevel(), hasTsa);
    if (!sp::isKnownLevel(level)) {
        throw sdbus::Error{sdbus::Error::Name{kBadParamErrName}, "Unsupported signature level"};
    }
    // This release produces the whole baseline AdES family (b-b, b-t, b-lt,
    // b-lta). Fail closed at the agent for anything outside it.
    if (!sp::isImplementedSignLevel(level)) {
        throw sdbus::Error{sdbus::Error::Name{kBadParamErrName}, "Only the " + sp::implementedSignLevelsDisplay() +
                                                                     " signature levels are supported in this release"};
    }
    // A tsaUrl is meaningful only for the timestamped/long-term family. Checked
    // against the RESOLVED level: a request that deferred and lifted to b-t on
    // the strength of this very URL is legitimate, and only an explicit b-b can
    // still land here.
    if (!tsaUrl.empty() && level == "b-b") {
        throw sdbus::Error{sdbus::Error::Name{kBadParamErrName},
                           "tsaUrl is only meaningful for the timestamped/long-term family (b-t/b-lt/b-lta)"};
    }

    std::string packaging = optString(options, "packaging", "auto");
    if (packaging == "auto" || packaging.empty()) {
        packaging = sp::defaultPackagingFor(format);
    }
    if (!sp::isKnownPackaging(packaging)) {
        throw sdbus::Error{sdbus::Error::Name{kBadParamErrName}, "Unsupported packaging mode"};
    }

    // visualSignature attaches a PAdES visible-signature appearance; all six
    // nested fields are required together once the map itself is present.
    std::optional<Operations::VisualParams> visual;
    if (const auto nested = optNestedMap(options, "visualSignature")) {
        if (format != "pades") {
            throw sdbus::Error{sdbus::Error::Name{kBadParamErrName},
                               "visualSignature is only supported for the pades format"};
        }
        const auto page = optNestedNumber(*nested, "page");
        const auto x = optNestedNumber(*nested, "x");
        const auto y = optNestedNumber(*nested, "y");
        const auto width = optNestedNumber(*nested, "width");
        const auto height = optNestedNumber(*nested, "height");
        std::optional<std::string> text;
        if (const auto textIt = nested->find("text"); textIt != nested->end()) {
            try {
                text = textIt->second.get<std::string>();
            } catch (const sdbus::Error&) {
            }
        }
        if (!page || !x || !y || !width || !height || !text ||
            !sp::isValidVisualGeometry(static_cast<std::int64_t>(*page), *x, *y, *width, *height)) {
            throw sdbus::Error{sdbus::Error::Name{kBadParamErrName},
                               "visualSignature requires page/x/y/width/height/text, a non-negative page, and a "
                               "positive width/height"};
        }
        visual = Operations::VisualParams{
            .page = static_cast<int>(*page),
            .x = static_cast<float>(*x),
            .y = static_cast<float>(*y),
            .width = static_cast<float>(*width),
            .height = static_cast<float>(*height),
            .text = std::move(*text),
        };
    }

    return ResolvedSignOptions{
        .format = std::move(format),
        .level = std::move(level),
        .packaging = std::move(packaging),
        .allowExpired = optBool(options, "allowExpired", false),
        .reason = optString(options, "reason", config.defaultReason()),
        .location = optString(options, "location", config.defaultLocation()),
        .tsaUrl = std::move(tsaUrl),
        .visual = std::move(visual),
    };
}

} // namespace

CardObject::CardObject(sdbus::IConnection& connection, sdbus::ObjectPath path, std::uint32_t capabilities,
                       sdbus::ObjectPath reader, Operations::OperationManager& manager, CardOperationDeps deps)
    : AdaptorInterfaces(connection, path), m_connection(connection), m_capabilities(capabilities),
      m_reader(std::move(reader)), m_manager(manager), m_deps(std::move(deps)), m_selfPath(std::move(path)),
      m_cardType(m_deps.cardType)
{
    // Auto-populate the non-owning seam handles from the unique_ptr members
    // when those were provided by the production path (BusExporter). Tests
    // that supply handles directly bypass this branch.
    if (m_deps.ownedReader && !m_deps.reader) {
        m_deps.reader = m_deps.ownedReader.get();
    }
    if (m_deps.ownedDepositor && !m_deps.depositor) {
        m_deps.depositor = m_deps.ownedDepositor.get();
    }
    if (m_deps.ownedCertReader && !m_deps.certReader) {
        m_deps.certReader = m_deps.ownedCertReader.get();
    }
    if (m_deps.ownedTrustVerifier && !m_deps.trustVerifier) {
        m_deps.trustVerifier = m_deps.ownedTrustVerifier.get();
    }
    if (m_deps.ownedSigner && !m_deps.signer) {
        m_deps.signer = m_deps.ownedSigner.get();
    }
    if (m_deps.ownedCredentials && !m_deps.credentialManager) {
        m_deps.credentialManager = m_deps.ownedCredentials.get();
    }
    registerAdaptor();
    // Announce over the ObjectManager so a client tracking the live tree resolves
    // the card immediately (sdbus-c++ does not auto-emit InterfacesAdded). Without
    // this, the owning reader reports HasCard=true but the client never learns how
    // to reach the Card1 object until it re-runs GetManagedObjects by hand.
    emitObjectManagerAdded(getObject(), "card");
}

CardObject::~CardObject()
{
    // Withdraw BEFORE unregistering, while the interface list is still enumerable,
    // so live-tracking clients drop the card (and terminalise its operations).
    emitObjectManagerRemoved(getObject(), "card");
    unregisterAdaptor();
}

void CardObject::attachLifetimeGuards(Operations::OperationBase& op) const
{
    // Co-own the single crypto-worker context for the op's whole lifetime and bind
    // the agent-wide shutdown-cancel token. An op whose worker is abandoned while
    // blocked in the consent prompt then keeps every core member its post-unblock
    // unwind may touch alive through this ONE share: the prompter for the blocked
    // call, the gate for the SlotGuard unwind, and the credential cache for a nested
    // CAN/MRZ prompt's putCan/putMrz (which lands past the flow gate). The context's
    // lease member is harmlessly along for the ride (the typed path never touches the
    // pkcs11 lease). On teardown the op bails at its flow's post-prompt gate + skips
    // its wire completion where it can. No-ops for a null context / default token a
    // conformance test may leave unset.
    op.keepAlive(m_deps.cryptoContext);
    // Co-own the op's OWN sdbus channel resource class too: a share of the agent bus
    // connection, so an abandoned typed op keeps the connection alive until it drains
    // and its channel adaptor's emit + unregister touch LIVE memory (a DIFFERENT
    // resource than the core members the crypto context covers). Held in the op's
    // keepAlive vector, which is destroyed AFTER the channel (OperationBase member
    // order), so the unregister at op destruction still sees a live connection.
    op.keepAlive(m_deps.connectionKeepAlive);
    // Co-own the LM seam bundle the op drives. The op Deps carry the seam by bare
    // reference (bound at build time from the .get() handle), so an abandoned
    // qualified-sign worker that unblocks past the flow gate and dereferences its
    // signer seam's vtable + the engine it holds by reference would touch a seam
    // freed with the CardObject — unless the op co-owns the seam share. The sign
    // seam is the one with post-unblock state (snapshot() + recordLastTsaUrlUsed);
    // the stateless read/cert seams are co-owned uniformly so the invariant does not
    // rest on their statelessness. Null in tests that wire the bare handles directly
    // (keepAlive no-ops a null share).
    op.keepAlive(m_deps.ownedSigner);
    op.keepAlive(m_deps.ownedReader);
    // The deposit seam holds the plugin registry by reference, so an abandoned
    // reader that unblocks past the flow gate and renegotiates must not
    // dereference a seam freed with the CardObject.
    op.keepAlive(m_deps.ownedDepositor);
    op.keepAlive(m_deps.ownedCertReader);
    op.keepAlive(m_deps.ownedTrustVerifier);
    // The credential seam is stateless (a router over the plugin list), co-owned
    // uniformly with the other seams so an abandoned credential worker that unblocks
    // past the flow gate never dereferences a seam freed with the CardObject.
    op.keepAlive(m_deps.ownedCredentials);
    op.bindShutdownToken(m_deps.shutdownToken);
}

std::uint32_t CardObject::Capabilities()
{
    return m_capabilities;
}

sdbus::ObjectPath CardObject::Reader()
{
    return m_reader;
}

std::string CardObject::PreReadAuthMethod()
{
    // Empty (e.g. a test that never set it) reads as the no-unlock default,
    // matching the documented Card1.PreReadAuthMethod vocabulary.
    return m_deps.preReadAuth.empty() ? std::string{"None"} : m_deps.preReadAuth;
}

std::string CardObject::CardType()
{
    const std::lock_guard guard(m_cardTypeMutex);
    return m_cardType;
}

std::string CardObject::Atr()
{
    // Immutable after construction (known before this object exists); no lock.
    return m_deps.atrHex;
}

void CardObject::updateCardType(const std::string& cardType)
{
    {
        const std::lock_guard guard(m_cardTypeMutex);
        if (m_cardType == cardType) {
            return; // no-op: nothing actually changed
        }
        m_cardType = cardType;
    }
    // Emitted OUTSIDE the lock: emitPropertiesChangedSignal takes the sd-bus
    // connection lock, and holding m_cardTypeMutex across a bus call would
    // invert the bus/agent lock order (mirrors ReaderObject::updateCardPresence).
    getObject().emitPropertiesChangedSignal(sdbus::InterfaceName{org::librescrs::Agent::Card1_adaptor::INTERFACE_NAME},
                                            std::vector<sdbus::PropertyName>{sdbus::PropertyName{"CardType"}});
}

bool CardObject::hasIdentityCapability() const noexcept
{
    return (m_capabilities & kIdentityCapBit) != 0u;
}

bool CardObject::hasPkiCapability() const noexcept
{
    return (m_capabilities & kPkiCapBit) != 0u;
}

bool CardObject::hasPinManagementCapability() const noexcept
{
    return (m_capabilities & kPinManagementCapBit) != 0u;
}

bool CardObject::hasAllSeams() const noexcept
{
    // The session now comes from the OperationManager's per-reader holder, not a
    // per-card opener seam, so the opener is no longer part of the seam set.
    return m_deps.reader != nullptr && m_deps.prompter != nullptr && m_deps.serializer != nullptr &&
           m_deps.credentials != nullptr && m_deps.readCache != nullptr;
}

bool CardObject::hasCertSeams() const noexcept
{
    // Cert read uses the certReader + trustVerifier seams plus the shared
    // prompt/credential plumbing; it does NOT need the identity CardReader or
    // the identity read cache.
    return m_deps.certReader != nullptr && m_deps.trustVerifier != nullptr && m_deps.prompter != nullptr &&
           m_deps.serializer != nullptr && m_deps.credentials != nullptr;
}

bool CardObject::hasTokenInfoSeams() const noexcept
{
    // Token info uses the identity CardReader seam's readTokenInfo() (a
    // sibling of read()) + the shared prompt/credential plumbing; it does
    // NOT need the identity read cache (thin, no caching), mirroring
    // hasCertSeams()'s shape.
    return m_deps.reader != nullptr && m_deps.prompter != nullptr && m_deps.serializer != nullptr &&
           m_deps.credentials != nullptr;
}

bool CardObject::hasSignSeams() const noexcept
{
    // Sign uses the signer seam + the shared credential plumbing, plus the
    // agent-wide authorization gate, rate-limiter and config SSOT.
    return m_deps.signer != nullptr && m_deps.prompter != nullptr && m_deps.serializer != nullptr &&
           m_deps.credentials != nullptr && m_deps.authorizer != nullptr && m_deps.rateLimiter != nullptr &&
           m_deps.config != nullptr;
}

bool CardObject::hasCredentialSeams() const noexcept
{
    // The Credentials1 flows need the PIN-lifecycle seam + the shared prompt /
    // secret-cache plumbing + the per-card snapshot store. ManagePin /
    // ActivateSigningKey additionally consult the authorization gate + rate limiter
    // (required uniformly here so a mis-wired card fails closed rather than
    // spawning an un-gated mutation).
    return m_deps.credentialManager != nullptr && m_deps.prompter != nullptr && m_deps.serializer != nullptr &&
           m_deps.credentials != nullptr && m_deps.snapshotCache != nullptr && m_deps.readCache != nullptr &&
           m_deps.authorizer != nullptr && m_deps.rateLimiter != nullptr;
}

void CardObject::authorizeCredentialMutation(const std::string& sender) const
{
    // Authorize the CLIENT (default-allow; site policy may restrict) then apply the
    // per-caller rate-limit, both keyed on the caller's unique bus name and BEFORE
    // any prompt — the same authorize-then-allow ordering Card1.Sign uses, so a
    // rejected caller never reaches the consent dialog.
    if (!m_deps.authorizer->authorize(kActionCredentialsManage, CallerToken{sender})) {
        throw sdbus::Error{sdbus::Error::Name{LibreLinux::AgentWire::kErrNotAuthorized},
                           "Not authorized to manage credentials"};
    }
    if (!m_deps.rateLimiter->allow(CallerToken{sender})) {
        throw sdbus::Error{sdbus::Error::Name{LibreLinux::AgentWire::kErrRateLimited},
                           "Too many credential requests; try again shortly"};
    }
}

std::string CardObject::callerSender() const noexcept
{
    // sdbus-c++ 2.x exposes the in-flight method call via IObject::
    // getCurrentlyProcessedMessage(); the inherited getObject() accessor
    // (from ObjectHolder) gives us the IObject. Message::getSender() returns
    // const char*. Wrap in try-catch so a malformed message (e.g. signal
    // dispatch context confusion in a test) cannot crash the slot.
    try {
        const auto msg = getObject().getCurrentlyProcessedMessage();
        if (const char* sender = msg.getSender(); sender != nullptr) {
            return std::string{sender};
        }
    } catch (...) {
        // Fall through; empty sender => OperationManager skips registration
        // for this op (the NameOwnerChanged auto-cancel becomes a no-op).
    }
    return {};
}

std::string CardObject::callerRequesterLabel() const noexcept
{
    // Resolve the requesting client's human-meaningful label from the
    // kernel-validated PID of the in-flight method call. CallerIdentity pins
    // the process via pidfd before reading /proc to avoid PID-reuse, and
    // sanitises the result for safe display as client-supplied chrome. Any
    // failure yields an empty string and the prompt simply omits the
    // requester line — the operation is never blocked on identity resolution.
    try {
        const auto msg = getObject().getCurrentlyProcessedMessage();
        const pid_t pid = msg.getCredsPid();
        return CallerIdentity::resolveRequesterLabel(pid);
    } catch (...) {
        return {};
    }
}

sdbus::ObjectPath CardObject::ReadIdentity()
{
    if (!hasIdentityCapability()) {
        throw sdbus::Error{sdbus::Error::Name{kUnsupportedErrName}, "Card does not advertise IdentityData capability"};
    }
    if (!hasAllSeams()) {
        throw sdbus::Error{sdbus::Error::Name{kInternalErrName}, "Card operation dependencies not wired"};
    }
    // Resolve the caller's identity + capture the sender WHILE the in-flight
    // message is still current (both read the per-call message credentials).
    const std::string requester = callerRequesterLabel();
    const std::string sender = callerSender();
    Operations::ReadIdentityOperation::Deps deps{
        // holder is stamped by OperationManager from the per-reader worker.
        .reader = *m_deps.reader,
        .depositor = depositorOrNoOp(m_deps.depositor),
        .prompter = *m_deps.prompter,
        .serializer = *m_deps.serializer,
        .credentials = *m_deps.credentials,
        .readCache = *m_deps.readCache,
        .cardKey = m_deps.cardKey,
        .readerName = m_deps.readerName,
        .requester = requester,
        .artifact = kArtifactIdentity,
        .onCardType = m_deps.onCardTypeResolved,
    };
    // Pass the requesting client's unique-name (CallerToken) into publish so the
    // sender → ops table is wired BEFORE the op enters the worker queue; a
    // NameOwnerChanged that lands mid-publish still finds the id. publish hands
    // the closure the worker holder + the minted OperationId; the backend factory
    // builds the exported adaptor and the backend maps the id to the wire path.
    // The per-reader backlog cap surfaces as QueueFull → the RateLimited wire error.
    try {
        const auto id = m_manager.publish(
            objectIdFromPath(m_reader), m_deps.readerName, CallerToken{sender},
            [this, deps = std::move(deps)](Operations::CardSessionHolder* holder,
                                           OperationId opId) mutable -> std::unique_ptr<Operations::OperationBase> {
                deps.holder = holder;
                auto op = buildIdentityOperation(m_connection, opObjectPath(opId), std::move(deps));
                attachLifetimeGuards(*op);
                return op;
            });
        return opObjectPath(id);
    } catch (const Operations::QueueFull&) {
        throw sdbus::Error{sdbus::Error::Name{LibreLinux::AgentWire::kErrRateLimited},
                           "reader operation backlog full; retry shortly"};
    }
}

sdbus::ObjectPath CardObject::GetPhoto()
{
    if (!hasIdentityCapability()) {
        // Photo metadata lives in IdentityData; a card without the bit can
        // never carry a photo, so the gate fires here rather than deferring
        // a guaranteed-empty cache lookup into the Operation.
        throw sdbus::Error{sdbus::Error::Name{kUnsupportedErrName}, "Card does not advertise IdentityData capability"};
    }
    if (!hasAllSeams()) {
        throw sdbus::Error{sdbus::Error::Name{kInternalErrName}, "Card operation dependencies not wired"};
    }
    const std::string requester = callerRequesterLabel();
    const std::string sender = callerSender();
    Operations::GetPhotoOperation::Deps deps{
        // holder is stamped by OperationManager from the per-reader worker.
        .reader = *m_deps.reader,
        .depositor = depositorOrNoOp(m_deps.depositor),
        .prompter = *m_deps.prompter,
        .serializer = *m_deps.serializer,
        .credentials = *m_deps.credentials,
        .readCache = *m_deps.readCache,
        .cardKey = m_deps.cardKey,
        .readerName = m_deps.readerName,
        .requester = requester,
        .artifact = kArtifactPhoto,
        .onCardType = m_deps.onCardTypeResolved,
    };
    try {
        const auto id = m_manager.publish(
            objectIdFromPath(m_reader), m_deps.readerName, CallerToken{sender},
            [this, deps = std::move(deps)](Operations::CardSessionHolder* holder,
                                           OperationId opId) mutable -> std::unique_ptr<Operations::OperationBase> {
                deps.holder = holder;
                // GetPhoto prompts on a read-cache miss (it runs IdentityReadFlow),
                // so it is the same abandoned-worker class as its three siblings and
                // needs the same lifetime guards (co-own the crypto context + the
                // connection, bind the shutdown token).
                auto op = buildPhotoOperation(m_connection, opObjectPath(opId), std::move(deps));
                attachLifetimeGuards(*op);
                return op;
            });
        return opObjectPath(id);
    } catch (const Operations::QueueFull&) {
        throw sdbus::Error{sdbus::Error::Name{LibreLinux::AgentWire::kErrRateLimited},
                           "reader operation backlog full; retry shortly"};
    }
}

sdbus::ObjectPath CardObject::ReadCertificates()
{
    if (!hasPkiCapability()) {
        throw sdbus::Error{sdbus::Error::Name{kUnsupportedErrName}, "Card does not advertise PKI capability"};
    }
    if (!hasCertSeams()) {
        throw sdbus::Error{sdbus::Error::Name{kInternalErrName}, "Card operation dependencies not wired"};
    }
    const std::string requester = callerRequesterLabel();
    const std::string sender = callerSender();
    Operations::ReadCertificatesOperation::Deps deps{
        // holder is stamped by OperationManager from the per-reader worker.
        .certReader = *m_deps.certReader,  .trustVerifier = *m_deps.trustVerifier, .prompter = *m_deps.prompter,
        .serializer = *m_deps.serializer,  .credentials = *m_deps.credentials,     .readCache = *m_deps.readCache,
        .cardKey = m_deps.cardKey,         .readerName = m_deps.readerName,        .requester = requester,
        .artifact = kArtifactCertificates,
    };
    try {
        const auto id = m_manager.publish(
            objectIdFromPath(m_reader), m_deps.readerName, CallerToken{sender},
            [this, deps = std::move(deps)](Operations::CardSessionHolder* holder,
                                           OperationId opId) mutable -> std::unique_ptr<Operations::OperationBase> {
                deps.holder = holder;
                auto op = buildCertificatesOperation(m_connection, opObjectPath(opId), std::move(deps));
                attachLifetimeGuards(*op);
                return op;
            });
        return opObjectPath(id);
    } catch (const Operations::QueueFull&) {
        throw sdbus::Error{sdbus::Error::Name{LibreLinux::AgentWire::kErrRateLimited},
                           "reader operation backlog full; retry shortly"};
    }
}

sdbus::ObjectPath CardObject::ReadTokenInfo()
{
    if (!hasPkiCapability()) {
        throw sdbus::Error{sdbus::Error::Name{kUnsupportedErrName}, "Card does not advertise PKI capability"};
    }
    if (!hasTokenInfoSeams()) {
        throw sdbus::Error{sdbus::Error::Name{kInternalErrName}, "Card operation dependencies not wired"};
    }
    const std::string requester = callerRequesterLabel();
    const std::string sender = callerSender();
    Operations::ReadTokenInfoOperation::Deps deps{
        // holder is stamped by OperationManager from the per-reader worker.
        .reader = *m_deps.reader,         .prompter = *m_deps.prompter,
        .serializer = *m_deps.serializer, .credentials = *m_deps.credentials,
        .cardKey = m_deps.cardKey,        .readerName = m_deps.readerName,
        .requester = requester,           .artifact = kArtifactTokenInfo,
    };
    try {
        const auto id = m_manager.publish(
            objectIdFromPath(m_reader), m_deps.readerName, CallerToken{sender},
            [this, deps = std::move(deps)](Operations::CardSessionHolder* holder,
                                           OperationId opId) mutable -> std::unique_ptr<Operations::OperationBase> {
                deps.holder = holder;
                auto op = buildTokenInfoOperation(m_connection, opObjectPath(opId), std::move(deps));
                attachLifetimeGuards(*op);
                return op;
            });
        return opObjectPath(id);
    } catch (const Operations::QueueFull&) {
        throw sdbus::Error{sdbus::Error::Name{LibreLinux::AgentWire::kErrRateLimited},
                           "reader operation backlog full; retry shortly"};
    }
}

sdbus::ObjectPath CardObject::Sign(const std::string& certId, const sdbus::UnixFd& inputFd,
                                   const std::map<std::string, sdbus::Variant>& options)
{
    if (!hasPkiCapability()) {
        throw sdbus::Error{sdbus::Error::Name{kUnsupportedErrName}, "Card does not advertise PKI capability"};
    }
    if (!hasSignSeams()) {
        throw sdbus::Error{sdbus::Error::Name{kInternalErrName}, "Card operation dependencies not wired"};
    }
    if (certId.empty()) {
        throw sdbus::Error{sdbus::Error::Name{kBadParamErrName}, "certId is required (no auto-select)"};
    }

    // Authorize the CLIENT (default-allow; site policy may restrict) then apply
    // the sign-flood rate-limit, both keyed on the caller's unique bus name —
    // BEFORE ingesting the document, so a rejected caller never makes the agent
    // read (up to 256 MiB off) the input fd.
    const std::string sender = callerSender();
    if (!m_deps.authorizer->authorize(kActionSign, CallerToken{sender})) {
        throw sdbus::Error{sdbus::Error::Name{LibreLinux::AgentWire::kErrNotAuthorized}, "Not authorized to sign"};
    }
    if (!m_deps.rateLimiter->allow(CallerToken{sender})) {
        throw sdbus::Error{sdbus::Error::Name{LibreLinux::AgentWire::kErrRateLimited},
                           "Too many signing requests; try again shortly"};
    }

    // KNOWN LIMITATION (deferred): the whole document — up to kMaxInputBytes
    // (256 MiB) — is read SYNCHRONOUSLY here on the single-threaded bus event
    // loop, so a large *regular-file* input stalls all D-Bus dispatch (other
    // clients, this op's later Cancel, NameOwnerChanged) for the read duration.
    // The unbounded-stall DoS is already closed: readDocument fstat-rejects any
    // NON-regular fd (pipe/socket/char) up front, so the read is always bounded
    // by a finite, seekable source AND by the 256 MiB cap. Moving the bulk read
    // into the per-reader worker's doWork() is the SOTA fix but is intentionally
    // NOT done here: it would change the cap/empty checks from synchronous method
    // throws to asynchronous Operation-Finished errors (a wire-contract shift)
    // and would push an owned, cancellation-aware input fd through SignParams +
    // every SignFlow test harness (which today sets inputDocument bytes
    // directly). Format=auto only needs a small prefix; the eventual fix should
    // sniff a bounded prefix on the bus thread and hand the fd to the worker.
    auto doc = readDocument(inputFd.get(), kMaxInputBytes);
    if (doc.status == ReadStatus::NotRegular) {
        throw sdbus::Error{sdbus::Error::Name{kBadParamErrName},
                           "Input must be a regular file or memfd (no pipes/sockets)"};
    }
    if (doc.status == ReadStatus::TooLarge) {
        throw sdbus::Error{sdbus::Error::Name{kInputTooLargeErrName}, "Input document exceeds the 256 MiB limit"};
    }
    if (doc.status == ReadStatus::Error) {
        throw sdbus::Error{sdbus::Error::Name{kInternalErrName}, "Failed to read the input document"};
    }
    if (doc.bytes.empty()) {
        throw sdbus::Error{sdbus::Error::Name{kBadParamErrName}, "Input document is empty"};
    }

    // Resolve format (sniff on auto), level, packaging, allowExpired, reason,
    // location, tsaUrl and visualSignature to concrete/validated values —
    // out-of-vocabulary is a method-entry rejection. Shared verbatim with
    // Card1.SignBatch via resolveSignOptions() so the two entries can never
    // drift; an absent level/reason/location falls back to the agent's
    // Config1 SSOT.
    ResolvedSignOptions resolved = resolveSignOptions(options, doc.bytes, *m_deps.config);

    const std::string requester = callerRequesterLabel();
    log::infof("sign requested: requester={} certId={} format={} level={} packaging={} bytes={}", requester,
               certId.substr(0, 12), resolved.format, resolved.level, resolved.packaging, doc.bytes.size());
    Operations::SignParams params{
        .certId = certId,
        .inputDocument = std::move(doc.bytes),
        .format = std::move(resolved.format),
        .level = std::move(resolved.level),
        .packaging = std::move(resolved.packaging),
        .allowExpired = resolved.allowExpired,
        // displayName surfaces in the consent prompt as CLIENT-SUPPLIED chrome:
        // sanitize it (collapse control bytes, cap length) so a hostile name
        // cannot forge prompt lines or inject terminal escapes (LR4). reason/
        // location are PDF signature-dictionary metadata (not prompt chrome).
        .displayName = sanitizeLabel(optString(options, "displayName", {})),
        .reason = std::move(resolved.reason),
        .location = std::move(resolved.location),
        .tsaUrl = std::move(resolved.tsaUrl),
        .visual = std::move(resolved.visual),
    };
    Operations::SignOperation::Deps deps{
        // holder is stamped by OperationManager from the per-reader worker.
        .signer = *m_deps.signer,         .prompter = *m_deps.prompter,
        .serializer = *m_deps.serializer, .credentials = *m_deps.credentials,
        .cardKey = m_deps.cardKey,        .readerName = m_deps.readerName,
        .requester = requester,           .params = std::move(params),
    };
    try {
        const auto id = m_manager.publish(
            objectIdFromPath(m_reader), m_deps.readerName, CallerToken{sender},
            [this, deps = std::move(deps)](Operations::CardSessionHolder* holder,
                                           OperationId opId) mutable -> std::unique_ptr<Operations::OperationBase> {
                deps.holder = holder;
                auto op = buildSignOperation(m_connection, opObjectPath(opId), std::move(deps));
                attachLifetimeGuards(*op);
                return op;
            });
        return opObjectPath(id);
    } catch (const Operations::QueueFull&) {
        throw sdbus::Error{sdbus::Error::Name{LibreLinux::AgentWire::kErrRateLimited},
                           "reader operation backlog full; retry shortly"};
    }
}

sdbus::ObjectPath CardObject::SignBatch(const std::vector<sdbus::Struct<std::string, sdbus::UnixFd>>& documents,
                                        const std::string& certId, const std::map<std::string, sdbus::Variant>& options)
{
    if (!hasPkiCapability()) {
        throw sdbus::Error{sdbus::Error::Name{kUnsupportedErrName}, "Card does not advertise PKI capability"};
    }
    // SAME seam set as a single Sign (signer + shared prompt/credential
    // plumbing + authorizer/rateLimiter/config) — SignBatch needs nothing
    // beyond it.
    if (!hasSignSeams()) {
        throw sdbus::Error{sdbus::Error::Name{kInternalErrName}, "Card operation dependencies not wired"};
    }
    if (certId.empty()) {
        throw sdbus::Error{sdbus::Error::Name{kBadParamErrName}, "certId is required (no auto-select)"};
    }

    // Authorize the CLIENT then apply the SAME sign-flood rate-limit as a
    // single Sign, keyed on the caller's unique bus name — BEFORE reading any
    // document, mirroring Sign's own ordering exactly. MANDATORY invariant:
    // this ONE allow() call is the ONLY rate-limiter charge for the whole
    // dispatch — the batch loops over `documents` entirely below and inside
    // the flow, never re-entering this method or calling allow() again, so
    // one SignBatch call (of any size 1-12) always costs exactly one charge,
    // exactly like one Sign call costs one charge regardless of document size.
    const std::string sender = callerSender();
    if (!m_deps.authorizer->authorize(kActionSign, CallerToken{sender})) {
        throw sdbus::Error{sdbus::Error::Name{LibreLinux::AgentWire::kErrNotAuthorized}, "Not authorized to sign"};
    }
    if (!m_deps.rateLimiter->allow(CallerToken{sender})) {
        throw sdbus::Error{sdbus::Error::Name{LibreLinux::AgentWire::kErrRateLimited},
                           "Too many signing requests; try again shortly"};
    }

    if (!Operations::isValidBatchDocumentCount(documents.size())) {
        throw sdbus::Error{sdbus::Error::Name{kInvalidRequestErrName},
                           "Batch document count must be between " + std::to_string(Operations::kMinBatchDocuments) +
                               " and " + std::to_string(Operations::kMaxBatchDocuments)};
    }

    // Read every document off its own fd, in request order — the SAME 256 MiB
    // cap + regular-file-only + non-empty rule Sign's own readDocument enforces
    // for its single document, applied per document here. A single bad
    // document rejects the WHOLE call (no Operation minted): method entry has
    // no per-row partial semantics, only the flow does (auth/crypto failures).
    std::vector<Operations::BatchDocumentInput> inputs;
    inputs.reserve(documents.size());
    for (const auto& entry : documents) {
        const std::string& displayName = std::get<0>(entry);
        const sdbus::UnixFd& fd = std::get<1>(entry);
        auto doc = readDocument(fd.get(), kMaxInputBytes);
        if (doc.status == ReadStatus::NotRegular) {
            throw sdbus::Error{sdbus::Error::Name{kBadParamErrName},
                               "Every batch document must be a regular file or memfd (no pipes/sockets)"};
        }
        if (doc.status == ReadStatus::TooLarge) {
            throw sdbus::Error{sdbus::Error::Name{kInputTooLargeErrName}, "A batch document exceeds the 256 MiB limit"};
        }
        if (doc.status == ReadStatus::Error) {
            throw sdbus::Error{sdbus::Error::Name{kInternalErrName}, "Failed to read a batch input document"};
        }
        if (doc.bytes.empty()) {
            throw sdbus::Error{sdbus::Error::Name{kBadParamErrName}, "A batch document is empty"};
        }
        inputs.push_back(Operations::BatchDocumentInput{
            .displayName = sanitizeLabel(displayName),
            .bytes = std::move(doc.bytes),
        });
    }

    // Options: IDENTICAL vocabulary to Sign's own, resolved via the SAME
    // helper. format=auto sniffs off the FIRST document only — the whole
    // batch shares one resolved format/level/packaging, not a per-document
    // resolution. A "displayName" key (if sent) is simply never read here:
    // each entry in `documents` already supplied its own name above.
    ResolvedSignOptions resolved = resolveSignOptions(options, inputs.front().bytes, *m_deps.config);

    const std::string requester = callerRequesterLabel();
    log::infof("sign-batch requested: requester={} certId={} documents={} format={} level={} packaging={} artifact={}",
               requester, certId.substr(0, 12), inputs.size(), resolved.format, resolved.level, resolved.packaging,
               kArtifactSignatureBatch);

    Operations::SignParams params{
        .certId = certId,
        // Ignored by BatchSignFlow — each entry in `documents` above
        // supplies its own bytes/name — left explicitly default.
        .inputDocument = {},
        .format = std::move(resolved.format),
        .level = std::move(resolved.level),
        .packaging = std::move(resolved.packaging),
        .allowExpired = resolved.allowExpired,
        .displayName = {},
        .reason = std::move(resolved.reason),
        .location = std::move(resolved.location),
        .tsaUrl = std::move(resolved.tsaUrl),
        .visual = std::move(resolved.visual),
    };
    Operations::SignBatchOperation::Deps deps{
        // holder is stamped by OperationManager from the per-reader worker.
        .signer = *m_deps.signer,         .prompter = *m_deps.prompter,
        .serializer = *m_deps.serializer, .credentials = *m_deps.credentials,
        .cardKey = m_deps.cardKey,        .readerName = m_deps.readerName,
        .requester = requester,           .params = std::move(params),
        .documents = std::move(inputs),
    };
    try {
        const auto id = m_manager.publish(
            objectIdFromPath(m_reader), m_deps.readerName, CallerToken{sender},
            [this, deps = std::move(deps)](Operations::CardSessionHolder* holder,
                                           OperationId opId) mutable -> std::unique_ptr<Operations::OperationBase> {
                deps.holder = holder;
                auto op = buildSignBatchOperation(m_connection, opObjectPath(opId), std::move(deps));
                attachLifetimeGuards(*op);
                return op;
            });
        return opObjectPath(id);
    } catch (const Operations::QueueFull&) {
        throw sdbus::Error{sdbus::Error::Name{LibreLinux::AgentWire::kErrRateLimited},
                           "reader operation backlog full; retry shortly"};
    }
}

namespace {

// Map a validatePinManageRequest EntryError onto its typed wire error. UnknownVerb
// / UnknownOption / InvalidCombination are the client's fault (InvalidRequest);
// UnknownCredential (bad or unlisted pinId, incl. the never-listed case) is its own
// name so a client can distinguish "re-list and retry" from "fix your request".
[[noreturn]] void throwEntryError(EntryError err)
{
    switch (err) {
    case EntryError::UnknownCredential:
        throw sdbus::Error{sdbus::Error::Name{kUnknownCredentialErrName},
                           "pinId does not match any credential from the latest ListCredentials"};
    case EntryError::AmbiguousCredential:
        // Distinct ids sharing one label: the seam addresses the card by label,
        // so the plugin would have to guess which PIN the user meant.
        throw sdbus::Error{sdbus::Error::Name{kInvalidRequestErrName},
                           "pinId addresses a credential label that is not unique on this card"};
    case EntryError::UnknownVerb:
    case EntryError::UnknownOption:
    case EntryError::InvalidCombination:
        break;
    }
    throw sdbus::Error{sdbus::Error::Name{kInvalidRequestErrName}, "malformed credential-management request"};
}

} // namespace

sdbus::ObjectPath CardObject::ManagePin(const std::string& pinId, const std::string& verb,
                                        const std::map<std::string, sdbus::Variant>& options)
{
    // Entry gating: a management request against a card that does not advertise
    // PinManagement (bit 3) is refused at entry with no Operation minted, mirroring
    // the Identity/PKI gates.
    if (!hasPinManagementCapability()) {
        throw sdbus::Error{sdbus::Error::Name{kUnsupportedErrName}, "Card does not advertise PinManagement capability"};
    }
    if (!hasCredentialSeams()) {
        throw sdbus::Error{sdbus::Error::Name{kInternalErrName}, "Credential operation dependencies not wired"};
    }

    // Authorize + rate-limit FIRST (same posture + ordering as Sign): a rejected
    // caller never has request validation — including its snapshot-cache get()
    // side effect — run on its behalf, and never reaches a prompt.
    const std::string sender = callerSender();
    authorizeCredentialMutation(sender);

    // Undefined options key -> typed error at entry (the adaptor-layer half of the
    // entry-gating rule set; validatePinManageRequest owns verb/combination/pinId).
    for (const auto& [key, value] : options) {
        static_cast<void>(value);
        if (key != kOptionActivateKey) {
            throw sdbus::Error{sdbus::Error::Name{kInvalidRequestErrName}, "undefined ManagePin options key"};
        }
    }

    // A DEFINED key with the wrong variant type is an entry error too: silently
    // coercing a mistyped activateKey to false would run a different mutation
    // than the client asked for (the closed-options rule covers types, not just
    // key names).
    bool activateKey = false;
    if (const auto it = options.find(kOptionActivateKey); it != options.end()) {
        try {
            activateKey = it->second.get<bool>();
        } catch (const sdbus::Error&) {
            throw sdbus::Error{sdbus::Error::Name{kInvalidRequestErrName}, "activateKey must be a boolean"};
        }
    }

    Operations::PinManageRequest request{
        .cardKey = m_deps.cardKey,
        .pinId = pinId,
        .verb = verb,
        .activateKey = activateKey,
    };
    // Resolve the addressed record against the LATEST listing captured at entry. A
    // client that never listed (no snapshot) or names an unknown id is rejected here
    // rather than triggering an implicit list — an implicit list could prompt for
    // the CAN inside a call the user never framed as a read.
    std::optional<CredentialSnapshot> snapshot = m_deps.snapshotCache->get(m_deps.cardKey);
    if (const auto valid = Operations::validatePinManageRequest(request, snapshot ? &*snapshot : nullptr); !valid) {
        throwEntryError(valid.error());
    }

    const std::string requester = callerRequesterLabel();
    log::infof("credential change requested: requester={} verb={} pinId={}", requester, verb, pinId);
    Operations::ManagePinOperation::Deps deps{
        .credentials = *m_deps.credentialManager,
        .prompter = *m_deps.prompter,
        .serializer = *m_deps.serializer,
        .credCache = *m_deps.credentials,
        .snapshotCache = *m_deps.snapshotCache,
        .readCache = *m_deps.readCache,
        .cardKey = m_deps.cardKey,
        .readerName = m_deps.readerName,
        .requester = requester,
        .artifact = kArtifactCredentials,
        .request = std::move(request),
        .snapshot = std::move(*snapshot),
    };
    try {
        const auto id = m_manager.publish(
            objectIdFromPath(m_reader), m_deps.readerName, CallerToken{sender},
            [this, deps = std::move(deps)](Operations::CardSessionHolder* holder,
                                           OperationId opId) mutable -> std::unique_ptr<Operations::OperationBase> {
                deps.holder = holder;
                auto op = buildManagePinOperation(m_connection, opObjectPath(opId), std::move(deps));
                attachLifetimeGuards(*op);
                return op;
            });
        return opObjectPath(id);
    } catch (const Operations::QueueFull&) {
        throw sdbus::Error{sdbus::Error::Name{LibreLinux::AgentWire::kErrRateLimited},
                           "reader operation backlog full; retry shortly"};
    }
}

sdbus::ObjectPath CardObject::ActivateSigningKey()
{
    if (!hasPinManagementCapability()) {
        throw sdbus::Error{sdbus::Error::Name{kUnsupportedErrName}, "Card does not advertise PinManagement capability"};
    }
    if (!hasCredentialSeams()) {
        throw sdbus::Error{sdbus::Error::Name{kInternalErrName}, "Credential operation dependencies not wired"};
    }
    // Authorize + rate-limit (BEFORE any prompt). No client-supplied arguments to
    // validate — the addressed signing-key record is resolved inside the operation
    // from the latest listing (a card that exposes none answers unsupported).
    const std::string sender = callerSender();
    authorizeCredentialMutation(sender);

    const std::string requester = callerRequesterLabel();
    Operations::ActivateSigningKeyOperation::Deps deps{
        .credentials = *m_deps.credentialManager,
        .prompter = *m_deps.prompter,
        .serializer = *m_deps.serializer,
        .credCache = *m_deps.credentials,
        .snapshotCache = *m_deps.snapshotCache,
        .readCache = *m_deps.readCache,
        .cardKey = m_deps.cardKey,
        .readerName = m_deps.readerName,
        .requester = requester,
        .artifact = kArtifactCredentials,
    };
    try {
        const auto id = m_manager.publish(
            objectIdFromPath(m_reader), m_deps.readerName, CallerToken{sender},
            [this, deps = std::move(deps)](Operations::CardSessionHolder* holder,
                                           OperationId opId) mutable -> std::unique_ptr<Operations::OperationBase> {
                deps.holder = holder;
                auto op = buildActivateSigningKeyOperation(m_connection, opObjectPath(opId), std::move(deps));
                attachLifetimeGuards(*op);
                return op;
            });
        return opObjectPath(id);
    } catch (const Operations::QueueFull&) {
        throw sdbus::Error{sdbus::Error::Name{LibreLinux::AgentWire::kErrRateLimited},
                           "reader operation backlog full; retry shortly"};
    }
}

sdbus::ObjectPath CardObject::ListCredentials()
{
    // A read of the card's PIN credentials. Gates on PinManagement (no listing is
    // meaningful without it) but is NOT rate-limited — no card-state mutation.
    if (!hasPinManagementCapability()) {
        throw sdbus::Error{sdbus::Error::Name{kUnsupportedErrName}, "Card does not advertise PinManagement capability"};
    }
    if (!hasCredentialSeams()) {
        throw sdbus::Error{sdbus::Error::Name{kInternalErrName}, "Credential operation dependencies not wired"};
    }
    const std::string requester = callerRequesterLabel();
    const std::string sender = callerSender();
    Operations::ListCredentialsOperation::Deps deps{
        .credentials = *m_deps.credentialManager,
        .prompter = *m_deps.prompter,
        .serializer = *m_deps.serializer,
        .credCache = *m_deps.credentials,
        .snapshotCache = *m_deps.snapshotCache,
        .cardKey = m_deps.cardKey,
        .readerName = m_deps.readerName,
        .requester = requester,
        .artifact = kArtifactCredentials,
    };
    try {
        const auto id = m_manager.publish(
            objectIdFromPath(m_reader), m_deps.readerName, CallerToken{sender},
            [this, deps = std::move(deps)](Operations::CardSessionHolder* holder,
                                           OperationId opId) mutable -> std::unique_ptr<Operations::OperationBase> {
                deps.holder = holder;
                auto op = buildListCredentialsOperation(m_connection, opObjectPath(opId), std::move(deps));
                attachLifetimeGuards(*op);
                return op;
            });
        return opObjectPath(id);
    } catch (const Operations::QueueFull&) {
        throw sdbus::Error{sdbus::Error::Name{LibreLinux::AgentWire::kErrRateLimited},
                           "reader operation backlog full; retry shortly"};
    }
}

} // namespace LibreSCRS::Agent
