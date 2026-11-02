// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#include "dbus/CardObject.h"
#include "dbus/AuthorizedReply.h"
#include "dbus/SyncErrorBusName.h"
#include "AgentErrorNames.h" // shared wire error-name table (hoisted UnsupportedOnThisCard + credential errors)
#include "AgentObjectPath.h" // objectIdFromPath (reader path -> ObjectId)
#include <LibreSCRS/Agent/AgentCore.h>
#include <LibreSCRS/Agent/backend/Authorizer.h>
#include <LibreSCRS/Logging.h>
#include "CallerIdentity.h"
#include <LibreSCRS/Agent/cache/CredentialSnapshotCache.h>
#include <LibreSCRS/Agent/config/ConfigStore.h>
#include "dbus/ObjectManagerSignals.h" // emitObjectManagerAdded/Removed
#include "dbus/OperationPath.h"
#include <LibreSCRS/Agent/operations/OperationArtifact.h>
#include <LibreSCRS/Agent/operations/OperationLauncher.h>
#include <LibreSCRS/Agent/operations/PinChangeFlow.h> // PinManageRequest, validatePinManageRequest
#include <LibreSCRS/Agent/operations/RateLimiter.h>
#include <LibreSCRS/Agent/operations/BatchSignFlow.h> // isValidBatchDocumentCount, BatchDocumentInput
#include <LibreSCRS/Agent/operations/SignatureParams.h>
#include <LibreSCRS/Agent/util/CallerLabel.h>        // sanitizeLabel (neutral core)
#include <LibreSCRS/Agent/value/CredentialRecord.h>  // CredentialSnapshot, EntryError
#include <LibreSCRS/Agent/value/SyncErrorTaxonomy.h> // toSyncError
#include <LibreSCRS/Agent/wire/BoundedFdRead.h>      // readBoundedRegularFd, kMaxInputBytes
#include <LibreSCRS/Plugin/PluginTypes.h>
#include <sdbus-c++/Error.h>
#include <sdbus-c++/IObject.h>
#include <sdbus-c++/Message.h>
#include <sys/types.h> // pid_t
#include <cstdint>
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
constexpr const char* kInternalErrName = "org.librescrs.Agent.Error.Internal";
constexpr const char* kBadParamErrName = "org.librescrs.Agent.Error.UnsupportedSignatureParameter";
constexpr const char* kInputTooLargeErrName = "org.librescrs.Agent.Error.InputTooLarge";
// RateLimited / NotAuthorized are part of the shared credential contract, so
// they are sourced directly from common/AgentErrorNames.h at each call site
// (no hand-spelled local copy to drift from the producer/consumer spelling).

// The closed options-key set for Credentials1.ManagePin (all non-secret). Any
// other key at method entry is an undefined-option InvalidRequest.
constexpr const char* kOptionActivateKey = "activateKey";

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

    // The deferral sentinel is spelled once, in the agent's shared helpers, so
    // this frontend and the socket one cannot drift apart on it.
    std::string format;
    if (const auto requested = sp::requestedFormatFrom(optString(options, "format", ""))) {
        format = *requested;
    } else {
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
    // a request that DEFERS -- an absent key, or the sentinel the other two
    // option vocabularies accept the same way -- takes the configured default,
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

    const std::string packaging =
        sp::requestedPackagingFrom(optString(options, "packaging", "")).value_or(sp::defaultPackagingFor(format));
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
                       sdbus::ObjectPath reader, AgentCore& core, Operations::OperationLauncher& launcher,
                       CardOperationDeps deps)
    : AdaptorInterfaces(connection, path), m_connection(connection), m_capabilities(capabilities),
      m_reader(std::move(reader)), m_core(core), m_launcher(launcher), m_deps(std::move(deps)),
      m_selfPath(std::move(path)), m_cardType(m_deps.cardType)
{
    registerAdaptor();
    // Announce over the ObjectManager so a client tracking the live tree resolves
    // the card immediately (sdbus-c++ does not auto-emit InterfacesAdded). Without
    // this, the owning reader reports HasCard=true but the client never learns how
    // to reach the Card1 object until it re-runs GetManagedObjects by hand.
    emitObjectManagerAdded(getObject(), "card");
}

CardObject::~CardObject()
{
    // A grant running on the thread an authorization answered on finishes
    // before anything here is torn down; one arriving later runs nothing.
    m_grantGate->close();
    // Withdraw BEFORE unregistering, while the interface list is still enumerable,
    // so live-tracking clients drop the card (and terminalise its operations).
    emitObjectManagerRemoved(getObject(), "card");
    unregisterAdaptor();
}

template <class Args>
sdbus::ObjectPath CardObject::launch(ChannelMaker makeChannel, Args args, const std::string& sender,
                                     const std::string& requester)
{
    // The sender is registered for disconnect-cancel before the operation enters
    // the reader's queue, so a NameOwnerChanged that lands mid-launch still finds
    // it; an empty sender skips the registration.
    const Operations::OperationTarget target{
        .card = ReaderCard{.readerId = objectIdFromPath(m_reader),
                           .readerName = m_deps.readerName,
                           .cardKey = m_deps.cardKey},
        .caller = CallerToken{sender},
        .requester = requester,
    };
    // Operation1.Cancel from the launching client ends the operation the way a
    // dropped connection does: OperationManager::cancel trips its token and
    // dismisses a prompt it is waiting on.
    const auto launched = m_launcher.launch(
        target,
        [this, makeChannel, &sender](OperationId id, const std::shared_ptr<Operations::OperationState>& state) {
            Operations::CancelRoute cancel{
                .owner = sender,
                .run = [&operations = m_core.operationManager(), id] { operations.cancel(id); },
            };
            return makeChannel(m_connection, opObjectPath(id), state, std::move(cancel));
        },
        std::move(args));
    if (!launched) {
        throw sdbus::Error{sdbus::Error::Name{syncErrorBusName(launched.error())},
                           "reader operation backlog full; retry shortly"};
    }
    return opObjectPath(*launched);
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

void CardObject::rateLimitCredentialMutation(const std::string& sender) const
{
    // Applied after the client was authorised and BEFORE any prompt, keyed on
    // the caller's unique bus name -- the same authorize-then-allow ordering
    // Card1.Sign uses, so a rejected caller never reaches the consent dialog.
    if (!m_core.rateLimiter().allow(CallerToken{sender})) {
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
    // Resolve the caller's identity + capture the sender WHILE the in-flight
    // message is still current (both read the per-call message credentials).
    const std::string requester = callerRequesterLabel();
    const std::string sender = callerSender();
    return launch(makeIdentityChannel,
                  Operations::OperationLauncher::ReadIdentity{.onCardType = m_deps.onCardTypeResolved}, sender,
                  requester);
}

sdbus::ObjectPath CardObject::GetPhoto()
{
    if (!hasIdentityCapability()) {
        // Photo metadata lives in IdentityData; a card without the bit can
        // never carry a photo, so the gate fires here rather than deferring
        // a guaranteed-empty cache lookup into the Operation.
        throw sdbus::Error{sdbus::Error::Name{kUnsupportedErrName}, "Card does not advertise IdentityData capability"};
    }
    const std::string requester = callerRequesterLabel();
    const std::string sender = callerSender();
    return launch(makePhotoChannel, Operations::OperationLauncher::GetPhoto{.onCardType = m_deps.onCardTypeResolved},
                  sender, requester);
}

sdbus::ObjectPath CardObject::ReadCertificates()
{
    if (!hasPkiCapability()) {
        throw sdbus::Error{sdbus::Error::Name{kUnsupportedErrName}, "Card does not advertise PKI capability"};
    }
    const std::string requester = callerRequesterLabel();
    const std::string sender = callerSender();
    return launch(makeCertificatesChannel, Operations::OperationLauncher::ReadCertificates{}, sender, requester);
}

sdbus::ObjectPath CardObject::ReadTokenInfo()
{
    if (!hasPkiCapability()) {
        throw sdbus::Error{sdbus::Error::Name{kUnsupportedErrName}, "Card does not advertise PKI capability"};
    }
    const std::string requester = callerRequesterLabel();
    const std::string sender = callerSender();
    // Token info mints no result interface of its own: its snapshot rides
    // Identity1.Result like ReadIdentity's.
    return launch(makeIdentityChannel, Operations::OperationLauncher::ReadTokenInfo{}, sender, requester);
}

void CardObject::Sign(sdbus::Result<sdbus::ObjectPath>&& result, std::string certId, sdbus::UnixFd inputFd,
                      std::map<std::string, sdbus::Variant> options)
{
    if (!hasPkiCapability()) {
        result.returnError(
            sdbus::Error{sdbus::Error::Name{kUnsupportedErrName}, "Card does not advertise PKI capability"});
        return;
    }
    if (certId.empty()) {
        result.returnError(sdbus::Error{sdbus::Error::Name{kBadParamErrName}, "certId is required (no auto-select)"});
        return;
    }

    // Authorize the CLIENT (default-allow; site policy may restrict) then apply
    // the sign-flood rate-limit, both keyed on the caller's unique bus name —
    // BEFORE ingesting the document, so a rejected caller never makes the agent
    // read (up to 256 MiB off) the input fd.
    const std::string sender = callerSender();
    const std::string requester = callerRequesterLabel();
    authorizeThenReply(m_core.authorizer(), kActionSign, sender, std::move(result), "Not authorized to sign",
                       m_grantGate, [this, certId, inputFd, options, sender, requester] {
                           return signGranted(certId, inputFd, options, sender, requester);
                       });
}

sdbus::ObjectPath CardObject::signGranted(const std::string& certId, const sdbus::UnixFd& inputFd,
                                          const std::map<std::string, sdbus::Variant>& options,
                                          const std::string& sender, const std::string& requester)
{
    if (!m_core.rateLimiter().allow(CallerToken{sender})) {
        throw sdbus::Error{sdbus::Error::Name{LibreLinux::AgentWire::kErrRateLimited},
                           "Too many signing requests; try again shortly"};
    }

    // KNOWN LIMITATION (deferred): the whole document — up to Wire::kMaxInputBytes
    // (256 MiB) — is read SYNCHRONOUSLY here on the single-threaded bus event
    // loop, so a large *regular-file* input stalls all D-Bus dispatch (other
    // clients, this op's later Cancel, NameOwnerChanged) for the read duration.
    // The unbounded-stall DoS is already closed: readBoundedRegularFd fstat-rejects any
    // NON-regular fd (pipe/socket/char) up front, so the read is always bounded
    // by a finite, seekable source AND by the 256 MiB cap. Moving the bulk read
    // into the per-reader worker's doWork() is the SOTA fix but is intentionally
    // NOT done here: it would change the cap/empty checks from synchronous method
    // throws to asynchronous Operation-Finished errors (a wire-contract shift)
    // and would push an owned, cancellation-aware input fd through SignParams +
    // every SignFlow test harness (which today sets inputDocument bytes
    // directly). Format=auto only needs a small prefix; the eventual fix should
    // sniff a bounded prefix on the bus thread and hand the fd to the worker.
    auto doc = Wire::readBoundedRegularFd(inputFd.get(), Wire::kMaxInputBytes);
    if (doc.status == Wire::ReadStatus::NotRegular) {
        throw sdbus::Error{sdbus::Error::Name{kBadParamErrName},
                           "Input must be a regular file or memfd (no pipes/sockets)"};
    }
    if (doc.status == Wire::ReadStatus::TooLarge) {
        throw sdbus::Error{sdbus::Error::Name{kInputTooLargeErrName}, "Input document exceeds the 256 MiB limit"};
    }
    if (doc.status == Wire::ReadStatus::Error) {
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
    ResolvedSignOptions resolved = resolveSignOptions(options, doc.bytes, m_core.configStore());

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
    return launch(makeSignChannel, Operations::OperationLauncher::Sign{.params = std::move(params)}, sender, requester);
}

void CardObject::SignBatch(sdbus::Result<sdbus::ObjectPath>&& result,
                           std::vector<sdbus::Struct<std::string, sdbus::UnixFd>> documents, std::string certId,
                           std::map<std::string, sdbus::Variant> options)
{
    if (!hasPkiCapability()) {
        result.returnError(
            sdbus::Error{sdbus::Error::Name{kUnsupportedErrName}, "Card does not advertise PKI capability"});
        return;
    }
    if (certId.empty()) {
        result.returnError(sdbus::Error{sdbus::Error::Name{kBadParamErrName}, "certId is required (no auto-select)"});
        return;
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
    const std::string requester = callerRequesterLabel();
    authorizeThenReply(m_core.authorizer(), kActionSign, sender, std::move(result), "Not authorized to sign",
                       m_grantGate, [this, documents, certId, options, sender, requester] {
                           return signBatchGranted(documents, certId, options, sender, requester);
                       });
}

sdbus::ObjectPath CardObject::signBatchGranted(const std::vector<sdbus::Struct<std::string, sdbus::UnixFd>>& documents,
                                               const std::string& certId,
                                               const std::map<std::string, sdbus::Variant>& options,
                                               const std::string& sender, const std::string& requester)
{
    if (!m_core.rateLimiter().allow(CallerToken{sender})) {
        throw sdbus::Error{sdbus::Error::Name{LibreLinux::AgentWire::kErrRateLimited},
                           "Too many signing requests; try again shortly"};
    }

    if (!Operations::isValidBatchDocumentCount(documents.size())) {
        throw sdbus::Error{sdbus::Error::Name{kInvalidRequestErrName},
                           "Batch document count must be between " + std::to_string(Operations::kMinBatchDocuments) +
                               " and " + std::to_string(Operations::kMaxBatchDocuments)};
    }

    // Read every document off its own fd, in request order — the SAME 256 MiB
    // cap + regular-file-only + non-empty rule Sign's own read enforces
    // for its single document, applied per document here. A single bad
    // document rejects the WHOLE call (no Operation minted): method entry has
    // no per-row partial semantics, only the flow does (auth/crypto failures).
    std::vector<Operations::BatchDocumentInput> inputs;
    inputs.reserve(documents.size());
    for (const auto& entry : documents) {
        const std::string& displayName = std::get<0>(entry);
        const sdbus::UnixFd& fd = std::get<1>(entry);
        auto doc = Wire::readBoundedRegularFd(fd.get(), Wire::kMaxInputBytes);
        if (doc.status == Wire::ReadStatus::NotRegular) {
            throw sdbus::Error{sdbus::Error::Name{kBadParamErrName},
                               "Every batch document must be a regular file or memfd (no pipes/sockets)"};
        }
        if (doc.status == Wire::ReadStatus::TooLarge) {
            throw sdbus::Error{sdbus::Error::Name{kInputTooLargeErrName}, "A batch document exceeds the 256 MiB limit"};
        }
        if (doc.status == Wire::ReadStatus::Error) {
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
    ResolvedSignOptions resolved = resolveSignOptions(options, inputs.front().bytes, m_core.configStore());

    log::infof("sign-batch requested: requester={} certId={} documents={} format={} level={} packaging={} artifact={}",
               requester, certId.substr(0, 12), inputs.size(), resolved.format, resolved.level, resolved.packaging,
               Operations::Artifact::kSignatureBatch);

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
    return launch(makeSignBatchChannel,
                  Operations::OperationLauncher::SignBatch{.params = std::move(params), .documents = std::move(inputs)},
                  sender, requester);
}

namespace {

// A validatePinManageRequest EntryError as a typed wire error. The NAME is the
// agent library's mapping (toSyncError: UnknownCredential is its own, so a
// client can tell "re-list and retry" from "fix your request"; everything else
// is InvalidRequest); the message says which of them it was.
const char* entryErrorMessage(EntryError err) noexcept
{
    switch (err) {
    case EntryError::UnknownCredential:
        return "pinId does not match any credential from the latest ListCredentials";
    case EntryError::AmbiguousCredential:
        // Distinct ids sharing one label: the seam addresses the card by label,
        // so the plugin would have to guess which PIN the user meant.
        return "pinId addresses a credential label that is not unique on this card";
    case EntryError::UnknownVerb:
    case EntryError::UnknownOption:
    case EntryError::InvalidCombination:
        break;
    }
    return "malformed credential-management request";
}

[[noreturn]] void throwEntryError(EntryError err)
{
    throw sdbus::Error{sdbus::Error::Name{syncErrorBusName(toSyncError(err))}, entryErrorMessage(err)};
}

} // namespace

void CardObject::ManagePin(sdbus::Result<sdbus::ObjectPath>&& result, std::string pinId, std::string verb,
                           std::map<std::string, sdbus::Variant> options)
{
    // Entry gating: a management request against a card that does not advertise
    // PinManagement (bit 3) is refused at entry with no Operation minted, mirroring
    // the Identity/PKI gates.
    if (!hasPinManagementCapability()) {
        result.returnError(
            sdbus::Error{sdbus::Error::Name{kUnsupportedErrName}, "Card does not advertise PinManagement capability"});
        return;
    }

    // Authorize + rate-limit FIRST (same posture + ordering as Sign): a rejected
    // caller never has request validation — including its snapshot-cache get()
    // side effect — run on its behalf, and never reaches a prompt.
    const std::string sender = callerSender();
    const std::string requester = callerRequesterLabel();
    authorizeThenReply(m_core.authorizer(), kActionCredentialsManage, sender, std::move(result),
                       "Not authorized to manage credentials", m_grantGate,
                       [this, pinId, verb, options, sender, requester] {
                           return managePinGranted(pinId, verb, options, sender, requester);
                       });
}

sdbus::ObjectPath CardObject::managePinGranted(const std::string& pinId, const std::string& verb,
                                               const std::map<std::string, sdbus::Variant>& options,
                                               const std::string& sender, const std::string& requester)
{
    rateLimitCredentialMutation(sender);

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
    std::optional<CredentialSnapshot> snapshot = m_core.credentialSnapshotCache().get(m_deps.cardKey);
    if (const auto valid = Operations::validatePinManageRequest(request, snapshot ? &*snapshot : nullptr); !valid) {
        throwEntryError(valid.error());
    }

    log::infof("credential change requested: requester={} verb={} pinId={}", requester, verb, pinId);
    return launch(
        makeCredentialsChannel,
        Operations::OperationLauncher::ManagePin{.request = std::move(request), .snapshot = std::move(*snapshot)},
        sender, requester);
}

void CardObject::ActivateSigningKey(sdbus::Result<sdbus::ObjectPath>&& result)
{
    if (!hasPinManagementCapability()) {
        result.returnError(
            sdbus::Error{sdbus::Error::Name{kUnsupportedErrName}, "Card does not advertise PinManagement capability"});
        return;
    }
    // Authorize + rate-limit (BEFORE any prompt). No client-supplied arguments to
    // validate — the addressed signing-key record is resolved inside the operation
    // from the latest listing (a card that exposes none answers unsupported).
    const std::string sender = callerSender();
    const std::string requester = callerRequesterLabel();
    authorizeThenReply(m_core.authorizer(), kActionCredentialsManage, sender, std::move(result),
                       "Not authorized to manage credentials", m_grantGate,
                       [this, sender, requester] { return activateSigningKeyGranted(sender, requester); });
}

sdbus::ObjectPath CardObject::activateSigningKeyGranted(const std::string& sender, const std::string& requester)
{
    rateLimitCredentialMutation(sender);

    return launch(makeCredentialsChannel, Operations::OperationLauncher::ActivateSigningKey{}, sender, requester);
}

sdbus::ObjectPath CardObject::ListCredentials()
{
    // A read of the card's PIN credentials. Gates on PinManagement (no listing is
    // meaningful without it) but is NOT rate-limited — no card-state mutation.
    if (!hasPinManagementCapability()) {
        throw sdbus::Error{sdbus::Error::Name{kUnsupportedErrName}, "Card does not advertise PinManagement capability"};
    }
    const std::string requester = callerRequesterLabel();
    const std::string sender = callerSender();
    return launch(makeCredentialsChannel, Operations::OperationLauncher::ListCredentials{}, sender, requester);
}

} // namespace LibreSCRS::Agent
