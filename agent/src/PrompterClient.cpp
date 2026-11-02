// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#include "PrompterClient.h"
#include <LibreSCRS/Logging.h>
#include "PrompterCapability.h" // the version guard in front of every prompt
#include "PrompterWire.h"       // shared Prompter1 kind / option-key / status vocabulary
#include "SecretMemfdReader.h"
#include "org.librescrs.Prompter1_proxy.h"
#include <LibreSCRS/Agent/backend/PromptTypes.h> // promptStatusFor
#include <LibreSCRS/Agent/wire/ReaderInterface.h>
#include <LibreSCRS/Auth/PaceSecretKind.h>
#include <sdbus-c++/Error.h>
#include <sdbus-c++/IProxy.h>
#include <sdbus-c++/ProxyInterfaces.h>
#include <sdbus-c++/Types.h>
#include <algorithm>
#include <chrono>
#include <map>
#include <optional>
#include <string>
#include <tuple>
#include <utility>

namespace LibreSCRS::Agent {

namespace {

// Kind / option-key names live in common/PrompterWire.h (shared with the
// prompter producer so the two binaries cannot drift); the kind words and the
// reply status are the agent library's.
using LibreLinux::PrompterWire::kKindCan;
using LibreLinux::PrompterWire::kKindMrz;
using LibreLinux::PrompterWire::PromptReplyStatus;

// A reply word this build does not know is the prompter failing, never a
// success: "unauthorized" and anything unrecognised land on Error alike.
PromptReplyStatus replyStatusOf(std::string_view raw)
{
    return LibreLinux::PrompterWire::replyStatusFromToken(raw).value_or(PromptReplyStatus::Error);
}

// A reply to a request that offered no alternative kind: the MRZ success word
// is unexpected there and fails closed like any unknown one.
PromptStatus parseStatus(std::string_view raw)
{
    return promptStatusFor(replyStatusOf(raw), /*mrzAlternativeOffered=*/false);
}

// Marshal the reader's identity. Each key is omitted when empty, like every
// other optional option -- a prompt whose reader could not be resolved says
// nothing rather than naming the wrong one.
void emplaceReaderIdentity(std::map<std::string, sdbus::Variant>& dict, const PromptOptions& options)
{
    if (!options.reader.model.empty()) {
        dict.emplace(LibreLinux::PrompterWire::kOptReaderModel, sdbus::Variant{options.reader.model});
    }
    if (options.reader.iface != LibreSCRS::Agent::ReaderInterface::Unknown) {
        dict.emplace(LibreLinux::PrompterWire::kOptReaderInterface,
                     sdbus::Variant{std::string{LibreSCRS::Agent::Wire::readerInterfaceToken(options.reader.iface)}});
    }
    if (!options.reader.full.empty()) {
        dict.emplace(LibreLinux::PrompterWire::kOptReaderFull, sdbus::Variant{options.reader.full});
    }
}

// Did THIS request offer the user a switch to the MRZ form? True only for the
// exact shape the prompter mints its distinct status on: a CAN request whose
// alternative-kind list named the MRZ kind. The list is marshalled for every
// kind (see buildOptionsDict), so the requested-kind test here is what keeps a
// future caller that sets altKinds on some other prompt from being handed an
// MRZ payload in that prompt's slot.
bool offeredMrzAlternative(std::string_view kind, const PromptOptions& options)
{
    if (kind != std::string_view{kKindCan}) {
        return false;
    }
    return std::ranges::find(options.altKinds, std::string_view{kKindMrz}) != options.altKinds.end();
}

struct ParsedStatus
{
    PromptStatus status = PromptStatus::Error;
    std::optional<LibreSCRS::Auth::PaceSecretKind> chosenKind;
};

// The RequestSecret status parse, aware of what this very request asked for.
// Exactly one status is sent-options-dependent: the MRZ success word is
// meaningful only to a caller that opted in (promptStatusFor reads it as an
// error otherwise), and it names WHICH credential the secret is.
ParsedStatus parseRequestSecretStatus(std::string_view raw, bool mrzAlternativeOffered)
{
    const PromptReplyStatus reply = replyStatusOf(raw);
    const PromptStatus status = promptStatusFor(reply, mrzAlternativeOffered);
    if (status == PromptStatus::Ok && reply == PromptReplyStatus::OkMrz) {
        return ParsedStatus{status, LibreSCRS::Auth::PaceSecretKind::Mrz};
    }
    return ParsedStatus{status, std::nullopt};
}

std::map<std::string, sdbus::Variant> buildOptionsDict(const PromptOptions& options)
{
    std::map<std::string, sdbus::Variant> dict;
    // The identity this prompt answers to. Omitted when unstamped, exactly like
    // every other optional key -- a prompter then simply has no name to dismiss
    // it by.
    if (!options.promptId.empty()) {
        dict.emplace(LibreLinux::PrompterWire::kOptPromptId, sdbus::Variant{options.promptId});
    }
    // A DURATION the prompter starts when it shows the window, so what elapses
    // is exactly what the holder sees counting down. Omitted at 0 like every
    // other optional key -- 0 must never read as an instant expiry.
    if (options.deadlineMs > 0) {
        dict.emplace(LibreLinux::PrompterWire::kOptDeadlineMs, sdbus::Variant{options.deadlineMs});
    }
    emplaceReaderIdentity(dict, options);
    if (!options.title.empty()) {
        dict.emplace(LibreLinux::PrompterWire::kOptTitle, sdbus::Variant{options.title});
    }
    if (!options.description.empty()) {
        dict.emplace(LibreLinux::PrompterWire::kOptDescription, sdbus::Variant{options.description});
    }
    if (!options.requester.empty()) {
        dict.emplace(LibreLinux::PrompterWire::kOptRequester, sdbus::Variant{options.requester});
    }
    if (!options.artifact.empty()) {
        dict.emplace(LibreLinux::PrompterWire::kOptArtifact, sdbus::Variant{options.artifact});
    }
    if (!options.artifacts.empty()) {
        // UNTRUSTED per-document display names (BatchSignFlow's consent
        // prompt) — a documented `as` key, distinct from the TRUSTED
        // `artifact` singular above. Never used as (or folded into) the
        // trusted category token.
        dict.emplace(LibreLinux::PrompterWire::kOptArtifacts, sdbus::Variant{options.artifacts});
    }
    if (options.minLength > 0) {
        dict.emplace(LibreLinux::PrompterWire::kOptMinLength, sdbus::Variant{options.minLength});
    }
    if (options.maxLength > 0) {
        dict.emplace(LibreLinux::PrompterWire::kOptMaxLength, sdbus::Variant{options.maxLength});
    }
    // Retry context (CredentialCache::applyRetryContext): both stay at their
    // default on the first-ever prompt for a card, so both are omitted then —
    // exactly like every other optional key above.
    if (options.attempt > 0) {
        dict.emplace(LibreLinux::PrompterWire::kOptAttempt, sdbus::Variant{options.attempt});
    }
    if (!options.lastError.empty()) {
        dict.emplace(LibreLinux::PrompterWire::kOptLastError, sdbus::Variant{options.lastError});
    }
    // Opt-in to an in-dialog switch to an alternative credential form. Omitted
    // whenever the caller sets none, so every existing caller's dictionary is
    // byte-identical to before; a prompter that predates the key simply drops
    // it and answers with the plain status vocabulary.
    if (!options.altKinds.empty()) {
        dict.emplace(LibreLinux::PrompterWire::kOptAltKinds, sdbus::Variant{options.altKinds});
    }
    // What the offered form is worth, so the dialog can re-base its clock on
    // the switch instead of leaving the holder the budget sized for the form
    // they just left. Omitted at 0 like every other optional key.
    if (options.altDeadlineMs > 0) {
        dict.emplace(LibreLinux::PrompterWire::kOptAltDeadlineMs, sdbus::Variant{options.altDeadlineMs});
    }
    return dict;
}

// Options dictionary for the change_pin dialog. The display chrome (title /
// description / requester / artifact) marshals exactly as the single-secret
// path; the length bounds differ. RequestSecrets exposes PER-ROLE bounds
// (primary_* for the current-PIN field, new_* for the new + confirm fields),
// while the seam carries ONE (min, max) pair — so it maps onto both roles: the
// same policy applies to the current and the new PIN. The single-secret
// min_length/max_length keys are deliberately NOT sent (the change_pin dialog
// ignores them). The display-only labels the dialog consumes — card_label
// (the card/token the change applies to) and pin_label (the PIN role being
// changed) — cross here; the title is left to the prompter's localized action
// title unless a caller explicitly set one.
std::map<std::string, sdbus::Variant> buildChangePinOptionsDict(const PromptOptions& options)
{
    std::map<std::string, sdbus::Variant> dict;
    // The identity this prompt answers to. Omitted when unstamped, exactly like
    // every other optional key -- a prompter then simply has no name to dismiss
    // it by.
    if (!options.promptId.empty()) {
        dict.emplace(LibreLinux::PrompterWire::kOptPromptId, sdbus::Variant{options.promptId});
    }
    // A DURATION the prompter starts when it shows the window, so what elapses
    // is exactly what the holder sees counting down. Omitted at 0 like every
    // other optional key -- 0 must never read as an instant expiry.
    if (options.deadlineMs > 0) {
        dict.emplace(LibreLinux::PrompterWire::kOptDeadlineMs, sdbus::Variant{options.deadlineMs});
    }
    emplaceReaderIdentity(dict, options);
    if (!options.title.empty()) {
        dict.emplace(LibreLinux::PrompterWire::kOptTitle, sdbus::Variant{options.title});
    }
    if (!options.description.empty()) {
        dict.emplace(LibreLinux::PrompterWire::kOptDescription, sdbus::Variant{options.description});
    }
    if (!options.requester.empty()) {
        dict.emplace(LibreLinux::PrompterWire::kOptRequester, sdbus::Variant{options.requester});
    }
    if (!options.artifact.empty()) {
        dict.emplace(LibreLinux::PrompterWire::kOptArtifact, sdbus::Variant{options.artifact});
    }
    if (!options.cardLabel.empty()) {
        dict.emplace(LibreLinux::PrompterWire::kOptCardLabel, sdbus::Variant{options.cardLabel});
    }
    if (!options.pinLabel.empty()) {
        dict.emplace(LibreLinux::PrompterWire::kOptPinLabel, sdbus::Variant{options.pinLabel});
    }
    if (options.minLength > 0) {
        dict.emplace(LibreLinux::PrompterWire::kOptPrimaryMinLength, sdbus::Variant{options.minLength});
        dict.emplace(LibreLinux::PrompterWire::kOptNewMinLength, sdbus::Variant{options.minLength});
    }
    if (options.maxLength > 0) {
        dict.emplace(LibreLinux::PrompterWire::kOptPrimaryMaxLength, sdbus::Variant{options.maxLength});
        dict.emplace(LibreLinux::PrompterWire::kOptNewMaxLength, sdbus::Variant{options.maxLength});
    }
    return dict;
}

} // namespace

// Concrete proxy: joins the generated Prompter1_proxy interface class onto
// the sdbus-c++ ProxyInterfaces helper, binding it to a caller-owned
// IConnection. The generated base's constructor takes an sdbus::IProxy&,
// which ProxyInterfaces supplies via getProxy().
class PrompterClient::Impl final : public sdbus::ProxyInterfaces<org::librescrs::Prompter1_proxy>
{
public:
    Impl(sdbus::IConnection& connection, std::string serviceName, std::string objectPath)
        : ProxyInterfaces(connection, sdbus::ServiceName{std::move(serviceName)},
                          sdbus::ObjectPath{std::move(objectPath)})
    {
        registerProxy();
    }

    ~Impl()
    {
        unregisterProxy();
    }

    // The interactive calls below bypass the generated convenience methods:
    // those run on the D-Bus DEFAULT method timeout (~25 s), which aborted
    // real human-paced entries mid-typing. The raw proxy lets the call carry
    // an explicit budget.
    sdbus::IProxy& proxy()
    {
        return getProxy();
    }
};

PrompterClient::PrompterClient(std::string serviceName, std::string objectPath,
                               std::chrono::microseconds interactiveBudget)
    : m_interactiveBudget(interactiveBudget), m_serviceName(std::move(serviceName)), m_objectPath(std::move(objectPath))
{}

PrompterClient::~PrompterClient() = default;

PromptResult PrompterClient::requestPin(const PromptOptions& options)
{
    return request(LibreLinux::PrompterWire::kKindPin, options);
}

PromptResult PrompterClient::requestCan(const PromptOptions& options)
{
    return request(LibreLinux::PrompterWire::kKindCan, options);
}

PromptResult PrompterClient::requestMrz(const PromptOptions& options)
{
    return request(LibreLinux::PrompterWire::kKindMrz, options);
}

void PrompterClient::cancel(const std::string& promptId) noexcept
{
    // Its own connection, like every call here: a cancel has to be deliverable
    // while a worker is blocked in a request, and two operations cancelled at
    // once must not drive one bus from two threads.
    try {
        auto connection = sdbus::createSessionBusConnection();
        Impl canceller(*connection, m_serviceName, m_objectPath);
        canceller.Cancel(promptId);
    } catch (const sdbus::Error& e) {
        log::warnf("PrompterClient: Cancel({}) failed: {}", promptId, e.getMessage());
    } catch (const std::exception& e) {
        log::warnf("PrompterClient: Cancel({}) threw: {}", promptId, e.what());
    } catch (...) {
        log::warn("PrompterClient: Cancel failed with unknown exception");
    }
}

void PrompterClient::resetPrompter() noexcept
{
    try {
        auto connection = sdbus::createSessionBusConnection();
        Impl resetter(*connection, m_serviceName, m_objectPath);
        resetter.Reset();
    } catch (const sdbus::Error& e) {
        log::warnf("PrompterClient: Reset failed: {}", e.getMessage());
    } catch (const std::exception& e) {
        log::warnf("PrompterClient: Reset threw: {}", e.what());
    } catch (...) {
        log::warn("PrompterClient: Reset failed with unknown exception");
    }
}

PrompterClient::Usability PrompterClient::prompterUsability()
{
    const std::lock_guard lock{m_capabilityMutex};
    if (m_capability.has_value()) {
        return *m_capability ? Usability::Usable : Usability::TooOld;
    }
    std::optional<std::uint32_t> reported;
    try {
        auto connection = sdbus::createSessionBusConnection();
        Impl probe(*connection, m_serviceName, m_objectPath);
        reported = probe.ProtocolVersion();
    } catch (const sdbus::Error& e) {
        // An older helper publishes no such property: the bus answers that the
        // property does not exist (sd-bus says UnknownProperty, Qt InvalidArgs).
        // That is an answer about the helper, and it is remembered. Anything
        // else -- the helper not running yet, in its restart limit, slow to
        // activate -- says nothing about which helper it is, so the next prompt
        // asks again.
        const std::string name = e.getName();
        if (name != "org.freedesktop.DBus.Error.UnknownProperty" && name != "org.freedesktop.DBus.Error.InvalidArgs") {
            log::warnf("PrompterClient: the prompter could not be reached: {}", e.getMessage());
            return Usability::Unreachable;
        }
        log::warnf("PrompterClient: the prompter publishes no protocol version: {}", e.getMessage());
    } catch (const std::exception& e) {
        log::warnf("PrompterClient: the prompter could not be reached: {}", e.what());
        return Usability::Unreachable;
    }
    m_capability = PrompterCapability::usable(reported);
    if (!*m_capability) {
        log::warn("PrompterClient: the credential window helper is out of date; refusing to raise a prompt it "
                  "could not dismiss");
    }
    return *m_capability ? Usability::Usable : Usability::TooOld;
}

template <typename Result>
bool PrompterClient::refuseUnlessUsable(Result& result)
{
    switch (prompterUsability()) {
    case Usability::Usable:
        return false;
    case Usability::TooOld:
        // Not a failure of the helper: it is running and serving, it simply
        // predates the addressed cancel, so a prompt raised now could never be
        // dismissed. A capability gap, and one the holder can clear.
        result.status = PromptStatus::HelperTooOld;
        result.userMessage = "the credential window helper is out of date";
        return true;
    case Usability::Unreachable:
        result.status = PromptStatus::Error;
        result.userMessage = "the credential window helper could not be reached";
        return true;
    }
    return true;
}

PromptResult PrompterClient::request(std::string_view kind, const PromptOptions& options)
{
    PromptResult result;

    // Refuse BEFORE any window is raised. A helper that cannot be told to
    // dismiss a prompt would leave it standing with nobody able to close it --
    // the defect this design removes, returning through a mismatched pair.
    if (refuseUnlessUsable(result)) {
        return result;
    }

    // The call returns std::tuple<status, secret_fd, user_message> — strings +
    // sdbus::UnixFd — and may throw sdbus::Error on transport or bus failure.
    // Any throw collapses to PromptStatus::Error + e.getMessage(). Issued raw
    // (not via the generated convenience method) to carry the interactive
    // budget.
    std::tuple<std::string, sdbus::UnixFd, std::string> reply;
    try {
        // One connection for this prompt alone, torn down with the call. The
        // reply is pumped INLINE by this worker, so a shared connection would
        // be driven by two threads the moment anything else spoke to the
        // prompter. Declared before the proxy so it outlives it.
        auto connection = sdbus::createSessionBusConnection();
        Impl call(*connection, m_serviceName, m_objectPath);
        call.proxy()
            .callMethod("RequestSecret")
            .onInterface(org::librescrs::Prompter1_proxy::INTERFACE_NAME)
            .withTimeout(m_interactiveBudget)
            .withArguments(std::string{kind}, buildOptionsDict(options))
            .storeResultsTo(reply);
    } catch (const sdbus::Error& e) {
        log::warnf("PrompterClient: D-Bus call RequestSecret({}) failed: {}", kind, e.getMessage());
        // The prompter may still be showing the dialog this call abandoned
        // (budget expiry is the canonical case): dismiss it so the user is not
        // left typing into a prompt with no consumer. Best-effort.
        cancel(options.promptId);
        result.status = PromptStatus::Error;
        result.userMessage = e.getMessage();
        return result;
    } catch (const std::exception& e) {
        log::warnf("PrompterClient: RequestSecret({}) threw: {}", kind, e.what());
        result.status = PromptStatus::Error;
        result.userMessage = e.what();
        return result;
    }

    auto& [rawStatus, secretFd, userMessage] = reply;
    const auto parsed = parseRequestSecretStatus(rawStatus, offeredMrzAlternative(kind, options));
    result.status = parsed.status;
    result.chosenKind = parsed.chosenKind;
    result.userMessage = std::move(userMessage);

    if (result.status != PromptStatus::Ok) {
        // Non-ok carries no usable secret — let the UnixFd destructor close
        // any incidental fd the prompter may have included.
        return result;
    }

    std::string readError;
    auto secret = SecretMemfdReader::read(std::move(secretFd), &readError);
    if (!secret.has_value()) {
        log::warnf("PrompterClient: memfd read failed for {}: {}", kind, readError);
        result.status = PromptStatus::Error;
        // No secret means no credential to classify: drop the chosen kind too,
        // so a failed result never reads as "holding an MRZ".
        result.chosenKind.reset();
        if (result.userMessage.empty()) {
            result.userMessage = readError;
        }
        return result;
    }
    result.secret = std::move(*secret);
    return result;
}

PinChangePromptResult PrompterClient::requestPinChange(const PromptOptions& options)
{
    PinChangePromptResult result;

    // Same refusal as the single-secret path, for the same reason.
    if (refuseUnlessUsable(result)) {
        return result;
    }

    // The call returns std::tuple<status, primary_fd, secondary_fd,
    // user_message> and may throw sdbus::Error on transport / bus failure. Any
    // throw collapses to PromptStatus::Error + e.getMessage(), matching the
    // no-throw contract of the single-secret calls. Issued raw to carry the
    // interactive budget (a PIN change is the SLOWEST entry: two fields plus
    // a confirmation).
    std::tuple<std::string, sdbus::UnixFd, sdbus::UnixFd, std::string> reply;
    try {
        // Own connection, same rationale as the single-secret path.
        auto connection = sdbus::createSessionBusConnection();
        Impl call(*connection, m_serviceName, m_objectPath);
        call.proxy()
            .callMethod("RequestSecrets")
            .onInterface(org::librescrs::Prompter1_proxy::INTERFACE_NAME)
            .withTimeout(m_interactiveBudget)
            .withArguments(std::string{LibreLinux::PrompterWire::kKindChangePin}, buildChangePinOptionsDict(options))
            .storeResultsTo(reply);
    } catch (const sdbus::Error& e) {
        log::warnf("PrompterClient: D-Bus call RequestSecrets(change_pin) failed: {}", e.getMessage());
        // Dismiss the possibly-orphaned change_pin dialog — same rationale as
        // the single-secret path.
        cancel(options.promptId);
        result.status = PromptStatus::Error;
        result.userMessage = e.getMessage();
        return result;
    } catch (const std::exception& e) {
        log::warnf("PrompterClient: RequestSecrets(change_pin) threw: {}", e.what());
        result.status = PromptStatus::Error;
        result.userMessage = e.what();
        return result;
    }

    auto& [rawStatus, primaryFd, secondaryFd, userMessage] = reply;
    result.status = parseStatus(rawStatus);
    result.userMessage = std::move(userMessage);

    if (result.status != PromptStatus::Ok) {
        // Non-ok carries no usable secret; both fds are zero-length sealed
        // memfds by contract. Let the UnixFd destructors close them.
        return result;
    }

    // Read BOTH sealed fds into cleansing Secure::Strings BEFORE committing
    // either to the result. Each read seal-verifies its fd and always closes
    // it (RAII). If EITHER read fails, the whole change fails closed: the
    // locals below go out of scope and scrub, so NO partial secret escapes into
    // the result (both `current` and `newPin` stay disengaged).
    std::string primaryError;
    auto current = SecretMemfdReader::read(std::move(primaryFd), &primaryError);
    std::string secondaryError;
    auto newPin = SecretMemfdReader::read(std::move(secondaryFd), &secondaryError);

    if (!current.has_value() || !newPin.has_value()) {
        log::warnf("PrompterClient: change_pin memfd read failed (primary='{}', secondary='{}')", primaryError,
                   secondaryError);
        result.status = PromptStatus::Error;
        if (result.userMessage.empty()) {
            result.userMessage = !primaryError.empty() ? primaryError : secondaryError;
        }
        return result;
    }

    result.current = std::move(*current);
    result.newPin = std::move(*newPin);
    return result;
}

} // namespace LibreSCRS::Agent
