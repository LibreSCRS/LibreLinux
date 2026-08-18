// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#include "PrompterClient.h"
#include <LibreSCRS/Agent/backend/Logging.h>
#include "PrompterWire.h" // shared Prompter1 kind / option-key / status vocabulary
#include "SecretMemfdReader.h"
#include "org.librescrs.Prompter1_proxy.h"
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

// Kind / option-key / status names live in common/PrompterWire.h (shared with
// the prompter producer so the two binaries cannot drift).
using LibreLinux::PrompterWire::kKindCan;
using LibreLinux::PrompterWire::kKindMrz;
using LibreLinux::PrompterWire::kStatusCancelled;
using LibreLinux::PrompterWire::kStatusOk;
using LibreLinux::PrompterWire::kStatusOkMrz;
using LibreLinux::PrompterWire::kStatusUnauthorized;

PromptStatus parseStatus(std::string_view raw)
{
    if (raw == kStatusOk) {
        return PromptStatus::Ok;
    }
    if (raw == kStatusCancelled) {
        return PromptStatus::Cancelled;
    }
    // "unauthorized" is the prompter's fail-closed rejection of a NON-agent
    // caller. The agent is the only authorized caller, so it never legitimately
    // receives this; were its peer-creds somehow unrecognised, collapsing to
    // Error is the correct fail-closed outcome. Matched explicitly (not left to
    // the fall-through) so the wire value is acknowledged, not silently unknown.
    if (raw == kStatusUnauthorized) {
        return PromptStatus::Error;
    }
    return PromptStatus::Error;
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
// Exactly one status is sent-options-dependent: the distinct success token is
// meaningful only to a caller that opted in, and is otherwise unexpected
// vocabulary. Deliberately NOT recognised in parseStatus above — a status the
// caller never invited must take the same fail-closed route as any unknown one,
// which is precisely what the delegation below does.
ParsedStatus parseRequestSecretStatus(std::string_view raw, bool mrzAlternativeOffered)
{
    if (mrzAlternativeOffered && raw == kStatusOkMrz) {
        return ParsedStatus{PromptStatus::Ok, LibreSCRS::Auth::PaceSecretKind::Mrz};
    }
    return ParsedStatus{parseStatus(raw), std::nullopt};
}

std::map<std::string, sdbus::Variant> buildOptionsDict(const PromptOptions& options)
{
    std::map<std::string, sdbus::Variant> dict;
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

PrompterClient::PrompterClient(std::shared_ptr<sdbus::IConnection> connection, std::string serviceName,
                               std::string objectPath, std::chrono::microseconds interactiveBudget)
    : m_connection(std::move(connection)), m_interactiveBudget(interactiveBudget),
      m_serviceName(std::move(serviceName)), m_objectPath(std::move(objectPath)),
      m_impl(std::make_unique<Impl>(*m_connection, m_serviceName, m_objectPath))
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

void PrompterClient::cancel() noexcept
{
    try {
        m_impl->CancelCurrent();
    } catch (const sdbus::Error& e) {
        log::warnf("PrompterClient: CancelCurrent failed: {}", e.getMessage());
    } catch (const std::exception& e) {
        log::warnf("PrompterClient: CancelCurrent threw: {}", e.what());
    } catch (...) {
        log::warn("PrompterClient: CancelCurrent failed with unknown exception");
    }
}

void PrompterClient::cancelVia(sdbus::IConnection& connection) noexcept
{
    // One-shot proxy on the supplied (main) connection: NOT m_connection, which a
    // wedged worker may be pumping inline for its blocking RequestSecret. See the
    // header for why a cross-connection cancel still lands (PID-based correlation).
    try {
        Impl canceller(connection, m_serviceName, m_objectPath);
        canceller.CancelCurrent();
    } catch (const sdbus::Error& e) {
        log::warnf("PrompterClient: cross-connection CancelCurrent failed: {}", e.getMessage());
    } catch (const std::exception& e) {
        log::warnf("PrompterClient: cross-connection CancelCurrent threw: {}", e.what());
    } catch (...) {
        log::warn("PrompterClient: cross-connection CancelCurrent failed with unknown exception");
    }
}

PromptResult PrompterClient::request(std::string_view kind, const PromptOptions& options)
{
    PromptResult result;

    // The call returns std::tuple<status, secret_fd, user_message> — strings +
    // sdbus::UnixFd — and may throw sdbus::Error on transport or bus failure.
    // Any throw collapses to PromptStatus::Error + e.getMessage(). Issued raw
    // (not via the generated convenience method) to carry the interactive
    // budget.
    std::tuple<std::string, sdbus::UnixFd, std::string> reply;
    try {
        m_impl->proxy()
            .callMethod("RequestSecret")
            .onInterface(org::librescrs::Prompter1_proxy::INTERFACE_NAME)
            .withTimeout(m_interactiveBudget)
            .withArguments(std::string{kind}, buildOptionsDict(options))
            .storeResultsTo(reply);
    } catch (const sdbus::Error& e) {
        log::warnf("PrompterClient: D-Bus call RequestSecret({}) failed: {}", kind, e.getMessage());
        // The prompter may still be showing the dialog this call abandoned
        // (budget expiry is the canonical case): dismiss it so the user is
        // not left typing into a prompt with no consumer. The blocking call
        // has already returned, so m_connection is free again; best-effort.
        cancel();
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

    // The call returns std::tuple<status, primary_fd, secondary_fd,
    // user_message> and may throw sdbus::Error on transport / bus failure. Any
    // throw collapses to PromptStatus::Error + e.getMessage(), matching the
    // no-throw contract of the single-secret calls. Issued raw to carry the
    // interactive budget (a PIN change is the SLOWEST entry: two fields plus
    // a confirmation).
    std::tuple<std::string, sdbus::UnixFd, sdbus::UnixFd, std::string> reply;
    try {
        m_impl->proxy()
            .callMethod("RequestSecrets")
            .onInterface(org::librescrs::Prompter1_proxy::INTERFACE_NAME)
            .withTimeout(m_interactiveBudget)
            .withArguments(std::string{LibreLinux::PrompterWire::kKindChangePin}, buildChangePinOptionsDict(options))
            .storeResultsTo(reply);
    } catch (const sdbus::Error& e) {
        log::warnf("PrompterClient: D-Bus call RequestSecrets(change_pin) failed: {}", e.getMessage());
        // Dismiss the possibly-orphaned change_pin dialog — same rationale as
        // the single-secret path.
        cancel();
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
