// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "PrompterService.h"

#include "CallerAuthorizer.h"
#include "PromptDialog.h"
#include "PrompterWire.h" // shared Prompter1 kind / option-key / status vocabulary
#include "SecretMemfd.h"

#include <QCoreApplication>
#include <QMetaObject>
#include <QString>
#include <QStringList>
#include <QThread>

#include <sdbus-c++/Message.h>

#include <unistd.h> // close

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace LibreLinux::Prompter {

namespace {
// The windows currently on screen. One per process by construction (the
// prompter hosts exactly one Prompter1 object), GUI-thread confined, and NOT a
// singleton handed out to arbitrary callers: PrompterService is its only user
// and reaches it through the accessor below.
PromptRegistry& registry()
{
    static PromptRegistry instance;
    return instance;
}
} // namespace

PromptRegistry& PrompterService::registryForTest() noexcept
{
    return registry();
}

namespace {

// Kind / option-key / status names live in common/PrompterWire.h (shared with
// the agent consumer so the two binaries cannot drift). kStatusUnauthorized
// pairs with a zero-byte sealed memfd so no dialog shows and no secret leaks.
using PrompterWire::kOptAltDeadlineMs;
using PrompterWire::kOptAltKinds;
using PrompterWire::kOptArtifact;
using PrompterWire::kOptArtifacts;
using PrompterWire::kOptAttempt;
using PrompterWire::kOptCardLabel;
using PrompterWire::kOptDeadlineMs;
using PrompterWire::kOptDescription;
using PrompterWire::kOptLastError;
using PrompterWire::kOptMaxLength;
using PrompterWire::kOptMinLength;
using PrompterWire::kOptNewMaxLength;
using PrompterWire::kOptNewMinLength;
using PrompterWire::kOptPinLabel;
using PrompterWire::kOptPrimaryMaxLength;
using PrompterWire::kOptPrimaryMinLength;
using PrompterWire::kOptPromptId;
using PrompterWire::kOptReaderFull;
using PrompterWire::kOptReaderInterface;
using PrompterWire::kOptReaderModel;
using PrompterWire::kOptRequester;
using PrompterWire::kOptTitle;
using PrompterWire::kStatusCancelled;
using PrompterWire::kStatusError;
using PrompterWire::kStatusOk;
using PrompterWire::kStatusOkMrz;
using PrompterWire::kStatusTimeout;
using PrompterWire::kStatusUnauthorized;

// Lift a stringly-typed option, tolerating either a real string variant
// or a missing entry. Unrecognised types are treated as missing.
std::string optionString(const std::map<std::string, sdbus::Variant>& opts, const char* key)
{
    auto it = opts.find(key);
    if (it == opts.end()) {
        return {};
    }
    try {
        return it->second.get<std::string>();
    } catch (const sdbus::Error&) {
        return {};
    }
}

// Lift the UNTRUSTED `artifacts` (as) option, tolerating a missing entry or a
// mistyped one (either answers an empty list — the caller simply omits the
// batch file-list rendering, exactly like a missing string option renders no
// line). Every entry lands in the dialog as inert plain text (see
// PromptDialog::buildLayout); this helper does no sanitisation of its own —
// the wire values are already client-supplied strings, same trust level as
// `requester`/`artifact`.
QStringList optionStringList(const std::map<std::string, sdbus::Variant>& opts, const char* key)
{
    auto it = opts.find(key);
    if (it == opts.end()) {
        return {};
    }
    try {
        const auto raw = it->second.get<std::vector<std::string>>();
        QStringList out;
        out.reserve(static_cast<int>(raw.size()));
        for (const auto& s : raw) {
            out.push_back(QString::fromStdString(s));
        }
        return out;
    } catch (const sdbus::Error&) {
        return {};
    }
}

// Lift a uint32 option, returning the supplied @p fallback on type
// mismatch or missing entry. The D-Bus signature on the wire is `u`.
std::uint32_t optionUInt(const std::map<std::string, sdbus::Variant>& opts, const char* key, std::uint32_t fallback)
{
    auto it = opts.find(key);
    if (it == opts.end()) {
        return fallback;
    }
    try {
        return it->second.get<std::uint32_t>();
    } catch (const sdbus::Error&) {
        return fallback;
    }
}

std::optional<PromptDialog::Kind> parseKind(const std::string& kind)
{
    if (kind == PrompterWire::kKindPin)
        return PromptDialog::Kind::Pin;
    if (kind == PrompterWire::kKindCan)
        return PromptDialog::Kind::Can;
    if (kind == PrompterWire::kKindMrz)
        return PromptDialog::Kind::Mrz;
    return std::nullopt;
}

PromptDialog::Options buildOptions(const std::map<std::string, sdbus::Variant>& opts)
{
    PromptDialog::Options out;
    out.title = QString::fromStdString(optionString(opts, kOptTitle));
    out.description = QString::fromStdString(optionString(opts, kOptDescription));
    out.requester = QString::fromStdString(optionString(opts, kOptRequester));
    out.artifact = QString::fromStdString(optionString(opts, kOptArtifact));
    out.artifacts = optionStringList(opts, kOptArtifacts);
    out.minLength = static_cast<int>(optionUInt(opts, kOptMinLength, 4u));
    out.maxLength = static_cast<int>(optionUInt(opts, kOptMaxLength, 8u));
    if (out.maxLength < out.minLength) {
        out.maxLength = out.minLength;
    }
    // Retry context: fallback 0 means "absent" (see PromptOptions::attempt),
    // matching the sender's own omit-when-default convention.
    out.attempt = static_cast<int>(optionUInt(opts, kOptAttempt, 0u));
    out.lastError = QString::fromStdString(optionString(opts, kOptLastError));
    // Plain value carry, no policy: a mistyped (or absent) `alt_kinds` yields
    // an empty list here — the same "treated as absent" tolerance every other
    // lift above has. Whether any member is actually offered depends on the
    // requested KIND, which this helper deliberately does not see; that
    // decision is made once, in the RequestSecret handler.
    out.altKinds = optionStringList(opts, kOptAltKinds);
    // Trusted reader identity, carried verbatim; the dialog turns the closed
    // interface token into words.
    out.readerModel = QString::fromStdString(optionString(opts, kOptReaderModel));
    out.readerInterface = QString::fromStdString(optionString(opts, kOptReaderInterface));
    out.readerFull = QString::fromStdString(optionString(opts, kOptReaderFull));
    return out;
}

// RequestSecrets options: the shared display keys plus the per-role bounds
// (primary -> current field, new -> new AND confirm fields) and the two
// display-only labels. Each role's range is clamped like the single path.
PromptDialog::Options buildMultiOptions(const std::map<std::string, sdbus::Variant>& opts)
{
    PromptDialog::Options out = buildOptions(opts);
    out.primaryMinLength = static_cast<int>(optionUInt(opts, kOptPrimaryMinLength, 4u));
    out.primaryMaxLength = static_cast<int>(optionUInt(opts, kOptPrimaryMaxLength, 8u));
    if (out.primaryMaxLength < out.primaryMinLength) {
        out.primaryMaxLength = out.primaryMinLength;
    }
    out.newMinLength = static_cast<int>(optionUInt(opts, kOptNewMinLength, 4u));
    out.newMaxLength = static_cast<int>(optionUInt(opts, kOptNewMaxLength, 8u));
    if (out.newMaxLength < out.newMinLength) {
        out.newMaxLength = out.newMinLength;
    }
    out.cardLabel = QString::fromStdString(optionString(opts, kOptCardLabel));
    out.pinLabel = QString::fromStdString(optionString(opts, kOptPinLabel));
    return out;
}

// POST @p fn to the Qt main thread and return at once. Nothing is held: the
// whole point of the asynchronous handler is that a human typing into one
// window cannot stall the next request.
//
// @returns false when the functor could NOT be delivered (the GUI thread is
// gone / the app is tearing down). It then never ran, so the caller must fail
// closed rather than leave a D-Bus call with no answer.
template <class Fn>
bool postToMain(QObject* target, Fn&& fn)
{
    return QMetaObject::invokeMethod(target, std::forward<Fn>(fn), Qt::QueuedConnection);
}

// Send a reply on @p result, adopting @p fd. The fd MUST be a real descriptor
// (a possibly empty sealed memfd), never the -1 sentinel and never 0: the wire
// encoder cannot send -1, and adopting 0 would close stdin.
//
// A throw means the caller is gone. The window is already closed and its entry
// already taken by the time this runs, so swallowing is what prevents a leak
// rather than what causes one.
void answerSecret(SecretResult& result, std::string status, int fd) noexcept
{
    try {
        result.returnResults(std::move(status), sdbus::UnixFd{fd, sdbus::adopt_fd}, std::string{});
    } catch (...) {
        std::fprintf(stderr, "librescrs-pinentry-kde: reply dropped (caller gone)\n");
    }
}

void answerSecrets(SecretsResult& result, std::string status, int primaryFd, int secondaryFd) noexcept
{
    try {
        result.returnResults(std::move(status), sdbus::UnixFd{primaryFd, sdbus::adopt_fd},
                             sdbus::UnixFd{secondaryFd, sdbus::adopt_fd}, std::string{});
    } catch (...) {
        std::fprintf(stderr, "librescrs-pinentry-kde: reply dropped (caller gone)\n");
    }
}

// Build the window, register it, show it. The COMPLETION answers -- this
// returns immediately, so the D-Bus worker is not held and a second reader's
// prompt can be served while this window stands.
//
// Heap-allocated, unlike the old stack dialog: the window outlives the call
// that raised it. Its own completion is what deletes it, and that runs while
// the widget is still alive, so the secret is read before anything is torn
// down (the same ordering the stack version had after exec() returned).
//
// Runs on the Qt main thread.
void raiseWindow(PromptDialog::Kind kind, const PromptDialog::Options& opts, pid_t ownerPid,
                 const std::string& promptId, bool offerMrzSwitch, std::chrono::milliseconds entryBudget,
                 std::chrono::milliseconds altEntryBudget, const std::shared_ptr<SecretResult>& result)
{
    auto* dlg = new PromptDialog(kind, opts);
    const auto handle = registry().add(dlg, ownerPid, promptId);
    if (!handle) {
        // Two windows answering to one name would make a dismissal ambiguous,
        // which is the defect this registry exists to end. Refuse, fail closed.
        delete dlg;
        answerSecret(*result, kStatusError, makeEmptySealedFd());
        return;
    }

    QObject::connect(dlg, &QDialog::finished, dlg, [dlg, h = *handle, offerMrzSwitch, result](int code) {
        // Take the entry FIRST: exactly one path ever answers a prompt, so a
        // dismissal that raced this completion finds nothing and no-ops.
        if (!registry().take(h)) {
            return;
        }
        if (code != QDialog::Accepted) {
            // The clock and the holder are different events, and a client that
            // conflates them tells the holder they cancelled what expired.
            answerSecret(*result, dlg->expired() ? kStatusTimeout : kStatusCancelled, makeEmptySealedFd());
        } else if (const int fd = dlg->captureSecretFd(); fd < 0) {
            answerSecret(*result, kStatusError, makeEmptySealedFd());
        } else {
            // The ONLY site that mints the switched-to-MRZ status, gated on the
            // very offer this prompt made: an accepted prompt that offered the
            // switch AND was submitted on the MRZ form answers with it, because
            // the fd then carries an MRZ payload rather than a CAN.
            const bool switched = offerMrzSwitch && dlg->mrzChosen();
            answerSecret(*result, switched ? kStatusOkMrz : kStatusOk, fd);
        }
        dlg->deleteLater();
    });

    // Armed BEFORE show(): the timer starts from the show event, so the
    // holder's time begins when the window is actually on screen.
    dlg->setEntryDeadline(entryBudget);
    // What the offered switch is worth, armed alongside it: the dialog re-bases
    // on it if the holder takes the offer, and ignores it otherwise. Only for a
    // window that actually offers the switch -- a budget for a form this dialog
    // cannot show would be a clock nobody can reach.
    if (offerMrzSwitch) {
        dlg->setAlternateEntryDeadline(altEntryBudget);
    }
    // Shown, not exec'd, and without taking focus (see PromptDialog's ctor).
    dlg->show();
    dlg->announce();
}

void raiseChangePinWindow(const PromptDialog::Options& opts, pid_t ownerPid, const std::string& promptId,
                          std::chrono::milliseconds entryBudget, const std::shared_ptr<SecretsResult>& result)
{
    auto* dlg = new PromptDialog(PromptDialog::Kind::ChangePin, opts);
    const auto handle = registry().add(dlg, ownerPid, promptId);
    if (!handle) {
        delete dlg;
        answerSecrets(*result, kStatusError, makeEmptySealedFd(), makeEmptySealedFd());
        return;
    }

    QObject::connect(dlg, &QDialog::finished, dlg, [dlg, h = *handle, result](int code) {
        if (!registry().take(h)) {
            return;
        }
        if (code != QDialog::Accepted) {
            answerSecrets(*result, dlg->expired() ? kStatusTimeout : kStatusCancelled, makeEmptySealedFd(),
                          makeEmptySealedFd());
            dlg->deleteLater();
            return;
        }
        const PromptDialog::SecretFdPair pair = dlg->takeSecretFdPair();
        if (pair.primaryFd < 0 || pair.secondaryFd < 0) {
            // Partial capture must not leak the half that succeeded.
            if (pair.primaryFd >= 0) {
                ::close(pair.primaryFd);
            }
            if (pair.secondaryFd >= 0) {
                ::close(pair.secondaryFd);
            }
            answerSecrets(*result, kStatusError, makeEmptySealedFd(), makeEmptySealedFd());
        } else {
            answerSecrets(*result, kStatusOk, pair.primaryFd, pair.secondaryFd);
        }
        dlg->deleteLater();
    });

    dlg->setEntryDeadline(entryBudget);
    dlg->show();
    dlg->announce();
}

} // namespace

PrompterService::PrompterService(sdbus::IConnection& connection, sdbus::ObjectPath path)
    : AdaptorInterfaces(connection, std::move(path))
{
    // Per sdbus-c++ contract: register at the END of the ctor so the
    // generated vtable is wired before any inbound dispatch could land.
    registerAdaptor();
}

PrompterService::~PrompterService()
{
    // Symmetric teardown — see ctor note.
    unregisterAdaptor();
}

void PrompterService::RequestSecret(SecretResult&& result, std::string kind,
                                    std::map<std::string, sdbus::Variant> options)
{
    // shared_ptr so the reply handle can be captured by a copyable functor and
    // carried across the post into the window's completion. It is answered
    // exactly once: whichever path takes the registry entry.
    auto reply = std::make_shared<SecretResult>(std::move(result));

    // Trust boundary: only the agent binary may drive the prompter. Reject a
    // non-agent caller with a zero-byte sealed memfd + "unauthorized" status
    // (the existing no-secret encoding) BEFORE any window is constructed, so a
    // rogue same-user process can neither phish a secret nor flash a UI.
    const pid_t ownerPid = authorizeCaller("RequestSecret");
    if (ownerPid == 0) {
        answerSecret(*reply, std::string{kStatusUnauthorized}, makeEmptySealedFd());
        return;
    }

    const auto parsedKind = parseKind(kind);
    if (!parsedKind) {
        // Empty user_message: the "error" status already carries the semantics
        // and clients map their own taxonomy. A hardcoded English literal here
        // would be permanently untranslatable and off the msgKey/fallback wire
        // convention.
        answerSecret(*reply, std::string{kStatusError}, makeEmptySealedFd());
        return;
    }
    PromptDialog::Options opts = buildOptions(options);
    // Routing metadata, not chrome: the dialog never sees it. Absent means this
    // caller cannot address its prompts, and a dismissal will find no match.
    const std::string promptId = optionString(options, kOptPromptId);
    // A DURATION, not an absolute time: no shared clock between the two
    // processes. 0 (or absent) means no deadline, never an instant expiry.
    const std::chrono::milliseconds entryBudget{optionUInt(options, kOptDeadlineMs, 0u)};
    // Same shape and same origin instant as entryBudget; meaningful only if the
    // conjunction below actually offers the switch.
    const std::chrono::milliseconds altEntryBudget{optionUInt(options, kOptAltDeadlineMs, 0u)};

    // THE conjunction, evaluated once and nowhere else: the alternative-kind
    // opt-in is meaningful only on a CAN request, and only for the alternative
    // this dialog can actually offer. This is the single site where both the
    // requested kind and the lifted options are in scope, and the flag it
    // produces is the same one the completion's status decision reads — so an
    // offer the user never saw can never be answered, and an answer the caller
    // never opted into can never be minted.
    const bool offerMrzSwitch =
        *parsedKind == PromptDialog::Kind::Can && opts.altKinds.contains(QString::fromLatin1(PrompterWire::kKindMrz));
    opts.offerMrzSwitch = offerMrzSwitch;

    // Every widget allocation, layout and event dispatch runs on the Qt main
    // thread. POST, never block: holding this thread is what stopped a second
    // reader's prompt from being served at all.
    auto* app = QCoreApplication::instance();
    const auto raise = [kind = *parsedKind, opts, ownerPid, promptId, offerMrzSwitch, entryBudget, altEntryBudget,
                        reply] {
        raiseWindow(kind, opts, ownerPid, promptId, offerMrzSwitch, entryBudget, altEntryBudget, reply);
    };
    if (app == nullptr || QThread::currentThread() == app->thread()) {
        // Already on the main thread (single-threaded test harness, or a
        // future synchronous dispatcher) — raise directly.
        raise();
        return;
    }
    if (!postToMain(app, raise)) {
        // The GUI thread never got the window (shutdown race). Fail closed with
        // a real empty-sealed fd — never the -1 sentinel, which the wire encoder
        // cannot send.
        answerSecret(*reply, std::string{kStatusError}, makeEmptySealedFd());
    }
}

void PrompterService::RequestSecrets(SecretsResult&& result, std::string kind,
                                     std::map<std::string, sdbus::Variant> options)
{
    auto reply = std::make_shared<SecretsResult>(std::move(result));

    // Same trust boundary as RequestSecret: fail closed BEFORE any window, with
    // the established zero-byte-sealed-memfd no-secret encoding — on BOTH fds
    // of the multi-secret reply.
    const pid_t ownerPid = authorizeCaller("RequestSecrets");
    if (ownerPid == 0) {
        answerSecrets(*reply, std::string{kStatusUnauthorized}, makeEmptySealedFd(), makeEmptySealedFd());
        return;
    }
    if (kind != PrompterWire::kKindChangePin) {
        answerSecrets(*reply, std::string{kStatusError}, makeEmptySealedFd(), makeEmptySealedFd());
        return;
    }

    const PromptDialog::Options opts = buildMultiOptions(options);
    const std::string promptId = optionString(options, kOptPromptId);
    const std::chrono::milliseconds entryBudget{optionUInt(options, kOptDeadlineMs, 0u)};

    auto* app = QCoreApplication::instance();
    const auto raise = [opts, ownerPid, promptId, entryBudget, reply] {
        raiseChangePinWindow(opts, ownerPid, promptId, entryBudget, reply);
    };
    if (app == nullptr || QThread::currentThread() == app->thread()) {
        raise();
        return;
    }
    if (!postToMain(app, raise)) {
        answerSecrets(*reply, std::string{kStatusError}, makeEmptySealedFd(), makeEmptySealedFd());
    }
}

void PrompterService::dismissOnGuiThread(const std::string& promptId, pid_t callerPid) noexcept
{
    // Runs on the Qt main thread, so the lookup and the dismissal are one
    // uninterrupted step: a window that answered in the meantime is simply not
    // in the registry any more, which is the documented idempotent no-op rather
    // than a pointer to a deleted dialog.
    const auto handle = registry().findByPromptId(promptId);
    if (!handle) {
        return;
    }
    const auto entry = registry().find(*handle);
    if (!entry) {
        return;
    }
    // Per-window ownership: only the caller that raised THIS window may dismiss
    // it, so one authenticated peer cannot close another's dialog.
    if (!isActivePromptOwner(entry->ownerPid, callerPid)) {
        return;
    }
    // The entry is left in place: QDialog::reject() emits finished, and the
    // completion is the one path that takes the entry and answers. Two paths
    // answering one prompt is what the take-first discipline there prevents.
    // Method-name dispatch via QMetaObject is the load-bearing entry;
    // PromptDialogRejectTest pins reject() as an addressable slot.
    QMetaObject::invokeMethod(entry->window, "reject", Qt::QueuedConnection);
}

pid_t PrompterService::authorizeCaller(const char* method)
{
    // The in-flight call's sender PID, from the kernel-validated sd-bus
    // message credentials. sd-bus augments creds on demand; getCredsPid()
    // throws if the bus did not (or could not) supply them.
    pid_t callerPid = 0;
    try {
        callerPid = getObject().getCurrentlyProcessedMessage().getCredsPid();
    } catch (const sdbus::Error& e) {
        std::fprintf(stderr, "librescrs-pinentry-kde: %s rejected: cannot resolve caller PID: %s\n", method,
                     e.getMessage().c_str());
        return 0;
    }

    const std::filesystem::path expectedPeer = CallerAuthorizer::resolveExpectedPeerPath();
    if (!CallerAuthorizer::isAuthorizedCaller(callerPid, expectedPeer)) {
        // Log the rejection WITHOUT any secret material — PID + the expected
        // peer path are non-sensitive and aid operators diagnosing a denied
        // caller (e.g. a misconfigured install or an actual intrusion).
        std::fprintf(stderr, "librescrs-pinentry-kde: %s rejected: caller pid=%ld is not the agent (expected %s)\n",
                     method, static_cast<long>(callerPid), expectedPeer.c_str());
        return 0;
    }
    return callerPid;
}

void PrompterService::dismissEveryWindowOnGuiThread() noexcept
{
    // Runs on the Qt main thread, like every other window action. The entries
    // are LEFT in place: each window's reject() emits finished, and that
    // completion is the one path that takes its entry and answers it.
    for (const auto handle : registry().handles()) {
        if (const auto entry = registry().find(handle)) {
            QMetaObject::invokeMethod(entry->window, "reject", Qt::QueuedConnection);
        }
    }
}

void PrompterService::Reset()
{
    // Binary-identity gate only. NOT the per-window owner gate: an orphan's
    // owner is a process that no longer exists, so requiring ownership would
    // clear exactly the windows this exists to clear.
    if (authorizeCaller("Reset") == 0) {
        return;
    }
    auto* app = QCoreApplication::instance();
    if (app == nullptr || QThread::currentThread() == app->thread()) {
        dismissEveryWindowOnGuiThread();
        return;
    }
    static_cast<void>(postToMain(app, [] { dismissEveryWindowOnGuiThread(); }));
}

void PrompterService::resetForTest() noexcept
{
    dismissEveryWindowOnGuiThread();
}

uint32_t PrompterService::ProtocolVersion()
{
    return PrompterWire::kProtocolVersion;
}

void PrompterService::Cancel(const std::string& promptId)
{
    // Same binary-identity gate as RequestSecret: a non-agent caller must not
    // be able to inject a cancel (a denial-of-service against a legitimate
    // prompt). Unauthorised Cancel is a silent no-op.
    const pid_t callerPid = authorizeCaller("Cancel");
    if (callerPid == 0) {
        return;
    }

    // The lookup itself is posted, not just the dismissal: everything that
    // touches the registry or a window runs on the Qt main thread.
    auto* app = QCoreApplication::instance();
    if (app == nullptr || QThread::currentThread() == app->thread()) {
        dismissOnGuiThread(promptId, callerPid);
        return;
    }
    static_cast<void>(postToMain(app, [promptId, callerPid] { dismissOnGuiThread(promptId, callerPid); }));
}

bool PrompterService::isActivePromptOwner(pid_t ownerPid, pid_t callerPid) noexcept
{
    return ownerPid != 0 && ownerPid == callerPid;
}

void PrompterService::cancelForTest(const std::string& promptId) noexcept
{
    // The test seam skips only the bus round trip and the binary-identity gate;
    // the ownership check still applies, so it passes this process's own PID --
    // the same PID a test's in-process request registered under.
    dismissOnGuiThread(promptId, ::getpid());
}

} // namespace LibreLinux::Prompter
