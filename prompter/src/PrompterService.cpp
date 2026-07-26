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
#include <cstdint>
#include <cstdio>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace LibreLinux::Prompter {

// Single-instance dialog tracker (see header for the no-singleton rationale).
std::atomic<PromptDialog*> PrompterService::s_activeDialog{nullptr};

// Owner PID of the in-flight prompt (0 == idle). See header.
std::atomic<pid_t> PrompterService::s_activeOwnerPid{0};

namespace {

// Kind / option-key / status names live in common/PrompterWire.h (shared with
// the agent consumer so the two binaries cannot drift). kStatusUnauthorized
// pairs with a zero-byte sealed memfd so no dialog shows and no secret leaks.
using PrompterWire::kOptArtifact;
using PrompterWire::kOptArtifacts;
using PrompterWire::kOptAttempt;
using PrompterWire::kOptCardLabel;
using PrompterWire::kOptDescription;
using PrompterWire::kOptLastError;
using PrompterWire::kOptMaxLength;
using PrompterWire::kOptMinLength;
using PrompterWire::kOptNewMaxLength;
using PrompterWire::kOptNewMinLength;
using PrompterWire::kOptPinLabel;
using PrompterWire::kOptPrimaryMaxLength;
using PrompterWire::kOptPrimaryMinLength;
using PrompterWire::kOptRequester;
using PrompterWire::kOptTitle;
using PrompterWire::kStatusCancelled;
using PrompterWire::kStatusError;
using PrompterWire::kStatusOk;
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

// Run @p fn on the Qt main thread (the thread @p target lives on) and
// block until it returns. Used to flip from the sdbus-c++ worker thread
// back into the GUI thread; the D-Bus caller is itself already blocked on
// the method reply, so the additional thread-block here changes nothing
// observable.
template <class Fn>
auto runOnMain(QObject* target, Fn&& fn) -> std::optional<decltype(fn())>
{
    using Ret = decltype(fn());
    std::optional<Ret> result;
    // invokeMethod returns false when the functor could NOT be delivered (the
    // target thread is absent / the app is tearing down). In that case the
    // functor never ran, so `result` stays disengaged and the caller must fail
    // closed rather than adopt a default-constructed (sentinel-fd) outcome.
    const bool ran = QMetaObject::invokeMethod(target, [&]() { result = fn(); }, Qt::BlockingQueuedConnection);
    if (!ran) {
        return std::nullopt;
    }
    return result;
}

struct DialogOutcome
{
    std::string status;
    // Defaults to the -1 "no fd" sentinel (matching SecretFdPair), NOT 0:
    // a default-constructed outcome (e.g. a failed main-thread hop) must never
    // be adopted as fd 0 (stdin). Set to a real (possibly empty-sealed) memfd
    // on every reachable return.
    int fd{-1};
};

// The fd MUST default to the -1 "no fd" sentinel, never 0 (a live descriptor —
// stdin): a default-constructed outcome from a failed main-thread hop is later
// adopted by sdbus::UnixFd, and adopting 0 would close stdin. This locks the
// invariant at compile time — an omitted / 0 initializer fails the build.
static_assert(DialogOutcome{}.fd == -1, "DialogOutcome::fd must default to the -1 no-fd sentinel");

// Publishes the dialog so PrompterService::CancelCurrent (running on the
// sdbus-c++ worker thread) can post a queued reject() to the GUI thread.
// Stored before exec() and cleared after the event loop returns. The owner
// PID is published FIRST so a CancelCurrent that observes a live dialog also
// sees a consistent owner, and cleared AFTER the dialog slot.
struct ActiveDialogScope
{
    ActiveDialogScope(PromptDialog& dlg, pid_t ownerPid)
    {
        PrompterService::s_activeOwnerPid.store(ownerPid, std::memory_order_release);
        PrompterService::s_activeDialog.store(&dlg, std::memory_order_release);
    }
    ~ActiveDialogScope()
    {
        PrompterService::s_activeDialog.store(nullptr, std::memory_order_release);
        PrompterService::s_activeOwnerPid.store(0, std::memory_order_release);
    }
    ActiveDialogScope(const ActiveDialogScope&) = delete;
    ActiveDialogScope& operator=(const ActiveDialogScope&) = delete;
};

DialogOutcome runDialog(PromptDialog::Kind kind, const PromptDialog::Options& opts, pid_t ownerPid)
{
    // Stack-allocated dialog: deterministic teardown of the embedded
    // input widget right after we extract the fd, scrubbing residue from
    // user-space buffers before the function returns.
    PromptDialog dlg(kind, opts);
    int code = 0;
    {
        ActiveDialogScope scope(dlg, ownerPid);
        code = dlg.exec();
    }
    if (code != QDialog::Accepted) {
        return {kStatusCancelled, makeEmptySealedFd()};
    }
    const int fd = dlg.captureSecretFd();
    if (fd < 0) {
        return {kStatusError, makeEmptySealedFd()};
    }
    return {kStatusOk, fd};
}

struct MultiDialogOutcome
{
    std::string status;
    // Both fds default to the -1 no-fd sentinel (see DialogOutcome): a failed
    // hop must not adopt fd 0 twice and double-close stdin.
    int primaryFd{-1};   // current secret; empty sealed fd unless status is ok
    int secondaryFd{-1}; // new secret; empty sealed fd unless status is ok
};

// Same -1 sentinel invariant as DialogOutcome, on BOTH fds: a failed hop would
// otherwise adopt fd 0 twice and double-close stdin.
static_assert(MultiDialogOutcome{}.primaryFd == -1 && MultiDialogOutcome{}.secondaryFd == -1,
              "MultiDialogOutcome fds must default to the -1 no-fd sentinel");

MultiDialogOutcome runChangePinDialog(const PromptDialog::Options& opts, pid_t ownerPid)
{
    PromptDialog dlg(PromptDialog::Kind::ChangePin, opts);
    int code = 0;
    {
        ActiveDialogScope scope(dlg, ownerPid);
        code = dlg.exec();
    }
    if (code != QDialog::Accepted) {
        return {kStatusCancelled, makeEmptySealedFd(), makeEmptySealedFd()};
    }
    const PromptDialog::SecretFdPair pair = dlg.takeSecretFdPair();
    if (pair.primaryFd < 0 || pair.secondaryFd < 0) {
        // Partial capture must not leak the half that succeeded.
        if (pair.primaryFd >= 0) {
            ::close(pair.primaryFd);
        }
        if (pair.secondaryFd >= 0) {
            ::close(pair.secondaryFd);
        }
        return {kStatusError, makeEmptySealedFd(), makeEmptySealedFd()};
    }
    return {kStatusOk, pair.primaryFd, pair.secondaryFd};
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

std::tuple<std::string, sdbus::UnixFd, std::string>
PrompterService::RequestSecret(const std::string& kind, const std::map<std::string, sdbus::Variant>& options)
{
    // Trust boundary: only the agent binary may drive the prompter. Reject a
    // non-agent caller with a zero-byte sealed memfd + "unauthorized" status
    // (the existing no-secret encoding) BEFORE any dialog is constructed, so
    // a rogue same-user process can neither phish a secret nor flash a UI.
    const pid_t ownerPid = authorizeCaller("RequestSecret");
    if (ownerPid == 0) {
        sdbus::UnixFd wrapped{makeEmptySealedFd(), sdbus::adopt_fd};
        return std::make_tuple(std::string{kStatusUnauthorized}, std::move(wrapped), std::string{});
    }

    const auto parsedKind = parseKind(kind);
    if (!parsedKind) {
        // adopt_fd: take exclusive ownership of the fd we just created,
        // skipping the redundant dup() the default ctor would perform.
        // UnixFd treats -1 as "no fd" and is a no-op on destruction.
        sdbus::UnixFd wrapped{makeEmptySealedFd(), sdbus::adopt_fd};
        // Empty user_message: the "error" status already carries the semantics
        // and clients map their own taxonomy. A hardcoded English literal here
        // would be permanently untranslatable and off the msgKey/fallback wire
        // convention.
        return std::make_tuple(std::string{kStatusError}, std::move(wrapped), std::string{});
    }
    const PromptDialog::Options opts = buildOptions(options);

    // Hop to the Qt main thread: every widget allocation, layout, event
    // dispatch and exec() must run there.
    auto* app = QCoreApplication::instance();
    DialogOutcome outcome;
    if (app && QThread::currentThread() != app->thread()) {
        std::optional<DialogOutcome> hopped = runOnMain(app, [&]() { return runDialog(*parsedKind, opts, ownerPid); });
        if (hopped) {
            outcome = std::move(*hopped);
        } else {
            // The GUI thread never ran the dialog (shutdown race). Fail closed:
            // a real empty-sealed fd (never the -1 sentinel, which the wire
            // encoder cannot send) with Error status. makeEmptySealedFd() runs
            // ONLY here, so the success path leaks no fd.
            outcome = DialogOutcome{std::string{kStatusError}, makeEmptySealedFd()};
        }
    } else {
        // Already on the main thread (single-threaded test harness, or a
        // future synchronous dispatcher) — call directly.
        outcome = runDialog(*parsedKind, opts, ownerPid);
    }

    // sdbus::UnixFd with adopt_fd takes exclusive ownership of the fd we
    // just minted (no dup, no double-close). The wire encoder transmits
    // it via SCM_RIGHTS; the receiver gets its own dup'd fd.
    sdbus::UnixFd wrapped{outcome.fd, sdbus::adopt_fd};
    return std::make_tuple(outcome.status, std::move(wrapped), std::string{});
}

std::tuple<std::string, sdbus::UnixFd, sdbus::UnixFd, std::string>
PrompterService::RequestSecrets(const std::string& kind, const std::map<std::string, sdbus::Variant>& options)
{
    // Same trust boundary as RequestSecret: fail closed BEFORE any dialog,
    // with the established zero-byte-sealed-memfd no-secret encoding — on
    // BOTH fds of the multi-secret reply.
    const pid_t ownerPid = authorizeCaller("RequestSecrets");
    if (ownerPid == 0) {
        sdbus::UnixFd primary{makeEmptySealedFd(), sdbus::adopt_fd};
        sdbus::UnixFd secondary{makeEmptySealedFd(), sdbus::adopt_fd};
        return std::make_tuple(std::string{kStatusUnauthorized}, std::move(primary), std::move(secondary),
                               std::string{});
    }

    if (kind != PrompterWire::kKindChangePin) {
        sdbus::UnixFd primary{makeEmptySealedFd(), sdbus::adopt_fd};
        sdbus::UnixFd secondary{makeEmptySealedFd(), sdbus::adopt_fd};
        // Empty user_message (see RequestSecret): status "error" is the contract;
        // no bare English literal on the wire.
        return std::make_tuple(std::string{kStatusError}, std::move(primary), std::move(secondary), std::string{});
    }
    const PromptDialog::Options opts = buildMultiOptions(options);

    // Hop to the Qt main thread — same discipline as RequestSecret.
    auto* app = QCoreApplication::instance();
    MultiDialogOutcome outcome;
    if (app && QThread::currentThread() != app->thread()) {
        std::optional<MultiDialogOutcome> hopped = runOnMain(app, [&]() { return runChangePinDialog(opts, ownerPid); });
        if (hopped) {
            outcome = std::move(*hopped);
        } else {
            // Shutdown race, both secrets: fail closed with two real
            // empty-sealed fds (never the -1 sentinels) + Error status.
            // makeEmptySealedFd() runs ONLY here (no success-path leak).
            outcome = MultiDialogOutcome{std::string{kStatusError}, makeEmptySealedFd(), makeEmptySealedFd()};
        }
    } else {
        outcome = runChangePinDialog(opts, ownerPid);
    }

    sdbus::UnixFd primary{outcome.primaryFd, sdbus::adopt_fd};
    sdbus::UnixFd secondary{outcome.secondaryFd, sdbus::adopt_fd};
    return std::make_tuple(outcome.status, std::move(primary), std::move(secondary), std::string{});
}

void PrompterService::rejectActiveDialog() noexcept
{
    auto* dlg = s_activeDialog.load(std::memory_order_acquire);
    if (dlg == nullptr) {
        // Idle prompter — documented no-op.
        return;
    }
    // reject() must run on the GUI thread; CancelCurrent dispatches on the
    // sdbus-c++ worker. QueuedConnection posts an event to the dialog's
    // owning thread (the Qt main thread inside runDialog()), where the
    // QDialog::reject slot runs safely. Method-name dispatch via
    // QMetaObject is the load-bearing entry; the regression test in
    // PromptDialogRejectTest pins reject() as an addressable slot.
    QMetaObject::invokeMethod(dlg, "reject", Qt::QueuedConnection);
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

void PrompterService::CancelCurrent()
{
    // Same binary-identity gate as RequestSecret: a non-agent caller must not
    // be able to inject a cancel (a denial-of-service against a legitimate
    // prompt). Unauthorised CancelCurrent is a silent no-op.
    const pid_t callerPid = authorizeCaller("CancelCurrent");
    if (callerPid == 0) {
        return;
    }

    // Ownership gate: only the caller that initiated the CURRENTLY-active
    // prompt may cancel it. A CancelCurrent from a different (but still
    // agent-authenticated) caller — or against an idle prompter — is a no-op.
    // Reading the owner before dispatching keeps the check race-tolerant: if
    // the dialog tears down between here and rejectActiveDialog(), the latter
    // already no-ops on a null s_activeDialog.
    const pid_t owner = s_activeOwnerPid.load(std::memory_order_acquire);
    if (!isActivePromptOwner(owner, callerPid)) {
        return;
    }
    rejectActiveDialog();
}

bool PrompterService::isActivePromptOwner(pid_t ownerPid, pid_t callerPid) noexcept
{
    return ownerPid != 0 && ownerPid == callerPid;
}

void PrompterService::cancelCurrentForTest() noexcept
{
    rejectActiveDialog();
}

} // namespace LibreLinux::Prompter
