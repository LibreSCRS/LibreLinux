// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once

#include "org.librescrs.Prompter1_adaptor.h"

#include <sdbus-c++/AdaptorInterfaces.h>
#include <sdbus-c++/IConnection.h>
#include <sdbus-c++/Types.h>

#include <sys/types.h> // pid_t

#include <atomic>
#include <filesystem>
#include <map>
#include <mutex>
#include <string>
#include <tuple>

namespace LibreLinux::Prompter {

class PromptDialog;

/// D-Bus host object for @c org.librescrs.Prompter1 at
/// @c /org/librescrs/Prompter1. Implements the single @c RequestSecret
/// method by:
///   1. Marshalling the call from the sdbus-c++ worker thread back into
///      the Qt main thread via @c QMetaObject::invokeMethod with
///      @c Qt::BlockingQueuedConnection (the agent caller is already
///      blocked on the D-Bus return, so blocking the worker thread here
///      is consistent with the request semantics).
///   2. Constructing a @ref PromptDialog matching the requested @c kind
///      and showing it modally.
///   3. On accept, sealing the entered secret into a memfd and returning
///      @c ("ok", fd, "") to the caller.
///   4. On reject / unknown kind, returning the corresponding status and
///      an empty sealed memfd (a 0-byte memfd, NOT @c -1 — the wire
///      signature requires a real file descriptor).
///
/// The adaptor base destructor is non-virtual — per the sdbus-c++
/// contract @ref AdaptorInterfaces subclasses must NOT mark their dtor
/// @c override, must call @c unregisterAdaptor() in the body, and must
/// call @c registerAdaptor() at the end of the ctor.
class PrompterService final : public sdbus::AdaptorInterfaces<org::librescrs::Prompter1_adaptor>
{
public:
    PrompterService(sdbus::IConnection& connection, sdbus::ObjectPath path);
    ~PrompterService();

    PrompterService(const PrompterService&) = delete;
    PrompterService& operator=(const PrompterService&) = delete;

    // Test seam: dispatch to the named dialog without a D-Bus round trip.
    // Same code path Cancel() takes; called by PrompterCancelTest to pin the
    // no-live-prompt no-op contract.
    static void cancelForTest(const std::string& promptId) noexcept;

    // Pure ownership predicate consulted by CancelCurrent AFTER the caller has
    // passed the binary-identity gate: only the caller that initiated the
    // CURRENTLY-active prompt may cancel it. @returns true iff @p ownerPid is a
    // live owner (non-zero) AND equals @p callerPid. A cancel from a different
    // (but still agent-authenticated) peer, or against an idle prompter
    // (ownerPid == 0), returns false. Factored out so the rejection of a
    // distinct authenticated caller is unit-testable without a second real PID
    // on the bus (two same-user binaries share the test process's PID).
    [[nodiscard]] static bool isActivePromptOwner(pid_t ownerPid, pid_t callerPid) noexcept;

    // Pure addressing predicate, the id counterpart of isActivePromptOwner
    // above and factored out for the same reason: more than one credential
    // window can stand, so a dismissal has to name one, and getting this wrong
    // closes another reader's dialog. @returns true iff @p activeId is a real
    // addressee (non-empty) AND equals @p requestedId. An unaddressable prompt
    // (empty activeId, from a caller that sent no id) is never dismissable by
    // name -- refusing is correct: there is nothing to distinguish it from any
    // other unaddressable prompt.
    [[nodiscard]] static bool isNamedPrompt(const std::string& activeId, const std::string& requestedId) noexcept;

    // Visible to PromptDialog::ActiveScope (file-scope helper inside
    // PrompterService.cpp). Tracks the dialog currently being exec'd so
    // CancelCurrent has somewhere to dispatch reject() to. Atomic because
    // the D-Bus worker thread reads it without holding the GUI mutex.
    //
    // Single-static rationale (per project convention banning singletons):
    // the prompter binary handles exactly one dialog at a time by its
    // existing architecture (RequestSecret is synchronous and runDialog
    // marshals through the Qt main thread). One slot suffices; no
    // multi-instance state is needed.
    static std::atomic<PromptDialog*> s_activeDialog;

    // PID of the caller that initiated the CURRENTLY-active prompt. Set
    // alongside s_activeDialog and consulted by CancelCurrent so that only
    // the originating caller may cancel an in-flight prompt (a different
    // same-user peer's CancelCurrent is a no-op). Paired with s_activeDialog
    // under the same store/clear discipline; 0 means "no owner / idle".
    static std::atomic<pid_t> s_activeOwnerPid;

    // Id of the CURRENTLY-active prompt, so a dismissal that names a different
    // one cannot close it. Guarded by the same mutex the scope publishes under:
    // a std::string cannot be read atomically the way the two slots above can.
    static std::mutex s_activeMutex;
    static std::string s_activePromptId;

private:
    // Generated adaptor — dispatched on the sdbus-c++ worker thread.
    std::tuple<std::string, sdbus::UnixFd, std::string>
    RequestSecret(const std::string& kind, const std::map<std::string, sdbus::Variant>& options) override;

    // Multi-secret variant (kind "change_pin"): same authorisation gate,
    // same main-thread dialog marshalling; returns TWO sealed memfds —
    // primary (current secret) + secondary (new secret), both zero-length
    // whenever status is not "ok". The confirm entry never leaves the dialog.
    std::tuple<std::string, sdbus::UnixFd, sdbus::UnixFd, std::string>
    RequestSecrets(const std::string& kind, const std::map<std::string, sdbus::Variant>& options) override;

    // Agent-driven dismissal of the ONE prompt @p promptId names: posts
    // reject() via QueuedConnection when that prompt is the one currently
    // exec'ing. An id that names no live prompt is a silent no-op, so a
    // dismissal racing the user's own is harmless. Gated on caller identity
    // (must be the agent binary) AND prompt ownership (must be the caller that
    // started that prompt).
    void Cancel(const std::string& promptId) override;

    static void rejectDialog(const std::string& promptId) noexcept;

    // Resolve the in-flight D-Bus caller's PID from the message credentials,
    // then verify the backing executable is the expected agent binary.
    // Returns the resolved PID on success (for ownership tracking) so the
    // caller can fold authorisation + identity into one query. Returns 0
    // when the caller is unauthorised or the PID could not be resolved.
    // Logs the rejection (no secret material).
    [[nodiscard]] pid_t authorizeCaller(const char* method);
};

} // namespace LibreLinux::Prompter
