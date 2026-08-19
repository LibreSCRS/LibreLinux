// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once

#include "PromptRegistry.h"
#include "org.librescrs.Prompter1_adaptor.h"

#include <sdbus-c++/AdaptorInterfaces.h>
#include <sdbus-c++/IConnection.h>
#include <sdbus-c++/Types.h>

#include <sys/types.h> // pid_t

#include <filesystem>
#include <map>
#include <string>

namespace LibreLinux::Prompter {

class PromptDialog;

/// Reply handles of the two asynchronous request methods, named once here so
/// the signatures below read as contracts rather than as generated noise.
using SecretResult = sdbus::Result<std::string, sdbus::UnixFd, std::string>;
using SecretsResult = sdbus::Result<std::string, sdbus::UnixFd, sdbus::UnixFd, std::string>;

/// D-Bus host object for @c org.librescrs.Prompter1 at
/// @c /org/librescrs/Prompter1. Serves each request ASYNCHRONOUSLY:
///   1. Authorise the caller, then POST (never block) a functor to the Qt
///      main thread carrying the reply handle.
///   2. On that thread, build a @ref PromptDialog for the requested @c kind,
///      register it in @ref PromptRegistry, @c show() it — non-modal, without
///      taking focus — and RETURN. No thread is held while a human types, so
///      a second reader's prompt is served while the first window stands.
///   3. When a window finishes, its completion seals the entered secret into
///      a memfd and answers @c ("ok", fd, "") on that window's own handle.
///   4. On reject / unknown kind / a failed post, answer the corresponding
///      status with an empty sealed memfd (a 0-byte memfd, NOT @c -1 — the
///      wire signature requires a real file descriptor).
///
/// The registry and every window live on the Qt main thread; the D-Bus worker
/// threads only post to it. That is what makes a dismissal racing a window's
/// own completion a documented no-op rather than a dangling pointer.
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

    // Test seam: dispatch to the named window without a D-Bus round trip.
    // Same code path Cancel() takes past the authorisation gate.
    static void cancelForTest(const std::string& promptId) noexcept;

    // Test seam: sweep every window without a D-Bus round trip. Same code path
    // Reset() takes past the authorisation gate.
    static void resetForTest() noexcept;

    // Test seam: the live-window registry, so a test can assert which windows
    // stand without a display server or a second process.
    [[nodiscard]] static PromptRegistry& registryForTest() noexcept;

    // Pure ownership predicate consulted after the caller has passed the
    // binary-identity gate: only the caller that raised a window may dismiss
    // it. @returns true iff @p ownerPid is a live owner (non-zero) AND equals
    // @p callerPid. A dismissal from a different (but still
    // agent-authenticated) peer returns false. Factored out so the rejection of
    // a distinct authenticated caller is unit-testable without a second real
    // PID on the bus (two same-user binaries share the test process's PID).
    [[nodiscard]] static bool isActivePromptOwner(pid_t ownerPid, pid_t callerPid) noexcept;

private:
    // Generated adaptor — dispatched on the sdbus-c++ worker thread. Takes the
    // reply handle rather than returning a tuple: the answer is sent later,
    // from the window's own completion.
    void RequestSecret(SecretResult&& result, std::string kind, std::map<std::string, sdbus::Variant> options) override;

    // Multi-secret variant (kind "change_pin"): same authorisation gate, same
    // posted-window discipline; answers with TWO sealed memfds — primary
    // (current secret) + secondary (new secret), both zero-length whenever
    // status is not "ok". The confirm entry never leaves the dialog.
    void RequestSecrets(SecretsResult&& result, std::string kind,
                        std::map<std::string, sdbus::Variant> options) override;

    // Agent-driven dismissal of the ONE window @p promptId names. Posts the
    // lookup AND the dismissal to the Qt main thread, so an id that names no
    // live window — including one that just answered — is a silent no-op rather
    // than a stale pointer. Gated on caller identity (must be the agent binary)
    // AND per-window ownership (must be the caller that raised it).
    void Cancel(const std::string& promptId) override;

    // The contract this binary implements (PrompterWire::kProtocolVersion).
    // The agent reads it once and refuses to raise a prompt it could not
    // dismiss -- this helper outlives agent restarts, so a mismatch is routine
    // rather than exotic.
    // Close every window this helper is showing, whoever raised it -- an
    // orphan's owner is a process that no longer exists, so a per-owner sweep
    // would clear nothing. The binary-identity gate still applies.
    void Reset() override;

    uint32_t ProtocolVersion() override;

    static void dismissOnGuiThread(const std::string& promptId, pid_t callerPid) noexcept;
    static void dismissEveryWindowOnGuiThread() noexcept;

    // Resolve the in-flight D-Bus caller's PID from the message credentials,
    // then verify the backing executable is the expected agent binary.
    // Returns the resolved PID on success (for ownership tracking) so the
    // caller can fold authorisation + identity into one query. Returns 0
    // when the caller is unauthorised or the PID could not be resolved.
    // Logs the rejection (no secret material).
    [[nodiscard]] pid_t authorizeCaller(const char* method);
};

} // namespace LibreLinux::Prompter
