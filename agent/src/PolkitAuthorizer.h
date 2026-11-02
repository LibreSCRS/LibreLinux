// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <LibreSCRS/Agent/backend/Authorizer.h>

#include <sdbus-c++/Types.h>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <string_view>

namespace sdbus {
class IConnection;
}

namespace LibreSCRS::Agent {

// Pure, daemon-free helpers behind PolkitAuthorizer, factored out so the
// authorization logic that does not require a live polkit can be unit-tested.
namespace PolkitDetail {

// Parse the process start time (field 22 of /proc/<pid>/stat, in clock ticks
// since boot) from a raw stat line. This is the value polkit itself uses to
// pin a unix-process subject against PID reuse. The comm field (field 2) is
// wrapped in parentheses and may itself contain spaces and parentheses, so we
// split on the LAST ')' and count fields from there. Returns nullopt on any
// malformed input (no ')', too few trailing fields, non-numeric start time).
[[nodiscard]] std::optional<std::uint64_t> parseProcStartTime(const std::string& statContent);

// The "uid" entry of a unix-process subject, typed the way polkit reads it:
// int32 ("i"). An entry of another type is ignored as if absent.
[[nodiscard]] sdbus::Variant uidDetail(std::uint32_t uid);

// Build the polkit unix-process subject detail dictionary: {"pid": u,
// "start-time": t, optional "uid": i}. uid is included only when present.
[[nodiscard]] std::map<std::string, sdbus::Variant> buildUnixProcessDetails(std::uint32_t pid, std::uint64_t startTime,
                                                                            std::optional<std::uint32_t> uid);

// The unix-process subject details for a caller the bus daemon describes by
// @p credentials (org.freedesktop.DBus.GetConnectionCredentials). When the bus
// hands out a ProcessFD and the UnixUserID, the subject is that pidfd + uid: a
// handle on the calling process that no recycled pid can redirect, which polkit
// accepts in place of a pid (and only with the uid). Otherwise the ProcessID
// with its start time, read by
// @p startTimeOf (pid-reuse pinned; see common/ProcPidPin.h for the residual
// that path keeps). nullopt when neither can be built.
[[nodiscard]] std::optional<std::map<std::string, sdbus::Variant>>
unixProcessDetailsFrom(const std::map<std::string, sdbus::Variant>& credentials,
                       const std::function<std::optional<std::uint64_t>(std::uint32_t)>& startTimeOf);

// Map the CheckAuthorization reply tuple's (is_authorized, is_challenge) pair
// to the boolean authorize() result. Because we pass AllowUserInteraction, a
// satisfiable challenge resolves to is_authorized=true synchronously; an
// unresolved/declined challenge stays is_authorized=false, i.e. denied.
[[nodiscard]] inline bool interpretReply(bool isAuthorized, bool /*isChallenge*/) noexcept
{
    return isAuthorized;
}

} // namespace PolkitDetail

// Production authorizer backed by org.freedesktop.PolicyKit1.Authority on the
// SYSTEM bus. Resolves the caller's unique D-Bus name to the bus daemon's
// kernel-validated credentials -- a pidfd where the bus hands one out, the pid
// and its start time where it does not -- and asks polkit CheckAuthorization
// for the requested action, honouring the .policy defaults (allow / auth_self
// / auth_admin).
//
// Constructed eagerly: it opens its OWN system-bus connection at construction
// and throws sdbus::Error if that fails, so the caller (AgentService) can fall
// back to DefaultAuthorizer instead of running without a policy gate. The
// session-bus handle is injected by ctor-DI (AgentService already owns it) and
// is used only to ask the bus daemon for the caller's credentials.
//
// Undecided (not a deny): any failure to reach polkit, resolve the pid, or
// parse the reply -- nothing was decided, so nothing is told to the caller as
// a refusal.
//
// The system-bus connection runs its own event loop thread so that an
// asynchronous CheckAuthorization can be answered while the agent's
// dispatcher goes on serving.
class PolkitAuthorizer final : public Authorizer
{
public:
    // @p sessionBus MUST outlive this authorizer (AgentService owns it).
    explicit PolkitAuthorizer(sdbus::IConnection& sessionBus);
    ~PolkitAuthorizer() override;

    PolkitAuthorizer(const PolkitAuthorizer&) = delete;
    PolkitAuthorizer& operator=(const PolkitAuthorizer&) = delete;
    PolkitAuthorizer(PolkitAuthorizer&&) = delete;
    PolkitAuthorizer& operator=(PolkitAuthorizer&&) = delete;

    [[nodiscard]] AuthorizationOutcome authorize(std::string_view actionId, const CallerToken& caller) override;

    /// Asks polkit without waiting for it: CheckAuthorization goes out as an
    /// asynchronous call on this authorizer's own system-bus connection, and
    /// @p done runs when polkit answers -- which, for an auth_self action, is
    /// when a person has answered a password dialog. Until then the caller's
    /// thread is free. Anything that keeps polkit from being asked at all
    /// (no caller, no pid, no start time) is answered at once, Undecided.
    void authorizeAsync(std::string_view actionId, const CallerToken& caller, Completion done) override;

    /// Where authorizeAsync() hands an answer back. Unset, @p done runs on this
    /// authorizer's own system-bus thread; the agent sets it to its dispatcher
    /// loop so that a deferred method resumes on the thread that owns its
    /// objects. Set once, before the first call.
    using Post = std::function<void(std::function<void()>)>;
    void deliverAnswersThrough(Post post);

private:
    class Impl;
    std::unique_ptr<Impl> m_impl;
};

} // namespace LibreSCRS::Agent
