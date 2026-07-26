// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <LibreSCRS/Agent/backend/Authorizer.h>

#include <sdbus-c++/Types.h>
#include <cstdint>
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

// Build the polkit unix-process subject detail dictionary: {"pid": u,
// "start-time": t, optional "uid": u}. uid is included only when present.
[[nodiscard]] std::map<std::string, sdbus::Variant> buildUnixProcessDetails(std::uint32_t pid, std::uint64_t startTime,
                                                                            std::optional<std::uint32_t> uid);

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
// SYSTEM bus. Resolves the caller's unique D-Bus name to a kernel-validated
// pid (+ start-time) and asks polkit CheckAuthorization for the requested
// action, honouring the .policy defaults (allow / auth_self / auth_admin).
//
// Constructed eagerly: it opens its OWN system-bus connection at construction
// and throws sdbus::Error if that fails, so the caller (AgentService) can fall
// back to DefaultAuthorizer instead of running without a policy gate. The
// session-bus handle is injected by ctor-DI (AgentService already owns it) and
// is used only to resolve callerBusName -> pid via the bus daemon.
//
// Fail-closed: any failure to reach polkit, resolve the pid, or parse the
// reply yields a deny (authorize() returns false) and a single warn log.
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

    [[nodiscard]] bool authorize(std::string_view actionId, const CallerToken& caller) override;

private:
    class Impl;
    std::unique_ptr<Impl> m_impl;
};

} // namespace LibreSCRS::Agent
