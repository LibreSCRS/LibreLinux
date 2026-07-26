// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#include "PolkitAuthorizer.h"
#include <LibreSCRS/Agent/backend/Logging.h>
#include "ProcPidPin.h" // librelinux-common pinned /proc readers

#include <sdbus-c++/Error.h>
#include <sdbus-c++/IConnection.h>
#include <sdbus-c++/IProxy.h>
#include <sdbus-c++/Types.h>
#include <sstream>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

namespace LibreSCRS::Agent {

namespace {

// org.freedesktop.PolicyKit1 well-known names.
constexpr const char* kPolkitService = "org.freedesktop.PolicyKit1";
constexpr const char* kPolkitPath = "/org/freedesktop/PolicyKit1/Authority";
constexpr const char* kPolkitIface = "org.freedesktop.PolicyKit1.Authority";

// org.freedesktop.DBus (the bus daemon) — used to resolve a unique bus name to
// a kernel-validated pid.
constexpr const char* kDBusService = "org.freedesktop.DBus";
constexpr const char* kDBusPath = "/org/freedesktop/DBus";
constexpr const char* kDBusIface = "org.freedesktop.DBus";

// polkit CheckAuthorization flag: allow the authority to interact with the
// user (so auth_self/auth_admin actions can prompt). 0x1 == AllowUserInteraction.
constexpr std::uint32_t kAllowUserInteraction = 0x1u;

} // namespace

namespace PolkitDetail {

std::optional<std::uint64_t> parseProcStartTime(const std::string& statContent)
{
    // /proc/<pid>/stat: "pid (comm) state ppid ...". comm is parenthesised and
    // may contain spaces AND embedded parentheses, so locate the LAST ')' and
    // count whitespace-separated fields from the character after it. After the
    // ')' the field numbering is: [0]=state(field3) ... so field 22 (start
    // time) is index 22 - 3 = 19 in the post-')' token list.
    const auto close = statContent.rfind(')');
    if (close == std::string::npos || close + 1 >= statContent.size()) {
        return std::nullopt;
    }

    std::istringstream rest(statContent.substr(close + 1));
    std::string token;
    std::vector<std::string> fields;
    while (rest >> token) {
        fields.push_back(token);
        if (fields.size() > 20) {
            break; // we only need up to index 19
        }
    }
    // index 19 == field 22 (start time).
    constexpr std::size_t kStartTimeIndex = 19;
    if (fields.size() <= kStartTimeIndex) {
        return std::nullopt;
    }

    try {
        std::size_t consumed = 0;
        const unsigned long long v = std::stoull(fields[kStartTimeIndex], &consumed);
        if (consumed != fields[kStartTimeIndex].size()) {
            return std::nullopt; // trailing non-numeric garbage
        }
        return static_cast<std::uint64_t>(v);
    } catch (const std::exception&) {
        return std::nullopt;
    }
}

std::map<std::string, sdbus::Variant> buildUnixProcessDetails(std::uint32_t pid, std::uint64_t startTime,
                                                              std::optional<std::uint32_t> uid)
{
    std::map<std::string, sdbus::Variant> details;
    details.emplace("pid", sdbus::Variant{pid});
    details.emplace("start-time", sdbus::Variant{startTime});
    if (uid.has_value()) {
        details.emplace("uid", sdbus::Variant{*uid});
    }
    return details;
}

} // namespace PolkitDetail

class PolkitAuthorizer::Impl
{
public:
    explicit Impl(sdbus::IConnection& sessionBus) : m_sessionBus(sessionBus)
    {
        // Open our OWN system-bus connection. AF_UNIX, so the unit's
        // RestrictAddressFamilies permits it. Throws sdbus::Error on failure —
        // the ctor surfaces that so AgentService can fall back.
        m_systemBus = sdbus::createSystemBusConnection();
        m_polkitProxy =
            sdbus::createProxy(*m_systemBus, sdbus::ServiceName{kPolkitService}, sdbus::ObjectPath{kPolkitPath});
        m_dbusProxy = sdbus::createProxy(m_sessionBus, sdbus::ServiceName{kDBusService}, sdbus::ObjectPath{kDBusPath});
    }

    bool authorize(std::string_view actionId, const CallerToken& caller)
    {
        // The transport-resolved caller token carries the Linux unique bus name;
        // derive it once and reuse for pid/uid resolution and the warn logs.
        const std::string busName{caller.str()};

        // Empty bus name -> an internal/agent-originated mutation (no external
        // D-Bus caller). We do NOT consult polkit (there is no subject to
        // build) and fail-CLOSED: the only external entry points pass a real
        // unique name, so an empty name here would be an internal misuse, not a
        // legitimate request. Returning false keeps the trust tier locked
        // rather than silently auto-allowing.
        if (busName.empty()) {
            log::warn("PolkitAuthorizer: empty caller bus name; denying (no polkit subject)");
            return false;
        }

        const auto pid = resolveCallerPid(busName);
        if (!pid.has_value()) {
            log::warnf("PolkitAuthorizer: could not resolve pid for {}; denying", busName);
            return false;
        }

        const auto startTime = readStartTime(*pid);
        if (!startTime.has_value()) {
            log::warnf("PolkitAuthorizer: could not read start-time for pid {}; denying", *pid);
            return false;
        }

        auto details = PolkitDetail::buildUnixProcessDetails(*pid, *startTime, readUid(busName));

        try {
            // CheckAuthorization signature: (sa{sv}) s a{ss} u s -> (b b a{ss}).
            // subject = ("unix-process", details); empty action-details; flags
            // with AllowUserInteraction; empty cancellation id.
            sdbus::Struct<std::string, std::map<std::string, sdbus::Variant>> subject{std::string{"unix-process"},
                                                                                      std::move(details)};
            const std::map<std::string, std::string> emptyDetails;

            sdbus::Struct<bool, bool, std::map<std::string, std::string>> reply;
            m_polkitProxy->callMethod("CheckAuthorization")
                .onInterface(sdbus::InterfaceName{kPolkitIface})
                .withArguments(subject, std::string{actionId}, emptyDetails, kAllowUserInteraction, std::string{})
                .storeResultsTo(reply);

            const bool isAuthorized = reply.get<0>();
            const bool isChallenge = reply.get<1>();
            return PolkitDetail::interpretReply(isAuthorized, isChallenge);
        } catch (const sdbus::Error& e) {
            log::warnf("PolkitAuthorizer: CheckAuthorization failed: {}; denying", e.getMessage());
            return false;
        } catch (const std::exception& e) {
            log::warnf("PolkitAuthorizer: CheckAuthorization threw: {}; denying", e.what());
            return false;
        }
    }

private:
    std::optional<std::uint32_t> resolveCallerPid(const std::string& busName)
    {
        try {
            std::uint32_t pid = 0;
            m_dbusProxy->callMethod("GetConnectionUnixProcessID")
                .onInterface(sdbus::InterfaceName{kDBusIface})
                .withArguments(busName)
                .storeResultsTo(pid);
            return pid;
        } catch (const sdbus::Error& e) {
            log::warnf("PolkitAuthorizer: GetConnectionUnixProcessID({}) failed: {}", busName, e.getMessage());
            return std::nullopt;
        } catch (const std::exception&) {
            return std::nullopt;
        }
    }

    std::optional<std::uint32_t> readUid(const std::string& busName)
    {
        try {
            std::uint32_t uid = 0;
            m_dbusProxy->callMethod("GetConnectionUnixUser")
                .onInterface(sdbus::InterfaceName{kDBusIface})
                .withArguments(busName)
                .storeResultsTo(uid);
            return uid;
        } catch (const std::exception&) {
            // uid is optional in the subject; absence is not fatal.
            return std::nullopt;
        }
    }

    static std::optional<std::uint64_t> readStartTime(std::uint32_t pid)
    {
        // Pidfd-anchored /proc/<pid>/stat read with a post-read liveness probe
        // so a recycled PID cannot let us authorize the wrong process (the
        // security-critical window the polkit start-time subject is meant to
        // close). The pin and read live in the shared common/ProcPidPin.h,
        // also used by CallerIdentity and the prompter's CallerAuthorizer.
        const auto stat = LibreLinux::Common::readProcStatPinned(static_cast<pid_t>(pid));
        if (!stat) {
            return std::nullopt;
        }
        return PolkitDetail::parseProcStartTime(*stat);
    }

    sdbus::IConnection& m_sessionBus;
    std::unique_ptr<sdbus::IConnection> m_systemBus;
    std::unique_ptr<sdbus::IProxy> m_polkitProxy;
    std::unique_ptr<sdbus::IProxy> m_dbusProxy;
};

PolkitAuthorizer::PolkitAuthorizer(sdbus::IConnection& sessionBus) : m_impl(std::make_unique<Impl>(sessionBus)) {}

PolkitAuthorizer::~PolkitAuthorizer() = default;

bool PolkitAuthorizer::authorize(std::string_view actionId, const CallerToken& caller)
{
    return m_impl->authorize(actionId, caller);
}

} // namespace LibreSCRS::Agent
