// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#include "PolkitAuthorizer.h"
#include <LibreSCRS/Logging.h>
#include "ProcPidPin.h" // librelinux-common pinned /proc readers

#include <sdbus-c++/Error.h>
#include <sdbus-c++/IConnection.h>
#include <sdbus-c++/IProxy.h>
#include <sdbus-c++/Types.h>
#include <chrono>
#include <optional>
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

// CheckAuthorization is answered by a PERSON, not by a machine: with
// AllowUserInteraction set, an auth_self action puts a password dialog on
// screen and this call does not return until it is answered. The inherited
// D-Bus default of 25s is a machine's budget and it expires mid-ceremony.
//
// Sized deliberately BELOW the client's own authorized-call budget
// (AgentClient::kAuthorizedCallTimeoutMs, 120000ms) with room left for the
// rest of the method. If this leg outlasted the client's, the client would
// abandon the call while the agent went on to APPLY the change, and the user
// would be told nothing happened after something did -- the same lie this
// fix removes, pointed the other way.
constexpr std::chrono::seconds kAuthorizationBudget{90};

} // namespace

namespace PolkitDetail {

sdbus::Variant uidDetail(std::uint32_t uid)
{
    // polkit reads "uid" as a signed 32-bit integer and ignores one of any
    // other type -- and a pidfd subject without a uid is refused. The bus
    // reports the uid unsigned; the cast keeps every bit of it.
    return sdbus::Variant{static_cast<std::int32_t>(uid)};
}

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
        details.emplace("uid", uidDetail(*uid));
    }
    return details;
}

std::optional<std::map<std::string, sdbus::Variant>>
unixProcessDetailsFrom(const std::map<std::string, sdbus::Variant>& credentials,
                       const std::function<std::optional<std::uint64_t>(std::uint32_t)>& startTimeOf)
{
    try {
        std::optional<std::uint32_t> uid;
        if (const auto it = credentials.find("UnixUserID"); it != credentials.end()) {
            uid = it->second.get<std::uint32_t>();
        }
        // polkit takes a pidfd only together with the uid; without one it
        // rejects the subject outright, so a pidfd alone falls back to the pid.
        if (const auto it = credentials.find("ProcessFD"); it != credentials.end() && uid.has_value()) {
            std::map<std::string, sdbus::Variant> details;
            details.emplace("pidfd", sdbus::Variant{it->second.get<sdbus::UnixFd>()});
            details.emplace("uid", uidDetail(*uid));
            return details;
        }
        const auto it = credentials.find("ProcessID");
        if (it == credentials.end()) {
            return std::nullopt;
        }
        const auto pid = it->second.get<std::uint32_t>();
        const auto startTime = startTimeOf(pid);
        if (!startTime.has_value()) {
            return std::nullopt;
        }
        return buildUnixProcessDetails(pid, *startTime, uid);
    } catch (const sdbus::Error&) {
        return std::nullopt; // a member of an unexpected type
    }
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
        // The asynchronous CheckAuthorization's reply is read here, on this
        // connection's own thread, never on the agent's dispatcher.
        m_systemBus->enterEventLoopAsync();
    }

    ~Impl()
    {
        // Stop the reply thread before the proxies its handlers use go away. A
        // CheckAuthorization still pending is dropped with its proxy; its
        // completion never runs, and the deferred reply it held tells the
        // caller that nothing was changed (authorizeThenReply).
        m_systemBus->leaveEventLoop();
        m_polkitProxy.reset();
    }

    Impl(const Impl&) = delete;
    Impl& operator=(const Impl&) = delete;
    Impl(Impl&&) = delete;
    Impl& operator=(Impl&&) = delete;

    void setPost(Post post)
    {
        m_post = std::move(post);
    }

    AuthorizationOutcome authorize(std::string_view actionId, const CallerToken& caller)
    {
        auto subject = subjectFor(caller);
        if (!subject) {
            return AuthorizationOutcome::Undecided;
        }
        try {
            CheckAuthorizationReply reply;
            m_polkitProxy->callMethod("CheckAuthorization")
                .onInterface(sdbus::InterfaceName{kPolkitIface})
                .withTimeout(kAuthorizationBudget)
                .withArguments(*subject, std::string{actionId}, std::map<std::string, std::string>{},
                               kAllowUserInteraction, std::string{})
                .storeResultsTo(reply);
            return outcomeOf(reply);
        } catch (const sdbus::Error& e) {
            log::warnf("PolkitAuthorizer: CheckAuthorization failed: {}; undecided", e.getMessage());
            return AuthorizationOutcome::Undecided;
        } catch (const std::exception& e) {
            log::warnf("PolkitAuthorizer: CheckAuthorization threw: {}; undecided", e.what());
            return AuthorizationOutcome::Undecided;
        }
    }

    void authorizeAsync(std::string_view actionId, const CallerToken& caller, Completion done)
    {
        auto subject = subjectFor(caller);
        if (!subject) {
            done(AuthorizationOutcome::Undecided);
            return;
        }
        try {
            m_polkitProxy->callMethodAsync("CheckAuthorization")
                .onInterface(sdbus::InterfaceName{kPolkitIface})
                .withTimeout(kAuthorizationBudget)
                .withArguments(*subject, std::string{actionId}, std::map<std::string, std::string>{},
                               kAllowUserInteraction, std::string{})
                .uponReplyInvoke([this, done](std::optional<sdbus::Error> error, CheckAuthorizationReply reply) {
                    AuthorizationOutcome outcome = AuthorizationOutcome::Undecided;
                    if (error) {
                        log::warnf("PolkitAuthorizer: CheckAuthorization failed: {}; undecided", error->getMessage());
                    } else {
                        outcome = outcomeOf(reply);
                    }
                    deliver(done, outcome);
                });
        } catch (const std::exception& e) {
            log::warnf("PolkitAuthorizer: CheckAuthorization could not be sent: {}; undecided", e.what());
            done(AuthorizationOutcome::Undecided);
        }
    }

private:
    using Subject = sdbus::Struct<std::string, std::map<std::string, sdbus::Variant>>;
    using CheckAuthorizationReply = sdbus::Struct<bool, bool, std::map<std::string, std::string>>;

    static AuthorizationOutcome outcomeOf(const CheckAuthorizationReply& reply)
    {
        return PolkitDetail::interpretReply(reply.get<0>(), reply.get<1>()) ? AuthorizationOutcome::Granted
                                                                            : AuthorizationOutcome::Denied;
    }

    void deliver(const Completion& done, AuthorizationOutcome outcome) const
    {
        if (m_post) {
            m_post([done, outcome] { done(outcome); });
        } else {
            done(outcome);
        }
    }

    // The polkit subject for @p caller: ("unix-process", {pid, start-time,
    // uid}). nullopt -- and a logged reason -- when there is nothing to ask
    // polkit about; nothing was decided then.
    std::optional<Subject> subjectFor(const CallerToken& caller)
    {
        // The transport-resolved caller token carries the Linux unique bus name;
        // derive it once and reuse for the credentials lookup and the warn logs.
        const std::string busName{caller.str()};

        // Empty bus name -> an internal/agent-originated mutation (no external
        // D-Bus caller). We do NOT consult polkit (there is no subject to
        // build) — nothing was decided, so this is Undecided like every other
        // "could not even ask" case below, not a policy Denial.
        if (busName.empty()) {
            log::warn("PolkitAuthorizer: empty caller bus name; undecided (no polkit subject)");
            return std::nullopt;
        }

        std::map<std::string, sdbus::Variant> credentials;
        try {
            m_dbusProxy->callMethod("GetConnectionCredentials")
                .onInterface(sdbus::InterfaceName{kDBusIface})
                .withArguments(busName)
                .storeResultsTo(credentials);
        } catch (const std::exception& e) {
            log::warnf("PolkitAuthorizer: GetConnectionCredentials({}) failed: {}; undecided", busName, e.what());
            return std::nullopt;
        }
        auto details = PolkitDetail::unixProcessDetailsFrom(credentials, &readStartTime);
        if (!details.has_value()) {
            log::warnf("PolkitAuthorizer: no pidfd, or no pid and start time, for {}; undecided", busName);
            return std::nullopt;
        }
        // CheckAuthorization signature: (sa{sv}) s a{ss} u s -> (b b a{ss}).
        // subject = ("unix-process", details); empty action-details; flags
        // with AllowUserInteraction; empty cancellation id. Timeout widened
        // to kAuthorizationBudget -- see its comment above.
        return Subject{std::string{"unix-process"}, std::move(*details)};
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
    Post m_post;
};

PolkitAuthorizer::PolkitAuthorizer(sdbus::IConnection& sessionBus) : m_impl(std::make_unique<Impl>(sessionBus)) {}

PolkitAuthorizer::~PolkitAuthorizer() = default;

AuthorizationOutcome PolkitAuthorizer::authorize(std::string_view actionId, const CallerToken& caller)
{
    return m_impl->authorize(actionId, caller);
}

void PolkitAuthorizer::authorizeAsync(std::string_view actionId, const CallerToken& caller, Completion done)
{
    m_impl->authorizeAsync(actionId, caller, std::move(done));
}

void PolkitAuthorizer::deliverAnswersThrough(Post post)
{
    m_impl->setPost(std::move(post));
}

} // namespace LibreSCRS::Agent
