// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#include "SessionLifecycleWatch.h"
#include <LibreSCRS/Agent/AgentCore.h>
#include <LibreSCRS/Logging.h>
#include <sdbus-c++/Error.h>
#include <sdbus-c++/IConnection.h>
#include <sdbus-c++/IProxy.h>
#include <sdbus-c++/Types.h>
#include <chrono>
#include <exception>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace LibreSCRS::Agent {

namespace {
constexpr const char* kLogindService = "org.freedesktop.login1";
constexpr const char* kLogindPath = "/org/freedesktop/login1";
constexpr const char* kManagerIface = "org.freedesktop.login1.Manager";
constexpr const char* kSessionIface = "org.freedesktop.login1.Session";
constexpr const char* kPropertiesIface = "org.freedesktop.DBus.Properties";

// The one blocking call the watch makes, at agent start-up: long enough for a
// busy logind, short enough that a wedged one does not hold the agent's start.
constexpr std::chrono::seconds kSessionLookupBudget{3};

// Hand @p reason to @p handler (a quiesce or the end of one, named by @p what
// in the log) without letting a failure escape into the bus dispatch that
// delivered the event. One function for both: the two handler types are the
// same type, so two overloads would collide.
void deliver(const SessionLifecycleWatch::OnQuiesce& handler, QuiesceReason reason, const char* what) noexcept
{
    try {
        handler(reason);
    } catch (const std::exception& e) {
        log::warnf("session lifecycle: {} for reason {} failed: {}", what, static_cast<unsigned>(reason), e.what());
    } catch (...) {
        log::warnf("session lifecycle: {} for reason {} failed", what, static_cast<unsigned>(reason));
    }
}
} // namespace

SessionLifecycleWatch::SessionLifecycleWatch(sdbus::IConnection& systemBus, OnQuiesce onQuiesce, OnResume onResume)
    : m_onQuiesce(std::move(onQuiesce)), m_onResume(std::move(onResume))
{
    m_manager = sdbus::createProxy(systemBus, sdbus::ServiceName{kLogindService}, sdbus::ObjectPath{kLogindPath});
    m_manager->uponSignal(sdbus::SignalName{"PrepareForSleep"})
        .onInterface(sdbus::InterfaceName{kManagerIface})
        .call([this](bool start) {
            if (start) {
                deliver(m_onQuiesce, QuiesceReason::SystemSleep, "quiesce");
            } else {
                deliver(m_onResume, QuiesceReason::SystemSleep, "resume");
            }
        });
    watchSession(systemBus);
}

SessionLifecycleWatch::~SessionLifecycleWatch() = default;

void SessionLifecycleWatch::watchSession(sdbus::IConnection& systemBus)
{
    sdbus::ObjectPath session;
    try {
        m_manager->callMethod("GetSession")
            .onInterface(sdbus::InterfaceName{kManagerIface})
            .withTimeout(kSessionLookupBudget)
            .withArguments(std::string{"auto"})
            .storeResultsTo(session);
    } catch (const sdbus::Error& e) {
        log::infof("session lifecycle: logind names no session for this user ({}); only sleep is watched",
                   e.getMessage());
        return;
    }
    m_sessionPath = session;
    m_session = sdbus::createProxy(systemBus, sdbus::ServiceName{kLogindService}, std::move(session));
    m_session->uponSignal(sdbus::SignalName{"Lock"}).onInterface(sdbus::InterfaceName{kSessionIface}).call([this] {
        deliver(m_onQuiesce, QuiesceReason::ScreenLocked, "quiesce");
    });
    m_session->uponSignal(sdbus::SignalName{"PropertiesChanged"})
        .onInterface(sdbus::InterfaceName{kPropertiesIface})
        .call([this](const std::string& iface, const std::map<std::string, sdbus::Variant>& changed,
                     const std::vector<std::string>& /*invalidated*/) {
            if (iface != kSessionIface) {
                return;
            }
            // logind sends a property only when it changed, so a value is a transition.
            const auto boolean = [&changed](const char* name) -> std::optional<bool> {
                const auto it = changed.find(name);
                if (it == changed.end()) {
                    return std::nullopt;
                }
                try {
                    return it->second.get<bool>();
                } catch (const sdbus::Error&) {
                    return std::nullopt; // not a boolean: not logind's property
                }
            };
            if (const auto active = boolean("Active")) {
                if (*active) {
                    deliver(m_onResume, QuiesceReason::SessionInactive, "resume");
                } else {
                    deliver(m_onQuiesce, QuiesceReason::SessionInactive, "quiesce");
                }
            }
            if (const auto locked = boolean("LockedHint")) {
                if (*locked) {
                    deliver(m_onQuiesce, QuiesceReason::ScreenLocked, "quiesce");
                } else {
                    deliver(m_onResume, QuiesceReason::ScreenLocked, "resume");
                }
            }
        });
    log::infof("session lifecycle: watching logind session {}", m_sessionPath);
}

void quiesceUnderLock(AgentCore& core, std::mutex& stateMutex, QuiesceReason reason)
{
    {
        const std::lock_guard lock(stateMutex);
        core.quiesce(reason);
    }
    log::infof("session lifecycle: card access quiesced (reason {})", static_cast<unsigned>(reason));
}

void resumeUnderLock(AgentCore& core, std::mutex& stateMutex)
{
    {
        const std::lock_guard lock(stateMutex);
        core.resume();
    }
    log::infof("session lifecycle: card holds resumed after wake");
}

std::unique_ptr<SessionLifecycleWatch> watchSessionLifecycle(sdbus::IConnection& systemBus, AgentCore& core,
                                                             std::mutex& stateMutex, LifecycleNotifier notifier)
{
    // Every callback runs on the dispatch thread of systemBus, so the set needs
    // no lock of its own; the notifier is called outside stateMutex.
    auto active = std::make_shared<QuiesceSet>();
    auto shared = std::make_shared<const LifecycleNotifier>(std::move(notifier));
    return std::make_unique<SessionLifecycleWatch>(
        systemBus,
        [&core, &stateMutex, active, shared](QuiesceReason reason) {
            quiesceUnderLock(core, stateMutex, reason);
            active->begin(reason);
            if (shared->quiesced) {
                shared->quiesced(reason);
            }
        },
        [&core, &stateMutex, active, shared](QuiesceReason reason) {
            if (reason == QuiesceReason::SystemSleep) {
                resumeUnderLock(core, stateMutex);
            }
            if (active->end(reason) && shared->resumed) {
                shared->resumed(reason);
            }
        });
}

} // namespace LibreSCRS::Agent
