// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <LibreSCRS/Agent/wire/QuiesceReason.h>
#include <functional>
#include <memory>
#include <mutex>
#include <string>

namespace sdbus {
class IConnection;
class IProxy;
} // namespace sdbus

namespace LibreSCRS::Agent {
class AgentCore;

// systemd-logind's events for "the holder's session went away", in the agent's
// one vocabulary. On the system bus it watches:
//
//   Manager.PrepareForSleep(true)                -> SystemSleep
//   the holder's session Lock, or LockedHint true -> ScreenLocked
//   the holder's session Active false            -> SessionInactive
//
// Waking up, unlocking and becoming active again report nothing: what the agent
// forgot on the way out is not restored on the way back. Both lock reports are
// watched because they come from different places -- Lock is someone asking
// logind to lock the session (loginctl lock-session, an idle policy), LockedHint
// is the desktop's screen locker saying it locked -- and a desktop locked from
// its own shortcut sends only the second. One lock can therefore be reported
// twice; revoking the leases a second time costs nothing.
//
// The holder's session is the one logind resolves "auto" to: the caller's own,
// or, for a user service running outside every session as the agent does, the
// user's graphical session. It is looked up once, here; when logind names none,
// only sleep is watched.
//
// The handler runs on the thread that dispatches @p systemBus; the agent attaches
// that connection to its own event loop, so it runs on the dispatcher.
// @p systemBus must outlive the watch.
class SessionLifecycleWatch
{
public:
    using OnQuiesce = std::function<void(QuiesceReason)>;

    SessionLifecycleWatch(sdbus::IConnection& systemBus, OnQuiesce onQuiesce);
    ~SessionLifecycleWatch();
    SessionLifecycleWatch(const SessionLifecycleWatch&) = delete;
    SessionLifecycleWatch& operator=(const SessionLifecycleWatch&) = delete;

    // The session object watched for lock and activity; empty when logind named none.
    [[nodiscard]] const std::string& sessionPath() const noexcept
    {
        return m_sessionPath;
    }

private:
    void watchSession(sdbus::IConnection& systemBus);

    OnQuiesce m_onQuiesce;
    std::string m_sessionPath;
    std::unique_ptr<sdbus::IProxy> m_manager;
    std::unique_ptr<sdbus::IProxy> m_session;
};

// The agent's answer to a lifecycle event: the core forgets what @p reason calls
// for, under @p stateMutex (the lock that serialises the object registry the core
// walks).
void quiesceUnderLock(AgentCore& core, std::mutex& stateMutex, QuiesceReason reason);

// The watch the agent runs: logind on @p systemBus, answered by quiesceUnderLock.
// Every argument must outlive the returned watch.
[[nodiscard]] std::unique_ptr<SessionLifecycleWatch> watchSessionLifecycle(sdbus::IConnection& systemBus,
                                                                           AgentCore& core, std::mutex& stateMutex);

} // namespace LibreSCRS::Agent
