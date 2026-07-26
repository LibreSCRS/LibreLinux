// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <chrono>
#include <cstdint>
#include <functional>
#include <mutex>
#include <unordered_set>
#include <vector>

struct sd_event;
struct sd_event_source;

namespace LibreSCRS::Agent {

// Marshals callbacks onto an sd-event loop thread.
//
// The agent runs card I/O on per-reader worker threads, but a live exported
// D-Bus object's mutable state (e.g. a CardObject's PreReadAuthMethod property)
// may only be touched on the event-loop thread that also dispatches the property
// getters. A worker that resolves such a value hands it here; the callback then
// runs on the loop thread.
//
// The wakeup eventfd is registered as an sd-event io source by the constructor,
// which therefore MUST run on the thread that runs the sd-event loop (production:
// AgentService's main thread, which both installs the loop and runs
// sd_event_loop). post()/postAfter() are thread-safe and may be called from any
// thread: they only queue the callback and write the wakeup eventfd — they never
// touch sd-event state off the loop thread (postAfter hops onto the loop thread
// before arming its timer).
class EventLoopPoster
{
public:
    // Registers the wakeup eventfd as an io source on @p event. Throws
    // std::runtime_error on eventfd/sd-event failure. @p event must remain valid
    // for the poster's lifetime (the io source also holds a ref on it).
    explicit EventLoopPoster(sd_event* event);
    ~EventLoopPoster();

    EventLoopPoster(const EventLoopPoster&) = delete;
    EventLoopPoster& operator=(const EventLoopPoster&) = delete;

    // Queue @p fn to run on the loop thread and wake the loop. Thread-safe; never
    // throws (an allocation failure silently drops the callback to honour the
    // worker-thread no-throw contract). A no-op if @p fn is empty.
    void post(std::function<void()> fn) noexcept;

    // Run @p fn on the loop thread after @p delay (a non-positive delay degrades
    // to an immediate post()). Thread-safe: the one-shot sd-event timer is armed
    // ON the loop thread (it first hops via post()), so this is safe to call from
    // a worker or the monitor thread. Used to reschedule a transiently
    // back-pressured worker hop without busy-spinning the loop.
    void postAfter(std::chrono::microseconds delay, std::function<void()> fn) noexcept;

private:
    struct Timer; // one-shot retry timer context (loop-thread owned)

    static int onReadable(sd_event_source* source, int fd, std::uint32_t revents, void* userdata) noexcept;
    static int onTimer(sd_event_source* source, std::uint64_t usec, void* userdata) noexcept;
    void drain() noexcept;
    void armTimer(std::chrono::microseconds delay, std::function<void()> fn) noexcept; // loop thread only

    sd_event* m_event{nullptr};
    sd_event_source* m_source{nullptr};
    int m_eventfd{-1};
    std::mutex m_mutex;
    std::vector<std::function<void()>> m_pending; // guarded by m_mutex
    // Outstanding one-shot retry timers. Touched ONLY on the loop thread
    // (armTimer / onTimer / the destructor all run there), so no mutex is needed.
    std::unordered_set<Timer*> m_timers;
};

} // namespace LibreSCRS::Agent
