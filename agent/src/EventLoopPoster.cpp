// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#include "EventLoopPoster.h"
#include <systemd/sd-event.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <unistd.h>
#include <stdexcept>
#include <utility>

namespace LibreSCRS::Agent {

// One-shot retry timer context: owns the callback and the sd-event timer source
// it is bound to. Heap-allocated so it can outlive the postAfter() frame; freed
// by onTimer() when it fires, or by the poster's destructor for timers that
// never fire (shutdown).
struct EventLoopPoster::Timer
{
    EventLoopPoster* poster{nullptr};
    sd_event_source* source{nullptr};
    std::function<void()> fn;
};

EventLoopPoster::EventLoopPoster(sd_event* event) : m_event(event)
{
    m_eventfd = ::eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
    if (m_eventfd < 0) {
        throw std::runtime_error{"EventLoopPoster: eventfd() failed"};
    }
    if (sd_event_add_io(m_event, &m_source, m_eventfd, EPOLLIN, &EventLoopPoster::onReadable, this) < 0) {
        ::close(m_eventfd);
        m_eventfd = -1;
        throw std::runtime_error{"EventLoopPoster: sd_event_add_io() failed"};
    }
    // Best-effort label for journald/strace; non-fatal on failure.
    sd_event_source_set_description(m_source, "librescrs-agent-loop-poster");
}

EventLoopPoster::~EventLoopPoster()
{
    // Loop thread only (by shutdown the loop has returned). Release any pending
    // one-shot retry timers — they can no longer fire — and the wakeup source.
    for (auto* timer : m_timers) {
        if (timer != nullptr) {
            if (timer->source != nullptr) {
                sd_event_source_unref(timer->source);
            }
            delete timer;
        }
    }
    m_timers.clear();
    if (m_source != nullptr) {
        sd_event_source_unref(m_source);
        m_source = nullptr;
    }
    if (m_eventfd >= 0) {
        ::close(m_eventfd);
        m_eventfd = -1;
    }
}

void EventLoopPoster::post(std::function<void()> fn) noexcept
{
    if (!fn) {
        return;
    }
    try {
        std::lock_guard lock(m_mutex);
        m_pending.push_back(std::move(fn));
    } catch (...) {
        return; // allocation failure: drop to honour the noexcept contract
    }
    // Wake the loop. EFD_NONBLOCK: a write only fails (EAGAIN) at counter
    // overflow (2^64-2 un-drained wakeups) — impossible here. Any failure still
    // leaves the callback queued for the next wakeup, so the result is ignored.
    const std::uint64_t one = 1;
    if (::write(m_eventfd, &one, sizeof(one)) < 0) {
        // Intentionally ignored — see above.
    }
}

void EventLoopPoster::postAfter(std::chrono::microseconds delay, std::function<void()> fn) noexcept
{
    if (!fn) {
        return;
    }
    if (delay.count() <= 0) {
        post(std::move(fn));
        return;
    }
    // sd_event_add_time is loop-thread only, so hop onto the loop first (post()
    // is thread-safe) and arm the one-shot timer there.
    post([this, delay, fn = std::move(fn)]() mutable { armTimer(delay, std::move(fn)); });
}

void EventLoopPoster::armTimer(std::chrono::microseconds delay, std::function<void()> fn) noexcept
{
    // Loop thread only.
    std::uint64_t now = 0;
    if (sd_event_now(m_event, CLOCK_MONOTONIC, &now) < 0) {
        // Cannot read the clock; run the work immediately rather than drop it.
        if (fn) {
            try {
                fn();
            } catch (...) {
            }
        }
        return;
    }
    Timer* timer = nullptr;
    try {
        timer = new Timer{this, nullptr, std::move(fn)};
    } catch (...) {
        return; // allocation failure: drop (honour noexcept)
    }
    sd_event_source* src = nullptr;
    if (sd_event_add_time(m_event, &src, CLOCK_MONOTONIC, now + static_cast<std::uint64_t>(delay.count()), 0,
                          &EventLoopPoster::onTimer, timer) < 0) {
        // Scheduling failed; run the work via an immediate post instead of losing it.
        post(std::move(timer->fn));
        delete timer;
        return;
    }
    timer->source = src;
    try {
        m_timers.insert(timer);
    } catch (...) {
        // Tracking failed; the timer will still fire and free itself in onTimer,
        // it just won't be reclaimed early at shutdown. Leave it armed.
    }
    sd_event_source_set_description(src, "librescrs-agent-loop-poster-retry");
}

int EventLoopPoster::onReadable(sd_event_source* /*source*/, int fd, std::uint32_t /*revents*/, void* userdata) noexcept
{
    // Drain the eventfd counter so the level-triggered source does not re-fire.
    std::uint64_t sink = 0;
    if (::read(fd, &sink, sizeof(sink)) < 0) {
        // EAGAIN on a spurious wake — the queue below is still drained.
    }
    auto* self = static_cast<EventLoopPoster*>(userdata);
    if (self != nullptr) {
        self->drain();
    }
    return 0;
}

int EventLoopPoster::onTimer(sd_event_source* source, std::uint64_t /*usec*/, void* userdata) noexcept
{
    auto* timer = static_cast<Timer*>(userdata);
    if (timer == nullptr) {
        return 0;
    }
    auto fn = std::move(timer->fn);
    if (timer->poster != nullptr) {
        timer->poster->m_timers.erase(timer);
    }
    sd_event_source_unref(source); // one-shot: release our ref
    delete timer;
    if (fn) {
        try {
            fn();
        } catch (...) {
        }
    }
    return 0;
}

void EventLoopPoster::drain() noexcept
{
    std::vector<std::function<void()>> batch;
    {
        std::lock_guard lock(m_mutex);
        batch.swap(m_pending);
    }
    // Run callbacks OUTSIDE the lock so a callback may itself post() without
    // self-deadlocking.
    for (auto& fn : batch) {
        if (fn) {
            try {
                fn();
            } catch (...) {
            }
        }
    }
}

} // namespace LibreSCRS::Agent
