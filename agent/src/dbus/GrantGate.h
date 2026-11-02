// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <mutex>

namespace LibreSCRS::Agent {

// What a deferred grant runs under, held by the object it runs on.
//
// A synchronous handler ran under the bus dispatcher, and an object is
// withdrawn from the bus only between two dispatches -- so its destructor
// waited for a handler that was running. A grant that runs after an
// asynchronous authorization has no such wait: it runs on whatever thread the
// answer arrives on, while a card's object may be destroyed on the reader
// monitor's thread. The object therefore closes its gate first thing in its
// destructor: a grant already running holds the destructor until it returns,
// and one that arrives afterwards finds the gate closed and runs nothing.
class GrantGate
{
public:
    // Run @p body unless the gate is closed. Returns whether it ran.
    template <typename Body>
    bool runIfOpen(const Body& body)
    {
        const std::lock_guard lock{m_mutex};
        if (m_closed) {
            return false;
        }
        body();
        return true;
    }

    // Close the gate: wait for a body that is running; none runs afterwards.
    void close() noexcept
    {
        const std::lock_guard lock{m_mutex};
        m_closed = true;
    }

private:
    std::mutex m_mutex;
    bool m_closed = false;
};

} // namespace LibreSCRS::Agent
