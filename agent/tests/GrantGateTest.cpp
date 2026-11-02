// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// The gate a grant runs under after an asynchronous authorization. A grant
// runs on the thread the answer arrived on; the object it runs on may be
// destroyed on another (a card's object on the reader monitor's thread). The
// destructor closes the gate first, so it waits for a grant that is running
// and no grant runs once it has.

#include "dbus/GrantGate.h"

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <mutex>
#include <thread>

using LibreSCRS::Agent::GrantGate;
using namespace std::chrono_literals;

TEST(GrantGate, AnOpenGateRunsTheGrant)
{
    GrantGate gate;
    bool ran = false;
    EXPECT_TRUE(gate.runIfOpen([&ran] { ran = true; }));
    EXPECT_TRUE(ran);
}

TEST(GrantGate, AGrantArrivingAfterTheObjectWentRunsNothing)
{
    GrantGate gate;
    gate.close();
    bool ran = false;
    EXPECT_FALSE(gate.runIfOpen([&ran] { ran = true; }));
    EXPECT_FALSE(ran);
}

// The grant is running when the object's destructor starts: closing waits
// for it to return, so nothing the grant uses is torn down under it.
TEST(GrantGate, AGrantRunningWhenTheObjectGoesHoldsTheDestructor)
{
    GrantGate gate;
    std::mutex mutex;
    std::condition_variable cv;
    bool entered = false;
    bool release = false;
    std::atomic<bool> grantReturned{false};
    std::atomic<bool> closeReturned{false};
    std::atomic<bool> closedBeforeGrantReturned{false};

    std::thread grant([&] {
        gate.runIfOpen([&] {
            std::unique_lock lock{mutex};
            entered = true;
            cv.notify_all();
            cv.wait_for(lock, 5s, [&] { return release; });
            grantReturned = true;
        });
    });
    {
        std::unique_lock lock{mutex};
        ASSERT_TRUE(cv.wait_for(lock, 5s, [&] { return entered; }));
    }

    std::thread destructor([&] {
        gate.close();
        closedBeforeGrantReturned = !grantReturned.load();
        closeReturned = true;
    });

    std::this_thread::sleep_for(300ms);
    EXPECT_FALSE(closeReturned.load()) << "the destructor went on while the grant was still running";

    {
        const std::lock_guard lock{mutex};
        release = true;
    }
    cv.notify_all();
    grant.join();
    destructor.join();
    EXPECT_TRUE(closeReturned.load());
    EXPECT_FALSE(closedBeforeGrantReturned.load());
}
