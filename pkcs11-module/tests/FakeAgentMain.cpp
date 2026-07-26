// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Standalone process that stands up the test FakeAgent on the (private) session
// bus and idles until killed. Used by the Pkcs11ToolRpc integration CTest so an
// external consumer — pkcs11-tool --module librescrs-pkcs11-agent.so — can drive
// the real C_* ABI against a fake card backend, exactly as a deployed app would
// drive it against the real agent. Argv: [hasCard(0|1)] [preReadAuthMethod].

#include "FakeAgent.h"

#include <csignal>
#include <cstdlib>
#include <cstring>
#include <string>

using namespace librescrs_pkcs11_testfake;

namespace {
volatile std::sig_atomic_t g_stop = 0;
void onSignal(int)
{
    g_stop = 1;
}
} // namespace

int main(int argc, char** argv)
{
    const bool hasCard = argc < 2 || std::strcmp(argv[1], "0") != 0;
    const std::string preRead = argc >= 3 ? argv[2] : "None";

    std::signal(SIGTERM, onSignal);
    std::signal(SIGINT, onSignal);

    auto conn = sdbus::createSessionBusConnection();
    FakeAgent fake(*conn, hasCard, preRead);
    conn->requestName(sdbus::ServiceName{kServiceName});
    conn->enterEventLoopAsync();

    // Signal readiness on stdout so the test harness can wait deterministically.
    std::fputs("READY\n", stdout);
    std::fflush(stdout);

    while (g_stop == 0) {
        // The bus runs on its own thread; idle cheaply until terminated.
        struct timespec ts{0, 50 * 1000 * 1000};
        nanosleep(&ts, nullptr);
    }
    conn->leaveEventLoop();
    return 0;
}
