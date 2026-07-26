// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Entry point for the headless environment-driven test prompter
// (librescrs-pinentry-test): claims org.librescrs.Prompter1 on whatever bus
// DBUS_SESSION_BUS_ADDRESS points at (a private dbus-run-session bus for an
// automated end-to-end test, or a real session bus for a manual lab run) and
// answers RequestSecret from LIBRESCRS_TEST_PIN / LIBRESCRS_TEST_CAN /
// LIBRESCRS_TEST_MRZ instead of raising a dialog. See EnvPrompterService.h
// for the caller-authorisation and burn-through-guard discipline.
//
// NEVER installed: this target lives in prompter/tests/ (no install() rule
// reaches it anywhere in this tree) — the packaged prompter selection is
// file-only config (org.librescrs.Prompter1.service.in's Exec= line always
// names librescrs-pinentry-kde), so production D-Bus activation can never
// start this binary. Reachable only by explicitly running it against a bus.

#include "EnvPrompterService.h"

#include <sdbus-c++/IConnection.h>
#include <sdbus-c++/sdbus-c++.h>

#include <cstdio>
#include <memory>

namespace {
constexpr const char* kServiceName = "org.librescrs.Prompter1";
constexpr const char* kRootPath = "/org/librescrs/Prompter1";
} // namespace

int main()
{
    std::unique_ptr<sdbus::IConnection> connection;
    try {
        connection = sdbus::createSessionBusConnection();
    } catch (const sdbus::Error& e) {
        std::fprintf(stderr, "librescrs-pinentry-test: failed to open session bus: %s\n", e.getMessage().c_str());
        return 1;
    }

    try {
        connection->requestName(sdbus::ServiceName{kServiceName});
    } catch (const sdbus::Error& e) {
        // Already running, or another prompter owns the well-known name.
        std::fprintf(stderr, "librescrs-pinentry-test: name %s already taken: %s\n", kServiceName,
                     e.getMessage().c_str());
        return 1;
    }

    std::unique_ptr<LibreLinux::Prompter::EnvPrompterService> service;
    try {
        service = std::make_unique<LibreLinux::Prompter::EnvPrompterService>(*connection, sdbus::ObjectPath{kRootPath});
    } catch (const std::exception& e) {
        std::fprintf(stderr, "librescrs-pinentry-test: failed to export Prompter1 adaptor: %s\n", e.what());
        return 1;
    }

    // Synchronous loop: this is a standalone tool meant to run until the
    // harness (or a lab operator) terminates it, not a library component.
    connection->enterEventLoop();

    service.reset();
    try {
        connection->releaseName(sdbus::ServiceName{kServiceName});
    } catch (...) {
        // Best-effort during shutdown.
    }
    return 0;
}
