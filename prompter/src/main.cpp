// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "PrompterService.h"

#include <KAboutData>
#include <KLocalizedString>

#include <QApplication>
#include <QCoreApplication>

#include <sdbus-c++/IConnection.h>
#include <sdbus-c++/sdbus-c++.h>

#include <cstdio>
#include <exception>
#include <memory>

#include <sys/prctl.h>

namespace {

constexpr const char* kServiceName = "org.librescrs.Prompter1";
constexpr const char* kRootPath = "/org/librescrs/Prompter1";

} // namespace

int main(int argc, char* argv[])
{
    // Disable core dumps and detach ptrace before QApplication starts and long
    // before any plaintext PIN reaches this process. PR_SET_DUMPABLE 0 makes the
    // process non-dumpable: the kernel skips core dumps on crash and refuses
    // PTRACE_ATTACH from a same-UID debugger, so the typed-in PIN cannot be
    // scraped from a core file or an attached tracer. This complements the unit's
    // LimitCORE=0 and matters even more here than in the agent because this binary
    // briefly holds the user's secret in plaintext. Set first so it also covers
    // any crash during Qt/KF6 platform-plugin startup.
    ::prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);

    // QApplication MUST come first: it sets the per-thread event loop the
    // sdbus-c++ worker will marshal Qt-thread invocations into.
    QApplication app(argc, argv);
    QCoreApplication::setOrganizationName(QStringLiteral("LibreSCRS"));
    QCoreApplication::setOrganizationDomain(QStringLiteral("librescrs.github.io"));
    QCoreApplication::setApplicationName(QStringLiteral("librescrs-pinentry-kde"));

    // KAboutData wiring is the KDE standard for crash reporting + the
    // "About this application" affordance Plasma surfaces around modal
    // dialogs. Component name matches the binary so KCrash + plasma-
    // notify can attribute correctly.
    KLocalizedString::setApplicationDomain(QByteArrayLiteral("librescrs-pinentry-kde"));
    KAboutData aboutData(
        QStringLiteral("librescrs-pinentry-kde"), i18nc("@title application name", "LibreSCRS Pinentry"),
        QStringLiteral(LIBRELINUX_VERSION_STR),
        i18nc("@info:tooltip short description", "Secure-input prompter for the LibreSCRS smart-card agent."),
        KAboutLicense::LGPL_V2_1);
    KAboutData::setApplicationData(aboutData);

    std::unique_ptr<sdbus::IConnection> connection;
    try {
        connection = sdbus::createSessionBusConnection();
    } catch (const sdbus::Error& e) {
        std::fprintf(stderr, "librescrs-pinentry-kde: failed to open session bus: %s\n", e.getMessage().c_str());
        return 1;
    }

    try {
        connection->requestName(sdbus::ServiceName{kServiceName});
    } catch (const sdbus::Error& e) {
        // Already running, or another agent owns the well-known name —
        // either way, exit cleanly so D-Bus activation does not loop.
        std::fprintf(stderr, "librescrs-pinentry-kde: name %s already taken: %s\n", kServiceName,
                     e.getMessage().c_str());
        return 1;
    }

    std::unique_ptr<LibreLinux::Prompter::PrompterService> service;
    try {
        service = std::make_unique<LibreLinux::Prompter::PrompterService>(*connection, sdbus::ObjectPath{kRootPath});
    } catch (const std::exception& e) {
        std::fprintf(stderr, "librescrs-pinentry-kde: failed to export Prompter1 adaptor: %s\n", e.what());
        return 1;
    }

    // sdbus-c++ pumps inbound traffic on its own worker thread; Qt pumps
    // UI on the main thread. PrompterService::RequestSecret bridges with
    // QMetaObject::invokeMethod(Qt::BlockingQueuedConnection).
    connection->enterEventLoopAsync();

    const int rc = app.exec();

    // Tear down in reverse: stop dispatching method calls before the
    // adaptor unregisters, then drop the name and let the connection
    // close in its own dtor.
    connection->leaveEventLoop();
    service.reset();
    try {
        connection->releaseName(sdbus::ServiceName{kServiceName});
    } catch (...) {
        // Best-effort during shutdown.
    }
    return rc;
}
