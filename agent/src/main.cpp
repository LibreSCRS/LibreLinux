// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#include "AgentService.h"
#include "ConfigPaths.h"
#include "PluginDirectory.h"
#include <LibreSCRS/Agent/backend/Logging.h>
#include <LibreSCRS/Agent/presence/PluginCapabilityResolver.h>
#include <LibreSCRS/Plugin/CardPluginService.h>
#include <cstdlib>
#include <memory>
#include <string>
#include <sys/prctl.h>

#ifndef LIBRELINUX_VERSION_STR
#define LIBRELINUX_VERSION_STR "0.0.1"
#endif
#ifndef LIBRESCRS_DEFAULT_PLUGIN_DIR
#define LIBRESCRS_DEFAULT_PLUGIN_DIR "/usr/lib/librescrs/plugins"
#endif

int main(int /*argc*/, char** /*argv*/)
{
    // Disable core dumps and detach ptrace before any card secret (CAN, PIN,
    // PACE-derived keys) can land in this process's address space. PR_SET_DUMPABLE
    // 0 makes the process non-dumpable: the kernel skips core dumps on crash and
    // refuses PTRACE_ATTACH from a same-UID debugger, closing the most direct
    // route to scraping plaintext secrets out of a live or crashed agent. This is
    // the in-process complement to the unit's LimitCORE=0; both are kept because
    // the binary may also run outside systemd (tests, dev runs).
    //
    // mlock note: we deliberately do NOT mlock secret pages here. The systemd
    // unit's seccomp filter denies @resources, which covers mlock/mlock2/munlock;
    // calling them would be killed by SIGSYS. Adding mlock would require widening
    // that filter and is out of scope for this hardening step.
    ::prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);

    // Wire the logging facade at the composition root. An empty sink selects the
    // built-in journald (syslog-priority-prefixed std::clog) sink; the category
    // is passed explicitly so the librescrs form is owner-visible here.
    LibreSCRS::Agent::log::init({}, "rs.librescrs.agent");

    // Resolve the plugin directory and SAY SO. A directory that yields no
    // plugins makes every card report as unusable, which is indistinguishable
    // from a card nothing supports — so the trail (which source won, which lost,
    // how many plugins loaded, what failed) is logged before anything else can
    // go wrong. Zero loaded is a warning, not a footnote.
    const char* envDir = std::getenv("LIBRESCRS_PLUGIN_DIR");
    const auto pluginDirs = LibreSCRS::Agent::resolvePluginDir(
        {.environment = (envDir && *envDir) ? envDir : "", .compiledDefault = LIBRESCRS_DEFAULT_PLUGIN_DIR});

    auto pluginService = std::make_shared<LibreSCRS::Plugin::CardPluginService>(pluginDirs.dir);
    LibreSCRS::Agent::reportPluginLoad(pluginDirs, *pluginService);

    // Own the resolver on the stack; AgentService takes a reference. The
    // registry share is KEPT here (co-owned with the resolver) so the service
    // can also hand it to the per-card credential depositor, which needs
    // mutable plugin handles the capability seam deliberately does not expose.
    LibreSCRS::Agent::PluginCapabilityResolver resolver(pluginService);
    LibreSCRS::Agent::AgentService agent(resolver, LIBRELINUX_VERSION_STR, LibreSCRS::Agent::resolveConfigFile(),
                                         LibreSCRS::Agent::resolveCacheRoot(), pluginService.get());
    if (!agent.registerOnBus()) {
        return 1;
    }
    agent.run();
    return 0;
}
