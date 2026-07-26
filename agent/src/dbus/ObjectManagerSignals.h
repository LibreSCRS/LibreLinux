// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <LibreSCRS/Agent/backend/Logging.h>
#include <sdbus-c++/IObject.h>
#include <exception>

/// @file
/// @brief org.freedesktop.DBus.ObjectManager live-tree announcements.
///
/// sdbus-c++ serves `GetManagedObjects` from its own object registry
/// automatically, but does NOT auto-emit `InterfacesAdded`/`InterfacesRemoved`
/// when an object is registered/unregistered — the object must emit them
/// itself. A client that discovers the tree lazily (the LibreKDE plasmoid's
/// AgentClient) relies on these live signals; without them a freshly inserted
/// card is invisible until the client re-runs `GetManagedObjects` by hand.
///
/// Both helpers are best-effort and `noexcept`: an emit failure is logged and
/// swallowed. That matters on two counts — the removal helper runs from an
/// object destructor (a throwing dtor would abort), and a dropped announcement
/// is recoverable (the client can still fall back to `GetManagedObjects`), so it
/// must never take down the agent.

namespace LibreSCRS::Agent {

/// Announce an object over the ObjectManager. Call AFTER `registerAdaptor()`:
/// the no-arg form iterates every registered interface, queries all properties,
/// and adds the builtin `org.freedesktop.DBus.*` interfaces — the full snapshot
/// a client expects in the `InterfacesAdded` payload.
inline void emitObjectManagerAdded(sdbus::IObject& object, const char* what) noexcept
{
    try {
        object.emitInterfacesAddedSignal();
    } catch (const std::exception& e) {
        log::warnf("ObjectManager: InterfacesAdded emit failed for {}: {}", what, e.what());
    } catch (...) {
        log::warn("ObjectManager: InterfacesAdded emit failed (unknown error)");
    }
}

/// Withdraw an object over the ObjectManager. Call BEFORE `unregisterAdaptor()`
/// (and before destroying the object) so the still-registered interface list can
/// be enumerated for the `InterfacesRemoved` payload.
inline void emitObjectManagerRemoved(sdbus::IObject& object, const char* what) noexcept
{
    try {
        object.emitInterfacesRemovedSignal();
    } catch (const std::exception& e) {
        log::warnf("ObjectManager: InterfacesRemoved emit failed for {}: {}", what, e.what());
    } catch (...) {
        log::warn("ObjectManager: InterfacesRemoved emit failed (unknown error)");
    }
}

} // namespace LibreSCRS::Agent
