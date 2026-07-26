// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include "dbus/ObjectManagerSignals.h" // emitObjectManagerAdded/Removed
#include "org.librescrs.Agent.Reader1_adaptor.h"
#include <sdbus-c++/AdaptorInterfaces.h>
#include <sdbus-c++/IConnection.h>
#include <sdbus-c++/Types.h>
#include <mutex>
#include <string>
#include <utility>
#include <vector>
namespace LibreSCRS::Agent {
// Real exported D-Bus object at /org/librescrs/Agent/reader/<n>.
// Name is fixed at construction; HasCard/Card are live — updated via
// updateCardPresence() on insert/remove, which emits
// org.freedesktop.DBus.Properties.PropertiesChanged so observers never see
// stale presence.
class ReaderObject final : public sdbus::AdaptorInterfaces<org::librescrs::Agent::Reader1_adaptor>
{
public:
    ReaderObject(sdbus::IConnection& connection, sdbus::ObjectPath path, std::string name, bool hasCard,
                 sdbus::ObjectPath card)
        : AdaptorInterfaces(connection, std::move(path)), m_name(std::move(name)), m_hasCard(hasCard),
          m_card(std::move(card))
    {
        registerAdaptor();
        // Announce over the ObjectManager so a client tracking the live tree sees
        // the reader immediately (sdbus-c++ does not auto-emit InterfacesAdded).
        emitObjectManagerAdded(getObject(), "reader");
    }
    ~ReaderObject()
    {
        // Withdraw BEFORE unregistering, while the interface list is still
        // enumerable, so live-tracking clients see the reader leave.
        emitObjectManagerRemoved(getObject(), "reader");
        unregisterAdaptor();
    }

    /// Reader's human-readable name (the underlying-platform identifier
    /// used to open a CardSession). Set once at construction.
    [[nodiscard]] const std::string& name() const noexcept
    {
        return m_name;
    }

    /// An ATOMIC snapshot of the live presence fields (m_hasCard / m_card) plus
    /// the immutable name, taken under a SINGLE lock so a consumer never observes
    /// a torn {hasCard, card} pair (e.g. hasCard=true alongside a just-cleared
    /// card path). m_card is "/" when no card. Consumed by the PKCS#11 host to
    /// resolve a reader path to the card it currently holds.
    struct PresenceSnapshot
    {
        bool hasCard;
        sdbus::ObjectPath card;
        std::string name;
    };
    [[nodiscard]] PresenceSnapshot snapshot() const
    {
        const std::lock_guard guard(m_mutex);
        return {m_hasCard, m_card, m_name};
    }

    /// Update the live HasCard/Card presence and emit a single
    /// PropertiesChanged for whichever of the two actually changed. A no-op
    /// (no signal) when both already hold the requested values.
    void updateCardPresence(bool hasCard, sdbus::ObjectPath card)
    {
        std::vector<sdbus::PropertyName> changed;
        {
            // Mutate the live presence fields under the lock so the loop-thread
            // resolveReaderCard reader and the bus-thread HasCard()/Card()
            // property getters never observe a torn value. The PropertiesChanged
            // emission is deliberately kept OUTSIDE the lock: it takes the sd-bus
            // connection lock, and holding m_mutex across a bus call would invert
            // the bus/agent lock order.
            const std::lock_guard guard(m_mutex);
            if (m_hasCard != hasCard) {
                m_hasCard = hasCard;
                changed.emplace_back("HasCard");
            }
            if (m_card != card) {
                m_card = std::move(card);
                changed.emplace_back("Card");
            }
        }
        if (changed.empty()) {
            return;
        }
        getObject().emitPropertiesChangedSignal(sdbus::InterfaceName{Reader1_adaptor::INTERFACE_NAME}, changed);
    }

private:
    std::string Name() override
    {
        return m_name;
    }
    bool HasCard() override
    {
        const std::lock_guard guard(m_mutex);
        return m_hasCard;
    }
    sdbus::ObjectPath Card() override
    {
        const std::lock_guard guard(m_mutex);
        return m_card;
    }
    // Guards the live presence fields (m_hasCard / m_card): the monitor-thread
    // updateCardPresence writer must not tear against the loop-thread
    // resolveReaderCard reader or the bus-thread Reader1 property getters.
    // m_name is set once at construction and never mutated, so it needs no guard.
    mutable std::mutex m_mutex;
    std::string m_name;
    bool m_hasCard;
    sdbus::ObjectPath m_card;
};
} // namespace LibreSCRS::Agent
