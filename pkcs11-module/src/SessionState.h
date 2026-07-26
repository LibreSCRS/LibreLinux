// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// SessionState — the module's per-process session/object/cursor bookkeeping
// behind the C_* ABI. Holds the live slot model (built from an AgentClient
// snapshot), the slotID<->reader mapping, opaque object handles, and per-session
// find / sign / decrypt cursors. It performs NO D-Bus and NO crypto: Module.cpp
// owns the AgentClient and feeds snapshots in; SessionState answers the pure
// handle/cursor questions. Object handles encode (slot, object-index) so a
// handle resolves without a global object table.

#pragma once

#include "ObjectModel.h"
#include "pkcs11.h"

#include <cstdint>
#include <map>
#include <optional>
#include <vector>

namespace LibreSCRS::Pkcs11Agent {

/// @brief A live sign operation initialised by C_SignInit.
struct SignCursor
{
    bool active = false;
    std::string reader;
    std::string certId;
    std::uint32_t modulusBits = 0;
    std::vector<std::uint8_t> accumulated; ///< For the C_SignUpdate multi-part path.
};

/// @brief A live decrypt operation initialised by C_DecryptInit.
struct DecryptCursor
{
    bool active = false;
    std::string reader;
    std::string certId;
    std::vector<std::uint8_t> accumulated; ///< For the C_DecryptUpdate multi-part path.
};

/// @brief A live C_FindObjects enumeration.
struct FindCursor
{
    bool active = false;
    std::vector<CK_OBJECT_HANDLE> matches;
    std::size_t next = 0;
};

/// @brief One open PKCS#11 session.
struct Session
{
    CK_SLOT_ID slot = 0;
    CK_FLAGS flags = 0;
    bool loggedIn = false;
    FindCursor find;
    SignCursor sign;
    DecryptCursor decrypt;
    /// @brief A blocking agent RPC (login / sign / decrypt) is in flight on this
    ///        session, with the global lock RELEASED. Re-entrant blocking calls
    ///        on the same session are refused (CKR_OPERATION_ACTIVE) so the op
    ///        cursors cannot be mutated under the running RPC.
    bool rpcInFlight = false;
};

/// @brief Per-process session/object state behind the C_* ABI.
class SessionState
{
public:
    /// @brief Replace the slot model from a fresh agent snapshot. Slot IDs are
    ///        assigned by reader-path order and kept STABLE across refreshes so
    ///        a slot id a caller holds keeps meaning the same reader.
    void setModel(ObjectModel model);

    [[nodiscard]] const ObjectModel& model() const noexcept
    {
        return m_model;
    }

    /// @brief All slot IDs (optionally only token-present ones).
    [[nodiscard]] std::vector<CK_SLOT_ID> slotIds(bool tokenPresentOnly) const;

    /// @brief Resolve a slot id to its model slot (nullptr if unknown).
    [[nodiscard]] const Slot* slotById(CK_SLOT_ID id) const;

    // --- sessions ----------------------------------------------------------
    [[nodiscard]] CK_SESSION_HANDLE openSession(CK_SLOT_ID slot, CK_FLAGS flags);
    [[nodiscard]] Session* session(CK_SESSION_HANDLE h);
    bool closeSession(CK_SESSION_HANDLE h);
    void closeAllSessions(CK_SLOT_ID slot);
    /// @brief Slot ids that still have at least one open session.
    [[nodiscard]] bool slotHasSessions(CK_SLOT_ID slot) const;

    // --- objects -----------------------------------------------------------
    /// @brief Encode an object handle from (slot, object index).
    [[nodiscard]] static CK_OBJECT_HANDLE encodeHandle(CK_SLOT_ID slot, std::size_t objIndex);
    /// @brief Decode -> the Object* on the given session's slot (nullptr if stale).
    [[nodiscard]] const Object* resolveObject(CK_SLOT_ID slot, CK_OBJECT_HANDLE h) const;

    /// @brief Object handles on @p slot matching @p tmpl (CKA_CLASS / CKA_ID).
    [[nodiscard]] std::vector<CK_OBJECT_HANDLE> findMatches(CK_SLOT_ID slot, CK_ATTRIBUTE_PTR tmpl,
                                                            CK_ULONG count) const;

private:
    ObjectModel m_model;
    std::map<std::string, CK_SLOT_ID> m_readerToSlot; ///< stable reader-path -> slot id
    CK_SLOT_ID m_nextSlotId = 0;
    std::map<CK_SLOT_ID, std::size_t> m_slotIndex; ///< slot id -> index into m_model.slots
    std::map<CK_SESSION_HANDLE, Session> m_sessions;
    CK_SESSION_HANDLE m_nextSession = 1;
};

} // namespace LibreSCRS::Pkcs11Agent
