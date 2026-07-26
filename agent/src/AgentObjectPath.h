// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// The backend's SOLE ObjectId <-> D-Bus object-path bijection. The neutral agent
// core traffics ONLY in opaque ObjectIds (PresenceModel mints them, the
// OperationManager keys its per-reader workers by them, the CardKeyTracker and
// LeaseManager key on them); the wire object paths under /org/librescrs/Agent
// live only here, in the platform backend. agentObjectPath() composes a path
// from an id; objectIdFromPath() recovers the id from a path this backend itself
// composed (its inverse). Both directions are owned here so the two can never
// drift.
//
// Header-only; depends only on the shared wire-name table (kRootPath) and the
// neutral ObjectId newtype.

#pragma once
#include "AgentInterfaceNames.h" // LibreLinux::AgentWire::kRootPath
#include <LibreSCRS/Agent/Identity.h>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <system_error>

namespace LibreSCRS::Agent {

// Opaque-counter -> object path, e.g.
//   agentObjectPath("reader", ObjectId{1}) == "/org/librescrs/Agent/reader/1".
// The ObjectId is a single per-process monotonic counter, so reader and card
// paths never collide and a bare withdraw(ObjectId) maps to exactly one object.
inline std::string agentObjectPath(std::string_view kind, ObjectId id)
{
    return std::string(LibreLinux::AgentWire::kRootPath) + "/" + std::string(kind) + "/" + std::to_string(id.value());
}

// Inverse of agentObjectPath: recover the ObjectId from a path THIS backend
// composed (its trailing "/<n>" segment). Returns an invalid ObjectId{} for a
// path with no numeric tail ("/" or a malformed path). Used to key the neutral
// core's ObjectId-keyed surfaces (the OperationManager worker map, the
// LeaseManager card component) from a reader/card path that arrived over the wire.
inline ObjectId objectIdFromPath(std::string_view path)
{
    const auto slash = path.rfind('/');
    if (slash == std::string_view::npos || slash + 1 >= path.size()) {
        return ObjectId{};
    }
    // Parse the trailing "/<n>" segment with std::from_chars: it rejects a
    // non-numeric or empty tail (invalid_argument), a value that would overflow
    // uint64 (result_out_of_range — the old value*10+digit accumulation silently
    // WRAPPED), and — via the ptr!=last check — any trailing junk after the digits
    // (from_chars stops at the first non-digit, and a '-'/'+' sign is not a digit
    // for an unsigned target). Only a fully-consumed, in-range numeric tail is a
    // path THIS backend composed; anything else recovers ObjectId{} (invalid).
    const char* const first = path.data() + slash + 1;
    const char* const last = path.data() + path.size();
    std::uint64_t value = 0;
    const auto [ptr, ec] = std::from_chars(first, last, value);
    if (ec != std::errc{} || ptr != last) {
        return ObjectId{};
    }
    return ObjectId{value};
}

} // namespace LibreSCRS::Agent
