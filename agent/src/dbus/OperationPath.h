// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <LibreSCRS/Agent/Identity.h>
#include <sdbus-c++/Types.h>
#include <format>

namespace LibreSCRS::Agent {

// Linux mapping of a core OperationId onto its exported D-Bus object path.
// The core never reconstructs a path; this is the backend's sole owner of the
// OperationId<->op-path relation.
[[nodiscard]] inline sdbus::ObjectPath opObjectPath(OperationId id)
{
    return sdbus::ObjectPath{std::format("/org/librescrs/Agent/op/{}", id.value())};
}

} // namespace LibreSCRS::Agent
