// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <functional>
#include <string>

namespace LibreSCRS::Agent::Operations {

// Who may end an operation over the bus, and what ending it runs. Operation
// paths are sequential, so any client can name another's operation: only the
// unique bus name that launched it (`owner`) is heard. An empty owner or an
// empty `run` makes Operation1.Cancel a no-op.
struct CancelRoute
{
    std::string owner;
    std::function<void()> run;
};

} // namespace LibreSCRS::Agent::Operations
