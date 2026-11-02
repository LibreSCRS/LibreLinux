// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <LibreSCRS/Agent/wire/SyncError.h>

#include <string>
#include <string_view>

namespace LibreSCRS::Agent {

// Every refusal this bus names is the agent wire's SyncError under the bus
// prefix: one vocabulary for both transports. The agent library maps a broker
// outcome or a credential entry error onto it (toSyncError); this only spells
// the result as an org.librescrs.Agent.Error.* name -- the strings the PKCS#11
// module and every client branch on (common/AgentErrorNames.h).
inline constexpr std::string_view kSyncErrorBusPrefix = "org.librescrs.Agent.Error.";

[[nodiscard]] inline std::string syncErrorBusName(Wire::SyncError error)
{
    return std::string{kSyncErrorBusPrefix}.append(Wire::syncErrorName(error));
}

} // namespace LibreSCRS::Agent
