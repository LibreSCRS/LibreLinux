// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// This platform's answer to AgentClientFactory.h, in its own translation unit.
// It is deliberately NOT part of any library the module links: the definition
// belongs to whoever builds a module, so that a second host cannot inherit it
// and end up talking over a transport it does not have.

#include <LibreSCRS/Agent/pkcs11/AgentClientFactory.h>

#include "DBusAgentClient.h"

namespace LibreSCRS::Pkcs11Agent {

std::unique_ptr<AgentClient> makeAgentClient()
{
    return std::make_unique<DBusAgentClient>();
}

} // namespace LibreSCRS::Pkcs11Agent
