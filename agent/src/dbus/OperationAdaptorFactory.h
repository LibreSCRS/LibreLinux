// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <LibreSCRS/Agent/OperationState.h>
#include <LibreSCRS/Agent/backend/OperationChannel.h>
#include "operations/CancelRoute.h"
#include <sdbus-c++/IConnection.h>
#include <sdbus-c++/Types.h>
#include <memory>

namespace LibreSCRS::Agent {

// The bus side of a card operation: each builds the exported Operation1 +
// typed result sub-adaptor at @p path over the state the operation shares with
// it. The agent library's OperationLauncher builds the operation itself around
// the channel, so this file knows nothing of an operation's dependencies.
using ChannelMaker = std::unique_ptr<Operations::OperationChannel> (*)(
    sdbus::IConnection& bus, sdbus::ObjectPath path, std::shared_ptr<Operations::OperationState> state,
    Operations::CancelRoute cancel);

// ReadIdentity. ReadTokenInfo reuses it: its snapshot rides Identity1.Result.
[[nodiscard]] std::unique_ptr<Operations::OperationChannel>
makeIdentityChannel(sdbus::IConnection& bus, sdbus::ObjectPath path, std::shared_ptr<Operations::OperationState> state,
                    Operations::CancelRoute cancel);
[[nodiscard]] std::unique_ptr<Operations::OperationChannel>
makePhotoChannel(sdbus::IConnection& bus, sdbus::ObjectPath path, std::shared_ptr<Operations::OperationState> state,
                 Operations::CancelRoute cancel);
[[nodiscard]] std::unique_ptr<Operations::OperationChannel>
makeCertificatesChannel(sdbus::IConnection& bus, sdbus::ObjectPath path,
                        std::shared_ptr<Operations::OperationState> state, Operations::CancelRoute cancel);
[[nodiscard]] std::unique_ptr<Operations::OperationChannel>
makeSignChannel(sdbus::IConnection& bus, sdbus::ObjectPath path, std::shared_ptr<Operations::OperationState> state,
                Operations::CancelRoute cancel);
[[nodiscard]] std::unique_ptr<Operations::OperationChannel>
makeSignBatchChannel(sdbus::IConnection& bus, sdbus::ObjectPath path, std::shared_ptr<Operations::OperationState> state,
                     Operations::CancelRoute cancel);
// ListCredentials, ManagePin and ActivateSigningKey: Credentials1.Result inline.
[[nodiscard]] std::unique_ptr<Operations::OperationChannel>
makeCredentialsChannel(sdbus::IConnection& bus, sdbus::ObjectPath path,
                       std::shared_ptr<Operations::OperationState> state, Operations::CancelRoute cancel);

} // namespace LibreSCRS::Agent
