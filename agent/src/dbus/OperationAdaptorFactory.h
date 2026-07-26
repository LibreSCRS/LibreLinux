// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include "operations/ActivateSigningKeyOperation.h"
#include "operations/GetPhotoOperation.h"
#include "operations/ListCredentialsOperation.h"
#include "operations/ManagePinOperation.h"
#include <LibreSCRS/Agent/operations/OperationBase.h>
#include "operations/ReadCertificatesOperation.h"
#include "operations/ReadIdentityOperation.h"
#include "operations/ReadTokenInfoOperation.h"
#include "operations/SignBatchOperation.h"
#include "operations/SignOperation.h"
#include <sdbus-c++/IConnection.h>
#include <sdbus-c++/Types.h>
#include <memory>

namespace LibreSCRS::Agent {

// Backend adaptor factories. Each builds the sdbus-hosted Operation1 + typed
// sub-adaptor, the shared OperationState, and the typed Operation host for one
// Card1 method, then returns the OperationBase the core OperationManager queues.
// Moved out of the (now neutral) OperationManager so the core scheduler carries
// no sdbus adaptor construction; the caller derives the exported wire path via
// dbus/OperationPath.h and hands it in here.
[[nodiscard]] std::unique_ptr<Operations::OperationBase>
buildIdentityOperation(sdbus::IConnection& bus, const sdbus::ObjectPath& path,
                       Operations::ReadIdentityOperation::Deps deps);
[[nodiscard]] std::unique_ptr<Operations::OperationBase>
buildPhotoOperation(sdbus::IConnection& bus, const sdbus::ObjectPath& path, Operations::GetPhotoOperation::Deps deps);
[[nodiscard]] std::unique_ptr<Operations::OperationBase>
buildCertificatesOperation(sdbus::IConnection& bus, const sdbus::ObjectPath& path,
                           Operations::ReadCertificatesOperation::Deps deps);
// Reuses the SAME Identity1 channel machinery buildIdentityOperation does
// (Operations::IdentityChannel): ReadTokenInfo mints NO new result
// interface — its CardReadSnapshot rides Identity1.Result exactly like
// ReadIdentity's.
[[nodiscard]] std::unique_ptr<Operations::OperationBase>
buildTokenInfoOperation(sdbus::IConnection& bus, const sdbus::ObjectPath& path,
                        Operations::ReadTokenInfoOperation::Deps deps);
[[nodiscard]] std::unique_ptr<Operations::OperationBase>
buildSignOperation(sdbus::IConnection& bus, const sdbus::ObjectPath& path, Operations::SignOperation::Deps deps);
[[nodiscard]] std::unique_ptr<Operations::OperationBase>
buildSignBatchOperation(sdbus::IConnection& bus, const sdbus::ObjectPath& path,
                        Operations::SignBatchOperation::Deps deps);

// Credentials1 operations. Each builds the Operation1 + Operation.Credentials1
// typed host on @p path (delivering the (a{sv}, aa{sv}) result inline) and returns
// the OperationBase the scheduler queues.
[[nodiscard]] std::unique_ptr<Operations::OperationBase>
buildListCredentialsOperation(sdbus::IConnection& bus, const sdbus::ObjectPath& path,
                              Operations::ListCredentialsOperation::Deps deps);
[[nodiscard]] std::unique_ptr<Operations::OperationBase>
buildManagePinOperation(sdbus::IConnection& bus, const sdbus::ObjectPath& path,
                        Operations::ManagePinOperation::Deps deps);
[[nodiscard]] std::unique_ptr<Operations::OperationBase>
buildActivateSigningKeyOperation(sdbus::IConnection& bus, const sdbus::ObjectPath& path,
                                 Operations::ActivateSigningKeyOperation::Deps deps);

} // namespace LibreSCRS::Agent
