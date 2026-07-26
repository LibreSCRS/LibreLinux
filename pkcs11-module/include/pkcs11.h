// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

// Self-contained PKCS#11 header for the agent-proxy module. Defines the five
// platform-specific macros the OASIS spec requires (CK_PTR / the function
// declaration + pointer macros / NULL_PTR) for a UNIX/ELF build, then pulls in
// the vendored OASIS v3.2 header set (pkcs11-oasis.h -> pkcs11t.h + pkcs11f.h).
// Consumers include ONLY this file: #include "pkcs11.h".
//
// The vendored OASIS headers are a verbatim copy of LibreMiddleware's
// lib/pkcs11/include/pkcs11 set; this module advertises a v2.40 function list
// (CK_FUNCTION_LIST) for maximum loader compatibility (Java SunPKCS11 rejects
// 3.x), exactly as the LM native module does.

#ifndef LIBRESCRS_PKCS11_AGENT_PKCS11_H
#define LIBRESCRS_PKCS11_AGENT_PKCS11_H 1

// 1. CK_PTR — pointer indirection.
#define CK_PTR *

// 2. CK_DECLARE_FUNCTION — an importable/exportable Cryptoki function. We mark
//    nothing here; symbol visibility is controlled by the linker version script
//    (src/exports.map) which exposes ONLY C_GetFunctionList.
#define CK_DECLARE_FUNCTION(returnType, name) returnType name

// 3. CK_DECLARE_FUNCTION_POINTER — a Cryptoki API function pointer.
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType(*name)

// 4. CK_CALLBACK_FUNCTION — an application callback function pointer.
#define CK_CALLBACK_FUNCTION(returnType, name) returnType(*name)

// 5. NULL_PTR — the null pointer value.
#ifndef NULL_PTR
#define NULL_PTR nullptr
#endif

#include "pkcs11-oasis.h"

#endif // LIBRESCRS_PKCS11_AGENT_PKCS11_H
