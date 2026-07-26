// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
// Compile-conformance: the Pkcs11_1 interface XML generates a usable adaptor.
#include "org.librescrs.Agent.Pkcs11_1_adaptor.h"
#include <gtest/gtest.h>

TEST(Pkcs11XmlCodegen, InterfaceNameMatches)
{
    EXPECT_STREQ(org::librescrs::Agent::Pkcs11_1_adaptor::INTERFACE_NAME, "org.librescrs.Agent.Pkcs11_1");
}
