// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Compile-only contract test: the generated adaptor headers for Operation1
// + Operation.Identity1 + Operation.Photo1 must exist and declare the
// classes the rest of the agent will reference.
#include "org.librescrs.Agent.Operation1_adaptor.h"
#include "org.librescrs.Agent.Operation.Identity1_adaptor.h"
#include "org.librescrs.Agent.Operation.Photo1_adaptor.h"
#include <gtest/gtest.h>
#include <type_traits>

namespace {
using Operation1Adaptor = org::librescrs::Agent::Operation1_adaptor;
using IdentityAdaptor = org::librescrs::Agent::Operation::Identity1_adaptor;
using PhotoAdaptor = org::librescrs::Agent::Operation::Photo1_adaptor;
static_assert(std::is_class_v<Operation1Adaptor>);
static_assert(std::is_class_v<IdentityAdaptor>);
static_assert(std::is_class_v<PhotoAdaptor>);
} // namespace

TEST(OperationXml, AdaptorHeadersCompile)
{
    SUCCEED();
}
