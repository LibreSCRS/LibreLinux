// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Compile-only contract test: the Prompter1 proxy carries the ADDRESSED
// Cancel(prompt_id) alongside the existing RequestSecret. Cancel is a protected
// member on the generated proxy (sdbus-c++ convention); we verify its existence
// by deriving a probe that exposes it through a public adapter.
#include "org.librescrs.Prompter1_proxy.h"
#include <sdbus-c++/IConnection.h>
#include <sdbus-c++/IProxy.h>
#include <gtest/gtest.h>
#include <memory>
#include <type_traits>

namespace {
class PromProbe : public org::librescrs::Prompter1_proxy
{
public:
    PromProbe(sdbus::IProxy& proxy) : org::librescrs::Prompter1_proxy(proxy) {}
    using org::librescrs::Prompter1_proxy::Cancel;
};
static_assert(std::is_class_v<PromProbe>);
} // namespace

TEST(Prompter1CancelXml, AddressedCancelExposedOnProxy)
{
    SUCCEED();
}
