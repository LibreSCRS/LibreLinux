// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Compile-only contract test: the Manager1 adaptor must declare the
// documented properties (Version, Features) with the documented signatures.
// The generated members are private-virtual per sdbus-c++ convention, so we
// verify their existence by overriding them in a derived class (private-
// virtual is callable via the vtable, just not nameable outside the class) —
// the same pattern Card1MethodsXmlCodegenTest.cpp uses for Card1.
#include "org.librescrs.Agent.Manager1_adaptor.h"
#include <sdbus-c++/Types.h>
#include <gtest/gtest.h>
#include <string>
#include <tuple>
#include <type_traits>
#include <vector>

namespace {
class Manager1Probe : public org::librescrs::Agent::Manager1_adaptor
{
private:
    std::string Version() override
    {
        return {};
    }
    std::vector<std::string> Features() override
    {
        return {};
    }
    // LayoutVisualSignature/GetAppearanceFont — card-independent,
    // synchronous, no Operation object.
    std::tuple<double, double, std::vector<std::string>, bool>
    LayoutVisualSignature(const std::string& /*text*/, const double& /*x*/, const double& /*y*/,
                          const double& /*width*/, const double& /*height*/) override
    {
        return {};
    }
    sdbus::UnixFd GetAppearanceFont() override
    {
        return {};
    }
};
static_assert(!std::is_abstract_v<Manager1Probe>,
              "Manager1 adaptor must expose Version + Features + LayoutVisualSignature + GetAppearanceFont "
              "pure-virtuals");
} // namespace

TEST(Manager1XmlCodegen, PropertiesExposed)
{
    SUCCEED();
}
