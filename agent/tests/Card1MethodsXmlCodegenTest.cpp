// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Compile-only contract test: the Card1 adaptor must declare the documented
// properties (Capabilities, Reader, PreReadAuthMethod, CardType, Atr) and
// methods (ReadIdentity, GetPhoto, ReadCertificates, Sign) with the documented
// signatures. The generated members are private-virtual per sdbus-c++
// convention, so we verify their existence by overriding them in a derived
// class (private-virtual is callable via the vtable, just not nameable outside
// the class).
#include "org.librescrs.Agent.Card1_adaptor.h"
#include <sdbus-c++/Types.h>
#include <gtest/gtest.h>
#include <map>
#include <string>
#include <type_traits>
#include <vector>

namespace {
class Card1Probe : public org::librescrs::Agent::Card1_adaptor
{
private:
    std::uint32_t Capabilities() override
    {
        return 0;
    }
    sdbus::ObjectPath Reader() override
    {
        return sdbus::ObjectPath{"/"};
    }
    std::string PreReadAuthMethod() override
    {
        return "None";
    }
    std::string CardType() override
    {
        return "";
    }
    std::string Atr() override
    {
        return "";
    }
    sdbus::ObjectPath ReadIdentity() override
    {
        return sdbus::ObjectPath{"/"};
    }
    sdbus::ObjectPath GetPhoto() override
    {
        return sdbus::ObjectPath{"/"};
    }
    sdbus::ObjectPath ReadCertificates() override
    {
        return sdbus::ObjectPath{"/"};
    }
    sdbus::ObjectPath ReadTokenInfo() override
    {
        return sdbus::ObjectPath{"/"};
    }
    sdbus::ObjectPath Sign(const std::string& /*certId*/, const sdbus::UnixFd& /*inputFd*/,
                           const std::map<std::string, sdbus::Variant>& /*options*/) override
    {
        return sdbus::ObjectPath{"/"};
    }
    sdbus::ObjectPath SignBatch(const std::vector<sdbus::Struct<std::string, sdbus::UnixFd>>& /*documents*/,
                                const std::string& /*certId*/,
                                const std::map<std::string, sdbus::Variant>& /*options*/) override
    {
        return sdbus::ObjectPath{"/"};
    }
};
static_assert(!std::is_abstract_v<Card1Probe>,
              "Card1 adaptor must expose PreReadAuthMethod + CardType + Atr + ReadIdentity + GetPhoto + "
              "ReadCertificates + ReadTokenInfo + Sign + SignBatch pure-virtuals");
} // namespace

TEST(Card1MethodsXml, PropertiesAndMethodsExposed)
{
    SUCCEED();
}
