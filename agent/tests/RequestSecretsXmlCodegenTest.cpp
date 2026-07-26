// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Compile-time contract test: the Prompter1 proxy gains RequestSecrets
// (multi-secret request) alongside the existing RequestSecret. Pins the full
// wire shape — in: (kind, options); out: (status, primary_fd, secondary_fd,
// user_message) — via a static_assert on the generated method's type, plus
// the shared PrompterWire vocabulary both binaries key off. A drift in the
// XML (renamed/reordered/retyped argument) regenerates a proxy whose method
// type no longer matches and this translation unit stops compiling.
#include "org.librescrs.Prompter1_proxy.h"

#include "PrompterWire.h"

#include <sdbus-c++/IProxy.h>
#include <gtest/gtest.h>
#include <map>
#include <string>
#include <tuple>
#include <type_traits>
#include <utility>

namespace {

class PromProbe : public org::librescrs::Prompter1_proxy
{
public:
    PromProbe(sdbus::IProxy& proxy) : org::librescrs::Prompter1_proxy(proxy) {}
    using org::librescrs::Prompter1_proxy::RequestSecrets;
};

// The generated proxy must expose RequestSecrets(kind, options) returning the
// four-field reply tuple (status, primary_fd, secondary_fd, user_message).
static_assert(std::is_same_v<decltype(std::declval<PromProbe&>().RequestSecrets(
                                 std::declval<const std::string&>(),
                                 std::declval<const std::map<std::string, sdbus::Variant>&>())),
                             std::tuple<std::string, sdbus::UnixFd, sdbus::UnixFd, std::string>>,
              "RequestSecrets wire shape drifted from (s status, h primary_fd, h secondary_fd, s user_message)");

} // namespace

TEST(RequestSecretsXml, ProxyExposesRequestSecrets)
{
    SUCCEED();
}

TEST(RequestSecretsXml, ChangePinWireVocabularyIsPinned)
{
    namespace wire = LibreLinux::PrompterWire;
    EXPECT_STREQ(wire::kKindChangePin, "change_pin");
    EXPECT_STREQ(wire::kOptPrimaryMinLength, "primary_min_length");
    EXPECT_STREQ(wire::kOptPrimaryMaxLength, "primary_max_length");
    EXPECT_STREQ(wire::kOptNewMinLength, "new_min_length");
    EXPECT_STREQ(wire::kOptNewMaxLength, "new_max_length");
    EXPECT_STREQ(wire::kOptCardLabel, "card_label");
    EXPECT_STREQ(wire::kOptPinLabel, "pin_label");
}
