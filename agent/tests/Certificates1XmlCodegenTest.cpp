// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Compile-only contract test: the generated Certificates1 adaptor's Result emit
// must accept exactly the frozen wire shape a(sba{sa{s(ssv)}}uasasu). A
// post-freeze member reorder/retype would compile the marshaller clean but
// break every client; this static_assert is the lock.
#include "org.librescrs.Agent.Operation.Certificates1_adaptor.h"
#include <sdbus-c++/Types.h>
#include <gtest/gtest.h>
#include <cstdint>
#include <map>
#include <string>
#include <type_traits>
#include <vector>

namespace {
// (ssv): labelKey, labelFallback, value — NOT Identity1's (sssv).
using FieldTuple = sdbus::Struct<std::string, std::string, sdbus::Variant>;
using FieldMap = std::map<std::string, std::map<std::string, FieldTuple>>;
// (s b a{sa{s(ssv)}} u as as u): certId, signingCapable, fields, keyUsageBits,
// ekuOids, chainSubjectCns, trustStatus.
using CertTuple = sdbus::Struct<std::string, bool, FieldMap, std::uint32_t, std::vector<std::string>,
                                std::vector<std::string>, std::uint32_t>;
using Adaptor = org::librescrs::Agent::Operation::Certificates1_adaptor;

static_assert(std::is_invocable_v<decltype(&Adaptor::emitResult), Adaptor&, const std::vector<CertTuple>&>,
              "Certificates1.Result wire shape frozen as a(sba{sa{s(ssv)}}uasasu); if this fails the generated "
              "emitResult signature drifted from the struct order/types declared in "
              "dbus/org.librescrs.Agent.Operation.Certificates1.xml");

// GetResult() -> a(sba{sa{s(ssv)}}uasasu) is a private pure-virtual per
// sdbus-c++ convention (the late-subscriber recovery pull, same shape as the
// Result signal); verify it exists with the documented return shape by
// overriding it.
class Certificates1Probe : public Adaptor
{
private:
    std::vector<CertTuple> GetResult() override
    {
        return {};
    }
};
static_assert(!std::is_abstract_v<Certificates1Probe>,
              "Certificates1 adaptor must expose GetResult() -> a(sba{sa{s(ssv)}}uasasu) as declared in "
              "dbus/org.librescrs.Agent.Operation.Certificates1.xml");
} // namespace

TEST(Certificates1Xml, ResultAndGetResultWireShapesFrozen)
{
    SUCCEED();
}
