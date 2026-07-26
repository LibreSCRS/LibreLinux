// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Compile-only contract test: the generated Identity1 adaptor must expose the
// frozen Result signal shape a{sa{s(sssv)}}, the Group signal shape
// (s groupKey, a{s(sssv)} fields), and a GetResult method returning the SAME
// shape as Result (the late-subscriber recovery pull). A post-freeze drift
// would compile a marshaller clean but break every client; these
// static_asserts are the lock.
#include "org.librescrs.Agent.Operation.Identity1_adaptor.h"
#include <sdbus-c++/Types.h>
#include <gtest/gtest.h>
#include <map>
#include <string>
#include <type_traits>

namespace {
// (sssv): labelKey, labelFallback, type, value.
using FieldTuple = sdbus::Struct<std::string, std::string, std::string, sdbus::Variant>;
using FieldsMap = std::map<std::string, std::map<std::string, FieldTuple>>;
// One group's field map -- the value half of one FieldsMap entry, and the
// entirety of Group's own `fields` arg.
using GroupFieldsMap = std::map<std::string, FieldTuple>;
using Adaptor = org::librescrs::Agent::Operation::Identity1_adaptor;

// Result(a{sa{s(sssv)}} fields).
static_assert(std::is_invocable_v<decltype(&Adaptor::emitResult), Adaptor&, const FieldsMap&>,
              "Identity1.Result wire shape frozen as a{sa{s(sssv)}}; the generated emitResult signature drifted from "
              "the shape declared in dbus/org.librescrs.Agent.Operation.Identity1.xml");

// Group(s groupKey, a{s(sssv)} fields) -- progressive per-group delivery,
// strictly ahead of Result above for the SAME op.
static_assert(std::is_invocable_v<decltype(&Adaptor::emitGroup), Adaptor&, const std::string&, const GroupFieldsMap&>,
              "Identity1.Group wire shape frozen as (s groupKey, a{s(sssv)} fields); the generated emitGroup signature "
              "drifted from the shape declared in dbus/org.librescrs.Agent.Operation.Identity1.xml");

// GetResult() -> a{sa{s(sssv)}} is a private pure-virtual per sdbus-c++
// convention; verify it exists with the documented return shape by overriding it.
class Identity1Probe : public Adaptor
{
private:
    FieldsMap GetResult() override
    {
        return {};
    }
};
static_assert(!std::is_abstract_v<Identity1Probe>,
              "Identity1 adaptor must expose GetResult() -> a{sa{s(sssv)}} as declared in "
              "dbus/org.librescrs.Agent.Operation.Identity1.xml");
} // namespace

TEST(Identity1Xml, ResultGroupAndGetResultWireShapesFrozen)
{
    SUCCEED();
}
