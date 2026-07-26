// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Compile-only contract test: the generated SignBatch1 adaptor must expose
// the frozen Result signal shape (a(sha{sv}u)) and a GetResult method
// returning the SAME shape. A post-freeze drift would compile a marshaller
// clean but break every client; these static_asserts are the lock. Mirrors
// Sign1XmlCodegenTest.cpp's convention.
#include "org.librescrs.Agent.Operation.SignBatch1_adaptor.h"
#include <sdbus-c++/Types.h>
#include <gtest/gtest.h>
#include <cstdint>
#include <map>
#include <string>
#include <type_traits>
#include <vector>

namespace {
using Adaptor = org::librescrs::Agent::Operation::SignBatch1_adaptor;
using RowTuple = sdbus::Struct<std::string, sdbus::UnixFd, std::map<std::string, sdbus::Variant>, std::uint32_t>;
using RowsWire = std::vector<RowTuple>;

// Result(a(sha{sv}u) rows).
static_assert(std::is_invocable_v<decltype(&Adaptor::emitResult), Adaptor&, const RowsWire&>,
              "SignBatch1.Result wire shape frozen as a(sha{sv}u); the generated emitResult signature drifted from "
              "the shape declared in dbus/org.librescrs.Agent.Operation.SignBatch1.xml");

// GetResult() -> a(sha{sv}u) is a private pure-virtual per sdbus-c++ convention;
// verify it exists with the documented return shape by overriding it.
class SignBatch1Probe : public Adaptor
{
private:
    RowsWire GetResult() override
    {
        return RowsWire{};
    }
};
static_assert(!std::is_abstract_v<SignBatch1Probe>,
              "SignBatch1 adaptor must expose GetResult() -> a(sha{sv}u) as declared in "
              "dbus/org.librescrs.Agent.Operation.SignBatch1.xml");
} // namespace

TEST(SignBatch1Xml, ResultAndGetResultWireShapesFrozen)
{
    SUCCEED();
}
