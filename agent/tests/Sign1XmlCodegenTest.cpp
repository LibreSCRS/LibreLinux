// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Compile-only contract test: the generated Sign1 adaptor must expose the frozen
// Result signal shape (h, a{sv}) and a GetResult method returning (h, a{sv}).
// A post-freeze drift would compile a marshaller clean but break every client;
// these static_asserts are the lock.
#include "org.librescrs.Agent.Operation.Sign1_adaptor.h"
#include <sdbus-c++/Types.h>
#include <gtest/gtest.h>
#include <map>
#include <string>
#include <tuple>
#include <type_traits>

namespace {
using Adaptor = org::librescrs::Agent::Operation::Sign1_adaptor;
using MetaMap = std::map<std::string, sdbus::Variant>;

// Result(h signedArtifact, a{sv} meta).
static_assert(std::is_invocable_v<decltype(&Adaptor::emitResult), Adaptor&, const sdbus::UnixFd&, const MetaMap&>,
              "Sign1.Result wire shape frozen as (h, a{sv}); the generated emitResult signature drifted from the shape "
              "declared in dbus/org.librescrs.Agent.Operation.Sign1.xml");

// GetResult() -> (h, a{sv}) is a private pure-virtual per sdbus-c++ convention;
// verify it exists with the documented return shape by overriding it.
class Sign1Probe : public Adaptor
{
private:
    std::tuple<sdbus::UnixFd, MetaMap> GetResult() override
    {
        return {sdbus::UnixFd{}, MetaMap{}};
    }
};
static_assert(!std::is_abstract_v<Sign1Probe>, "Sign1 adaptor must expose GetResult() -> (h, a{sv}) as declared in "
                                               "dbus/org.librescrs.Agent.Operation.Sign1.xml");
} // namespace

TEST(Sign1Xml, ResultAndGetResultWireShapesFrozen)
{
    SUCCEED();
}
