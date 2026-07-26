// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Compile-only contract test: the generated Photo1 adaptor must expose the
// frozen Result signal shape a{sh} and a GetResult method returning the SAME
// shape (the late-subscriber recovery pull; the fds are freshly re-sealed
// memfds of the retained bytes). A post-freeze drift would compile a
// marshaller clean but break every client; these static_asserts are the lock.
#include "org.librescrs.Agent.Operation.Photo1_adaptor.h"
#include <sdbus-c++/Types.h>
#include <gtest/gtest.h>
#include <map>
#include <string>
#include <type_traits>

namespace {
using PhotoMap = std::map<std::string, sdbus::UnixFd>;
using Adaptor = org::librescrs::Agent::Operation::Photo1_adaptor;

// Result(a{sh} photos).
static_assert(std::is_invocable_v<decltype(&Adaptor::emitResult), Adaptor&, const PhotoMap&>,
              "Photo1.Result wire shape frozen as a{sh}; the generated emitResult signature drifted from the shape "
              "declared in dbus/org.librescrs.Agent.Operation.Photo1.xml");

// GetResult() -> a{sh} is a private pure-virtual per sdbus-c++ convention;
// verify it exists with the documented return shape by overriding it.
class Photo1Probe : public Adaptor
{
private:
    PhotoMap GetResult() override
    {
        return {};
    }
};
static_assert(!std::is_abstract_v<Photo1Probe>, "Photo1 adaptor must expose GetResult() -> a{sh} as declared in "
                                                "dbus/org.librescrs.Agent.Operation.Photo1.xml");
} // namespace

TEST(Photo1Xml, ResultAndGetResultWireShapesFrozen)
{
    SUCCEED();
}
