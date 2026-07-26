// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <LibreSCRS/Agent/OperationState.h>
#include "org.librescrs.Agent.Operation1_adaptor.h"
#include <sdbus-c++/AdaptorInterfaces.h>
#include <sdbus-c++/IConnection.h>
#include <sdbus-c++/IObject.h>
#include <sdbus-c++/Types.h> // sdbus::UnixFd, sdbus::ObjectPath, ...
#include <atomic>
#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace LibreSCRS::Agent::Operations {

// sdbus-c++ host class. Templated on the typed-result sub-adaptor so each
// Operation kind composes its own (Operation1 + Identity1, Operation1 + Photo1,
// …) pair without runtime virtual dispatch. Not final — and always abstract:
// every typed sub-interface adds the GetResult late-subscriber recovery METHOD
// (generated pure-virtual), so a per-kind adaptor in dbus/OperationAdaptorFactory
// derives from the matching instantiation to implement it, reusing all the
// Operation1 machinery here.
template <typename ResultSubAdaptor>
class Operation1Adaptor : public sdbus::AdaptorInterfaces<org::librescrs::Agent::Operation1_adaptor, ResultSubAdaptor>
{
    using Base = sdbus::AdaptorInterfaces<org::librescrs::Agent::Operation1_adaptor, ResultSubAdaptor>;

public:
    Operation1Adaptor(sdbus::IConnection& connection, sdbus::ObjectPath path, std::shared_ptr<OperationState> state)
        : Base(connection, std::move(path)), m_state(std::move(state))
    {
        Base::registerAdaptor();
    }

    // Virtual: the per-kind adaptors (Identity1/Certificates1/Photo1/Sign1 in
    // dbus/OperationAdaptorFactory) derive from this to add their GetResult method.
    virtual ~Operation1Adaptor()
    {
        Base::unregisterAdaptor();
    }

    Operation1Adaptor(const Operation1Adaptor&) = delete;
    Operation1Adaptor& operator=(const Operation1Adaptor&) = delete;
    Operation1Adaptor(Operation1Adaptor&&) = delete;
    Operation1Adaptor& operator=(Operation1Adaptor&&) = delete;

    [[nodiscard]] std::uint32_t phase() const
    {
        return m_state ? m_state->phase.load() : 0u;
    }
    [[nodiscard]] double progress() const
    {
        return m_state ? m_state->progress.load() : 0.0;
    }
    [[nodiscard]] bool isIndeterminate() const
    {
        return m_state && m_state->isIndeterminate.load();
    }
    [[nodiscard]] std::uint32_t watchdogTimeoutSeconds() const
    {
        return m_state ? m_state->watchdogTimeoutSec.load() : 0u;
    }
    [[nodiscard]] bool completed() const
    {
        return m_state && m_state->completed.load();
    }
    [[nodiscard]] std::uint32_t terminalStatus() const
    {
        return m_state ? m_state->terminalStatus.load() : 0u;
    }
    [[nodiscard]] std::uint32_t terminalErrorCode() const
    {
        return m_state ? m_state->terminalErrorCode.load() : 0u;
    }

    // noexcept emit wrappers — D-Bus dispatch failures (and the message-key
    // string allocation) get logged but never propagated up the worker.
    void emitFinishedNx(std::uint32_t status, std::uint32_t errorCode, std::string_view msgKey,
                        std::string_view msgFallback) noexcept;

    void emitPropertiesChangedForOperation1() noexcept;

#ifdef LIBRELINUX_TESTING
    void invokeCancelForTest() noexcept
    {
        if (m_state) {
            m_state->cancelled.store(true, std::memory_order_release);
        }
    }
#endif

private:
    // Generated private-virtual surface — sdbus-c++ convention.
    std::uint32_t Phase() override
    {
        return phase();
    }
    double Progress() override
    {
        return progress();
    }
    bool IsIndeterminate() override
    {
        return isIndeterminate();
    }
    std::uint32_t WatchdogTimeoutSeconds() override
    {
        return watchdogTimeoutSeconds();
    }
    bool Completed() override
    {
        return completed();
    }
    std::uint32_t Status() override
    {
        return terminalStatus();
    }
    std::uint32_t ErrorCode() override
    {
        return terminalErrorCode();
    }
    void Cancel() override
    {
        if (m_state) {
            m_state->cancelled.store(true, std::memory_order_release);
        }
    }

    std::shared_ptr<OperationState> m_state;
};

} // namespace LibreSCRS::Agent::Operations

// --- Typed-result emit helpers --------------------------------------------
//
// Each helper marshals an agent-side value into the wire shape declared in
// the matching Operation.<X>1.xml signal and forwards through the generated
// sub-adaptor's emitResult. Forward decls (no header includes for the
// generated adaptors) keep this header light; the .cpp pulls in the full
// types it needs.

namespace org::librescrs::Agent::Operation {
class Identity1_adaptor;
class Photo1_adaptor;
class Certificates1_adaptor;
} // namespace org::librescrs::Agent::Operation

namespace LibreSCRS::Agent {
struct CardReadSnapshot; // full type in CardReadSnapshot.h
struct CertSnapshot;     // full type in CertSnapshot.h
struct GroupSnapshot;    // full type in CardReadSnapshot.h
} // namespace LibreSCRS::Agent

namespace LibreSCRS::Agent::Operations {

// Frozen wire shapes shared by the Result signal emits and the GetResult
// late-subscriber recovery replies (see the matching Operation.<X>1.xml).
// Identity1: a{sa{s(sssv)}} — group -> field -> (labelKey, labelFallback, type, value).
using Identity1Wire =
    std::map<std::string, std::map<std::string, sdbus::Struct<std::string, std::string, std::string, sdbus::Variant>>>;
// Identity1.Group's own `fields` arg: a{s(sssv)} — ONE group's field map,
// exactly Identity1Wire's mapped_type (the value half of one outer-map
// entry) named on its own for the Group signal's signature.
using Identity1GroupFieldsWire = Identity1Wire::mapped_type;
// Certificates1: a(sba{sa{s(ssv)}}uasasu) — the (ssv) field tuple deliberately
// drops Identity1's type string (the frozen field-key namespace carries it).
using Certificates1FieldTuple = sdbus::Struct<std::string, std::string, sdbus::Variant>;
using Certificates1FieldMap = std::map<std::string, std::map<std::string, Certificates1FieldTuple>>;
using Certificates1CertTuple = sdbus::Struct<std::string, bool, Certificates1FieldMap, std::uint32_t,
                                             std::vector<std::string>, std::vector<std::string>, std::uint32_t>;
using Certificates1Wire = std::vector<Certificates1CertTuple>;

// Marshal an agent-side snapshot into the frozen wire shape. Shared by the
// Result signal emit and the GetResult recovery reply so the two can never
// drift. Throwing (allocation): the emit helpers wrap them in their noexcept
// try blocks; a GetResult lets sdbus-c++ map the throw to an error reply.
[[nodiscard]] Identity1Wire buildIdentity1Wire(const LibreSCRS::Agent::CardReadSnapshot& snapshot);
[[nodiscard]] Certificates1Wire buildCertificates1Wire(const std::vector<LibreSCRS::Agent::CertSnapshot>& certs);
// One group's field map — shared by buildIdentity1Wire's per-group loop and
// emitIdentity1Group below so the two encodings of this cell shape can never
// drift apart.
[[nodiscard]] Identity1GroupFieldsWire buildIdentity1GroupWire(const LibreSCRS::Agent::GroupSnapshot& group);

void emitIdentity1Result(org::librescrs::Agent::Operation::Identity1_adaptor& sub,
                         const LibreSCRS::Agent::CardReadSnapshot& snapshot) noexcept;

// Progressive per-group delivery, strictly ahead of emitIdentity1Result for
// the SAME op (see Operation.Identity1.xml's Group signal doc comment).
void emitIdentity1Group(org::librescrs::Agent::Operation::Identity1_adaptor& sub,
                        const LibreSCRS::Agent::GroupSnapshot& group) noexcept;

// Marshals the parsed certificate list into the Certificates1.Result (ssv)
// field-group wire shape. Emitted BEFORE Operation1.Finished.
void emitCertificates1Result(org::librescrs::Agent::Operation::Certificates1_adaptor& sub,
                             const std::vector<LibreSCRS::Agent::CertSnapshot>& certs) noexcept;

// Takes the wire map BY VALUE. The caller adopts each raw fd into a
// sdbus::UnixFd before constructing this map, so any std::bad_alloc the
// caller hits during map construction unwinds via UnixFd destructors —
// no fds leak. Inside this helper the map is moved into the sub-adaptor
// emit; sdbus-c++ owns the UnixFds from there.
void emitPhoto1Result(org::librescrs::Agent::Operation::Photo1_adaptor& sub,
                      std::map<std::string, sdbus::UnixFd> photoFds) noexcept;

} // namespace LibreSCRS::Agent::Operations
