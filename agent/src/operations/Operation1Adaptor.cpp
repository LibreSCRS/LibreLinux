// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#include "operations/Operation1Adaptor.h"

#include "AgentInterfaceNames.h" // shared service/path/interface names
#include <LibreSCRS/Agent/value/CardReadSnapshot.h>
#include <LibreSCRS/Agent/value/CertSnapshot.h>
#include <LibreSCRS/Agent/backend/Logging.h>
#include "org.librescrs.Agent.Operation.Certificates1_adaptor.h"
#include "org.librescrs.Agent.Operation.Credentials1_adaptor.h"
#include "org.librescrs.Agent.Operation.Identity1_adaptor.h"
#include "org.librescrs.Agent.Operation.Photo1_adaptor.h"
#include "org.librescrs.Agent.Operation.Sign1_adaptor.h"
#include "org.librescrs.Agent.Operation.SignBatch1_adaptor.h"

#include <sdbus-c++/Types.h>

#include <cstdint>
#include <exception>
#include <map>
#include <string>
#include <utility>
#include <vector>

namespace LibreSCRS::Agent::Operations {

// kOperation1Iface lives in common/AgentInterfaceNames.h (shared agent-wire names
// under LibreLinux::AgentWire — qualified explicitly now that this backend lives
// in the LibreSCRS::Agent namespace).
using LibreLinux::AgentWire::kOperation1Iface;

template <typename ResultSubAdaptor>
void Operation1Adaptor<ResultSubAdaptor>::emitFinishedNx(std::uint32_t status, std::uint32_t errorCode,
                                                         std::string_view msgKey, std::string_view msgFallback) noexcept
{
    try {
        // emitFinished lives on the generated Operation1_adaptor base; the
        // generated emit helper does the bus marshalling. The string_view ->
        // std::string materialisation (the generated signal takes owning
        // strings) is caught here too, so a caller on the noexcept
        // OperationChannel boundary never has to allocate.
        this->emitFinished(status, errorCode, std::string{msgKey}, std::string{msgFallback});
    } catch (const std::exception& e) {
        log::warnf("Operation1Adaptor: emitFinished failed: {}", e.what());
    } catch (...) {
        log::warn("Operation1Adaptor: emitFinished failed with unknown exception");
    }
}

template <typename ResultSubAdaptor>
void Operation1Adaptor<ResultSubAdaptor>::emitPropertiesChangedForOperation1() noexcept
{
    try {
        const sdbus::InterfaceName iface{kOperation1Iface};
        const std::vector<sdbus::PropertyName> props{
            sdbus::PropertyName{"Phase"},           sdbus::PropertyName{"Progress"},
            sdbus::PropertyName{"IsIndeterminate"}, sdbus::PropertyName{"WatchdogTimeoutSeconds"},
            sdbus::PropertyName{"Completed"},       sdbus::PropertyName{"Status"},
            sdbus::PropertyName{"ErrorCode"}};
        // emitPropertiesChangedSignal is inherited from IObject (re-exposed
        // via the AdaptorInterfaces base).
        this->getObject().emitPropertiesChangedSignal(iface, props);
    } catch (const std::exception& e) {
        log::warnf("Operation1Adaptor: emitPropertiesChanged failed: {}", e.what());
    } catch (...) {
        log::warn("Operation1Adaptor: emitPropertiesChanged failed with unknown exception");
    }
}

namespace {

constexpr const char* fieldTypeWire(FieldType t) noexcept
{
    switch (t) {
    case FieldType::Text:
        return "text";
    case FieldType::Date:
        return "date";
    case FieldType::Binary:
        return "binary";
    case FieldType::Photo:
        return "photo"; // omitted in practice; defensive default
    }
    return "binary";
}

} // namespace

Identity1GroupFieldsWire buildIdentity1GroupWire(const GroupSnapshot& g)
{
    Identity1GroupFieldsWire wire;
    for (const auto& f : g.fields) {
        if (f.type == FieldType::Photo) {
            continue; // photos ride on Photo1.Result
        }
        sdbus::Variant v = (f.type == FieldType::Text || f.type == FieldType::Date) ? sdbus::Variant{f.textValue}
                                                                                    : sdbus::Variant{f.binaryValue};
        wire[f.fieldKey] = sdbus::Struct{f.labelKey, f.labelFallback, std::string{fieldTypeWire(f.type)}, std::move(v)};
    }
    return wire;
}

Identity1Wire buildIdentity1Wire(const CardReadSnapshot& snapshot)
{
    Identity1Wire wire;
    for (const auto& g : snapshot.groups) {
        // Preserve the pre-existing omission rule: a group whose every field
        // was Photo (or that carried none at all) never gets an entry here,
        // exactly as the original inlined double loop never touched
        // wire[groupKey] for such a group.
        auto fields = buildIdentity1GroupWire(g);
        if (!fields.empty()) {
            wire[g.groupKey] = std::move(fields);
        }
    }
    return wire;
}

void emitIdentity1Result(org::librescrs::Agent::Operation::Identity1_adaptor& sub,
                         const CardReadSnapshot& snapshot) noexcept
{
    try {
        sub.emitResult(buildIdentity1Wire(snapshot));
    } catch (const std::exception& e) {
        log::warnf("Operation1Adaptor: Identity1.emitResult failed: {}", e.what());
    } catch (...) {
        log::warn("Operation1Adaptor: Identity1.emitResult failed with unknown exception");
    }
}

void emitIdentity1Group(org::librescrs::Agent::Operation::Identity1_adaptor& sub, const GroupSnapshot& group) noexcept
{
    try {
        sub.emitGroup(group.groupKey, buildIdentity1GroupWire(group));
    } catch (const std::exception& e) {
        log::warnf("Operation1Adaptor: Identity1.emitGroup failed: {}", e.what());
    } catch (...) {
        log::warn("Operation1Adaptor: Identity1.emitGroup failed with unknown exception");
    }
}

void emitPhoto1Result(org::librescrs::Agent::Operation::Photo1_adaptor& sub,
                      std::map<std::string, sdbus::UnixFd> photoFds) noexcept
{
    try {
        sub.emitResult(photoFds);
    } catch (const std::exception& e) {
        log::warnf("Operation1Adaptor: Photo1.emitResult failed: {}", e.what());
        // photoFds dtor closes every UnixFd on unwind — no leak.
    } catch (...) {
        log::warn("Operation1Adaptor: Photo1.emitResult failed with unknown exception");
    }
}

Certificates1Wire buildCertificates1Wire(const std::vector<CertSnapshot>& certs)
{
    Certificates1Wire wire;
    wire.reserve(certs.size());
    for (const auto& c : certs) {
        Certificates1FieldMap fields;
        for (const auto& g : c.fields) {
            auto& fmap = fields[g.groupKey];
            for (const auto& f : g.fields) {
                // All cert fields are text (DN/dates/hex); (ssv) drops the type.
                fmap[f.fieldKey] = Certificates1FieldTuple{f.labelKey, f.labelFallback, sdbus::Variant{f.textValue}};
            }
        }
        wire.emplace_back(c.certId, c.signingCapable, std::move(fields), c.keyUsageBits, c.ekuOids, c.chainSubjectCns,
                          c.trustStatus);
    }
    return wire;
}

void emitCertificates1Result(org::librescrs::Agent::Operation::Certificates1_adaptor& sub,
                             const std::vector<CertSnapshot>& certs) noexcept
{
    try {
        sub.emitResult(buildCertificates1Wire(certs));
    } catch (const std::exception& e) {
        log::warnf("Operation1Adaptor: Certificates1.emitResult failed: {}", e.what());
    } catch (...) {
        log::warn("Operation1Adaptor: Certificates1.emitResult failed with unknown exception");
    }
}

// Explicit instantiations — the agent ships exactly these flavours. Every
// instantiation is abstract (each typed sub-adaptor declares the GetResult
// late-subscriber recovery method, left pure here); the per-kind adaptors
// derived in dbus/OperationAdaptorFactory implement it.
template class Operation1Adaptor<org::librescrs::Agent::Operation::Identity1_adaptor>;
template class Operation1Adaptor<org::librescrs::Agent::Operation::Photo1_adaptor>;
template class Operation1Adaptor<org::librescrs::Agent::Operation::Certificates1_adaptor>;
template class Operation1Adaptor<org::librescrs::Agent::Operation::Sign1_adaptor>;
template class Operation1Adaptor<org::librescrs::Agent::Operation::SignBatch1_adaptor>;
template class Operation1Adaptor<org::librescrs::Agent::Operation::Credentials1_adaptor>;

} // namespace LibreSCRS::Agent::Operations
