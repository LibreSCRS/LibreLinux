// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// One way to read a card's certificates through the agent: Card1.ReadCertificates,
// wait for the operation to end, then Certificates1.GetResult. The module's D-Bus
// client and the hardware sign proof (e2e/sign-proof.cpp) both read this way, so
// a recovery fixed in one cannot be missing from the other.
//
// The certificates are taken from GetResult once the read has ended, never from
// the Result signal. The agent emits Result before it marks the operation
// complete, so a client subscribing between the two misses Result yet finds the
// read not complete and catches only Finished. A read the agent answers from its
// cache ends before the reply carrying the operation path leaves it, so Finished
// too has already gone out: the Finished handler is armed before Completed is
// read, so a read that is not Completed yet is one whose Finished is still
// coming, and a Completed one is judged by its terminal Status property.
//
// Header-only: sdbus-c++ and the agent library's standard-library-only wire
// headers. No LibreMiddleware, no Qt, nothing the module does not already link.

#pragma once

#include "AgentErrorNames.h"
#include "AgentInterfaceNames.h"
#include "CertResultWire.h"

#include <LibreSCRS/Agent/OperationPhase.h>     // OperationStatus
#include <LibreSCRS/Agent/pkcs11/AgentClient.h> // kInteractiveTimeoutSecs
#include <LibreSCRS/Agent/wire/ErrorCode.h>

#include <sdbus-c++/sdbus-c++.h>

#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <mutex>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace LibreSCRS::Pkcs11Agent {

// What a certificate read is given to end. A read can ask for the card's CAN
// before it reads, so it waits as long as any call that can prompt: a shorter
// wait gives up while the window is still open and leaves it standing with
// nobody to take its answer.
inline constexpr std::chrono::seconds kCertificateReadBudget{kInteractiveTimeoutSecs};
static_assert(kCertificateReadBudget >= LibreSCRS::Agent::Operations::kMaxSequentialPromptBudget,
              "a certificate read must outlast the agent's longest prompt chain");

// How a certificate read ended.
struct CertificateRead
{
    sdbus::ObjectPath operation;               // the Operation1 object the agent created
    bool timedOut = false;                     // no end within the budget
    std::uint32_t status = 2;                  // Operation1 status; 0 is Ok (default: Error)
    std::uint32_t errorCode = 0;               // Operation1 error code
    std::string message;                       // Finished's fallback text; empty for a read that had already ended
    std::vector<CertResultEntry> certificates; // filled only for an Ok read

    [[nodiscard]] bool ok() const noexcept
    {
        return !timedOut && status == 0;
    }

    // Whether asking again would end the same way. A read the holder ended
    // (the CAN window cancelled, left to expire, a wrong or blocked secret) or
    // one the card cannot answer does, and asking again raises the window
    // again; it stands until a reader or card changes. Only a failure on the
    // way to the card -- no end within the budget, the card unreachable
    // mid-read, the agent's own watchdog, a rate limit -- is worth asking again.
    // A prompter the agent could not reach settles too: the session bus starts
    // it on demand, so its absence is a broken install the next query does not
    // mend. A wrong secret settles once the agent has used up its own retries.
    [[nodiscard]] bool settled() const noexcept
    {
        using LibreSCRS::Agent::ErrorCode;
        using LibreSCRS::Agent::Operations::OperationStatus;
        if (timedOut)
            return false;
        if (status != static_cast<std::uint32_t>(OperationStatus::Error))
            return true;
        switch (static_cast<ErrorCode>(errorCode)) {
        case ErrorCode::CardRemoved:
        case ErrorCode::CommunicationError:
        case ErrorCode::WatchdogTimeout:
        case ErrorCode::RateLimited:
            return false;
        default:
            return true;
        }
    }
};

// Whether Card1.ReadCertificates refusing with @p errorName would refuse again
// for the same card: only when the card has no certificates the agent can read.
// A busy reader, a rate limit or an agent that is not there may answer next time.
[[nodiscard]] inline bool refusalSettles(std::string_view errorName) noexcept
{
    return errorName == LibreLinux::AgentWire::kErrUnsupportedOnThisCard;
}

// Read the certificates of the card at @p cardPath over @p conn, waiting at most
// @p budget for the operation to end; a read that does not end in time is
// cancelled at the agent. A failed call throws sdbus::Error; every other way
// the read can end is in the returned value.
[[nodiscard]] inline CertificateRead readCertificates(sdbus::IConnection& conn, const sdbus::ObjectPath& cardPath,
                                                      std::chrono::seconds budget = kCertificateReadBudget)
{
    using LibreLinux::AgentWire::kCardIface;
    using LibreLinux::AgentWire::kCertificatesIface;
    using LibreLinux::AgentWire::kOperation1Iface;
    using LibreLinux::AgentWire::kServiceName;

    CertificateRead read;
    auto cardProxy = sdbus::createProxy(conn, sdbus::ServiceName{kServiceName}, cardPath);
    cardProxy->callMethod("ReadCertificates")
        .onInterface(sdbus::InterfaceName{kCardIface})
        .storeResultsTo(read.operation);

    // State BEFORE the proxy that owns the handler, so the proxy dies FIRST and
    // no signal can be delivered into a dead frame: sdbus-c++ keeps a handler
    // armed for as long as its proxy lives and runs it on the event-loop thread.
    std::mutex mtx;
    std::condition_variable cv;
    bool finished = false;
    std::uint32_t status = 2;
    std::uint32_t errorCode = 0;
    std::string message;

    auto opProxy = sdbus::createProxy(conn, sdbus::ServiceName{kServiceName}, read.operation);
    opProxy->uponSignal(sdbus::SignalName{"Finished"})
        .onInterface(sdbus::InterfaceName{kOperation1Iface})
        .call([&](std::uint32_t st, std::uint32_t code, const std::string& /*msgKey*/, const std::string& fallback) {
            const std::lock_guard lk(mtx);
            status = st;
            errorCode = code;
            message = fallback;
            finished = true;
            cv.notify_all();
        });

    const auto completed =
        opProxy->getProperty(sdbus::PropertyName{"Completed"}).onInterface(kOperation1Iface).get<bool>();
    if (completed) {
        read.status =
            opProxy->getProperty(sdbus::PropertyName{"Status"}).onInterface(kOperation1Iface).get<std::uint32_t>();
        read.errorCode =
            opProxy->getProperty(sdbus::PropertyName{"ErrorCode"}).onInterface(kOperation1Iface).get<std::uint32_t>();
    } else {
        std::unique_lock lk(mtx);
        if (!cv.wait_for(lk, budget, [&] { return finished; })) {
            lk.unlock();
            read.timedOut = true;
            // Nobody waits for this read any more: end it, so whatever window
            // it raised closes instead of standing with no consumer.
            try {
                opProxy->callMethod("Cancel").onInterface(sdbus::InterfaceName{kOperation1Iface}).dontExpectReply();
            } catch (...) {
            }
            return read;
        }
        read.status = status;
        read.errorCode = errorCode;
        read.message = std::move(message);
    }
    if (read.status != 0 /*Ok*/) {
        return read;
    }
    opProxy->callMethod("GetResult")
        .onInterface(sdbus::InterfaceName{kCertificatesIface})
        .storeResultsTo(read.certificates);
    return read;
}

} // namespace LibreSCRS::Pkcs11Agent
