// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// The reader-routing seams AgentCore's PKCS#11 host consults, expressed in terms
// of the slim transport's presence snapshot. The neutral core traffics in opaque
// ObjectIds and a card-key string; the transport answers a reader OBJECT PATH with
// {reader name, card object path}. These factories reconcile the two shapes: the
// reader's opaque ObjectId is recovered from the reader path through the backend's
// sole ObjectId<->path bijection (objectIdFromPath), so no core-visible type has
// to grow a wire concept and the transport's ReaderCard stays a pure wire triple.
//
// The returned callables borrow @p transport by reference; it MUST outlive the
// AgentCore that stores them (AgentService + tests enforce this — the transport is
// torn down AFTER the core that holds the seams).
#pragma once
#include "AgentObjectPath.h"                     // objectIdFromPath (reader/card path -> ObjectId)
#include "BusExporter.h"                         // BusExporter::resolveReaderCard (presence snapshot)
#include <LibreSCRS/Agent/AgentCore.h>           // ReaderCard, ResolveReaderCard
#include <LibreSCRS/Agent/pkcs11/Pkcs11Broker.h> // Pkcs11Broker::ResolveCardKeySeam
#include <optional>
#include <string>

namespace LibreSCRS::Agent {

// Reader path -> {readerId, readerName, cardKey}, or nullopt when the reader holds
// no card. The readerId is the reader path's opaque tail; the readerName + cardKey
// come straight from the transport's self-consistent presence snapshot.
[[nodiscard]] inline ResolveReaderCard makeResolveReaderCard(const BusExporter& transport)
{
    return [&transport](const std::string& readerPath) -> std::optional<ReaderCard> {
        const auto rc = transport.resolveReaderCard(readerPath);
        if (!rc) {
            return std::nullopt;
        }
        return ReaderCard{
            .readerId = objectIdFromPath(readerPath),
            .readerName = rc->readerName,
            .cardKey = rc->cardKey,
        };
    };
}

// Reader path -> the card's opaque ObjectId (the lease key's card component),
// recovered from the per-insertion card object path the reader currently holds;
// nullopt when no card is present.
[[nodiscard]] inline Pkcs11Broker::ResolveCardKeySeam makeResolveCardKey(const BusExporter& transport)
{
    return [&transport](const std::string& readerPath) -> std::optional<ObjectId> {
        const auto rc = transport.resolveReaderCard(readerPath);
        if (!rc) {
            return std::nullopt;
        }
        return objectIdFromPath(rc->cardKey);
    };
}

} // namespace LibreSCRS::Agent
