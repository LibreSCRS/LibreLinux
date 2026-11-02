// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include "dbus/GrantGate.h"
#include "dbus/OperationAdaptorFactory.h" // ChannelMaker
#include "org.librescrs.Agent.Card1_adaptor.h"
#include "org.librescrs.Agent.Credentials1_adaptor.h"
#include <sdbus-c++/AdaptorInterfaces.h>
#include <sdbus-c++/IConnection.h>
#include <sdbus-c++/Types.h>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

namespace LibreSCRS::Agent {

class AgentCore;

namespace Operations {
class OperationLauncher;
} // namespace Operations

// What one card object knows about its own card, resolved by AgentFrontend before
// the object is exported. Everything an operation on the card needs beyond this
// comes from the agent core through the OperationLauncher.
struct CardOperationDeps
{
    std::string cardKey;
    std::string readerName;

    // Wire value of the read-only Card1.PreReadAuthMethod property
    // ("None"|"Mrz"|"Can"). Resolved by PresenceModel during capability
    // resolution and carried through here. Empty is treated as "None".
    std::string preReadAuth;

    // Initial Card1.CardType value: the pluginId of the strictly
    // highest-priority candidate, arbitrated at the same deferred point as
    // preReadAuth above, or empty (tied candidates / not yet known -- see
    // CardTypeArbitration.h). The CardObject re-publishes a LATER authoritative value
    // (from a completed read) via PropertiesChanged -- this field only seeds
    // the value at construction.
    std::string cardType;
    // Card1.Atr: uppercase hex, no separators, the full session ATR. Known
    // synchronously before the card object is even constructed and never
    // changes for the card's lifetime -- no live-update path needed.
    std::string atrHex;

    // Built by AgentFrontend (buildDepsForCard's callers): handed to the
    // launcher as the identity and photo reads' card-type sink. Runs on the
    // PER-READER WORKER thread (inside
    // IdentityReadFlow::run(), synchronously within doWork()) -- NOT the bus
    // thread -- so it must NEVER touch this CardObject (or anything else
    // bus-thread-owned) directly; AgentFrontend's implementation hops onto the
    // event-loop thread via its value-captured loop-post sink (mirroring
    // scheduleCardResolve's worker->loop marshal) and re-resolves the card by its
    // STRING path under AgentFrontend's own mutex. Card removal does NOT drain
    // the reader's in-flight ops, so this callback can fire (and marshal here)
    // AFTER the card was withdrawn: AgentFrontend::applyCardTypeUpdate CO-OWNS
    // the CardObject (a shared_ptr copy taken under its mutex) for the whole
    // update, so a concurrent monitor-thread withdraw only drops the map's owner
    // and can never free this object while the update dereferences it. A card
    // withdrawn before the marshal lands is simply not found and the update is
    // dropped. Either way the worker never touches freed memory.
    std::function<void(const std::string&)> onCardTypeResolved;
};

// Real exported D-Bus object at /org/librescrs/Agent/card/<n>. Carries the
// ATR-resolved capabilities and the parent reader path. Each method checks what
// only this bus can check (the capability bit, authorization, its own argument
// decoding) and hands the operation to the agent library's OperationLauncher with
// the channel that exports it here.
class CardObject final
    : public sdbus::AdaptorInterfaces<org::librescrs::Agent::Card1_adaptor, org::librescrs::Agent::Credentials1_adaptor>
{
public:
    CardObject(sdbus::IConnection& connection, sdbus::ObjectPath path, std::uint32_t capabilities,
               sdbus::ObjectPath reader, AgentCore& core, Operations::OperationLauncher& launcher,
               CardOperationDeps deps);
    ~CardObject();

    CardObject(const CardObject&) = delete;
    CardObject& operator=(const CardObject&) = delete;

    // Update the live CardType and emit a PropertiesChanged for it -- the
    // post-read authoritative update (IdentityReadFlow resolving
    // CardData::cardType via ReadIdentity or a GetPhoto cache miss). A no-op
    // (no signal) when the value did not actually change. PUBLIC (unlike the
    // Card1 method overrides below): called externally by AgentFrontend, on
    // the event-loop thread, once it has safely re-resolved this object by
    // its object path (see CardOperationDeps::onCardTypeResolved's comment).
    void updateCardType(const std::string& cardType);

private:
    std::uint32_t Capabilities() override;
    sdbus::ObjectPath Reader() override;
    std::string PreReadAuthMethod() override;
    std::string CardType() override;
    std::string Atr() override;
    sdbus::ObjectPath ReadIdentity() override;
    sdbus::ObjectPath GetPhoto() override;
    sdbus::ObjectPath ReadCertificates() override;
    sdbus::ObjectPath ReadTokenInfo() override;
    // Sign, SignBatch, ManagePin and ActivateSigningKey are authorised before
    // they act, and the authority may take as long as a person needs to answer
    // a dialog, so they are ASYNC methods: the reply is deferred until it
    // answers, and the dispatcher serves everyone else meanwhile
    // (authorizeThenReply). The *Granted halves run only after a grant and keep
    // the synchronous shape: return the operation path, throw the refusal.
    void Sign(sdbus::Result<sdbus::ObjectPath>&& result, std::string certId, sdbus::UnixFd inputFd,
              std::map<std::string, sdbus::Variant> options) override;
    // documents: a(sh) -- (displayName, inputFd) per entry, 1-12. Same gates
    // as Sign -- see SignBatch's own doc block in dbus/CardObject.cpp.
    void SignBatch(sdbus::Result<sdbus::ObjectPath>&& result,
                   std::vector<sdbus::Struct<std::string, sdbus::UnixFd>> documents, std::string certId,
                   std::map<std::string, sdbus::Variant> options) override;
    sdbus::ObjectPath signGranted(const std::string& certId, const sdbus::UnixFd& inputFd,
                                  const std::map<std::string, sdbus::Variant>& options, const std::string& sender,
                                  const std::string& requester);
    sdbus::ObjectPath signBatchGranted(const std::vector<sdbus::Struct<std::string, sdbus::UnixFd>>& documents,
                                       const std::string& certId, const std::map<std::string, sdbus::Variant>& options,
                                       const std::string& sender, const std::string& requester);

    // Credentials1 surface (hosted on this same card path). Entry gating per
    // design: capability bit 3 (PinManagement) -> UnsupportedOnThisCard; ManagePin
    // additionally rejects malformed verb / undefined option / illegal combination
    // (InvalidRequest) and an unknown/unlisted pinId (UnknownCredential) before any
    // Operation is minted. Mutations route through the same Authorizer + RateLimiter
    // as Sign, before any prompt.
    void ManagePin(sdbus::Result<sdbus::ObjectPath>&& result, std::string pinId, std::string verb,
                   std::map<std::string, sdbus::Variant> options) override;
    void ActivateSigningKey(sdbus::Result<sdbus::ObjectPath>&& result) override;
    sdbus::ObjectPath managePinGranted(const std::string& pinId, const std::string& verb,
                                       const std::map<std::string, sdbus::Variant>& options, const std::string& sender,
                                       const std::string& requester);
    sdbus::ObjectPath activateSigningKeyGranted(const std::string& sender, const std::string& requester);
    sdbus::ObjectPath ListCredentials() override;

    // Launch @p args on this card's reader for the caller of the method being
    // served, its result exported through @p makeChannel. A full reader queue
    // throws RateLimited.
    template <class Args>
    sdbus::ObjectPath launch(ChannelMaker makeChannel, Args args, const std::string& sender,
                             const std::string& requester);

    [[nodiscard]] bool hasIdentityCapability() const noexcept;
    [[nodiscard]] bool hasPkiCapability() const noexcept;
    [[nodiscard]] bool hasPinManagementCapability() const noexcept;
    // Rate-limit an authorised Credentials1 mutation (ManagePin /
    // ActivateSigningKey) through the SAME RateLimiter as Card1.Sign, BEFORE any
    // prompt. Throws RateLimited on rejection.
    void rateLimitCredentialMutation(const std::string& sender) const;
    [[nodiscard]] std::string callerSender() const noexcept;
    // Best-effort human-meaningful label for the client driving the in-flight
    // method call (the consent prompt's "Requested by: <x>"). Empty on any
    // resolution failure.
    [[nodiscard]] std::string callerRequesterLabel() const noexcept;

    // The agent bus connection (same connection the AdaptorInterfaces base is
    // hosted on). Held so the Card1 methods can build each Operation's exported
    // channel (dbus/OperationAdaptorFactory).
    sdbus::IConnection& m_connection;
    std::uint32_t m_capabilities;
    sdbus::ObjectPath m_reader;
    // The authorizer, rate limiter, signing configuration and credential
    // listing the methods consult before launching. Outlives this object.
    AgentCore& m_core;
    // Outlives this object (AgentFrontend owns both).
    Operations::OperationLauncher& m_launcher;
    CardOperationDeps m_deps;
    sdbus::ObjectPath m_selfPath;
    // Live CardType (seeded from m_deps.cardType, updated post-read). Guarded
    // by m_cardTypeMutex: updateCardType() runs off the bus thread (a worker
    // thread, via the IdentityReadFlow onCardType callback), racing the
    // bus-thread CardType() property getter. m_deps.atrHex is immutable after
    // construction and needs no guard.
    mutable std::mutex m_cardTypeMutex;
    std::string m_cardType;
    // What a grant that answers after an asynchronous authorization runs
    // under; closed first thing in the destructor (authorizeThenReply).
    std::shared_ptr<GrantGate> m_grantGate = std::make_shared<GrantGate>();
};

} // namespace LibreSCRS::Agent
