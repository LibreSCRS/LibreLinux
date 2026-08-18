// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <LibreSCRS/Agent/operations/Seams.h>
#include "org.librescrs.Agent.Card1_adaptor.h"
#include "org.librescrs.Agent.Credentials1_adaptor.h"
#include <LibreSCRS/CancelToken.h>
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

class CredentialCache;
class CardReadCache;
class CredentialSnapshotCache;
class Authorizer;
struct CryptoWorkerContext;

namespace Config {
class ConfigStore;
}

namespace Operations {
class OperationManager;
class OperationBase;
class PromptSerializer;
class RateLimiter;
class CredentialManager;
class TrustVerifier;
} // namespace Operations

// Per-card seam bundle constructed by BusExporter::buildDepsForCard and
// transferred into the CardObject. The CardObject owns the seams (shared_ptr
// members) so they share the card's lifetime; freed when ObjectRegistry erases
// the card on CardRemoved — UNLESS an abandoned typed op still co-owns one.
//
// The seams are shared_ptr (not unique_ptr) so a typed op abandoned to the
// process-lifetime zombie list can CO-OWN the seam it drives (keepAlive'd in
// attachLifetimeGuards): the sign seam holds the signing-engine provider by
// reference and, on unblock past the flow gate, dereferences its own vtable +
// that engine, so the seam object itself must outlive the zombie. The stateless
// read/cert seams are co-owned too, so their statelessness is a safety margin,
// not the thing the invariant rests on.
//
// The raw pointers are convenience handles into the shared_ptr members; the
// CardObject's ctor wires them after taking ownership of the shares.
struct CardOperationDeps
{
    std::shared_ptr<Operations::CardReader> ownedReader;
    // Deposits a holder-chosen passport MRZ into the candidate plugins when an
    // identity read renegotiates a CAN prompt into an MRZ read. Same
    // co-ownership class as the other seams: it holds the plugin registry by
    // reference, so an abandoned reader that unblocks past the flow gate must
    // not find it freed with the card. Engaged only when the frontend was given
    // a plugin registry to resolve deposit targets from.
    std::shared_ptr<Operations::CredentialDepositor> ownedDepositor;
    std::shared_ptr<Operations::CertificateReader> ownedCertReader;
    std::shared_ptr<Operations::Signer> ownedSigner;
    std::shared_ptr<Operations::CredentialManager> ownedCredentials;
    // Same co-ownership class as ownedSigner: LmTrustVerifier holds the
    // SigningEngineProvider by reference (it reuses that provider's own
    // TrustStoreService rather than building a second one), so an abandoned
    // ReadCertificates worker that unblocks past the flow gate and
    // dereferences this seam's vtable + the engine it holds must keep the
    // seam alive too.
    std::shared_ptr<Operations::TrustVerifier> ownedTrustVerifier;

    // Non-owning handles. May be set directly (test path) or auto-populated
    // from the shared_ptr members above by CardObject's ctor when those are
    // engaged. The Operation classes consume references, so these handles
    // must remain valid for the card's lifetime.
    Operations::CardReader* reader{nullptr};
    // Auto-populated from ownedDepositor. Left null by tests that wire the bare
    // handles directly; CardObject then hands the read/photo operations the
    // shared no-op depositor, so the flow's reference is always well-formed and
    // a renegotiation simply deposits nothing.
    Operations::CredentialDepositor* depositor{nullptr};
    Operations::CertificateReader* certReader{nullptr};
    Operations::TrustVerifier* trustVerifier{nullptr};
    Operations::Signer* signer{nullptr};
    // PIN-lifecycle plugin seam driving the Credentials1 flows (list / change /
    // activate). Co-owned via ownedCredentials for the abandoned-worker keep-alive.
    Operations::CredentialManager* credentialManager{nullptr};
    Operations::PrompterClientBase* prompter{nullptr};
    // Agent-wide single-live-prompt gate. Shared across all cards/readers;
    // the agent owns it (one per process). May be null in tests that never
    // drive a real prompt.
    Operations::PromptSerializer* serializer{nullptr};
    CredentialCache* credentials{nullptr};
    // Per-card ListCredentials snapshot store (the id namespace ManagePin /
    // ActivateSigningKey address). Owned by AgentCore's crypto-worker context so an
    // abandoned credential worker keeps it alive on unblock; the CardObject only
    // borrows the pointer.
    CredentialSnapshotCache* snapshotCache{nullptr};

    // Abandoned-worker keep-alive: a single shared handle to the crypto-worker
    // context the CardObject attaches (op.keepAlive) to every typed op it spawns.
    // An op whose worker is abandoned while blocked in the consent prompt co-owns
    // every core member its post-unblock unwind may touch through this ONE share:
    // the prompter for the blocked call itself, the prompt gate for the SlotGuard
    // unwind, and the credential cache for a nested CAN/MRZ prompt's putCan/putMrz
    // past the flow gate. The typed path never touches the pkcs11 lease, so that
    // member of the context is harmlessly along for the ride. The bare
    // prompter/serializer/credentials handles above stay for the flow's `&` Deps;
    // this is pure ownership. May be null in tests that never drive a real prompt.
    std::shared_ptr<CryptoWorkerContext> cryptoContext;
    // Abandoned-worker keep-alive for the op's OWN sdbus channel/adaptor: a share of
    // the agent bus connection, keepAlive'd (attachLifetimeGuards) into every typed
    // op. A typed op abandoned to the process-lifetime zombie list co-owns the
    // connection until it drains, so its channel adaptor's emit (watchdog/finish) +
    // unregister (op destruction) touch a LIVE connection, not one freed with the
    // AgentService host. A DIFFERENT resource class than the crypto context (which
    // covers core members); this covers the backend transport object. May be null in
    // tests that never drive a real bus.
    std::shared_ptr<sdbus::IConnection> connectionKeepAlive;
    // Agent-wide shutdown-cancel token, bound to every typed op so on backend
    // teardown the flow bails at its post-prompt gate before touching torn-down
    // members and the op skips its wire completion. Default = never-cancellable.
    LibreSCRS::CancelToken shutdownToken;
    CardReadCache* readCache{nullptr};
    // Client-authorization gate (polkit) + sign-flood throttle. Both are
    // agent-wide singletons shared across cards; the Sign method consults them.
    Authorizer* authorizer{nullptr};
    Operations::RateLimiter* rateLimiter{nullptr};
    // Agent-owned signing config — the single source of truth for signing
    // defaults. Sign reads DefaultLevel/Reason/Location as the fallbacks for
    // absent options.
    Config::ConfigStore* config{nullptr};

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

    // Built by AgentFrontend (buildDepsForCard's callers): forwarded verbatim
    // into ReadIdentityOperation::Deps / GetPhotoOperation::Deps as
    // onCardType. Runs on the PER-READER WORKER thread (inside
    // IdentityReadFlow::run(), synchronously within doWork()) -- NOT the bus
    // thread -- so it must NEVER touch this CardObject (or anything else
    // bus-thread-owned) directly; AgentFrontend's implementation hops onto the
    // event-loop thread via its value-captured loop-post sink (mirroring
    // makeCardResolver's worker->loop marshal) and re-resolves the card by its
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
// ATR-resolved capabilities, the parent reader path, a reference to the
// OperationManager, and the per-card seam bundle that ReadIdentity / GetPhoto
// pass into each spawned Operation.
class CardObject final
    : public sdbus::AdaptorInterfaces<org::librescrs::Agent::Card1_adaptor, org::librescrs::Agent::Credentials1_adaptor>
{
public:
    CardObject(sdbus::IConnection& connection, sdbus::ObjectPath path, std::uint32_t capabilities,
               sdbus::ObjectPath reader, Operations::OperationManager& manager, CardOperationDeps deps);
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
    sdbus::ObjectPath Sign(const std::string& certId, const sdbus::UnixFd& inputFd,
                           const std::map<std::string, sdbus::Variant>& options) override;
    // documents: a(sh) -- (displayName, inputFd) per entry, 1-12. Shares the
    // exact same seam gate (hasSignSeams()) as Sign -- see SignBatch's own
    // doc block in dbus/CardObject.cpp.
    sdbus::ObjectPath SignBatch(const std::vector<sdbus::Struct<std::string, sdbus::UnixFd>>& documents,
                                const std::string& certId,
                                const std::map<std::string, sdbus::Variant>& options) override;

    // Credentials1 surface (hosted on this same card path). Entry gating per
    // design: capability bit 3 (PinManagement) -> UnsupportedOnThisCard; ManagePin
    // additionally rejects malformed verb / undefined option / illegal combination
    // (InvalidRequest) and an unknown/unlisted pinId (UnknownCredential) before any
    // Operation is minted. Mutations route through the same Authorizer + RateLimiter
    // as Sign, before any prompt.
    sdbus::ObjectPath ManagePin(const std::string& pinId, const std::string& verb,
                                const std::map<std::string, sdbus::Variant>& options) override;
    sdbus::ObjectPath ActivateSigningKey() override;
    sdbus::ObjectPath ListCredentials() override;

    // Attach the abandoned-worker lifetime guards to a freshly built typed op:
    // co-own the prompter + prompt-gate + credential-cache shares and bind the
    // shutdown-cancel token, so an op whose worker is abandoned mid-prompt keeps
    // every member its unwind touches alive and bails + skips completion on teardown.
    void attachLifetimeGuards(Operations::OperationBase& op) const;

    [[nodiscard]] bool hasIdentityCapability() const noexcept;
    [[nodiscard]] bool hasPkiCapability() const noexcept;
    [[nodiscard]] bool hasPinManagementCapability() const noexcept;
    [[nodiscard]] bool hasAllSeams() const noexcept;
    [[nodiscard]] bool hasCertSeams() const noexcept;
    // Token info uses the identity CardReader seam (readTokenInfo(), a
    // sibling of read()) + the shared prompt/credential plumbing; it does
    // NOT need the identity read cache (thin, no caching).
    [[nodiscard]] bool hasTokenInfoSeams() const noexcept;
    [[nodiscard]] bool hasSignSeams() const noexcept;
    [[nodiscard]] bool hasCredentialSeams() const noexcept;
    // Authorize + rate-limit a Credentials1 mutation (ManagePin / ActivateSigningKey)
    // through the SAME Authorizer action + RateLimiter as Card1.Sign, in that order,
    // BEFORE any prompt. Throws the mapped typed error (NotAuthorized / RateLimited)
    // on rejection; returns normally when the caller may proceed.
    void authorizeCredentialMutation(const std::string& sender) const;
    [[nodiscard]] std::string callerSender() const noexcept;
    // Best-effort human-meaningful label for the client driving the in-flight
    // method call (the consent prompt's "Requested by: <x>"). Empty on any
    // resolution failure.
    [[nodiscard]] std::string callerRequesterLabel() const noexcept;

    // The agent bus connection (same connection the AdaptorInterfaces base is
    // hosted on). Held so the Card1 methods can build each Operation's exported
    // sdbus adaptor via the backend factory (dbus/OperationAdaptorFactory).
    sdbus::IConnection& m_connection;
    std::uint32_t m_capabilities;
    sdbus::ObjectPath m_reader;
    Operations::OperationManager& m_manager;
    CardOperationDeps m_deps;
    sdbus::ObjectPath m_selfPath;
    // Live CardType (seeded from m_deps.cardType, updated post-read). Guarded
    // by m_cardTypeMutex: updateCardType() runs off the bus thread (a worker
    // thread, via the IdentityReadFlow onCardType callback), racing the
    // bus-thread CardType() property getter. m_deps.atrHex is immutable after
    // construction and needs no guard.
    mutable std::mutex m_cardTypeMutex;
    std::string m_cardType;
};

} // namespace LibreSCRS::Agent
