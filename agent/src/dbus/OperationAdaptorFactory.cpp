// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#include "dbus/OperationAdaptorFactory.h"

#include "SealedMemfd.h"
#include "dbus/CredentialOutcomeNames.h"
#include "dbus/TypedResultStore.h"
#include "operations/Operation1Adaptor.h"
#include <LibreSCRS/Agent/backend/Logging.h>
#include <LibreSCRS/Agent/backend/OperationChannel.h>
#include <LibreSCRS/Agent/OperationState.h>
#include "org.librescrs.Agent.Operation.Certificates1_adaptor.h"
#include "org.librescrs.Agent.Operation.Credentials1_adaptor.h"
#include "org.librescrs.Agent.Operation.Identity1_adaptor.h"
#include "org.librescrs.Agent.Operation.Photo1_adaptor.h"
#include "org.librescrs.Agent.Operation.Sign1_adaptor.h"
#include "org.librescrs.Agent.Operation.SignBatch1_adaptor.h"

#include <sdbus-c++/Error.h>
#include <sdbus-c++/Types.h>

#include <unistd.h> // ::close (Photo1.GetResult adoption failure path)

#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>
#include <variant>
#include <vector>

namespace LibreSCRS::Agent::Operations {

namespace {

// The frozen NoResult error every GetResult maps an un-ready recovery store to
// (grace window elapsed / op not finished Ok / re-seal failed).
constexpr const char* kNoResult = "org.librescrs.Agent.Error.NoResult";

[[noreturn]] void throwNoResult(const char* what)
{
    throw sdbus::Error{sdbus::Error::Name{kNoResult}, what};
}

// One OperationChannel impl per typed sub-adaptor. Each owns its inner
// per-kind adaptor (Operation1 + the typed sub-interface incl. its GetResult)
// and shares the same OperationState so Cancel() flips the same flag the worker
// observes via OperationBase::isCancelled(). emitResult selects its variant arm
// from the closed ResultPayload, publishes the late-subscriber recovery store
// (served by GetResult while the op survives the cleanup grace), and marshals
// the matching wire signal (the memfd sealing for Photo1/Sign1 lives here — the
// core yields plain bytes). emitFinished/emitResult are the noexcept backend
// boundary. Every channel declares its recovery store BEFORE its inner adaptor:
// the adaptor's GetResult reads the same store the channel writes on emitResult.

// Operation1 + Identity1 host: adds the Identity1.GetResult late-subscriber
// recovery, re-marshalling the retained snapshot through the SAME wire builder
// the Result signal used.
class Identity1Adaptor final : public Operation1Adaptor<org::librescrs::Agent::Operation::Identity1_adaptor>
{
public:
    Identity1Adaptor(sdbus::IConnection& bus, sdbus::ObjectPath path, std::shared_ptr<OperationState> state,
                     std::shared_ptr<IdentityResultState> resultState)
        : Operation1Adaptor(bus, std::move(path), std::move(state)), m_resultState(std::move(resultState))
    {}

private:
    Identity1Wire GetResult() override
    {
        auto snapshot = m_resultState ? readStoredResult(*m_resultState) : std::nullopt;
        if (!snapshot) {
            throwNoResult("no identity result is available");
        }
        return buildIdentity1Wire(*snapshot);
    }

    std::shared_ptr<IdentityResultState> m_resultState;
};

class IdentityChannel final : public OperationChannel
{
public:
    IdentityChannel(sdbus::IConnection& bus, sdbus::ObjectPath path, std::shared_ptr<OperationState> state)
        : m_resultState(std::make_shared<IdentityResultState>()),
          m_inner(bus, std::move(path), std::move(state), m_resultState)
    {}
    void emitPropertiesChanged() noexcept override
    {
        m_inner.emitPropertiesChangedForOperation1();
    }
    void emitFinished(OperationStatus s, ErrorCode e, std::string_view k, std::string_view f) noexcept override
    {
        m_inner.emitFinishedNx(static_cast<std::uint32_t>(s), static_cast<std::uint32_t>(e), k, f);
    }
    bool emitResult(const ResultPayload& r) noexcept override
    {
        // Identity1 delivers inline (no memfd seal), so it can never fail closed
        // (the frozen core contract keeps inline channels always-true). The
        // recovery store is published BEFORE the signal (Sign's ordering) so a
        // late subscriber that races the signal recovers via GetResult; a
        // publish failure (bad_alloc) cannot block the inline signal, so it
        // fails OPEN — logged, signal still emitted, GetResult maps to NoResult.
        if (const auto* snap = std::get_if<CardReadSnapshot>(&r)) {
            if (!publishResult(*m_resultState, *snap)) {
                log::warn("IdentityChannel: recovery-store publish failed; "
                          "a late Identity1.GetResult will map to Error.NoResult");
            }
            emitIdentity1Result(m_inner, *snap);
        }
        return true;
    }
    // Progressive delivery: called from the SAME worker thread, inside the
    // SAME doWork() call, that will go on to call emitResult above once
    // IdentityReadFlow::run() returns -- no new cross-thread hop, no new
    // lifetime hazard versus the already-established emitResult contract.
    // Never fails closed (a dropped Group signal is not fatal to the op: the
    // eventual Result stays authoritative regardless), so this stays void
    // rather than bool like emitResult.
    void emitGroup(const GroupSnapshot& group) noexcept override
    {
        emitIdentity1Group(m_inner, group);
    }

private:
    std::shared_ptr<IdentityResultState> m_resultState;
    Identity1Adaptor m_inner;
};

// Operation1 + Certificates1 host: adds the Certificates1.GetResult recovery,
// re-marshalling the retained parse through the SAME wire builder as the signal.
class Certificates1Adaptor final : public Operation1Adaptor<org::librescrs::Agent::Operation::Certificates1_adaptor>
{
public:
    Certificates1Adaptor(sdbus::IConnection& bus, sdbus::ObjectPath path, std::shared_ptr<OperationState> state,
                         std::shared_ptr<CertificatesResultState> resultState)
        : Operation1Adaptor(bus, std::move(path), std::move(state)), m_resultState(std::move(resultState))
    {}

private:
    Certificates1Wire GetResult() override
    {
        auto certs = m_resultState ? readStoredResult(*m_resultState) : std::nullopt;
        if (!certs) {
            throwNoResult("no certificates result is available");
        }
        return buildCertificates1Wire(*certs);
    }

    std::shared_ptr<CertificatesResultState> m_resultState;
};

class CertificatesChannel final : public OperationChannel
{
public:
    CertificatesChannel(sdbus::IConnection& bus, sdbus::ObjectPath path, std::shared_ptr<OperationState> state)
        : m_resultState(std::make_shared<CertificatesResultState>()),
          m_inner(bus, std::move(path), std::move(state), m_resultState)
    {}
    void emitPropertiesChanged() noexcept override
    {
        m_inner.emitPropertiesChangedForOperation1();
    }
    void emitFinished(OperationStatus s, ErrorCode e, std::string_view k, std::string_view f) noexcept override
    {
        m_inner.emitFinishedNx(static_cast<std::uint32_t>(s), static_cast<std::uint32_t>(e), k, f);
    }
    bool emitResult(const ResultPayload& r) noexcept override
    {
        // Certificates1 delivers inline (no memfd seal), so it can never fail
        // closed. Publish-before-emit + fail-open publish: see IdentityChannel.
        if (const auto* certs = std::get_if<std::vector<CertSnapshot>>(&r)) {
            if (!publishResult(*m_resultState, *certs)) {
                log::warn("CertificatesChannel: recovery-store publish failed; "
                          "a late Certificates1.GetResult will map to Error.NoResult");
            }
            emitCertificates1Result(m_inner, *certs);
        }
        return true;
    }

private:
    std::shared_ptr<CertificatesResultState> m_resultState;
    Certificates1Adaptor m_inner;
};

// Operation1 + Photo1 host: adds the Photo1.GetResult recovery. The store
// retains raw photo BYTES (exactly like the Sign artifact); every GetResult
// re-seals them into FRESH sealed memfds, so nothing here tracks fd lifetime —
// the reply's UnixFds are the only handles and sdbus-c++ closes them post-send.
class Photo1Adaptor final : public Operation1Adaptor<org::librescrs::Agent::Operation::Photo1_adaptor>
{
public:
    Photo1Adaptor(sdbus::IConnection& bus, sdbus::ObjectPath path, std::shared_ptr<OperationState> state,
                  std::shared_ptr<PhotoResultState> resultState)
        : Operation1Adaptor(bus, std::move(path), std::move(state)), m_resultState(std::move(resultState))
    {}

private:
    std::map<std::string, sdbus::UnixFd> GetResult() override
    {
        auto sealed = m_resultState ? sealStoredPhotos(*m_resultState, &SealedMemfd::create) : std::nullopt;
        if (!sealed) {
            throwNoResult("no photo result is available");
        }
        // Adopt every raw fd into a UnixFd as it is inserted, so a bad_alloc
        // mid-build unwinds via the UnixFd destructors — no fd leaks. A raw fd
        // pending adoption on the throwing path is closed explicitly.
        std::map<std::string, sdbus::UnixFd> photos;
        for (auto& s : *sealed) {
            sdbus::UnixFd owned{s.fd, sdbus::adopt_fd};
            s.fd = -1; // adopted — sealStoredPhotos ownership handed over
            try {
                photos.emplace(std::move(s.key), std::move(owned));
            } catch (...) {
                // `owned` (moved-from or not) + `photos` close theirs; close the
                // rest still parked in `sealed`.
                for (const auto& rest : *sealed) {
                    if (rest.fd >= 0) {
                        ::close(rest.fd);
                    }
                }
                throw;
            }
        }
        return photos;
    }

    std::shared_ptr<PhotoResultState> m_resultState;
};

class PhotoChannel final : public OperationChannel
{
public:
    PhotoChannel(sdbus::IConnection& bus, sdbus::ObjectPath path, std::shared_ptr<OperationState> state)
        : m_resultState(std::make_shared<PhotoResultState>()),
          m_inner(bus, std::move(path), std::move(state), m_resultState)
    {}
    void emitPropertiesChanged() noexcept override
    {
        m_inner.emitPropertiesChangedForOperation1();
    }
    void emitFinished(OperationStatus s, ErrorCode e, std::string_view k, std::string_view f) noexcept override
    {
        m_inner.emitFinishedNx(static_cast<std::uint32_t>(s), static_cast<std::uint32_t>(e), k, f);
    }
    bool emitResult(const ResultPayload& r) noexcept override
    {
        const auto* photos = std::get_if<PhotoResult>(&r);
        if (!photos) {
            return true; // not this channel's payload arm; nothing to deliver
        }
        // Seal each raw photo into a sealed memfd, keyed by "groupKey:fieldKey".
        // Build the wire map with UnixFd values (RAII): a bad_alloc mid-build
        // unwinds via the UnixFd destructors and closes every fd — no leak. A
        // seal failure fails the op CLOSED (return false): GetPhotoOperation then
        // finishes Error(CommunicationError) rather than leaking Finished(Ok)
        // with no photo signal. Mirrors Sign's ordering: seal FIRST, publish the
        // recovery store only after every REQUIRED seal succeeded (a publish
        // copy failure also fails closed — the wire map is discarded, fds close
        // via RAII, and the store stays UNREADY so a racing Photo1.GetResult
        // maps to Error.NoResult), then emit — an emit failure after a
        // successful publish fails OPEN inside the noexcept emit helper (logged;
        // the op finishes Ok and the client recovers via GetResult).
        try {
            std::map<std::string, sdbus::UnixFd> fds;
            for (const auto& p : *photos) {
                if (p.bytes.empty()) {
                    continue;
                }
                const int fd = SealedMemfd::create(std::span<const std::uint8_t>{p.bytes});
                if (fd < 0) {
                    return false; // fail-closed (fds dtor closes already-built UnixFds)
                }
                fds.emplace(p.key, sdbus::UnixFd{fd, sdbus::adopt_fd});
            }
            if (!fds.empty()) {
                if (!publishResult(*m_resultState, *photos)) {
                    return false; // fail-closed: store unready, no half-delivered Ok
                }
                emitPhoto1Result(m_inner, std::move(fds));
            }
            return true;
        } catch (...) {
            // fds dtor closes any partially-built UnixFds on unwind; fail closed.
            return false;
        }
    }

private:
    std::shared_ptr<PhotoResultState> m_resultState;
    Photo1Adaptor m_inner;
};

// Sign1 wire metadata (a{sv}) from the resolved SignMeta.
std::map<std::string, sdbus::Variant> toMetaVariants(const SignMeta& meta)
{
    std::map<std::string, sdbus::Variant> out;
    out.emplace("format", sdbus::Variant{meta.format});
    out.emplace("level", sdbus::Variant{meta.level});
    out.emplace("tsaUsed", sdbus::Variant{meta.tsaUsed});
    out.emplace("chainComplete", sdbus::Variant{meta.chainComplete});
    return out;
}

// Operation1 + Sign1 host. Derives from the generic Operation1Adaptor to reuse
// all of the Operation1 property/Cancel/Finished machinery and adds the Sign1
// GetResult method. GetResult re-dups the sealed artifact from the shared
// recovery store while the operation is alive (cleanup-grace) AND finished Ok;
// otherwise Error.NoResult.
class Sign1Adaptor final : public Operation1Adaptor<org::librescrs::Agent::Operation::Sign1_adaptor>
{
public:
    Sign1Adaptor(sdbus::IConnection& bus, sdbus::ObjectPath path, std::shared_ptr<OperationState> state,
                 std::shared_ptr<SignResultState> resultState)
        : Operation1Adaptor(bus, std::move(path), std::move(state)), m_resultState(std::move(resultState))
    {}

private:
    std::tuple<sdbus::UnixFd, std::map<std::string, sdbus::Variant>> GetResult() override
    {
        SealedSignResult sealed = m_resultState ? sealStoredResult(*m_resultState) : SealedSignResult{};
        if (sealed.fd < 0) {
            throwNoResult("no signed result is available");
        }
        return {sdbus::UnixFd{sealed.fd, sdbus::adopt_fd}, toMetaVariants(sealed.meta)};
    }

    std::shared_ptr<SignResultState> m_resultState;
};

class SignChannel final : public OperationChannel
{
public:
    SignChannel(sdbus::IConnection& bus, sdbus::ObjectPath path, std::shared_ptr<OperationState> state)
        : m_resultState(std::make_shared<SignResultState>()),
          m_inner(bus, std::move(path), std::move(state), m_resultState)
    {}
    void emitPropertiesChanged() noexcept override
    {
        m_inner.emitPropertiesChangedForOperation1();
    }
    void emitFinished(OperationStatus s, ErrorCode e, std::string_view k, std::string_view f) noexcept override
    {
        m_inner.emitFinishedNx(static_cast<std::uint32_t>(s), static_cast<std::uint32_t>(e), k, f);
    }
    bool emitResult(const ResultPayload& r) noexcept override
    {
        const auto* artifact = std::get_if<SignedArtifact>(&r);
        if (!artifact) {
            return true; // not this channel's payload arm; nothing to deliver
        }
        // Fail-CLOSED on the seal, fail-OPEN once it has succeeded (see
        // sealPublishAndEmitSignResult). A seal failure returns false so
        // SignOperation finishes Error with the store left UNREADY; once the seal
        // succeeds the store is READY, so a throw from toMetaVariants()/the signal
        // marshaling below no longer fails the op closed — it is logged and the op
        // finishes Ok, and the client recovers the already-published artifact via
        // Sign1.GetResult (store ready <=> client gets Ok). The emit lambda ADOPTS
        // the sealed fd first so RAII closes it on every path, including that throw.
        return sealPublishAndEmitSignResult(*m_resultState, artifact->bytes, artifact->meta, &SealedMemfd::create,
                                            [this, artifact](int fd) {
                                                sdbus::UnixFd owned{fd, sdbus::adopt_fd};
                                                m_inner.emitResult(owned, toMetaVariants(artifact->meta));
                                            });
    }

private:
    // Declared before m_inner: the Sign1 adaptor's GetResult reads the same
    // recovery store this channel writes on emitResult.
    std::shared_ptr<SignResultState> m_resultState;
    Sign1Adaptor m_inner;
};

// SignBatch1 wire row: a(sha{sv}u) -- (displayName, artifact fd, meta, errorCode).
using SignBatch1RowTuple =
    sdbus::Struct<std::string, sdbus::UnixFd, std::map<std::string, sdbus::Variant>, std::uint32_t>;
using SignBatch1Wire = std::vector<SignBatch1RowTuple>;

// Operation1 + SignBatch1 host. GetResult re-seals EVERY retained row fresh
// (including a failed row's zero-length fd) from the shared recovery store
// while the operation is alive (cleanup-grace) AND at least one document was
// attempted; otherwise Error.NoResult. Mirrors Sign1Adaptor's shape, one
// artifact-per-row instead of a single artifact.
class SignBatch1Adaptor final : public Operation1Adaptor<org::librescrs::Agent::Operation::SignBatch1_adaptor>
{
public:
    SignBatch1Adaptor(sdbus::IConnection& bus, sdbus::ObjectPath path, std::shared_ptr<OperationState> state,
                      std::shared_ptr<SignBatchResultState> resultState)
        : Operation1Adaptor(bus, std::move(path), std::move(state)), m_resultState(std::move(resultState))
    {}

private:
    SignBatch1Wire GetResult() override
    {
        auto sealed = m_resultState ? sealStoredSignBatchResult(*m_resultState, &SealedMemfd::create) : std::nullopt;
        if (!sealed) {
            throwNoResult("no batch signing result is available");
        }
        SignBatch1Wire rows;
        rows.reserve(sealed->size());
        for (auto& s : *sealed) {
            // Adopt the fd into a UnixFd IMMEDIATELY (before it can be
            // orphaned by a later throw) — mirrors Photo1Adaptor::GetResult's
            // exact idiom, extended to a positional array of rows rather
            // than a map.
            sdbus::UnixFd owned{s.fd, sdbus::adopt_fd};
            s.fd = -1; // adopted — sealStoredSignBatchResult ownership handed over
            try {
                rows.emplace_back(std::move(s.displayName), std::move(owned), toMetaVariants(s.meta),
                                  static_cast<std::uint32_t>(s.code));
            } catch (...) {
                // `owned` (moved-from or not) closes via its own destructor on
                // unwind; close every row NOT yet processed (s.fd == -1 marks
                // the ones already adopted, correctly skipped here).
                for (const auto& rest : *sealed) {
                    if (rest.fd >= 0) {
                        ::close(rest.fd);
                    }
                }
                throw;
            }
        }
        return rows;
    }

    std::shared_ptr<SignBatchResultState> m_resultState;
};

class SignBatchChannel final : public OperationChannel
{
public:
    SignBatchChannel(sdbus::IConnection& bus, sdbus::ObjectPath path, std::shared_ptr<OperationState> state)
        : m_resultState(std::make_shared<SignBatchResultState>()),
          m_inner(bus, std::move(path), std::move(state), m_resultState)
    {}
    void emitPropertiesChanged() noexcept override
    {
        m_inner.emitPropertiesChangedForOperation1();
    }
    void emitFinished(OperationStatus s, ErrorCode e, std::string_view k, std::string_view f) noexcept override
    {
        m_inner.emitFinishedNx(static_cast<std::uint32_t>(s), static_cast<std::uint32_t>(e), k, f);
    }
    bool emitResult(const ResultPayload& r) noexcept override
    {
        const auto* rows = std::get_if<BatchSignResult>(&r);
        if (!rows) {
            return true; // not this channel's payload arm; nothing to deliver
        }
        // Seal EVERY row (a zero-length span for a failed row is a VALID
        // seal, never a failure) and publish the recovery store BEFORE the
        // signal, exactly like Sign1's own ordering. A REQUIRED seal failure
        // fails the op CLOSED (store stays unready); once every seal has
        // succeeded, an emit-marshaling throw fails OPEN (the store is
        // already published, so the client recovers via
        // SignBatch1.GetResult) — same two-phase contract as
        // sealPublishAndEmitSignResult, generalised to N rows.
        auto sealed = publishSealedSignBatchResult(*m_resultState, *rows, &SealedMemfd::create);
        if (!sealed) {
            return false; // fail closed: a seal failed, store stays unready
        }
        try {
            SignBatch1Wire wire;
            wire.reserve(sealed->size());
            for (auto& s : *sealed) {
                sdbus::UnixFd owned{s.fd, sdbus::adopt_fd};
                s.fd = -1;
                try {
                    wire.emplace_back(std::move(s.displayName), std::move(owned), toMetaVariants(s.meta),
                                      static_cast<std::uint32_t>(s.code));
                } catch (...) {
                    for (const auto& rest : *sealed) {
                        if (rest.fd >= 0) {
                            ::close(rest.fd);
                        }
                    }
                    throw;
                }
            }
            m_inner.emitResult(wire);
        } catch (const std::exception& ex) {
            log::warnf("SignBatchChannel: SignBatch1.Result emit failed after a successful seal "
                       "(store ready; client recovers via SignBatch1.GetResult): {}",
                       ex.what());
        } catch (...) {
            log::warn("SignBatchChannel: SignBatch1.Result emit failed after a successful seal "
                      "(store ready; client recovers via SignBatch1.GetResult)");
        }
        return true; // fail open: every seal + the publish already succeeded
    }

private:
    // Declared before m_inner: the SignBatch1 adaptor's GetResult reads the
    // same recovery store this channel writes on emitResult.
    std::shared_ptr<SignBatchResultState> m_resultState;
    SignBatch1Adaptor m_inner;
};

// --- Credentials1 wire marshaling -----------------------------------------

using CredentialResultDict = std::map<std::string, sdbus::Variant>;
using CredentialRecordsWire = std::vector<std::map<std::string, sdbus::Variant>>;

// The uniform outcome payload -> a{sv}. "outcome" + "blocked" are always present;
// retries_left / pin_activated / key_activated are OMITTED when absent (never a
// sentinel). The outcome crosses as its camelCase STRING token, never an int.
CredentialResultDict toCredentialResultDict(const CredentialOpResult& op)
{
    CredentialResultDict out;
    out.emplace("outcome", sdbus::Variant{std::string{credentialOutcomeToken(op.outcome)}});
    out.emplace("blocked", sdbus::Variant{op.blocked});
    if (op.retriesLeft) {
        out.emplace("retries_left", sdbus::Variant{*op.retriesLeft});
    }
    if (op.pinActivated) {
        out.emplace("pin_activated", sdbus::Variant{*op.pinActivated});
    }
    if (op.keyActivated) {
        out.emplace("key_activated", sdbus::Variant{*op.keyActivated});
    }
    return out;
}

// One credential record -> a{sv}. snake_case keys; the enum-valued fields are
// already the frozen camelCase tokens (tokenized in the core value mapper). Integer + guidance
// keys are omitted when absent; boolean keys are always present.
std::map<std::string, sdbus::Variant> toCredentialRecordDict(const CredentialRecord& r)
{
    std::map<std::string, sdbus::Variant> out;
    out.emplace("id", sdbus::Variant{r.id});
    out.emplace("label", sdbus::Variant{r.label});
    out.emplace("kind", sdbus::Variant{r.kind});
    out.emplace("state", sdbus::Variant{r.state});
    const auto emplaceInt = [&out](const char* key, const std::optional<int>& v) {
        if (v) {
            out.emplace(key, sdbus::Variant{*v});
        }
    };
    emplaceInt("retries_left", r.retriesLeft);
    emplaceInt("retries_max", r.retriesMax);
    emplaceInt("uses_left", r.usesLeft);
    emplaceInt("uses_max", r.usesMax);
    emplaceInt("unblocks_left", r.unblocksLeft);
    emplaceInt("min_length", r.minLength);
    emplaceInt("max_length", r.maxLength);
    out.emplace("can_change", sdbus::Variant{r.canChange});
    out.emplace("unblockable", sdbus::Variant{r.unblockable});
    out.emplace("unblock_style", sdbus::Variant{r.unblockStyle});
    out.emplace("activatable", sdbus::Variant{r.activatable});
    out.emplace("key_activation_pending", sdbus::Variant{r.keyActivationPending});
    out.emplace("key_activatable", sdbus::Variant{r.keyActivatable});
    out.emplace("recovery", sdbus::Variant{r.recovery});
    out.emplace("probe_safe", sdbus::Variant{r.probeSafe});
    const auto emplaceStr = [&out](const char* key, const std::optional<std::string>& v) {
        if (v) {
            out.emplace(key, sdbus::Variant{*v});
        }
    };
    emplaceStr("blocked_guidance_key", r.blockedGuidanceKey);
    emplaceStr("blocked_guidance_fallback", r.blockedGuidanceFallback);
    emplaceStr("key_activation_guidance_key", r.keyActivationGuidanceKey);
    emplaceStr("key_activation_guidance_fallback", r.keyActivationGuidanceFallback);
    return out;
}

CredentialRecordsWire toCredentialRecordsWire(const std::vector<CredentialRecord>& records)
{
    CredentialRecordsWire out;
    out.reserve(records.size());
    for (const auto& r : records) {
        out.push_back(toCredentialRecordDict(r));
    }
    return out;
}

// Operation1 + Credentials1 host: adds the Credentials1.GetResult recovery,
// re-marshalling the retained (op + records) through the SAME wire builders as
// the Result signal.
class Credentials1Adaptor final : public Operation1Adaptor<org::librescrs::Agent::Operation::Credentials1_adaptor>
{
public:
    Credentials1Adaptor(sdbus::IConnection& bus, sdbus::ObjectPath path, std::shared_ptr<OperationState> state,
                        std::shared_ptr<CredentialsResultState> resultState)
        : Operation1Adaptor(bus, std::move(path), std::move(state)), m_resultState(std::move(resultState))
    {}

private:
    std::tuple<CredentialResultDict, CredentialRecordsWire> GetResult() override
    {
        auto stored = m_resultState ? readStoredResult(*m_resultState) : std::nullopt;
        if (!stored) {
            throwNoResult("no credential result is available");
        }
        return {toCredentialResultDict(stored->op), toCredentialRecordsWire(stored->records)};
    }

    std::shared_ptr<CredentialsResultState> m_resultState;
};

class CredentialsChannel final : public OperationChannel
{
public:
    CredentialsChannel(sdbus::IConnection& bus, sdbus::ObjectPath path, std::shared_ptr<OperationState> state)
        : m_resultState(std::make_shared<CredentialsResultState>()),
          m_inner(bus, std::move(path), std::move(state), m_resultState)
    {}
    void emitPropertiesChanged() noexcept override
    {
        m_inner.emitPropertiesChangedForOperation1();
    }
    void emitFinished(OperationStatus s, ErrorCode e, std::string_view k, std::string_view f) noexcept override
    {
        m_inner.emitFinishedNx(static_cast<std::uint32_t>(s), static_cast<std::uint32_t>(e), k, f);
    }
    bool emitResult(const ResultPayload& r) noexcept override
    {
        // Credentials1 delivers inline (no memfd seal), so it can never fail
        // closed. Publish-before-emit + fail-open publish, exactly like Identity/
        // Certificates: a late Credentials1.GetResult recovers via the store.
        if (const auto* cred = std::get_if<CredentialResult>(&r)) {
            if (!publishResult(*m_resultState, *cred)) {
                log::warn("CredentialsChannel: recovery-store publish failed; a late "
                          "Credentials1.GetResult will map to Error.NoResult");
            }
            try {
                m_inner.emitResult(toCredentialResultDict(cred->op), toCredentialRecordsWire(cred->records));
            } catch (...) {
                // Inline emit marshaling threw (allocation): fail OPEN — the store
                // is published, so the op finishes normally and the client recovers
                // via Credentials1.GetResult.
                log::warn("CredentialsChannel: Credentials1.Result emit failed after publish "
                          "(client recovers via Credentials1.GetResult)");
            }
        }
        return true;
    }

private:
    std::shared_ptr<CredentialsResultState> m_resultState;
    Credentials1Adaptor m_inner;
};

} // namespace

} // namespace LibreSCRS::Agent::Operations

namespace LibreSCRS::Agent {

std::unique_ptr<Operations::OperationBase> buildIdentityOperation(sdbus::IConnection& bus,
                                                                  const sdbus::ObjectPath& path,
                                                                  Operations::ReadIdentityOperation::Deps deps)
{
    // Construct the shared OperationState BEFORE the channel so the same
    // shared_ptr is handed to the channel and to OperationBase — no window
    // where Cancel() is dropped before hooks are bound.
    auto state = std::make_shared<Operations::OperationState>();
    auto channel = std::make_unique<Operations::IdentityChannel>(bus, path, state);
    return std::make_unique<Operations::ReadIdentityOperation>(std::move(channel), std::move(deps), state);
}

std::unique_ptr<Operations::OperationBase> buildPhotoOperation(sdbus::IConnection& bus, const sdbus::ObjectPath& path,
                                                               Operations::GetPhotoOperation::Deps deps)
{
    auto state = std::make_shared<Operations::OperationState>();
    auto channel = std::make_unique<Operations::PhotoChannel>(bus, path, state);
    return std::make_unique<Operations::GetPhotoOperation>(std::move(channel), std::move(deps), state);
}

std::unique_ptr<Operations::OperationBase> buildCertificatesOperation(sdbus::IConnection& bus,
                                                                      const sdbus::ObjectPath& path,
                                                                      Operations::ReadCertificatesOperation::Deps deps)
{
    auto state = std::make_shared<Operations::OperationState>();
    auto channel = std::make_unique<Operations::CertificatesChannel>(bus, path, state);
    return std::make_unique<Operations::ReadCertificatesOperation>(std::move(channel), std::move(deps), state);
}

std::unique_ptr<Operations::OperationBase> buildTokenInfoOperation(sdbus::IConnection& bus,
                                                                   const sdbus::ObjectPath& path,
                                                                   Operations::ReadTokenInfoOperation::Deps deps)
{
    // Reuses IdentityChannel verbatim: it marshals any CardReadSnapshot
    // through Identity1.Result/GetResult regardless of which Operation
    // produced it — ReadTokenInfo mints NO new result interface.
    auto state = std::make_shared<Operations::OperationState>();
    auto channel = std::make_unique<Operations::IdentityChannel>(bus, path, state);
    return std::make_unique<Operations::ReadTokenInfoOperation>(std::move(channel), std::move(deps), state);
}

std::unique_ptr<Operations::OperationBase> buildSignOperation(sdbus::IConnection& bus, const sdbus::ObjectPath& path,
                                                              Operations::SignOperation::Deps deps)
{
    auto state = std::make_shared<Operations::OperationState>();
    // The SignChannel owns the recovery store shared between its emitResult
    // (writer) and the Sign1 adaptor's GetResult (reader); the op no longer
    // threads it in.
    auto channel = std::make_unique<Operations::SignChannel>(bus, path, state);
    return std::make_unique<Operations::SignOperation>(std::move(channel), std::move(deps), state);
}

std::unique_ptr<Operations::OperationBase> buildSignBatchOperation(sdbus::IConnection& bus,
                                                                   const sdbus::ObjectPath& path,
                                                                   Operations::SignBatchOperation::Deps deps)
{
    auto state = std::make_shared<Operations::OperationState>();
    // The SignBatchChannel owns the recovery store shared between its
    // emitResult (writer) and the SignBatch1 adaptor's GetResult (reader),
    // mirroring SignChannel's own composition.
    auto channel = std::make_unique<Operations::SignBatchChannel>(bus, path, state);
    return std::make_unique<Operations::SignBatchOperation>(std::move(channel), std::move(deps), state);
}

std::unique_ptr<Operations::OperationBase>
buildListCredentialsOperation(sdbus::IConnection& bus, const sdbus::ObjectPath& path,
                              Operations::ListCredentialsOperation::Deps deps)
{
    auto state = std::make_shared<Operations::OperationState>();
    auto channel = std::make_unique<Operations::CredentialsChannel>(bus, path, state);
    return std::make_unique<Operations::ListCredentialsOperation>(std::move(channel), std::move(deps), state);
}

std::unique_ptr<Operations::OperationBase> buildManagePinOperation(sdbus::IConnection& bus,
                                                                   const sdbus::ObjectPath& path,
                                                                   Operations::ManagePinOperation::Deps deps)
{
    auto state = std::make_shared<Operations::OperationState>();
    auto channel = std::make_unique<Operations::CredentialsChannel>(bus, path, state);
    return std::make_unique<Operations::ManagePinOperation>(std::move(channel), std::move(deps), state);
}

std::unique_ptr<Operations::OperationBase>
buildActivateSigningKeyOperation(sdbus::IConnection& bus, const sdbus::ObjectPath& path,
                                 Operations::ActivateSigningKeyOperation::Deps deps)
{
    auto state = std::make_shared<Operations::OperationState>();
    auto channel = std::make_unique<Operations::CredentialsChannel>(bus, path, state);
    return std::make_unique<Operations::ActivateSigningKeyOperation>(std::move(channel), std::move(deps), state);
}

} // namespace LibreSCRS::Agent
