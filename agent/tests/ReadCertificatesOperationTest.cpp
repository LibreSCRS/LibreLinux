// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// A hot certificate cache serves ReadCertificates from RAM without opening a
// session or running the cert reader (mirrors GetPhotoOperation's cache-hit
// contract).

#include <LibreSCRS/Agent/cache/CardReadCache.h>
#include <LibreSCRS/Agent/operations/CardSessionHolder.h>
#include <LibreSCRS/Agent/operations/PromptSerializer.h>
#include "operations/ReadCertificatesOperation.h"

#include <LibreSCRS/SmartCard/CardMap.h>
#include <LibreSCRS/SmartCard/CardSession.h>
#include <gtest/gtest.h>
#include <cstdint>
#include <expected>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

using namespace LibreSCRS::Agent;
using namespace LibreSCRS::Agent::Operations;

namespace {

struct EmittedFinish
{
    std::uint32_t status;
    std::uint32_t errorCode;
};

class FakeOperationChannel final : public OperationChannel
{
public:
    void emitFinished(OperationStatus status, ErrorCode errorCode, std::string_view, std::string_view) noexcept override
    {
        finishes.push_back({static_cast<std::uint32_t>(status), static_cast<std::uint32_t>(errorCode)});
    }
    void emitPropertiesChanged() noexcept override {}
    bool emitResult(const ResultPayload& result) noexcept override
    {
        if (const auto* certs = std::get_if<std::vector<CertSnapshot>>(&result)) {
            captured = *certs;
        }
        return true;
    }
    std::vector<EmittedFinish> finishes;
    std::optional<std::vector<CertSnapshot>> captured;
};

std::vector<CertSnapshot> certsFixture()
{
    CertSnapshot cert;
    cert.certId = "abc123";
    cert.signingCapable = true;
    std::vector<CertSnapshot> certs;
    certs.push_back(std::move(cert));
    return certs;
}

// Holder whose factory fails the test if invoked: the cache-hot path must never
// acquire a session.
inline std::unique_ptr<CardSessionHolder> makeUnusedHolder()
{
    auto factory = [](const std::string& r)
        -> std::expected<std::shared_ptr<LibreSCRS::SmartCard::CardSession>, LibreSCRS::SmartCard::OpenError> {
        ADD_FAILURE() << "holder must not open a session when the cert cache is hot";
        return LibreSCRS::SmartCard::detail::makeDetachedCardSession(r);
    };
    auto resolver = [](std::span<const std::uint8_t>, LibreSCRS::SmartCard::CardSession&) { return CandidateList{}; };
    return std::make_unique<CardSessionHolder>("Unused", std::move(factory), std::move(resolver),
                                               std::make_shared<LibreSCRS::SmartCard::CardMap>());
}

class UnusedCertReader final : public CertificateReader
{
public:
    CertReadOutcome read(LibreSCRS::SmartCard::CardSession&, const CandidateList&, LibreSCRS::CancelToken) override
    {
        ADD_FAILURE() << "certReader must not run when the cert cache is hot";
        return CertReadOutcome{};
    }
};

// A trust verifier that fails the test if invoked -- the cache-hit path must
// never re-derive a verdict for an already-cached (already-verdicted) cert.
class UnusedTrustVerifier final : public TrustVerifier
{
public:
    TrustVerdict verify(std::span<const std::uint8_t>, std::span<const std::vector<std::uint8_t>>) override
    {
        ADD_FAILURE() << "trustVerifier must not run when the cert cache is hot";
        return TrustVerdict{};
    }
};

// Deterministic fixed-verdict fake for the cold-read path, which is not this
// test's concern (CertReadFlowTest owns the verdict-mapping matrix).
class FixedTrustVerifier final : public TrustVerifier
{
public:
    TrustVerdict verify(std::span<const std::uint8_t>, std::span<const std::vector<std::uint8_t>>) override
    {
        return TrustVerdict{CertTrustStatus::Unknown, {}};
    }
};

class UnusedPrompter final : public PrompterClientBase
{
public:
    PromptResult requestPin(const PromptOptions&) override
    {
        return {};
    }
    PromptResult requestCan(const PromptOptions&) override
    {
        return {};
    }
    PromptResult requestMrz(const PromptOptions&) override
    {
        return {};
    }
};

// A working holder that opens a detached session and resolves no candidates, so a
// COLD read reaches the fake reader and succeeds (mirrors CertReadFlowTest).
inline std::unique_ptr<CardSessionHolder> makeWorkingHolder()
{
    auto factory = [](const std::string& r)
        -> std::expected<std::shared_ptr<LibreSCRS::SmartCard::CardSession>, LibreSCRS::SmartCard::OpenError> {
        return LibreSCRS::SmartCard::detail::makeDetachedCardSession(r);
    };
    auto resolver = [](std::span<const std::uint8_t>, LibreSCRS::SmartCard::CardSession&) { return CandidateList{}; };
    return std::make_unique<CardSessionHolder>("FakeReader", std::move(factory), std::move(resolver),
                                               std::make_shared<LibreSCRS::SmartCard::CardMap>());
}

// A reader that returns a fixed successful outcome — drives the populate path.
class OkCertReader final : public CertificateReader
{
public:
    explicit OkCertReader(std::vector<CertSnapshot> certs) : m_certs(std::move(certs)) {}
    CertReadOutcome read(LibreSCRS::SmartCard::CardSession&, const CandidateList&, LibreSCRS::CancelToken) override
    {
        return CertReadOutcome{CertReadOutcome::Status::Ok, m_certs, {}};
    }

private:
    std::vector<CertSnapshot> m_certs;
};

} // namespace

TEST(ReadCertificatesOperation, CacheHitSkipsFlowAndEmitsCertificates)
{
    CardReadCache readCache;
    readCache.putCertificates("card-A", certsFixture());
    auto holder = makeUnusedHolder();
    UnusedCertReader certReader;
    UnusedTrustVerifier trustVerifier;
    UnusedPrompter prompter;
    PromptSerializer serializer;
    CredentialCache credCache;

    auto adaptor = std::make_unique<FakeOperationChannel>();
    auto* raw = adaptor.get();

    auto state = std::make_shared<OperationState>();
    ReadCertificatesOperation op(std::move(adaptor),
                                 ReadCertificatesOperation::Deps{
                                     .holder = holder.get(),
                                     .certReader = certReader,
                                     .trustVerifier = trustVerifier,
                                     .prompter = prompter,
                                     .serializer = serializer,
                                     .credentials = credCache,
                                     .readCache = readCache,
                                     .cardKey = "card-A",
                                     .readerName = "FakeReader",
                                     .requester = "test",
                                     .artifact = "certificates",
                                 },
                                 state);
    op.runOnWorker();

    ASSERT_EQ(raw->finishes.size(), 1u);
    EXPECT_EQ(raw->finishes[0].status, static_cast<std::uint32_t>(OperationStatus::Ok));
    ASSERT_TRUE(raw->captured.has_value());
    ASSERT_EQ(raw->captured->size(), 1u);
    EXPECT_EQ(raw->captured->front().certId, "abc123");
}

// A cold read (empty cache) runs the flow and POPULATES the cache — this op owns
// its own cache-write, so a dropped putCertificates would silently re-walk the
// card forever with no other test failing.
TEST(ReadCertificatesOperation, ColdReadPopulatesTheCache)
{
    CardReadCache readCache; // starts cold
    auto holder = makeWorkingHolder();
    OkCertReader certReader(certsFixture());
    FixedTrustVerifier trustVerifier;
    UnusedPrompter prompter;
    PromptSerializer serializer;
    CredentialCache credCache;

    auto adaptor = std::make_unique<FakeOperationChannel>();
    auto* raw = adaptor.get();

    auto state = std::make_shared<OperationState>();
    ReadCertificatesOperation op(std::move(adaptor),
                                 ReadCertificatesOperation::Deps{
                                     .holder = holder.get(),
                                     .certReader = certReader,
                                     .trustVerifier = trustVerifier,
                                     .prompter = prompter,
                                     .serializer = serializer,
                                     .credentials = credCache,
                                     .readCache = readCache,
                                     .cardKey = "card-A",
                                     .readerName = "FakeReader",
                                     .requester = "test",
                                     .artifact = "certificates",
                                 },
                                 state);

    ASSERT_FALSE(readCache.getCertificates("card-A").has_value()) << "cache starts cold";
    op.runOnWorker();

    ASSERT_EQ(raw->finishes.size(), 1u);
    EXPECT_EQ(raw->finishes[0].status, static_cast<std::uint32_t>(OperationStatus::Ok));
    auto cached = readCache.getCertificates("card-A");
    ASSERT_TRUE(cached.has_value()) << "a successful cold read must populate the cache";
    ASSERT_EQ(cached->size(), 1u);
    EXPECT_EQ(cached->front().certId, "abc123");
}
