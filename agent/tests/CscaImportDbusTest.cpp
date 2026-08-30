// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Config1.ImportCscaMasterList end-to-end over a private session bus.
//
// What this file is really about is ORDER: authorise, then rate-limit, then
// read the descriptor. A refused caller must not be able to make the agent read
// anything at all — the same discipline Card1.Sign follows, for the same
// reason, and the reason it is worth a test of its own is that an
// implementation with the checks in the WRONG order returns the very same error
// name. Only the side effect tells them apart, so the two ordering tests below
// assert the side effect:
//
//   * RefusedCallerNeverAdvancesTheDescriptor watches the shared file offset.
//     A descriptor sent over D-Bus arrives as a second reference to ONE open
//     file description, so the offset the agent would advance by reading is the
//     offset this test can still see. Zero after a refusal means not one byte
//     was consumed.
//   * RefusedCallerIsTurnedAwayBeforeTheDescriptorIsEvenInspected hands over a
//     PIPE. Reading rejects a pipe with a different error than the authorizer
//     raises, so the error NAME alone says which check ran first.

#include "SyntheticMasterList.h"
#include "trust/CscaAnchorImport.h"

#include <LibreSCRS/Agent/backend/Authorizer.h>
#include <LibreSCRS/Agent/config/ConfigStore.h>
#include <LibreSCRS/Agent/operations/RateLimiter.h>
#include "dbus/ManagerObject.h"

#include <sdbus-c++/sdbus-c++.h>
#include <gtest/gtest.h>

#include <fcntl.h>
#include <unistd.h>

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <map>
#include <string>
#include <vector>

namespace fs = std::filesystem;
// Not `using namespace ...::Test`: inside a TEST() body an unqualified `Test::`
// resolves to gtest's own base class, which is a confusing way to fail.
namespace fixture = LibreSCRS::Agent::Test;
using namespace LibreSCRS::Agent;

namespace {

constexpr const char* kRootPath = "/org/librescrs/Agent";
constexpr const char* kCfgIface = "org.librescrs.Agent.Config1";
constexpr const char* kProps = "org.freedesktop.DBus.Properties";
constexpr const char* kMethod = "ImportCscaMasterList";

class DenyAuthorizer final : public Authorizer
{
public:
    bool authorize(std::string_view, const CallerToken&) override
    {
        return false;
    }
};

class AllowAuthorizer final : public Authorizer
{
public:
    bool authorize(std::string_view, const CallerToken&) override
    {
        return true;
    }
};

// A regular file holding @p bytes, with its own descriptor left at offset 0.
class TempFile
{
public:
    TempFile(const fs::path& dir, const char* name, const std::vector<std::uint8_t>& bytes) : m_path(dir / name)
    {
        fs::create_directories(dir);
        std::ofstream out(m_path, std::ios::binary | std::ios::trunc);
        out.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
        out.close();
        m_fd = ::open(m_path.c_str(), O_RDONLY | O_CLOEXEC);
    }
    ~TempFile()
    {
        if (m_fd >= 0) {
            ::close(m_fd);
        }
        std::error_code ec;
        fs::remove(m_path, ec);
    }
    TempFile(const TempFile&) = delete;
    TempFile& operator=(const TempFile&) = delete;

    [[nodiscard]] int fd() const
    {
        return m_fd;
    }
    [[nodiscard]] const fs::path& path() const
    {
        return m_path;
    }
    // Where the SHARED open file description currently stands.
    [[nodiscard]] off_t offset() const
    {
        return ::lseek(m_fd, 0, SEEK_CUR);
    }

private:
    fs::path m_path;
    int m_fd{-1};
};

// One private bus, one agent object, one client proxy.
struct Harness
{
    explicit Harness(const char* tag, Authorizer& authorizer)
        : dir(fs::temp_directory_path() / (std::string{"ll-csca-dbus-"} + tag)),
          service(std::string{"org.librescrs.Agent.Test.CscaImport."} + tag)
    {
        fs::remove_all(dir);
        serverConn = sdbus::createSessionBusConnection();
        serverConn->requestName(sdbus::ServiceName{service});
        config = std::make_unique<Config::ConfigStore>(dir / "agent.conf", dir / "cache");
        manager = std::make_unique<ManagerObject>(*serverConn, sdbus::ObjectPath{kRootPath}, "t", *config, authorizer,
                                                  limiter, nullptr);
        serverConn->enterEventLoopAsync();

        clientConn = sdbus::createSessionBusConnection();
        clientConn->enterEventLoopAsync();
        proxy = sdbus::createProxy(*clientConn, sdbus::ServiceName{service}, sdbus::ObjectPath{kRootPath});
    }
    ~Harness()
    {
        proxy.reset();
        manager.reset();
        fs::remove_all(dir);
    }
    Harness(const Harness&) = delete;
    Harness& operator=(const Harness&) = delete;

    // Drive the import and hand back the rejection name (empty == accepted).
    std::string importFd(int fd, std::map<std::string, sdbus::Variant>* summary = nullptr)
    {
        try {
            std::map<std::string, sdbus::Variant> out;
            proxy->callMethod(kMethod)
                .onInterface(sdbus::InterfaceName{kCfgIface})
                .withArguments(sdbus::UnixFd{fd})
                .storeResultsTo(out);
            if (summary != nullptr) {
                *summary = std::move(out);
            }
            return {};
        } catch (const sdbus::Error& e) {
            return e.getName();
        }
    }

    std::map<std::string, sdbus::Variant> anchorState()
    {
        sdbus::Variant v;
        proxy->callMethod("Get")
            .onInterface(sdbus::InterfaceName{kProps})
            .withArguments(std::string{kCfgIface}, std::string{"CscaAnchorState"})
            .storeResultsTo(v);
        return v.get<std::map<std::string, sdbus::Variant>>();
    }

    fs::path dir;
    std::string service;
    std::unique_ptr<sdbus::IConnection> serverConn;
    std::unique_ptr<sdbus::IConnection> clientConn;
    std::unique_ptr<Config::ConfigStore> config;
    Operations::RateLimiter limiter;
    std::unique_ptr<ManagerObject> manager;
    std::unique_ptr<sdbus::IProxy> proxy;
};

constexpr const char* kErrReplayed = "org.librescrs.Agent.Error.MasterListReplayed";

// Two instants a publisher might have signed at, an hour apart.
constexpr std::int64_t kSignedEarlier = 1'700'000'000;
constexpr std::int64_t kSignedLater = 1'700'003'600;

std::vector<std::uint8_t> aValidMasterList()
{
    return fixture::signMasterList({fixture::makeCsca("CSCA A", "AA"), fixture::makeCsca("CSCA B", "BB")},
                                   fixture::makeIndependentSigner())
        .der;
}

} // namespace

// --- order: authorise, rate-limit, THEN read -------------------------------

TEST(CscaImportDbus, RefusedCallerNeverAdvancesTheDescriptor)
{
    DenyAuthorizer deny;
    Harness h("deny-offset", deny);

    TempFile file(h.dir / "in", "masterlist.ml", aValidMasterList());
    ASSERT_GE(file.fd(), 0);
    ASSERT_EQ(file.offset(), 0) << "the descriptor must start where a read would be visible";

    EXPECT_EQ(h.importFd(file.fd()), "org.librescrs.Agent.Error.NotAuthorized");

    // The proof. The descriptor the agent received refers to the SAME open file
    // description as this one, so any read the agent performed would show up
    // here as an advanced offset. An implementation that ingested the list and
    // only then consulted the authorizer returns the identical error name and
    // fails on exactly this line.
    EXPECT_EQ(file.offset(), 0) << "a refused caller made the agent read the descriptor";
}

TEST(CscaImportDbus, RefusedCallerIsTurnedAwayBeforeTheDescriptorIsEvenInspected)
{
    DenyAuthorizer deny;
    Harness h("deny-pipe", deny);

    int pipeFds[2] = {-1, -1};
    ASSERT_EQ(::pipe(pipeFds), 0);

    // A pipe is refused by the read path with its own error name. Getting
    // NotAuthorized back therefore proves the authorizer ran first: had the
    // descriptor been inspected before the caller was judged, this would come
    // back as the invalid-request rejection instead.
    EXPECT_EQ(h.importFd(pipeFds[0]), "org.librescrs.Agent.Error.NotAuthorized");

    ::close(pipeFds[0]);
    ::close(pipeFds[1]);
}

TEST(CscaImportDbus, RateLimitPrecedesTheRead)
{
    AllowAuthorizer allow;
    Harness h("ratelimit", allow);

    // Spend the caller's budget on well-formed calls. Each is refused on its
    // CONTENT, which means each one got past the rate limiter and counted.
    TempFile garbage(h.dir / "in", "garbage.ml", {0x01, 0x02, 0x03});
    ASSERT_GE(garbage.fd(), 0);
    for (std::size_t i = 0; i < Operations::RateLimiter::kMaxPerWindow; ++i) {
        ASSERT_EQ(::lseek(garbage.fd(), 0, SEEK_SET), 0);
        EXPECT_EQ(h.importFd(garbage.fd()), "org.librescrs.Agent.Error.NotAMasterList") << "call " << i;
    }

    // Now over budget, and handed a descriptor the read path would reject with
    // a different name. RateLimited coming back means the limiter ran first.
    int pipeFds[2] = {-1, -1};
    ASSERT_EQ(::pipe(pipeFds), 0);
    EXPECT_EQ(h.importFd(pipeFds[0]), "org.librescrs.Agent.Error.RateLimited");
    ::close(pipeFds[0]);
    ::close(pipeFds[1]);
}

// --- descriptor discipline -------------------------------------------------

TEST(CscaImportDbus, NonRegularDescriptorIsRefused)
{
    AllowAuthorizer allow;
    Harness h("pipe", allow);

    int pipeFds[2] = {-1, -1};
    ASSERT_EQ(::pipe(pipeFds), 0);
    // Closed, so a broken implementation that read anyway sees EOF instead of
    // blocking the bus thread forever — which is the very stall the fstat
    // rejection exists to prevent.
    ::close(pipeFds[1]);

    EXPECT_EQ(h.importFd(pipeFds[0]), "org.librescrs.Agent.Error.InvalidRequest");
    ::close(pipeFds[0]);
}

TEST(CscaImportDbus, OversizeInputIsRefused)
{
    AllowAuthorizer allow;
    Harness h("oversize", allow);

    // Sparse: resize_file allocates no blocks, so this costs neither memory nor
    // disk, and it still reads as one byte past the cap.
    const fs::path path = h.dir / "huge.ml";
    fs::create_directories(h.dir);
    {
        std::ofstream create(path, std::ios::binary);
    }
    fs::resize_file(path, Trust::kMaxMasterListBytes + 1);
    const int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
    ASSERT_GE(fd, 0);

    EXPECT_EQ(h.importFd(fd), "org.librescrs.Agent.Error.InputTooLarge");
    ::close(fd);
}

// --- the accepted path -----------------------------------------------------

TEST(CscaImportDbus, AValidListIsImportedAndSummarised)
{
    AllowAuthorizer allow;
    Harness h("accept", allow);

    // Three anchors from two countries, so the two counts cannot be confused.
    const auto list =
        fixture::signMasterList({fixture::makeCsca("CSCA One Old", "AA"), fixture::makeCsca("CSCA One New", "AA"),
                                 fixture::makeCsca("CSCA Two", "BB")},
                                fixture::makeIndependentSigner());
    TempFile file(h.dir / "in", "masterlist.ml", list.der);
    ASSERT_GE(file.fd(), 0);

    std::map<std::string, sdbus::Variant> summary;
    ASSERT_EQ(h.importFd(file.fd(), &summary), "");

    EXPECT_EQ(summary.at("anchors").get<std::uint32_t>(), 3u);
    EXPECT_EQ(summary.at("issuers").get<std::uint32_t>(), 2u);
    EXPECT_EQ(summary.at("signer").get<std::string>(), Trust::toHex(list.signerSpkiSha256));
    EXPECT_EQ(summary.at("origin").get<std::string>(), "import");
    EXPECT_GT(summary.at("acceptedAt").get<std::int64_t>(), 0);
    // Trusted on first import: nothing was compared, and the wire says so
    // rather than letting a client render "verified".
    EXPECT_FALSE(summary.at("signerPinned").get<bool>());

    // The readable state a client shows carries the same answer.
    const auto state = h.anchorState();
    EXPECT_EQ(state.at("anchors").get<std::uint32_t>(), 3u);
    EXPECT_EQ(state.at("issuers").get<std::uint32_t>(), 2u);
    EXPECT_EQ(state.at("signer").get<std::string>(), Trust::toHex(list.signerSpkiSha256));
}

TEST(CscaImportDbus, AnchorStateIsEmptyUntilSomethingIsImported)
{
    AllowAuthorizer allow;
    Harness h("empty-state", allow);
    EXPECT_TRUE(h.anchorState().empty()) << "an agent that has imported nothing must not describe a trust store";
}

TEST(CscaImportDbus, AChangedSignerIsRefusedOverTheWire)
{
    AllowAuthorizer allow;
    Harness h("signer-changed", allow);

    const auto first = fixture::signMasterList({fixture::makeCsca("CSCA A", "AA")}, fixture::makeIndependentSigner());
    TempFile firstFile(h.dir / "in", "first.ml", first.der);
    ASSERT_EQ(h.importFd(firstFile.fd()), "");

    const auto stranger =
        fixture::signMasterList({fixture::makeCsca("CSCA X", "XX")}, fixture::makeIndependentSigner());
    TempFile strangerFile(h.dir / "in", "stranger.ml", stranger.der);
    EXPECT_EQ(h.importFd(strangerFile.fd()), "org.librescrs.Agent.Error.MasterListSignerChanged");

    // The refusal changed nothing a client can read.
    const auto state = h.anchorState();
    EXPECT_EQ(state.at("anchors").get<std::uint32_t>(), 1u);
    EXPECT_EQ(state.at("signer").get<std::string>(), Trust::toHex(first.signerSpkiSha256));
}

TEST(CscaImportDbus, ARotatedPublisherIsFollowedWhenItChainsToTheTrustedAnchors)
{
    AllowAuthorizer allow;
    Harness h("rotation", allow);

    const auto anchorA = fixture::makeCsca("CSCA A", "AA");
    const auto first = fixture::signMasterList({anchorA}, fixture::makeIndependentSigner());
    TempFile firstFile(h.dir / "in", "first.ml", first.der);
    ASSERT_EQ(h.importFd(firstFile.fd()), "");

    const auto rotated = fixture::makeSignerIssuedBy(anchorA);
    const auto second = fixture::signMasterList({anchorA, fixture::makeCsca("CSCA C", "CC")}, rotated);
    TempFile secondFile(h.dir / "in", "second.ml", second.der);

    std::map<std::string, sdbus::Variant> summary;
    ASSERT_EQ(h.importFd(secondFile.fd(), &summary), "");

    EXPECT_EQ(summary.at("signer").get<std::string>(), Trust::toHex(second.signerSpkiSha256));
    EXPECT_TRUE(summary.at("signerPinned").get<bool>()) << "the rotation was checked, not merely observed";
}

// --- replay: the wire says whether the protection is on ---------------------

TEST(CscaImportDbus, ADatedListTurnsReplayRefusalOnAndSaysSo)
{
    AllowAuthorizer allow;
    Harness h("replay-active", allow);

    const auto list = fixture::signMasterListDated({fixture::makeCsca("CSCA A", "AA")},
                                                   fixture::makeIndependentSigner(), kSignedEarlier);
    TempFile file(h.dir / "in", "dated.ml", list.der);
    std::map<std::string, sdbus::Variant> summary;
    ASSERT_EQ(h.importFd(file.fd(), &summary), "");

    ASSERT_TRUE(summary.contains("replayRefusalActive")) << "a client cannot see whether the protection is on";
    EXPECT_TRUE(summary.at("replayRefusalActive").get<bool>());
    ASSERT_TRUE(summary.contains("signedAt"));
    EXPECT_EQ(summary.at("signedAt").get<std::int64_t>(), kSignedEarlier);
    // When it was signed and when it was accepted are different facts and must
    // not be served from the same value.
    EXPECT_NE(summary.at("acceptedAt").get<std::int64_t>(), kSignedEarlier);

    const auto state = h.anchorState();
    ASSERT_TRUE(state.contains("replayRefusalActive"));
    EXPECT_TRUE(state.at("replayRefusalActive").get<bool>());
    EXPECT_EQ(state.at("signedAt").get<std::int64_t>(), kSignedEarlier);
}

TEST(CscaImportDbus, AnUndatedListLeavesReplayRefusalInactiveAndSaysSo)
{
    AllowAuthorizer allow;
    Harness h("replay-inactive", allow);

    // An undated list is accepted — nothing is refused for a property the
    // ecosystem may not provide — but the installation is told that a rollback
    // is something this agent cannot detect. "Cannot be checked" is not "safe".
    TempFile file(h.dir / "in", "undated.ml", aValidMasterList());
    std::map<std::string, sdbus::Variant> summary;
    ASSERT_EQ(h.importFd(file.fd(), &summary), "");

    ASSERT_TRUE(summary.contains("replayRefusalActive"));
    EXPECT_FALSE(summary.at("replayRefusalActive").get<bool>());
    EXPECT_FALSE(summary.contains("signedAt")) << "a date was reported for a list that carries none";

    const auto state = h.anchorState();
    ASSERT_TRUE(state.contains("replayRefusalActive"));
    EXPECT_FALSE(state.at("replayRefusalActive").get<bool>());
    EXPECT_FALSE(state.contains("signedAt"));
}

TEST(CscaImportDbus, AnOlderListIsRefusedOverTheWire)
{
    AllowAuthorizer allow;
    Harness h("replay-older", allow);

    const auto signer = fixture::makeIndependentSigner();
    const auto first = fixture::signMasterListDated({fixture::makeCsca("CSCA A", "AA")}, signer, kSignedLater);
    TempFile firstFile(h.dir / "in", "first.ml", first.der);
    ASSERT_EQ(h.importFd(firstFile.fd()), "");

    const auto older =
        fixture::signMasterListDated({fixture::makeCsca("CSCA Withdrawn", "ZZ")}, signer, kSignedEarlier);
    TempFile olderFile(h.dir / "in", "older.ml", older.der);
    EXPECT_EQ(h.importFd(olderFile.fd()), kErrReplayed);

    // The refusal changed nothing a client can read.
    const auto state = h.anchorState();
    EXPECT_EQ(state.at("signer").get<std::string>(), Trust::toHex(first.signerSpkiSha256));
    EXPECT_EQ(state.at("signedAt").get<std::int64_t>(), kSignedLater);
}

TEST(CscaImportDbus, AnUndatedListCannotStripADatedOneOverTheWire)
{
    AllowAuthorizer allow;
    Harness h("replay-strip", allow);

    const auto signer = fixture::makeIndependentSigner();
    const auto first = fixture::signMasterListDated({fixture::makeCsca("CSCA A", "AA")}, signer, kSignedLater);
    TempFile firstFile(h.dir / "in", "first.ml", first.der);
    ASSERT_EQ(h.importFd(firstFile.fd()), "");

    // The same publisher, no date. Accepting it would take the protection away.
    const auto undated = fixture::signMasterList({fixture::makeCsca("CSCA Withdrawn", "ZZ")}, signer);
    ASSERT_FALSE(undated.signingTime.has_value()) << "the fixture dated the list this case is about";
    TempFile undatedFile(h.dir / "in", "undated.ml", undated.der);
    EXPECT_EQ(h.importFd(undatedFile.fd()), kErrReplayed);

    const auto state = h.anchorState();
    EXPECT_TRUE(state.at("replayRefusalActive").get<bool>()) << "the protection was switched off from the wire";
    EXPECT_EQ(state.at("signedAt").get<std::int64_t>(), kSignedLater);
}
