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
#include <LibreSCRS/Agent/trust/CscaAnchorImport.h>

#include <LibreSCRS/Agent/backend/Authorizer.h>
#include <LibreSCRS/Agent/config/ConfigStore.h>
#include <LibreSCRS/Agent/operations/RateLimiter.h>
#include "dbus/ManagerObject.h"

#include <sdbus-c++/sdbus-c++.h>
#include <gtest/gtest.h>

#include <fcntl.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <map>
#include <string>
#include <thread>
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
          service(std::string{"org.librescrs.Agent.Test.CscaImport."} + tag), auth(&authorizer)
    {
        fs::remove_all(dir);
        serverConn = sdbus::createSessionBusConnection();
        serverConn->requestName(sdbus::ServiceName{service});
        build();
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

    // The agent stopping and starting again over the SAME directory. Both
    // halves of what a restart re-reads are rebuilt — the configuration store
    // from its file, the root object over the store — because a report that
    // has outlived its anchors can only be caught at the moment the two are
    // brought back together.
    void restart()
    {
        manager.reset();
        config.reset();
        build();
    }

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

    // Drive ForgetCscaAnchors. Hands back the rejection name (empty == accepted)
    // and, when accepted, what the agent said it destroyed.
    std::string forgetAnchors(std::uint64_t* anchorsForgotten = nullptr, bool* hadPinnedSigner = nullptr)
    {
        try {
            std::uint64_t forgotten = 0;
            bool pinned = false;
            proxy->callMethod("ForgetCscaAnchors")
                .onInterface(sdbus::InterfaceName{kCfgIface})
                .storeResultsTo(forgotten, pinned);
            if (anchorsForgotten != nullptr) {
                *anchorsForgotten = forgotten;
            }
            if (hadPinnedSigner != nullptr) {
                *hadPinnedSigner = pinned;
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

    // Drive SetValue/Reset and hand back the rejection name (empty == accepted).
    std::string setValue(const std::string& key, const sdbus::Variant& value)
    {
        try {
            proxy->callMethod("SetValue").onInterface(sdbus::InterfaceName{kCfgIface}).withArguments(key, value);
            return {};
        } catch (const sdbus::Error& e) {
            return e.getName();
        }
    }

    std::string reset(const std::string& key)
    {
        try {
            proxy->callMethod("Reset").onInterface(sdbus::InterfaceName{kCfgIface}).withArguments(key);
            return {};
        } catch (const sdbus::Error& e) {
            return e.getName();
        }
    }

    void build()
    {
        config = std::make_unique<Config::ConfigStore>(dir / "agent.conf", dir / "cache");
        manager = std::make_unique<ManagerObject>(*serverConn, sdbus::ObjectPath{kRootPath}, "t", *config, *auth,
                                                  limiter, nullptr);
    }

    fs::path dir;
    std::string service;
    Authorizer* auth{nullptr};
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

// --- a collection, which is what the directory actually serves --------------
//
// One file, several master lists, each published and signed by a different
// country. What the wire has to say about it is the whole question this section
// answers, because the vocabulary it inherited was written for one publisher
// and the file carries dozens.
//
// The rule they enforce together: NAMING one publisher out of many is the
// thing to avoid, and an ABSENT key is how this vocabulary already spells
// "that cannot be told" -- `signedAt` has meant exactly that for an undated
// list since the first version of this interface. So the three single-
// publisher keys go absent rather than picking a winner. A client built
// before the collection existed reads a missing key and shows nothing; the
// same client reading one of twenty-eight fingerprints under a label its
// dialog renders as "the publisher" would show something FALSE, and the two
// are not failures of the same size.

TEST(CscaImportDbus, ACollectionIsImportedAsTheUnionOfItsLists)
{
    AllowAuthorizer allow;
    Harness h("collection", allow);

    // Two publishers, three anchors, two countries -- and one anchor carried
    // by BOTH lists, because the lists in a real collection overlap and the
    // union must collapse the repeat rather than count it twice.
    const auto shared = fixture::makeCsca("CSCA Shared", "AA");
    const auto first =
        fixture::signMasterList({shared, fixture::makeCsca("CSCA One", "AA")}, fixture::makeIndependentSigner());
    const auto second =
        fixture::signMasterList({shared, fixture::makeCsca("CSCA Two", "BB")}, fixture::makeIndependentSigner());
    // With the stray base64 attribute the portal's own export carries: a scan
    // that counted every base64 value would offer one list too many here.
    const auto ldif = fixture::makeLdifCollection({first.der, second.der}, /*strayBase64Attribute=*/true);

    TempFile file(h.dir / "in", "collection.ldif", ldif);
    ASSERT_GE(file.fd(), 0);

    std::map<std::string, sdbus::Variant> summary;
    ASSERT_EQ(h.importFd(file.fd(), &summary), "");

    EXPECT_EQ(summary.at("anchors").get<std::uint32_t>(), 3u) << "the shared anchor was stored twice, or a list was "
                                                                 "dropped";
    EXPECT_EQ(summary.at("issuers").get<std::uint32_t>(), 2u);
    EXPECT_EQ(summary.at("origin").get<std::string>(), "import");

    const auto state = h.anchorState();
    EXPECT_EQ(state.at("anchors").get<std::uint32_t>(), 3u);
    EXPECT_EQ(state.at("issuers").get<std::uint32_t>(), 2u);
}

TEST(CscaImportDbus, ACollectionNamesNoPublisherAtAll)
{
    AllowAuthorizer allow;
    Harness h("collection-unnamed", allow);

    // BOTH lists dated, and dated DIFFERENTLY. That is what makes the absent
    // `signedAt` below a decision rather than an artefact: there are two
    // perfectly good dates here and no single one of them is the collection's.
    const auto first = fixture::signMasterListDated({fixture::makeCsca("CSCA One", "AA")},
                                                    fixture::makeIndependentSigner(), kSignedEarlier);
    const auto second = fixture::signMasterListDated({fixture::makeCsca("CSCA Two", "BB")},
                                                     fixture::makeIndependentSigner(), kSignedLater);
    const auto ldif = fixture::makeLdifCollection({first.der, second.der}, /*strayBase64Attribute=*/false);

    TempFile file(h.dir / "in", "collection.ldif", ldif);
    std::map<std::string, sdbus::Variant> summary;
    ASSERT_EQ(h.importFd(file.fd(), &summary), "");

    EXPECT_FALSE(summary.contains("signer")) << "one publisher out of several was named as THE publisher";
    EXPECT_FALSE(summary.contains("signedAt")) << "one publisher's signing time was served as the collection's";

    // The property a settings dialog reads says the same, and goes on saying
    // it after a restart -- the record is the only thing a client that has
    // just connected can be answered from.
    const auto state = h.anchorState();
    EXPECT_FALSE(state.contains("signer"));
    EXPECT_FALSE(state.contains("signedAt"));
    EXPECT_EQ(state.at("anchors").get<std::uint32_t>(), 2u) << "what IS known was withheld along with what is not";

    h.restart();
    const auto afterRestart = h.anchorState();
    EXPECT_FALSE(afterRestart.contains("signer")) << "the restart re-invented a publisher the import declined to name";
    EXPECT_FALSE(afterRestart.contains("signedAt"));
    EXPECT_EQ(afterRestart.at("anchors").get<std::uint32_t>(), 2u);
}

TEST(CscaImportDbus, ACollectionSaysWhetherEveryPublisherWasEstablished)
{
    AllowAuthorizer allow;
    Harness h("collection-established", allow);

    const auto signerA = fixture::makeIndependentSigner();
    const auto signerB = fixture::makeIndependentSigner();
    const auto firstA = fixture::signMasterListDated({fixture::makeCsca("CSCA A", "AA")}, signerA, kSignedEarlier);
    const auto firstB = fixture::signMasterListDated({fixture::makeCsca("CSCA B", "BB")}, signerB, kSignedEarlier);

    TempFile firstFile(h.dir / "in", "first.ldif",
                       fixture::makeLdifCollection({firstA.der, firstB.der}, /*strayBase64Attribute=*/false));
    std::map<std::string, sdbus::Variant> firstSummary;
    ASSERT_EQ(h.importFd(firstFile.fd(), &firstSummary), "");
    EXPECT_FALSE(firstSummary.at("signerPinned").get<bool>())
        << "a trust-on-first-import claimed every publisher's identity had been established";

    // The same two publishers again, each list newer than its own. Both are
    // now on record, so both are MATCHED rather than merely observed.
    const auto againA = fixture::signMasterListDated({fixture::makeCsca("CSCA A", "AA")}, signerA, kSignedLater);
    const auto againB = fixture::signMasterListDated({fixture::makeCsca("CSCA B", "BB")}, signerB, kSignedLater);
    TempFile againFile(h.dir / "in", "again.ldif",
                       fixture::makeLdifCollection({againA.der, againB.der}, /*strayBase64Attribute=*/false));
    std::map<std::string, sdbus::Variant> againSummary;
    ASSERT_EQ(h.importFd(againFile.fd(), &againSummary), "");
    EXPECT_TRUE(againSummary.at("signerPinned").get<bool>())
        << "every publisher was established and the wire would not say so";
    // Decided SEPARATELY from the naming, and this is the pair that shows it:
    // the collection can be fully established and still have no one publisher
    // to name. A surface may say "checked" here; it may not say "checked, and
    // it was this one".
    EXPECT_FALSE(againSummary.contains("signer")) << "an established collection named a publisher after all";
}

TEST(CscaImportDbus, APublisherStillFollowedAloneIsNamedAgain)
{
    AllowAuthorizer allow;
    Harness h("collection-narrowed", allow);

    // A single published list first, so exactly one publisher is on record --
    // and the wire names it, because there IS one publisher to name.
    const auto signerA = fixture::makeIndependentSigner();
    const auto alone = fixture::signMasterListDated({fixture::makeCsca("CSCA A", "AA")}, signerA, kSignedEarlier);
    TempFile aloneFile(h.dir / "in", "alone.ml", alone.der);
    std::map<std::string, sdbus::Variant> aloneSummary;
    ASSERT_EQ(h.importFd(aloneFile.fd(), &aloneSummary), "");
    EXPECT_EQ(aloneSummary.at("signer").get<std::string>(), Trust::toHex(alone.signerSpkiSha256))
        << "a single publisher stopped being named, which is a regression and not a generalisation";

    // Now a collection carrying that publisher and a stranger: a signer this
    // agent has no record of and whose certificate chains to nothing it holds.
    // The stranger's list is refused and the other is taken, which is the
    // partial outcome a collection makes ordinary.
    const auto againA = fixture::signMasterListDated({fixture::makeCsca("CSCA A", "AA")}, signerA, kSignedLater);
    const auto stranger = fixture::signMasterListDated({fixture::makeCsca("CSCA C", "CC")},
                                                       fixture::makeIndependentSigner(), kSignedLater);
    TempFile file(h.dir / "in", "mixed.ldif",
                  fixture::makeLdifCollection({againA.der, stranger.der}, /*strayBase64Attribute=*/false));
    std::map<std::string, sdbus::Variant> summary;
    ASSERT_EQ(h.importFd(file.fd(), &summary), "");

    // What the agent follows AFTERWARDS is what the wire describes, and it is
    // one publisher again -- the stranger vouched for nothing, so its anchors
    // are not in the store and its fingerprint is not in this report. The rule
    // is about how many publishers are followed, never about how the file that
    // narrowed them down happened to arrive.
    EXPECT_EQ(summary.at("anchors").get<std::uint32_t>(), 1u) << "the refused list's anchors reached the store";
    EXPECT_EQ(summary.at("signer").get<std::string>(), Trust::toHex(againA.signerSpkiSha256));
    EXPECT_TRUE(summary.at("signerPinned").get<bool>()) << "the surviving publisher was matched against its record "
                                                           "and the wire would not say so";
    EXPECT_EQ(summary.at("signedAt").get<std::int64_t>(), kSignedLater);
}

TEST(CscaImportDbus, OneUndatedListInACollectionTurnsReplayRefusalOff)
{
    AllowAuthorizer allow;
    Harness h("collection-undated", allow);

    // One publisher dates its list and one does not, which is an ordinary
    // Tuesday across dozens of countries. The aggregate is the WEAKEST of its
    // parts: the undated publisher's anchors can be rolled back freely, and a
    // surface told the protection is active could not know that.
    const auto dated = fixture::signMasterListDated({fixture::makeCsca("CSCA Dated", "AA")},
                                                    fixture::makeIndependentSigner(), kSignedEarlier);
    const auto undated =
        fixture::signMasterList({fixture::makeCsca("CSCA Undated", "BB")}, fixture::makeIndependentSigner());
    TempFile file(h.dir / "in", "mixed-dates.ldif",
                  fixture::makeLdifCollection({dated.der, undated.der}, /*strayBase64Attribute=*/false));

    std::map<std::string, sdbus::Variant> summary;
    ASSERT_EQ(h.importFd(file.fd(), &summary), "");

    ASSERT_TRUE(summary.contains("replayRefusalActive")) << "the one key whose false is the interesting value went "
                                                            "missing";
    EXPECT_FALSE(summary.at("replayRefusalActive").get<bool>())
        << "a dated majority reported a protection the undated publisher does not have";

    const auto state = h.anchorState();
    ASSERT_TRUE(state.contains("replayRefusalActive"));
    EXPECT_FALSE(state.at("replayRefusalActive").get<bool>());
}

TEST(CscaImportDbus, AnchorStateIsEmptyUntilSomethingIsImported)
{
    AllowAuthorizer allow;
    Harness h("empty-state", allow);
    EXPECT_TRUE(h.anchorState().empty()) << "an agent that has imported nothing must not describe a trust store";
}

// --- what a client that has just STARTED reads ------------------------------
//
// The import reply answers the client that performed the import. A client that
// has only just connected has no reply to read, and until the agent REMEMBERED
// the accepted state its settings surface could say nothing at all about what
// is installed. These three cases are that memory: it is written, it is what
// the bus serves, and it cannot be written from the bus.

TEST(CscaImportDbus, AnAcceptedImportIsRememberedInTheConfiguration)
{
    AllowAuthorizer allow;
    Harness h("remembered", allow);

    const auto list =
        fixture::signMasterListDated({fixture::makeCsca("CSCA One", "AA"), fixture::makeCsca("CSCA Two", "BB")},
                                     fixture::makeIndependentSigner(), kSignedEarlier);
    TempFile file(h.dir / "in", "masterlist.ml", list.der);
    ASSERT_EQ(h.importFd(file.fd()), "");

    const auto recorded = h.config->cscaAnchorState();
    ASSERT_TRUE(recorded.has_value()) << "the accepted import left no record in the agent's configuration";
    EXPECT_EQ(recorded->anchors, 2u);
    EXPECT_EQ(recorded->issuers, 2u);
    EXPECT_EQ(recorded->signer, Trust::toHex(list.signerSpkiSha256));
    EXPECT_FALSE(recorded->signerPinned) << "a first import establishes nothing, and the record must not claim it did";
    EXPECT_TRUE(recorded->replayRefusalActive);
    ASSERT_TRUE(recorded->signedAt.has_value());
    EXPECT_EQ(*recorded->signedAt, kSignedEarlier);
    EXPECT_EQ(recorded->origin, "import");

    // On DISK, not merely in memory. A second store over the same file is the
    // restart this record exists for: it is the only thing a client that has
    // just started could be answered from.
    Config::ConfigStore restarted(h.dir / "agent.conf", h.dir / "cache");
    EXPECT_EQ(restarted.cscaAnchorState(), recorded) << "the record did not survive a restart";
}

TEST(CscaImportDbus, TheReadableStateIsServedFromTheRecordedConfiguration)
{
    AllowAuthorizer allow;
    Harness h("served-from-config", allow);

    // No import in this test at all: the report is placed where a restarted
    // agent would find it, and the bus is then asked. The property and the
    // configuration key carry the same name, so serving them from two
    // different places would let the agent describe itself two ways with
    // nothing to notice the difference.
    Config::CscaAnchorState remembered;
    remembered.anchors = 212;
    remembered.issuers = 47;
    remembered.replayRefusalActive = false;
    remembered.signer = "ab12";
    remembered.signerPinned = true;
    remembered.acceptedAt = 1'700'000'000;
    remembered.origin = "import";
    h.config->recordCscaAnchorState(remembered);

    const auto state = h.anchorState();
    ASSERT_FALSE(state.empty()) << "the bus does not serve the state the agent remembers";
    EXPECT_EQ(state.at("anchors").get<std::uint32_t>(), 212u);
    EXPECT_EQ(state.at("issuers").get<std::uint32_t>(), 47u);
    EXPECT_EQ(state.at("signer").get<std::string>(), "ab12");
    EXPECT_TRUE(state.at("signerPinned").get<bool>());
    EXPECT_EQ(state.at("acceptedAt").get<std::int64_t>(), 1'700'000'000);
    EXPECT_EQ(state.at("origin").get<std::string>(), "import");
    ASSERT_TRUE(state.contains("replayRefusalActive"));
    EXPECT_FALSE(state.at("replayRefusalActive").get<bool>());
    // Absence survives the trip through the agent's own memory: a remembered
    // report carrying no signing time must not come back as one signed at the
    // epoch.
    EXPECT_FALSE(state.contains("signedAt")) << "a date was served for a report that carries none";
}

TEST(CscaImportDbus, TheAnchorStateCannotBeWrittenOverTheBus)
{
    AllowAuthorizer allow;
    Harness h("read-only", allow);

    const auto list = fixture::signMasterList({fixture::makeCsca("CSCA A", "AA")}, fixture::makeIndependentSigner());
    TempFile file(h.dir / "in", "masterlist.ml", list.der);
    ASSERT_EQ(h.importFd(file.fd()), "");

    // The authorizer here says yes to everything, so a refusal can only come
    // from the key's own read-only classification. That is the point: a client
    // able to write this would be CLAIMING what passports are checked against
    // without installing a single anchor.
    std::map<std::string, sdbus::Variant> forged;
    forged["anchors"] = sdbus::Variant{std::uint32_t{9999}};
    forged["issuers"] = sdbus::Variant{std::uint32_t{195}};
    forged["replayRefusalActive"] = sdbus::Variant{true};
    EXPECT_EQ(h.setValue("CscaAnchorState", sdbus::Variant{forged}), "org.librescrs.Agent.Error.ReadOnlyConfig");
    // Reset repeats the guard, because clearing the report is a write too:
    // "this agent holds nothing" is as much a claim as any other.
    EXPECT_EQ(h.reset("CscaAnchorState"), "org.librescrs.Agent.Error.ReadOnlyConfig");

    const auto after = h.anchorState();
    EXPECT_EQ(after.at("anchors").get<std::uint32_t>(), 1u) << "a refused write changed what a client reads";
    EXPECT_EQ(after.at("signer").get<std::string>(), Trust::toHex(list.signerSpkiSha256));
}

TEST(CscaImportDbus, AnAcceptedImportAnnouncesTheChangeExactlyOnce)
{
    AllowAuthorizer allow;
    Harness h("changed-signal", allow);

    // AgentService wires this in production; replicate it, because the RECORD
    // the import writes is what announces the change now. There is no
    // hand-written emit on the import path any more, and a client that
    // refetches whenever it is told to must be told once for one import --
    // neither nought times nor twice.
    h.config->setOnChanged([&h](const std::string& key) {
        if (h.manager) {
            h.manager->emitConfigChanged(key);
        }
    });

    std::atomic<int> announced{0};
    std::string announcedKey;
    h.proxy->uponSignal("Changed").onInterface(sdbus::InterfaceName{kCfgIface}).call([&](const std::string& key) {
        announcedKey = key;
        announced.fetch_add(1, std::memory_order_acq_rel);
    });
    std::this_thread::sleep_for(std::chrono::milliseconds(100)); // let the match rule propagate

    TempFile file(h.dir / "in", "masterlist.ml", aValidMasterList());
    ASSERT_GE(file.fd(), 0);
    ASSERT_EQ(h.importFd(file.fd()), "");

    for (int i = 0; i < 100 && announced.load(std::memory_order_acquire) == 0; ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    ASSERT_EQ(announced.load(std::memory_order_acquire), 1) << "the accepted import announced nothing";
    EXPECT_EQ(announcedKey, "CscaAnchorState");

    // Settle before counting: a second emit beside the store's own would arrive
    // late rather than not at all, and would wake every listening client twice.
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    EXPECT_EQ(announced.load(std::memory_order_acquire), 1) << "one import announced more than one change";
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

// --- a report the anchor cache does not bear out ----------------------------
//
// The record follows the CONFIGURATION file. What it describes is a directory
// of anchor files plus the cache's own state file, either of which a person may
// edit or delete; the configuration survives that, so the record goes on
// describing an agent that is no longer there. Both halves err in the
// OVERSTATING direction, which for a trust surface is the dangerous one:
// missing anchors leave the COUNTS false, and a missing cache state leaves the
// SIGNER false — a pin claimed over an agent that now follows nobody.
//
// Only the display is at stake, and the tests are written knowing it: every
// verdict reads the cache itself and never this report, so no document can be
// accepted on the strength of one.
//
// Reconciliation happens once, at startup, and asks only cheap questions:
// whether an anchor file exists at all, and whether the cache establishes a
// signer. Nothing is re-verified, and nothing in the cache is touched — which
// is a property the last two cases here exist to hold on to.

TEST(CscaImportDbus, ARememberedReportSurvivesARestartThatFindsItsAnchors)
{
    AllowAuthorizer allow;
    Harness h("reconcile-intact", allow);

    const auto list = fixture::signMasterList({fixture::makeCsca("CSCA A", "AA"), fixture::makeCsca("CSCA B", "BB")},
                                              fixture::makeIndependentSigner());
    TempFile file(h.dir / "in", "masterlist.ml", list.der);
    ASSERT_EQ(h.importFd(file.fd()), "");

    h.restart();

    const auto state = h.anchorState();
    ASSERT_FALSE(state.empty()) << "a restart discarded a report whose anchors are still on disk";
    EXPECT_EQ(state.at("anchors").get<std::uint32_t>(), 2u);
    EXPECT_EQ(state.at("signer").get<std::string>(), Trust::toHex(list.signerSpkiSha256));
}

TEST(CscaImportDbus, AReportWhoseAnchorCacheWasWipedIsNotServedAsCurrent)
{
    AllowAuthorizer allow;
    Harness h("reconcile-wiped", allow);

    const auto list = fixture::signMasterList({fixture::makeCsca("CSCA A", "AA"), fixture::makeCsca("CSCA B", "BB")},
                                              fixture::makeIndependentSigner());
    TempFile file(h.dir / "in", "masterlist.ml", list.der);
    ASSERT_EQ(h.importFd(file.fd()), "");
    ASSERT_FALSE(h.anchorState().empty());

    // The whole cache directory, the way a person clearing out a cache would.
    // The configuration file is elsewhere and is untouched by it.
    std::error_code ec;
    fs::remove_all(fs::path{h.config->cscaCacheDir()}, ec);
    ASSERT_FALSE(ec);

    h.restart();

    EXPECT_TRUE(h.anchorState().empty()) << "the agent served counts for anchors it no longer holds";
    EXPECT_FALSE(h.config->cscaAnchorState().has_value()) << "the stale report is still in the configuration";

    // Where the pin actually lives, asserted rather than assumed: it went with
    // the cache, not with the report, so the next list is a first import again
    // — trusted on sight, and saying so. A record that had been feeding the
    // pin would make this list a stranger's instead.
    const auto next = fixture::signMasterList({fixture::makeCsca("CSCA X", "XX")}, fixture::makeIndependentSigner());
    TempFile nextFile(h.dir / "in", "next.ml", next.der);
    std::map<std::string, sdbus::Variant> summary;
    ASSERT_EQ(h.importFd(nextFile.fd(), &summary), "");
    EXPECT_FALSE(summary.at("signerPinned").get<bool>());
}

TEST(CscaImportDbus, AReportWhosePinnedSignerIsGoneIsNotServedAsCurrent)
{
    AllowAuthorizer allow;
    Harness h("reconcile-unpinned", allow);

    const auto list = fixture::signMasterList({fixture::makeCsca("CSCA A", "AA"), fixture::makeCsca("CSCA B", "BB")},
                                              fixture::makeIndependentSigner());
    TempFile file(h.dir / "in", "masterlist.ml", list.der);
    ASSERT_EQ(h.importFd(file.fd()), "");
    ASSERT_EQ(h.anchorState().at("signer").get<std::string>(), Trust::toHex(list.signerSpkiSha256));

    // The other half of the same fault, and the easy one to miss: only the
    // cache's own state file goes. The anchors stay, so the COUNTS a client
    // reads are still true — and that is exactly why an implementation that
    // only asks "are there anchors" walks straight past this. What is no
    // longer true is the signer beside them: with nothing left to read the pin
    // from, the agent follows nobody, so "pinned to X" describes a trust
    // narrower than the one actually in force.
    const fs::path cacheDir{h.config->cscaCacheDir()};
    std::error_code ec;
    ASSERT_TRUE(fs::remove(cacheDir / "state", ec)) << "the fixture removed nothing";
    ASSERT_FALSE(ec);
    ASSERT_TRUE(fs::exists(cacheDir / "anchors", ec)) << "the fixture removed more than the state file";

    h.restart();

    EXPECT_TRUE(h.anchorState().empty()) << "the agent named a publisher it no longer follows";
    EXPECT_FALSE(h.config->cscaAnchorState().has_value()) << "the stale report is still in the configuration";

    // The reconciliation reports; it does not tidy. The anchors it just
    // declined to describe are still on disk, untouched.
    EXPECT_TRUE(fs::exists(cacheDir / "anchors", ec))
        << "the reconciliation deleted anchors it only had to stop describing";

    // And the agent's behaviour agrees with what it now reports rather than
    // with what it used to: no pin left, so the next list is a first import
    // again, trusted on sight and saying so.
    const auto next = fixture::signMasterList({fixture::makeCsca("CSCA X", "XX")}, fixture::makeIndependentSigner());
    TempFile nextFile(h.dir / "in", "next.ml", next.der);
    std::map<std::string, sdbus::Variant> summary;
    ASSERT_EQ(h.importFd(nextFile.fd(), &summary), "");
    EXPECT_FALSE(summary.at("signerPinned").get<bool>());
}

TEST(CscaImportDbus, DiscardingAStaleReportLeavesTheSignerPinStanding)
{
    AllowAuthorizer allow;
    Harness h("reconcile-pin", allow);

    const auto publisher = fixture::makeIndependentSigner();
    const auto anchorA = fixture::makeCsca("CSCA A", "AA");
    const auto first = fixture::signMasterList({anchorA}, publisher);
    TempFile firstFile(h.dir / "in", "first.ml", first.der);
    ASSERT_EQ(h.importFd(firstFile.fd()), "");

    // Only the ANCHORS go. The cache's own state file stays, and that file is
    // what the pin and the rotation rule are read from — so this is the case
    // that would expose a reconciliation which "helpfully" cleared the cache
    // too, or which had been serving the pin out of the configuration.
    std::error_code ec;
    fs::remove_all(fs::path{h.config->cscaCacheDir()} / "anchors", ec);
    ASSERT_FALSE(ec);

    h.restart();
    EXPECT_TRUE(h.anchorState().empty()) << "counts were served for anchors that are gone";

    // A stranger is still refused ...
    const auto stranger =
        fixture::signMasterList({fixture::makeCsca("CSCA X", "XX")}, fixture::makeIndependentSigner());
    TempFile strangerFile(h.dir / "in", "stranger.ml", stranger.der);
    EXPECT_EQ(h.importFd(strangerFile.fd()), "org.librescrs.Agent.Error.MasterListSignerChanged")
        << "the wiped cache let a publisher this agent does not follow install anchors";

    // ... and the publisher the agent DOES follow is recognised, not merely
    // observed. signerPinned true is the pin being read; a blanket refusal
    // above would satisfy the previous assertion on its own.
    const auto second = fixture::signMasterList({anchorA, fixture::makeCsca("CSCA B", "BB")}, publisher);
    TempFile secondFile(h.dir / "in", "second.ml", second.der);
    std::map<std::string, sdbus::Variant> summary;
    ASSERT_EQ(h.importFd(secondFile.fd(), &summary), "");
    EXPECT_TRUE(summary.at("signerPinned").get<bool>()) << "the pin was discarded along with the report";
}

// --- who is told where the anchors are -------------------------------------
//
// This closes a gap that a real passport on a dogfood machine found: an
// import wrote anchors into the cache, and the plugin that judges a document
// was never told the directory existed. That the published directory really
// is the one an import wrote into is proved on the shared-library side, where
// AnchorCache and publishAnchorDirectory now live. What only this repository
// can prove is that ITS OWN startup path makes the call, with the CONFIGURED
// directory — which is what the guard below reads off this file's neighbour,
// AgentService.cpp.

// The composition root really makes the call, and makes it with the CONFIGURED
// cache directory rather than one rebuilt from the cache root. Read off the
// shipped source, the way this repository's other composition-root guards are:
// AgentService::registerOnBus needs a session bus and a PC/SC monitor that CI
// has not got, so there is no way to drive it here — but a wiring line that
// silently goes missing is the whole defect this closes, and the guard is a
// good deal better than nothing watching it at all.
//
// The configured value matters and is asserted for itself: CscaCacheDir is a
// settable key, so an installation that has set it imports into one directory,
// and a path rebuilt from the cache root would have the plugins read another.
TEST(CscaAnchorPublication, TheAgentPublishesTheConfiguredDirectoryAtStartup)
{
    std::ifstream in(LIBRELINUX_AGENTSERVICE_CPP, std::ios::binary);
    ASSERT_TRUE(in) << "AgentService source path not wired";
    const std::string src{std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
    ASSERT_FALSE(src.empty());

    EXPECT_NE(src.find("publishAnchorDirectory("), std::string::npos)
        << "nothing hands the card plugins the anchors this agent holds";
    EXPECT_NE(src.find("configStore().cscaCacheDir()"), std::string::npos)
        << "the published directory must come from the CONFIGURED cache dir, not one rebuilt from the cache root";
}

// --- forgetting, over the bus ------------------------------------------------
//
// The shared library owns WHAT a forget is and in which order; these assert
// what only this host can hold — that the verb exists on the bus, that it sits
// behind the same authorization as the import, and that the property a client
// reads afterwards agrees with it.

TEST(CscaForgetDbus, ForgettingClearsTheAnchorsAndTheServedReport)
{
    AllowAuthorizer allow;
    Harness h("forget-ok", allow);

    const auto list = fixture::signMasterList({fixture::makeCsca("CSCA A", "AA"), fixture::makeCsca("CSCA B", "BB")},
                                              fixture::makeIndependentSigner());
    TempFile file(h.dir / "in", "masterlist.ml", list.der);
    ASSERT_EQ(h.importFd(file.fd()), "");
    ASSERT_FALSE(h.anchorState().empty());

    std::uint64_t forgotten = 0;
    bool pinned = false;
    ASSERT_EQ(h.forgetAnchors(&forgotten, &pinned), "");

    EXPECT_EQ(forgotten, 2u) << "the reply describes what was destroyed";
    EXPECT_TRUE(pinned) << "a publisher was being followed and the reply did not say so";
    EXPECT_TRUE(h.anchorState().empty()) << "the property still serves a report for anchors that are gone";
}

// The reason the verb exists, asserted end to end over the bus: a publisher the
// agent refused before is taken in afterwards, and taken in as a first import.
TEST(CscaForgetDbus, AfterForgettingARefusedPublisherIsAcceptedAgain)
{
    AllowAuthorizer allow;
    Harness h("forget-reopens", allow);

    const auto first = fixture::signMasterList({fixture::makeCsca("CSCA A", "AA")}, fixture::makeIndependentSigner());
    TempFile firstFile(h.dir / "in", "first.ml", first.der);
    ASSERT_EQ(h.importFd(firstFile.fd()), "");

    const auto stranger =
        fixture::signMasterList({fixture::makeCsca("CSCA X", "XX")}, fixture::makeIndependentSigner());
    TempFile strangerFile(h.dir / "in", "stranger.ml", stranger.der);
    ASSERT_EQ(h.importFd(strangerFile.fd()), "org.librescrs.Agent.Error.MasterListSignerChanged")
        << "the fixture did not reproduce the trap";

    ASSERT_EQ(h.forgetAnchors(), "");

    TempFile againFile(h.dir / "in", "again.ml", stranger.der);
    std::map<std::string, sdbus::Variant> summary;
    ASSERT_EQ(h.importFd(againFile.fd(), &summary), "") << "the publisher is still refused after forgetting";
    EXPECT_FALSE(summary.at("signerPinned").get<bool>())
        << "an import after forgetting was reported as an established publisher";
}

// Same gate as the import, and for the stronger version of the same reason:
// this does not name where anchors may come from, it throws away the ones a
// passport is checked against.
TEST(CscaForgetDbus, ForgettingIsRefusedWithoutTheTrustAuthorization)
{
    DenyAuthorizer deny;
    Harness h("forget-denied", deny);

    // Seeded through the library rather than over the bus, because the bus is
    // closed to us here -- which is the point: a refused caller must not be
    // able to reach the store at all.
    Trust::AnchorCache cache{fs::path{h.config->cscaCacheDir()}};
    const auto list = fixture::signMasterList({fixture::makeCsca("CSCA A", "AA"), fixture::makeCsca("CSCA B", "BB")},
                                              fixture::makeIndependentSigner());
    ASSERT_TRUE(Trust::importMasterList(list.der, cache, kSignedLater).has_value());
    ASSERT_TRUE(cache.holdsAnchor());

    EXPECT_EQ(h.forgetAnchors(), "org.librescrs.Agent.Error.NotAuthorized");

    // The error name alone proves nothing, and this is the half that matters:
    // a refusal that deleted the anchors anyway answers IDENTICALLY to one that
    // did not, so only the store can tell them apart. Moving the authorization
    // below the deletion keeps this method's reply exactly as it is and fails
    // right here.
    EXPECT_TRUE(cache.holdsAnchor()) << "a refused caller destroyed the anchors and was told it was refused";
    EXPECT_TRUE(cache.state().present) << "a refused caller destroyed the pin and was told it was refused";
}

// Holding nothing is not a failure: an agent that imported nothing has already
// forgotten everything, and it says so with zeros rather than an error.
TEST(CscaForgetDbus, ForgettingWithNothingInstalledAnswersZeros)
{
    AllowAuthorizer allow;
    Harness h("forget-empty", allow);

    std::uint64_t forgotten = 1;
    bool pinned = true;
    ASSERT_EQ(h.forgetAnchors(&forgotten, &pinned), "");
    EXPECT_EQ(forgotten, 0u);
    EXPECT_FALSE(pinned);
}
