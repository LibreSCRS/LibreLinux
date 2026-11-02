// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Unit coverage for the PolkitAuthorizer's pure helpers — the pieces that do
// NOT need a live polkit daemon: /proc/<pid>/stat start-time parsing (the
// PID-reuse-pinning value polkit itself keys on), the unix-process subject
// detail construction, and the CheckAuthorization reply -> bool mapping. The
// live CheckAuthorization round-trip is validated manually against a running
// polkitd (see the increment report) and on hardware.

#include <LibreSCRS/Agent/backend/Authorizer.h>
#include "PolkitAuthorizer.h"
#include "ProcPidPin.h" // librelinux-common pinned /proc readers

#include <fcntl.h>    // open
#include <sys/wait.h> // waitpid
#include <unistd.h>   // fork, getpid, _exit

#include <gtest/gtest.h>
#include <cstdint>
#include <map>
#include <optional>
#include <string>

using namespace LibreSCRS::Agent;
using LibreLinux::Common::readProcExePinned;
using LibreLinux::Common::readProcStatPinned;
using LibreSCRS::Agent::PolkitDetail::buildUnixProcessDetails;
using LibreSCRS::Agent::PolkitDetail::interpretReply;
using LibreSCRS::Agent::PolkitDetail::parseProcStartTime;
using LibreSCRS::Agent::PolkitDetail::uidDetail;
using LibreSCRS::Agent::PolkitDetail::unixProcessDetailsFrom;

TEST(PolkitProcStat, ParsesField22FromASimpleLine)
{
    // pid comm state ppid ... field22 (1-indexed). Build a line whose 22nd
    // whitespace-separated field is a known start-time.
    const std::string stat = "1234 (cat) R 1000 1234 1000 34816 1234 4194304 100 0 0 0 1 2 3 4 20 0 1 0 987654 5 6 7";
    const auto st = parseProcStartTime(stat);
    ASSERT_TRUE(st.has_value());
    EXPECT_EQ(*st, 987654u);
}

TEST(PolkitProcStat, HandlesParensInsideComm)
{
    // The comm field can contain spaces and parentheses; the parser must split
    // on the LAST ')' so the field offsets after it stay correct.
    const std::string stat =
        "4321 (weird )( name) S 1000 4321 1000 34816 4321 4194304 100 0 0 0 1 2 3 4 20 0 1 0 555111 5 6";
    const auto st = parseProcStartTime(stat);
    ASSERT_TRUE(st.has_value());
    EXPECT_EQ(*st, 555111u);
}

TEST(PolkitProcStat, HandlesSpacesInComm)
{
    const std::string stat = "77 (my program) R 1 77 1 0 -1 4194560 50 0 0 0 0 0 0 0 20 0 1 0 42 1 2";
    const auto st = parseProcStartTime(stat);
    ASSERT_TRUE(st.has_value());
    EXPECT_EQ(*st, 42u);
}

TEST(PolkitProcStat, ToleratesTrailingNewline)
{
    const std::string stat = "1234 (cat) R 1000 1234 1000 34816 1234 4194304 100 0 0 0 1 2 3 4 20 0 1 0 987654 5 6 7\n";
    const auto st = parseProcStartTime(stat);
    ASSERT_TRUE(st.has_value());
    EXPECT_EQ(*st, 987654u);
}

TEST(PolkitProcStat, RejectsMalformedShortLine)
{
    EXPECT_FALSE(parseProcStartTime("1234 (cat) R 1000").has_value());
    EXPECT_FALSE(parseProcStartTime("").has_value());
    EXPECT_FALSE(parseProcStartTime("no parens here at all 1 2 3").has_value());
}

TEST(PolkitProcStat, RejectsNonNumericStartTime)
{
    const std::string stat =
        "1234 (cat) R 1000 1234 1000 34816 1234 4194304 100 0 0 0 1 2 3 4 20 0 1 0 notanumber 5 6 7";
    EXPECT_FALSE(parseProcStartTime(stat).has_value());
}

// The pidfd-pinned /proc/<pid>/stat read (librelinux-common, shared with
// CallerIdentity and the prompter's CallerAuthorizer). The pin + post-read
// probe close the PID-reuse window before the security gate reads start-time.
TEST(ProcPidPin, ReadsOwnStatAndParsesStartTime)
{
    // Our own PID is guaranteed live and pidfd-pinnable on any supported host.
    const auto stat = readProcStatPinned(::getpid());
    ASSERT_TRUE(stat.has_value()) << "self /proc/<pid>/stat must be readable under a pidfd pin";
    EXPECT_NE(stat->find(')'), std::string::npos) << "a real stat line carries the parenthesised comm";
    const auto startTime = parseProcStartTime(*stat);
    ASSERT_TRUE(startTime.has_value()) << "self start-time must parse from the pinned read";
}

TEST(ProcPidPin, BogusPidYieldsNullopt)
{
    // PID 0 and negatives are never valid targets; the helper must fail closed
    // (nullopt) rather than touching /proc/0/... or a negative path.
    EXPECT_FALSE(readProcStatPinned(0).has_value());
    EXPECT_FALSE(readProcStatPinned(-1).has_value());
}

TEST(ProcPidPin, ReapedChildPidYieldsNullopt)
{
    // A real-but-reaped PID: pidfd_open fails with ESRCH (the process is
    // gone), so both readers must fail closed instead of reading whatever
    // /proc/<pid> might mean by the time a recycled process owns the number.
    const pid_t child = ::fork();
    ASSERT_NE(child, -1) << "fork failed";
    if (child == 0) {
        ::_exit(0);
    }
    int status = 0;
    ASSERT_EQ(::waitpid(child, &status, 0), child);
    EXPECT_FALSE(readProcStatPinned(child).has_value());
    EXPECT_FALSE(readProcExePinned(child).has_value());
}

TEST(PolkitSubject, BuildsUnixProcessDetailsWithPidAndStartTime)
{
    const auto details =
        buildUnixProcessDetails(/*pid=*/4242u, /*startTime=*/987654u, /*uid=*/std::optional<std::uint32_t>{1000u});
    ASSERT_TRUE(details.contains("pid"));
    ASSERT_TRUE(details.contains("start-time"));
    ASSERT_TRUE(details.contains("uid"));
    EXPECT_EQ(details.at("pid").get<std::uint32_t>(), 4242u);
    EXPECT_EQ(details.at("start-time").get<std::uint64_t>(), 987654u);
    EXPECT_STREQ(details.at("uid").peekValueType(), "i");
    EXPECT_EQ(details.at("uid").get<std::int32_t>(), 1000);
}

// polkit reads a subject's uid as int32 and treats an entry of any other type
// as absent -- the unsigned value the bus reports must not reach it as "u".
TEST(PolkitSubject, TheUidIsTheSignedIntegerPolkitReads)
{
    EXPECT_STREQ(uidDetail(1000u).peekValueType(), "i");
    EXPECT_EQ(uidDetail(1000u).get<std::int32_t>(), 1000);
    EXPECT_EQ(uidDetail(0u).get<std::int32_t>(), 0);
}

TEST(PolkitSubject, OmitsUidWhenAbsent)
{
    const auto details = buildUnixProcessDetails(7u, 1u, std::nullopt);
    EXPECT_TRUE(details.contains("pid"));
    EXPECT_TRUE(details.contains("start-time"));
    EXPECT_FALSE(details.contains("uid"));
}

TEST(PolkitReply, AuthorizedTrueRegardlessOfChallenge)
{
    EXPECT_TRUE(interpretReply(/*isAuthorized=*/true, /*isChallenge=*/false));
    EXPECT_TRUE(interpretReply(/*isAuthorized=*/true, /*isChallenge=*/true));
}

TEST(PolkitReply, NotAuthorizedIsDenied)
{
    EXPECT_FALSE(interpretReply(false, false));
    // A pending challenge that did NOT resolve to authorized is a deny (we pass
    // AllowUserInteraction, so a satisfiable challenge resolves to authorized).
    EXPECT_FALSE(interpretReply(false, true));
}

// The polkit-unreachable fallback must be a fail-closed allow-LIST: only the
// low-tier configure and the default-allow sign actions are permitted; the
// trust tier and any unknown action id are denied.
TEST(DefaultAuthorizer, AllowsConfigureAndSignOnly)
{
    DefaultAuthorizer auth;
    EXPECT_EQ(auth.authorize(kActionConfigure, CallerToken{":1.7"}), AuthorizationOutcome::Granted);
    EXPECT_EQ(auth.authorize(kActionSign, CallerToken{":1.7"}), AuthorizationOutcome::Granted);
    EXPECT_EQ(auth.authorize(kActionConfigureTrust, CallerToken{":1.7"}), AuthorizationOutcome::Denied);
    EXPECT_EQ(auth.authorize("org.librescrs.agent.future.unknown", CallerToken{":1.7"}), AuthorizationOutcome::Denied);
    EXPECT_EQ(auth.authorize("", CallerToken{":1.7"}), AuthorizationOutcome::Denied);
}

// PKCS#11 lease establishment shares the sign posture: default-allow,
// PIN-as-consent. It must be on the fail-closed fallback allow-list too so a
// PKCS#11 app can still log in when polkitd is unreachable.
TEST(DefaultAuthorizer, AllowsPkcs11Login)
{
    DefaultAuthorizer auth;
    EXPECT_EQ(auth.authorize(kActionPkcs11Login, CallerToken{":1.7"}), AuthorizationOutcome::Granted);
}

// A bus that hands out the caller's pidfd: the subject is that pidfd (and the
// uid), and no start time is read -- there is no pid to pin.
TEST(PolkitSubject, APidfdFromTheBusIsTheSubject)
{
    const int fd = ::open("/dev/null", O_RDONLY | O_CLOEXEC);
    ASSERT_GE(fd, 0);
    const std::map<std::string, sdbus::Variant> credentials{
        {"ProcessID", sdbus::Variant{std::uint32_t{4242}}},
        {"UnixUserID", sdbus::Variant{std::uint32_t{1000}}},
        {"ProcessFD", sdbus::Variant{sdbus::UnixFd{fd, sdbus::adopt_fd}}},
    };
    int startTimeReads = 0;
    const auto details = unixProcessDetailsFrom(credentials, [&startTimeReads](std::uint32_t) {
        ++startTimeReads;
        return std::optional<std::uint64_t>{1};
    });
    ASSERT_TRUE(details.has_value());
    EXPECT_EQ(details->count("pidfd"), 1u);
    EXPECT_EQ(details->count("pid"), 0u);
    EXPECT_EQ(details->count("start-time"), 0u);
    EXPECT_STREQ(details->at("uid").peekValueType(), "i");
    EXPECT_EQ(details->at("uid").get<std::int32_t>(), 1000);
    EXPECT_EQ(startTimeReads, 0);
}

// polkit refuses a pidfd subject that carries no uid, so a bus that hands out
// the pidfd but not the uid gets the pid pinned by its start time instead.
TEST(PolkitSubject, APidfdWithoutTheUidFallsBackToThePid)
{
    const int fd = ::open("/dev/null", O_RDONLY | O_CLOEXEC);
    ASSERT_GE(fd, 0);
    const std::map<std::string, sdbus::Variant> credentials{
        {"ProcessID", sdbus::Variant{std::uint32_t{4242}}},
        {"ProcessFD", sdbus::Variant{sdbus::UnixFd{fd, sdbus::adopt_fd}}},
    };
    const auto details =
        unixProcessDetailsFrom(credentials, [](std::uint32_t) { return std::optional<std::uint64_t>{987654}; });
    ASSERT_TRUE(details.has_value());
    EXPECT_EQ(details->count("pidfd"), 0u);
    EXPECT_EQ(details->count("uid"), 0u);
    EXPECT_EQ(details->at("pid").get<std::uint32_t>(), 4242u);
    EXPECT_EQ(details->at("start-time").get<std::uint64_t>(), 987654u);
}

// A bus that hands out no pidfd: the pid, pinned by its start time.
TEST(PolkitSubject, WithoutAPidfdThePidAndItsStartTimeAreTheSubject)
{
    const std::map<std::string, sdbus::Variant> credentials{
        {"ProcessID", sdbus::Variant{std::uint32_t{4242}}},
        {"UnixUserID", sdbus::Variant{std::uint32_t{1000}}},
    };
    const auto details = unixProcessDetailsFrom(
        credentials, [](std::uint32_t pid) { return std::optional<std::uint64_t>{pid == 4242 ? 987654 : 0}; });
    ASSERT_TRUE(details.has_value());
    EXPECT_EQ(details->count("pidfd"), 0u);
    EXPECT_EQ(details->at("pid").get<std::uint32_t>(), 4242u);
    EXPECT_EQ(details->at("start-time").get<std::uint64_t>(), 987654u);
    EXPECT_STREQ(details->at("uid").peekValueType(), "i");
    EXPECT_EQ(details->at("uid").get<std::int32_t>(), 1000);
}

// No pidfd and no start time, or no pid at all: nothing to ask polkit about.
TEST(PolkitSubject, WithNeitherThereIsNoSubject)
{
    const std::map<std::string, sdbus::Variant> pidOnly{{"ProcessID", sdbus::Variant{std::uint32_t{4242}}}};
    EXPECT_FALSE(unixProcessDetailsFrom(pidOnly, [](std::uint32_t) { return std::optional<std::uint64_t>{}; }));
    const std::map<std::string, sdbus::Variant> none{{"UnixUserID", sdbus::Variant{std::uint32_t{1000}}}};
    EXPECT_FALSE(unixProcessDetailsFrom(none, [](std::uint32_t) { return std::optional<std::uint64_t>{1}; }));
}
