// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Where the daemon looks for card plugins, and what it says about it.
//
// The daemon picked a directory and constructed the registry in silence, so a
// machine with no plugins in either candidate location was indistinguishable
// from a machine holding a card nothing supports: every card reported as
// unusable, and nothing anywhere named the directory that had been tried —
// recovering it meant pulling the compiled-in path out of the binary with
// `strings`. These cases pin both halves: the resolution reports which source
// won and why the other one lost, and loading nothing is a warning that names
// the directory and says whether it is even there.
//
// The assertions are on the TEXT an operator reads, not merely on the fact that
// some line was emitted — a report that says nothing useful is the defect.
#include "PluginDirectory.h"

#include <LibreSCRS/Agent/backend/Logging.h>
#include <LibreSCRS/Plugin/CardPluginService.h>

#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>
#include <string>
#include <unistd.h>
#include <vector>

namespace {

namespace fs = std::filesystem;

using LibreSCRS::Agent::PluginDirCandidate;
using LibreSCRS::Agent::PluginDirInputs;
using LibreSCRS::Agent::pluginLoadReportLines;
using LibreSCRS::Agent::reportPluginLoad;
using LibreSCRS::Agent::resolvePluginDir;

using Source = PluginDirCandidate::Source;
using Verdict = PluginDirCandidate::Verdict;
using State = LibreSCRS::Agent::PluginDirState;
using Level = LibreSCRS::Agent::log::Level;
using LoadOutcome = LibreSCRS::Plugin::LoadOutcome;

// A directory that removes itself, so a case can hand the cascade a real
// on-disk layout instead of a mocked filesystem.
class TempDir
{
public:
    explicit TempDir(const std::string& tag)
        : root(fs::temp_directory_path() / ("ll-plugindir-" + tag + "-" + std::to_string(::getpid())))
    {
        fs::remove_all(root);
        fs::create_directories(root);
    }
    ~TempDir()
    {
        fs::remove_all(root);
    }

    TempDir(const TempDir&) = delete;
    TempDir& operator=(const TempDir&) = delete;

    [[nodiscard]] const fs::path& path() const noexcept
    {
        return root;
    }

private:
    fs::path root;
};

// Every line the report produced, joined — cases assert on what the operator
// reading the journal can see, not on line indices.
std::string joined(const std::vector<std::pair<Level, std::string>>& lines)
{
    std::string all;
    for (const auto& [level, text] : lines) {
        all += text;
        all += '\n';
    }
    return all;
}

bool hasLevel(const std::vector<std::pair<Level, std::string>>& lines, Level wanted)
{
    for (const auto& [level, text] : lines) {
        if (level == wanted) {
            return true;
        }
    }
    return false;
}

// --- the cascade ---------------------------------------------------------

TEST(PluginDirectory, EnvironmentOverrideWinsAndIsTheOnlyCandidate)
{
    const auto resolution = resolvePluginDir(
        PluginDirInputs{.environment = "/opt/plugins", .compiledDefault = "/usr/lib/librescrs/plugins"});

    EXPECT_EQ(resolution.dir, fs::path("/opt/plugins"));
    ASSERT_EQ(resolution.candidates.size(), 1U);
    EXPECT_EQ(resolution.candidates.front().source, Source::Environment);
    EXPECT_EQ(resolution.candidates.front().verdict, Verdict::Chosen);
}

TEST(PluginDirectory, CompiledDefaultIsTheTerminalFallbackAndRecordsThatTheEnvironmentWasUnset)
{
    const auto resolution =
        resolvePluginDir(PluginDirInputs{.environment = "", .compiledDefault = "/usr/lib/librescrs/plugins"});

    EXPECT_EQ(resolution.dir, fs::path("/usr/lib/librescrs/plugins"));
    ASSERT_EQ(resolution.candidates.size(), 2U);
    EXPECT_EQ(resolution.candidates[0].source, Source::Environment);
    EXPECT_EQ(resolution.candidates[0].verdict, Verdict::Unset);
    EXPECT_TRUE(resolution.candidates[0].path.empty());
    EXPECT_EQ(resolution.candidates[1].source, Source::CompiledDefault);
    EXPECT_EQ(resolution.candidates[1].verdict, Verdict::Chosen);
}

TEST(PluginDirectory, TheChosenDirectoryIsAlwaysTheLastCandidate)
{
    for (const std::string& env : {std::string("/opt/plugins"), std::string()}) {
        const auto resolution = resolvePluginDir(PluginDirInputs{.environment = env, .compiledDefault = "/usr/lib/x"});
        ASSERT_FALSE(resolution.candidates.empty());
        EXPECT_EQ(resolution.candidates.back().verdict, Verdict::Chosen);
        EXPECT_EQ(resolution.candidates.back().path, resolution.dir);
    }
}

TEST(PluginDirectory, WhetherTheChosenDirectoryIsThereIsPartOfTheResolution)
{
    TempDir present("present");
    const auto real = resolvePluginDir(
        PluginDirInputs{.environment = present.path().string(), .compiledDefault = "/usr/lib/librescrs/plugins"});
    EXPECT_EQ(real.dirState, State::Present);
    EXPECT_TRUE(real.dirError.empty());

    const auto absent = resolvePluginDir(PluginDirInputs{.environment = (present.path() / "nowhere").string(),
                                                         .compiledDefault = "/usr/lib/librescrs/plugins"});
    EXPECT_EQ(absent.dirState, State::Absent);
}

TEST(PluginDirectory, APathThatIsAFileIsNotADirectory)
{
    TempDir tree("isfile");
    const fs::path file = tree.path() / "a-file";
    {
        std::ofstream out(file);
        out << "not a directory";
    }

    // Deliberate: something is there, but no *directory* is, so it takes the
    // same state — and the same message — as nothing being there.
    EXPECT_EQ(resolvePluginDir(PluginDirInputs{.environment = file.string(), .compiledDefault = "/unused"}).dirState,
              State::Absent);
}

TEST(PluginDirectory, ADirectoryThatCannotBeExaminedIsNotReportedAsAbsent)
{
    if (::geteuid() == 0) {
        GTEST_SKIP() << "root bypasses directory permissions, so this state is unreachable here";
    }
    TempDir tree("unreadable");
    const fs::path outer = tree.path() / "outer";
    const fs::path inner = outer / "plugins";
    fs::create_directories(inner);
    fs::permissions(outer, fs::perms::none);

    const auto resolution =
        resolvePluginDir(PluginDirInputs{.environment = inner.string(), .compiledDefault = "/unused"});
    // Restore before asserting so TempDir's destructor can always clean up.
    fs::permissions(outer, fs::perms::owner_all);

    // `is_directory` answers false here exactly as it does for a missing path.
    // Calling that "does not exist" would send the reader to create a directory
    // that is already on disk — the misdiagnosis this whole report exists to end.
    EXPECT_EQ(resolution.dirState, State::Unreadable);
    EXPECT_FALSE(resolution.dirError.empty()) << "the reason it could not be read is the actionable half";
}

// --- what gets said about it ---------------------------------------------

TEST(PluginDirectoryReport, ZeroPluginsIsAWarningNamingTheDirectory)
{
    TempDir empty("empty-lines");
    const auto resolution =
        resolvePluginDir(PluginDirInputs{.environment = empty.path().string(), .compiledDefault = "/unused"});

    const auto lines = pluginLoadReportLines(resolution, 0, {});

    EXPECT_TRUE(hasLevel(lines, Level::Warn)) << "loading nothing must not be reported at info severity:\n"
                                              << joined(lines);
    EXPECT_NE(joined(lines).find(empty.path().string()), std::string::npos)
        << "the directory that produced nothing has to be named:\n"
        << joined(lines);
}

TEST(PluginDirectoryReport, ADirectoryThatIsNotEvenThereSaysSoRatherThanJustReportingZero)
{
    // Derived from a temp dir rather than naming a real prefix: a machine that
    // happens to have LibreSCRS installed must not turn this case green.
    TempDir tree("absent");
    const auto resolution =
        resolvePluginDir(PluginDirInputs{.environment = "", .compiledDefault = tree.path() / "no-such-dir"});
    ASSERT_EQ(resolution.dirState, State::Absent);

    const std::string text = joined(pluginLoadReportLines(resolution, 0, {}));

    // "empty" and "not there at all" are different faults with different fixes;
    // reporting only the count leaves the reader unable to tell them apart.
    EXPECT_NE(text.find("does not exist"), std::string::npos)
        << "an absent directory has to be reported as absent, not merely as empty:\n"
        << text;
}

TEST(PluginDirectoryReport, AnUnreadableDirectoryIsReportedWithTheReasonItCouldNotBeRead)
{
    if (::geteuid() == 0) {
        GTEST_SKIP() << "root bypasses directory permissions, so this state is unreachable here";
    }
    TempDir tree("unreadable-lines");
    const fs::path outer = tree.path() / "outer";
    const fs::path inner = outer / "plugins";
    fs::create_directories(inner);
    fs::permissions(outer, fs::perms::none);

    const auto resolution =
        resolvePluginDir(PluginDirInputs{.environment = inner.string(), .compiledDefault = "/unused"});
    fs::permissions(outer, fs::perms::owner_all);
    ASSERT_EQ(resolution.dirState, State::Unreadable);

    const auto lines = pluginLoadReportLines(resolution, 0, {});
    const std::string text = joined(lines);

    EXPECT_TRUE(hasLevel(lines, Level::Warn)) << text;
    EXPECT_NE(text.find("could not be read"), std::string::npos) << text;
    EXPECT_NE(text.find(resolution.dirError), std::string::npos)
        << "the filesystem's own reason is what makes this actionable:\n"
        << text;
    EXPECT_EQ(text.find("does not exist"), std::string::npos)
        << "a directory that is merely unreadable must not be reported as missing:\n"
        << text;
}

TEST(PluginDirectoryReport, NamesTheEnvironmentOverrideAsTriedAndUnset)
{
    const auto resolution =
        resolvePluginDir(PluginDirInputs{.environment = "", .compiledDefault = "/usr/lib/librescrs/plugins"});

    const std::string text = joined(pluginLoadReportLines(resolution, 0, {}));

    EXPECT_NE(text.find("LIBRESCRS_PLUGIN_DIR"), std::string::npos)
        << "the override the reader is about to be told to set has to be named:\n"
        << text;
    EXPECT_NE(text.find("not set"), std::string::npos) << "and named as unset, not merely mentioned:\n" << text;
}

TEST(PluginDirectoryReport, NamesTheSourceOfTheDirectoryItChose)
{
    const std::string fallback = joined(pluginLoadReportLines(
        resolvePluginDir(PluginDirInputs{.environment = "", .compiledDefault = "/usr/lib/x"}), 0, {}));
    EXPECT_NE(fallback.find("compiled-in default"), std::string::npos)
        << "a path nobody configured has to be attributed to the binary:\n"
        << fallback;

    const std::string overridden = joined(pluginLoadReportLines(
        resolvePluginDir(PluginDirInputs{.environment = "/opt/plugins", .compiledDefault = "/usr/lib/x"}), 0, {}));
    EXPECT_NE(overridden.find("LIBRESCRS_PLUGIN_DIR"), std::string::npos)
        << "an overridden path has to be attributed to the override:\n"
        << overridden;
    EXPECT_EQ(overridden.find("/usr/lib/x"), std::string::npos)
        << "the compiled-in default was never tried and must not be reported as if it were:\n"
        << overridden;
}

TEST(PluginDirectoryReport, LoadedPluginsAreInformationalAndCounted)
{
    TempDir dir("counted");
    const auto resolution =
        resolvePluginDir(PluginDirInputs{.environment = dir.path().string(), .compiledDefault = "/unused"});
    const std::vector<LoadOutcome> report{
        LoadOutcome{.soPath = dir.path() / "a.so", .pluginId = "a", .status = LoadOutcome::Status::Loaded},
        LoadOutcome{.soPath = dir.path() / "b.so", .pluginId = "b", .status = LoadOutcome::Status::Loaded}};

    const auto lines = pluginLoadReportLines(resolution, 2, report);

    EXPECT_FALSE(hasLevel(lines, Level::Warn)) << "a healthy load must not warn:\n" << joined(lines);
    EXPECT_NE(joined(lines).find("loaded 2 plugins"), std::string::npos) << "the count has to be reported:\n"
                                                                         << joined(lines);
}

TEST(PluginDirectoryReport, ASinglePluginIsCountedInTheSingular)
{
    TempDir dir("one");
    const auto resolution =
        resolvePluginDir(PluginDirInputs{.environment = dir.path().string(), .compiledDefault = "/unused"});
    const std::vector<LoadOutcome> report{
        LoadOutcome{.soPath = dir.path() / "a.so", .pluginId = "a", .status = LoadOutcome::Status::Loaded}};

    // A one-family install is an ordinary deployment, and this line exists to be
    // read by a person — "loaded 1 plugins" is the kind of sloppiness that makes
    // a reader distrust the rest of the report.
    const std::string text = joined(pluginLoadReportLines(resolution, 1, report));

    EXPECT_NE(text.find("loaded 1 plugin from"), std::string::npos) << text;
}

TEST(PluginDirectoryReport, AFileThatFailedToLoadIsNamedWithItsDiagnostic)
{
    TempDir dir("failed");
    const auto resolution =
        resolvePluginDir(PluginDirInputs{.environment = dir.path().string(), .compiledDefault = "/unused"});
    const std::vector<LoadOutcome> report{LoadOutcome{.soPath = dir.path() / "broken.so",
                                                      .pluginId = "",
                                                      .status = LoadOutcome::Status::AbiMismatch,
                                                      .diagnostic = "expected ABI 8 got 6"}};

    const auto lines = pluginLoadReportLines(resolution, 0, report);
    const std::string text = joined(lines);

    EXPECT_TRUE(hasLevel(lines, Level::Warn)) << text;
    EXPECT_NE(text.find("broken.so"), std::string::npos) << "the file that failed has to be named:\n" << text;
    EXPECT_NE(text.find("plugin ABI mismatch"), std::string::npos) << "as does why it failed:\n" << text;
    EXPECT_NE(text.find("expected ABI 8 got 6"), std::string::npos) << "as does the detail behind it:\n" << text;
}

TEST(PluginDirectoryReport, ASuccessfullyLoadedFileIsNotListedAsAProblem)
{
    TempDir dir("mixed");
    const auto resolution =
        resolvePluginDir(PluginDirInputs{.environment = dir.path().string(), .compiledDefault = "/unused"});
    const std::vector<LoadOutcome> report{
        LoadOutcome{.soPath = dir.path() / "good.so", .pluginId = "good", .status = LoadOutcome::Status::Loaded},
        LoadOutcome{.soPath = dir.path() / "bad.so",
                    .pluginId = "",
                    .status = LoadOutcome::Status::DlopenFailed,
                    .diagnostic = "undefined symbol: nope"}};

    const std::string text = joined(pluginLoadReportLines(resolution, 1, report));

    EXPECT_EQ(text.find("good.so"), std::string::npos) << "a plugin that loaded is covered by the count:\n" << text;
    EXPECT_NE(text.find("bad.so"), std::string::npos) << text;
}

// --- end to end, against a real registry over a real directory -----------

TEST(PluginDirectoryReport, AnEmptyDirectoryReachesTheLogAsAWarning)
{
    TempDir empty("empty");
    std::vector<std::pair<Level, std::string>> captured;
    LibreSCRS::Agent::log::init(
        [&captured](Level level, std::string_view line) { captured.emplace_back(level, std::string(line)); });

    const auto resolution =
        resolvePluginDir(PluginDirInputs{.environment = empty.path().string(), .compiledDefault = "/unused"});
    const LibreSCRS::Plugin::CardPluginService service(resolution.dir);
    reportPluginLoad(resolution, service);

    LibreSCRS::Agent::log::resetForTest();

    ASSERT_FALSE(captured.empty()) << "resolving a plugin directory must not be silent";
    EXPECT_TRUE(hasLevel(captured, Level::Warn)) << joined(captured);
    EXPECT_NE(joined(captured).find(empty.path().string()), std::string::npos) << joined(captured);
}

TEST(PluginDirectoryReport, AnUnloadableFileInTheDirectoryReachesTheLog)
{
    TempDir dir("broken");
    {
        std::ofstream bogus(dir.path() / "not-a-plugin.so", std::ios::binary);
        bogus << "this is not an elf";
    }
    std::vector<std::pair<Level, std::string>> captured;
    LibreSCRS::Agent::log::init(
        [&captured](Level level, std::string_view line) { captured.emplace_back(level, std::string(line)); });

    const auto resolution =
        resolvePluginDir(PluginDirInputs{.environment = dir.path().string(), .compiledDefault = "/unused"});
    const LibreSCRS::Plugin::CardPluginService service(resolution.dir);
    reportPluginLoad(resolution, service);

    LibreSCRS::Agent::log::resetForTest();

    EXPECT_NE(joined(captured).find("not-a-plugin.so"), std::string::npos)
        << "a file that failed to load has to be named:\n"
        << joined(captured);
}

} // namespace
