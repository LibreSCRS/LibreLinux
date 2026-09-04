// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Guard: a platform backend owns transports and construction sites, never the
// card operations themselves. The nine operation classes live in the agent
// core, are declared in its namespace and include only its headers; a copy in a
// backend can only drift, and a tenth forked operation would be invisible to
// the core's own tests.
//
// These are SHAPE rules read off the shipped source, not a list of nine names,
// so a new fork trips them too. The test links no agent library and needs no
// bus, no middleware and no card: it reads the backend's source tree through
// the path the build system hands it.

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <gtest/gtest.h>
#include <regex>
#include <sstream>
#include <string>
#include <vector>

namespace {

namespace fs = std::filesystem;

fs::path hostSrcDir()
{
    return fs::path(LIBRESCRS_HOST_SRC_DIR).lexically_normal();
}

std::string slurp(const fs::path& path)
{
    std::ifstream in(path);
    std::stringstream buffer;
    buffer << in.rdbuf();
    return buffer.str();
}

// Every C++ source and header under the backend's source tree, sorted so a
// failure message reads the same way twice.
std::vector<fs::path> hostSources()
{
    std::vector<fs::path> out;
    std::error_code ec;
    for (fs::recursive_directory_iterator it(hostSrcDir(), ec), end; it != end; it.increment(ec)) {
        if (ec || !it->is_regular_file()) {
            continue;
        }
        const std::string ext = it->path().extension().string();
        if (ext == ".h" || ext == ".hpp" || ext == ".cpp" || ext == ".mm") {
            out.push_back(it->path());
        }
    }
    std::sort(out.begin(), out.end());
    return out;
}

std::string relPath(const fs::path& p)
{
    return p.lexically_relative(hostSrcDir()).string();
}

// Lines of `file` that match `re`, rendered as "path:line: text".
std::vector<std::string> matchingLines(const fs::path& file, const std::regex& re)
{
    std::vector<std::string> hits;
    std::ifstream in(file);
    std::string line;
    int number = 0;
    while (std::getline(in, line)) {
        ++number;
        if (std::regex_search(line, re)) {
            hits.push_back(relPath(file) + ":" + std::to_string(number) + ": " + line);
        }
    }
    return hits;
}

// The argument list of the first `CardPluginService>(` construction in `text`,
// paren-balanced, or an empty optional when there is no such construction.
std::string constructionArguments(const std::string& text, bool& found)
{
    found = false;
    const std::string marker = "CardPluginService>(";
    const std::size_t at = text.find(marker);
    if (at == std::string::npos) {
        return {};
    }
    found = true;
    std::size_t i = at + marker.size();
    int depth = 1;
    const std::size_t start = i;
    for (; i < text.size() && depth > 0; ++i) {
        if (text[i] == '(') {
            ++depth;
        } else if (text[i] == ')') {
            --depth;
        }
    }
    return text.substr(start, i - start - 1);
}

} // namespace

// A card operation is a class of the agent core. A backend that declares one
// has forked it: the fork is invisible to the core's tests and drifts silently,
// which has already cost two dependency fields in a sibling backend. A
// per-platform difference belongs in the injected dependency set or in the
// operation channel, never in a forked class.
TEST(HostOperationOwnership, TheBackendDefinesNoOperationSubclass)
{
    const std::regex subclass(R"(:[[:space:]]*public[[:space:]]+(Operations::)?OperationBase\b)");
    std::vector<std::string> hits;
    for (const auto& file : hostSources()) {
        auto lines = matchingLines(file, subclass);
        hits.insert(hits.end(), lines.begin(), lines.end());
    }

    std::string report;
    for (const auto& hit : hits) {
        report += "\n  " + hit;
    }
    EXPECT_TRUE(hits.empty()) << "this backend declares " << hits.size()
                              << " operation subclass(es) of its own:" << report
                              << "\n\nThe operation classes belong to the agent core, where every host shares one"
                                 "\ncopy and one suite of tests. A subclass declared here is a fork the core"
                                 "\ncannot see: it drifts, and the drift shows up as a behavioural difference"
                                 "\nbetween platforms that no test asserts. Put the per-host difference in the"
                                 "\ninjected dependency set or in the operation channel instead.";
}

// Which plugin claims a card is one decision with one answer. A backend that
// counts candidates and reads a plugin id itself is arbitrating a second time,
// by its own rules, and the two answers diverge without anything failing.
TEST(HostOperationOwnership, TheBackendDoesNotArbitrateCardTypeItself)
{
    std::vector<std::string> offenders;
    for (const auto& file : hostSources()) {
        const std::string text = slurp(file);
        if (text.find("candidates.size() == 1") != std::string::npos && text.find("pluginId()") != std::string::npos) {
            offenders.push_back(relPath(file));
        }
    }

    std::string report;
    for (const auto& file : offenders) {
        report += "\n  " + file;
    }
    EXPECT_TRUE(offenders.empty()) << "this backend arbitrates the card type itself in:" << report
                                   << "\n\nCounting candidates and reading a plugin id here duplicates the shared"
                                      "\narbitration the core exposes. Call it instead, so both hosts answer the"
                                      "\nsame question the same way.";
}

// The plugin service decides whether a card's certificate chain can be
// verified. Constructed without a trust store it silently answers "unverified"
// forever, and nothing in the running system says so.
TEST(HostOperationOwnership, TheCompositionRootGivesPluginsATrustStore)
{
    const fs::path mainCpp = hostSrcDir() / "main.cpp";
    const std::string text = slurp(mainCpp);
    ASSERT_FALSE(text.empty()) << "composition root not found at " << mainCpp.string();

    bool found = false;
    const std::string args = constructionArguments(text, found);
    ASSERT_TRUE(found) << "no CardPluginService construction found in " << relPath(mainCpp);

    EXPECT_NE(args.find(','), std::string::npos)
        << "the composition root constructs the plugin service with one argument:"
           "\n  "
        << relPath(mainCpp) << ": CardPluginService(" << args
        << ")"
           "\n\nThe single-argument overload defaults the trust store to null, so every"
           "\ncard certificate stays unverifiable for the life of the process and no"
           "\nfailure is reported. Pass the trust store explicitly.";
}
