// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Machine gate for the Operation1 errorCode taxonomy: pins the agent's
// ErrorCode enum, value-for-value and count, against the enumeration
// documented in dbus/org.librescrs.Agent.Operation1.xml. That enumeration is
// the canonical wire contract — a new code lands there first (codes cross the
// bus as plain uint32; the XML doc block is the only place the wire values are
// published to clients).
//
// Two teeth, one TU:
//  - wireNameFor() switches over EVERY enumerator with no default, and this
//    file compiles with -Werror=switch — an ErrorCode appended upstream
//    without touching this repo fails the build right here, naming the new
//    enumerator.
//  - the runtime test parses the enumeration out of the XML in the source
//    tree (path injected by CMake, same pattern as TransportCaptureGuardTest)
//    and compares it entry-for-entry with the enum — so the forced follow-up
//    to an enum append is the XML edit, and that visible XML diff is the
//    signal client mirrors react to.
//
// Assumes the taxonomy stays contiguous from 0 (append-only, never renumber,
// no gaps) — the same rule the XML block and the enum header both state.

#include <LibreSCRS/Agent/value/ErrorTaxonomy.h>

#include <gtest/gtest.h>

#include <algorithm>
#include <cstdint>
#include <fstream>
#include <regex>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

namespace {

using LibreSCRS::Agent::ErrorCode;

// Canonical wire name per enumerator. NO default case: with -Werror=switch a
// new enumerator is a compile error until it is named here — and the runtime
// comparison below then fails until the XML enumerates it too.
constexpr const char* wireNameFor(ErrorCode code) noexcept
{
    switch (code) {
    case ErrorCode::None:
        return "None";
    case ErrorCode::CardRemoved:
        return "CardRemoved";
    case ErrorCode::CredentialWrong:
        return "CredentialWrong";
    case ErrorCode::CredentialBlocked:
        return "CredentialBlocked";
    case ErrorCode::CommunicationError:
        return "CommunicationError";
    case ErrorCode::ParseError:
        return "ParseError";
    case ErrorCode::UnsupportedCard:
        return "UnsupportedCard";
    case ErrorCode::AuthFailed:
        return "AuthFailed";
    case ErrorCode::PrompterError:
        return "PrompterError";
    case ErrorCode::CapabilityMissing:
        return "CapabilityMissing";
    case ErrorCode::WatchdogTimeout:
        return "WatchdogTimeout";
    case ErrorCode::KeyNotFound:
        return "KeyNotFound";
    case ErrorCode::KeyAmbiguous:
        return "KeyAmbiguous";
    case ErrorCode::CertExpiredBlocked:
        return "CertExpiredBlocked";
    case ErrorCode::ChainIncomplete:
        return "ChainIncomplete";
    case ErrorCode::TsaUnreachable:
        return "TsaUnreachable";
    case ErrorCode::SigningEngineError:
        return "SigningEngineError";
    case ErrorCode::RateLimited:
        return "RateLimited";
    case ErrorCode::EngineUnavailable:
        return "EngineUnavailable";
    case ErrorCode::InvalidDocument:
        return "InvalidDocument";
    case ErrorCode::EntryExpired:
        return "EntryExpired";
    }
    return nullptr; // not a taxonomy value (used to probe past the end)
}

// Taxonomy size derived from the switch itself (values outside it fall
// through to nullptr), so the count tracks the switch automatically and no
// separate constant can go stale.
constexpr std::uint32_t taxonomyCount() noexcept
{
    std::uint32_t count = 0;
    while (wireNameFor(static_cast<ErrorCode>(count)) != nullptr) {
        ++count;
    }
    return count;
}

constexpr std::uint32_t kTaxonomyCount = taxonomyCount();
static_assert(kTaxonomyCount >= 18u, "the taxonomy is append-only; it can only grow");

std::string slurp(const char* path)
{
    std::ifstream in(path);
    std::stringstream buffer;
    buffer << in.rdbuf();
    return buffer.str();
}

// Extracts the "<value>  <Name> ..." entries of the doc-comment block that
// follows the "Finished.errorCode:" marker — one contiguous run of lines
// starting with a number; the first non-matching line after the run ends it.
std::vector<std::pair<std::uint32_t, std::string>> parseXmlEnumeration(const std::string& xml)
{
    std::vector<std::pair<std::uint32_t, std::string>> entries;
    std::istringstream lines(xml);
    std::string line;
    const std::regex entryRe(R"(^\s*(\d+)\s+([A-Za-z][A-Za-z0-9]*))");
    bool inBlock = false;
    while (std::getline(lines, line)) {
        if (!inBlock) {
            inBlock = line.find("Finished.errorCode:") != std::string::npos;
            continue;
        }
        std::smatch match;
        if (std::regex_search(line, match, entryRe)) {
            entries.emplace_back(static_cast<std::uint32_t>(std::stoul(match[1].str())), match[2].str());
        } else if (!entries.empty()) {
            break;
        }
    }
    return entries;
}

} // namespace

TEST(Operation1ErrorCodeXmlGuard, XmlEnumerationMatchesAgentEnumValueForValue)
{
    const std::string xml = slurp(LIBRELINUX_OPERATION1_XML);
    ASSERT_FALSE(xml.empty()) << "Operation1.xml source path not wired";

    const auto entries = parseXmlEnumeration(xml);
    ASSERT_FALSE(entries.empty()) << "could not locate the Finished.errorCode enumeration in Operation1.xml — "
                                     "if the doc block was reworded, keep the 'Finished.errorCode:' marker and the "
                                     "'<value>  <Name>' entry lines this guard parses";

    EXPECT_EQ(entries.size(), kTaxonomyCount)
        << "Operation1.xml enumerates " << entries.size() << " error codes but the agent ErrorCode enum has "
        << kTaxonomyCount << " — the XML is the canonical wire contract, keep the two identical (append-only)";

    const std::size_t common = std::min<std::size_t>(entries.size(), kTaxonomyCount);
    for (std::size_t i = 0; i < common; ++i) {
        EXPECT_EQ(entries[i].first, static_cast<std::uint32_t>(i))
            << "Operation1.xml errorCode enumeration is not contiguous at entry " << i
            << " — the taxonomy is append-only from 0, never renumbered";
        EXPECT_EQ(entries[i].second, wireNameFor(static_cast<ErrorCode>(i)))
            << "Operation1.xml names errorCode " << i << " '" << entries[i].second << "' but the agent enum calls it '"
            << wireNameFor(static_cast<ErrorCode>(i)) << "'";
    }
}
