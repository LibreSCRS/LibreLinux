// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#include "trust/CscaAnchorImport.h"

#include <LibreSCRS/Certificate/ParsedCertificate.h>
#include <LibreSCRS/Trust/CscaMasterList.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <iterator>
#include <set>
#include <system_error>
#include <utility>

namespace LibreSCRS::Agent::Trust {
namespace {

namespace fs = std::filesystem;
namespace lm = LibreSCRS::Trust;

constexpr const char* kAnchorsDirName = "anchors";
constexpr const char* kAnchorsStagingName = "anchors.incoming";
constexpr const char* kStateFileName = "state";
constexpr const char* kAnchorSuffix = ".cer";

ImportRefusal refusalFor(lm::MasterListError e) noexcept
{
    switch (e) {
    case lm::MasterListError::NotAMasterList:
        return ImportRefusal::NotAMasterList;
    case lm::MasterListError::Empty:
        return ImportRefusal::Empty;
    case lm::MasterListError::Malformed:
        return ImportRefusal::Malformed;
    case lm::MasterListError::BadSignature:
        return ImportRefusal::BadSignature;
    case lm::MasterListError::SignerMismatch:
        return ImportRefusal::SignerChanged;
    }
    return ImportRefusal::NotAMasterList;
}

// Distinct issuing countries among @p anchors, by the SUBJECT's country
// attribute — an anchor is a country's own authority, so its subject is who it
// belongs to. An anchor that does not parse, or that carries no country, shares
// the empty bucket rather than inventing an issuer of its own; over-counting
// here would tell a person their store covers more countries than it does.
std::uint32_t countIssuers(const std::vector<std::vector<std::uint8_t>>& anchors)
{
    std::set<std::string> countries;
    for (const auto& der : anchors) {
        auto parsed = Certificate::ParsedCertificate::fromDer(der);
        countries.insert(parsed ? parsed->subject().country() : std::string{});
    }
    return static_cast<std::uint32_t>(countries.size());
}

std::optional<std::vector<std::uint8_t>> readFile(const fs::path& path)
{
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        return std::nullopt;
    }
    return std::vector<std::uint8_t>(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
}

bool writeFile(const fs::path& path, const std::vector<std::uint8_t>& bytes)
{
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out) {
        return false;
    }
    if (!bytes.empty()) {
        out.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    }
    out.close();
    return out.good();
}

// A whole decimal integer, or nothing. Deliberately strict: strtoll answers 0
// for text that is not a number at all, and a state file whose date read as
// "the epoch" would silently refuse every list a publisher has ever signed.
std::optional<std::int64_t> wholeInteger(const std::string& value)
{
    const std::size_t first = (!value.empty() && value.front() == '-') ? 1 : 0;
    if (value.size() == first) {
        return std::nullopt;
    }
    for (std::size_t i = first; i < value.size(); ++i) {
        if (value[i] < '0' || value[i] > '9') {
            return std::nullopt;
        }
    }
    errno = 0;
    char* end = nullptr;
    const long long parsed = std::strtoll(value.c_str(), &end, 10);
    if (errno == ERANGE || end != value.c_str() + value.size()) {
        return std::nullopt;
    }
    return static_cast<std::int64_t>(parsed);
}

std::optional<SignerFingerprint> fingerprintFromHex(std::string_view hex)
{
    if (hex.size() != kSignerFingerprintSize * 2) {
        return std::nullopt;
    }
    SignerFingerprint out{};
    for (std::size_t i = 0; i < kSignerFingerprintSize; ++i) {
        int value = 0;
        for (std::size_t nibble = 0; nibble < 2; ++nibble) {
            const char c = hex[i * 2 + nibble];
            int digit = 0;
            if (c >= '0' && c <= '9') {
                digit = c - '0';
            } else if (c >= 'a' && c <= 'f') {
                digit = c - 'a' + 10;
            } else {
                return std::nullopt;
            }
            value = value * 16 + digit;
        }
        out[i] = static_cast<std::uint8_t>(value);
    }
    return out;
}

} // namespace

std::string toHex(const SignerFingerprint& fingerprint)
{
    static constexpr char kDigits[] = "0123456789abcdef";
    std::string out;
    out.reserve(fingerprint.size() * 2);
    for (std::uint8_t b : fingerprint) {
        out.push_back(kDigits[b >> 4]);
        out.push_back(kDigits[b & 0x0F]);
    }
    return out;
}

AnchorCache::AnchorCache(fs::path dir) : m_dir(std::move(dir)) {}

AnchorState AnchorCache::state() const
{
    AnchorState out;
    std::ifstream in(m_dir / kStateFileName);
    if (!in) {
        return out; // no cache yet, or unreadable: the agent believes nothing
    }
    std::optional<SignerFingerprint> signer;
    bool signedAtUnreadable = false;
    std::string line;
    while (std::getline(in, line)) {
        const auto eq = line.find('=');
        if (eq == std::string::npos) {
            continue;
        }
        const std::string key = line.substr(0, eq);
        const std::string value = line.substr(eq + 1);
        if (key == "signer") {
            signer = fingerprintFromHex(value);
        } else if (key == "signerPinned") {
            out.signerPinned = (value == "1");
        } else if (key == "anchors") {
            out.anchorCount = static_cast<std::uint32_t>(std::strtoul(value.c_str(), nullptr, 10));
        } else if (key == "issuers") {
            out.issuerCount = static_cast<std::uint32_t>(std::strtoul(value.c_str(), nullptr, 10));
        } else if (key == "acceptedAt") {
            out.acceptedAt = static_cast<std::int64_t>(std::strtoll(value.c_str(), nullptr, 10));
        } else if (key == "signedAt") {
            // Written only when the accepted list carried a date, so ABSENT and
            // UNREADABLE are different situations and only the first is normal.
            out.signedAt = wholeInteger(value);
            signedAtUnreadable = !out.signedAt.has_value();
        } else if (key == "origin") {
            out.origin = value;
        }
    }
    // A state file without a readable signer establishes nothing, so it is read
    // as no state at all rather than as a pin of all-zero bytes — which every
    // list would then fail to match, wedging the agent on a corrupt file.
    //
    // A date that is PRESENT and unreadable is treated the same way, and for the
    // opposite reason: reading it as absent would quietly turn replay refusal
    // off, so a corrupt file would be a way to strip the protection. Asking for
    // the list again is the cheap end of that trade.
    if (!signer || signedAtUnreadable) {
        return AnchorState{};
    }
    out.signer = *signer;
    out.present = true;
    return out;
}

std::vector<std::vector<std::uint8_t>> AnchorCache::anchors() const
{
    std::vector<fs::path> files;
    std::error_code ec;
    for (const auto& entry : fs::directory_iterator(m_dir / kAnchorsDirName, ec)) {
        if (entry.is_regular_file(ec) && entry.path().extension() == kAnchorSuffix) {
            files.push_back(entry.path());
        }
    }
    // directory_iterator order is unspecified; the stored order is the list's
    // own, and it is the file names that carry it.
    std::sort(files.begin(), files.end());

    std::vector<std::vector<std::uint8_t>> out;
    out.reserve(files.size());
    for (const auto& file : files) {
        if (auto bytes = readFile(file)) {
            out.push_back(std::move(*bytes));
        }
    }
    return out;
}

bool AnchorCache::holdsAnchor() const
{
    std::error_code ec;
    // Constructed with an error_code, so a directory that is absent or cannot
    // be read yields nothing rather than throwing — and reads as "holds no
    // anchor", which is what the caller has to act on either way.
    for (const auto& entry : fs::directory_iterator(m_dir / kAnchorsDirName, ec)) {
        if (entry.is_regular_file(ec) && entry.path().extension() == kAnchorSuffix) {
            return true;
        }
    }
    return false;
}

bool AnchorCache::replace(const std::vector<std::vector<std::uint8_t>>& anchors, const AnchorState& state)
{
    std::error_code ec;
    const fs::path staging = m_dir / kAnchorsStagingName;
    const fs::path live = m_dir / kAnchorsDirName;

    fs::create_directories(m_dir, ec);
    if (ec) {
        return false;
    }
    fs::remove_all(staging, ec);
    if (ec || !fs::create_directory(staging, ec) || ec) {
        return false;
    }

    // Everything is written into a staging directory first, so a failure part
    // way through cannot leave a half-replaced trust store live.
    for (std::size_t i = 0; i < anchors.size(); ++i) {
        char name[32];
        std::snprintf(name, sizeof(name), "%06zu%s", i, kAnchorSuffix);
        if (!writeFile(staging / name, anchors[i])) {
            fs::remove_all(staging, ec);
            return false;
        }
    }

    fs::remove_all(live, ec);
    if (ec) {
        fs::remove_all(staging, ec);
        return false;
    }
    fs::rename(staging, live, ec);
    if (ec) {
        fs::remove_all(staging, ec);
        return false;
    }

    // The state file is written LAST. Until it lands the agent believes
    // nothing, which is the safe way for a torn import to end: better to have
    // to import again than to follow a signer whose anchors never arrived.
    std::string text;
    text += "signer=" + toHex(state.signer) + "\n";
    text += std::string{"signerPinned="} + (state.signerPinned ? "1" : "0") + "\n";
    text += "anchors=" + std::to_string(state.anchorCount) + "\n";
    text += "issuers=" + std::to_string(state.issuerCount) + "\n";
    text += "acceptedAt=" + std::to_string(state.acceptedAt) + "\n";
    if (state.signedAt) {
        // Omitted, never written as a sentinel: a list that carries no date and
        // one signed at the epoch must not read back the same.
        text += "signedAt=" + std::to_string(*state.signedAt) + "\n";
    }
    text += "origin=" + state.origin + "\n";
    const std::vector<std::uint8_t> bytes(text.begin(), text.end());
    return writeFile(m_dir / kStateFileName, bytes);
}

std::expected<AnchorState, Refusal> importMasterList(const std::vector<std::uint8_t>& der, AnchorCache& cache,
                                                     std::int64_t now)
{
    const AnchorState prior = cache.state();

    // Store the verified list and answer with what was established. Reads the
    // anchor count from what the list CARRIED, unfiltered.
    //
    // @p identityEstablished is passed rather than read off the verified list
    // because the two ways this agent can establish a signer are not the same
    // question the facade answers. It matched the pin, OR it chains to an anchor
    // already trusted; the facade only knows about the first.
    // Whether @p incoming may replace what has already been accepted, on the
    // ground of WHEN it was signed. The rule, one line per case:
    //
    //   accepted   incoming   outcome
    //   dated      dated      accept only if STRICTLY newer
    //   dated      undated    REFUSE
    //   undated    dated      accept
    //   undated    undated    accept
    //
    // Row two is the asymmetric one and it is the whole point. signingTime is
    // OPTIONAL in CMS, so refusing every undated list would turn the feature off
    // for a publisher that does not date its lists — while letting an undated
    // list replace a dated one would hand an attacker a way to STRIP a
    // protection this installation already had, and every later rollback with
    // it. So: never refuse for a property the ecosystem may not provide, and
    // never let one be taken away.
    //
    // Strictly newer, not merely not-older. Two lists signed at the same instant
    // are the same statement as far as anything here can tell, and re-installing
    // one buys nothing that would justify accepting an attacker's copy.
    const auto replayRefusal = [&](const lm::VerifiedMasterList& incoming) -> std::optional<Refusal> {
        if (!prior.present || !prior.signedAt) {
            return std::nullopt;
        }
        const std::optional<std::int64_t> offered = incoming.signingTimeEpochSeconds;
        if (offered && *offered > *prior.signedAt) {
            return std::nullopt;
        }
        return Refusal{ImportRefusal::Replayed, std::nullopt, prior.signer, offered, prior.signedAt};
    };

    const auto accept = [&](const lm::VerifiedMasterList& verified,
                            bool identityEstablished) -> std::expected<AnchorState, Refusal> {
        // Applied here rather than at each call site so that no way of reaching
        // an acceptance — first import, same signer, lawful rotation — can skip
        // it. On a first import there is nothing to compare against and it
        // stands aside.
        if (auto refusal = replayRefusal(verified)) {
            return std::unexpected(*refusal);
        }
        AnchorState next;
        next.present = true;
        next.signer = verified.signerSpkiSha256;
        next.signerPinned = identityEstablished;
        next.anchorCount = static_cast<std::uint32_t>(verified.anchors.size());
        next.issuerCount = countIssuers(verified.anchors);
        next.acceptedAt = now;
        next.signedAt = verified.signingTimeEpochSeconds;
        next.origin = "import";
        if (!cache.replace(verified.anchors, next)) {
            return std::unexpected(Refusal{ImportRefusal::CacheNotWritable, verified.signerSpkiSha256,
                                           prior.present ? std::optional{prior.signer} : std::nullopt, std::nullopt,
                                           std::nullopt});
        }
        return next;
    };

    if (!prior.present) {
        // Trust on first import: there is nothing to check a first list against,
        // so whoever signed it becomes the pin and signerPinned records that
        // nothing was compared.
        auto verified = lm::parseAndVerifyMasterList(der, nullptr);
        if (!verified) {
            return std::unexpected(
                Refusal{refusalFor(verified.error()), std::nullopt, std::nullopt, std::nullopt, std::nullopt});
        }
        return accept(*verified, false);
    }

    // Pinned. The ordinary case: the publisher the agent already follows.
    auto verified = lm::parseAndVerifyMasterList(der, &prior.signer);
    if (verified) {
        return accept(*verified, true);
    }
    if (verified.error() != lm::MasterListError::SignerMismatch) {
        return std::unexpected(
            Refusal{refusalFor(verified.error()), std::nullopt, prior.signer, std::nullopt, std::nullopt});
    }

    // The signer changed. Verify once more without the pin, which names the key
    // that actually signed it and hands back that key's certificate.
    auto unpinned = lm::parseAndVerifyMasterList(der, nullptr);
    if (!unpinned) {
        return std::unexpected(
            Refusal{ImportRefusal::SignerChanged, std::nullopt, prior.signer, std::nullopt, std::nullopt});
    }

    // The rotation rule. A publisher that has rotated its key is followed
    // automatically when the certificate that SIGNED this list chains to an
    // anchor the previously accepted list carried.
    //
    // The certificate is the one the verification resolved, so "it signed this
    // list" needs no separate proof — that is what made it the signer. Handing
    // the path build some other certificate that merely chains would let a
    // stranger ride in behind any certificate the authority ever issued.
    //
    // The anchors handed to the path build are read from the cache — the list
    // ALREADY TRUSTED — before anything is replaced. Judging the new signer
    // against anchors carried by the list being imported would be circular: an
    // attacker signs a list of his own anchors with a key he issued from one of
    // them, and it comes out internally consistent every time.
    if (lm::signerChainsToAnyAnchor(unpinned->signerCertDer, cache.anchors())) {
        return accept(*unpinned, true);
    }

    return std::unexpected(
        Refusal{ImportRefusal::SignerChanged, unpinned->signerSpkiSha256, prior.signer, std::nullopt, std::nullopt});
}

} // namespace LibreSCRS::Agent::Trust
