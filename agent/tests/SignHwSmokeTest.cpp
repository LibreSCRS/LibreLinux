// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Hardware smoke for the agent's signing core (LmCertificateReader + LmSigner +
// SigningEngineProvider) against real cards. SKIPPED unless LIBRESCRS_HW=1, so
// CI/dev runs without a reader are unaffected.
//
// CREDENTIAL SAFETY: PINs/CAN come ONLY from the
// environment, never hardcoded. A wrong signing PIN decrements an irreversible
// card counter, so the sign phase ABORTS on the first auth failure (g_pinFailed)
// and never retries. Run the PIN-free cert-read phase first to validate plumbing
// before any PIN is presented. Env vars:
//   LIBRESCRS_HW=1                 enable (else every test SKIPs)
//   LIBRESCRS_PLUGIN_DIR=<dir>     LM card plugins (…/lib/librescrs/plugins)
//   LIBRESCRS_PKCS11_MODULE=<so>   the native signing backend's PKCS#11 module
//                                  (…/lib/pkcs11/librescrs-pkcs11.so), unless on
//                                  the loader path
//   LIBRESCRS_CAN / LIBRESCRS_MRZ  PACE channel secret (low-secrecy, no lockout)
//   LIBRESCRS_SIGN_READER=<substr> sign phase only: pick exactly one reader
//   LIBRESCRS_SIGN_PIN=<pin>       sign phase only: that card's signing PIN
// Cert-read phase:  …  --gtest_filter='*CertRead*'   (no SIGN_* needed)
// Sign phase:       …  --gtest_filter='*Sign*'       (after cert-read is clean)
#include <LibreSCRS/Agent/util/Sha256Hex.h>
#include <LibreSCRS/Agent/presence/PluginCapabilityResolver.h>
#include <LibreSCRS/Agent/operations/CardPluginRouting.h>
#include <LibreSCRS/Agent/operations/CardSessionHolder.h>
#include <LibreSCRS/Agent/operations/LmSeams.h>
#include <LibreSCRS/Agent/operations/SignGate.h>
#include <LibreSCRS/Agent/operations/SigningEngineProvider.h>
#include <LibreSCRS/Agent/config/ConfigStore.h>

#include <LibreSCRS/Auth/AuthRequirement.h>
#include <LibreSCRS/Auth/CredentialResult.h>
#include <LibreSCRS/Auth/PaceSecretKind.h>
#include <LibreSCRS/CancelToken.h>
#include <LibreSCRS/Plugin/CardPluginService.h>
#include <LibreSCRS/Secure/String.h>
#include <LibreSCRS/SmartCard/CardSession.h>
#include <LibreSCRS/SmartCard/MonitorService.h>
#include <gtest/gtest.h>

#include <cstdlib>
#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <vector>

using namespace LibreSCRS::Agent;
using namespace LibreSCRS::Agent::Operations;

namespace {

// Irreversible-lockout guard: once a PIN VERIFY fails, never present a PIN again.
bool g_pinFailed = false;
#define SKIP_IF_PIN_FAILED()                                                                                           \
    if (g_pinFailed)                                                                                                   \
    GTEST_SKIP() << "aborted: a prior signing PIN attempt failed (preserving the retry counter)"

std::optional<std::string> env(const char* name)
{
    const char* v = std::getenv(name);
    if (v == nullptr || *v == '\0') {
        return std::nullopt;
    }
    return std::string{v};
}

bool hwEnabled()
{
    return env("LIBRESCRS_HW").has_value();
}

struct LiveCard
{
    std::string readerName;
    std::vector<std::uint8_t> atr;
    std::shared_ptr<LibreSCRS::SmartCard::CardSession> session;
    std::shared_ptr<const LibreSCRS::Plugin::CardPlugin> plugin;
};

std::shared_ptr<LibreSCRS::Plugin::CardPluginService> pluginService()
{
    auto dir = env("LIBRESCRS_PLUGIN_DIR").value_or("/usr/lib/librescrs/plugins");
    return std::make_shared<LibreSCRS::Plugin::CardPluginService>(std::filesystem::path{dir});
}

// Enumerate readers, open each card, resolve its plugin. Never presents a secret.
std::vector<LiveCard> discoverCards(PluginCapabilityResolver& resolver)
{
    std::vector<LiveCard> cards;
    LibreSCRS::SmartCard::MonitorService mon{LibreSCRS::SmartCard::MonitorService::Config::fromEnv()};
    auto readers = mon.listReaders();
    if (!readers) {
        return cards;
    }
    for (const auto& name : *readers) {
        auto opened = LibreSCRS::SmartCard::CardSession::open(name);
        if (!opened) {
            continue; // empty reader / open failure — not a card
        }
        auto session = std::make_shared<LibreSCRS::SmartCard::CardSession>(std::move(*opened));
        const auto atr = session->atr();
        // Resolve candidates on the already-open session (the two-phase ATR +
        // AID-probe lookup) and take the highest-priority match — no extra
        // transient open.
        auto candidates = resolver.resolveCandidates(atr, *session);
        std::shared_ptr<const LibreSCRS::Plugin::CardPlugin> plugin = candidates.empty() ? nullptr : candidates.front();
        cards.push_back(LiveCard{name, atr, std::move(session), std::move(plugin)});
    }
    return cards;
}

// One unified credential provider: env CAN/MRZ for PACE channel establishment,
// env PIN for signing. Field ids match the LM conventions (can/mrz/pin).
LibreSCRS::Auth::CredentialProvider envProvider()
{
    return [](const LibreSCRS::Auth::AuthRequirement& req) -> LibreSCRS::Auth::CredentialResult {
        using namespace LibreSCRS::Auth;
        const int purpose = static_cast<int>(req.purpose());
        const int kind = req.paceKind() ? static_cast<int>(*req.paceKind()) : -1;
        std::fprintf(stderr, "  [provider] requested purpose=%d paceKind=%d fields=%zu\n", purpose, kind,
                     req.fields().size());
        auto ok = [](std::string id, const std::string& secret) {
            std::vector<CredentialEntry> e;
            e.emplace_back(std::move(id), LibreSCRS::Secure::String{secret});
            return CredentialResult::ok(std::move(e));
        };
        if (req.purpose() == Purpose::Signing) {
            if (auto pin = env("LIBRESCRS_SIGN_PIN")) {
                return ok("pin", *pin);
            }
            return CredentialResult::error(LibreSCRS::LocalizedText{});
        }
        if (const auto kind = req.paceKind()) {
            if (*kind == PaceSecretKind::Can) {
                if (auto can = env("LIBRESCRS_CAN")) {
                    return ok("can", *can);
                }
            } else if (*kind == PaceSecretKind::Mrz) {
                if (auto mrz = env("LIBRESCRS_MRZ")) {
                    return ok("mrz", *mrz);
                }
            }
        }
        return CredentialResult::error(LibreSCRS::LocalizedText{});
    };
}

// Per-purpose prompt tallies, observed by the shared-session test after the run.
struct CredCounts
{
    int can = 0; // PACE CAN requests (PaceSecretKind::Can)
    int mrz = 0; // PACE MRZ requests (PaceSecretKind::Mrz)
    int pin = 0; // signing-PIN requests (Purpose::Signing)
};

// A counting wrapper that DELEGATES the env CAN/MRZ/PIN logic of envProvider()
// while tallying each prompt by purpose. Counters are captured by reference so
// the test reads them after the run. Field ids stay can/mrz/pin (LM convention).
LibreSCRS::Auth::CredentialProvider countingProvider(CredCounts& counts)
{
    auto inner = envProvider();
    return [inner, &counts](const LibreSCRS::Auth::AuthRequirement& req) -> LibreSCRS::Auth::CredentialResult {
        using namespace LibreSCRS::Auth;
        if (req.purpose() == Purpose::Signing) {
            ++counts.pin;
        } else if (const auto kind = req.paceKind()) {
            if (*kind == PaceSecretKind::Can) {
                ++counts.can;
            } else if (*kind == PaceSecretKind::Mrz) {
                ++counts.mrz;
            }
        }
        return inner(req);
    };
}

} // namespace

// ---- PROBE: detect candidates without any credential provider (no PACE) ----

TEST(SignHwSmokeCertRead, CandidateDetectionWithoutPace)
{
    if (!hwEnabled()) {
        GTEST_SKIP() << "set LIBRESCRS_HW=1";
    }
    auto svc = pluginService();
    LibreSCRS::SmartCard::MonitorService mon{LibreSCRS::SmartCard::MonitorService::Config::fromEnv()};
    auto readers = mon.listReaders();
    ASSERT_TRUE(readers.has_value());
    for (const auto& name : *readers) {
        auto opened = LibreSCRS::SmartCard::CardSession::open(name);
        if (!opened) {
            continue;
        }
        auto session = std::make_shared<LibreSCRS::SmartCard::CardSession>(std::move(*opened));
        // NO setCredentialProvider — so no CAN is available during probing.
        auto cands = svc->findAllCandidates(session->atr(), *session);
        std::printf("\n[probe-no-pace] reader=%s candidates:", name.c_str());
        bool pki = false;
        for (const auto& c : cands) {
            if (!c) {
                continue;
            }
            std::printf(" %s(caps=0x%x)", c->pluginId().c_str(), static_cast<unsigned>(c->capabilities()));
            if (LibreSCRS::Plugin::hasCapability(c->capabilities(), LibreSCRS::Plugin::CardCapabilities::PKI)) {
                pki = true;
            }
        }
        std::printf("  -> PKI-detected=%d\n", pki ? 1 : 0);
    }
}

// ---- PHASE 1: PIN-free cert read (validates plumbing; no irreversible risk) ----

TEST(SignHwSmokeCertRead, EnumerateAndReadCertificates)
{
    if (!hwEnabled()) {
        GTEST_SKIP() << "set LIBRESCRS_HW=1 (+ LIBRESCRS_PLUGIN_DIR) to run hardware smoke";
    }
    auto svc = pluginService();
    PluginCapabilityResolver resolver{svc};
    auto cards = discoverCards(resolver);
    ASSERT_FALSE(cards.empty()) << "no cards found in any reader";

    int signingCapableTotal = 0;
    for (auto& c : cards) {
        std::printf("\n[card] reader=%s primary-plugin=%s\n", c.readerName.c_str(),
                    c.plugin ? c.plugin->pluginId().c_str() : "NONE");
        c.session->setCredentialProvider(envProvider());
        // Sweep ALL candidate plugins (not just the probe-priority winner) so we
        // see which plugin can actually read this card's PKI certs — a dual-applet
        // card (emrtd + pkcs15) has the passport plugin win the probe while the
        // PKI applet lives behind a different plugin.
        auto candidates = svc->findAllCandidates(c.atr, *c.session);
        std::printf("  %zu candidate plugin(s)\n", candidates.size());
        for (const auto& cand : candidates) {
            if (!cand) {
                continue;
            }
            LmCertificateReader reader{};
            auto out = reader.read(*c.session, CandidateList{cand}, LibreSCRS::CancelToken{});
            std::printf("    plugin=%-10s caps=0x%x preReadAuth=%d -> status=%d certs=%zu %s\n",
                        cand->pluginId().c_str(), static_cast<unsigned>(cand->capabilities()),
                        static_cast<int>(cand->preReadAuth(*c.session)), static_cast<int>(out.status), out.certs.size(),
                        out.status != CertReadOutcome::Status::Ok ? out.msgFallback.c_str() : "");
            for (const auto& cert : out.certs) {
                std::printf("        cert certId=%s signingCapable=%d\n", cert.certId.substr(0, 16).c_str(),
                            cert.signingCapable ? 1 : 0);
                if (cert.signingCapable) {
                    ++signingCapableTotal;
                }
            }
        }
    }
    std::printf("\n[summary] signing-capable certs across all cards: %d\n", signingCapableTotal);
    EXPECT_GT(signingCapableTotal, 0) << "expected at least one signing-capable certificate";
}

// ---- PHASE 2: sign with the env PIN (GUARDED; one attempt; abort on failure) ----

TEST(SignHwSmokeSign, SignFirstSigningCapableCert)
{
    if (!hwEnabled()) {
        GTEST_SKIP() << "set LIBRESCRS_HW=1 to run hardware smoke";
    }
    if (!env("LIBRESCRS_SIGN_PIN")) {
        GTEST_SKIP() << "set LIBRESCRS_SIGN_PIN to attempt a signature (PIN-free cert-read runs without it)";
    }
    SKIP_IF_PIN_FAILED();
    // Target exactly ONE reader (substring match) so a single env PIN is presented
    // to the intended card only — cards have different PINs, and a wrong PIN is
    // irreversible. Required: LIBRESCRS_SIGN_READER.
    const auto target = env("LIBRESCRS_SIGN_READER");
    ASSERT_TRUE(target.has_value()) << "set LIBRESCRS_SIGN_READER (reader-name substring) to pick the card to sign";

    auto svc = pluginService();
    LibreSCRS::SmartCard::MonitorService mon{LibreSCRS::SmartCard::MonitorService::Config::fromEnv()};
    auto readers = mon.listReaders();
    ASSERT_TRUE(readers.has_value());
    std::string readerName;
    for (const auto& r : *readers) {
        if (r.find(*target) != std::string::npos) {
            readerName = r;
            break;
        }
    }
    ASSERT_FALSE(readerName.empty()) << "no reader matches LIBRESCRS_SIGN_READER=" << *target;

    auto opened = LibreSCRS::SmartCard::CardSession::open(readerName);
    ASSERT_TRUE(opened.has_value()) << "open failed: " << (opened ? "" : opened.error().userMessage.defaultText);
    auto session = std::make_shared<LibreSCRS::SmartCard::CardSession>(std::move(*opened));
    session->setCredentialProvider(envProvider());
    const auto atr = session->atr();

    // Pick the candidate plugin that actually exposes a signing-capable cert on
    // THIS card (the probe-priority winner may be the passport plugin on a
    // dual-applet card). findAllCandidates also probes the session into the right
    // applet state for the subsequent sign.
    std::shared_ptr<const LibreSCRS::Plugin::CardPlugin> signPlugin;
    std::optional<std::string> certId;
    for (const auto& cand : svc->findAllCandidates(atr, *session)) {
        if (!cand) {
            continue;
        }
        LmCertificateReader reader{};
        auto certs = reader.read(*session, CandidateList{cand}, LibreSCRS::CancelToken{});
        if (certs.status != CertReadOutcome::Status::Ok) {
            continue;
        }
        for (const auto& cert : certs.certs) {
            if (cert.signingCapable) {
                signPlugin = cand;
                certId = cert.certId;
                break;
            }
        }
        if (signPlugin) {
            break;
        }
    }
    ASSERT_TRUE(signPlugin && certId) << "no signing-capable cert found on reader " << readerName;
    std::printf("\n[sign] reader=%s plugin=%s certId=%s — ONE attempt\n", readerName.c_str(),
                signPlugin->pluginId().c_str(), certId->substr(0, 16).c_str());

    const std::filesystem::path cfgDir = std::filesystem::temp_directory_path() / "librescrs-hw-smoke";
    Config::ConfigStore cfg{cfgDir / "agent.conf", cfgDir / "cache"};
    SigningEngineProvider engine{cfg};

    // B-B CAdES-detached over a tiny buffer — no PDF/container needed.
    SignParams params;
    params.certId = *certId;
    params.inputDocument = {'h', 'w', '-', 's', 'm', 'o', 'k', 'e'};
    params.format = "cades";
    params.level = "b-b";
    params.packaging = "detached";
    params.allowExpired = true; // test cert may be expired; B-B honours consent
    params.displayName = "hw-smoke";

    LmSigner signer{engine};
    auto outcome = signer.sign(session, params, CandidateList{signPlugin}, envProvider(), LibreSCRS::CancelToken{});
    std::printf("  sign status=%d bytes=%zu msg=%s\n", static_cast<int>(outcome.status),
                outcome.signedDocumentBytes.size(), outcome.msgFallback.c_str());

    if (outcome.status == SignOutcome::Status::AuthFailed || outcome.status == SignOutcome::Status::CardBlocked) {
        g_pinFailed = true; // do not present a PIN again this run
        FAIL() << "signing PIN rejected on " << readerName << " — ABORTING (counter preserved)";
    }
    EXPECT_EQ(outcome.status, SignOutcome::Status::Ok) << "sign failed: " << outcome.msgFallback;
    EXPECT_FALSE(outcome.signedDocumentBytes.empty());
}

// ---- PHASE 2b: B-T (single RFC-3161 timestamp) with a real TSA ----
//
// Identical card-handling + irreversible-lockout discipline as the B-B sign,
// but writes a real TSA URL (env LIBRESCRS_TSA_URL) into the ConfigStore so the
// SigningEngineProvider builds a non-empty TsaProvider, then requests level=b-t.
// On success the artifact is a timestamped signature and tsaUsed is the honest
// derived flag. Additionally gated on LIBRESCRS_TSA_URL so it SKIPs everywhere a
// TSA endpoint is not provided. For a DSS oracle, assert the validated
// info.level is *-BASELINE-T (not a bare TOTAL_PASSED) for this artifact.
TEST(SignHwSmokeSign, SignBaselineTWithRealTsa)
{
    if (!hwEnabled()) {
        GTEST_SKIP() << "set LIBRESCRS_HW=1 to run hardware smoke";
    }
    if (!env("LIBRESCRS_SIGN_PIN")) {
        GTEST_SKIP() << "set LIBRESCRS_SIGN_PIN to attempt a signature";
    }
    const auto tsaUrl = env("LIBRESCRS_TSA_URL");
    if (!tsaUrl) {
        GTEST_SKIP() << "set LIBRESCRS_TSA_URL (an RFC-3161 endpoint) to exercise B-T timestamping";
    }
    SKIP_IF_PIN_FAILED();
    const auto target = env("LIBRESCRS_SIGN_READER");
    ASSERT_TRUE(target.has_value()) << "set LIBRESCRS_SIGN_READER (reader-name substring) to pick the card to sign";

    auto svc = pluginService();
    LibreSCRS::SmartCard::MonitorService mon{LibreSCRS::SmartCard::MonitorService::Config::fromEnv()};
    auto readers = mon.listReaders();
    ASSERT_TRUE(readers.has_value());
    std::string readerName;
    for (const auto& r : *readers) {
        if (r.find(*target) != std::string::npos) {
            readerName = r;
            break;
        }
    }
    ASSERT_FALSE(readerName.empty()) << "no reader matches LIBRESCRS_SIGN_READER=" << *target;

    auto opened = LibreSCRS::SmartCard::CardSession::open(readerName);
    ASSERT_TRUE(opened.has_value());
    auto session = std::make_shared<LibreSCRS::SmartCard::CardSession>(std::move(*opened));
    session->setCredentialProvider(envProvider());
    const auto atr = session->atr();

    std::shared_ptr<const LibreSCRS::Plugin::CardPlugin> signPlugin;
    std::optional<std::string> certId;
    for (const auto& cand : svc->findAllCandidates(atr, *session)) {
        if (!cand) {
            continue;
        }
        LmCertificateReader reader{};
        auto certs = reader.read(*session, CandidateList{cand}, LibreSCRS::CancelToken{});
        if (certs.status != CertReadOutcome::Status::Ok) {
            continue;
        }
        for (const auto& cert : certs.certs) {
            if (cert.signingCapable) {
                signPlugin = cand;
                certId = cert.certId;
                break;
            }
        }
        if (signPlugin) {
            break;
        }
    }
    ASSERT_TRUE(signPlugin && certId) << "no signing-capable cert found on reader " << readerName;
    std::printf("\n[sign-bt] reader=%s plugin=%s certId=%s tsa=%s — ONE attempt\n", readerName.c_str(),
                signPlugin->pluginId().c_str(), certId->substr(0, 16).c_str(), tsaUrl->c_str());

    // A real TsaProvider is built only when ConfigStore.TsaUrls is non-empty, so
    // configure the env TSA before constructing the engine.
    const std::filesystem::path cfgDir = std::filesystem::temp_directory_path() / "librescrs-hw-smoke-bt";
    Config::ConfigStore cfg{cfgDir / "agent.conf", cfgDir / "cache"};
    ASSERT_TRUE(cfg.setTsaUrls(std::vector<std::string>{*tsaUrl}).ok);
    SigningEngineProvider engine{cfg};
    ASSERT_FALSE(engine.snapshot().boundTsaUrl.empty()) << "engine must bind the configured TSA URL";

    SignParams params;
    params.certId = *certId;
    params.inputDocument = {'h', 'w', '-', 'b', 't'};
    params.format = "cades";
    params.level = "b-t"; // single RFC-3161 timestamp over the signature
    params.packaging = "detached";
    params.allowExpired = false; // the qualified family hard-blocks an expired cert
    params.displayName = "hw-smoke-bt";

    LmSigner signer{engine};
    auto outcome = signer.sign(session, params, CandidateList{signPlugin}, envProvider(), LibreSCRS::CancelToken{});
    std::printf("  sign-bt status=%d bytes=%zu resolvedLevel=%s tsaUsed=%d msg=%s\n", static_cast<int>(outcome.status),
                outcome.signedDocumentBytes.size(), outcome.resolvedLevel.c_str(), outcome.tsaUsed ? 1 : 0,
                outcome.msgFallback.c_str());

    if (outcome.status == SignOutcome::Status::AuthFailed || outcome.status == SignOutcome::Status::CardBlocked) {
        g_pinFailed = true;
        FAIL() << "signing PIN rejected on " << readerName << " — ABORTING (counter preserved)";
    }
    EXPECT_EQ(outcome.status, SignOutcome::Status::Ok) << "B-T sign failed: " << outcome.msgFallback;
    EXPECT_FALSE(outcome.signedDocumentBytes.empty());
    EXPECT_EQ(outcome.resolvedLevel, "b-t");
    EXPECT_TRUE(outcome.tsaUsed) << "a successful B-T sign with a configured TSA reports tsaUsed";
    // The agent records the bound TSA URL after a successful timestamped sign.
    EXPECT_EQ(cfg.lastTsaUrl(), *tsaUrl);
    // DSS oracle: validate `outcome.signedDocumentBytes` and assert the
    // reported AdES level is *-BASELINE-T (a present, well-formed timestamp), NOT
    // a bare TOTAL_PASSED — a B-B artifact would also pass TOTAL_PASSED.
}

// ---- B-LT: complete the chain from the Trusted List and embed revocation ----
// Like SignBaselineTWithRealTsa, but also writes a Trusted-List source (default
// the canonical mit.gov.rs TL; override via LIBRESCRS_TSL_URL) into the
// ConfigStore so the engine completes the card's leaf-only chain up to the
// issuing CA and embeds revocation. A card whose issuing CA IS in the TL (e.g. a
// real qualified PKS card) produces a B-LT; a TEST card whose CA is absent from
// the TL fails closed (chain incomplete) and SKIPs — that is the designed
// behaviour, not a defect.
TEST(SignHwSmokeSign, SignBaselineLtWithTrustedList)
{
    if (!hwEnabled()) {
        GTEST_SKIP() << "set LIBRESCRS_HW=1 to run hardware smoke";
    }
    if (!env("LIBRESCRS_SIGN_PIN")) {
        GTEST_SKIP() << "set LIBRESCRS_SIGN_PIN to attempt a signature";
    }
    const auto tsaUrl = env("LIBRESCRS_TSA_URL");
    if (!tsaUrl) {
        GTEST_SKIP() << "set LIBRESCRS_TSA_URL (B-LT carries a B-T timestamp)";
    }
    SKIP_IF_PIN_FAILED();
    const auto target = env("LIBRESCRS_SIGN_READER");
    ASSERT_TRUE(target.has_value()) << "set LIBRESCRS_SIGN_READER (reader-name substring) to pick the card to sign";

    auto svc = pluginService();
    LibreSCRS::SmartCard::MonitorService mon{LibreSCRS::SmartCard::MonitorService::Config::fromEnv()};
    auto readers = mon.listReaders();
    ASSERT_TRUE(readers.has_value());
    std::string readerName;
    for (const auto& r : *readers) {
        if (r.find(*target) != std::string::npos) {
            readerName = r;
            break;
        }
    }
    ASSERT_FALSE(readerName.empty()) << "no reader matches LIBRESCRS_SIGN_READER=" << *target;

    auto opened = LibreSCRS::SmartCard::CardSession::open(readerName);
    ASSERT_TRUE(opened.has_value());
    auto session = std::make_shared<LibreSCRS::SmartCard::CardSession>(std::move(*opened));
    session->setCredentialProvider(envProvider());
    const auto atr = session->atr();

    std::shared_ptr<const LibreSCRS::Plugin::CardPlugin> signPlugin;
    std::optional<std::string> certId;
    for (const auto& cand : svc->findAllCandidates(atr, *session)) {
        if (!cand) {
            continue;
        }
        LmCertificateReader reader{};
        auto certs = reader.read(*session, CandidateList{cand}, LibreSCRS::CancelToken{});
        if (certs.status != CertReadOutcome::Status::Ok) {
            continue;
        }
        for (const auto& cert : certs.certs) {
            if (cert.signingCapable) {
                signPlugin = cand;
                certId = cert.certId;
                break;
            }
        }
        if (signPlugin) {
            break;
        }
    }
    ASSERT_TRUE(signPlugin && certId) << "no signing-capable cert found on reader " << readerName;

    const std::string tlUrl = env("LIBRESCRS_TSL_URL").value_or("https://www.mit.gov.rs/TrustedList/TSL-RS.xml");
    std::printf("\n[sign-blt] reader=%s plugin=%s certId=%s tsa=%s tl=%s — ONE attempt\n", readerName.c_str(),
                signPlugin->pluginId().c_str(), certId->substr(0, 16).c_str(), tsaUrl->c_str(), tlUrl.c_str());

    const std::filesystem::path cfgDir = std::filesystem::temp_directory_path() / "librescrs-hw-smoke-blt";
    Config::ConfigStore cfg{cfgDir / "agent.conf", cfgDir / "cache"};
    ASSERT_TRUE(cfg.setTsaUrls(std::vector<std::string>{*tsaUrl}).ok);
    Config::TslSource tl;
    tl.url = tlUrl;
    tl.isLotl = false;
    tl.eager = true;
    ASSERT_TRUE(cfg.setTslSources(std::vector<Config::TslSource>{tl}).ok);
    SigningEngineProvider engine{cfg};

    SignParams params;
    params.certId = *certId;
    params.inputDocument = {'h', 'w', '-', 'b', 'l', 't'};
    params.format = "cades";
    params.level = "b-lt"; // timestamp + completed chain + embedded revocation
    params.packaging = "detached";
    params.allowExpired = false;
    params.displayName = "hw-smoke-blt";

    LmSigner signer{engine};
    auto outcome = signer.sign(session, params, CandidateList{signPlugin}, envProvider(), LibreSCRS::CancelToken{});
    std::printf("  sign-blt status=%d bytes=%zu resolvedLevel=%s msg=%s\n", static_cast<int>(outcome.status),
                outcome.signedDocumentBytes.size(), outcome.resolvedLevel.c_str(), outcome.msgFallback.c_str());

    if (outcome.status == SignOutcome::Status::AuthFailed || outcome.status == SignOutcome::Status::CardBlocked) {
        g_pinFailed = true;
        FAIL() << "signing PIN rejected on " << readerName << " — ABORTING (counter preserved)";
    }
    if (outcome.status != SignOutcome::Status::Ok) {
        // Fail-closed: the card's issuing CA is not in the configured TL, or the
        // leaf's revocation was unreachable. Correct for a test card; not a defect.
        GTEST_SKIP() << "B-LT not produced (fail-closed / network): " << outcome.msgFallback;
    }
    EXPECT_FALSE(outcome.signedDocumentBytes.empty());
    EXPECT_EQ(outcome.resolvedLevel, "b-lt");
    // DSS oracle: validate `outcome.signedDocumentBytes` and assert the
    // reported AdES level is *-BASELINE-LT (completed chain + revocation present).
}

// ---- B-T expired-cert HARD BLOCK: never timestamps an expired signer ----
//
// A qualified-family (b-t) request over an EXPIRED signing cert must be blocked
// BEFORE any PIN is presented, even with allowExpired=true (the timestamped
// family ignores it). PIN-free by construction (the gate fires first), so this
// carries no irreversible-lockout risk and needs no SIGN_PIN. Requires a card
// whose signing cert is expired; SKIPs unless explicitly opted in via
// LIBRESCRS_EXPIRED_SIGN_READER so it never fires against a valid card.
TEST(SignHwSmokeSign, SignBaselineTExpiredCertIsHardBlockedBeforePin)
{
    if (!hwEnabled()) {
        GTEST_SKIP() << "set LIBRESCRS_HW=1 to run hardware smoke";
    }
    const auto target = env("LIBRESCRS_EXPIRED_SIGN_READER");
    if (!target) {
        GTEST_SKIP() << "set LIBRESCRS_EXPIRED_SIGN_READER (a card with an EXPIRED signing cert) to exercise the "
                        "B-T expired hard-block";
    }
    const auto tsaUrl = env("LIBRESCRS_TSA_URL");
    if (!tsaUrl) {
        GTEST_SKIP() << "set LIBRESCRS_TSA_URL to build a real TsaProvider for the B-T expired hard-block";
    }

    auto svc = pluginService();
    LibreSCRS::SmartCard::MonitorService mon{LibreSCRS::SmartCard::MonitorService::Config::fromEnv()};
    auto readers = mon.listReaders();
    ASSERT_TRUE(readers.has_value());
    std::string readerName;
    for (const auto& r : *readers) {
        if (r.find(*target) != std::string::npos) {
            readerName = r;
            break;
        }
    }
    ASSERT_FALSE(readerName.empty()) << "no reader matches LIBRESCRS_EXPIRED_SIGN_READER=" << *target;

    auto opened = LibreSCRS::SmartCard::CardSession::open(readerName);
    ASSERT_TRUE(opened.has_value());
    auto session = std::make_shared<LibreSCRS::SmartCard::CardSession>(std::move(*opened));
    session->setCredentialProvider(envProvider());
    const auto atr = session->atr();

    std::shared_ptr<const LibreSCRS::Plugin::CardPlugin> signPlugin;
    std::optional<std::string> certId;
    for (const auto& cand : svc->findAllCandidates(atr, *session)) {
        if (!cand) {
            continue;
        }
        LmCertificateReader reader{};
        auto certs = reader.read(*session, CandidateList{cand}, LibreSCRS::CancelToken{});
        if (certs.status != CertReadOutcome::Status::Ok) {
            continue;
        }
        for (const auto& cert : certs.certs) {
            if (cert.signingCapable) {
                signPlugin = cand;
                certId = cert.certId;
                break;
            }
        }
        if (signPlugin) {
            break;
        }
    }
    ASSERT_TRUE(signPlugin && certId) << "no signing-capable cert found on reader " << readerName;

    const std::filesystem::path cfgDir = std::filesystem::temp_directory_path() / "librescrs-hw-smoke-bt-expired";
    Config::ConfigStore cfg{cfgDir / "agent.conf", cfgDir / "cache"};
    ASSERT_TRUE(cfg.setTsaUrls(std::vector<std::string>{*tsaUrl}).ok);
    SigningEngineProvider engine{cfg};

    SignParams params;
    params.certId = *certId;
    params.inputDocument = {'h', 'w', '-', 'b', 't', '-', 'x'};
    params.format = "cades";
    params.level = "b-t";
    params.packaging = "detached";
    params.allowExpired = true; // the qualified family must IGNORE this
    params.displayName = "hw-smoke-bt-expired";

    LmSigner signer{engine};
    auto outcome = signer.sign(session, params, CandidateList{signPlugin}, envProvider(), LibreSCRS::CancelToken{});
    std::printf("\n[sign-bt-expired] reader=%s status=%d msg=%s\n", readerName.c_str(),
                static_cast<int>(outcome.status), outcome.msgFallback.c_str());
    // Hard block BEFORE any PIN: a wrong PIN was never presented (no lockout risk).
    EXPECT_EQ(outcome.status, SignOutcome::Status::CertExpiredBlocked)
        << "a b-t sign over an expired cert must be hard-blocked, never timestamped";
    EXPECT_TRUE(outcome.signedDocumentBytes.empty());
    EXPECT_FALSE(outcome.tsaUsed);
}

// ---- ONE-SESSION MULTI-APPLET: shared PACE across identity + cert + sign ----
//
// The per-reader CardSessionHolder keeps ONE CardSession open across every
// operation, so a contactless PACE channel is established exactly ONCE — not
// per op. This drives ReadIdentity -> ReadCertificates -> Sign on a single
// holder (built EXACTLY like production OperationManager::workerFor) and counts
// how many times the credential provider is asked for the PACE CAN. Re-opening
// the channel per op would bump the count; the shared session must not.
//
// The PIN-free part (identity + cert read) validates the shared-PACE property
// with NO irreversible risk, so the controller can run it without a PIN first.
// The sign step is gated on LIBRESCRS_SIGN_PIN and honours the irreversible-
// lockout guard exactly like SignFirstSigningCapableCert.
TEST(SignHwSmokeSign, OneSessionMultiOpSharedPace)
{
    if (!hwEnabled()) {
        GTEST_SKIP() << "set LIBRESCRS_HW=1 to run hardware smoke";
    }
    // Target exactly ONE reader so a (possible) signing PIN reaches only the
    // intended card — a wrong PIN is irreversible.
    const auto target = env("LIBRESCRS_SIGN_READER");
    ASSERT_TRUE(target.has_value()) << "set LIBRESCRS_SIGN_READER (reader-name substring) to pick the card";
    SKIP_IF_PIN_FAILED();

    LibreSCRS::SmartCard::MonitorService mon{LibreSCRS::SmartCard::MonitorService::Config::fromEnv()};
    auto readers = mon.listReaders();
    ASSERT_TRUE(readers.has_value());
    std::string readerName;
    for (const auto& r : *readers) {
        if (r.find(*target) != std::string::npos) {
            readerName = r;
            break;
        }
    }
    ASSERT_FALSE(readerName.empty()) << "no reader matches LIBRESCRS_SIGN_READER=" << *target;

    // Build the production-style holder for this reader: the SAME SessionFactory
    // (CardSession::open -> shared_ptr), CandidateResolver (forwards to the
    // plugin resolver's resolveCandidates), and a fresh CardMap that
    // OperationManager::workerFor uses. This exercises the REAL holder, so the
    // open-once / resolve-once semantics under test are the production ones.
    PluginCapabilityResolver resolver{pluginService()};
    SessionFactory factory = [](const std::string& r)
        -> std::expected<std::shared_ptr<LibreSCRS::SmartCard::CardSession>, LibreSCRS::SmartCard::OpenError> {
        auto opened = LibreSCRS::SmartCard::CardSession::open(r);
        if (!opened) {
            return std::unexpected{opened.error()};
        }
        return std::make_shared<LibreSCRS::SmartCard::CardSession>(std::move(*opened));
    };
    CandidateResolver candResolver = [&resolver](std::span<const std::uint8_t> atr,
                                                 LibreSCRS::SmartCard::CardSession& s) -> CandidateList {
        return resolver.resolveCandidates(atr, s);
    };
    CardSessionHolder holder{readerName, std::move(factory), std::move(candResolver),
                             std::make_shared<LibreSCRS::SmartCard::CardMap>()};

    auto acq = holder.acquire();
    ASSERT_TRUE(acq.has_value()) << "holder.acquire failed on " << readerName;

    // Install the COUNTING provider on the SHARED session BEFORE the first op so
    // any CAN prompt during identity / cert reads (the readers trigger PACE via
    // the session's provider) is counted. The signer is also handed this same
    // provider so a signing-PIN prompt is tallied on the pin counter.
    CredCounts counts;
    acq->session->setCredentialProvider(countingProvider(counts));

    // --- Op 1: identity (no assert — a PKI-only card has no identity applet) ---
    LmCardReader idReader{};
    auto idOut = idReader.read(*acq->session, identityCandidates(acq->candidates), LibreSCRS::CancelToken{});
    std::printf("\n[shared] reader=%s op1-identity status=%d\n", readerName.c_str(), static_cast<int>(idOut.status));

    // --- Op 2: cert read (must find a signing-capable cert on the SAME session) ---
    LmCertificateReader certReader{};
    auto certOut = certReader.read(*acq->session, pkiCandidates(acq->candidates), LibreSCRS::CancelToken{});
    std::optional<std::string> certId;
    for (const auto& cert : certOut.certs) {
        if (cert.signingCapable) {
            certId = cert.certId;
            break;
        }
    }
    std::printf("[shared] op2-certread status=%d certs=%zu signing-capable=%d\n", static_cast<int>(certOut.status),
                certOut.certs.size(), certId ? 1 : 0);
    ASSERT_TRUE(certId.has_value()) << "no signing-capable cert on reader " << readerName;

    // --- Op 3: sign (PIN-gated; one attempt; abort on auth failure) ---
    SignOutcome signOut;
    bool signAttempted = false;
    if (env("LIBRESCRS_SIGN_PIN") && !g_pinFailed) {
        signAttempted = true;
        const std::filesystem::path cfgDir = std::filesystem::temp_directory_path() / "librescrs-hw-smoke";
        Config::ConfigStore cfg{cfgDir / "agent.conf", cfgDir / "cache"};
        SigningEngineProvider engine{cfg};

        SignParams params;
        params.certId = *certId;
        params.inputDocument = {'h', 'w', '-', 's', 'm', 'o', 'k', 'e'};
        params.format = "cades";
        params.level = "b-b";
        params.packaging = "detached";
        params.allowExpired = true;
        params.displayName = "hw-smoke-shared";

        LmSigner signer{engine};
        signOut = signer.sign(acq->session, params, signingCandidates(acq->candidates), countingProvider(counts),
                              LibreSCRS::CancelToken{});
        std::printf("[shared] op3-sign status=%d bytes=%zu msg=%s\n", static_cast<int>(signOut.status),
                    signOut.signedDocumentBytes.size(), signOut.msgFallback.c_str());
        if (signOut.status == SignOutcome::Status::AuthFailed || signOut.status == SignOutcome::Status::CardBlocked) {
            g_pinFailed = true; // never present this PIN again this run
            std::printf("[shared] counts: can=%d mrz=%d pin=%d\n", counts.can, counts.mrz, counts.pin);
            FAIL() << "signing PIN rejected on " << readerName << " — ABORTING (counter preserved)";
        }
        EXPECT_EQ(signOut.status, SignOutcome::Status::Ok) << "sign failed: " << signOut.msgFallback;
        EXPECT_FALSE(signOut.signedDocumentBytes.empty());
    } else {
        std::printf("[shared] op3-sign SKIPPED (LIBRESCRS_SIGN_PIN unset) — shared-PACE property still asserted\n");
    }

    // --- The key assertions (hold in BOTH the PIN-free and the full run) ---
    std::printf("[shared] counts: can=%d mrz=%d pin=%d (sign-attempted=%d)\n", counts.can, counts.mrz, counts.pin,
                signAttempted ? 1 : 0);
    // PACE is established at most ONCE across all three ops because the holder
    // keeps ONE CardSession open. <=1 (not ==1) because a contact card needing
    // no PACE never prompts for a CAN (count 0); a contactless PACE card needs
    // it exactly once. Either way the count must never grow per op.
    EXPECT_LE(counts.can, 1) << "PACE CAN prompted more than once — the shared session re-established PACE per op";
}
