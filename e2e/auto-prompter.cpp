// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// AUTONOMOUS TEST HARNESS — NOT part of the shipped product, not a CMake
// target. CI compiles it via e2e/build.sh but never runs it.
//
// Headless auto-prompter: implements org.librescrs.Prompter1 so a through-the-
// agent hardware smoke run needs NO human at the pinentry dialog. It answers
// RequestSecret(kind) — and RequestSecrets(kind) for the two-secret change_pin
// flow — from env-provided secrets and returns them in a sealed memfd
// (SCM_RIGHTS), exactly like the real KDE prompter, but only when a physical
// GATE FILE exists, so a PIN can never be released by accident.
//
// It REUSES the tree's own sealed-memfd creator (common/SealedMemfdCreator.h)
// and the generated Prompter1 adaptor, so the seal set it produces is byte-for-
// byte identical to the real prompter's and satisfies the agent's
// SecretMemfdReader contract.
//
// SAFETY: never logs secret bytes; fail-closed (cancelled) when the gate is
// absent or the env var for the requested kind is unset.

#include "org.librescrs.Prompter1_adaptor.h" // generated (build/*/generated)

#include "PrompterWire.h"       // LibreLinux::PrompterWire kind/status vocab
#include "SealedMemfdCreator.h" // LibreLinux::Common::makeSealedMemfd

#include <sdbus-c++/AdaptorInterfaces.h>
#include <sdbus-c++/IConnection.h>
#include <sdbus-c++/Types.h>

#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <pthread.h>
#include <span>
#include <string>
#include <string_view>
#include <tuple>
#include <unistd.h>
#include <vector>

namespace {

constexpr const char* kServiceName = "org.librescrs.Prompter1";
constexpr const char* kObjectPath = "/org/librescrs/Prompter1";
constexpr const char* kDefaultGate = "/tmp/librescrs-e2e/prompt.gate";

namespace wire = LibreLinux::PrompterWire;

std::string gatePath()
{
    const char* g = std::getenv("LIBRESCRS_PROMPTER_GATE");
    return (g && *g) ? std::string{g} : std::string{kDefaultGate};
}

bool gateOpen()
{
    return ::access(gatePath().c_str(), F_OK) == 0;
}

// Env var backing each secret kind. Unknown kind -> nullptr (fail-closed).
const char* envKeyFor(std::string_view kind)
{
    if (kind == wire::kKindPin) {
        return "LIBRESCRS_SIGN_PIN";
    }
    if (kind == wire::kKindCan) {
        return "LIBRESCRS_CAN";
    }
    if (kind == wire::kKindMrz) {
        return "LIBRESCRS_MRZ";
    }
    return nullptr;
}

// Does the request's alternative-kind option name @p kind? A missing or
// mistyped entry reads as "not offered" — the same treated-as-absent tolerance
// the real prompter's option lifts have.
bool altKindsOffer(const std::map<std::string, sdbus::Variant>& options, std::string_view kind)
{
    const auto it = options.find(wire::kOptAltKinds);
    if (it == options.end()) {
        return false;
    }
    try {
        for (const auto& offered : it->second.get<std::vector<std::string>>()) {
            if (offered == kind) {
                return true;
            }
        }
    } catch (const sdbus::Error&) {
        return false;
    }
    return false;
}

// Does this run want the harness to take an offered switch to the MRZ form?
// A run that does not say so explicitly behaves byte-for-byte as before, so
// every existing leg keeps answering the requested kind.
bool mrzSwitchRequested()
{
    const char* v = std::getenv("LIBRESCRS_FORCE_MRZ");
    return v != nullptr && std::string_view{v} == "1";
}

// A sealed memfd built via the SAME shared creator the real prompter uses:
// F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE, SEAL_SEAL omitted. Never logs
// bytes. Empty span -> a valid 0-byte sealed fd (the cancellation carrier).
int sealedFd(std::string_view bytes)
{
    return LibreLinux::Common::makeSealedMemfd(
        "librescrs-e2e-secret",
        std::span<const std::uint8_t>{reinterpret_cast<const std::uint8_t*>(bytes.data()), bytes.size()});
}

// stderr log — kind + whether answered ONLY, never the secret itself.
void logDecision(std::string_view kind, bool answered, const char* reason)
{
    std::fprintf(stderr, "[auto-prompter] RequestSecret kind=%.*s answered=%s%s%s\n", static_cast<int>(kind.size()),
                 kind.data(), answered ? "yes" : "no", reason ? " reason=" : "", reason ? reason : "");
}

class AutoPrompter final : public sdbus::AdaptorInterfaces<org::librescrs::Prompter1_adaptor>
{
public:
    AutoPrompter(sdbus::IConnection& connection, sdbus::ObjectPath path)
        : AdaptorInterfaces(connection, std::move(path))
    {
        registerAdaptor();
    }
    ~AutoPrompter()
    {
        unregisterAdaptor();
    }

    AutoPrompter(const AutoPrompter&) = delete;
    AutoPrompter& operator=(const AutoPrompter&) = delete;
    AutoPrompter(AutoPrompter&&) = delete;
    AutoPrompter& operator=(AutoPrompter&&) = delete;

private:
    std::tuple<std::string, sdbus::UnixFd, std::string>
    RequestSecret(const std::string& kind, const std::map<std::string, sdbus::Variant>& options) override
    {
        // SAFETY GATE: no gate file -> never release anything.
        if (!gateOpen()) {
            logDecision(kind, false, "no-gate");
            return {wire::kStatusCancelled, sdbus::UnixFd{sealedFd({}), sdbus::adopt_fd}, std::string{}};
        }

        // Stand in for a user who takes the offered switch to the MRZ form:
        // answer the alternative credential with the distinct status, so a leg
        // can drive the alternative-kind path with no human at the dialog. All
        // three conditions must hold — the gate above, an explicit request from
        // this run, and an actual offer on this prompt — so nothing changes for
        // any leg that does not ask for it.
        if (kind == wire::kKindCan && mrzSwitchRequested() && altKindsOffer(options, wire::kKindMrz)) {
            const char* mrz = std::getenv("LIBRESCRS_MRZ");
            if (mrz == nullptr) {
                // Same fail-safe as every other kind: NEVER fabricate a secret.
                logDecision(kind, false, "env-unset");
                return {wire::kStatusCancelled, sdbus::UnixFd{sealedFd({}), sdbus::adopt_fd}, std::string{}};
            }
            logDecision(kind, true, "alt-kind-mrz");
            return {wire::kStatusOkMrz, sdbus::UnixFd{sealedFd(std::string_view{mrz}), sdbus::adopt_fd}, std::string{}};
        }

        const char* key = envKeyFor(kind);
        if (key == nullptr) {
            logDecision(kind, false, "unknown-kind");
            return {wire::kStatusCancelled, sdbus::UnixFd{sealedFd({}), sdbus::adopt_fd}, std::string{}};
        }

        const char* value = std::getenv(key);
        if (value == nullptr) {
            // Env unset -> fail-safe: NEVER fabricate a secret.
            logDecision(kind, false, "env-unset");
            return {wire::kStatusCancelled, sdbus::UnixFd{sealedFd({}), sdbus::adopt_fd}, std::string{}};
        }

        // Exactly the env bytes, no trailing newline.
        const std::string_view secret{value};
        logDecision(kind, true, nullptr);
        return {wire::kStatusOk, sdbus::UnixFd{sealedFd(secret), sdbus::adopt_fd}, std::string{}};
    }

    // The multi-secret path (change_pin): primary = current PIN, secondary =
    // new PIN. Same fail-closed discipline as the single-secret path — the gate
    // file, then BOTH env vars, and nothing is released unless both are present.
    // Answering with a half-filled pair would let a change run with a fabricated
    // second secret, so the check is all-or-nothing.
    std::tuple<std::string, sdbus::UnixFd, sdbus::UnixFd, std::string>
    RequestSecrets(const std::string& kind, const std::map<std::string, sdbus::Variant>& /*options*/) override
    {
        const auto refuse = [&](const char* reason) {
            logDecision(kind, false, reason);
            return std::tuple{wire::kStatusCancelled, sdbus::UnixFd{sealedFd({}), sdbus::adopt_fd},
                              sdbus::UnixFd{sealedFd({}), sdbus::adopt_fd}, std::string{}};
        };

        if (!gateOpen()) {
            return refuse("no-gate");
        }
        if (kind != wire::kKindChangePin) {
            return refuse("unknown-kind");
        }

        const char* current = std::getenv("LIBRESCRS_SIGN_PIN");
        const char* replacement = std::getenv("LIBRESCRS_NEW_PIN");
        if (current == nullptr || replacement == nullptr) {
            return refuse("env-unset");
        }

        logDecision(kind, true, nullptr);
        return {wire::kStatusOk, sdbus::UnixFd{sealedFd(std::string_view{current}), sdbus::adopt_fd},
                sdbus::UnixFd{sealedFd(std::string_view{replacement}), sdbus::adopt_fd}, std::string{}};
    }

    void CancelCurrent() override
    {
        // No dialog to dismiss — clean no-op.
        std::fprintf(stderr, "[auto-prompter] CancelCurrent (no-op)\n");
    }
};

} // namespace

int main()
{
    // Block the termination signals in every thread, then wait for one in main
    // while the sd-bus event loop runs async — a clean, race-free shutdown.
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGINT);
    sigaddset(&mask, SIGTERM);
    pthread_sigmask(SIG_BLOCK, &mask, nullptr);

    auto connection = sdbus::createSessionBusConnection();
    if (connection == nullptr) {
        std::fprintf(stderr, "[auto-prompter] FATAL: no session bus (run under dbus-run-session)\n");
        return 1;
    }

    try {
        connection->requestName(sdbus::ServiceName{kServiceName});
    } catch (const sdbus::Error& e) {
        std::fprintf(stderr, "[auto-prompter] FATAL: name %s taken: %s\n", kServiceName, e.getMessage().c_str());
        return 1;
    }

    AutoPrompter prompter(*connection, sdbus::ObjectPath{kObjectPath});
    connection->enterEventLoopAsync();

    std::fprintf(stderr, "[auto-prompter] ready: owns %s at %s (gate=%s)\n", kServiceName, kObjectPath,
                 gatePath().c_str());

    int sig = 0;
    sigwait(&mask, &sig);
    std::fprintf(stderr, "[auto-prompter] signal %d — leaving event loop\n", sig);
    connection->leaveEventLoop();
    return 0;
}
