// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "EnvPrompterService.h"

#include "CallerAuthorizer.h"
#include "PrompterWire.h" // shared Prompter1 kind / option-key / status vocabulary
#include "SecretMemfd.h"

#include <sdbus-c++/Message.h>

#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <filesystem>
#include <map>
#include <optional>
#include <string>
#include <tuple>
#include <utility>

namespace LibreLinux::Prompter {

namespace {

std::optional<std::string> envValue(const char* name)
{
    const char* v = std::getenv(name);
    if (v == nullptr || *v == '\0') {
        return std::nullopt;
    }
    return std::string{v};
}

// True iff `options` carries the wire's retry-context `attempt` key with a
// value > 0 -- a genuine re-prompt (the previous answer for this kind was
// rejected by the card), never a first-ever ask. A missing or mistyped key
// answers false, same tolerant-lift convention as PrompterService's own
// option readers.
bool isRetryPrompt(const std::map<std::string, sdbus::Variant>& options)
{
    auto it = options.find(PrompterWire::kOptAttempt);
    if (it == options.end()) {
        return false;
    }
    try {
        return it->second.get<std::uint32_t>() > 0;
    } catch (const sdbus::Error&) {
        return false;
    }
}

std::tuple<std::string, sdbus::UnixFd, std::string> errorReply(const std::string& message)
{
    sdbus::UnixFd fd{makeEmptySealedFd(), sdbus::adopt_fd};
    return std::make_tuple(std::string{PrompterWire::kStatusError}, std::move(fd), message);
}

} // namespace

EnvPrompterService::EnvPrompterService(sdbus::IConnection& connection, sdbus::ObjectPath path)
    : AdaptorInterfaces(connection, std::move(path))
{
    // Per sdbus-c++ contract: register at the END of the ctor.
    registerAdaptor();
}

EnvPrompterService::~EnvPrompterService()
{
    unregisterAdaptor();
}

std::tuple<std::string, sdbus::UnixFd, std::string>
EnvPrompterService::buildSecretReply(const std::string& kind, const std::map<std::string, sdbus::Variant>& options)
{
    const pid_t ownerPid = authorizeCaller("RequestSecret");
    if (ownerPid == 0) {
        sdbus::UnixFd fd{makeEmptySealedFd(), sdbus::adopt_fd};
        return std::make_tuple(std::string{PrompterWire::kStatusUnauthorized}, std::move(fd), std::string{});
    }

    const char* envVar = nullptr;
    std::atomic<bool>* guard = nullptr;
    if (kind == PrompterWire::kKindPin) {
        envVar = "LIBRESCRS_TEST_PIN";
        guard = &m_pinFailed;
    } else if (kind == PrompterWire::kKindCan) {
        envVar = "LIBRESCRS_TEST_CAN";
        guard = &m_canFailed;
    } else if (kind == PrompterWire::kKindMrz) {
        envVar = "LIBRESCRS_TEST_MRZ";
        guard = &m_mrzFailed;
    } else {
        return errorReply("unrecognised secret kind");
    }

    // SPLIT OF RESPONSIBILITY -- read before trusting this to cover PIN:
    // this guard is real and symmetric across pin/can/mrz, but a real
    // agent-driven run only ever attaches `attempt` to CAN/MRZ requests
    // (CredentialCache::applyRetryContext; PIN/PUK never reach it). The
    // signing PIN is prompted fresh every operation by SignFlow /
    // BatchSignFlow / RawCryptoFlow / KeyActivationFlow with no `attempt`
    // ever set, so guard-tripping for "pin" below only happens if a caller
    // hand-injects `attempt` (as EnvPrompterServiceTest does, to exercise the
    // mechanism) -- it does not happen from real agent traffic. PIN
    // burn-through protection against a real card's retry counter is the
    // GTEST harness's g_pinFailed + SKIP_IF_PIN_FAILED() + 3-retry discipline
    // in the test bodies, not this guard. See EnvPrompterService.h for the
    // full explanation.
    if (guard->load(std::memory_order_relaxed)) {
        return errorReply("test prompter: refusing " + kind +
                          " -- a prior attempt for this kind was already rejected this run (burn-through guard)");
    }
    if (isRetryPrompt(options)) {
        // The card rejected what we handed out last time. Trip the guard
        // BEFORE refusing so every later request for this kind in this
        // process also refuses -- mirrors g_pinFailed's "never present the
        // secret again after the first rejection," generalised to CAN/MRZ.
        guard->store(true, std::memory_order_relaxed);
        return errorReply("test prompter: refusing to retry " + kind +
                          " after a rejected attempt (burn-through guard)");
    }

    const auto value = envValue(envVar);
    if (!value) {
        return errorReply(std::string{"test prompter: no test secret configured ("} + envVar + " unset)");
    }

    const int fd = makeSealedSecretFd(*value);
    if (fd < 0) {
        return errorReply("test prompter: failed to seal the test secret into a memfd");
    }
    sdbus::UnixFd wrapped{fd, sdbus::adopt_fd};
    return std::make_tuple(std::string{PrompterWire::kStatusOk}, std::move(wrapped), std::string{});
}

std::tuple<std::string, sdbus::UnixFd, sdbus::UnixFd, std::string>
EnvPrompterService::buildSecretsReply(const std::string& /*kind*/,
                                      const std::map<std::string, sdbus::Variant>& /*options*/)
{
    const pid_t ownerPid = authorizeCaller("RequestSecrets");
    sdbus::UnixFd primary{makeEmptySealedFd(), sdbus::adopt_fd};
    sdbus::UnixFd secondary{makeEmptySealedFd(), sdbus::adopt_fd};
    if (ownerPid == 0) {
        return std::make_tuple(std::string{PrompterWire::kStatusUnauthorized}, std::move(primary), std::move(secondary),
                               std::string{});
    }
    // change_pin is not modelled by this env-driven prompter (see header).
    return std::make_tuple(std::string{PrompterWire::kStatusError}, std::move(primary), std::move(secondary),
                           std::string{"change_pin is not supported by the env-driven test prompter"});
}

void EnvPrompterService::RequestSecret(sdbus::Result<std::string, sdbus::UnixFd, std::string>&& result,
                                       std::string kind, std::map<std::string, sdbus::Variant> options)
{
    auto reply = buildSecretReply(kind, options);
    result.returnResults(std::get<0>(reply), std::get<1>(reply), std::get<2>(reply));
}

void EnvPrompterService::RequestSecrets(sdbus::Result<std::string, sdbus::UnixFd, sdbus::UnixFd, std::string>&& result,
                                        std::string kind, std::map<std::string, sdbus::Variant> options)
{
    auto reply = buildSecretsReply(kind, options);
    result.returnResults(std::get<0>(reply), std::get<1>(reply), std::get<2>(reply), std::get<3>(reply));
}

void EnvPrompterService::Cancel(const std::string& promptId)
{
    (void)promptId;
    // No real dialog is ever shown -- nothing to dismiss. Still gate on
    // caller identity for parity with the production contract (and so a
    // rejection is logged like every other method here).
    (void)authorizeCaller("Cancel");
}

pid_t EnvPrompterService::authorizeCaller(const char* method)
{
    pid_t callerPid = 0;
    try {
        callerPid = getObject().getCurrentlyProcessedMessage().getCredsPid();
    } catch (const sdbus::Error& e) {
        std::fprintf(stderr, "librescrs-pinentry-test: %s rejected: cannot resolve caller PID: %s\n", method,
                     e.getMessage().c_str());
        return 0;
    }

    const std::filesystem::path expectedPeer = CallerAuthorizer::resolveExpectedPeerPath();
    if (!CallerAuthorizer::isAuthorizedCaller(callerPid, expectedPeer)) {
        std::fprintf(stderr, "librescrs-pinentry-test: %s rejected: caller pid=%ld is not the agent (expected %s)\n",
                     method, static_cast<long>(callerPid), expectedPeer.c_str());
        return 0;
    }
    return callerPid;
}

} // namespace LibreLinux::Prompter
