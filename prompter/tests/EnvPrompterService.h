// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once

#include "org.librescrs.Prompter1_adaptor.h"

#include <sdbus-c++/AdaptorInterfaces.h>
#include <sdbus-c++/IConnection.h>
#include <sdbus-c++/Types.h>

#include <sys/types.h> // pid_t

#include <atomic>

namespace LibreLinux::Prompter {

/// Headless @c org.librescrs.Prompter1 implementation for end-to-end tests:
/// answers @c RequestSecret from @c LIBRESCRS_TEST_PIN / @c LIBRESCRS_TEST_CAN
/// / @c LIBRESCRS_TEST_MRZ instead of raising a dialog. Built ONLY into the
/// test tree (`prompter/tests/`), which carries no `install()` rule for it —
/// the packaged prompter selection is file-only config
/// (`org.librescrs.Prompter1.service.in`'s `Exec=` line, always
/// `librescrs-pinentry-kde`), so this binary is reachable only by a test
/// harness or a lab operator that starts it explicitly on a bus, never by
/// production D-Bus activation.
///
/// Same binary-identity trust gate as the production prompter
/// (@ref CallerAuthorizer) — a lab run authorises the real agent via the
/// @c LIBRELINUX_TESTING env-override escape hatch, so the trust boundary is
/// never silently bypassed just because this is a test tool.
///
/// Burn-through guard (mirrors the @c g_pinFailed test-guard pattern the HW
/// smoke suites use): the wire's `attempt` option (set by
/// @c CredentialCache::applyRetryContext) present on a request means the
/// PREVIOUS answer for that secret kind was rejected by the card. Rather than
/// resupply the same env secret blindly, this service refuses every later
/// request for that kind for the remainder of the process's life, exactly
/// like "abort after the first failure, never present the secret again."
///
/// SCOPE — read before assuming this protects PIN too: the guard is fully
/// effective for CAN/MRZ, the only kinds @c CredentialCache::requestCredential
/// ever attaches `attempt` to (PIN/PUK short-circuit to an error before
/// reaching @c applyRetryContext — see @c CredentialCache.h). The signing PIN
/// is built fresh by @c SignFlow / @c BatchSignFlow / @c RawCryptoFlow /
/// @c KeyActivationFlow with a default-constructed @c PromptOptions; none of
/// them ever set `attempt`, because PIN is never cached and is never routed
/// through @c CredentialCache in the first place. So in a real agent-driven
/// run this guard NEVER trips for PIN: a wrong @c LIBRESCRS_TEST_PIN is
/// resupplied on every new signing operation with nothing here to stop it
/// from burning a real card's PIN retry counter. PIN burn-through protection
/// is the CALLER's responsibility — the GTEST harness's own @c g_pinFailed +
/// @c SKIP_IF_PIN_FAILED() + 3-retries-before-permanent-block discipline in
/// the test bodies (this project's CRITICAL Test Safety rule) — not this
/// guard.
class EnvPrompterService final : public sdbus::AdaptorInterfaces<org::librescrs::Prompter1_adaptor>
{
public:
    EnvPrompterService(sdbus::IConnection& connection, sdbus::ObjectPath path);
    ~EnvPrompterService();

    EnvPrompterService(const EnvPrompterService&) = delete;
    EnvPrompterService& operator=(const EnvPrompterService&) = delete;
    EnvPrompterService(EnvPrompterService&&) = delete;
    EnvPrompterService& operator=(EnvPrompterService&&) = delete;

private:
    std::tuple<std::string, sdbus::UnixFd, std::string>
    RequestSecret(const std::string& kind, const std::map<std::string, sdbus::Variant>& options) override;

    // change_pin (current + new PIN) is out of scope for this env-driven
    // prompter — no LIBRESCRS_TEST_* pair models it — so this always refuses,
    // matching PrompterClientBase's own default-Error contract for a backend
    // that never wired multi-secret prompting.
    std::tuple<std::string, sdbus::UnixFd, sdbus::UnixFd, std::string>
    RequestSecrets(const std::string& kind, const std::map<std::string, sdbus::Variant>& options) override;

    void CancelCurrent() override;

    // Resolves the in-flight caller's PID and checks it against the expected
    // agent binary (see CallerAuthorizer). Returns 0 (and logs, no secret
    // material) on any rejection.
    [[nodiscard]] pid_t authorizeCaller(const char* method);

    // Per-kind burn-through guard: true once a retry (the wire's `attempt`
    // option > 0) was observed for that kind — every later request for it is
    // refused for the rest of the process's life. m_canFailed/m_mrzFailed are
    // the ones a real agent-driven run actually exercises. m_pinFailed exists
    // for symmetry and only trips if something explicitly hands this service
    // an `attempt` on a "pin" request (e.g. a hand-injected test payload) —
    // the real agent never does that (see the class doc above), so treat
    // m_pinFailed as inert in practice, not as PIN protection.
    std::atomic<bool> m_pinFailed{false};
    std::atomic<bool> m_canFailed{false};
    std::atomic<bool> m_mrzFailed{false};
};

} // namespace LibreLinux::Prompter
