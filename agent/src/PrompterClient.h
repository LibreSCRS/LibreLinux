// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <LibreSCRS/Agent/backend/PromptTypes.h>
#include <LibreSCRS/Agent/backend/PrompterClientBase.h>
#include <sdbus-c++/IConnection.h>
#include <memory>
#include <string>
#include <string_view>
namespace LibreSCRS::Agent {

class PrompterClient : public LibreSCRS::Agent::Operations::PrompterClientBase
{
public:
    // CO-OWNS the connection (shared_ptr, not a borrow): the per-reader crypto
    // worker pumps its blocking Prompter1.RequestSecret reply INLINE on this
    // connection, so a worker abandoned while still blocked in that call must keep
    // the connection alive even after the agent that created this client is gone.
    // A crypto seam value-captures a shared_ptr to this client (which shares the
    // connection), so the connection outlives any such zombie worker's in-flight
    // call. serviceName / objectPath default to the well-known names defined by the
    // org.librescrs.Prompter1 interface.
    explicit PrompterClient(std::shared_ptr<sdbus::IConnection> connection,
                            std::string serviceName = "org.librescrs.Prompter1",
                            std::string objectPath = "/org/librescrs/Prompter1");

    ~PrompterClient() override;

    PrompterClient(const PrompterClient&) = delete;
    PrompterClient& operator=(const PrompterClient&) = delete;
    PrompterClient(PrompterClient&&) = delete;
    PrompterClient& operator=(PrompterClient&&) = delete;

    // Synchronous blocking calls — invoke on a worker thread. None of them
    // throw: D-Bus / I/O failures are surfaced via PromptStatus::Error +
    // a populated PromptResult::userMessage.
    [[nodiscard]] PromptResult requestPin(const PromptOptions& options) override;
    [[nodiscard]] PromptResult requestCan(const PromptOptions& options) override;
    [[nodiscard]] PromptResult requestMrz(const PromptOptions& options) override;

    // Two-secret PIN-change prompt over Prompter1.RequestSecrets: the current
    // and the new PIN are captured in ONE modal and returned as two sealed
    // memfds (primary = current, secondary = new); the confirm re-entry never
    // crosses the wire. Both fds are read into cleansing Secure::Strings BEFORE
    // either is committed, so a seal-verification failure on either fd fails the
    // whole change closed (status Error) with NO partial secret escaping. Like
    // the single-secret calls this is synchronous, blocking, and no-throw.
    [[nodiscard]] PinChangePromptResult requestPinChange(const PromptOptions& options) override;

    // Issues Prompter1.CancelCurrent so the prompter dismisses any modal
    // it is showing for this agent connection. Invoked when an Operation
    // in AwaitingConsent is cancelled (the user cancelled the read; the
    // modal must go away). Exceptions from the bus call are logged and
    // swallowed.
    void cancel() noexcept override;

    // CancelCurrent issued on a SEPARATE @p connection (the agent's main bus),
    // never m_connection. Used during shutdown: a crypto worker wedged in a blocking
    // RequestSecret is pumping m_connection inline, so a cancel routed through it
    // would put two threads on one sd_bus. The prompter authorises + correlates
    // CancelCurrent by the caller PID — which both the agent's main and prompter
    // connections share — so a cross-connection cancel still dismisses the modal the
    // worker is blocked on, and RequestSecret returns Cancelled. Best-effort +
    // noexcept: a failure just falls back to the crypto seam's shared_ptr keep-alive.
    void cancelVia(sdbus::IConnection& connection) noexcept;

private:
    // Single point of contact with the generated proxy; the public requestX
    // wrappers forward the kind discriminator unchanged.
    [[nodiscard]] PromptResult request(std::string_view kind, const PromptOptions& options);

    // Co-owned outbound connection the generated proxy is bound to. Declared
    // BEFORE m_impl so it is destroyed AFTER it (the proxy unregisters against a
    // live connection).
    std::shared_ptr<sdbus::IConnection> m_connection;
    // Well-known prompter service name + object path, retained so cancelVia() can
    // build a one-shot proxy on the main connection with the same target.
    std::string m_serviceName;
    std::string m_objectPath;

    // Pimpl over the generated proxy so the public header pulls in only
    // LibreSCRS::Secure + sdbus-c++ forward-decls, not the codegen TU.
    class Impl;
    std::unique_ptr<Impl> m_impl;
};

} // namespace LibreSCRS::Agent
