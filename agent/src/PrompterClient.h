// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <LibreSCRS/Agent/backend/PromptTypes.h>
#include <LibreSCRS/Agent/backend/PrompterClientBase.h>
#include <chrono>
#include <string>
#include <string_view>
namespace LibreSCRS::Agent {

class PrompterClient : public LibreSCRS::Agent::Operations::PrompterClientBase
{
public:
    // Interactive prompts are answered at HUMAN speed (reading the MRZ off a
    // lifted passport, calendar entry, careful PIN typing), so the request
    // calls carry this explicit budget instead of the D-Bus default method
    // timeout (~25 s), which aborted real entries mid-typing. Far beyond any
    // legitimate entry, still bounded so a wedged prompter cannot hold an
    // agent worker forever; teardown stays event-driven (CancelCurrent).
    static constexpr std::chrono::minutes kDefaultInteractiveBudget{10};

    // Owns NO connection: every call opens its own and closes it on return.
    // sd-bus connections are thread-aware but not thread-safe, and a blocking
    // RequestSecret pumps its reply inline, so any sharing would put a second
    // thread on a bus a worker is already driving -- which is what made a
    // cancel undeliverable and left dialogs on screen with no consumer. A
    // per-call connection also makes the zombie-worker keep-alive automatic:
    // the connection lives in the blocked call's own frame.
    // serviceName / objectPath default to the well-known names defined by the
    // org.librescrs.Prompter1 interface. @p interactiveBudget is injectable for
    // tests only — production call sites keep the default.
    explicit PrompterClient(std::string serviceName = "org.librescrs.Prompter1",
                            std::string objectPath = "/org/librescrs/Prompter1",
                            std::chrono::microseconds interactiveBudget = kDefaultInteractiveBudget);

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

    // Issues Prompter1.CancelCurrent so the prompter dismisses the modal it is
    // showing. Invoked when an Operation in AwaitingConsent is cancelled (the
    // user cancelled the read; the modal must go away), and during shutdown.
    // Runs on its own one-shot connection like every other call here, so it is
    // deliverable no matter which worker is blocked in a request and no matter
    // how many operations are cancelled at once. Exceptions from the bus call
    // are logged and swallowed.
    void cancel() noexcept override;

private:
    // Single point of contact with the generated proxy; the public requestX
    // wrappers forward the kind discriminator unchanged.
    [[nodiscard]] PromptResult request(std::string_view kind, const PromptOptions& options);

    // Per-call budget for the interactive request calls (see
    // kDefaultInteractiveBudget); test-injectable via the constructor.
    std::chrono::microseconds m_interactiveBudget;
    // Well-known prompter service name + object path: every call builds its own
    // one-shot proxy against this target.
    std::string m_serviceName;
    std::string m_objectPath;

    // Pimpl over the generated proxy so the public header pulls in only
    // LibreSCRS::Secure + sdbus-c++ forward-decls, not the codegen TU.
    class Impl;
};

} // namespace LibreSCRS::Agent
