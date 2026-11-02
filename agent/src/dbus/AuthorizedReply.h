// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include "AgentErrorNames.h" // LibreLinux::AgentWire::kErrNotAuthorized / kErrCommunication
#include "dbus/GrantGate.h"
#include <LibreSCRS/Agent/Identity.h>
#include <LibreSCRS/Agent/backend/Authorizer.h>

#include <sdbus-c++/sdbus-c++.h>

#include <exception>
#include <functional>
#include <memory>
#include <string>
#include <string_view>
#include <tuple>
#include <type_traits>
#include <utility>

namespace LibreSCRS::Agent {

// Reply to a deferred method call with what @p body returns, or with the
// sdbus::Error it throws. A body written the way a synchronous handler is --
// return the results, throw the refusal -- keeps its shape when it moves behind
// an asynchronous authorization.
template <typename... Results, typename Body>
void replyWith(const sdbus::Result<Results...>& result, const Body& body) noexcept
{
    try {
        using Returned = std::invoke_result_t<const Body&>;
        if constexpr (std::is_void_v<Returned>) {
            body();
            result.returnResults();
        } else if constexpr (sizeof...(Results) == 1) {
            result.returnResults(body());
        } else {
            std::apply([&result](const auto&... values) { result.returnResults(values...); }, body());
        }
    } catch (const sdbus::Error& e) {
        result.returnError(e);
    } catch (const std::exception& e) {
        result.returnError(sdbus::Error{sdbus::Error::Name{"org.freedesktop.DBus.Error.Failed"}, e.what()});
    }
}

namespace AuthorizedReplyDetail {

// A deferred reply that is answered even if the authorization never is: an
// authorizer torn down while a question is outstanding (the agent stopping)
// drops the completion, and the caller would otherwise hear nothing until its
// own timeout.
template <typename... Results>
struct PendingReply
{
    explicit PendingReply(sdbus::Result<Results...>&& r) : result(std::move(r)) {}
    ~PendingReply()
    {
        if (answered) {
            return;
        }
        try {
            result.returnError(sdbus::Error{sdbus::Error::Name{LibreLinux::AgentWire::kErrCommunication},
                                            "The agent stopped before the authorization service answered; "
                                            "nothing was changed"});
        } catch (...) {
            // The connection is going away as well; there is no one to tell.
        }
    }
    PendingReply(const PendingReply&) = delete;
    PendingReply& operator=(const PendingReply&) = delete;
    PendingReply(PendingReply&&) = delete;
    PendingReply& operator=(PendingReply&&) = delete;

    sdbus::Result<Results...> result;
    bool answered = false; // set by the one completion that runs
};

} // namespace AuthorizedReplyDetail

// Ask @p authorizer whether @p sender may do @p action WITHOUT holding the
// thread that dispatched the call, then reply: with @p granted's outcome, or
// with the refusal, or with the silence.
//
// An authority may hold its answer while a person decides (a polkit password
// dialog). A handler that waited for it held the bus dispatcher -- and, through
// the connection's lock, every signal the agent's worker threads emit -- for as
// long as the dialog stayed open. The reply is deferred instead, and the
// dispatcher serves everyone else meanwhile.
//
// @p granted runs when (and only when) the authority granted; it may run later
// and on another thread than the handler (the production authorizer hands its
// answers back to the dispatcher thread). Everything it needs is therefore
// captured BY VALUE -- the caller's identity and arguments included, since the
// in-flight message is gone by then -- and it runs through @p gate, the gate of
// the object it runs on: if that object was withdrawn meanwhile (a card pulled
// while a dialog was open), nothing runs and the caller is told nothing was
// changed.
template <typename... Results, typename Granted>
void authorizeThenReply(Authorizer& authorizer, std::string_view action, const std::string& sender,
                        sdbus::Result<Results...>&& result, std::string deniedMessage, std::shared_ptr<GrantGate> gate,
                        Granted granted)
{
    auto reply = std::make_shared<AuthorizedReplyDetail::PendingReply<Results...>>(std::move(result));
    authorizer.authorizeAsync(
        action, CallerToken{sender},
        [reply, denied = std::move(deniedMessage), gate = std::move(gate),
         granted = std::move(granted)](AuthorizationOutcome outcome) {
            reply->answered = true;
            switch (outcome) {
            case AuthorizationOutcome::Granted:
                break;
            case AuthorizationOutcome::Denied:
                reply->result.returnError(
                    sdbus::Error{sdbus::Error::Name{LibreLinux::AgentWire::kErrNotAuthorized}, denied});
                return;
            case AuthorizationOutcome::Undecided:
                // Nothing was decided and nothing was changed. Saying "not
                // authorized" here tells a person who authenticated correctly
                // that they were refused -- a claim about a security decision
                // nobody made.
                reply->result.returnError(
                    sdbus::Error{sdbus::Error::Name{LibreLinux::AgentWire::kErrCommunication},
                                 "The authorization service did not answer; nothing was changed"});
                return;
            }
            if (!gate->runIfOpen([&reply, &granted] { replyWith(reply->result, granted); })) {
                reply->result.returnError(sdbus::Error{sdbus::Error::Name{LibreLinux::AgentWire::kErrCommunication},
                                                       "The object went away while authorization was pending; "
                                                       "nothing was changed"});
            }
        });
}

} // namespace LibreSCRS::Agent
