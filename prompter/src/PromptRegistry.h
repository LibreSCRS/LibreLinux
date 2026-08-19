// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once

#include <sys/types.h> // pid_t

#include <cstddef>
#include <cstdint>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

namespace LibreLinux::Prompter {

class PromptDialog;

/// The credential windows currently on screen, and who may dismiss each.
///
/// Replaces the single-dialog slot the prompter used to keep. More than one
/// window can stand at once — that is the whole point of keying the agent's
/// prompt gate by card — so "the active dialog" stopped being a thing that
/// exists, and with it "dismiss the current modal".
///
/// Two rules, and the second is what makes concurrent windows safe:
///
///  1. The container is mutex-guarded, because an observer (a test harness, and
///     nothing else today) may read it from another thread.
///  2. ACTING on a window — dismissing it, answering it, deleting it — happens
///     only on the Qt main thread. The D-Bus worker threads never touch a
///     window pointer; they post a functor that does the lookup AND the action
///     together on that thread. So a dismissal can never hold a pointer another
///     thread is deleting underneath it: by the time the posted functor runs,
///     the entry is either still there or already gone, and "already gone" is
///     the documented idempotent no-op.
class PromptRegistry
{
public:
    /// Internal identity, distinct from the agent's prompt id: a window raised
    /// by a caller that sent no id still has to be owned, answered and cleaned
    /// up — it merely cannot be dismissed BY NAME.
    using Handle = std::uint64_t;

    struct Entry
    {
        PromptDialog* window{nullptr};
        pid_t ownerPid{0};
        std::string promptId;
    };

    /// Take ownership of @p window's registration. Fails (returns nullopt) when
    /// @p promptId is already live: two windows answering to one name would make
    /// a dismissal ambiguous, which is the defect this registry exists to end.
    /// An EMPTY @p promptId never collides — every unaddressable window is
    /// distinct, and none of them is reachable by name.
    [[nodiscard]] std::optional<Handle> add(PromptDialog* window, pid_t ownerPid, std::string promptId);

    /// The window @p promptId names, if one is live. Never matches an empty id:
    /// a prompt raised without one has nothing to tell it apart from any other.
    [[nodiscard]] std::optional<Handle> findByPromptId(const std::string& promptId) const;

    [[nodiscard]] std::optional<Entry> find(Handle handle) const;

    /// Remove and return the entry, so exactly one caller ever answers a given
    /// prompt: a second take finds nothing.
    std::optional<Entry> take(Handle handle);

    /// Every live handle, for the whole-registry sweep an agent restart needs.
    [[nodiscard]] std::vector<Handle> handles() const;

    /// Remove and return EVERY entry. What an agent restart needs: an orphan's
    /// owner is a process that no longer exists, so a per-owner sweep would
    /// clear nothing.
    std::vector<Entry> takeAll();

    [[nodiscard]] std::size_t size() const;
    [[nodiscard]] bool empty() const;

private:
    // Guards the two vectors below. Held only for the container operation
    // itself, never across a Qt call.
    mutable std::mutex m_mutex;
    // A vector, not a map: this holds a handful of entries at most (one per
    // reader with a dialog up), lookup is by two different keys, and iteration
    // order is the order windows were raised.
    std::vector<Entry> m_entries;
    std::vector<Handle> m_handles;
    Handle m_nextHandle{1}; // 0 is reserved as "no handle"

    // Index of the entry @p promptId names; callers hold m_mutex. Never matches
    // an empty id.
    [[nodiscard]] std::optional<std::size_t> indexOfPromptId(const std::string& promptId) const;
};

} // namespace LibreLinux::Prompter
