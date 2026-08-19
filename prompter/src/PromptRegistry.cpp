// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "PromptRegistry.h"

#include <algorithm>
#include <utility>

namespace LibreLinux::Prompter {

std::optional<PromptRegistry::Handle> PromptRegistry::add(PromptDialog* window, pid_t ownerPid, std::string promptId)
{
    if (window == nullptr) {
        return std::nullopt;
    }
    const std::lock_guard lock{m_mutex};
    if (!promptId.empty() && indexOfPromptId(promptId).has_value()) {
        return std::nullopt;
    }
    const Handle handle = m_nextHandle++;
    m_entries.push_back(Entry{window, ownerPid, std::move(promptId)});
    m_handles.push_back(handle);
    return handle;
}

std::optional<std::size_t> PromptRegistry::indexOfPromptId(const std::string& promptId) const
{
    // Callers hold m_mutex.
    if (promptId.empty()) {
        return std::nullopt;
    }
    for (std::size_t i = 0; i < m_entries.size(); ++i) {
        if (m_entries[i].promptId == promptId) {
            return i;
        }
    }
    return std::nullopt;
}

std::optional<PromptRegistry::Handle> PromptRegistry::findByPromptId(const std::string& promptId) const
{
    const std::lock_guard lock{m_mutex};
    const auto index = indexOfPromptId(promptId);
    return index ? std::optional<Handle>{m_handles[*index]} : std::nullopt;
}

std::optional<PromptRegistry::Entry> PromptRegistry::find(Handle handle) const
{
    const std::lock_guard lock{m_mutex};
    const auto it = std::ranges::find(m_handles, handle);
    if (it == m_handles.end()) {
        return std::nullopt;
    }
    return m_entries[static_cast<std::size_t>(std::distance(m_handles.begin(), it))];
}

std::optional<PromptRegistry::Entry> PromptRegistry::take(Handle handle)
{
    const std::lock_guard lock{m_mutex};
    const auto it = std::ranges::find(m_handles, handle);
    if (it == m_handles.end()) {
        return std::nullopt;
    }
    const auto index = static_cast<std::size_t>(std::distance(m_handles.begin(), it));
    Entry taken = std::move(m_entries[index]);
    m_entries.erase(m_entries.begin() + static_cast<std::ptrdiff_t>(index));
    m_handles.erase(it);
    return taken;
}

std::vector<PromptRegistry::Handle> PromptRegistry::handles() const
{
    const std::lock_guard lock{m_mutex};
    return m_handles;
}

std::vector<PromptRegistry::Entry> PromptRegistry::takeAll()
{
    const std::lock_guard lock{m_mutex};
    std::vector<Entry> taken = std::move(m_entries);
    m_entries.clear();
    m_handles.clear();
    return taken;
}

std::size_t PromptRegistry::size() const
{
    const std::lock_guard lock{m_mutex};
    return m_handles.size();
}

bool PromptRegistry::empty() const
{
    const std::lock_guard lock{m_mutex};
    return m_handles.empty();
}

} // namespace LibreLinux::Prompter
