// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <LibreSCRS/Agent/cache/CardReadCache.h>
#include <LibreSCRS/Agent/cache/CredentialCache.h>
#include <LibreSCRS/Agent/cache/CredentialSnapshotCache.h>
#include <string>

namespace LibreSCRS::Agent {

// The exact set of per-card caches dropped when a card (or its reader) is
// removed, all keyed on the card object path. This is the SINGLE source of truth
// shared by the AgentService card-removal hook (setOnKeyRemoved) and its
// regression test, so *which* caches are invalidated on removal is genuinely
// under test rather than re-mirrored by hand: dropping one from here breaks both
// production and the test together.
//
// The PKCS#11 login-lease revocation and reader-session invalidation stay in the
// hook itself — they need the frontend / operation manager, not just the caches.
inline void invalidateCardRemovalCaches(CredentialCache& credentialCache, CardReadCache& cardReadCache,
                                        CredentialSnapshotCache& snapshotCache, const std::string& cardPath)
{
    // CAN/MRZ secret cache + the identity/certificate read cache.
    credentialCache.invalidate(cardPath);
    cardReadCache.invalidate(cardPath);
    // The per-card ListCredentials snapshot: its id namespace is void once the
    // card is gone (a re-insert re-lists afresh).
    snapshotCache.invalidate(cardPath);
}

} // namespace LibreSCRS::Agent
