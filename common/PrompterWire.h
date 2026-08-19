// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// The single definition of the Prompter1 D-Bus wire vocabulary shared across
// THIS boundary's two binaries: the secret-KIND strings, the option-dict KEYS
// the request marshals, and the STATUS strings the prompter returns. The
// producer side (PrompterClient.cpp issuing the request + parsing the status)
// and the consumer side (PrompterService.cpp parsing the kind + option dict and
// minting the status) each used to hand-spell these same literals, with no
// compile/link tie between the two binaries — so a typo on either side was a
// silent wire mismatch (unknown kind -> error, dropped option, unrecognised
// status -> generic error) with no compile failure. Sharing one constexpr table
// closes that gap.
//
// The kind strings ("pin"/"can"/"mrz") ARE the CredentialEntry field identifiers
// the LM Auth surface matches against AuthRequirement keys — those three kinds
// are neutral vocabulary and are also defined in the agent core's PrompterWire
// copy (LibreSCRS::PrompterWire), which the Qt-free credential plumbing keys off.
// The option-key/status vocabulary is transport-only and lives HERE alone.
//
// Header-only, dependency-free (no Qt, no sdbus, no LM) — included by the agent
// backend and the Qt prompter via the librelinux-common interface target.

#pragma once

namespace LibreLinux::PrompterWire {

// Secret kind requested over RequestSecret(kind, options); also the
// CredentialEntry field identifier the LM Auth surface matches.
inline constexpr const char* kKindPin = "pin";
inline constexpr const char* kKindCan = "can";
inline constexpr const char* kKindMrz = "mrz";

// Multi-secret kind requested over RequestSecrets(kind, options): the PIN
// change prompt (current + new + confirm). The confirm entry is validated
// inside the prompter and NEVER crosses the wire — the reply carries exactly
// two sealed fds: primary (current) and secondary (new).
inline constexpr const char* kKindChangePin = "change_pin";

// Option-dict keys (the a{sv} options argument of RequestSecret).
// The identity this prompt answers to for the lifetime of the call: the value
// Cancel names to dismiss THIS window and no other. Agent-minted and OPAQUE --
// the prompter stores it and never parses it, so the agent can change its shape
// without touching this side. More than one credential window can stand at
// once, which is why a dismissal has to name one.
inline constexpr const char* kOptPromptId = "prompt_id";
// How long the holder gets, from the moment the window is SHOWN. A DURATION in
// milliseconds, not an absolute time, so the two processes need no shared clock
// and transport latency is not charged to the human. Absent or 0 means "no
// deadline set" -- a prompter must never read that as an instant expiry. The
// prompter enforces it and closes its own window, so a window cannot be left
// standing by a dismissal that never arrived.
inline constexpr const char* kOptDeadlineMs = "deadline_ms";
inline constexpr const char* kOptTitle = "title";
inline constexpr const char* kOptDescription = "description";
inline constexpr const char* kOptRequester = "requester";
inline constexpr const char* kOptArtifact = "artifact";
// UNTRUSTED, unlike kOptArtifact above: the enumerated per-document display
// names of a Card1.SignBatch consent (an `as` array). kOptArtifact stays the
// TRUSTED, agent-owned category token for the whole request ("signature-batch"
// for a batch); this list is client-supplied chrome the prompter renders
// alongside it, never as (or inside) the trusted label itself. Absent for
// every prompt that is not a batch sign.
inline constexpr const char* kOptArtifacts = "artifacts";
inline constexpr const char* kOptMinLength = "min_length";
inline constexpr const char* kOptMaxLength = "max_length";
// Retry context on a RequestSecret re-issued after the card rejected the
// CAN/MRZ collected last time for the SAME card (absent on the first-ever
// prompt for a card):
//   "attempt"    (u) which attempt this prompt is (2 = second attempt, ...)
//   "last_error" (s) msgKey of the failure that triggered the retry (an
//                LibreSCRS::Auth::ErrorKeys value, e.g. the pre-read
//                auth-failure key) -- an open, growable value space, unlike
//                the closed kKind*/kStatus* vocabularies above; the prompter
//                maps recognised keys to localized text and falls back to a
//                generic line for anything else, never showing the raw key.
inline constexpr const char* kOptAttempt = "attempt";
inline constexpr const char* kOptLastError = "last_error";
// Opt-in on a kind-"can" RequestSecret: the ALTERNATIVE credential kinds the
// caller can also consume for the same operation, as an `as` array of kind
// strings from the kKind* vocabulary above (today the only meaningful member is
// kKindMrz). Sending it asks the prompter to offer the user an in-dialog switch
// to that alternative form; unknown members are ignored, never rendered.
//
// Additive rollout contract, BOTH directions:
//   * new caller x old prompter -- the prompter lifts only the keys it knows,
//     so this one is dropped: no switch is offered and the reply is the plain
//     kStatusOk vocabulary, exactly as before.
//   * old caller x new prompter -- the key is absent, so the switch affordance
//     is never constructed and kStatusOkMrz below is structurally unmintable.
// The key is meaningful ONLY on kind "can"; a request of any other kind that
// carries it renders no switch and answers with today's status vocabulary.
inline constexpr const char* kOptAltKinds = "alt_kinds";

// Additional option-dict keys of RequestSecrets (all non-secret metadata).
// Per-role bounds: primary_* applies to the CURRENT credential field,
// new_* applies to BOTH the new and the confirm fields.
inline constexpr const char* kOptPrimaryMinLength = "primary_min_length";
inline constexpr const char* kOptPrimaryMaxLength = "primary_max_length";
inline constexpr const char* kOptNewMinLength = "new_min_length";
inline constexpr const char* kOptNewMaxLength = "new_max_length";
// Display-only labels: the card the change applies to and the human-readable
// name of the PIN role being changed (e.g. a signature PIN vs a card PIN).
inline constexpr const char* kOptCardLabel = "card_label";
inline constexpr const char* kOptPinLabel = "pin_label";

// Status strings returned by RequestSecret (the first tuple element).
inline constexpr const char* kStatusOk = "ok";
// Returned INSTEAD of kStatusOk when, and only when, the request was kind
// "can", carried kOptAltKinds containing kKindMrz, and the user switched the
// dialog to the MRZ form before accepting: the secret_fd then carries an MRZ
// payload (the canonical three-line document-number / date-of-birth /
// date-of-expiry shape), not a CAN. It tells the caller WHICH credential it is
// holding, so it can deposit the value under the right field identifier.
//
// Minting is gated on the same offer the dialog rendered, so "offered" and
// "minted" cannot diverge: a caller that never opted in never sees this status,
// and a caller that opted in but whose user stayed on the CAN form gets plain
// kStatusOk. Consumers treat an unexpected kStatusOkMrz as they treat any
// unknown status -- fail closed to an error, never as a successful CAN.
inline constexpr const char* kStatusOkMrz = "ok_mrz";
inline constexpr const char* kStatusCancelled = "cancelled";
// The window closed itself because kOptDeadlineMs elapsed with no entry.
// DISTINCT from kStatusCancelled on purpose: a holder who dismissed a dialog
// and a holder whose time ran out did different things, and a client that
// conflates them tells the second one they cancelled something.
inline constexpr const char* kStatusTimeout = "timeout";
inline constexpr const char* kStatusError = "error";
// Returned to a caller that fails the prompter's binary-identity gate; pairs
// with a zero-byte sealed memfd so no dialog shows and no secret can be
// harvested. The agent is the only authorized caller, so it never legitimately
// receives this — but it is part of the wire contract both ends acknowledge.
inline constexpr const char* kStatusUnauthorized = "unauthorized";

} // namespace LibreLinux::PrompterWire
