// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// The Prompter1 D-Bus transport vocabulary shared across THIS boundary's two
// binaries: the option-dict KEYS the request marshals and the contract version.
// The producer side (PrompterClient.cpp issuing the request) and the consumer
// side (PrompterService.cpp parsing the option dict) each used to hand-spell
// these same literals, with no compile/link tie between the two binaries -- so
// a typo on either side was a silent wire mismatch with no compile failure.
//
// What every agent host and every prompter speaks alike -- the secret-KIND
// words, the reply STATUS words and the largest secret a prompter may hand
// back, and the reader-interface tokens -- is the agent library's, and is only
// named here (LibreSCRS/Agent/backend/PrompterWire.h,
// LibreSCRS/Agent/wire/ReaderInterface.h), never spelled again.
//
// Header-only, no Qt, no sdbus, no LM -- included by the agent backend and the
// Qt prompter via the librelinux-common interface target, which also carries
// the agent library's include directory for the two headers above (both
// standard-library only).

#pragma once

#include <LibreSCRS/Agent/backend/PrompterWire.h> // kind words, reply status, kMaxSecretBytes

#include <cstdint>

namespace LibreLinux::PrompterWire {

// The agent library's prompter vocabulary under this boundary's name.
using LibreSCRS::PrompterWire::kKindCan;
using LibreSCRS::PrompterWire::kKindChangePin;
using LibreSCRS::PrompterWire::kKindMrz;
using LibreSCRS::PrompterWire::kKindPin;
using LibreSCRS::PrompterWire::kMaxSecretBytes;
using LibreSCRS::PrompterWire::PromptReplyStatus;
using LibreSCRS::PrompterWire::replyStatusFromToken;
using LibreSCRS::PrompterWire::replyStatusToken;

// The Prompter1 contract this tree implements, published by the prompter as the
// read-only ProtocolVersion property and read once by the agent.
//
// Why a version at all: the prompter is a long-lived user unit and SURVIVES an
// agent restart, so a new agent routinely meets an older helper. A helper that
// does not understand a dismissal by name would leave every window hanging with
// no way to close it. The agent refuses to raise a prompt it could not dismiss
// rather than emulating the old behaviour: no compatibility shim.
//
// Bump this whenever a method the agent DEPENDS ON changes shape.
//   1 -- RequestSecret/RequestSecrets + CancelCurrent()
//   2 -- Cancel(prompt_id), prompt_id / deadline_ms / reader_* options,
//        the "timeout" reply word, Reset()
inline constexpr std::uint32_t kProtocolVersion = 2;

// The multi-secret kind (kKindChangePin, over RequestSecrets): the confirm
// entry is validated inside the prompter and NEVER crosses the wire -- the
// reply carries exactly two sealed fds: primary (current) and secondary (new).

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
// Which reader raised this prompt, as three flat keys. More than one credential
// window can stand at once, so a dialog that does not name its reader leaves the
// holder guessing which secret authorises which card -- and on a dual-interface
// unit whose two slots SHARE a serial, the qualifier below is the only thing
// separating two otherwise identical dialogs.
//
// All three are agent-owned and TRUSTED, unlike kOptArtifacts: the agent owns
// the reader roster and is the only layer that can tell a dual-interface unit's
// two slots apart. The prompter renders them and parses none of them.
inline constexpr const char* kOptReaderModel = "reader_model";
// A CLOSED vocabulary (the agent library's readerInterfaceToken), not prose. The agent has no
// localisation, so any English wording it composed would be unfixable by a
// prompter -- the agent keeps the judgement, the prompter keeps the words. An
// unrecognised value is treated as "unknown".
inline constexpr const char* kOptReaderInterface = "reader_interface";
// The literal PC/SC name, for a details affordance. Long enough to push the
// entry field off a small screen, so it never belongs in the chrome itself.
inline constexpr const char* kOptReaderFull = "reader_full";

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
//                the closed kind and reply-status vocabularies; the prompter
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
//     reply vocabulary, exactly as before.
//   * old caller x new prompter -- the key is absent, so the switch affordance
//     is never constructed and PromptReplyStatus::OkMrz is structurally unmintable.
// The key is meaningful ONLY on kind "can"; a request of any other kind that
// carries it renders no switch and answers with today's status vocabulary.
inline constexpr const char* kOptAltKinds = "alt_kinds";
// What the ALTERNATIVE form offered by kOptAltKinds is worth, as the same kind
// of DURATION as kOptDeadlineMs: milliseconds from the moment the window is
// SHOWN, never an increment on kOptDeadlineMs. A prompter that honours the
// switch RE-BASES its clock on this value minus what the window has already
// been standing -- a fresh copy granted on top of what was already spent would
// let one window outlive the transport carrying it.
//
// Meaningful only alongside kOptAltKinds; absent or 0 leaves the clock exactly
// as kOptDeadlineMs armed it, which is what an agent that predates this key
// sends and what its windows must keep doing.
inline constexpr const char* kOptAltDeadlineMs = "alt_deadline_ms";

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

// The reply status (the first tuple element of RequestSecret/RequestSecrets)
// is the agent library's PromptReplyStatus, spelled by replyStatusToken().
// Two words carry a rule of THIS transport:
//
//   * OkMrz ("ok_mrz") is minted INSTEAD of Ok when, and only when, the
//     request was kind "can", carried kOptAltKinds containing kKindMrz, and
//     the user switched the dialog to the MRZ form before accepting: the
//     secret_fd then carries an MRZ payload, not a CAN. Minting is gated on the
//     same offer the dialog rendered, so "offered" and "minted" cannot diverge;
//     a caller that never made the offer treats it as it treats any unknown
//     word -- an error, never a successful CAN.
//   * Unauthorized pairs with a zero-byte sealed memfd and answers a caller
//     that fails the prompter's binary-identity gate, so no dialog shows and no
//     secret can be harvested. The agent never legitimately receives it.

} // namespace LibreLinux::PrompterWire
