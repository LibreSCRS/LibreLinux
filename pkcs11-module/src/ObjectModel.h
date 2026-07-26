// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Pure mapping: an agent snapshot (readers/cards/signing certs + per-cert
// capability flags) -> PKCS#11 slots / tokens / objects / mechanisms. No D-Bus,
// no card I/O, no crypto — fully unit-testable.
//
// One slot per reader. CKF_TOKEN_PRESENT iff the reader has a card. For each
// signing cert on a present card the model emits three objects sharing one
// CKA_ID: a CKO_CERTIFICATE, a CKO_PUBLIC_KEY, and a non-extractable
// CKO_PRIVATE_KEY. The private key's CKA_SIGN / CKA_DECRYPT and the token's
// mechanism set are derived ENTIRELY from the agent-reported capabilities
// (canSign / canDecrypt / signsHashOnCard), never from the card type: a
// hash-on-card token (canSign + signsHashOnCard) advertises CKM_SHA256_RSA_PKCS
// sign-only, a DigestInfo token advertises CKM_RSA_PKCS, and a card the agent
// cannot drive (canSign == canDecrypt == false) advertises no mechanisms and a
// key with neither CKA_SIGN nor CKA_DECRYPT.

#pragma once

#include "pkcs11.h"

#include <cstdint>
#include <string>
#include <vector>

namespace LibreSCRS::Pkcs11Agent {

/// @brief One signing certificate reported by the agent for a card.
struct CertEntry
{
    std::string certId;              ///< Opaque stable id (== sha256hex of DER).
    std::string label;               ///< Display label (CKA_LABEL).
    std::vector<std::uint8_t> ckaId; ///< Shared CKA_ID for the cert + key pair.
    bool signingCapable = false;     ///< Paired on-card key + signing-suitable keyUsage.
    bool canSign = false;            ///< Agent can drive on-card RSA sign for this key.
    bool canDecrypt = false;         ///< Agent can drive on-card RSA decrypt for this key.
    bool signsHashOnCard = false;    ///< Card hashes on-card (NAM/IAS-ECC): advertise
                                     ///< CKM_SHA256_RSA_PKCS (raw message in), not
                                     ///< CKM_RSA_PKCS (caller-built DigestInfo).
    std::uint32_t modulusBits = 0;   ///< RSA modulus size in bits (0 if unknown).
};

/// @brief One reader (+ optional card) reported by the agent.
struct ReaderState
{
    std::string readerPath;       ///< Reader1 D-Bus object path.
    bool hasCard = false;         ///< A card is seated.
    std::string tokenLabel;       ///< Token label for CK_TOKEN_INFO.
    std::vector<CertEntry> certs; ///< Signing certs on the card (empty if none / no card).
};

/// @brief A full agent enumeration snapshot.
struct AgentSnapshot
{
    std::vector<ReaderState> readers;
};

/// @brief A PKCS#11 object (cert or key) derived from a CertEntry.
struct Object
{
    CK_OBJECT_CLASS cls = CKO_DATA;
    std::vector<std::uint8_t> ckaId;
    std::string label;
    std::string certId;            ///< Owning cert id (for lazy CKA_VALUE / agent calls).
    std::uint32_t modulusBits = 0; ///< For key objects: RSA modulus bits.
    bool sign = false;             ///< CKA_SIGN (private key).
    bool decrypt = false;          ///< CKA_DECRYPT (private key).
};

/// @brief A PKCS#11 slot (one per reader) + its token state.
struct Slot
{
    std::string readerPath;
    bool tokenPresent = false;
    bool protectedAuthPath = true; ///< Always true — the agent prompter collects the PIN.
    std::string tokenLabel;
    std::vector<Object> objects;               ///< Empty when no token present.
    std::vector<CK_MECHANISM_TYPE> mechanisms; ///< Capability-advertised; empty for gated tokens.
};

/// @brief The complete slot/token/object/mechanism model.
struct ObjectModel
{
    std::vector<Slot> slots;

    /// @brief Build the model from an agent snapshot (pure).
    [[nodiscard]] static ObjectModel build(const AgentSnapshot& snapshot);
};

} // namespace LibreSCRS::Pkcs11Agent
