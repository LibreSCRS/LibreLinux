// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "ObjectModel.h"

namespace LibreSCRS::Pkcs11Agent {

ObjectModel ObjectModel::build(const AgentSnapshot& snapshot)
{
    ObjectModel model;
    model.slots.reserve(snapshot.readers.size());

    for (const auto& reader : snapshot.readers) {
        Slot slot;
        slot.readerPath = reader.readerPath;
        slot.tokenPresent = reader.hasCard;
        slot.protectedAuthPath = true; // the agent prompter is the protected auth path
        slot.tokenLabel = reader.tokenLabel;

        if (!reader.hasCard) {
            model.slots.push_back(std::move(slot));
            continue;
        }

        bool anySign = false;
        bool anyDecrypt = false;
        bool anyHashOnCard = false;

        for (const auto& cert : reader.certs) {
            // Only signing certs (a paired on-card key + signing-suitable
            // keyUsage) surface as PKCS#11 objects.
            if (!cert.signingCapable)
                continue;

            // CKO_CERTIFICATE — public DER, fetched lazily by the module.
            Object certObj;
            certObj.cls = CKO_CERTIFICATE;
            certObj.ckaId = cert.ckaId;
            certObj.label = cert.label;
            certObj.certId = cert.certId;
            slot.objects.push_back(std::move(certObj));

            // CKO_PUBLIC_KEY — sharing the cert's CKA_ID.
            Object pubObj;
            pubObj.cls = CKO_PUBLIC_KEY;
            pubObj.ckaId = cert.ckaId;
            pubObj.label = cert.label;
            pubObj.certId = cert.certId;
            pubObj.modulusBits = cert.modulusBits;
            slot.objects.push_back(std::move(pubObj));

            // CKO_PRIVATE_KEY — non-extractable; capabilities gated by the agent.
            Object privObj;
            privObj.cls = CKO_PRIVATE_KEY;
            privObj.ckaId = cert.ckaId;
            privObj.label = cert.label;
            privObj.certId = cert.certId;
            privObj.modulusBits = cert.modulusBits;
            privObj.sign = cert.canSign;
            privObj.decrypt = cert.canDecrypt;
            slot.objects.push_back(std::move(privObj));

            anySign = anySign || cert.canSign;
            anyDecrypt = anyDecrypt || cert.canDecrypt;
            anyHashOnCard = anyHashOnCard || (cert.canSign && cert.signsHashOnCard);
        }

        // Mechanism table is capability-advertised per card family — at most one
        // RSA mechanism per slot, never both, chosen by where the SHA-256 digest
        // is computed. A token whose keys are all capability-gated (no canSign,
        // no canDecrypt) advertises NOTHING.
        // The module is libcrypto-free in BOTH cases: it never hashes — it
        // forwards the caller's bytes verbatim and the CARD or the CALLER owns
        // the digest.
        //
        //  * DigestInfo family (opensc/PKS, PreReadAuthMethod "None"): advertise
        //    CKM_RSA_PKCS. The caller supplies the complete, ready-to-pad block
        //    (a full DigestInfo for sign, or the ciphertext for decrypt) and the
        //    agent runs the raw private-key op on-card. The combined
        //    CKM_SHAxxx_RSA_PKCS mechanisms are NOT advertised here — the module
        //    cannot build the DigestInfo, so honouring them would sign a
        //    never-hashed message. NSS/Firefox, the openssl engine and the LM
        //    AdES path all drive CKM_RSA_PKCS with a pre-built DigestInfo.
        //  * Hash-on-card family (pkcs15/NAM IAS-ECC SSCD, PreReadAuthMethod
        //    "Can"): advertise CKM_SHA256_RSA_PKCS, sign-only. The card
        //    REJECTS a caller-supplied DigestInfo and instead hashes the RAW
        //    message itself, so the caller supplies the message bytes and the
        //    module relays them verbatim (still no host-side hashing). Decrypt is
        //    not advertised (the pkcs15 plugin has no decipher primitive).
        if (anyHashOnCard) {
            slot.mechanisms.push_back(CKM_SHA256_RSA_PKCS);
        } else if (anySign || anyDecrypt) {
            // CKM_RSA_PKCS covers raw RSA PKCS#1 v1.5 sign AND/OR decrypt; the
            // per-key CKA_SIGN / CKA_DECRYPT flags decide which the caller may use.
            slot.mechanisms.push_back(CKM_RSA_PKCS);
        }

        model.slots.push_back(std::move(slot));
    }

    return model;
}

} // namespace LibreSCRS::Pkcs11Agent
