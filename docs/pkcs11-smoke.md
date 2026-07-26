<!--
SPDX-License-Identifier: LGPL-2.1-or-later
SPDX-FileCopyrightText: 2026 hirashix0
-->

# Manual real-card smoke — the PKCS#11 agent-proxy module

This is the **manual** verification procedure for the agent-proxy PKCS#11
module (`librescrs-pkcs11-agent.so`) against **real cards** and **real
consumers** (Firefox, Thunderbird, OpenSSH, `pkcs11-tool`). The automated suite
(`ctest`) covers the C_* ABI, the security properties and the RPC plumbing
against a fake card backend; this document covers the things that need a
physical reader + a card + a desktop app, and **records the empirical outcomes**
of exercising the module against real hardware.

> **No PINs in this document, ever.** The module advertises
> `CKF_PROTECTED_AUTHENTICATION_PATH`: the **agent prompter** is the only PIN/CAN
> sink, and any PIN an app passes to `C_Login` is ignored and never put on the
> wire. You type the PIN/CAN into the prompter when it appears. A wrong **signing
> PIN** decrements an irreversible on-card counter — if the prompter rejects a
> PIN, **stop** and recheck before retrying (the agent does not retry for you).

## Architecture recap (what you are testing)

```
app (Firefox / Thunderbird / ssh / pkcs11-tool)
  └─ dlopen(librescrs-pkcs11-agent.so)        ← in-process, deployment (a)
       └─ D-Bus (session bus)
            └─ librescrs-agent                  ← the single card owner + policy
                 ├─ prompter (PIN/CAN)          ← CKF_PROTECTED_AUTHENTICATION_PATH
                 └─ PC/SC → card
```

The module holds **no card connection and no secret**; every crypto op runs
on-card inside the agent. Deployment **(b)** (out-of-process isolation) swaps the
in-process `dlopen` for `p11-kit remote`/`p11-kit server` + the stock
`p11-kit-client.so` — same `.so`, config-only difference.

## 0. Prerequisites

- A working dogfood install (see `docs/dogfooding.md`): a **running**
  `librescrs-agent` (`systemctl --user status librescrs-agent`) and a prompter,
  plus PC/SC (`systemctl status pcscd`) and a reader.
- A card. **PKS** (Serbian qualified-signature card, contact, PIN) signs +
  decrypts (DigestInfo `CKM_RSA_PKCS`). **NAM** (ID card over PACE) signs on-card
  (`CKM_SHA256_RSA_PKCS`, hash-on-card); decrypt is not supported — see §6.

## 1. Install + register the module with p11-kit

A system (package) install drops the files in the right places automatically:

| File | Destination (system install) |
| --- | --- |
| `librescrs-pkcs11-agent.so` | `pkg-config p11-kit-1 --variable p11_module_path` (`/usr/lib/pkcs11`) |
| `librescrs-agent.module` | `pkg-config p11-kit-1 --variable p11_module_configs` (`/usr/share/p11-kit/modules`) |
| `librescrs-p11-server.service` | the systemd **user** unit dir (deployment b only) |

For a throwaway VM/container test from a user-prefix build, copy them in:

```bash
sudo install -Dm644 build/pkcs11-module/librescrs-pkcs11-agent.so \
    /usr/lib/pkcs11/librescrs-pkcs11-agent.so
sudo install -Dm644 build/pkcs11-module/librescrs-agent.module \
    /usr/share/p11-kit/modules/librescrs-agent.module
```

## 2. Confirm the module loads + advertises the protected auth path

```bash
# Standalone, no NSS wiring needed:
pkcs11-tool --module /usr/lib/pkcs11/librescrs-pkcs11-agent.so -T
# Through p11-kit's proxy (once the .module is installed):
p11-kit list-modules | grep -A6 librescrs
```

**Expected:** a token is listed; the token flags include **`PIN pad present`**
(that is how `pkcs11-tool` renders `CKF_PROTECTED_AUTHENTICATION_PATH`) and
**`login required`**; the slot reflects the inserted reader. Then:

```bash
pkcs11-tool --module /usr/lib/pkcs11/librescrs-pkcs11-agent.so -O   # objects
```

**Expected:** a `Private Key Object` and a `Certificate Object` per signing cert
on the card.

## 3. Firefox — TLS client-auth (PKS)

NSS auto-discovers p11-kit modules where the distro wires `p11-kit-proxy` into
NSS. Where it does not, register the module:

- GUI: *Settings → Privacy & Security → Security Devices → Load* →
  `/usr/lib/pkcs11/librescrs-pkcs11-agent.so`; **or**
- CLI fallback:
  ```bash
  modutil -dbdir sql:$HOME/.pki/nssdb -add librescrs \
      -libfile /usr/lib/pkcs11/librescrs-pkcs11-agent.so
  ```

Browse to a TLS server that **requests a client certificate** (any mTLS test
endpoint). **Expected:** Firefox offers the card cert; on selection the **agent
prompter** appears once to collect the PIN; the handshake completes. Reload /
issue several requests — confirm **no re-prompt storm** (the lease covers
repeated signs within its idle window).

## 4. Thunderbird — S/MIME decrypt (PKS)

Load the same module in Thunderbird (*Settings → Privacy & Security → Security
Devices → Load*, or shared NSS db). Open an S/MIME message **encrypted to the
card cert**. **Expected:** the prompter collects the PIN once; the message body
decrypts (`C_Decrypt(CKM_RSA_PKCS)` → agent `Decrypt`).

## 5. OpenSSH — `PKCS11Provider`

```bash
ssh -I /usr/lib/pkcs11/librescrs-pkcs11-agent.so user@host
# or, persistently, in ~/.ssh/config:
#   PKCS11Provider /usr/lib/pkcs11/librescrs-pkcs11-agent.so
```

**Expected:** the prompter collects the PIN; auth succeeds. Leave the connection
idle past the lease idle-timeout, then trigger another op (e.g. a new session) —
confirm it **re-logins** (re-prompts) rather than hard-failing.

## 6. NAM — hash-on-card signing, decrypt gated

A **NAM** (ID-card-over-PACE, IAS-ECC SSCD) token signs on-card: `pkcs11-tool -T`
shows the token advertising **`CKM_SHA256_RSA_PKCS`** (sign-only — the card
computes the SHA-256 digest from the raw message), and its private key carries
`CKA_SIGN`. The DigestInfo `CKM_RSA_PKCS` mechanism is **not** advertised for NAM
(a hash-on-card card never receives a caller-built DigestInfo).

Decrypt remains gated: NAM carries neither a decrypt mechanism nor `CKA_DECRYPT`,
and `C_DecryptInit` returns `CKR_MECHANISM_INVALID`. On-card decrypt would need
MSE-CT / PSO-DECIPHER over SM, which is not implemented for this family.

As always, the agent prompter is the only PIN sink
(`CKF_PROTECTED_AUTHENTICATION_PATH`): never feed a placeholder PIN through the
module — a wrong signing PIN risks an irreversible NAM lockout.

## 7. Deployment (b) — out-of-process isolation (optional)

Two opt-in forms (see the comments in `librescrs-agent.module`):

1. **Per-client pipe, no daemon** — in the `.module`, comment out `module:` and
   enable `remote: |p11-kit remote …/librescrs-pkcs11-agent.so`. p11-kit spawns
   one `p11-kit remote` child per consumer; nothing to start.
2. **Shared server** — `systemctl --user enable --now librescrs-p11-server`,
   then enable `server-address:` in the `.module` so apps load the stock
   `p11-kit-client.so` against the per-user socket.

Verify the server socket is owner-only:

```bash
systemctl --user start librescrs-p11-server
stat -c '%a %U %F' "$XDG_RUNTIME_DIR/p11-kit/"*   # expect: 600 <you> socket
```

## 8. Recorded HW-empirical items (fill in on a real run)

Two questions could not be answered from the man pages / fake-agent suite and
must be settled on hardware. **Record the verified answers in the knowledge-repo
close-out note** (and, if they change behaviour, get owner sign-off):

1. **Lease vs PIN persistence.** Does **one** prompter PIN-verify at `C_Login`
   cover **many** subsequent `SignRaw`/`Decrypt` ops within the held agent
   session (i.e. the card keeps the VERIFY state for the channel lifetime), or
   does each card op re-require the PIN (forcing the lease to cache the PIN to
   avoid a prompt storm)?
   - **Why it matters:** if the card drops VERIFY per op, the current "Login =
     consent, lease = grant, never cache the PIN" model would re-prompt on every
     sign. The design explicitly does **not** cache PINs, so a per-op-VERIFY card
     needs an owner decision (accept the re-prompts vs add bounded PIN caching).
   - **How to test:** in §3 (Firefox) or §5 (ssh), do several signs inside the
     idle window and count prompter appearances. **One** prompt = lease model is
     correct as-is. **Per-op** prompts = escalate to owner.
   - **Result:** ___ (one prompt covers N signs / re-prompts per op) — date, card.

2. **CAN-prompt-on-enumerate (NAM).** Does cert **enumeration** of a NAM card
   (`C_GetSlotList`/`FindObjects`, e.g. when Firefox lists devices) trigger a
   **CAN** prompt — because reading the cert needs the PACE channel — and is
   that acceptable / cached for the session?
   - **Why it matters:** an enumerate-time CAN prompt on every device-list scan
     would be a poor UX; if the agent caches the PACE channel per card, the CAN
     is asked once.
   - **How to test:** insert a NAM card, open Firefox *Security Devices* (or run
     `pkcs11-tool -O`) twice; observe whether the CAN prompt appears each time.
   - **Result:** ___ (no prompt / once-cached / every enumerate) — date, card.

Also record, while you are on hardware:

- which `SC_ALGORITHM_RSA_PAD_*` decipher flag the PKS card accepted for
  `C_Decrypt` (relevant to the LM decipher seam);
- the `p11-kit server` socket mode actually observed (`stat` in §7 — expected
  `600`);
- whether NSS auto-discovered the module on your distro or needed `modutil`.
