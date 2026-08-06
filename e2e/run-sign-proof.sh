#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# One-command through-the-agent sign proof: builds the client, runs it under the
# HW smoke harness (arms the PIN gate around EXACTLY ONE sign), and — on success
# — cryptographically verifies the detached CAdES artifact with openssl.
#
# Secrets are passed ONLY via env (LIBRESCRS_CAN / LIBRESCRS_SIGN_PIN), never on
# a command line. The client performs a single sign and never retries.
#
# LIBRESCRS_PROOF_LEVEL pins a signature level; left unset the request carries
# none, and the run proves which level the agent resolves on its own.
#
#   Usage: LIBRESCRS_CAN=nnnnnn LIBRESCRS_SIGN_PIN=nnnnnn ./run-sign-proof.sh
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT_DIR="${LIBRESCRS_OUT_DIR:-/tmp/librescrs-e2e}"
ART="${OUT_DIR}/sign-cades.p7s"
DOC="${OUT_DIR}/sign-doc.txt"
export LIBRESCRS_OUT_DIR="$OUT_DIR"

# No certificate is pinned here. A default would bake one operator's own card
# into the repository, and it is not needed: unset, the client takes the first
# signing-capable certificate the card offers. Set LIBRESCRS_CERT_ID (or
# LIBRESCRS_CERT_PREFIX) to skip the discovery read — neither is secret, both
# derive from a public certificate.

"${HERE}/build.sh" || { echo "BUILD FAILED" >&2; exit 1; }

rm -f "$ART"
"${HERE}/run-hw-smoke.sh" "${HERE}/sign-proof"
RC=$?
echo "=== client RC=$RC ==="

if [[ $RC -eq 0 && -s "$ART" ]]; then
    echo "=== openssl cms -verify (detached CAdES over the document; chain check skipped) ==="
    VRC=0
    openssl cms -verify -no_signer_cert_verify -inform DER -in "$ART" \
        -content "$DOC" -out /dev/null || VRC=$?
    echo "=== openssl verify RC=$VRC ==="
    if [[ $VRC -ne 0 ]]; then
        echo "=== VERIFY FAILED — the artifact is not a valid signature over the document ===" >&2
        exit 1
    fi
else
    echo "=== NO artifact — sign did not succeed; nothing to verify ==="
fi
exit $RC
