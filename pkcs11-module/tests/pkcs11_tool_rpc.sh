#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# SPDX-FileCopyrightText: 2026 hirashix0
#
# RPC integration smoke: drive the EXTERNAL consumer pkcs11-tool
# against the real librescrs-pkcs11-agent.so module, with the test FakeAgent as
# the card backend on a private session bus. This is the in-process deployment
# (a) path end-to-end: pkcs11-tool -> dlopen(module) -> D-Bus -> FakeAgent.
#
# A full p11-kit-ROUTED run (apps reaching the module via a .module file in
# /usr/share/p11-kit/modules, or out-of-process via `p11-kit server`) is NOT
# exercised here — it needs a system install + a live p11-kit and is covered by
# the documented manual smoke. This script asserts the module is a
# well-formed PKCS#11 provider that a real consumer can enumerate.
#
# Invoked under dbus-run-session by CTest. Args:
#   $1 = path to FakeAgentMain
#   $2 = path to librescrs-pkcs11-agent.so
set -euo pipefail

FAKE_AGENT="$1"
MODULE="$2"

# Self-skip under AddressSanitizer: a stock (non-instrumented) pkcs11-tool that
# dlopens the ASan-instrumented module aborts with "ASan runtime does not come
# first in initial library list" (ASan must be the first loaded runtime, which a
# late dlopen by an uninstrumented host cannot satisfy). This is an artefact of
# the external-consumer harness, not a module defect, so the ASan suite skips it;
# the release-strict run still exercises it for real. Detect ASan by whether the
# built module links libasan (deterministic, no CMake plumbing needed). LD_PRELOAD
# of libasan would work but is fragile across toolchains, so we skip instead.
if command -v ldd >/dev/null 2>&1 && ldd "${MODULE}" 2>/dev/null | grep -qiE 'libasan|libclang_rt\.asan'; then
    echo "module is ASan-instrumented; stock pkcs11-tool cannot dlopen it (ASan-not-first); skipping" >&2
    exit 77 # ctest SKIP
fi

PKCS11_TOOL="$(command -v pkcs11-tool || true)"
if [[ -z "${PKCS11_TOOL}" ]]; then
    echo "pkcs11-tool not found; skipping RPC integration smoke" >&2
    exit 77 # ctest SKIP
fi

# Start the fake agent; wait for its READY line.
"${FAKE_AGENT}" 1 None &
FAKE_PID=$!
cleanup() { kill "${FAKE_PID}" 2>/dev/null || true; wait "${FAKE_PID}" 2>/dev/null || true; }
trap cleanup EXIT

# Wait (bounded) for the well-known name to appear by polling pkcs11-tool -T.
ready=0
for _ in $(seq 1 50); do
    if "${PKCS11_TOOL}" --module "${MODULE}" -T 2>/dev/null | grep -qi 'token'; then
        ready=1; break
    fi
    sleep 0.1
done
if [[ "${ready}" -ne 1 ]]; then
    echo "module never enumerated a token via pkcs11-tool" >&2
    exit 1
fi

echo "== pkcs11-tool -L (slots) =="
"${PKCS11_TOOL}" --module "${MODULE}" -L

echo "== pkcs11-tool -T (token info) =="
TINFO="$("${PKCS11_TOOL}" --module "${MODULE}" -T)"
echo "${TINFO}"
# The token MUST advertise CKF_PROTECTED_AUTHENTICATION_PATH (the agent prompter
# is the PIN sink; pkcs11-tool must not collect a PIN itself). pkcs11-tool renders
# this flag as "PIN pad present" in the token-flags line.
echo "${TINFO}" | grep -qiE 'PIN pad present|protected authentication path' \
    || { echo "token did not advertise the protected authentication path flag" >&2; exit 1; }

echo "== pkcs11-tool -O (objects) =="
OBJS="$("${PKCS11_TOOL}" --module "${MODULE}" -O)"
echo "${OBJS}"
# A private key + a certificate object must be enumerable (the FakeAgent's cert).
echo "${OBJS}" | grep -qi 'Private Key' || { echo "no private key object enumerated" >&2; exit 1; }
echo "${OBJS}" | grep -qiE 'Certificate' || { echo "no certificate object enumerated" >&2; exit 1; }

echo "RPC integration smoke OK"
