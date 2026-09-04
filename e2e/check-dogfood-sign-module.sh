#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# GATING dogfood signing guard.
#
# The native AdES signing path dlopens the LM PKCS#11 module
# `librescrs-pkcs11.so` by bare name. A dogfood/user install puts LM under its
# OWN prefix (~/.local/librescrs) that is not exe-relative to the agent, so
# SigningService::resolvePkcs11Module()'s relative probing misses it and every
# Card1.Sign fails "cannot open shared object file" — while the build-tree
# run-hw-smoke.sh masks the bug by exporting LIBRESCRS_PKCS11_MODULE itself.
#
# This check validates the DEPLOYED agent's OWN module resolution WITHOUT any
# export: it resolves the module the way the running agent would — reading the
# absolute path the middleware was CONFIGURED with out of the library the agent
# actually loads, which is the resolver's last candidate and the one that
# matches under every installed layout — then
# dlopens it and confirms C_GetFunctionList returns CKR_OK. It needs NO card,
# PIN, or prompter, so it runs in CI and post-install; it deterministically
# catches the missing/wrong/unloadable signing-module-path regression class.
#
# Exit: 0 = module resolves and loads (or agent not installed -> SKIP);
#       non-zero = the deployed agent could not load its signing module.
set -uo pipefail

SERVICE=librescrs-agent.service

# --- 1. resolve the module the DEPLOYED agent would use --------------------
module=""
src=""

# (a) the unit's own Environment (what the user-install build bakes in).
if command -v systemctl >/dev/null 2>&1; then
    env_line="$(systemctl --user show "$SERVICE" -p Environment 2>/dev/null)"
    module="$(printf '%s\n' "$env_line" | grep -oE 'LIBRESCRS_PKCS11_MODULE=[^ ]+' | head -1 | cut -d= -f2-)"
    [ -n "$module" ] && src="unit Environment"
fi

# Locate the installed agent binary (for the SKIP check and the FHS fallback).
exe=""
if command -v systemctl >/dev/null 2>&1; then
    exe="$(systemctl --user show "$SERVICE" -p ExecStart 2>/dev/null \
           | grep -oE 'path=[^ ;]+' | head -1 | cut -d= -f2-)"
fi

if [ -z "$module" ] && [ -z "$exe" ]; then
    echo "SKIP: $SERVICE not installed (no unit) — nothing to validate."
    exit 0
fi

# (b) the build-configured absolute the middleware baked into the library the
#     DEPLOYED agent actually loads. Under every installed layout — system
#     package or per-user prefix — this is the candidate that matches. We do not
#     re-implement the resolver's candidate order here: we read the value the
#     middleware itself was configured with, so this check follows the resolver
#     instead of restating an old copy of it. (It is a PRIVATE compile
#     definition, so the shell cannot see it any other way.)
if [ -z "$module" ] && [ -n "$exe" ]; then
    for t in ldd strings; do
        command -v "$t" >/dev/null 2>&1 || {
            echo "FAIL: $t not available; cannot resolve the deployed module." >&2
            exit 2
        }
    done
    # ${env_line:-}: this script runs under `set -u` and env_line is only
    # assigned inside the systemctl branch above.
    ld_path="$(printf '%s\n' "${env_line:-}" \
               | grep -oE 'LD_LIBRARY_PATH=[^ ]+' | head -1 | cut -d= -f2-)"
    signing_lib="$(LD_LIBRARY_PATH="${ld_path:-}" ldd "$exe" 2>/dev/null \
                   | awk '/libLibreSCRS_Signing\.so/ {print $3; exit}')"
    if [ -n "$signing_lib" ] && [ -e "$signing_lib" ]; then
        module="$(strings -a "$signing_lib" \
                  | grep -E '^/.+/pkcs11/librescrs-pkcs11\.(so|dylib)$' | head -1)"
        [ -n "$module" ] && src="build-configured absolute in $signing_lib"
    fi
fi

# (c) FHS fallback: mirror resolvePkcs11Module() candidate #4
#     (<exe-dir>/../lib/pkcs11/librescrs-pkcs11.so). This is what a SYSTEM
#     package relies on when the library carries no configured absolute.
if [ -z "$module" ] && [ -n "$exe" ]; then
    exedir="$(cd "$(dirname "$exe")" 2>/dev/null && pwd)"
    module="${exedir%/*}/lib/pkcs11/librescrs-pkcs11.so"
    src="exe-relative FHS layout"
fi

echo "Deployed agent signing module (via $src):"
echo "  $module"

# --- 2. it must exist -----------------------------------------------------
if [ ! -e "$module" ]; then
    echo "FAIL: module does not exist — Card1.Sign will fail 'cannot open shared object file'." >&2
    echo "      Two causes, and only these two: the middleware was built without" >&2
    echo "      LIBRESCRS_PKCS11_MODULE_FULL_PATH, so the library carries no" >&2
    echo "      configured absolute; or the module is not installed where that" >&2
    echo "      build said it would be." >&2
    exit 1
fi

# --- 3. it must dlopen and expose a working C_GetFunctionList --------------
python3 - "$module" <<'PY'
import ctypes, sys
mod = sys.argv[1]
try:
    lib = ctypes.CDLL(mod)
except OSError as e:
    print(f"FAIL: dlopen('{mod}') -> {e}", file=sys.stderr)
    sys.exit(2)
fn = getattr(lib, "C_GetFunctionList", None)
if fn is None:
    print("FAIL: loaded but C_GetFunctionList is missing — not a PKCS#11 module.", file=sys.stderr)
    sys.exit(3)
p = ctypes.c_void_p()
rc = fn(ctypes.byref(p))
if rc != 0 or not p.value:
    print(f"FAIL: C_GetFunctionList rc={rc} (CKR_OK=0), list={'set' if p.value else 'null'}.", file=sys.stderr)
    sys.exit(4)
print("PASS: module dlopens and C_GetFunctionList returns CKR_OK with a valid list.")
PY
rc=$?
[ $rc -eq 0 ] && echo "GATE PASS: the deployed agent can load its signing module." \
             || echo "GATE FAIL: the deployed agent cannot load its signing module (rc=$rc)." >&2
exit $rc
