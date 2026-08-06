#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# Level-deferral acceptance runner: same bring-up as run-hw-smoke.sh (private
# session bus, headless auto-prompter, PIN gate armed around exactly one call),
# but it SEEDS THE AGENT CONFIG first so the run can prove which level the
# agent resolves for a request that carries none.
#
# Secrets are inherited from the caller env (LIBRESCRS_SIGN_PIN) and never
# appear on a command line.
#
#   Usage: LIBRESCRS_SIGN_PIN=xxxx PROOF_DEFAULT_LEVEL=b-lta \
#          [PROOF_TSA_URL=https://...] ./run-level-proof.sh
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "${HERE}/.." && pwd)"
export AGENT_BIN="${REPO}/build/agent/librescrs-agent"
export AUTO_PROMPTER="${HERE}/auto-prompter"
export MODULE="${REPO}/build/pkcs11-module/librescrs-pkcs11-agent.so"
# shellcheck source=lib-env.sh
source "${HERE}/lib-env.sh"
librescrs_export_lm_paths "${REPO}" || exit 1
export E2E_LIB="${HERE}/lib-harness.sh"
export TEST_BIN="${HERE}/sign-proof"
# Build like the sibling runner does, rather than failing with "missing binary"
# on a fresh checkout and leaving the reader to find build.sh themselves.
"${HERE}/build.sh" || { echo "BUILD FAILED" >&2; exit 1; }

RUNDIR="$(mktemp -d /tmp/librescrs-level.XXXXXX)"; export RUNDIR
export XDG_CONFIG_HOME="${RUNDIR}/config" XDG_CACHE_HOME="${RUNDIR}/cache" XDG_RUNTIME_DIR="${RUNDIR}/runtime"
mkdir -p "$XDG_CONFIG_HOME/librescrs" "$XDG_CACHE_HOME" "$XDG_RUNTIME_DIR"; chmod 700 "$XDG_RUNTIME_DIR"

# --- the whole point of this runner: a configured, NON-default policy ---------
CONF="${XDG_CONFIG_HOME}/librescrs/agent.conf"
{
  echo "DefaultLevel=${PROOF_DEFAULT_LEVEL:?PROOF_DEFAULT_LEVEL required}"
  [[ -n "${PROOF_TSA_URL:-}" ]] && echo "TsaUrl=${PROOF_TSA_URL}"
} > "$CONF"
echo "=== agent.conf ==="; cat "$CONF"

export GATE="${RUNDIR}/prompt.gate"
export LIBRESCRS_PROMPTER_GATE="$GATE"
export LIBRESCRS_OUT_DIR="${RUNDIR}/out"; mkdir -p "$LIBRESCRS_OUT_DIR"

[[ -x "$AGENT_BIN" && -x "$AUTO_PROMPTER" && -f "$MODULE" && -x "$TEST_BIN" ]] || { echo "missing binary" >&2; exit 1; }

dbus-run-session -- bash -c '
  set -uo pipefail
  source "$E2E_LIB" || exit 1
  librescrs_harness_up || exit $?
  echo "=== arming gate + running the ONE sign ==="
  touch "$GATE"
  "$TEST_BIN"
  RC=$?
  rm -f "$GATE"
  echo "=== PROOF EXIT RC=$RC ==="
  echo "--- agent.log (tail) ---"; tail -30 "$RUNDIR/agent.log"
  echo "--- prompter.log ---"; cat "$RUNDIR/prompter.log"
  echo "RUNDIR=$RUNDIR"
  exit $RC
'
