#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# Self-contained through-the-agent HW smoke runner: brings up a private session
# bus with the agent daemon + headless auto-prompter, arms the PIN gate ONLY
# around the one test, runs it, disarms, tears down. Secrets (LIBRESCRS_SIGN_PIN
# / LIBRESCRS_CAN / LIBRESCRS_MRZ) are inherited from the caller env — never
# passed on a command line.
#   Usage: LIBRESCRS_SIGN_PIN=xxxx ./run-hw-smoke.sh <test-binary> [gtest_filter]
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
export TEST_BIN="${1:?test binary required}"
export TEST_FILTER="${2:-}"

RUNDIR="$(mktemp -d /tmp/librescrs-hw.XXXXXX)"; export RUNDIR
export XDG_CONFIG_HOME="${RUNDIR}/config" XDG_CACHE_HOME="${RUNDIR}/cache" XDG_RUNTIME_DIR="${RUNDIR}/runtime"
mkdir -p "$XDG_CONFIG_HOME" "$XDG_CACHE_HOME" "$XDG_RUNTIME_DIR"; chmod 700 "$XDG_RUNTIME_DIR"
export GATE="${RUNDIR}/prompt.gate"
export LIBRESCRS_PROMPTER_GATE="$GATE"

[[ -x "$AGENT_BIN" && -x "$AUTO_PROMPTER" && -f "$MODULE" && -x "$TEST_BIN" ]] || { echo "missing binary" >&2; exit 1; }

dbus-run-session -- bash -c '
  set -uo pipefail
  source "$E2E_LIB" || exit 1
  librescrs_harness_up || exit $?
  echo "=== arming gate + running test ==="
  touch "$GATE"
  if [[ -n "$TEST_FILTER" ]]; then
    LIBRESCRS_HW_SMOKE=1 LIBRESCRS_SMOKE_MODULE="$MODULE" "$TEST_BIN" --gtest_filter="$TEST_FILTER"
  else
    LIBRESCRS_HW_SMOKE=1 LIBRESCRS_SMOKE_MODULE="$MODULE" "$TEST_BIN"
  fi
  RC=$?
  rm -f "$GATE"
  echo "=== TEST EXIT RC=$RC ==="
  echo "--- agent.log (tail) ---"; tail -25 "$RUNDIR/agent.log"
  echo "--- auto-prompter.log ---"; cat "$RUNDIR/prompter.log"
  exit $RC
'
