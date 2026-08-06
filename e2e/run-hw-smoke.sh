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
  # Auto-prompter FIRST + claim the name, so the agent never dbus-activates the
  # installed (real) pinentry.
  "$AUTO_PROMPTER" > "$RUNDIR/prompter.log" 2>&1 & PROMPTER_PID=$!
  for _ in $(seq 1 50); do busctl --user status org.librescrs.Prompter1 >/dev/null 2>&1 && break; sleep 0.1; done
  # The org.librescrs polkit policy is not installed on this box (needs root), so
  # an installed-policy PolkitAuthorizer would deny the (default-allow) login as
  # an "unregistered action". Make the system bus unreachable to the agent so it
  # uses the shipping DefaultAuthorizer fallback, whose sign/login allow decision
  # is identical (only the trust/TSA tier differs, unused here).
  DBUS_SYSTEM_BUS_ADDRESS="unix:path=${RUNDIR}/no-system-bus" \
  "$AGENT_BIN"     > "$RUNDIR/agent.log"    2>&1 & AGENT_PID=$!
  cleanup(){ rm -f "$GATE"; kill "$PROMPTER_PID" "$AGENT_PID" 2>/dev/null; wait 2>/dev/null; }
  trap cleanup EXIT
  up=0
  for _ in $(seq 1 100); do
    busctl --user status org.librescrs.Agent >/dev/null 2>&1 && { up=1; break; }
    kill -0 "$AGENT_PID" 2>/dev/null || break
    sleep 0.1
  done
  if [[ $up -ne 1 ]]; then echo "=== AGENT DID NOT COME UP ==="; cat "$RUNDIR/agent.log"; exit 1; fi
  # Wait for the agent to finish async card enumeration + export at least one card object.
  card=0
  for _ in $(seq 1 150); do   # up to ~15s
    if busctl --user tree org.librescrs.Agent 2>/dev/null | grep -q "/org/librescrs/Agent/card/"; then card=1; break; fi
    sleep 0.1
  done
  echo "=== names owned; cards exported: $( busctl --user tree org.librescrs.Agent 2>/dev/null | grep -c "/card/" ) (readers: $( busctl --user tree org.librescrs.Agent 2>/dev/null | grep -c "/reader/" )) ==="
  if [[ $card -ne 1 ]]; then echo "=== NO CARD OBJECT EXPORTED ==="; echo "--- agent.log ---"; cat "$RUNDIR/agent.log"; exit 2; fi
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
