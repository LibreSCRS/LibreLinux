#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# Autonomous through-the-agent HW-smoke harness launcher.
#
# Brings up a PRIVATE session bus with the librescrs-agent daemon and the
# headless auto-prompter, waits until BOTH well-known names are owned, prints
# the bus address + PIDs, then BLOCKS so a caller can run a test against it.
#
# This script itself performs NO card / PIN / sign / login operation. It never
# sets a PIN and never creates the safety gate file — that is the caller's job,
# immediately around the one operation it wants to authorize.
#
# Secrets are inherited, not invented: whatever LIBRESCRS_SIGN_PIN / LIBRESCRS_CAN
# / LIBRESCRS_MRZ / LIBRESCRS_PROMPTER_GATE the operator exports before running
# this script is propagated into the private bus for the auto-prompter to read.
#
# Usage:
#   ./launch-e2e.sh                 # bring up agent + auto-prompter, block
#   LIBRESCRS_PLUGIN_DIR=... ./launch-e2e.sh
#
# When ready, the script prints DBUS_SESSION_BUS_ADDRESS. A separate shell can
# then:  export DBUS_SESSION_BUS_ADDRESS=<printed>  and run its test binary.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "${HERE}/.." && pwd)"

AGENT_BIN="${AGENT_BIN:-${REPO}/build/agent/librescrs-agent}"
AUTO_PROMPTER="${AUTO_PROMPTER:-${HERE}/auto-prompter}"
# shellcheck source=lib-env.sh
source "${HERE}/lib-env.sh"
librescrs_export_lm_paths "${REPO}" || exit 1
PLUGIN_DIR="${LIBRESCRS_PLUGIN_DIR}"
GATE="${LIBRESCRS_PROMPTER_GATE:-/tmp/librescrs-e2e/prompt.gate}"

[[ -x "${AGENT_BIN}" ]]      || { echo "missing agent binary: ${AGENT_BIN}" >&2; exit 1; }
[[ -x "${AUTO_PROMPTER}" ]]  || "${HERE}/build.sh"
[[ -d "${PLUGIN_DIR}" ]]     || { echo "missing plugin dir: ${PLUGIN_DIR}" >&2; exit 1; }

# Isolated, throwaway XDG + run dir so nothing touches the real user config.
RUNDIR="$(mktemp -d "${TMPDIR:-/tmp}/librescrs-e2e.XXXXXX")"
export XDG_CONFIG_HOME="${RUNDIR}/config"
export XDG_CACHE_HOME="${RUNDIR}/cache"
export XDG_RUNTIME_DIR="${RUNDIR}/runtime"
mkdir -p "${XDG_CONFIG_HOME}" "${XDG_CACHE_HOME}" "${XDG_RUNTIME_DIR}"
chmod 700 "${XDG_RUNTIME_DIR}"
mkdir -p "$(dirname "${GATE}")"

export LIBRESCRS_PLUGIN_DIR="${PLUGIN_DIR}"
export LIBRESCRS_PROMPTER_GATE="${GATE}"

echo "[launch] run dir       : ${RUNDIR}"
echo "[launch] plugin dir    : ${LIBRESCRS_PLUGIN_DIR}"
echo "[launch] gate file     : ${LIBRESCRS_PROMPTER_GATE} ($( [[ -e ${GATE} ]] && echo present || echo absent ))"
echo "[launch] agent binary  : ${AGENT_BIN}"
echo "[launch] auto-prompter : ${AUTO_PROMPTER}"
echo "[launch] starting private session bus ..."

# Everything below runs inside a fresh dbus-run-session. It publishes the bus
# address to ${RUNDIR}/bus-address for external consumers, then blocks.
BUS_ADDR_FILE="${RUNDIR}/bus-address"
export BUS_ADDR_FILE AGENT_BIN AUTO_PROMPTER RUNDIR

dbus-run-session -- bash -c '
  set -uo pipefail
  echo "${DBUS_SESSION_BUS_ADDRESS}" > "${BUS_ADDR_FILE}"

  "${AGENT_BIN}" > "${RUNDIR}/agent.log" 2>&1 &
  AGENT_PID=$!
  "${AUTO_PROMPTER}" > "${RUNDIR}/auto-prompter.log" 2>&1 &
  PROMPTER_PID=$!

  cleanup() {
    echo "[launch] stopping (agent=${AGENT_PID} prompter=${PROMPTER_PID}) ..." >&2
    kill "${PROMPTER_PID}" "${AGENT_PID}" 2>/dev/null || true
    wait "${PROMPTER_PID}" "${AGENT_PID}" 2>/dev/null || true
  }
  trap cleanup EXIT           # fires once on any exit
  trap "exit 130" INT TERM    # signals -> exit -> cleanup (single teardown)

  wait_for_name() {
    local name="$1"
    for _ in $(seq 1 100); do   # up to ~10s
      if busctl --user status "${name}" >/dev/null 2>&1; then return 0; fi
      # bail early if a child died
      kill -0 "${AGENT_PID}" 2>/dev/null || { echo "[launch] agent exited early; see ${RUNDIR}/agent.log" >&2; return 1; }
      kill -0 "${PROMPTER_PID}" 2>/dev/null || { echo "[launch] prompter exited early; see ${RUNDIR}/auto-prompter.log" >&2; return 1; }
      sleep 0.1
    done
    echo "[launch] timed out waiting for ${name}" >&2
    return 1
  }

  wait_for_name org.librescrs.Prompter1 || exit 1
  wait_for_name org.librescrs.Agent     || exit 1

  echo ""
  echo "================ librescrs e2e harness READY ================"
  echo "DBUS_SESSION_BUS_ADDRESS=${DBUS_SESSION_BUS_ADDRESS}"
  echo "  agent PID          : ${AGENT_PID}   (log: ${RUNDIR}/agent.log)"
  echo "  auto-prompter PID  : ${PROMPTER_PID}   (log: ${RUNDIR}/auto-prompter.log)"
  echo "  bus-address file   : ${BUS_ADDR_FILE}"
  echo "  names owned        : org.librescrs.Agent + org.librescrs.Prompter1"
  echo "------------------------------------------------------------"
  echo "In another shell, point a test at this bus with:"
  echo "  export DBUS_SESSION_BUS_ADDRESS=\"$(cat "${BUS_ADDR_FILE}")\""
  echo "  export LIBRESCRS_PROMPTER_GATE=\"'"${GATE}"'\""
  echo "Then (only when a card + a REAL follow-up wants it) touch the gate to arm."
  echo "Ctrl-C here tears everything down."
  echo "============================================================"

  # Block until signalled; cleanup trap kills both children.
  wait
'
