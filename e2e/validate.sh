#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# Driver: prove the memfd/seal contract end-to-end with a DUMMY pin and
# NO card. Starts a private session bus, launches the auto-prompter with a dummy
# secret, then runs the validator (which toggles the gate and asserts bytes +
# seals + gate behaviour). Nothing here touches a card, sign, login, or PIN op.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

[[ -x "${HERE}/auto-prompter" && -x "${HERE}/validate-prompter" ]] || "${HERE}/build.sh"

DUMMY_SECRET="contract-probe-not-a-pin"   # arbitrary bytes; nothing here reaches a card
export LIBRESCRS_PROMPTER_GATE="${LIBRESCRS_PROMPTER_GATE:-/tmp/librescrs-e2e/prompt.gate}"
mkdir -p "$(dirname "${LIBRESCRS_PROMPTER_GATE}")"
rm -f "${LIBRESCRS_PROMPTER_GATE}"   # start with the gate CLOSED
# Disarm the gate no matter how the run ends: under `set -e` a failing
# dbus-run-session exits this script immediately, so inline cleanup after the
# call would be skipped and a crashed run would leave the gate armed.
trap 'rm -f "${LIBRESCRS_PROMPTER_GATE}"' EXIT

dbus-run-session -- bash -c '
  set -euo pipefail
  export LIBRESCRS_SIGN_PIN="'"${DUMMY_SECRET}"'"
  export LIBRESCRS_PROMPTER_GATE="'"${LIBRESCRS_PROMPTER_GATE}"'"

  "'"${HERE}"'/auto-prompter" &
  AP=$!
  # WAIT for it, do not just signal it: dbus-run-session tears the bus down as
  # soon as this shell exits, and a prompter still in its event loop then throws
  # ENOTCONN out of the loop thread and aborts. Signal, then reap.
  trap "kill ${AP} 2>/dev/null; wait ${AP} 2>/dev/null || true" EXIT

  # Wait (max ~5s) for the well-known name to be owned.
  for _ in $(seq 1 50); do
    if busctl --user status org.librescrs.Prompter1 >/dev/null 2>&1; then break; fi
    sleep 0.1
  done
  busctl --user status org.librescrs.Prompter1 >/dev/null 2>&1 || { echo "prompter never owned its name" >&2; exit 2; }

  "'"${HERE}"'/validate-prompter" "'"${DUMMY_SECRET}"'"
'
