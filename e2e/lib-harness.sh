# SPDX-License-Identifier: LGPL-2.1-or-later
# Shared agent/prompter bring-up for the hardware-acceptance runners.
#
# Sourced, never executed — inside a runner's private dbus-run-session subshell
# (the runner exports E2E_LIB pointing here). Expects AUTO_PROMPTER, AGENT_BIN,
# RUNDIR and GATE in the environment. Keeping the bring-up in one place means
# every runner tests the same agent environment; a forked copy drifting would
# silently test a different one.

# Start the auto-prompter and the agent on the private session bus, install a
# cleanup trap, and wait until the agent owns its name and has exported at
# least one card object. Returns 1 (agent never came up) or 2 (no card object)
# with the agent log echoed; on 0 the caller may arm the gate and run its test.
librescrs_harness_up() {
    # Auto-prompter FIRST + claim the name, so the agent never dbus-activates
    # the installed (real) pinentry.
    "$AUTO_PROMPTER" > "$RUNDIR/prompter.log" 2>&1 & PROMPTER_PID=$!
    for _ in $(seq 1 50); do busctl --user status org.librescrs.Prompter1 >/dev/null 2>&1 && break; sleep 0.1; done
    # The org.librescrs polkit policy is not installed on this box (needs root),
    # so an installed-policy PolkitAuthorizer would deny the (default-allow)
    # login as an "unregistered action". Make the system bus unreachable to the
    # agent so it uses the shipping DefaultAuthorizer fallback, whose sign/login
    # allow decision is identical (only the trust/TSA tier differs, unused here).
    DBUS_SYSTEM_BUS_ADDRESS="unix:path=${RUNDIR}/no-system-bus" \
    "$AGENT_BIN" > "$RUNDIR/agent.log" 2>&1 & AGENT_PID=$!
    trap librescrs_harness_cleanup EXIT
    local up=0
    for _ in $(seq 1 100); do
        busctl --user status org.librescrs.Agent >/dev/null 2>&1 && { up=1; break; }
        kill -0 "$AGENT_PID" 2>/dev/null || break
        sleep 0.1
    done
    if [[ $up -ne 1 ]]; then echo "=== AGENT DID NOT COME UP ==="; cat "$RUNDIR/agent.log"; return 1; fi
    # Wait for the agent to finish async card enumeration + export at least one card object.
    local card=0
    for _ in $(seq 1 150); do   # up to ~15s
        if busctl --user tree org.librescrs.Agent 2>/dev/null | grep -q "/org/librescrs/Agent/card/"; then card=1; break; fi
        sleep 0.1
    done
    echo "=== names owned; cards exported: $( busctl --user tree org.librescrs.Agent 2>/dev/null | grep -c "/card/" ) (readers: $( busctl --user tree org.librescrs.Agent 2>/dev/null | grep -c "/reader/" )) ==="
    if [[ $card -ne 1 ]]; then echo "=== NO CARD OBJECT EXPORTED ==="; echo "--- agent.log ---"; tail -40 "$RUNDIR/agent.log"; return 2; fi
    return 0
}

librescrs_harness_cleanup() {
    rm -f "$GATE"
    kill "$PROMPTER_PID" "$AGENT_PID" 2>/dev/null
    wait 2>/dev/null
}
