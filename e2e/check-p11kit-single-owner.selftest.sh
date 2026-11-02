#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# check-p11kit-single-owner.selftest.sh — drive the gate through every state it
# must distinguish, and assert the exit code of each.
#
# A gate that has never failed is not a gate. This one greps `p11-kit
# list-modules` for an attribute line indented by exactly four spaces and
# compares a library description string: if p11-kit changes its indentation, or
# the proxy's description is reworded, the pattern stops matching and the gate
# reports "0 providers" — or, worse, silently stops telling the proxy from any
# other LibreSCRS module. Nothing about that failure looks like a failure.
#
# The states are synthesized, not found: half A is driven from captured
# enumerator transcripts (LIBRESCRS_P11_ENUM_FIXTURE) and half B from a scratch
# XDG_CONFIG_HOME. That is what makes this runnable on a CI runner which has no
# LibreSCRS module installed at all — the state most likely to be mistaken for
# success is exactly the empty one.
set -uo pipefail

GATE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/check-p11kit-single-owner.sh"
[ -x "$GATE" ] || { echo "FAIL: gate not executable: $GATE" >&2; exit 2; }

WORK="$(mktemp -d "${TMPDIR:-/var/tmp}/p11-single-owner-selftest-XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

OTHER_DESC="LibreSCRS PKCS#11"
PROXY_DESC="LibreSCRS agent-proxy PKCS#11"

# --- captured enumerator transcripts (half A) ------------------------------
# The indentation is load-bearing: p11-kit 0.26 indents module attributes by
# exactly four spaces, and the gate's pattern is anchored on that.
emit_module() { # $1 = description
    printf 'module: %s\n' "fixture"
    printf '    path: /nonexistent/%s.so\n' "fixture"
    printf '    library-description: %s\n' "$1"
    printf '    library-manufacturer: LibreSCRS\n'
    printf '    library-version: 5.0\n'
}
emit_foreign() {
    printf 'module: p11-kit-trust\n'
    printf '    path: /usr/lib/pkcs11/p11-kit-trust.so\n'
    printf '    library-description: PKCS#11 Kit Trust Module\n'
    printf '    library-manufacturer: PKCS#11 Kit\n'
}
{ emit_foreign; emit_module "$OTHER_DESC"; }                       > "$WORK/fix-other.txt"
{ emit_foreign; emit_module "$PROXY_DESC"; }                       > "$WORK/fix-proxy.txt"
{ emit_foreign; emit_module "$OTHER_DESC"; emit_module "$PROXY_DESC"; } > "$WORK/fix-both.txt"
{ emit_foreign; }                                                  > "$WORK/fix-none.txt"

# --- scratch config trees (half B) -----------------------------------------
mk_conf() { # $1 = state name -> echoes the XDG_CONFIG_HOME to use
    local d="$WORK/$1"; mkdir -p "$d/pkcs11/modules"; printf '%s' "$d"
}
other_decl()  { printf 'module: /opt/librescrs/lib/pkcs11/librescrs-pkcs11.so\npriority: 10\n' > "$1"; }
proxy_decl()  { printf 'module: /opt/librescrs/lib/pkcs11/librescrs-pkcs11-agent.so\npriority: 10\n' > "$1"; }

S1="$(mk_conf s1)"; other_decl "$S1/pkcs11/modules/librescrs.module"
S2="$(mk_conf s2)"; other_decl "$S2/pkcs11/modules/librescrs.module"
                    proxy_decl  "$S2/pkcs11/modules/librescrs-agent.module"
# S3: the other module is hidden from the enumerator but still registered.
S3="$(mk_conf s3)"
{ printf 'module: /opt/librescrs/lib/pkcs11/librescrs-pkcs11.so\n'
  printf 'priority: 10\n'
  printf 'disable-in: p11-kit\n'; } > "$S3/pkcs11/modules/librescrs.module"
proxy_decl "$S3/pkcs11/modules/librescrs-agent.module"
# S4: nothing p11-kit reads. The proxy declaration is elsewhere on disk.
S4="$(mk_conf s4)"; mkdir -p "$WORK/s4-unread/p11-kit/modules"
proxy_decl "$WORK/s4-unread/p11-kit/modules/librescrs-agent.module"
S5="$(mk_conf s5)"; proxy_decl "$S5/pkcs11/modules/librescrs-agent.module"

# The system directories are real and outside our control. If this host has a
# LibreSCRS declaration other than the proxy's in /usr/share/p11-kit/modules or
# /etc/pkcs11/modules, half B sees it in every state and the synthesized states
# stop being what they claim. Refuse rather than report a green that means
# nothing.
for d in /usr/share/p11-kit/modules /etc/pkcs11/modules; do
    [ -d "$d" ] || continue
    if grep -hE '^[[:space:]]*module:' "$d"/*.module 2>/dev/null | sed 's/^[[:space:]]*module:[[:space:]]*//' \
        | xargs -r -n1 basename | grep -E '^librescrs' | grep -vqE '^librescrs-pkcs11-agent\.(so|dylib)$'; then
        echo "FAIL: a LibreSCRS declaration other than the proxy's exists in $d; the" >&2
        echo "      synthesized states cannot be isolated from it. Remove it and re-run." >&2
        exit 2
    fi
done

failures=0
cases=0
red=0
assert() { # $1 name  $2 want-rc  $3 XDG  $4 fixture  $5... extra gate args
    local name="$1" want="$2" xdg="$3" fixture="$4"; shift 4
    cases=$((cases + 1))
    # red-proved: the case in which the gate returned non-zero on a state it
    # must refuse. Four of these five are exactly that.
    if [ "$want" != 0 ]; then red=$((red + 1)); fi
    # The name carries spaces; a filename must not.
    local slug; slug="$(printf '%s' "$name" | tr -c 'A-Za-z0-9' '_')"
    local out="$WORK/out-$slug.txt" got
    XDG_CONFIG_HOME="$xdg" LIBRESCRS_P11_ENUM_FIXTURE="$fixture" \
        "$GATE" "$@" > "$out" 2>&1
    got=$?
    if [ "$got" = "$want" ]; then
        printf 'ok   %-34s rc=%s\n' "$name" "$got"
    else
        printf 'FAIL %-34s want rc=%s got rc=%s\n' "$name" "$want" "$got"
        sed 's/^/       | /' "$out"
        failures=$((failures+1))
    fi
}

echo "== the host that installed the agent =="
assert "S1 another module only"    1 "$S1" "$WORK/fix-other.txt"
assert "S2 both registered"        1 "$S2" "$WORK/fix-both.txt"
assert "S3 other hidden by disable-in" 1 "$S3" "$WORK/fix-proxy.txt"
assert "S4 declaration unread"     1 "$S4" "$WORK/fix-none.txt"
assert "S5 proxy only"             0 "$S5" "$WORK/fix-proxy.txt"

echo "== the un-fixtured enumerator is reachable =="
# Not an assertion about this host's registration state — only that the real
# path runs, p11-kit is present, and the gate reaches a verdict instead of the
# exit-2 it uses for "I could not look".
cases=$((cases + 1))
XDG_CONFIG_HOME="$S4" "$GATE" > "$WORK/out-live.txt" 2>&1
live=$?
if [ "$live" = 0 ] || [ "$live" = 1 ]; then
    printf 'ok   %-34s rc=%s\n' "live enumerator reachable" "$live"
else
    printf 'FAIL %-34s rc=%s (expected 0 or 1)\n' "live enumerator reachable" "$live"
    sed 's/^/       | /' "$WORK/out-live.txt"
    failures=$((failures+1))
fi

echo
if [ "$failures" -eq 0 ]; then
    echo "PASS: the gate distinguishes all five states."
    printf 'selftest: %s cases, %s red-proved\n' "$cases" "$red"
    exit 0
fi
echo "FAIL: $failures assertion(s) failed." >&2
printf 'selftest: %s cases, %s red-proved\n' "$cases" "$red"
exit 1
