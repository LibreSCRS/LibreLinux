#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# check-p11kit-single-owner.sh — GATING check that a host exposes exactly ONE
# LibreSCRS PKCS#11 provider, and that it is the agent proxy.
#
#   check-p11kit-single-owner.sh [--expect proxy|none]
#
#   --expect proxy   (default) exactly one LibreSCRS provider, it is the proxy,
#                    no direct-module registration, and the proxy declaration is
#                    present in a directory p11-kit reads. This is what a host
#                    that installed the agent must look like.
#   --expect none    no LibreSCRS provider at all and no direct-module
#                    registration; the proxy declaration is not looked for. This
#                    is the middleware's own invariant: it contributes the
#                    library and registers nothing.
#
# Two LibreSCRS providers for one card means two independent PIN-entry models:
# the proxy collects the PIN in the agent's prompter (its token advertises
# CKF_PROTECTED_AUTHENTICATION_PATH) while the direct module takes the PIN
# inside the calling application, bypassing the agent's authorization, lease
# and prompter. Whichever dialog the user types into silently decides the
# security model of their signature.
#
# The check has two halves, and BOTH are needed. Do not delete half B as
# redundant:
#
#   A. LIVE ENUMERATION. `p11-kit list-modules` dlopens every registered module
#      and calls C_GetInfo, so a registration whose .so does not resolve is
#      silently absent. Counting providers here therefore also proves the
#      module was installed where p11-kit reads AND that it loads. A .module
#      dropped into a directory p11-kit does not read is invisible to the
#      install rules but caught here. The discriminator is the DESCRIPTION, not
#      the manufacturer: both providers claim the same manufacturer.
#
#   B. STATIC SCAN of the directories p11-kit reads. Half A alone can be fooled:
#      a `disable-in:` line hides a module from a named program without
#      unregistering it, so `p11-kit list-modules` stops reporting a provider
#      that every other consumer still loads. Measured: with `disable-in: p11-kit`
#      on the direct module, half A reports one provider while the same p11-kit
#      binary invoked under any other program name reports two. A one-line
#      change that only quiets the enumerator therefore cannot turn this green.
#
# An absent p11-kit is a FAILURE (exit 2), not a pass: a check that reports
# success on a host where it looked at nothing is worse than no check.
#
# Needs no card, no PIN, no running agent and no LIBRESCRS_TEST_* variable.
#
# LIBRESCRS_P11_ENUM_FIXTURE is a documented seam for the self-test beside this
# file: it replaces the INPUT of half A with a captured `p11-kit list-modules`
# transcript, so the five states this gate must distinguish can be driven on a
# runner that has no LibreSCRS module installed at all. Half B always reads the
# real directories. It is announced loudly when set, and no CI step sets it.
set -uo pipefail

PROXY_SO_STEM="librescrs-pkcs11-agent"
DIRECT_SO_RE='librescrs-pkcs11\.(so|dylib)'
PROXY_DESC="LibreSCRS agent-proxy PKCS#11"

EXPECT="proxy"
while [ $# -gt 0 ]; do
    case "$1" in
        --expect)
            [ $# -ge 2 ] || { echo "usage: $0 [--expect proxy|none]" >&2; exit 2; }
            EXPECT="$2"; shift 2 ;;
        --expect=*) EXPECT="${1#--expect=}"; shift ;;
        -h|--help) sed -n '2,50p' "$0"; exit 0 ;;
        *) echo "usage: $0 [--expect proxy|none]" >&2; exit 2 ;;
    esac
done
case "$EXPECT" in
    proxy|none) ;;
    *) echo "usage: $0 [--expect proxy|none]" >&2; exit 2 ;;
esac

fail() { echo "FAIL: $*" >&2; }

rc=0

# --- A. live enumeration ---------------------------------------------------
if [ -n "${LIBRESCRS_P11_ENUM_FIXTURE:-}" ]; then
    echo "NOTE: half A driven from a fixture: $LIBRESCRS_P11_ENUM_FIXTURE"
    [ -r "$LIBRESCRS_P11_ENUM_FIXTURE" ] || {
        fail "fixture is not readable: $LIBRESCRS_P11_ENUM_FIXTURE"; exit 2; }
    OUT="$(cat -- "$LIBRESCRS_P11_ENUM_FIXTURE")"
else
    if ! command -v p11-kit >/dev/null 2>&1; then
        fail "p11-kit is not installed; the registration this gate covers cannot be observed."
        echo "      Install p11-kit in the test environment rather than skipping the gate." >&2
        exit 2
    fi
    OUT="$(p11-kit list-modules 2>&1)" || {
        fail "p11-kit list-modules exited non-zero"; printf '%s\n' "$OUT" >&2; exit 2; }
fi

# Four leading spaces is exactly how p11-kit 0.26 indents a module attribute.
COUNT=$(printf '%s\n' "$OUT" | grep -c '^    library-manufacturer: LibreSCRS$')
DESCS=$(printf '%s\n' "$OUT" | grep '^    library-description: LibreSCRS' \
        | sed 's/^ *library-description: //')

echo "A. LibreSCRS providers p11-kit loads: $COUNT"
[ -n "$DESCS" ] && printf '%s\n' "$DESCS" | sed 's/^/     - /'

if [ "$EXPECT" = "none" ]; then
    if [ "$COUNT" -ne 0 ]; then
        fail "$COUNT LibreSCRS provider(s) registered; this install must register none."
        rc=1
    fi
else
    if [ "$COUNT" -eq 0 ]; then
        fail "no LibreSCRS provider is registered with p11-kit."
        echo "      Either the .module landed outside p11-kit's config dirs, or its" >&2
        echo "      module: path does not resolve to a loadable .so." >&2
        rc=1
    elif [ "$COUNT" -gt 1 ]; then
        fail "$COUNT LibreSCRS providers registered; exactly one is allowed."
        rc=1
    elif [ "$DESCS" != "$PROXY_DESC" ]; then
        fail "the single registered provider is not the agent proxy."
        echo "      want: $PROXY_DESC" >&2
        echo "      got : $DESCS" >&2
        rc=1
    fi
fi

# --- B. static scan of every directory p11-kit reads -----------------------
# Ascending precedence, as p11-kit reads them (see pkcs11.conf(5)).
CONF_DIRS=(
    "/usr/share/p11-kit/modules"
    "/etc/pkcs11/modules"
    "${XDG_CONFIG_HOME:-$HOME/.config}/pkcs11/modules"
)
echo "B. scanning p11-kit config dirs for a direct-module registration"
found_direct=0
found_proxy=0
for d in "${CONF_DIRS[@]}"; do
    [ -d "$d" ] || continue
    for f in "$d"/*.module; do
        [ -e "$f" ] || continue
        ref=$(grep -m1 -E '^[[:space:]]*module:[[:space:]]*[^[:space:]]' "$f" \
              | sed 's/^[[:space:]]*module:[[:space:]]*//')
        [ -n "$ref" ] || continue
        case "$(basename -- "$ref")" in
            "$PROXY_SO_STEM".so|"$PROXY_SO_STEM".dylib) found_proxy=1 ;;
            *) if printf '%s' "$(basename -- "$ref")" | grep -Eq "^$DIRECT_SO_RE\$"; then
                   found_direct=1
                   fail "direct-module registration still present: $f"
                   echo "         -> $ref" >&2
                   echo "         remove it:  rm $f" >&2
               fi ;;
        esac
    done
done
if [ "$found_direct" -eq 0 ]; then echo "     no direct-module registration found"; else rc=1; fi

if [ "$EXPECT" = "none" ]; then
    echo "     proxy declaration not required in this mode"
else
    if [ "$found_proxy" -eq 0 ]; then
        fail "no agent-proxy .module file found in any directory p11-kit reads."
        printf '       looked in: %s\n' "${CONF_DIRS[@]}" >&2
        rc=1
    else
        echo "     agent-proxy .module present"
    fi
fi

if [ $rc -eq 0 ]; then
    if [ "$EXPECT" = "none" ]; then
        echo "PASS: no LibreSCRS PKCS#11 provider is registered by this install."
    else
        echo "PASS: exactly one LibreSCRS provider, and it is the agent proxy."
    fi
fi
exit $rc
