#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# Build the autonomous test harness (auto-prompter + validator).
# Standalone g++ + pkg-config sdbus-c++ — deliberately NOT a CMake target, so
# it can never sneak into the shipped build. CI runs this script to compile
# the harness (and never runs the binaries). Reuses the tree's generated
# Prompter1 adaptor/proxy headers and the shared sealed-memfd creator.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "${HERE}/.." && pwd)"

GEN_ADAPTOR="${REPO}/build/prompter/generated"   # org.librescrs.Prompter1_adaptor.h
GEN_PROXY="${REPO}/build/agent/generated"         # org.librescrs.Prompter1_proxy.h
COMMON="${REPO}/common"                           # SealedMemfdCreator.h, PrompterWire.h

for f in \
    "${GEN_ADAPTOR}/org.librescrs.Prompter1_adaptor.h" \
    "${GEN_PROXY}/org.librescrs.Prompter1_proxy.h" \
    "${COMMON}/SealedMemfdCreator.h" \
    "${COMMON}/PrompterWire.h"; do
    [[ -f "$f" ]] || { echo "MISSING: $f (build the project first)" >&2; exit 1; }
done

# The agent library's vocabulary headers common/PrompterWire.h names (prompter
# kinds, reply status, the secret bound; standard library only). The configured
# tree records the agent library's checkout when it built it from source; an
# installed agent library's include directory is passed as LIBREAGENT_INCLUDE_DIR.
LA_INCLUDE="${LIBREAGENT_INCLUDE_DIR:-}"
if [[ -z "${LA_INCLUDE}" && -f "${REPO}/build/CMakeCache.txt" ]]; then
    LA_SRC="$(sed -n 's/^LibreAgent_SOURCE_DIR:STATIC=//p' "${REPO}/build/CMakeCache.txt")"
    if [[ -n "${LA_SRC}" ]]; then
        LA_INCLUDE="${LA_SRC}/include"
    fi
fi
[[ -f "${LA_INCLUDE}/LibreSCRS/Agent/backend/PrompterWire.h" ]] || {
    echo "MISSING: the agent library's headers (set LIBREAGENT_INCLUDE_DIR)" >&2
    exit 1
}

CXX="${CXX:-g++}"
SDBUS_CFLAGS="$(pkg-config --cflags sdbus-c++)"
SDBUS_LIBS="$(pkg-config --libs sdbus-c++)"
STD="${STD:--std=c++23}"

echo "[build] auto-prompter ..."
# shellcheck disable=SC2086
"${CXX}" ${STD} -O2 -Wall -Wextra \
    -I"${GEN_ADAPTOR}" -I"${COMMON}" -I"${LA_INCLUDE}" \
    ${SDBUS_CFLAGS} \
    "${HERE}/auto-prompter.cpp" -o "${HERE}/auto-prompter" \
    ${SDBUS_LIBS} -pthread

echo "[build] validate-prompter ..."
# shellcheck disable=SC2086
"${CXX}" ${STD} -O2 -Wall -Wextra \
    -I"${GEN_PROXY}" -I"${COMMON}" -I"${LA_INCLUDE}" \
    ${SDBUS_CFLAGS} \
    "${HERE}/validate-prompter.cpp" -o "${HERE}/validate-prompter" \
    ${SDBUS_LIBS} -pthread

echo "[build] sign-proof ..."
# A pure D-Bus client: no generated headers, only sdbus-c++ and the PKCS#11
# module's header-only certificate read (pkcs11-module/src/CertificateRead.h,
# which takes the interface names from common/ and the operation outcome words
# from the agent library's headers), so the proof reads certificates exactly
# as the module does. Built here anyway so one command
# produces every binary the runners expect, and so a compile break surfaces
# without a card in the reader.
# shellcheck disable=SC2086
"${CXX}" ${STD} -O2 -Wall -Wextra \
    -I"${REPO}/pkcs11-module/src" -I"${COMMON}" -I"${LA_INCLUDE}" \
    ${SDBUS_CFLAGS} \
    "${HERE}/sign-proof.cpp" -o "${HERE}/sign-proof" \
    ${SDBUS_LIBS} -pthread

echo "[build] OK -> ${HERE}/auto-prompter, ${HERE}/validate-prompter, ${HERE}/sign-proof"
