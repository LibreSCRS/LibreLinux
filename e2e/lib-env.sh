# SPDX-License-Identifier: LGPL-2.1-or-later
# Shared environment resolution for the hardware-acceptance runners.
#
# Sourced, never executed. The point of this file is that no runner hardcodes a
# path from one developer's machine: LibreMiddleware installs under its OWN
# prefix, which is not derivable from this repo, so the operator names it once
# and every runner agrees on what it means.

# Resolve the LibreMiddleware install prefix. LIBRESCRS_LM_PREFIX wins;
# otherwise fall back to the sibling checkout layout this workspace uses.
librescrs_resolve_lm_prefix() {
    local repo="$1"
    if [[ -n "${LIBRESCRS_LM_PREFIX:-}" ]]; then
        printf '%s' "${LIBRESCRS_LM_PREFIX}"
        return 0
    fi
    local sibling="${repo}/../LibreMiddleware/install"
    if [[ -d "${sibling}" ]]; then
        (cd "${sibling}" && pwd)
        return 0
    fi
    return 1
}

# Export LIBRESCRS_PLUGIN_DIR and LIBRESCRS_PKCS11_MODULE from that prefix,
# unless the caller already set them. Fails loudly and says what to set —
# a runner that silently proceeds without plugins reports every card as
# unsupported, which is indistinguishable from a card we do not support.
librescrs_export_lm_paths() {
    local repo="$1" prefix
    if ! prefix="$(librescrs_resolve_lm_prefix "${repo}")"; then
        echo "e2e: cannot find the LibreMiddleware install prefix." >&2
        echo "     Set LIBRESCRS_LM_PREFIX=/path/to/LibreMiddleware/install" >&2
        return 1
    fi

    export LIBRESCRS_PLUGIN_DIR="${LIBRESCRS_PLUGIN_DIR:-${prefix}/lib/librescrs/plugins}"
    # libresign's native AdES path dlopens the LM PKCS#11 module by bare name;
    # point it at the installed module so Card1.Sign (AdES) can load it.
    export LIBRESCRS_PKCS11_MODULE="${LIBRESCRS_PKCS11_MODULE:-${prefix}/lib/pkcs11/librescrs-pkcs11.so}"

    if [[ ! -d "${LIBRESCRS_PLUGIN_DIR}" ]]; then
        echo "e2e: no plugin directory at ${LIBRESCRS_PLUGIN_DIR}" >&2
        echo "     Install LibreMiddleware, or set LIBRESCRS_PLUGIN_DIR." >&2
        return 1
    fi
    if [[ ! -f "${LIBRESCRS_PKCS11_MODULE}" ]]; then
        echo "e2e: no PKCS#11 module at ${LIBRESCRS_PKCS11_MODULE}" >&2
        echo "     Set LIBRESCRS_PKCS11_MODULE to the installed librescrs-pkcs11.so." >&2
        return 1
    fi
    return 0
}
