#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# make-sbom.sh <output> <libreagent-checkout>
#
# A CycloneDX bill of materials for this repository's release: what is bundled
# INSIDE the agent binary rather than what the distribution resolves around it.
# The agent links the LibreAgent core statically, and the core's wire codec
# carries QCBOR compiled in, so neither appears in any package's dependency
# metadata -- this file is the only place either is named.
#
# Every commit below is read, never typed here: LibreAgent's from the
# LibreAgent row of deps.lock, QCBOR's from cmake/FetchQCBOR.cmake in a
# checkout of LibreAgent at that commit. The checkout is refused unless its
# HEAD is the locked commit, because a bill read from any other tree names
# code the release did not build.
#
# The middleware is a shared-library dependency every package declares, so it
# is not bundled and not listed.
#
# Exit: 0 written; 1 the checkout is not the locked commit, or a pin is missing;
#       2 usage.
set -euo pipefail

[ "$#" -eq 2 ] || { echo "usage: make-sbom.sh <output> <libreagent-checkout>" >&2; exit 2; }
out="$1"
la="$2"
repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
version="$(tr -d '[:space:]' < "$repo/VERSION")"

la_sha="$(awk '$1 == "LibreAgent" {print $3}' "$repo/deps.lock")"
[ -n "$la_sha" ] || { echo "make-sbom: deps.lock has no LibreAgent row" >&2; exit 1; }
head="$(git -C "$la" rev-parse HEAD 2>/dev/null || true)"
if [ "$head" != "$la_sha" ]; then
    echo "make-sbom: $la is at '${head:-not a git checkout}', deps.lock locks LibreAgent at $la_sha" >&2
    exit 1
fi
qcbor_sha="$(sed -nE 's/^[[:space:]]*GIT_TAG[[:space:]]+([0-9a-f]{40})[[:space:]]*$/\1/p' \
    "$la/cmake/FetchQCBOR.cmake" 2>/dev/null | head -n1)"
[ -n "$qcbor_sha" ] || { echo "make-sbom: no QCBOR pin in $la/cmake/FetchQCBOR.cmake" >&2; exit 1; }

python3 - "$out" "$version" "$la_sha" "$qcbor_sha" <<'PY'
import json
import sys

out, version, la_sha, qcbor_sha = sys.argv[1:]
doc = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.5",
    "version": 1,
    "metadata": {
        "component": {
            "type": "application",
            "name": "LibreLinux",
            "version": version,
            "purl": f"pkg:github/LibreSCRS/LibreLinux@{version}",
            "licenses": [{"license": {"id": "LGPL-2.1-or-later"}}],
        }
    },
    "components": [
        {
            "type": "library",
            "name": "libreagent-core",
            "version": f"git-{la_sha}",
            "purl": f"pkg:github/LibreSCRS/LibreAgent@{la_sha}",
            "licenses": [{"license": {"id": "LGPL-2.1-or-later"}}],
            "description": "linked statically into librescrs-agent",
        },
        {
            "type": "library",
            "name": "qcbor",
            "version": f"git-{qcbor_sha}",
            "purl": f"pkg:github/laurencelundblade/QCBOR@{qcbor_sha}",
            "licenses": [{"license": {"id": "BSD-3-Clause"}}],
            "description": "compiled into the LibreAgent wire codec",
        },
    ],
}
with open(out, "w", encoding="utf-8") as fh:
    json.dump(doc, fh, indent=2)
    fh.write("\n")
print(f"make-sbom: {len(doc['components'])} components -> {out}")
PY
