#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# Selftest for make-sbom.sh. The bill is signed and published beside the
# packages, so what it must never do is name code the release did not build:
# every refusal below is a tree the bill would otherwise have described wrongly,
# and the control proves the commits in the bill are the ones read from the
# lock and from the locked checkout, not typed anywhere.
#
# Fixtures are throwaway trees under /var/tmp (never /tmp, which is RAM on the
# maintainer's machine): a copy of the script in a minimal repository, and a
# git repository standing in for the LibreAgent checkout.
set -u

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
subject="$here/make-sbom.sh"
work="${TMPDIR_SELFTEST:-/var/tmp}/make-sbom-selftest.$$"
rm -rf "$work"; mkdir -p "$work"
trap 'rm -rf "$work"' EXIT

cases=0 red=0 fails=0
q=930708bb86481e88879eb1d87fd4d664f1d69503

agent() {  # agent <dir> [<qcbor-line>] -> prints its HEAD
    local d=$1 line=${2-"    GIT_TAG $q"}
    mkdir -p "$d/cmake"
    printf 'FetchContent_Declare(qcbor\n%s\n)\n' "$line" >"$d/cmake/FetchQCBOR.cmake"
    git -C "$d" init --quiet
    git -C "$d" add -A
    git -C "$d" -c user.name=t -c user.email=t@invalid -c commit.gpgsign=false \
        commit --quiet -m agent
    git -C "$d" rev-parse HEAD
}
consumer() {  # consumer <dir> <locked-agent-sha or empty>
    local d=$1
    mkdir -p "$d/ci/scripts"
    cp "$subject" "$d/ci/scripts/make-sbom.sh"
    echo 5.0.0 >"$d/VERSION"
    { echo "# <name> <url> <commit> <main|version>"
      [ -z "$2" ] || echo "LibreAgent  https://github.com/LibreSCRS/LibreAgent  $2  main"; } >"$d/deps.lock"
}
run() {  # run <consumer> <agent>
    out=$(bash "$1/ci/scripts/make-sbom.sh" "$1/sbom.json" "$2" 2>&1); rc=$?
}
expect_red() {  # expect_red <name> <consumer> <agent> <text>
    cases=$((cases + 1)); red=$((red + 1))
    run "$2" "$3"
    if [ "$rc" -eq 0 ]; then echo "CASE $1: expected a refusal, got rc=0"; fails=$((fails + 1)); return; fi
    case "$out" in *"$4"*) echo "ok   $1 (rc=$rc)" ;;
        *) echo "CASE $1: rc=$rc but no line says '$4'"; printf '    %s\n' "$out"; fails=$((fails + 1)) ;; esac
    [ ! -e "$2/sbom.json" ] || { echo "CASE $1: refused, yet a bill was written"; fails=$((fails + 1)); }
}

# control
la=$(agent "$work/la")
consumer "$work/ok" "$la"
cases=$((cases + 1))
run "$work/ok" "$work/la"
if [ "$rc" -ne 0 ]; then
    echo "CASE control: rc=$rc"; printf '    %s\n' "$out"; fails=$((fails + 1))
elif ! python3 - "$work/ok/sbom.json" "$la" "$q" <<'PY'
import json, sys
doc = json.load(open(sys.argv[1]))
purls = sorted(c["purl"] for c in doc["components"])
want = sorted([f"pkg:github/LibreSCRS/LibreAgent@{sys.argv[2]}",
               f"pkg:github/laurencelundblade/QCBOR@{sys.argv[3]}"])
assert doc["bomFormat"] == "CycloneDX", doc["bomFormat"]
assert doc["metadata"]["component"]["version"] == "5.0.0"
assert purls == want, purls
PY
then
    echo "CASE control: the bill does not name the locked commits"; fails=$((fails + 1))
else
    echo "ok   control"
fi

# the checkout is another commit than the lock
other=$(agent "$work/la-other" "    GIT_TAG $q  ")
consumer "$work/moved" "$other"
git -C "$work/la-other" -c user.name=t -c user.email=t@invalid -c commit.gpgsign=false \
    commit --quiet --allow-empty -m later
expect_red checkout_is_not_the_lock "$work/moved" "$work/la-other" "deps.lock locks LibreAgent at"

# no LibreAgent row in the lock
consumer "$work/norow" ""
expect_red no_agent_row "$work/norow" "$work/la" "no LibreAgent row"

# the pin the bill names cannot be read
nopin=$(agent "$work/la-nopin" "    GIT_TAG v1.6.1")
consumer "$work/nopin" "$nopin"
expect_red no_qcbor_pin "$work/nopin" "$work/la-nopin" "no QCBOR pin"

# not a git checkout at all
mkdir -p "$work/plain"
consumer "$work/plain-c" "$la"
expect_red not_a_checkout "$work/plain-c" "$work/plain" "not a git checkout"

if [ "$fails" -eq 0 ]; then echo "make-sbom selftest: all $cases cases passed"
else echo "make-sbom selftest: $fails of $cases case(s) failed"; fi
printf 'selftest: %s cases, %s red-proved\n' "$cases" "$red"
[ "$fails" -eq 0 ]
