#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# Selftest for check-recipe.sh. The shapes the recipe (or the tree around it)
# gets wrong, plus the real recipe as a control. One case only applies to a
# repository whose recipe carries a FetchContent pin; where it does not, the
# file says so out loud and counts one case fewer, because a silently dropped
# case is indistinguishable from one that passed.
#
# Each case asserts three things, because two of them are not enough:
#   * the fixture actually differs from the control (a perturbation that
#     changed nothing passes for the wrong reason);
#   * the exit code is non-zero;
#   * the named arm appears in the output. An exit code alone cannot tell a
#     refusal that worked from a refusal that fired on something else.
#
# Every fixture is a throwaway git repository under /var/tmp -- never the
# working tree, and never /tmp, which is RAM on the maintainer's machine. The
# repository name the gate compares the recipe against is handed to it the way
# CI hands it (CHECK_RECIPE_REPO here, GITHUB_REPOSITORY there), so a fixture
# directory can be named anything.
#
# The git commit is run with signing turned off for the invocation: a
# maintainer with commit.gpgSign=true set globally would otherwise be asked for
# a passphrase, and the case would hang on the prompt.
set -u

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
subject="$here/check-recipe.sh"
control_recipe="$here/PKGBUILD"
root=$(CDPATH= cd -- "$here/../.." && pwd)
ghrepo="${GITHUB_REPOSITORY:-}"
rname="${CHECK_RECIPE_REPO:-${ghrepo#*/}}"
[ -n "$rname" ] || rname=$(git -C "$root" remote get-url origin 2>/dev/null | sed -E 's#\.git$##; s#.*/##')
[ -n "$rname" ] || rname=$(basename "$root")
spec_rel=packaging/rpm/librelinux.spec

work="${TMPDIR_SELFTEST:-/var/tmp/check-recipe-selftest.$$}"
rm -rf "$work"; mkdir -p "$work"
trap 'rm -rf "$work"' EXIT

fails=0
cases=0
red=0

fx() { printf '%s/%s\n' "$work" "$1"; }

# fixture <name> -> builds $(fx <name>) as a minimal repository
fixture() {
    local d
    d=$(fx "$1")
    mkdir -p "$d/packaging/arch" "$d/packaging/rpm"
    cp "$control_recipe"  "$d/packaging/arch/PKGBUILD"
    cp "$subject"         "$d/packaging/arch/check-recipe.sh"
    cp "$root/VERSION"    "$d/VERSION"
    cp "$root/KEYS"       "$d/KEYS"
    cp "$root/$spec_rel"  "$d/$spec_rel"
    [ -f "$root/cmake/FetchQCBOR.cmake" ] && {
        mkdir -p "$d/cmake"
        cp "$root/cmake/FetchQCBOR.cmake" "$d/cmake/"
    }
    git -C "$d" init --quiet
    git -C "$d" add -A >/dev/null 2>&1
    git -C "$d" -c user.name=selftest -c user.email=selftest@invalid \
        -c commit.gpgsign=false \
        commit --quiet -m fixture >/dev/null 2>&1
}

run() {  # run <name> ; sets $out and $rc
    out=$(cd "$(fx "$1")" && CHECK_RECIPE_REPO="$rname" bash packaging/arch/check-recipe.sh 2>&1)
    rc=$?
}

changed() {  # changed <name> -- the fixture differs from the control somewhere
    local d f
    d=$(fx "$1")
    for f in packaging/arch/PKGBUILD VERSION KEYS "$spec_rel"; do
        cmp -s "$d/$f" "$root/$f" 2>/dev/null || return 0
    done
    [ -n "$(git -C "$d" ls-files -s | awk '$1 == 160000')" ]
}

expect_red() {  # expect_red <name> <substring>
    local c="$1" want="$2"
    cases=$((cases + 1))
    # every case here is a perturbation: a red one is the proof.
    red=$((red + 1))
    if ! changed "$c"; then
        echo "CASE $c: the fixture is identical to the control -- the perturbation changed nothing"
        fails=$((fails + 1)); return
    fi
    run "$c"
    if [ "$rc" -eq 0 ]; then
        echo "CASE $c: expected a non-zero exit, got 0"
        printf '%s\n' "$out" | sed 's/^/    /'
        fails=$((fails + 1)); return
    fi
    case "$out" in
        *"$want"*) echo "ok   $c (rc=$rc)" ;;
        *) echo "CASE $c: exit was non-zero but no line mentions '$want'"
           printf '%s\n' "$out" | sed 's/^/    /'
           fails=$((fails + 1)) ;;
    esac
}

recipe_of() { printf '%s/packaging/arch/PKGBUILD\n' "$(fx "$1")"; }
src_re='^    "'"$rname"'-\$pkgver::git\+https://github\.com/LibreSCRS/'"$rname"'\.git#tag=\$pkgver\?signed"$'
set_source() {  # set_source <name> <replacement line, verbatim>
    local f r
    f=$(recipe_of "$1")
    r=$2
    python3 - "$f" "$src_re" "$r" <<'PY'
import re, sys
path, pattern, repl = sys.argv[1:]
text = open(path).read()
new, n = re.subn(pattern, lambda _m: repl, text, flags=re.M)
if n != 1:
    sys.exit(f"the control source line was not found exactly once ({n})")
open(path, "w").write(new)
PY
}

# 1 -- GitHub's generated archive. It resolves for any published tag, so
#      nothing at build time would complain; only the gate can say the bytes
#      are not ours.
fixture generated_archive
set_source generated_archive '    "$pkgbase-$pkgver.tar.gz::https://github.com/LibreSCRS/'"$rname"'/archive/refs/tags/$pkgver.tar.gz"'
expect_red generated_archive "auto-generated archive"

# 2 -- a v-prefixed tag: the spelling every recipe carried before.
fixture v_prefixed_tag
set_source v_prefixed_tag '    "'"$rname"'-$pkgver::git+https://github.com/LibreSCRS/'"$rname"'.git#tag=v$pkgver?signed"'
expect_red v_prefixed_tag "v-prefixed tag"

# 3 -- the tag without ?signed: makepkg checks nothing out of the ordinary and
#      builds whatever tree the name points at.
fixture unsigned_tag
set_source unsigned_tag '    "'"$rname"'-$pkgver::git+https://github.com/LibreSCRS/'"$rname"'.git#tag=$pkgver"'
expect_red unsigned_tag "no ?signed"

# 4 -- the release tarball the recipe used to fetch: its sum could only be
#      written after the release, and nothing ties its bytes to a signature.
fixture release_tarball
set_source release_tarball '    "$pkgbase-$pkgver.tar.gz::https://github.com/LibreSCRS/'"$rname"'/releases/download/$pkgver/librelinux_$pkgver.orig.tar.gz"'
expect_red release_tarball "is not this repository's signed release tag"

# 5 -- a SIBLING repository's tag. These recipes are near-copies of one
#      another, so this is what a careless copy produces.
fixture sibling_repo
set_source sibling_repo '    "'"$rname"'-$pkgver::git+https://github.com/LibreSCRS/NotThisRepo.git#tag=$pkgver?signed"'
expect_red sibling_repo "while this repository is"

# 6 -- a local name build() does not cd into.
fixture local_name
set_source local_name '    "'"$rname"'::git+https://github.com/LibreSCRS/'"$rname"'.git#tag=$pkgver?signed"'
expect_red local_name "is not spelled"

# 7 -- pkgver disagrees with VERSION.
fixture pkgver_drift
sed -i 's/^pkgver=.*/pkgver=4.2.0/' "$(recipe_of pkgver_drift)"
expect_red pkgver_drift "arm2: version drift"

# 8 -- VERSION missing entirely. A missing input is a failure, not a skip.
fixture no_version
rm -f "$(fx no_version)/VERSION"
expect_red no_version "arm2"

# 9 -- the vacuum: source=() renamed so the pattern matches nothing.
fixture vacuum_source
sed -i 's/^source=(/sources=(/' "$(recipe_of vacuum_source)"
expect_red vacuum_source "vacuum"

# 10 -- a second source beside the tag.
fixture two_sources
sed -i '/^source=(/a\    "extra.patch"' "$(recipe_of two_sources)"
sed -i "s/^sha256sums=('SKIP')/sha256sums=('SKIP' '$(printf '%064d' 0)')/" "$(recipe_of two_sources)"
expect_red two_sources "expected exactly one entry"

# 11 -- validpgpkeys names a key that is not the release key.
fixture wrong_key
sed -i -E "s/^validpgpkeys=\('[0-9A-F]{40}'\)/validpgpkeys=('0123456789ABCDEF0123456789ABCDEF01234567')/" "$(recipe_of wrong_key)"
expect_red wrong_key "but the release key in KEYS is"

# 12 -- no validpgpkeys at all: ?signed then trusts any key the builder trusts.
fixture no_key
sed -i '/^validpgpkeys=/d' "$(recipe_of no_key)"
expect_red no_key "no validpgpkeys"

# 13 -- a sum written for the git source.
fixture git_sum
sed -i "s/^sha256sums=('SKIP')/sha256sums=('$(printf '%064d' 0)')/" "$(recipe_of git_sum)"
expect_red git_sum "carries the sum"

# 14 -- more sums than sources: makepkg pairs them by position.
fixture sum_count
sed -i "s/^sha256sums=('SKIP')/sha256sums=('SKIP' 'SKIP')/" "$(recipe_of sum_count)"
expect_red sum_count "makepkg pairs them"

# 15 -- the RPM spec states another version than VERSION.
fixture spec_drift
sed -i -E 's/^(Version:[[:space:]]+).*/\14.2.0/' "$(fx spec_drift)/$spec_rel"
expect_red spec_drift "arm2c: version drift"

# 16 -- a submodule gitlink the recipe does not pin. The perturbation is in
#       the INDEX, invisible in the recipe text.
fixture gitlink_drift
git -C "$(fx gitlink_drift)" update-index --add \
    --cacheinfo 160000,1111111111111111111111111111111111111111,thirdparty/not-pinned \
    >/dev/null 2>&1
if [ -z "$(git -C "$(fx gitlink_drift)" ls-files -s -- thirdparty/not-pinned)" ]; then
    echo "CASE gitlink_drift: the gitlink was not written -- the perturbation changed nothing"
    cases=$((cases + 1)); fails=$((fails + 1))
else
    expect_red gitlink_drift "arm3: submodule"
fi

# 17 -- the FetchContent pin drifts from the cmake module the build fetches
#       with. Only applies where the recipe carries one.
if grep -q '^_qcbor_commit=' "$control_recipe"; then
    fixture fetchcontent_drift
    sed -i -E 's/^([[:space:]]*GIT_TAG[[:space:]]+)[0-9a-f]{40}/\12222222222222222222222222222222222222222/' \
        "$(fx fetchcontent_drift)/cmake/FetchQCBOR.cmake"
    cases=$((cases + 1)); red=$((red + 1))
    run fetchcontent_drift
    case "$rc:$out" in
        0:*) echo "CASE fetchcontent_drift: expected a non-zero exit, got 0"; fails=$((fails + 1)) ;;
        *"arm3b: QCBOR pin drift"*) echo "ok   fetchcontent_drift (rc=$rc)" ;;
        *) echo "CASE fetchcontent_drift: no line mentions the pin drift"; fails=$((fails + 1)) ;;
    esac
else
    echo "CASE fetchcontent_drift: not applicable -- this recipe carries no _qcbor_commit"
fi

# 18 -- control: the real recipe, untouched, must pass, and every arm must
#       say what it measured.
fixture control
cases=$((cases + 1))
run control
if [ "$rc" -ne 0 ]; then
    echo "CASE control: the committed recipe does not pass its own gate (rc=$rc)"
    printf '%s\n' "$out" | sed 's/^/    /'; fails=$((fails + 1))
else
    for arm in "arm1:" "arm1b:" "arm2:" "arm2c:" "arm3:" "arm3b:" "arm4:"; do
        case "$out" in *"$arm"*) : ;; *)
            echo "CASE control: $arm said nothing about itself -- a silent arm is a vacuum"
            fails=$((fails + 1)) ;;
        esac
    done
    echo "ok   control"
fi

if [ "$fails" -eq 0 ]; then
    echo "check-recipe selftest: all $cases cases passed"
    printf 'selftest: %s cases, %s red-proved\n' "$cases" "$red"
    exit 0
fi
echo "check-recipe selftest: $fails of $cases case(s) failed"
printf 'selftest: %s cases, %s red-proved\n' "$cases" "$red"
exit 1
