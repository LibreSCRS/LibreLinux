#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# check-recipe.sh
#
# The Arch recipe must build this project's own signed release tag, and must
# say true things about it. Every arm prints what it measured, a skip
# included, because a silent skip is a vacuum and not a pass.
#
#   1  source= holds exactly one entry, and it is this repository's own git
#      source at the release tag, signature required:
#        <Repository>-$pkgver::git+https://github.com/LibreSCRS/<Repository>.git#tag=$pkgver?signed
#      Refused: GitHub's generated archive (its bytes are not ours to assert),
#      a v-prefixed tag (no tag in this stack is written so), a sibling
#      repository (these recipes are near-copies of one another), a tag
#      without ?signed (makepkg would build an unverified tree), and a local
#      name other than the <Repository>-$pkgver directory build() enters.
#   1b validpgpkeys names exactly one key, the primary fingerprint of KEYS at
#      the repository root: the key the release tags are signed with. ?signed
#      without it accepts any signature makepkg happens to trust.
#   2  pkgver equals the first line of VERSION, and so does the RPM spec's
#      Version: -- pkgver only labels the package; the installed CMake version
#      file is generated from VERSION.
#   3  every submodule gitlink is pinned verbatim in the recipe; and a
#      FetchContent pin carried by the recipe equals the pin in the cmake module
#      the build would otherwise fetch with.
#   4  sha256sums has one entry per source; a git source's entry is SKIP (a
#      checkout has no bytes a sum could pin -- the signature binds it) and
#      any other source's entry is a real 64-hex sum. This holds before the
#      tag exists as much as after it: no release asset is left in the recipe
#      whose sum has to wait for the release.
#
# Threat model. This reads the recipe as TEXT rather than sourcing it, so it
# guards against the honest regression: someone edits source=, bumps a version
# or refreshes a pin in the shapes this repository actually writes, and gets one
# of them wrong. It does not resist a recipe written to conceal intent: a URL
# assembled from variables, an architecture array (source_x86_64=()), a
# source=( or its closing ) not at column 0, a pin present only in a comment.
# Code review, not this gate, is what catches a recipe written to mislead.
#
# The repository's name is CHECK_RECIPE_REPO, else the repository part of
# GITHUB_REPOSITORY, else the name in the origin URL, else the directory name
# -- a clone may sit in a directory named anything.
#
# Exit: 0 every arm agrees; 1 an arm found a disagreement; 2 cannot judge (no
# recipe, no KEYS, no gpg).
set -u

[ "$#" -eq 0 ] || { echo "usage: check-recipe.sh" >&2; exit 2; }

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
root=$(CDPATH= cd -- "$here/../.." && pwd)
recipe="$here/PKGBUILD"

rc=0
note() { printf '%-6s %s\n' "$1" "$2"; }
bad()  { note FAIL "$1"; rc=1; }

[ -f "$recipe" ] || { note FAIL "no PKGBUILD next to this script ($recipe)"; exit 2; }

ghrepo="${GITHUB_REPOSITORY:-}"
reponame="${CHECK_RECIPE_REPO:-${ghrepo#*/}}"
if [ -z "$reponame" ]; then
  reponame=$(git -C "$root" remote get-url origin 2>/dev/null | sed -E 's#\.git$##; s#.*/##')
fi
[ -n "$reponame" ] || reponame=$(basename "$root")

pkgver=$(sed -nE 's/^pkgver=([^[:space:]#]+).*/\1/p' "$recipe" | head -1)
[ -n "$pkgver" ] || bad "no pkgver= in $recipe"

# array <name>: the quoted entries of a column-0 `<name>=( ... )` array, one per
# line, whether it is written on one line or several. A `#` outside quotes
# starts a comment; inside quotes it is part of the entry (#tag=...).
array() {
  awk -v name="$1" '
    !on && index($0, name "=(") == 1 { on = 1; $0 = substr($0, length(name) + 3) }
    on {
      q = ""; cur = ""
      for (i = 1; i <= length($0); i++) {
        c = substr($0, i, 1)
        if (q != "") { if (c == q) { print cur; cur = ""; q = "" } else cur = cur c; continue }
        if (c == "\"" || c == "\047") { q = c; continue }
        if (c == "#") break
        if (c == ")") { on = 0; exit }
      }
    }' "$recipe"
}

# --- arm 1 -----------------------------------------------------------------
mapfile -t entries < <(array source)
n=${#entries[@]}
if ! grep -q '^source=(' "$recipe"; then
  bad "arm1: no 'source=(' ... ')' array in the recipe -- the pattern matches nothing, which is a vacuum and not a pass"
elif [ "$n" -eq 0 ]; then
  bad "arm1: the source=() array holds no entries"
else
  want="$reponame-\$pkgver::git+https://github.com/LibreSCRS/$reponame.git#tag=\$pkgver?signed"
  own=0
  for e in "${entries[@]}"; do
    case "$e" in
      *archive/refs/tags*)
        bad "arm1: fetches GitHub's auto-generated archive, whose bytes this project does not produce: $e" ;;
    esac
    case "$e" in
      *'tag=v$pkgver'*|*'tag=v${pkgver}'*|*'/v$pkgver'*|*'/v${pkgver}'*)
        bad "arm1: asks for a v-prefixed tag; every tag this project publishes is unprefixed: $e" ;;
    esac
    case "$e" in
      *git+https://github.com/LibreSCRS/*)
        rest=${e#*git+https://github.com/LibreSCRS/}
        erepo=${rest%%[./#]*}
        if [ "$erepo" != "$reponame" ]; then
          bad "arm1: the git source is LibreSCRS/$erepo while this repository is $reponame -- a recipe copied between siblings builds the other one's sources"
        elif [ "$e" = "$want" ]; then
          own=$((own + 1))
        else
          case "$e" in *'?signed') ;; *) bad "arm1: the git source does not require a signed tag (no ?signed): $e" ;; esac
          bad "arm1: the git source is not spelled '$want': $e"
        fi ;;
      *) bad "arm1: '$e' is not this repository's signed release tag -- the one source a release recipe builds" ;;
    esac
  done
  printf 'arm1: %d source entr%s, %d the signed tag of LibreSCRS/%s\n' \
    "$n" "$([ "$n" -eq 1 ] && echo y || echo ies)" "$own" "$reponame"
  [ "$n" -eq 1 ] && [ "$own" -eq 1 ] || bad "arm1: expected exactly one entry, the signed tag of LibreSCRS/$reponame"
fi

# --- arm 1b ----------------------------------------------------------------
keys="$root/KEYS"
if [ ! -f "$keys" ]; then
  note FAIL "arm1b: $keys is missing -- the key the recipe trusts cannot be compared with anything"
  exit 2
fi
command -v gpg >/dev/null 2>&1 || { note FAIL "arm1b: gpg is not installed -- cannot read KEYS"; exit 2; }
gh="$(mktemp -d "${TMPDIR:-/var/tmp}/check-recipe-gpg.XXXXXX")" || exit 2
trap 'rm -rf "$gh"' EXIT
mapfile -t published < <(GNUPGHOME="$gh" gpg --batch --show-keys --with-colons "$keys" 2>/dev/null \
  | awk -F: '$1 == "pub" {p = 1; next} p && $1 == "fpr" {print $10; p = 0}')
if [ "${#published[@]}" -ne 1 ]; then
  note FAIL "arm1b: KEYS holds ${#published[@]} primary key(s), not one -- cannot say which one the recipe must name"
  exit 2
fi
mapfile -t trusted < <(array validpgpkeys)
if [ "${#trusted[@]}" -eq 0 ]; then
  bad "arm1b: no validpgpkeys -- ?signed then accepts a signature by any key makepkg trusts"
elif [ "${#trusted[@]}" -ne 1 ]; then
  bad "arm1b: validpgpkeys names ${#trusted[@]} keys; the release tags are signed by one"
elif [ "${trusted[0]}" != "${published[0]}" ]; then
  bad "arm1b: validpgpkeys names ${trusted[0]}, but the release key in KEYS is ${published[0]}"
else
  printf 'arm1b: validpgpkeys is the release key in KEYS (%s)\n' "${published[0]}"
fi

# --- arm 2 -----------------------------------------------------------------
vf="$root/VERSION"
declared=""
if [ ! -f "$vf" ]; then
  bad "arm2: $vf is missing -- pkgver cannot be shown to agree with anything"
else
  declared=$(sed -n '1p' "$vf" | tr -d '[:space:]'); declared=${declared#v}
  if [ -z "$declared" ]; then
    bad "arm2: first line of VERSION is empty"
  elif [ "$declared" != "$pkgver" ]; then
    bad "arm2: version drift -- VERSION says $declared, the recipe says pkgver=$pkgver"
  else
    printf 'arm2: pkgver=%s equals the first line of VERSION\n' "$pkgver"
  fi
fi

spec="$root/packaging/rpm/librelinux.spec"
if [ ! -f "$spec" ]; then
  printf 'arm2c: no packaging/rpm/librelinux.spec -- nothing to compare against VERSION\n'
elif [ -n "$declared" ]; then
  specver=$(sed -nE 's/^Version:[[:space:]]+([^[:space:]]+).*/\1/p' "$spec" | head -1)
  if [ -z "$specver" ]; then
    bad "arm2c: no 'Version:' line in $spec"
  elif [ "$specver" != "$declared" ]; then
    bad "arm2c: version drift -- VERSION says $declared, $spec says Version: $specver"
  else
    printf 'arm2c: %s Version: %s matches VERSION\n' "$(basename "$spec")" "$specver"
  fi
fi

# --- arm 3 -----------------------------------------------------------------
# Read from the index, not from HEAD: the gate judges the tree it is run over.
gl=0; ok=0
while read -r mode sha _stage path; do
  [ "$mode" = 160000 ] || continue
  gl=$((gl + 1))
  if grep -q "$sha" "$recipe"; then ok=$((ok + 1))
  else bad "arm3: submodule $path is pinned at $sha, which appears nowhere in the recipe"; fi
done < <(git -C "$root" ls-files -s 2>/dev/null)
printf 'arm3: %d submodule gitlink(s), %d pinned in the recipe\n' "$gl" "$ok"

fm="$root/cmake/FetchQCBOR.cmake"
rp=$(sed -nE 's/^_qcbor_commit=([0-9a-f]{40}).*/\1/p' "$recipe" | head -1)
if [ -n "$rp" ] && [ ! -f "$fm" ]; then
  bad "arm3b: the recipe pins _qcbor_commit=$rp but $fm is missing -- nothing to keep it in lockstep with"
elif [ -n "$rp" ]; then
  mapfile -t decl < <(sed -nE 's/^[[:space:]]*GIT_TAG[[:space:]]+([0-9a-f]{40})[[:space:]]*$/\1/p' "$fm")
  if [ "${#decl[@]}" -ne 1 ]; then
    bad "arm3b: cmake/FetchQCBOR.cmake must hold exactly one 'GIT_TAG <40-hex>' line; found ${#decl[@]}"
  elif [ "${decl[0]}" != "$rp" ]; then
    bad "arm3b: QCBOR pin drift -- cmake says ${decl[0]}, the recipe says $rp"
  else
    printf 'arm3b: QCBOR pin %s matches cmake/FetchQCBOR.cmake\n' "$rp"
  fi
else
  printf 'arm3b: the recipe carries no _qcbor_commit -- nothing to keep in lockstep\n'
fi

# --- arm 4 -----------------------------------------------------------------
mapfile -t sums < <(array sha256sums)
if [ "${#sums[@]}" -eq 0 ]; then
  bad "arm4: no sha256sums entries found -- the pattern matches nothing, which is a vacuum and not a pass"
elif [ "${#sums[@]}" -ne "$n" ]; then
  bad "arm4: ${#sums[@]} sha256sums entries for $n source entries -- makepkg pairs them by position"
else
  n_bad=0
  for i in "${!entries[@]}"; do
    e=${entries[$i]} v=${sums[$i]}
    case "$e" in
      *::git+*|git+*)
        if [ "$v" != SKIP ]; then
          bad "arm4: the git source '$e' carries the sum '$v' -- a checkout has no bytes a sum pins; its signature does"
          n_bad=$((n_bad + 1))
        fi ;;
      *)
        if [ "${#v}" -ne 64 ] || [[ "$v" == *[!0-9a-f]* ]]; then
          bad "arm4: '$e' has no real checksum ('$v')"
          n_bad=$((n_bad + 1))
        fi ;;
    esac
  done
  printf 'arm4: %d sha256sums entr%s, %d wrong for its source\n' \
    "${#sums[@]}" "$([ "${#sums[@]}" -eq 1 ] && echo y || echo ies)" "$n_bad"
fi

echo "check-recipe: $([ $rc -eq 0 ] && echo GREEN || echo RED)"
exit "$rc"
