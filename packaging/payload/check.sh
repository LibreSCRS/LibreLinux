#!/usr/bin/env bash
# check.sh <staged-usr-dir>
#
# The split packages' payload is declared in packaging/payload/*.files, and the
# recipe installs from those same files. This compares them with a real staged
# `cmake --install` tree in BOTH directions:
#
#   * a path claimed but not installed  -> error, named
#   * a file installed but not claimed  -> error, named
#   * a pattern matching nothing        -> error, named
#
# The third one is not decoration. Two Serbian message catalogues were never
# claimed by any spelling, and two more paths were claimed under names nothing
# installs; the recipe aborted partway through under `set -e` for the second
# pair and silently shipped without the first. A rename that stops matching has
# to fail loudly rather than pass vacuously.
#
# Symlinks count as installed files. A shared library ships as three entries —
# libfoo.so.X.Y.Z and the two symlinks that make it linkable and loadable — and
# `find -type f` sees only the first, so a package could ship the real file, no
# SONAME link, and pass a check that never looked.
#
# usr/share/licenses/<pkg>/LICENSE is installed by the recipe from the source
# tree, not from the staged install, so it is excluded from the comparison.
set -u

usage() { echo "usage: check.sh <staged-usr-dir>" >&2; exit 2; }

[ "$#" -eq 1 ] || usage
stage=$1
[ -d "$stage" ] || { echo "not a directory: $stage" >&2; exit 2; }

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
shopt -s nullglob
lists=("$here"/*.files)
shopt -u nullglob
[ "${#lists[@]}" -gt 0 ] || { echo "no *.files under $here — nothing to compare, and that is not a pass" >&2; exit 2; }

rc=0
claimed=$(mktemp); trap 'rm -f "$claimed" "$installed" "$claimed_s" "$installed_s"' EXIT
installed=$(mktemp); claimed_s=$(mktemp); installed_s=$(mktemp)

for list in "${lists[@]}"; do
    while IFS= read -r pattern || [ -n "$pattern" ]; do
        case "$pattern" in ''|'#'*) continue;; esac
        # Expand the pattern against the staged tree. A literal path is just a
        # pattern with no wildcard, so both go through the same expansion and
        # the same empty-match rule.
        n=0
        while IFS= read -r hit; do
            [ -e "$hit" ] || [ -L "$hit" ] || continue
            printf '%s\n' "${hit#"$stage"/}" >> "$claimed"
            n=$((n + 1))
        done < <(compgen -G "$stage/$pattern" || true)
        if [ "$n" -eq 0 ]; then
            echo "MISSING   $(basename "$list"): '$pattern' matches nothing under $stage"
            rc=1
        fi
    done < "$list"
done

find "$stage" \( -type f -o -type l \) \
    | sed "s|^$stage/||" \
    | grep -v '^share/licenses/' \
    > "$installed"

sort -u "$claimed"    > "$claimed_s"
sort -u "$installed"  > "$installed_s"

while IFS= read -r orphan; do
    echo "UNCLAIMED $orphan  — installed, but no packaging/payload/*.files line claims it"
    rc=1
done < <(comm -13 "$claimed_s" "$installed_s")

# A path claimed by two packages would be a file-ownership conflict at install
# time, which pacman reports as "exists in filesystem" only once both packages
# are built. Cheaper to say here.
while IFS= read -r dup; do
    echo "DOUBLE    $dup  — claimed by more than one payload list"
    rc=1
done < <(sort "$claimed" | uniq -d)

n_installed=$(wc -l < "$installed_s")
n_claimed=$(wc -l < "$claimed_s")
printf '%s files installed, %s claimed, %s orphaned\n' \
    "$n_installed" "$n_claimed" "$(comm -13 "$claimed_s" "$installed_s" | wc -l)"
exit "$rc"
