#!/usr/bin/env bash
# to-rpm-files.sh <payload-name>  -> a %files body on stdout
#
# Same source of truth as the Debian side, same non-mechanical mapping: see
# to-deb-install.sh for why lib/systemd/user is not the library directory.
#
# %{_userunitdir} is named rather than spelled out so that a regression in the
# unit directory becomes a loud build failure -- rpmbuild's check-files stops on
# an unpackaged file -- instead of a service nothing starts.
set -euo pipefail
list="$(dirname "${BASH_SOURCE[0]}")/${1:?usage: to-rpm-files.sh <payload-name>}.files"
[ -f "$list" ] || { echo "payload list $list is missing" >&2; exit 1; }

while IFS= read -r p || [ -n "$p" ]; do
  case "$p" in ''|'#'*) continue ;; esac
  case "$p" in
    lib/systemd/user/*) echo "%{_userunitdir}/${p#lib/systemd/user/}" ;;
    libexec/*)          echo "%{_libexecdir}/${p#libexec/}" ;;
    lib/*)              echo "%{_libdir}/${p#lib/}" ;;
    share/*)            echo "%{_datadir}/${p#share/}" ;;
    *)                  echo "%{_prefix}/$p" ;;
  esac
done < "$list"
