#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# to-deb-install.sh <payload-name>  -> a debhelper .install list on stdout
#
# The payload lists are the single source of truth for what each package
# carries; the Arch recipe reads them and so does the payload check. Translating
# them here rather than maintaining a third hand-written copy is the whole point.
#
# One mapping is not mechanical and must not be made so. The lists are
# prefix-relative and were written for a layout where the library directory is
# plain "lib", so two different things start with lib/:
#
#   lib/systemd/user/...  is /usr/lib/systemd/user everywhere. systemd does not
#                         read a multiarch or lib64 path, so this one stays
#                         literal.
#   lib/<anything else>   is the library directory, which is
#                         lib/x86_64-linux-gnu on Debian and lib64 on Fedora,
#                         so this one becomes a glob.
#
# Getting that backwards installs a unit into a directory the manager never
# looks at, which fails nothing and starts nothing.
set -euo pipefail
list="$(dirname "${BASH_SOURCE[0]}")/${1:?usage: to-deb-install.sh <payload-name>}.files"
[ -f "$list" ] || { echo "payload list $list is missing" >&2; exit 1; }

while IFS= read -r p || [ -n "$p" ]; do
  case "$p" in ''|'#'*) continue ;; esac
  case "$p" in
    lib/systemd/user/*) echo "usr/$p" ;;
    lib/*)              echo "usr/lib/*/${p#lib/}" ;;
    *)                  echo "usr/$p" ;;
  esac
done < "$list"
