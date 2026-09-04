#!/usr/bin/env bash
# Runs INSIDE a fresh container. /pkg holds this repository's packages,
# /pkg-<Repo> the upstream ones.
#
# The five files this package has to put in root-owned system directories are
# named one at a time. The p11-kit registration is the one that catches a unit
# or a module landing in lib64 on a target whose library directory is not lib.
set -uo pipefail
fail=0
check() { if [ "$2" -eq 0 ]; then echo "PASS $1"; else echo "FAIL $1"; fail=1; fi; }

if [ "${FAMILY:-deb}" = deb ]; then
  export DEBIAN_FRONTEND=noninteractive
  # The base container is not a machine. Ubuntu's image ships
  # /etc/dpkg/dpkg.cfg.d/excludes with path-exclude=/usr/share/locale/*/LC_MESSAGES/*.mo
  # (Debian's does not), so a package that carries translations installs without
  # them there. Asserting on disk under that configuration measures the image,
  # not the package, so the exclusion goes before anything is installed.
  rm -f /etc/dpkg/dpkg.cfg.d/excludes
  apt-get update -qq
  apt-get install -y -qq p11-kit dbus-daemon >/dev/null
  # Runtime packages only, and no LibreAgent package at all. The agent links
  # the core statically, so it depends on that package to BUILD and on nothing
  # from it at runtime -- installing the agent development packages here would
  # also drag in the middleware development package, and asserting over a set
  # nobody would install proves nothing about what a user gets.
  apt-get install -y --no-install-recommends \
      /pkg-LibreMiddleware/liblibrescrs5_*.deb \
      /pkg-LibreMiddleware/librescrs-card-plugins_*.deb \
      /pkg/librescrs-agent_*.deb /pkg/librescrs-pinentry-kde_*.deb >/dev/null
  check "V1 agent and prompter install with their upstreams" $?
  LIBGLOB="/usr/lib/*"
  installed_list() { dpkg-query -W -f='${Package}\n'; }
  files_of() { dpkg -L "$1" 2>/dev/null; }
  scripts_of() {
    for s in /var/lib/dpkg/info/librescrs-*.postinst /var/lib/dpkg/info/librescrs-*.postrm \
             /var/lib/dpkg/info/librescrs-*.preinst /var/lib/dpkg/info/librescrs-*.prerm; do
      [ -e "$s" ] || continue; echo "--- $s"; cat "$s"
    done
  }
  remove_ours() { apt-get purge -y $(installed_list | grep -E 'librescrs|liblibrescrs') >/dev/null; }
else
  dnf -y -q install p11-kit dbus-daemon >/dev/null
  # Runtime packages only -- see the Debian branch for why no agent package is
  # installed here.
  dnf -y -q install /pkg-LibreMiddleware/librescrs-middleware-5*.rpm \
      /pkg-LibreMiddleware/librescrs-card-plugins-5*.rpm \
      /pkg/librescrs-agent-5*.rpm /pkg/librescrs-pinentry-kde-5*.rpm >/dev/null
  check "V1 agent and prompter install with their upstreams" $?
  LIBGLOB="/usr/lib64"
  installed_list() { rpm -qa --qf '%{NAME}\n'; }
  files_of() { rpm -ql "$1" 2>/dev/null; }
  scripts_of() { rpm -q --scripts librescrs-agent librescrs-pinentry-kde 2>/dev/null; }
  remove_ours() { dnf -y -q remove $(installed_list | grep -E '^(librescrs|liblibrescrs)') >/dev/null; }
fi

# ── V2: the five system files, one assertion each ─────────────────────────
test -f /usr/share/polkit-1/actions/org.librescrs.agent.configure.policy
check "V2a polkit action" $?
test -f /usr/share/dbus-1/services/org.librescrs.Agent.service
check "V2b D-Bus service activation file" $?
test -f /usr/share/dbus-1/session.d/org.librescrs.Agent.conf
check "V2c D-Bus session policy" $?
# Named literally, not through a variable: systemd reads /usr/lib/systemd/user
# and nowhere else, and a unit installed under lib64 fails nothing and starts
# nothing.
test -f /usr/lib/systemd/user/librescrs-agent.service
check "V2d systemd user unit on /usr/lib/systemd/user" $?
test -f /usr/lib/systemd/user/librescrs-pinentry-kde.service
check "V2d2 prompter user unit on /usr/lib/systemd/user" $?
test -f /usr/lib/systemd/user/librescrs-p11-server.service
check "V2d3 module-server user unit on /usr/lib/systemd/user" $?
test -f /usr/share/p11-kit/modules/librescrs-agent.module
check "V2e p11-kit registration" $?

# ── V4/G4: exactly one provider, whatever installed it ────────────────────
n=$(ls /usr/share/p11-kit/modules/ | grep -c '^librescrs')
test "$n" -eq 1; check "G4 exactly one registration file (counted $n)" $?
ls -1 /usr/share/p11-kit/modules/
n=$(p11-kit list-modules | grep -c '^module: librescrs')
test "$n" -eq 1; check "G4 exactly one registered provider (counted $n)" $?
p11-kit list-modules

# ── V6: nothing of ours enabled anything ──────────────────────────────────
# Measured as the ABSENCE OF A SYMLINK, not with systemctl --user is-enabled:
# in a container with no user manager that command passes vacuously.
found=$(find /etc/systemd/user /usr/lib/systemd/user -name '*.wants' -type d 2>/dev/null \
        -exec find {} -name 'librescrs-*' \; | wc -l)
test "$found" -eq 0; check "V6 no enable symlink of ours (found $found)" $?

# ── V7: D-Bus activation without hardware ─────────────────────────────────
# The .service file carries Exec= as well as SystemdService=, sd_notify is a
# no-op without NOTIFY_SOCKET, and pcscd need not run: zero readers is a pass
# condition, not a failure.
if command -v dbus-run-session >/dev/null 2>&1; then
  # The well-known name is org.librescrs.Agent and the root object is
  # /org/librescrs/Agent -- read from common/AgentInterfaceNames.h, which is the
  # single table the agent itself uses. Asking for a name with a trailing 1
  # returns ServiceUnknown and looks exactly like a broken activation.
  timeout 60 dbus-run-session -- bash -c '
    dbus-send --session --print-reply --dest=org.librescrs.Agent \
      /org/librescrs/Agent org.freedesktop.DBus.Introspectable.Introspect' \
      > /tmp/introspect.txt 2>&1
  rc=$?
  grep -q 'org.freedesktop.DBus.ObjectManager\|org.librescrs.Agent' /tmp/introspect.txt; grc=$?
  test "$rc" -eq 0 -a "$grc" -eq 0
  check "V7 D-Bus activation with no enable and no reader" $?
  head -20 /tmp/introspect.txt
else
  echo "FAIL V7 dbus-run-session is not installed"; fail=1
fi

# ── V8: nothing generated mentions a home directory ───────────────────────
scripts_of > /tmp/scripts.txt 2>&1
if [ -s /tmp/scripts.txt ]; then
  grep -nE 'HOME|\.config|\.local|\.cache' /tmp/scripts.txt; test $? -ne 0
else true; fi
check "V8 no maintainer script touches a home directory" $?

# ── coexistence: every installed path owned exactly once ──────────────────
ours=$(installed_list | grep -E 'librescrs|liblibrescrs' | sort -u)
: > /tmp/all.txt
for p in $ours; do files_of "$p" | while read -r f; do [ -f "$f" ] || [ -L "$f" ] && echo "$f"; done; done \
  | sort > /tmp/all.txt
uniq -d < /tmp/all.txt > /tmp/dupes.txt
n=$(wc -l < /tmp/all.txt); echo "PATH_COUNT=$n"
# An empty list has no duplicates either. Without this the whole claim passes
# vacuously the moment the install step fails, which is precisely when it must
# not.
test "$n" -gt 20; check "V-coexist the path list is not empty (counted $n)" $?
test ! -s /tmp/dupes.txt; check "V-coexist every installed path owned exactly once" $?
[ -s /tmp/dupes.txt ] && cat /tmp/dupes.txt

# ── V11: no unresolved shared-library dependency ──────────────────────────
miss=0
for f in /usr/libexec/librescrs-agent /usr/libexec/librescrs-pinentry-kde \
         $LIBGLOB/pkcs11/librescrs-pkcs11-agent.so; do
  [ -e "$f" ] || continue
  if ldd "$f" 2>/dev/null | grep -q 'not found'; then echo "  not found in $f"; miss=1; fi
done
test "$miss" -eq 0; check "V11 no unresolved shared-library dependency" $?

# ── V9: removal leaves nothing under /usr ─────────────────────────────────
remove_ours
find /usr -iname '*librescrs*' > /tmp/leftover.txt
test ! -s /tmp/leftover.txt; check "V9 nothing left under /usr after removal" $?
[ -s /tmp/leftover.txt ] && cat /tmp/leftover.txt

exit $fail
