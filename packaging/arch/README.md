# Arch packaging — librelinux (split: librescrs-agent + librescrs-pinentry-kde)

`pkgbase=librelinux` builds **two** packages from one source tree:

| package                  | what                                   | Qt? |
|--------------------------|----------------------------------------|-----|
| `librescrs-agent`        | headless D-Bus session agent           | no  |
| `librescrs-pinentry-kde` | KDE secure PIN/CAN entry prompter      | yes |

The split keeps the agent Qt-free: installing only `librescrs-agent` pulls
**no** Qt/KF6 into the closure. `librescrs-pinentry-kde` depends on the agent,
`librescrs-middleware>=4.2` (it links `LibreMiddleware::Secure` =
`libLibreSCRS_Auth.so` for secure input handling), plus
`qt6-base kcoreaddons ki18n`.

The `PKGBUILD` is **release-shaped** (fetches the `v$pkgver` GitHub tag) and
uses **independent SemVer** (`pkgver=0.1.0`) per the post-A4 roadmap — 0.x
until the D-Bus wire surface freezes. This is distinct from
LibreMiddleware's version.

## What lands where (system / package install — the default, NOT user-install)

The package build does NOT pass `LIBRELINUX_USER_INSTALL`, so units land in
the FHS system dirs the session bus + `systemctl --user` actually read:

- `librescrs-agent`:
  - `/usr/libexec/librescrs-agent`
  - `/usr/lib/systemd/user/librescrs-agent.service`
  - `/usr/share/dbus-1/services/org.librescrs.Agent.service`
  - `/usr/share/dbus-1/interfaces/*.xml` (all interface XMLs)
  - `/usr/share/dbus-1/session.d/org.librescrs.Agent1.conf`
  - **`/usr/share/polkit-1/actions/org.librescrs.agent.configure.policy`**
    (system dir — required so PolkitAuthorizer can authorize
    `org.librescrs.agent.sign`; polkit reads actions only from the system dir)
- `librescrs-pinentry-kde`:
  - `/usr/libexec/librescrs-pinentry-kde`
  - `/usr/lib/systemd/user/librescrs-pinentry-kde.service`
  - `/usr/share/dbus-1/services/org.librescrs.Prompter.service`
  - `/usr/share/dbus-1/session.d/org.librescrs.Prompter1.conf`

## Release build (after the `v0.1.0` tag is pushed)

```sh
cd packaging/arch
updpkgsums      # fills in the real sha256sum
makepkg -si     # builds + installs both split packages
```

## Local dogfood build (no remote, no tag — build from this checkout)

Override the source to your local working tree:

```sh
REPO="$(git rev-parse --show-toplevel)"
mkdir -p /tmp/ll-arch && cp packaging/arch/PKGBUILD /tmp/ll-arch/
cd /tmp/ll-arch
# Replace the multi-line release `source=(...)` array wholesale with a single
# local-git entry (a single-line `s#^source=.*#...#` would mangle the
# multi-line array, leaving a dangling URL line + `)`). `sha256sums` is a
# single line, so a plain `s#` substitution is correct there.
# A git source named exactly LibreLinux-$pkgver checks out to
# $srcdir/LibreLinux-$pkgver — matching the hardcoded `cd` lines.
sed -i \
  -e "/^source=(/,/^)/c\\source=(\"LibreLinux-\$pkgver::git+file://$REPO\")" \
  -e "s#^sha256sums=.*#sha256sums=('SKIP')#" \
  PKGBUILD
makepkg -si
```

> `librescrs-middleware` must be installed first (it provides the
> `LibreMiddleware` CMake config package and the runtime `.so`s the agent
> links). Build/install that package before this one.
