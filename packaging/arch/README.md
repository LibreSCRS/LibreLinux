# Arch packaging — librelinux (split: librescrs-agent + librescrs-pinentry-kde)

`pkgbase=librelinux` builds **two** packages from one source tree:

| package                  | what                                   | Qt? |
|--------------------------|----------------------------------------|-----|
| `librescrs-agent`        | headless D-Bus session agent           | no  |
| `librescrs-pinentry-kde` | KDE secure PIN/CAN entry prompter      | yes |

The split keeps the agent Qt-free: installing only `librescrs-agent` pulls
**no** Qt/KF6 into the closure. `librescrs-pinentry-kde` depends on the agent,
`librescrs-middleware>=5.0` (it links `LibreSCRS::Secure` =
`libLibreSCRS_Auth.so` for secure input handling), plus
`qt6-base kcoreaddons ki18n`.

The `PKGBUILD` is **release-shaped**: its one source is this repository's
signed release tag, fetched with git (`#tag=$pkgver?signed`), and makepkg
refuses it unless the tag is signed by the key in `validpgpkeys` -- the
LibreSCRS release key, the primary key in [`KEYS`](../../KEYS).
`pkgver` is the first line of the repository's `VERSION` file: this component
no longer carries its own 0.x SemVer and is released in lockstep with the
rest of the stack.

## What lands where (system / package install — the default, NOT user-install)

The package build does NOT pass `LIBRELINUX_USER_INSTALL`, so units land in
the FHS system dirs the session bus + `systemctl --user` actually read.

**The payload is not listed here.** It lives in
[`packaging/payload/agent.files`](../payload/agent.files) and
[`packaging/payload/pinentry-kde.files`](../payload/pinentry-kde.files), which
are the same two files the recipe installs from and
[`packaging/payload/check.sh`](../payload/check.sh) compares against a real
staged `cmake --install` tree in both directions. A third hand-maintained copy
here is how the previous list went wrong: two of its paths named files nothing
installs, and two message catalogues were missing from every copy.

The one thing worth saying in prose, because a reader would not guess it from a
path: the polkit action must go to the **system** actions dir, because polkit
reads actions only from there, and without it `PolkitAuthorizer` cannot
authorize `org.librescrs.agent.sign`.

## Release build (after the `5.0.0` tag is published)

```sh
gpg --import KEYS   # once: the key makepkg checks the tag's signature against
cd packaging/arch
makepkg -si         # clones the tag, verifies its signature, builds and
                    # installs both split packages
```

A git source has no bytes a checksum could pin, so its `sha256sums` entry is
`SKIP`; the tag's signature is what binds the build to the release, and it is
checkable the moment the tag exists.

## Local dogfood build (no remote, no tag — build from this checkout)

Override the source to your local working tree:

```sh
REPO="$(git rev-parse --show-toplevel)"
mkdir -p /var/tmp/ll-arch && cp packaging/arch/PKGBUILD /var/tmp/ll-arch/
cd /var/tmp/ll-arch
# Replace the release `source=(...)` array wholesale with a single local-git
# entry, and drop the signature requirement a working tree cannot meet.
# A git source named exactly LibreLinux-$pkgver checks out to
# $srcdir/LibreLinux-$pkgver — matching the hardcoded `cd` lines.
sed -i \
  -e "/^source=(/,/^)/c\\source=(\"LibreLinux-\$pkgver::git+file://$REPO\")" \
  -e "/^validpgpkeys=/d" \
  PKGBUILD
makepkg -si
```

> `librescrs-middleware` must be installed first (it provides the
> `LibreMiddleware` CMake config package and the runtime `.so`s the agent
> links). Build/install that package before this one.
