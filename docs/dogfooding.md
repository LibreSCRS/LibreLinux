<!--
SPDX-License-Identifier: LGPL-2.1-or-later
SPDX-FileCopyrightText: 2026 hirashix0
-->

# Running the LibreSCRS stack locally (dogfooding)

This guide installs and runs the whole desktop stack on a single Linux box
**without root**, into your home directory:

- `librescrs-agent` — the headless, Qt-free per-user card broker (this repo);
- `librescrs-pinentry-kde` — the KDE secure PIN/CAN/MRZ prompter (this repo);
- the **LibreKDE** clients — the system-tray plasmoid, the Purpose "Sign"
  plugin, and the `card:/` KIO worker (sibling `LibreKDE` repo).

It targets Arch / Manjaro + KDE Plasma 6, but the agent and prompter are
distribution-agnostic. Every path below is the one the `user` install layout
actually produces; cross-check with `cmake --install … --verbose` if in doubt.

> **Security posture under a user install.** The agent uses **polkit**
> (`PolkitAuthorizer`) to authorize clients **whenever polkitd is reachable** —
> which is the case on a normal Arch/Manjaro + KDE box. It only falls back to
> its `DefaultAuthorizer` when there is no system bus / no polkit at all.
> polkit **denies any action id it does not know**, and it reads action files
> **only** from the system dir `/usr/share/polkit-1/actions` (there is no
> per-user actions location). A `cmake --install` into your home prefix
> therefore cannot register the agent's polkit action, and with the action
> missing **every `Card1.Sign` and every trust-tier config change is denied
> with "Not authorized" before the prompter even appears**.
>
> For that reason the dogfood flow has **one unavoidable `sudo` step**
> (Section 3a below): copy the single action file into the system dir. That one
> file registers `org.librescrs.agent.sign`, `org.librescrs.agent.configure`
> and `org.librescrs.agent.configure.trust`, and the shipped defaults
> allow-any for signing/low-tier config (the PIN you type is the human-presence
> proof) while requiring `auth_self` for the trust/timestamping tier. This is
> the only `sudo` in the dogfood flow; everything else lives in `$HOME`.

## 1. Prerequisites

```sh
# Arch / Manjaro
sudo pacman -S --needed pcsclite ccid sdbus-cpp systemd-libs \
    polkit qt6-base kf6 plasma-workspace

# Start the PC/SC daemon and plug in a reader
sudo systemctl enable --now pcscd.socket
pcsc_scan        # optional: confirm the reader + card are seen
```

You need:

- **pcscd running** (`pcscd.socket`) and a PC/SC reader attached;
- **sdbus-c++ ≥ 2.0** and **libsystemd** (build + runtime);
- **Qt 6.6+ and KF6 6.0+** for the prompter and the LibreKDE clients;
- a working **session D-Bus** (any normal graphical login has one);
- a LibreSCRS card to test with (e.g. a Serbian eID "PKS", or an ID card
  "NAM" that needs a CAN, or any eMRTD passport).

## 2. Install LibreMiddleware into the user prefix

The agent links LibreMiddleware ≥ 4.2 and loads its card plugins at runtime.
Install LM into `$HOME/.local/librescrs` (its own self-contained prefix):

```sh
# in the LibreMiddleware checkout
cmake -B build -S . -DCMAKE_BUILD_TYPE=RelWithDebInfo \
    -DCMAKE_INSTALL_PREFIX="$HOME/.local/librescrs" \
    -DLIBREMIDDLEWARE_BUILD_SHARED=ON
cmake --build build -j4
cmake --install build
```

This lands the shared libraries under `$HOME/.local/librescrs/lib` and the
card plugins under `$HOME/.local/librescrs/lib/librescrs/plugins/`
(`libopensc-plugin.so`, `librs-eid-plugin.so`, `libpkcs15-plugin.so`,
`libemrtd-plugin.so`, …).

### Plugin discovery (important)

The agent does **not** ship card plugins — they are LibreMiddleware's. At
startup the agent loads plugins from, in order of precedence:

1. the `LIBRESCRS_PLUGIN_DIR` environment variable, if set; otherwise
2. the compile-time default `${CMAKE_INSTALL_FULL_LIBDIR}/librescrs/plugins`.

Because LM is installed under its **own** prefix (`$HOME/.local/librescrs`)
and the agent under `$HOME/.local`, the compile-time default
(`$HOME/.local/lib/librescrs/plugins`) will **not** contain the plugins. Point
the agent at the LM plugin directory with the env override — wired into the
unit in step 4 below:

```sh
LIBRESCRS_PLUGIN_DIR="$HOME/.local/librescrs/lib/librescrs/plugins"
```

(If you instead install LM and the agent into the *same* prefix, the default
path resolves correctly and no override is needed.)

The agent reports all of this at startup, so you never have to guess which
directory it settled on:

```console
$ journalctl --user -u librescrs-agent | grep 'card plugins'
card plugins: LIBRESCRS_PLUGIN_DIR is not set
card plugins: using /usr/local/lib/librescrs/plugins (the compiled-in default)
card plugins: loaded 0 plugins from /usr/local/lib/librescrs/plugins — that directory does not exist; no card can be used until it does and holds plugins
```

A directory that yields no plugins is worth checking for first: with none
loaded, **every** card reports as unusable, which looks exactly like a card
LibreSCRS does not support. That case is logged at warning level and says which
of three things is wrong, because the fix differs:

| what the warning says | what to do |
|---|---|
| `no card can be used until this directory holds plugins` | the directory is there and empty — install LibreMiddleware's plugins into it, or point the override at where they already are |
| `that directory does not exist` | create it, or fix the override — nothing is at that path |
| `that directory could not be read (…)` | the directory exists but the agent cannot look inside it; fix the permissions on it or a parent |

A healthy start instead reports `loaded 6 plugins from …` at info with no
warning, and any plugin file that failed to load is named with its diagnostic
(`… was not loaded (plugin ABI mismatch): expected ABI 8 got 6`).

## 3. Build and install the agent + prompter (`--user`)

From this repository:

```sh
cmake --preset user            # = -DCMAKE_INSTALL_PREFIX=$HOME/.local
                               #   -DLIBRELINUX_USER_INSTALL=ON
                               #   -DCMAKE_PREFIX_PATH=$HOME/.local/librescrs
cmake --build --preset user
cmake --install build/user
```

The `user` preset's `LIBRELINUX_USER_INSTALL=ON` redirects the systemd and
D-Bus files into the per-user XDG locations (instead of the system paths
pkg-config returns). The result:

| Artifact | Path |
|---|---|
| `librescrs-agent`, `librescrs-pinentry-kde` | `~/.local/libexec/` |
| systemd user units | `~/.config/systemd/user/` |
| D-Bus session service files | `~/.local/share/dbus-1/services/` |
| D-Bus introspection XML | `~/.local/share/dbus-1/interfaces/` |
| D-Bus session policy | *(not installed — system-package-only; stock dbus does not scan `$XDG_CONFIG_HOME/dbus-1/session.d/`, and the session-bus default policy already allows the agent to run)* |
| polkit action | *(not installed by CMake — must be placed in the system dir by hand, see 3a)* |

The generated unit's `ExecStart` points at
`~/.local/libexec/librescrs-agent`, and the D-Bus activation file's `Exec`
matches.

## 3a. Install the polkit action into the system dir (one-time `sudo`)

The agent authorizes `Card1.Sign` and trust-tier config changes through
polkit, and polkit reads action files **only** from `/usr/share/polkit-1/actions`
(no per-user location). The user install above deliberately does **not** write
there. Until the action is registered, polkit denies the (unknown) action ids
and **signing fails with "Not authorized" before the prompter appears**.

Install the single action file once, with root:

```sh
# from this repository's checkout
sudo install -Dm644 agent/data/org.librescrs.agent.configure.policy \
    /usr/share/polkit-1/actions/org.librescrs.agent.configure.policy
```

This registers `org.librescrs.agent.sign` (allow-any — the PIN is the
human-presence proof), `org.librescrs.agent.configure` (allow-any) and
`org.librescrs.agent.configure.trust` (`auth_self`). It is the only `sudo`
in the dogfood flow. Do this **before** `systemctl --user enable --now` in
step 4 so the agent authorizes from the first call.

## 4. Wire plugin discovery into the unit and enable

The installed unit does not know where your LM plugins live, so add the
override with a drop-in (do **not** edit the installed unit in place):

```sh
mkdir -p ~/.config/systemd/user/librescrs-agent.service.d
cat > ~/.config/systemd/user/librescrs-agent.service.d/10-plugins.conf <<EOF
[Service]
Environment=LIBRESCRS_PLUGIN_DIR=%h/.local/librescrs/lib/librescrs/plugins
EOF

systemctl --user daemon-reload
systemctl --user enable --now librescrs-agent.service
```

`%h` expands to your home directory. You normally do **not** start the
prompter by hand: both the agent and the prompter are **D-Bus activated** — the
first method call to `org.librescrs.Agent` (or `org.librescrs.Prompter1`) makes
the session bus ask systemd to start the corresponding unit on demand. The
explicit `enable --now` above just keeps the agent resident so it can monitor
readers continuously.

### Signing module (no drop-in needed)

The native AdES signing path dlopens the LM PKCS#11 module
`librescrs-pkcs11.so`. Because LM lives under its **own** prefix
(`~/.local/librescrs`) that is not exe-relative to the agent, the signing
resolver cannot find it by relative probing — so the **user-install build bakes
the resolved absolute path into the installed unit** as
`Environment=LIBRESCRS_PKCS11_MODULE=…/lib/pkcs11/librescrs-pkcs11.so`
(see `agent/CMakeLists.txt`). You do **not** need a manual drop-in for it; if you
added one previously, you can delete it after reinstalling:

```sh
rm -f ~/.config/systemd/user/librescrs-agent.service.d/20-pkcs11-module.conf
systemctl --user daemon-reload && systemctl --user restart librescrs-agent.service
```

**Verify signing can load its module** (gating check — needs no card or PIN):

```sh
./e2e/check-dogfood-sign-module.sh
```

It resolves the module exactly as the running agent would and confirms it
`dlopen`s with a working `C_GetFunctionList`. Run it after every reinstall; a
non-zero exit means `Card1.Sign` would fail with "cannot open shared object
file" before you ever reach a card.

### Cache / egress reality note

The agent unit declares `CacheDirectory=librescrs`, so systemd creates
`~/.cache/librescrs` and exports `$CACHE_DIRECTORY`; the TSL / AIA / OCSP-CRL
caches for long-term signatures land there (config lives at
`~/.config/librescrs/agent.conf`). The unit also carries an
`IPAddressAllow=any` / `IPAddressDeny=…private-ranges` egress allowlist; for a
`--user` unit this cgroup filter is a **silent no-op** on most stock setups
(IP accounting is usually not delegated to the user manager). The authoritative
egress control is the in-code SSRF guard, so this is defence-in-depth only.

## 5. Install the LibreKDE desktop clients

From the sibling `LibreKDE` checkout. LibreKDE links **no** LibreMiddleware
(it is a pure D-Bus client of the agent), so it only needs the KDE/Qt SDK and
ECM:

```sh
cmake -B build -S . -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX="$HOME/.local"
cmake --build build -j4
cmake --install build
```

By default this builds and installs the plasmoid, the Purpose plugin, and the
KIO worker (`-DLIBREKDE_BUILD_PLASMOID/PURPOSE/KIO=ON`). KDE's `KDEInstallDirs`
decides the exact subpaths from the prefix (the `lib` infix — `lib`, `lib64`,
or `lib/qt6` — is distribution-dependent, so verify against
`build/install_manifest.txt` after installing). With prefix `$HOME/.local` the
layout is:

| Client | Path (relative to `$HOME/.local`) |
|---|---|
| Plasmoid package (`org.librescrs.smartcard`) | `share/plasma/plasmoids/org.librescrs.smartcard/` |
| Plasmoid backing applet | `<libdir>/plugins/plasma/applets/liblibrekde-plasmoid.so` |
| Plasmoid QML plugin + metadata | `<libdir>/qml/org/librescrs/smartcard/` |
| Purpose "Sign" plugin (`librescrs_sign_purpose`) | `<libdir>/plugins/kf6/purpose/` |
| `card:/` KIO worker (`card`) | `<libdir>/plugins/kf6/kio/` |
| AppStream metainfo | `share/metainfo/` |

`<libdir>` is whatever `KDE_INSTALL_LIBDIR` resolved to (read the manifest:
e.g. `lib`, or `lib/qt6` on some distros). For Plasma/Qt to find the
user-prefix QML and plugins, export the matching paths (add to
`~/.config/plasma-workspace/env/` or your shell profile, substituting your real
`<libdir>`):

```sh
export QML2_IMPORT_PATH="$HOME/.local/<libdir>/qml:$QML2_IMPORT_PATH"
export QT_PLUGIN_PATH="$HOME/.local/<libdir>/plugins:$QT_PLUGIN_PATH"
export XDG_DATA_DIRS="$HOME/.local/share:${XDG_DATA_DIRS:-/usr/local/share:/usr/share}"
```

Log out and back in (or `systemctl --user restart plasma-plasmashell`) so
plasmashell, the Purpose loader and KIO pick up the new paths.

## 6. End-to-end check

1. **Reader / identity / photo.** Right-click the system tray → *Add Widgets…*
   → add **LibreSCRS Smart Card** (`org.librescrs.smartcard`). Insert a card.
   The plasmoid should show the reader, then — after the prompter collects any
   required credential (PKS: PIN; NAM: CAN; passport: MRZ) — the identity
   fields and photo. The agent activates on the first call; the prompter pops
   automatically when a credential is needed.

2. **Signing via Purpose.** In Dolphin, right-click a PDF → *Share* → **Sign
   with LibreSCRS smart card**. Choose the signing certificate, then enter the
   PIN in the prompter. A signed file is produced (AdES B-B by default; the
   timestamp/long-term tier follows `~/.config/librescrs/agent.conf`).
   If signing fails with `org.freedesktop.PolicyKit1`/"Not authorized" and the
   prompter never appears, the polkit action from step **3a** is not installed
   in `/usr/share/polkit-1/actions` — install it and retry.

3. **`card:/` browsing.** Type `card:/` into Dolphin's location bar. The KIO
   worker lists the inserted card(s) and their readable objects, talking to the
   same agent.

## 7. Troubleshooting

```sh
# Agent logs (it logs to the journal via the user manager)
journalctl --user -u librescrs-agent -f

# Prompter logs
journalctl --user -u librescrs-pinentry-kde -f

# Is the agent on the bus? What does it export?
busctl --user list | grep librescrs
busctl --user tree org.librescrs.Agent
busctl --user introspect org.librescrs.Agent /org/librescrs/Agent

# Did the unit install where you expect, with the right ExecStart?
systemctl --user cat librescrs-agent.service
systemd-analyze --user verify ~/.config/systemd/user/librescrs-agent.service

# Confirm the plugin dir override took effect
systemctl --user show librescrs-agent.service -p Environment
```

Common issues:

- **No card data, only the reader.** The plugin dir override is missing or
  wrong — check `systemctl --user show … -p Environment` and that the path in
  the step-4 drop-in actually contains `*-plugin.so` files.
- **`org.freedesktop.DBus.Error.ServiceUnknown` / nothing happens.** Run
  `systemctl --user daemon-reload`; confirm `~/.local/share/dbus-1/services/
  org.librescrs.Agent.service` exists and its `Exec` path is correct.
- **Plasmoid not in the Add Widgets list / `card:/` unknown.** The user-prefix
  `QML2_IMPORT_PATH` / `QT_PLUGIN_PATH` / `XDG_DATA_DIRS` from step 5 are not in
  the session environment; re-log so plasmashell inherits them.
- **Prompter never appears.** Confirm `librescrs-pinentry-kde.service` and
  `org.librescrs.Prompter.service` installed, and that you are in a graphical
  session (the prompter needs the display server and KDE platform plugin).
- **Signing or trust-tier config refused with "Not authorized".** The polkit
  action is not registered. The agent gates these through polkit (active
  whenever polkitd is running), and polkit denies unknown action ids. Install
  the action into the system dir per step **3a**:
  `sudo install -Dm644 agent/data/org.librescrs.agent.configure.policy /usr/share/polkit-1/actions/`.
