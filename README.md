# LibreLinux

The Linux broker for the LibreSCRS smart-card ecosystem: the per-user
**LibreSCRS Agent** (`librescrs-agent`) — a headless, Qt-free D-Bus session
service that is the single owner of the card and its secrets. Desktop clients
(LibreKDE) reach it over D-Bus; standard PKCS#11 apps reach the card through the
`librescrs-pkcs11-agent` client module. System-level integration (PAM,
lockscreen) comes later.

Built on LibreMiddleware (LGPL-2.1+).

## Current status

The agent is a working per-user card broker. It claims `org.librescrs.Agent`
on the session bus and exposes the reader/card tree via
`org.freedesktop.DBus.ObjectManager` (real exported Reader1 / Card1 objects
driven by LibreMiddleware's MonitorService), plus typed `Operation1`
sub-interfaces for:

- **reader monitoring** — live reader/card presence over ObjectManager;
- **identity / photo / certificate read** — Serbian eID, vehicle and health
  cards plus generic eMRTD / PKCS#15 tokens, with credential activation
  (CAN / MRZ / PIN) collected through the pluggable prompter;
- **AdES signing** — baseline profiles B-B through B-LT/B-LTA (timestamped
  and long-term), with the signing PIN gathered by the prompter.

Hardening is in place: client authorization is gated through **polkit**
(`PolkitAuthorizer`; falls back to a fail-closed-trust-tier default gate when
polkit is unreachable), secrets are passed as **sealed memfds**, the daemon is
**Qt-free** and runs under a strict systemd sandbox, and outbound network
egress (timestamp / trusted-list / OCSP-CRL) is filtered by an in-code SSRF
guard backed by a best-effort cgroup egress allowlist. Secure PIN/CAN/MRZ entry
lives in a separate `librescrs-pinentry-kde` prompter (the Qt/KF6 boundary),
which the headless agent calls over a private session-bus interface.

## Build

```sh
cmake --preset debug
cmake --build build/debug
ctest --preset debug
```

The preset expects LibreMiddleware ≥ 4.2 installed at
`$HOME/.local/librescrs` (override via `CMAKE_PREFIX_PATH`). System
dependencies: `sdbus-cpp` ≥ 2.0, `libsystemd`, GoogleTest,
`dbus-run-session` (for the integration test). The Qt/KF6 prompter
additionally needs Qt 6.6+ and KF6 (toggle off with
`-DLIBRELINUX_BUILD_PROMPTER_KDE=OFF` for headless/server profiles).

## Running it on your own machine

To install and run the whole stack (agent + prompter + the LibreKDE desktop
clients) without root on a local Linux box, see
[`docs/dogfooding.md`](docs/dogfooding.md). The short version: configure with
the `user` preset, which installs into `$HOME/.local` with the systemd unit
and D-Bus service files placed in the per-user XDG directories.

```sh
cmake --preset user                 # -DCMAKE_INSTALL_PREFIX=$HOME/.local -DLIBRELINUX_USER_INSTALL=ON
cmake --build --preset user
cmake --install build/user
systemctl --user daemon-reload
```
