# LibreLinux Changelog

Notable user-visible changes per release. Format follows
[Keep a Changelog](https://keepachangelog.com/) loosely.

## [Unreleased] — 5.0.0

### Added

- **Every release carries a source tarball this project built.** The Arch
  recipe fetches that asset instead of the archive GitHub generates for a tag:
  the generated one omits every submodule tree, and its bytes are not ours to
  assert, so the recipe's `sha256sums` line said nothing about what was
  actually built. The published tarball is a function of the commit — every
  member carries the commit's own timestamp, owner `0/0` and a mode no umask
  can widen — so a packager who rebuilds it gets the same bytes back, up to the
  gzip implementation. It is named so that one file can serve as the `.orig`
  for `dpkg-source`; the `deb` and `rpm` builds still build from the checkout
  and do not consume it yet.

- **The agent and the prompter ship as distribution packages.** `deb` for
  Debian 13 and Ubuntu 26.04 LTS, `rpm` for Fedora 43. Five of the agent's files
  have to land in root-owned system directories — a systemd user unit, two D-Bus
  drop-ins, a polkit action and a p11-kit registration — so no bundle format can
  deliver it, and a distribution package is the only shape it can take.

  **The prompter is a hard dependency, not a suggestion.** An agent with no
  prompter installs, activates over D-Bus, enumerates a card and then fails on
  the first PIN, because the interface it calls has no implementation. The only
  prompter today is built on KF6, so a GNOME or XFCE machine installs KF6::I18n
  and KF6::CoreAddons along with it. That is why Ubuntu 26.04 LTS is the Ubuntu
  target: 24.04 LTS has no KF6 at all.

  **Nothing enables anything.** The unit is D-Bus activated, so the first call
  starts it whether or not it is enabled. Neither packaging system writes a
  preset or a wants symlink of ours, and no maintainer script is hand-written —
  which is also why none of them can touch `~/.config/librescrs` on removal.
  Configuration, cached data, a symlink from your own `systemctl --user enable`
  and an NSS profile entry you added yourself all survive uninstallation, on
  purpose.


First public release of the Linux host for the LibreSCRS smart-card
ecosystem. It ships two components: the per-user **LibreSCRS Agent**
and its secure PIN/CAN entry prompter, plus a client PKCS#11 module.

### Added

- **The agent proxy is the only registered PKCS#11 provider.** The middleware
  no longer registers a PKCS#11 module of its own, so one card offers one
  provider and one PIN-entry model. If a host still carries a hand-made
  registration of the direct module — installed from a published archive,
  following instructions that release shipped — no package manager will remove
  it. Remove it by hand:

  ```
  rm ~/.config/pkcs11/modules/librescrs.module
  ```

- **Per-user smart-card agent (`librescrs-agent`).** A headless,
  Qt-free D-Bus session service that is the single owner of the card
  and its secrets. It claims `org.librescrs.Agent` on the session bus
  and exposes the live reader/card tree over the standard D-Bus
  `ObjectManager` interface, so desktop clients see readers appearing
  and cards being inserted or removed in real time.
- **Card reading.** Identity, photo and certificate reads for Serbian
  eID, vehicle and health cards, plus generic ICAO eMRTD and PKCS#15
  tokens. Card credentials (CAN / MRZ / PIN) are collected through the
  prompter as each card requires them.
- **AdES signing.** Baseline profiles from B-B through B-T
  (timestamped), B-LT and B-LTA (long-term / archival validation
  material), with the signing PIN gathered securely by the prompter.
- **PKCS#11 client module (`librescrs-pkcs11-agent`).** Standard
  PKCS#11 applications reach the card through this module, which
  forwards operations to the agent rather than touching the card
  directly. It performs no cryptography itself: it offers a raw RSA
  sign / decrypt surface with per-operation re-authorization, and
  supports cards that compute the digest on-card.
- **Card PIN and key management.** The agent exposes a session-bus
  surface for listing a card's credentials with their state and
  changing a card PIN, with the required PIN(s) collected securely
  through the prompter and each request gated through **polkit** just
  like signing. The same surface additionally exposes PIN unblocking
  and signing-key activation for cards and plugins that support them;
  on the hardware supported in this release those requests return an
  "unsupported" result.
- **Secure entry prompter (`librescrs-pinentry-kde`).** A separate
  KDE-styled component for PIN / CAN / MRZ entry and PIN changes (with a
  dedicated current / new / confirm dialog), kept isolated from the
  headless agent and called over a private session-bus interface.
- **Security hardening.** Client authorization is gated through
  **polkit**; when polkit is unreachable, a built-in fallback keeps
  polkit's default-allow decision for the operational actions (sign,
  PKCS#11 login, configuration, credential management — the PIN
  remains the consent gate) and fails closed on the trust-elevation
  tier and on unknown actions.
  Secrets travel between components as **sealed in-memory buffers**
  and are never written to disk or logs. The daemon runs under a
  **strict systemd sandbox**, and outbound network access
  (timestamping, trusted lists, revocation) is filtered by an
  SSRF guard backed by a best-effort egress allowlist. The agent
  rate-limits signing and card-use requests to cap abuse under the
  default-allow posture.
- **Country-signing trust anchors.** The agent installs the CSCA
  certificates an electronic passport's signature is checked against,
  from signed ICAO master lists a person supplies. It takes both shapes
  a reader can arrive with: one published master list, or the directory
  export the ICAO Public Key Directory serves, which carries a
  separately signed list for every publishing country — installed in one
  action, with one authorization. The file is handed over as an open
  descriptor, so nothing is read from a path the agent was merely told
  about, and the request is gated through **polkit** on the
  trust-elevation tier, like the trusted lists it sits beside.

  Every list is verified against its own signer and the anchors kept are
  the union of the ones that survived; a list that does not verify is
  refused on its own without costing the rest. A publisher's later list
  must be strictly newer than the one already taken from that publisher,
  so a rollback to withdrawn anchors is refused. What the agent holds is
  readable over the session bus — how many anchors, how many issuing
  countries, and whether every publisher behind them was established —
  and is deliberately silent where a collection has no single answer to
  give.
- **Client-facing error contract.** Every operation reports a stable,
  documented phase / status / error-code over D-Bus, with both an
  i18n message key and a fallback string, and a recovery path for
  clients that miss the completion signal.
- **Arch Linux packaging.** Release-shaped split packages
  `librescrs-agent` and `librescrs-pinentry-kde`, wiring the systemd
  user service, D-Bus service files, polkit actions and the PKCS#11
  module.

### Changed

- **Dual-interface readers: the contact slot is kept powered while a card
  sits in it.** A dual-interface card in the contact slot of a reader such as
  the OMNIKEY 5422 couples weakly to the reader's contactless coupler, so the
  contactless slot reported it as an endless insert/remove flap (reader LED
  never at rest, a full card probe per flap). The agent now keeps a bare
  power hold on that contact slot: a second PC/SC connection that carries no
  secret and sends no traffic. The logical session still closes after 45 s
  idle exactly as before, so nothing lives longer in memory than it did.
  Consequence: a PC/SC client that asks for EXCLUSIVE access to that contact
  slot (GnuPG's scdaemon does by default) is refused while the card is
  present; SHARED clients, including OpenSC tools, are unaffected. On such a
  slot, and for cards whose PIN state is not bound to a secure channel, the
  card's own verified state now survives the 45 s idle close, so within a
  PKCS#11 login a signature after a longer pause no longer re-prompts before
  the login's own idle limit; as inside the old 45 s window, that on-card
  state is visible to any other local shared PC/SC client while the card
  stays powered.
