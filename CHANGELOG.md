# LibreLinux Changelog

Notable user-visible changes per release. Format follows
[Keep a Changelog](https://keepachangelog.com/) loosely.

## [Unreleased] — 4.3.0

First public release of the Linux host for the LibreSCRS smart-card
ecosystem. It ships two components: the per-user **LibreSCRS Agent**
and its secure PIN/CAN entry prompter, plus a client PKCS#11 module.

### Added

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
  **polkit**, with a fail-closed fallback when polkit is unreachable.
  Secrets travel between components as **sealed in-memory buffers**
  and are never written to disk or logs. The daemon runs under a
  **strict systemd sandbox**, and outbound network access
  (timestamping, trusted lists, revocation) is filtered by an
  SSRF guard backed by a best-effort egress allowlist. The agent
  rate-limits signing and card-use requests to cap abuse under the
  default-allow posture.
- **Client-facing error contract.** Every operation reports a stable,
  documented phase / status / error-code over D-Bus, with both an
  i18n message key and a fallback string, and a recovery path for
  clients that miss the completion signal.
- **Arch Linux packaging.** Release-shaped split packages
  `librescrs-agent` and `librescrs-pinentry-kde`, wiring the systemd
  user service, D-Bus service files, polkit actions and the PKCS#11
  module.
