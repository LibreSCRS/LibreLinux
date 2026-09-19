# Security Policy

## Reporting a vulnerability

Please report security vulnerabilities privately using GitHub Security
Advisories:

  https://github.com/LibreSCRS/LibreLinux/security/advisories/new

For non-GitHub correspondence, contact the project release signing
identity:

  librescrs@proton.me

We respond to security reports within five business days, follow up
with an initial assessment within ten days, and agree a disclosure
window with the reporter before anything is published.

Advisories we publish appear under this repository's Security tab;
consumers pinned to 4.x should watch it.

## Scope

In scope: anything reachable from a smart card, a network peer or a
parsed document before it has been authenticated — card and APDU
input, network input, document parsing; the IPC boundary between this
component and its callers, and the authorization checks guarding it;
handling of PINs, keys and other secrets; and the supply chain of the
artifact this repository ships.

Out of scope: this project's own tests and fuzz harnesses, denial of
service an attacker can already achieve as the user of their own
agent, and findings in vendored third-party code that belong to the
upstream project instead.

## Release verification

LibreSCRS releases ≥ 4.0 are cryptographically signed.

- **Git tags** are GPG-signed with the LibreSCRS Release Signing key
  (fingerprint `6B05889AC9A6A7188DF639B06F27A989C2031D16`). The CI
  release pipeline rejects any unsigned or wrong-fingerprint tag.
  See `KEYS` in this repository for the public key blob and the
  `gpg --verify` / `git tag -v` workflow.
- **Release artifacts.** LibreLinux distributes no prebuilt binaries of
  its own: the daemon, the prompter and the PKCS#11 module are compiled
  from the tag's sources by distribution packaging
  (`packaging/{arch,debian,rpm}`), which fetches the source tarball
  this repository's release workflow uploads. The components that
  distribute binaries sign them via Sigstore cosign keyless using
  GitHub Actions OIDC; see <https://librescrs.github.io/security/> for
  that end-to-end verification guide, including expected OIDC issuer
  and identity values.

## Supported versions

| Version | Supported |
|---------|-----------|
| 5.x     | ✅ Active  |
| 4.x     | ✅ Active  |
| 3.x     | ❌ EOL     |
