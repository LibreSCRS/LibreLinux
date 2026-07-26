<!--
SPDX-License-Identifier: LGPL-2.1-or-later
SPDX-FileCopyrightText: 2026 hirashix0
-->
# LibreLinux translation catalogs

## Prompter GUI catalog — `librescrs-pinentry-kde`

`librescrs-pinentry-kde.pot` is the extraction template; `sr/` (Serbian
Cyrillic, **primary**) and `sr@latin/` (Serbian Latin, secondary) hold the
translated `.po` pairs. These cover every user-visible string the KF6 pinentry
prompter renders itself: window titles, field labels, the card-identity and
application-request chrome, and the inline PIN-confirmation mismatch error.

Regenerate the template after touching any `i18n*()` call:

```sh
sh Messages.sh          # from the LibreLinux repo root; rewrites the .pot
msgmerge --update prompter/po/sr/librescrs-pinentry-kde.po \
    prompter/po/librescrs-pinentry-kde.pot
msgmerge --update prompter/po/sr@latin/librescrs-pinentry-kde.po \
    prompter/po/librescrs-pinentry-kde.pot
```

`ki18n_install(po)` (in `prompter/CMakeLists.txt`) compiles each `.po` to a
`.mo` and installs it under `<localedir>/<lang>/LC_MESSAGES/`. The prompter
binds these via `TRANSLATION_DOMAIN="librescrs-pinentry-kde"` and
`KLocalizedString::setApplicationDomain()`.

## Wire message keys localized by the DESKTOP CLIENT (not here)

The agent and its prompter are secure-input infrastructure; the strings below
travel over D-Bus as stable **keys plus an English fallback** and are localized
by the client application that talks to the agent (e.g. the KDE/Qt desktop
host), never by the prompter. They therefore have no `.po` entry in this
catalog and are listed here only so the client-side catalog stays in sync.

- **Operation `Finished` message keys** (`msgKey` + `msgFallback` args of the
  `org.librescrs.Agent.Operation1.Finished` signal): `op.ok`, `op.cancelled`,
  `op.open_failed`, `op.internal`, … — the client renders `msgKey`, falling
  back to `msgFallback` when it has no translation.

- **Credential outcome tokens** (the `outcome` value in the
  `org.librescrs.Agent.Operation.Credentials1` typed result):
  `unspecified`, `ok`, `userCancelled`, `missingFields`, `invalidPin`,
  `blocked`, `pluginError`, `unsupported`, `keyActivationFailed`, `cardRemoved`.
  The client maps each to its own copy — e.g. `keyActivationFailed` to a
  client string such as `credentials.key_activation_failed` ("The card's
  signing key could not be activated.").

- **Per-credential guidance keys** carried on each credential record
  (`blocked_guidance_key` / `blocked_guidance_fallback` and
  `key_activation_guidance_key` / `key_activation_guidance_fallback`). These
  originate in the middleware card-quirk tables and are forwarded verbatim;
  observed values include `librescrs.pin.blocked.issuer` and
  `librescrs.pin.keyActivation.issuer`. The client localizes the key and shows
  the fallback when it has no translation.
