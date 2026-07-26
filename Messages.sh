#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later
# SPDX-FileCopyrightText: 2026 hirashix0
#
# KDE l10n extraction for LibreLinux. ONE gettext domain:
#
#   librescrs-pinentry-kde
#     Every C++ i18n*/ki18n* string in the KF6 pinentry prompter (the sole
#     Qt/KF6 component; the agent and PKCS#11 module are Qt-free and carry no
#     user-visible catalog strings). Each prompter target pins
#     TRANSLATION_DOMAIN="librescrs-pinentry-kde".
#
# Tests are not user-visible and are excluded.
#
# Under KDE scripty, $XGETTEXT and $podir are provided by the l10n tooling.
# For a standalone run, sensible defaults are used so the .pot regenerates
# in place: sh Messages.sh
podir=${podir:-prompter/po}
XGETTEXT=${XGETTEXT:-"xgettext --from-code=UTF-8 --c++ --kde \
    -ci18n \
    -ki18n:1 -ki18nc:1c,2 -ki18np:1,2 -ki18ncp:1c,2,3 \
    -ki18nd:2 -ki18ndc:2c,3 -ki18ndp:2,3 -ki18ndcp:2c,3,4 \
    -kki18n:1 -kki18nc:1c,2 -kki18np:1,2 -kki18ncp:1c,2,3 \
    -kxi18n:1 -kxi18nc:1c,2 -kxi18np:1,2 -kxi18ncp:1c,2,3 \
    -kI18N_NOOP:1 -kI18NC_NOOP:1c,2 \
    --package-name=librescrs-pinentry-kde \
    --msgid-bugs-address=https://librescrs.github.io/"}

$XGETTEXT $(find prompter/src -name '*.cpp' -o -name '*.h' | sort) \
    -o "$podir/librescrs-pinentry-kde.pot"
