// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Runtime proof that the Serbian (Cyrillic-primary) prompter catalog actually
// RESOLVES through ki18n — not merely that the .po file exists on disk. CMake
// compiles the sr catalog to a .mo into a private XDG data tree laid out like a
// system install (<root>/locale/sr/LC_MESSAGES/librescrs-pinentry-kde.mo) and
// the test's XDG_DATA_DIRS entry exposes it, so KLocalizedString resolves it
// through the standard QStandardPaths::GenericDataLocation lookup (stable across
// ki18n versions, no system-wide install, no version-fragile addDomainLocaleDir).
//
// CRITICAL TRAP (why this test exists): under the C / C.UTF-8 locale the C
// library's gettext — which ki18n uses to read .mo catalogs — returns the msgid
// UNTRANSLATED, so a naive catalog test would PASS as English and hide a broken
// or empty Serbian catalog. This test therefore (a) runs under a real UTF-8
// locale (LANG=en_US.UTF-8, set by the CMake test properties; CI must
// locale-gen it) and (b) asserts the CYRILLIC (non-English) result, so a
// missing/empty catalog OR a C-locale run FAILS. The wrong-domain negative
// control proves the resolution is genuinely keyed on the prompter's domain
// rather than a global always-on translation.

#include <KLocalizedString>

#include <QCoreApplication>
#include <QString>

#include <gtest/gtest.h>

namespace {
constexpr const char* kDomain = "librescrs-pinentry-kde";
}

TEST(PromptCatalogResolution, SerbianCyrillicResolvesForKnownStrings)
{
    KLocalizedString::setLanguages({QStringLiteral("sr")});

    // "Enter PIN" (msgctxt "@title:window PIN entry dialog") -> "Унесите PIN".
    const QString enterPin = i18ndc(kDomain, "@title:window PIN entry dialog", "Enter PIN");
    EXPECT_EQ(enterPin, QString::fromUtf8("Унесите PIN"))
        << "the sr catalog did not resolve — is the compiled .mo on XDG_DATA_DIRS and LANG a real UTF-8 locale?";

    // A second, distinct entry proves this is genuine catalog resolution, not a
    // single hard-coded hit.
    const QString changePin = i18ndc(kDomain, "@title:window PIN change dialog", "Change PIN");
    EXPECT_EQ(changePin, QString::fromUtf8("Промени PIN")) << "a second sr msgstr must resolve independently";

    KLocalizedString::clearLanguages();
}

TEST(PromptCatalogResolution, WrongDomainDoesNotResolveToSerbian)
{
    KLocalizedString::setLanguages({QStringLiteral("sr")});

    // The SAME msgid+context under a domain with no catalog must fall back to
    // the English source string. If this returned Cyrillic the positive test
    // would be meaningless (a global always-on translation); asserting the
    // English fallback here proves the lookup is domain-keyed — and confirms the
    // test genuinely FAILS when pointed at a missing/wrong catalog.
    const QString viaWrongDomain = i18ndc("nonexistent-prompter-domain", "@title:window PIN entry dialog", "Enter PIN");
    EXPECT_EQ(viaWrongDomain, QStringLiteral("Enter PIN"))
        << "an unknown domain must not resolve to Serbian (domain-keyed lookup)";

    KLocalizedString::clearLanguages();
}

int main(int argc, char** argv)
{
    // KLocalizedString resolves catalog paths against a running QCoreApplication;
    // without one the sr catalog is never consulted.
    QCoreApplication app(argc, argv);
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}

TEST(PromptCatalogResolution, TheReaderInterfaceQualifierIsSaidInTheHoldersLanguage)
{
    // The agent sends a closed token, never prose: it has no localisation, so
    // any English it composed would arrive already written and no prompter
    // could fix it. This proves the prompter -- not the agent -- owns the words.
    KLocalizedString::setLanguages({QStringLiteral("sr")});

    const QString contactless =
        i18ndc(kDomain, "@info which physical slot of a reader a prompt belongs to", "contactless");
    EXPECT_EQ(contactless, QString::fromUtf8("бесконтактни"))
        << "the interface qualifier resolved to the English fallback under a Serbian locale";

    // Substituted, not raw: ki18n marks an unsupplied placeholder, so asserting
    // the bare pattern would fail on the marker rather than on the translation.
    const QString reader = i18ndc(kDomain, "@info which reader is asking for the credential", "Reader: %1",
                                  QStringLiteral("OMNIKEY 5422"));
    EXPECT_EQ(reader, QString::fromUtf8("Читач: OMNIKEY 5422"));

    const QString details = i18ndc(kDomain, "@action:button reveal the reader's full system name", "Reader details");
    EXPECT_EQ(details, QString::fromUtf8("Подаци о читачу"));
}
