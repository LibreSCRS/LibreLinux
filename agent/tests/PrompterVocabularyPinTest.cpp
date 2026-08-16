// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Absolute-spelling pin for the RequestSecret option/status vocabulary this
// boundary grew for the alternative-credential-kind switch.
//
// Every producer and consumer in this repository spells these tokens through
// the PrompterWire constants, which makes the two local binaries consistent BY
// CONSTRUCTION — but consistent with each other is not the same as consistent
// with the wire. Nothing else in the tree checks the LITERAL strings, so a
// rename of the constants' VALUES would keep every other test, and the
// spelling grep gate, perfectly green while silently breaking the macOS
// prompter's Swift mirror of the very same option key and status token (which
// is a separate source tree with its own copy of the spellings, and cannot be
// tied to these constants by the compiler).
//
// Hence this file, and this file alone, spells them absolutely: it is the
// single deliberate exception the spelling gate excludes by name. Changing a
// value here is therefore an explicit, reviewable act that says "the wire
// changed, go update the other platform" — exactly the discipline
// RequestSecretsXmlCodegenTest.cpp's ChangePinWireVocabularyIsPinned applies to
// the multi-secret vocabulary.

#include "PrompterWire.h"

#include <gtest/gtest.h>

TEST(RequestSecretWire, RequestSecretVocabularyIsPinned)
{
    namespace wire = LibreLinux::PrompterWire;
    EXPECT_STREQ(wire::kStatusOkMrz, "ok_mrz");
    EXPECT_STREQ(wire::kOptAltKinds, "alt_kinds");
}
