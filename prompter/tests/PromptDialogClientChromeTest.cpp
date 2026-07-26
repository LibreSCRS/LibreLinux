// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Pins the client-supplied chrome separation: requester + artifact are
// rendered inside a distinct, framed group box — visually separated from the
// prompter's own (trusted) wording — and as INERT plain text so a hostile
// requester/artifact string cannot inject markup that forges system chrome.
//
// Runs under QT_QPA_PLATFORM=offscreen so no display server is required.

#include "PromptDialog.h"

#include <QApplication>
#include <QGroupBox>
#include <QLabel>

#include <gtest/gtest.h>

using LibreLinux::Prompter::PromptDialog;

namespace {

PromptDialog::Options optsWith(const QString& requester, const QString& artifact)
{
    PromptDialog::Options o;
    o.requester = requester;
    o.artifact = artifact;
    return o;
}

} // namespace

TEST(PromptDialogClientChrome, RequesterAndArtifactRenderInDistinctGroup)
{
    int argc = 1;
    const char* argv[] = {"chrome-test"};
    QApplication app(argc, const_cast<char**>(argv));

    PromptDialog dlg(PromptDialog::Kind::Can, optsWith("firefox", "identity"), nullptr);

    // The client-supplied values live INSIDE the framed group, never loose in
    // the dialog body next to the trusted description.
    auto* group = dlg.findChild<QGroupBox*>(QStringLiteral("clientSuppliedGroup"));
    ASSERT_NE(group, nullptr) << "requester/artifact must be framed in the client-supplied group box";

    auto* requester = group->findChild<QLabel*>(QStringLiteral("requesterLabel"));
    auto* artifact = group->findChild<QLabel*>(QStringLiteral("artifactLabel"));
    ASSERT_NE(requester, nullptr);
    ASSERT_NE(artifact, nullptr);
    EXPECT_TRUE(requester->text().contains(QStringLiteral("firefox")));
    EXPECT_TRUE(artifact->text().contains(QStringLiteral("identity")));
}

TEST(PromptDialogClientChrome, ClientSuppliedLabelsAreInertPlainText)
{
    int argc = 1;
    const char* argv[] = {"chrome-test"};
    QApplication app(argc, const_cast<char**>(argv));

    // A hostile requester name containing markup must NOT be interpreted as
    // rich text (which could mimic the prompter's own chrome). The label must
    // be in Qt::PlainText so the markup is shown literally.
    PromptDialog dlg(PromptDialog::Kind::Can, optsWith(QStringLiteral("<b>System</b>"), QStringLiteral("identity")),
                     nullptr);

    auto* requester = dlg.findChild<QLabel*>(QStringLiteral("requesterLabel"));
    ASSERT_NE(requester, nullptr);
    EXPECT_EQ(requester->textFormat(), Qt::PlainText)
        << "client-supplied text must render as inert plain text (anti-spoofing)";
    EXPECT_TRUE(requester->text().contains(QStringLiteral("<b>System</b>")))
        << "the literal markup must be preserved, not stripped/interpreted";
}

TEST(PromptDialogClientChrome, NoGroupWhenNoClientMetadata)
{
    int argc = 1;
    const char* argv[] = {"chrome-test"};
    QApplication app(argc, const_cast<char**>(argv));

    // With neither requester nor artifact, the client-chrome frame is omitted
    // entirely — a system-initiated prompt shows no "requested by" area.
    PromptDialog dlg(PromptDialog::Kind::Pin, PromptDialog::Options{}, nullptr);
    EXPECT_EQ(dlg.findChild<QGroupBox*>(QStringLiteral("clientSuppliedGroup")), nullptr);
}

// Pins the batch-signing consent-honesty rendering: the enumerated
// per-document file list (PromptOptions::artifacts) must render OUTSIDE the
// trusted-looking "Requested by an application" group that frames `artifact`
// (the closed-vocabulary category token), as inert plain text, and must be
// omitted entirely for every non-batch prompt.
TEST(PromptDialogClientChrome, ArtifactsListRendersOutsideTheTrustedGroupAsInertPlainText)
{
    int argc = 1;
    const char* argv[] = {"chrome-test"};
    QApplication app(argc, const_cast<char**>(argv));

    PromptDialog::Options opts = optsWith("agent-klijent", "signature-batch");
    opts.artifacts = {QStringLiteral("a.pdf"), QStringLiteral("<b>b</b>.pdf"), QStringLiteral("c.pdf")};
    PromptDialog dlg(PromptDialog::Kind::Pin, opts, nullptr);

    auto* files = dlg.findChild<QLabel*>(QStringLiteral("artifactsLabel"));
    ASSERT_NE(files, nullptr) << "a populated artifacts list must render a label";
    EXPECT_TRUE(files->text().contains(QStringLiteral("a.pdf")));
    EXPECT_TRUE(files->text().contains(QStringLiteral("<b>b</b>.pdf")))
        << "the literal markup must be preserved, not stripped/interpreted";
    EXPECT_EQ(files->textFormat(), Qt::PlainText) << "the file list must render as inert plain text";

    // NEVER inside the trusted-looking "Requested by an application" group —
    // that box frames `artifact`, the closed-vocabulary agent-owned token;
    // folding the client-controlled file list into it would let the list
    // borrow the box's implied trust.
    auto* group = dlg.findChild<QGroupBox*>(QStringLiteral("clientSuppliedGroup"));
    ASSERT_NE(group, nullptr);
    EXPECT_EQ(group->findChild<QLabel*>(QStringLiteral("artifactsLabel")), nullptr)
        << "the artifacts list must never render inside the trusted-slot group box";
}

TEST(PromptDialogClientChrome, NoArtifactsLabelWhenListIsEmpty)
{
    int argc = 1;
    const char* argv[] = {"chrome-test"};
    QApplication app(argc, const_cast<char**>(argv));

    // Every non-batch prompt: artifacts stays empty, so no label renders.
    PromptDialog dlg(PromptDialog::Kind::Can, optsWith("firefox", "identity"), nullptr);
    EXPECT_EQ(dlg.findChild<QLabel*>(QStringLiteral("artifactsLabel")), nullptr);
}

// The "trusted area" comment in buildLayout() notwithstanding, `description`
// carries CLIENT-DERIVED text end to end (SignFlow's `displayName`,
// BatchSignFlow's `summarizeBatch(displayName...)`) -- never agent-authored
// markup. Qt::AutoText (the QLabel default) would let a hostile displayName
// like "<b>Verified by Ministry of Finance</b>" render as interpreted rich
// text INSIDE the zone the comment calls "system chrome", spoofing consent.
// It must render exactly like the already-inert artifactsLabel/requesterLabel.
TEST(PromptDialogClientChrome, DescriptionLabelIsInertPlainText)
{
    int argc = 1;
    const char* argv[] = {"chrome-test"};
    QApplication app(argc, const_cast<char**>(argv));

    PromptDialog::Options opts;
    opts.description = QStringLiteral("2 documents: a.pdf, c.pdf");
    PromptDialog dlg(PromptDialog::Kind::Pin, opts, nullptr);

    auto* desc = dlg.findChild<QLabel*>(QStringLiteral("promptDescription"));
    ASSERT_NE(desc, nullptr);
    EXPECT_EQ(desc->textFormat(), Qt::PlainText)
        << "the description must render as inert plain text (anti-spoofing) -- it "
           "carries client-derived document names, not trusted system wording";
}

TEST(PromptDialogClientChrome, DescriptionLabelWithMarkupRendersLiterally)
{
    int argc = 1;
    const char* argv[] = {"chrome-test"};
    QApplication app(argc, const_cast<char**>(argv));

    // A hostile client-supplied document displayName embedding markup must
    // NOT be interpreted as rich text -- it must show up as the literal
    // string, exactly like the artifacts list and requester/artifact labels.
    const QString hostile = QStringLiteral("<b>Verified by Ministry of Finance</b>");
    PromptDialog::Options opts;
    opts.description = hostile;
    PromptDialog dlg(PromptDialog::Kind::Pin, opts, nullptr);

    auto* desc = dlg.findChild<QLabel*>(QStringLiteral("promptDescription"));
    ASSERT_NE(desc, nullptr);
    EXPECT_EQ(desc->text(), hostile) << "the literal markup must be preserved, not stripped/interpreted";
    EXPECT_EQ(desc->textFormat(), Qt::PlainText)
        << "Qt must not be allowed to interpret the client-derived text as rich text";
}
