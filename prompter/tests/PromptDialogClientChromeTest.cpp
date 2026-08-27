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
#include <QToolButton>

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

TEST(PromptDialogClientChrome, RequesterRendersInGroupWhileKnownArtifactIsTrustedChrome)
{
    int argc = 1;
    const char* argv[] = {"chrome-test"};
    QApplication app(argc, const_cast<char**>(argv));

    PromptDialog dlg(PromptDialog::Kind::Can, optsWith("firefox", "identity"), nullptr);

    // The client-supplied requester lives INSIDE the framed group, never
    // loose in the dialog body next to the trusted description.
    auto* group = dlg.findChild<QGroupBox*>(QStringLiteral("clientSuppliedGroup"));
    ASSERT_NE(group, nullptr) << "a requester must be framed in the client-supplied group box";

    auto* requester = group->findChild<QLabel*>(QStringLiteral("requesterLabel"));
    ASSERT_NE(requester, nullptr);
    EXPECT_TRUE(requester->text().contains(QStringLiteral("firefox")));

    // "identity" is a TRUSTED closed-vocabulary token: it renders as prompter
    // chrome (a localized operation sentence) OUTSIDE the group, never as the
    // raw identifier inside it.
    EXPECT_EQ(group->findChild<QLabel*>(QStringLiteral("artifactLabel")), nullptr)
        << "a vocabulary token must not render as a raw client-supplied artifact";
    auto* operation = dlg.findChild<QLabel*>(QStringLiteral("operationLabel"));
    ASSERT_NE(operation, nullptr) << "a vocabulary token must render as the trusted operation line";
    EXPECT_TRUE(operation->text().contains(QStringLiteral("Reading identity data")))
        << "the token must render as the localized human sentence, not the raw identifier";
}

TEST(PromptDialogClientChrome, KnownArtifactAloneShowsTrustedOperationWithoutGroup)
{
    int argc = 1;
    const char* argv[] = {"chrome-test"};
    QApplication app(argc, const_cast<char**>(argv));

    // The agent's own consent prompts carry a vocabulary token and NO
    // requester: the dialog shows the trusted operation line and no
    // "requested by an application" frame at all.
    PromptDialog dlg(PromptDialog::Kind::Can, optsWith(QString{}, QStringLiteral("identity")), nullptr);

    EXPECT_EQ(dlg.findChild<QGroupBox*>(QStringLiteral("clientSuppliedGroup")), nullptr)
        << "nothing client-supplied is present, so no frame may render";
    auto* operation = dlg.findChild<QLabel*>(QStringLiteral("operationLabel"));
    ASSERT_NE(operation, nullptr);
    EXPECT_EQ(operation->textFormat(), Qt::PlainText);
}

TEST(PromptDialogClientChrome, UnknownArtifactStaysFramedAndInert)
{
    int argc = 1;
    const char* argv[] = {"chrome-test"};
    QApplication app(argc, const_cast<char**>(argv));

    // A token OUTSIDE the trusted vocabulary is client-supplied by
    // definition: framed in the group, rendered literally (inert), and it
    // must NOT mint a trusted operation line.
    const QString hostile = QStringLiteral("<b>System Verification</b>");
    PromptDialog dlg(PromptDialog::Kind::Can, optsWith(QString{}, hostile), nullptr);

    EXPECT_EQ(dlg.findChild<QLabel*>(QStringLiteral("operationLabel")), nullptr)
        << "an unknown token must never borrow the trusted operation chrome";
    auto* group = dlg.findChild<QGroupBox*>(QStringLiteral("clientSuppliedGroup"));
    ASSERT_NE(group, nullptr);
    auto* artifact = group->findChild<QLabel*>(QStringLiteral("artifactLabel"));
    ASSERT_NE(artifact, nullptr);
    EXPECT_EQ(artifact->textFormat(), Qt::PlainText);
    EXPECT_TRUE(artifact->text().contains(hostile)) << "the literal markup must be preserved, not stripped/interpreted";
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

// --- the reader row --------------------------------------------------------
//
// Two credential windows can stand at once, so a dialog that does not name its
// reader leaves the holder guessing which secret authorises which card. On the
// dual-interface reader on the owner's desk, whose two PC/SC names SHARE a
// serial, the qualifier is the only thing separating two otherwise identical
// dialogs.

namespace {

PromptDialog::Options optsWithReader(const QString& model, const QString& iface, const QString& full)
{
    PromptDialog::Options o;
    o.readerModel = model;
    o.readerInterface = iface;
    o.readerFull = full;
    return o;
}

constexpr const char* kOmnikeyContactless =
    "HID Global OMNIKEY 5422 Smartcard Reader [OMNIKEY 5422CL Smartcard Reader] (IM0O2C00NF10456904) 00 00";

} // namespace

TEST(PromptDialogReaderChrome, TheModelAndItsInterfaceQualifierAreBothRendered)
{
    int argc = 1;
    const char* argv[] = {"reader-chrome-test"};
    QApplication app(argc, const_cast<char**>(argv));

    PromptDialog dlg(PromptDialog::Kind::Can,
                     optsWithReader(QStringLiteral("OMNIKEY 5422"), QStringLiteral("contactless"),
                                    QString::fromLatin1(kOmnikeyContactless)));

    auto* label = dlg.findChild<QLabel*>(QStringLiteral("readerLabel"));
    ASSERT_NE(label, nullptr) << "the dialog does not name its reader";
    EXPECT_TRUE(label->text().contains(QStringLiteral("OMNIKEY 5422")));
    EXPECT_TRUE(label->text().contains(QStringLiteral("contactless")))
        << "without the qualifier the two slots of one reader are indistinguishable: " << label->text().toStdString();
}

TEST(PromptDialogReaderChrome, TheTwoSlotsOfOneReaderRenderDifferently)
{
    int argc = 1;
    const char* argv[] = {"reader-chrome-test"};
    QApplication app(argc, const_cast<char**>(argv));

    // The failure this exists to prevent, stated as the test: same model, same
    // serial, two windows the holder must be able to tell apart.
    PromptDialog contact(PromptDialog::Kind::Pin,
                         optsWithReader(QStringLiteral("OMNIKEY 5422"), QStringLiteral("contact"),
                                        QStringLiteral("... [OMNIKEY 5422 Smartcard Reader] ... 01 00")));
    PromptDialog contactless(PromptDialog::Kind::Can,
                             optsWithReader(QStringLiteral("OMNIKEY 5422"), QStringLiteral("contactless"),
                                            QString::fromLatin1(kOmnikeyContactless)));

    const QString a = contact.findChild<QLabel*>(QStringLiteral("readerLabel"))->text();
    const QString b = contactless.findChild<QLabel*>(QStringLiteral("readerLabel"))->text();
    EXPECT_NE(a, b) << "two slots of the same reader produced identical dialogs: " << a.toStdString();
}

TEST(PromptDialogReaderChrome, TheRawSystemNameIsAvailableButNotInTheChrome)
{
    int argc = 1;
    const char* argv[] = {"reader-chrome-test"};
    QApplication app(argc, const_cast<char**>(argv));

    // Long enough to push the entry field off a small screen, so it is offered
    // rather than shown.
    PromptDialog dlg(PromptDialog::Kind::Can,
                     optsWithReader(QStringLiteral("OMNIKEY 5422"), QStringLiteral("contactless"),
                                    QString::fromLatin1(kOmnikeyContactless)));

    auto* label = dlg.findChild<QLabel*>(QStringLiteral("readerLabel"));
    ASSERT_NE(label, nullptr);
    EXPECT_FALSE(label->text().contains(QString::fromLatin1(kOmnikeyContactless)));

    auto* full = dlg.findChild<QLabel*>(QStringLiteral("readerFullDetails"));
    ASSERT_NE(full, nullptr) << "the literal reader name is not reachable at all";
    EXPECT_EQ(full->text(), QString::fromLatin1(kOmnikeyContactless));

    // The reveal affordance is a disclosure control: a checkable tool button
    // carrying a style-drawn arrow that points at the text it reveals.
    auto* details = dlg.findChild<QToolButton*>(QStringLiteral("readerDetailsButton"));
    ASSERT_NE(details, nullptr) << "no disclosure control for the literal reader name";
    EXPECT_TRUE(details->isCheckable());
    EXPECT_EQ(details->arrowType(), Qt::RightArrow);

    // isVisibleTo, never isVisible: this dialog is never shown, and isVisible()
    // is false for every child of an unshown window, so it would pass on a
    // permanently visible label just as happily.
    EXPECT_FALSE(full->isVisibleTo(&dlg));

    details->click();
    EXPECT_TRUE(full->isVisibleTo(&dlg));
    EXPECT_EQ(details->arrowType(), Qt::DownArrow);

    details->click();
    EXPECT_FALSE(full->isVisibleTo(&dlg));
    EXPECT_EQ(details->arrowType(), Qt::RightArrow);
}

TEST(PromptDialogReaderChrome, AnUnknownQualifierRendersTheModelAlone)
{
    int argc = 1;
    const char* argv[] = {"reader-chrome-test"};
    QApplication app(argc, const_cast<char**>(argv));

    // A single-interface reader has nothing to disambiguate, so it gets no
    // qualifier rather than the word "unknown".
    PromptDialog dlg(PromptDialog::Kind::Pin,
                     optsWithReader(QStringLiteral("Gemalto PC Twin Reader"), QStringLiteral("unknown"),
                                    QStringLiteral("Gemalto PC Twin Reader (69988A87) 02 00")));

    auto* label = dlg.findChild<QLabel*>(QStringLiteral("readerLabel"));
    ASSERT_NE(label, nullptr);
    EXPECT_TRUE(label->text().contains(QStringLiteral("Gemalto PC Twin Reader")));
    EXPECT_FALSE(label->text().contains(QStringLiteral("unknown")));
}

TEST(PromptDialogReaderChrome, APromptWithNoResolvedReaderRendersNoReaderRow)
{
    int argc = 1;
    const char* argv[] = {"reader-chrome-test"};
    QApplication app(argc, const_cast<char**>(argv));

    PromptDialog dlg(PromptDialog::Kind::Pin, PromptDialog::Options{});
    EXPECT_EQ(dlg.findChild<QLabel*>(QStringLiteral("readerLabel")), nullptr);
    EXPECT_EQ(dlg.findChild<QLabel*>(QStringLiteral("readerFullDetails")), nullptr);
}

TEST(PromptDialogReaderChrome, TheReaderRowIsTrustedChromeNotClientSuppliedFraming)
{
    int argc = 1;
    const char* argv[] = {"reader-chrome-test"};
    QApplication app(argc, const_cast<char**>(argv));

    // The agent owns the roster and is the only layer that can tell a
    // dual-interface unit's slots apart, so this belongs with the trusted
    // labels -- never inside the box that frames client-supplied text.
    PromptDialog dlg(PromptDialog::Kind::Can,
                     optsWithReader(QStringLiteral("OMNIKEY 5422"), QStringLiteral("contactless"),
                                    QString::fromLatin1(kOmnikeyContactless)));

    auto* group = dlg.findChild<QGroupBox*>(QStringLiteral("clientSuppliedGroup"));
    if (group != nullptr) {
        EXPECT_EQ(group->findChild<QLabel*>(QStringLiteral("readerLabel")), nullptr);
    }
    auto* label = dlg.findChild<QLabel*>(QStringLiteral("readerLabel"));
    ASSERT_NE(label, nullptr);
    EXPECT_EQ(label->textFormat(), Qt::PlainText) << "defence in depth: the reader row renders inert";
}
