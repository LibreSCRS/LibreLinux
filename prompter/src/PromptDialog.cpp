// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "PromptDialog.h"

#include "CanInputWidget.h"
#include "ChangePinInputWidget.h"
#include "InputWidgetBase.h"
#include "MrzInputWidget.h"
#include "PinInputWidget.h"

#include <KLocalizedString>

#include <QDialogButtonBox>
#include <QFontMetrics>
#include <QGroupBox>
#include <QLabel>
#include <QPushButton>
#include <QVBoxLayout>

#include <unistd.h> // close

#include <utility>

namespace LibreLinux::Prompter {

namespace {

InputWidgetBase* widgetFor(PromptDialog::Kind kind, const PromptDialog::Options& opts,
                           const PromptDialog::ChangePinWidgetFactory& factory)
{
    switch (kind) {
    case PromptDialog::Kind::Pin:
        return new PinInputWidget(opts.minLength, opts.maxLength);
    case PromptDialog::Kind::Can:
        return new CanInputWidget;
    case PromptDialog::Kind::Mrz:
        return new MrzInputWidget;
    case PromptDialog::Kind::ChangePin:
        if (factory) {
            return factory(opts);
        }
        return new ChangePinInputWidget(opts.primaryMinLength, opts.primaryMaxLength, opts.newMinLength,
                                        opts.newMaxLength, opts.pinLabel);
    }
    // Defensive default — unreachable in well-typed callers, but the
    // function must produce a non-null widget on every path.
    return new PinInputWidget(opts.minLength, opts.maxLength);
}

// Recognised @c last_error msgKey (mirrors
// LibreSCRS::Auth::ErrorKeys::preReadAuthFailed().key on the agent's LM
// dependency; duplicated here as a documented literal, the same
// cross-binary vocabulary convention PrompterWire.h's kKind*/kStatus*
// constants already use -- this file has no LM dependency to share the
// constant with). The only source of a `last_error` today is the eMRTD read
// flows' AuthFailed path (CredentialCache::markCredentialWrong).
constexpr const char* kErrorPreReadAuthFailed = "librescrs.error.preRead.authFailed";

// Localized inline text for the retry-context error line shown above the
// input widget on a re-prompt (opts.attempt > 0). An unrecognised or empty
// key still returns a generic retry line rather than leaking the raw wire
// key to the user.
QString retryErrorText(const QString& lastErrorKey)
{
    if (lastErrorKey == QString::fromLatin1(kErrorPreReadAuthFailed) || lastErrorKey.isEmpty()) {
        return i18nc("@info:status inline error shown above a re-prompt after the card rejected the "
                     "previously entered CAN/MRZ",
                     "The value you entered was not accepted. Please try again.");
    }
    return i18nc("@info:status generic inline error shown above a credential re-prompt",
                 "Your previous entry was not accepted. Please try again.");
}

QString defaultTitle(PromptDialog::Kind kind)
{
    switch (kind) {
    case PromptDialog::Kind::Pin:
        return i18nc("@title:window PIN entry dialog", "Enter PIN");
    case PromptDialog::Kind::Can:
        return i18nc("@title:window CAN entry dialog", "Enter Card Access Number");
    case PromptDialog::Kind::Mrz:
        return i18nc("@title:window MRZ entry dialog", "Enter Machine-Readable Zone");
    case PromptDialog::Kind::ChangePin:
        return i18nc("@title:window PIN change dialog", "Change PIN");
    }
    return i18nc("@title:window generic credential entry", "Enter Credentials");
}

// Render an untrusted, client-supplied value into a label that can NEVER be
// mistaken for trusted system chrome: forced plain-text (so an embedded "<b>"
// or other markup is shown literally, not interpreted as rich text), and a
// stable object name so tests can pin the trust separation.
QLabel* makeClientSuppliedLabel(const QString& text, const char* objectName, QWidget* parent)
{
    auto* label = new QLabel(text, parent);
    label->setObjectName(QString::fromLatin1(objectName));
    label->setWordWrap(true);
    // Hard guard against rich-text injection: a hostile requester/artifact
    // string must render as inert text, not interpreted HTML markup.
    label->setTextFormat(Qt::PlainText);
    return label;
}

} // namespace

PromptDialog::PromptDialog(Kind kind, const Options& opts, QWidget* parent, ChangePinWidgetFactory factory)
    : QDialog(parent), m_widget(widgetFor(kind, opts, factory)), m_buttons(new QDialogButtonBox(this))
{
    if (kind == Kind::ChangePin) {
        // The factory (test seam) returns a ChangePinInputWidget (or a
        // subclass); the production branch constructs one directly.
        m_changePinWidget = static_cast<ChangePinInputWidget*>(m_widget);
    }
    setWindowTitle(opts.title.isEmpty() ? defaultTitle(kind) : opts.title);
    // Modal application-wide: this is a credentials prompt; it MUST take
    // input focus and block the requesting flow until resolved.
    setModal(true);

    buildLayout(opts);
    wireValidity();
}

PromptDialog::~PromptDialog()
{
    // A captured-but-never-taken pair (service error path, early teardown)
    // must not leak the fds.
    if (m_captured.primaryFd >= 0) {
        ::close(m_captured.primaryFd);
    }
    if (m_captured.secondaryFd >= 0) {
        ::close(m_captured.secondaryFd);
    }
}

void PromptDialog::buildLayout(const Options& opts)
{
    auto* layout = new QVBoxLayout(this);

    // This zone is prompter chrome (fixed position, no client-supplied
    // framing), but the TEXT it carries is not: both signing flows (single
    // and batch) fill `description` from a client-supplied document
    // displayName (SignFlow) or a summary built from those same names
    // (BatchSignFlow::summarizeBatch) -- never agent-authored wording. Forced
    // inert plain text, same guard as makeClientSuppliedLabel below, so a
    // hostile displayName like "<b>Verified by Ministry of Finance</b>"
    // cannot render as interpreted rich text and forge system chrome.
    if (!opts.description.isEmpty()) {
        auto* desc = new QLabel(opts.description, this);
        desc->setObjectName(QStringLiteral("promptDescription"));
        desc->setWordWrap(true);
        desc->setTextFormat(Qt::PlainText);
        layout->addWidget(desc);
    }

    // Untrusted area, but rendered in the SAME zone as the description above
    // (plain, unframed) rather than inside the "Requested by an application"
    // group below: the enumerated per-document file list of a batch signing
    // request (PromptOptions::artifacts on the wire). That group also frames
    // `artifact`, the TRUSTED closed-vocabulary category token
    // ("signature-batch" for a batch) — folding a client-controlled file
    // list into the same visually-labelled box would let it borrow the
    // box's implied trust. Forced inert plain text (makeClientSuppliedLabel)
    // since every name is client-supplied, exactly like the requester/
    // artifact labels further below. Omitted entirely when the list is empty
    // (every non-batch prompt).
    if (!opts.artifacts.isEmpty()) {
        auto* files = makeClientSuppliedLabel(i18nc("@info list of documents included in a batch signing request",
                                                    "Documents: %1", opts.artifacts.join(QStringLiteral(", "))),
                                              "artifactsLabel", this);
        layout->addWidget(files);
    }

    // Trusted area: the card the operation applies to (agent-derived
    // metadata, non-secret). Plain text as defence-in-depth.
    if (!opts.cardLabel.isEmpty()) {
        // %1 is the human-readable card name (e.g. "identity card").
        auto* card = new QLabel(i18nc("@info card identity label", "Card: %1", opts.cardLabel), this);
        card->setObjectName(QStringLiteral("cardLabel"));
        card->setWordWrap(true);
        card->setTextFormat(Qt::PlainText);
        layout->addWidget(card);
    }

    // Untrusted area: requester + artifact are supplied by the requesting
    // application. They are framed inside a clearly-titled group box so the
    // user can never confuse client-supplied text for the prompter's own
    // (trusted) wording — the title is fixed prompter chrome, the values
    // inside are inert plain text. The whole box is omitted when neither
    // field is present.
    if (!opts.requester.isEmpty() || !opts.artifact.isEmpty()) {
        auto* group = new QGroupBox(
            i18nc("@title:group framed area for application-supplied request details", "Requested by an application"),
            this);
        group->setObjectName(QStringLiteral("clientSuppliedGroup"));
        auto* groupLayout = new QVBoxLayout(group);
        if (!opts.requester.isEmpty()) {
            // %1 is the requesting application's identity (e.g. "firefox").
            groupLayout->addWidget(makeClientSuppliedLabel(
                i18nc("@info requester identity label", "Requested by: %1", opts.requester), "requesterLabel", group));
        }
        if (!opts.artifact.isEmpty()) {
            groupLayout->addWidget(makeClientSuppliedLabel(i18nc("@info artifact label", "Artifact: %1", opts.artifact),
                                                           "artifactLabel", group));
        }
        layout->addWidget(group);
    }

    // Retry-context inline error: shown ABOVE the input widget, immediately
    // preceding it, ONLY on a genuine re-prompt (opts.attempt > 0 -- the
    // wire's `attempt` option, set by CredentialCache::applyRetryContext).
    // Absent on the first-ever prompt for a card. No attempts counter is
    // rendered (parity with the GUI's inline-error-without-a-counter bar);
    // the number only selects presence, never appears in the text itself.
    if (opts.attempt > 0) {
        auto* retryError = new QLabel(retryErrorText(opts.lastError), this);
        retryError->setObjectName(QStringLiteral("retryErrorLabel"));
        retryError->setWordWrap(true);
        retryError->setTextFormat(Qt::PlainText);
        layout->addWidget(retryError);
    }

    m_widget->setParent(this);
    layout->addWidget(m_widget);

    m_buttons->setStandardButtons(QDialogButtonBox::Ok | QDialogButtonBox::Cancel);
    layout->addWidget(m_buttons);
    connect(m_buttons, &QDialogButtonBox::accepted, this, &QDialog::accept);
    connect(m_buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);
}

void PromptDialog::wireValidity()
{
    auto* okButton = m_buttons->button(QDialogButtonBox::Ok);
    if (!okButton)
        return;
    okButton->setEnabled(m_widget->isValid());
    // Receiver context is the BUTTON, not the dialog: during ~PromptDialog
    // the button box (an earlier child) is destroyed before the input widget,
    // whose destructor scrub emits textChanged -> validityChanged. With the
    // dialog as context that connection would still be live and the lambda
    // would touch the freed button; scoping it to the button severs it first.
    connect(m_widget, &InputWidgetBase::validityChanged, okButton,
            [this, okButton]() { okButton->setEnabled(m_widget->isValid()); });
}

int PromptDialog::captureSecretFd()
{
    // The widget is still alive (this dialog still holds it); the dialog
    // is closed but not yet destroyed at the caller's scope, so the
    // QLineEdit buffer can be safely read.
    return m_widget->captureSecretFd();
}

void PromptDialog::accept()
{
    // Idempotent capture: a re-entrant accept (e.g. a second queued
    // QDialogButtonBox::accepted delivered before exec() unwinds) must NOT
    // re-read the by-then-scrubbed edits and overwrite an already-captured
    // secret-bearing fd pair — that would orphan the first pair, leaking a
    // descriptor that holds the real PIN. Once captured, fall straight through
    // to QDialog::accept(). (A prior confirm-mismatch left m_captured at its
    // {-1,-1} default, so the mismatch re-check below still runs on retry.)
    const bool alreadyCaptured = m_captured.primaryFd >= 0 || m_captured.secondaryFd >= 0;
    if (m_changePinWidget != nullptr && !alreadyCaptured) {
        if (!m_changePinWidget->confirmMatchesNew()) {
            // Mismatch blocks acceptance: inline error, dialog stays open.
            m_changePinWidget->showConfirmMismatch();
            return;
        }
        // Read-then-hide: capture BOTH secrets from the still-visible,
        // still-enabled widgets NOW — QDialog::accept() below hides the
        // dialog, and no secret read may happen after any hide/disable.
        m_captured.primaryFd = m_changePinWidget->captureSecretFd();
        m_captured.secondaryFd = m_changePinWidget->captureNewSecretFd();
    }
    QDialog::accept();
}

PromptDialog::SecretFdPair PromptDialog::takeSecretFdPair()
{
    // Pure hand-over of what the accept path captured (or {-1, -1} after a
    // reject / a second take): ownership of the fds transfers to the caller.
    return std::exchange(m_captured, SecretFdPair{});
}

} // namespace LibreLinux::Prompter
