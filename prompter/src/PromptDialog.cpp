// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "PromptDialog.h"

#include "CanInputWidget.h"
#include "ChangePinInputWidget.h"
#include "InputWidgetBase.h"
#include "MrzInputWidget.h"
#include "PinInputWidget.h"

#include <KLocalizedString>

#include <QApplication>
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

// Prompter-authored line naming the credential the VISIBLE form takes. Rendered
// only on a prompt that offers the CAN/MRZ switch: there, and only there, the
// form under the caller's description can change while the dialog is open, so
// the dialog owes the user a line that follows the swap. Empty (and never
// rendered) for every other prompt — no existing dialog gains a label.
QString kindHintText(PromptDialog::Kind kind)
{
    switch (kind) {
    case PromptDialog::Kind::Can:
        return i18nc("@info line naming the credential the visible entry form takes",
                     "Enter the card access number (CAN) printed on the document.");
    case PromptDialog::Kind::Mrz:
        return i18nc("@info line naming the credential the visible entry form takes",
                     "Enter the document details exactly as printed in the machine-readable zone.");
    case PromptDialog::Kind::Pin:
    case PromptDialog::Kind::ChangePin:
        break;
    }
    return {};
}

// Label of the switch affordance: it always names the form the click would
// bring up, never the one already on screen.
QString switchButtonText(PromptDialog::Kind current)
{
    if (current == PromptDialog::Kind::Mrz) {
        return i18nc("@action:button switch the credential prompt back to the card access number form",
                     "Use card access number (CAN) instead");
    }
    return i18nc("@action:button switch the credential prompt to the passport machine-readable zone form",
                 "Use passport MRZ instead");
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

// Localized text for the TRUSTED, agent-owned artifact category tokens (the
// closed vocabulary the flows attach to their consent prompts). A recognised
// token renders as prompter chrome — a human sentence, not the raw
// identifier. Anything OUTSIDE the vocabulary is treated as client-supplied
// and stays framed + inert in the group box below. Empty QString = not a
// vocabulary token.
QString operationText(const QString& artifactToken)
{
    if (artifactToken == QLatin1String("identity"))
        return i18nc("@info consented operation", "Reading identity data");
    if (artifactToken == QLatin1String("photo"))
        return i18nc("@info consented operation", "Reading the photograph");
    if (artifactToken == QLatin1String("certificates"))
        return i18nc("@info consented operation", "Reading certificates");
    if (artifactToken == QLatin1String("token"))
        return i18nc("@info consented operation", "Reading token information");
    if (artifactToken == QLatin1String("credentials"))
        return i18nc("@info consented operation", "Reading PIN status");
    if (artifactToken == QLatin1String("signature"))
        return i18nc("@info consented operation", "Signing a document");
    if (artifactToken == QLatin1String("signature-batch"))
        return i18nc("@info consented operation", "Signing multiple documents");
    if (artifactToken == QLatin1String("pkcs11"))
        return i18nc("@info consented operation", "Cryptographic token operation");
    return {};
}

} // namespace

PromptDialog::PromptDialog(Kind kind, const Options& opts, QWidget* parent, ChangePinWidgetFactory factory)
    : QDialog(parent), m_kind(kind), m_opts(opts), m_widget(widgetFor(kind, opts, factory)),
      m_buttons(new QDialogButtonBox(this))
{
    if (kind == Kind::ChangePin) {
        // The factory (test seam) returns a ChangePinInputWidget (or a
        // subclass); the production branch constructs one directly.
        m_changePinWidget = static_cast<ChangePinInputWidget*>(m_widget);
    }
    setWindowTitle(opts.title.isEmpty() ? defaultTitle(kind) : opts.title);
    // NOT modal, and it does not take focus. Two readers can drive two
    // credential prompts at once, so an application-modal window would stack
    // the second behind the first, and one that grabbed focus would collect the
    // remaining digits of a PIN being typed into the other card's field.
    setModal(false);
    setWindowModality(Qt::NonModal);
    setAttribute(Qt::WA_ShowWithoutActivating, true);

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

    // Prompter chrome (trusted, agent-independent): which credential the form
    // currently on screen takes. Only a switchable prompt renders it, and
    // swapInputKind() re-renders it for the form it installs.
    if (opts.offerMrzSwitch) {
        m_kindHint = new QLabel(kindHintText(m_kind), this);
        m_kindHint->setObjectName(QStringLiteral("kindHintLabel"));
        m_kindHint->setWordWrap(true);
        m_kindHint->setTextFormat(Qt::PlainText);
        layout->addWidget(m_kindHint);
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

    // Trusted area: the operation being consented to, derived from the
    // agent-owned closed-vocabulary artifact token. Rendered as prompter
    // chrome (a localized human sentence) — never the raw identifier the
    // wire carries. Tokens outside the vocabulary fall through to the
    // framed client-supplied area below.
    const QString operation = operationText(opts.artifact);
    if (!operation.isEmpty()) {
        auto* op = new QLabel(i18nc("@info trusted operation label", "Operation: %1", operation), this);
        op->setObjectName(QStringLiteral("operationLabel"));
        op->setWordWrap(true);
        op->setTextFormat(Qt::PlainText);
        layout->addWidget(op);
    }

    // Untrusted area: the requester — and any artifact token OUTSIDE the
    // trusted vocabulary — are client-supplied. They are framed inside a
    // clearly-titled group box so the user can never confuse client-supplied
    // text for the prompter's own (trusted) wording — the title is fixed
    // prompter chrome, the values inside are inert plain text. The whole box
    // is omitted when nothing client-supplied is present (an agent-initiated
    // prompt with a recognised operation shows no box at all).
    const bool unknownArtifact = !opts.artifact.isEmpty() && operation.isEmpty();
    if (!opts.requester.isEmpty() || unknownArtifact) {
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
        if (unknownArtifact) {
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
        m_retryError = new QLabel(retryErrorText(opts.lastError), this);
        m_retryError->setObjectName(QStringLiteral("retryErrorLabel"));
        m_retryError->setWordWrap(true);
        m_retryError->setTextFormat(Qt::PlainText);
        layout->addWidget(m_retryError);
    }

    m_widget->setParent(this);
    layout->addWidget(m_widget);

    // The switch affordance sits between the input widget and the button box:
    // it changes what is being asked for, so it belongs with the entry area,
    // not among the accept/cancel actions. Flat, and explicitly NOT a default
    // button — Return must still accept the dialog, never silently swap the
    // form out from under a user who has already typed.
    if (opts.offerMrzSwitch) {
        m_switchButton = new QPushButton(switchButtonText(m_kind), this);
        m_switchButton->setObjectName(QStringLiteral("switchToMrzButton"));
        m_switchButton->setFlat(true);
        m_switchButton->setAutoDefault(false);
        m_switchButton->setDefault(false);
        connect(m_switchButton, &QPushButton::clicked, this, &PromptDialog::swapInputKind);
        layout->addWidget(m_switchButton);
    }

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

void PromptDialog::announce()
{
    ++m_announcements;
    // A taskbar/urgency hint, not an activation: it asks to be noticed without
    // stealing what the holder is typing.
    QApplication::alert(this);
}

int PromptDialog::announcementsRequested() const
{
    return m_announcements;
}

bool PromptDialog::mrzChosen() const
{
    return m_kind == Kind::Mrz;
}

void PromptDialog::clearRetryError()
{
    if (m_retryError == nullptr) {
        return;
    }
    if (auto* box = qobject_cast<QVBoxLayout*>(layout())) {
        box->removeWidget(m_retryError);
    }
    m_retryError->hide();
    m_retryError->setParent(nullptr);
    m_retryError->deleteLater();
    m_retryError = nullptr;
}

void PromptDialog::swapInputKind()
{
    auto* box = qobject_cast<QVBoxLayout*>(layout());
    if (box == nullptr || m_widget == nullptr) {
        return;
    }
    const int slot = box->indexOf(m_widget);
    if (slot < 0) {
        return;
    }
    const Kind next = (m_kind == Kind::Mrz) ? Kind::Can : Kind::Mrz;

    // Out with the old, in the ONE order that neither orphans it nor lets a
    // dying widget drive the surviving one: sever its signals first (its
    // destructor scrub emits textChanged -> validityChanged), take it off the
    // layout and out of the widget tree, then hand it to deleteLater — that
    // destructor IS the disposal path for whatever the user had typed.
    InputWidgetBase* previous = m_widget;
    previous->disconnect();
    box->removeWidget(previous);
    previous->hide();
    previous->setParent(nullptr);
    previous->deleteLater();

    // In with the new, at the SAME slot the old one held.
    m_widget = widgetFor(next, m_opts, {});
    m_widget->setParent(this);
    box->insertWidget(slot, m_widget);
    m_widget->show();
    m_kind = next;

    // Re-frame everything that spoke about the previous kind. The caller's own
    // title still wins if it supplied one; the numeric entry bounds are simply
    // not carried across — each form applies its own entry rules.
    setWindowTitle(m_opts.title.isEmpty() ? defaultTitle(next) : m_opts.title);
    if (m_kindHint != nullptr) {
        m_kindHint->setText(kindHintText(next));
    }
    clearRetryError();
    if (m_switchButton != nullptr) {
        m_switchButton->setText(switchButtonText(next));
    }
    wireValidity();
    m_widget->setFocus();
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
