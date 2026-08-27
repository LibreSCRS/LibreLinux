// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "PromptDialog.h"

#include "PrompterWire.h"

#include "CanInputWidget.h"
#include "ChangePinInputWidget.h"
#include "InputWidgetBase.h"
#include "MrzInputWidget.h"
#include "PinInputWidget.h"

#include <KLocalizedString>

#include <QApplication>
#include <QDialogButtonBox>
#include <QShowEvent>
#include <QTimer>
#include <QFontMetrics>
#include <QGroupBox>
#include <QLabel>
#include <QPushButton>
#include <QVBoxLayout>

#include <unistd.h> // close

#include <utility>

namespace LibreLinux::Prompter {

namespace {

// Every prompt opens at least this wide, so a card's successive dialogs do not
// change size with their text. Chosen to fit the longest reader chrome line
// this dialog renders without wrapping it in the common case.
constexpr int kMinimumDialogWidth = 460;

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

// The remaining entry time as M:SS. Language-neutral BY DESIGN and not an
// oversight: the macOS prompter has no localisation at all, so a worded
// countdown would read identically only on Linux. A glyph plus digits behaves
// the same on both.
QString formatRemaining(std::chrono::milliseconds remaining)
{
    const auto total = std::chrono::duration_cast<std::chrono::seconds>(remaining).count();
    const auto clamped = total < 0 ? 0 : total;
    return QStringLiteral("%1:%2").arg(clamped / 60).arg(clamped % 60, 2, 10, QLatin1Char('0'));
}

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

// The reader's interface qualifier, said in the holder's language. The agent
// sends a closed token and never prose: it has no localisation, so any English
// it composed would arrive already written and no prompter could fix it.
// An unrecognised token is treated as "unknown" and renders nothing.
QString readerInterfaceText(const QString& token)
{
    if (token == QLatin1String(PrompterWire::kReaderInterfaceContact))
        return i18nc("@info which physical slot of a reader a prompt belongs to", "contact");
    if (token == QLatin1String(PrompterWire::kReaderInterfaceContactless))
        return i18nc("@info which physical slot of a reader a prompt belongs to", "contactless");
    return {};
}

// A language-neutral mark beside the localised word, so the two platforms show
// the same thing where one of them has no localisation at all. These are the
// closest widely-rendered stand-ins for the chip and wave marks; the word
// beside them carries the meaning wherever a font lacks the glyph.
QString readerInterfaceGlyph(const QString& token)
{
    if (token == QLatin1String(PrompterWire::kReaderInterfaceContact))
        return QString::fromUtf8("\xF0\x9F\x92\xB3"); // card in a slot
    if (token == QLatin1String(PrompterWire::kReaderInterfaceContactless))
        return QString::fromUtf8("\xF0\x9F\x93\xB6"); // wireless waves
    return {};
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

    // One stable base width for every prompt. Without it the dialog is only as
    // wide as whatever text this particular prompt happens to carry -- the
    // action line differs per artifact, the reader name is long or short, the
    // description and the retry line come and go -- so consecutive prompts for
    // one card opened at three different sizes and the window appeared to jump
    // around the screen. Labels stay word-wrapped, so a longer text still grows
    // the dialog downward; this only stops it shrinking below a readable width.
    setMinimumWidth(kMinimumDialogWidth);
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

    // Trusted area: WHICH READER is asking. Load-bearing rather than chrome --
    // more than one credential window can stand at once, and on a
    // dual-interface unit whose two PC/SC names share a serial the qualifier is
    // the only thing separating two otherwise identical dialogs. Agent-owned,
    // so it sits with the other trusted labels and never inside the
    // client-supplied group box. Plain text as defence in depth.
    if (!opts.readerModel.isEmpty()) {
        const QString qualifier = readerInterfaceText(opts.readerInterface);
        const QString glyph = readerInterfaceGlyph(opts.readerInterface);
        // %1 is the reader's model, e.g. "OMNIKEY 5422".
        QString text = i18nc("@info which reader is asking for the credential", "Reader: %1", opts.readerModel);
        if (!qualifier.isEmpty()) {
            // %1 is a language-neutral mark, %2 the localised interface name.
            text += QStringLiteral(" %1 %2").arg(glyph, qualifier);
        }
        auto* reader = new QLabel(text, this);
        reader->setObjectName(QStringLiteral("readerLabel"));
        reader->setWordWrap(true);
        reader->setTextFormat(Qt::PlainText);
        layout->addWidget(reader);

        // The literal PC/SC name behind a details affordance: it is long enough
        // to push the entry field off a small screen, so it is available rather
        // than shown.
        if (!opts.readerFull.isEmpty()) {
            m_readerFullLabel = new QLabel(opts.readerFull, this);
            m_readerFullLabel->setObjectName(QStringLiteral("readerFullDetails"));
            m_readerFullLabel->setWordWrap(true);
            m_readerFullLabel->setTextFormat(Qt::PlainText);
            m_readerFullLabel->hide();
            layout->addWidget(m_readerFullLabel);

            auto* details =
                new QPushButton(i18nc("@action:button reveal the reader's full system name", "Reader details"), this);
            details->setObjectName(QStringLiteral("readerDetailsButton"));
            details->setFlat(true);
            details->setAutoDefault(false);
            details->setDefault(false);
            connect(details, &QPushButton::clicked, m_readerFullLabel,
                    [label = m_readerFullLabel] { label->setVisible(!label->isVisible()); });
            layout->addWidget(details);
        }
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
    // not among the accept/cancel actions. Framed, not flat — Breeze leaves a
    // flat button frameless until hover, which read as plain centred text and
    // was not taken for something clickable. Not a default button either:
    // Return must still accept the dialog, never silently swap the form out
    // from under a user who has already typed.
    if (opts.offerMrzSwitch) {
        m_switchButton = new QPushButton(switchButtonText(m_kind), this);
        m_switchButton->setObjectName(QStringLiteral("switchToMrzButton"));
        m_switchButton->setAutoDefault(false);
        m_switchButton->setDefault(false);
        connect(m_switchButton, &QPushButton::clicked, this, &PromptDialog::swapInputKind);
        layout->addWidget(m_switchButton);
    }

    // The entry clock, shown only once a deadline is armed (setEntryDeadline).
    // A window that closes itself must say so while it still can -- one that
    // just vanished mid-entry would be the confusion this replaces.
    m_countdownLabel = new QLabel(this);
    m_countdownLabel->setObjectName(QStringLiteral("countdownLabel"));
    m_countdownLabel->setTextFormat(Qt::PlainText);
    m_countdownLabel->hide();
    layout->addWidget(m_countdownLabel);

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

void PromptDialog::setEntryDeadline(std::chrono::milliseconds budget)
{
    m_entryBudget = budget;
    if (budget <= std::chrono::milliseconds::zero()) {
        // No deadline. Zero is the "unset" sentinel and must never be read as
        // an instant expiry -- a window that closed the moment it appeared
        // would be worse than one that never closes.
        return;
    }
    m_countdownLabel->show();
    m_countdownLabel->setText(QStringLiteral("\u23F1 %1").arg(formatRemaining(budget)));

    m_deadlineTimer = new QTimer(this);
    m_deadlineTimer->setSingleShot(true);
    connect(m_deadlineTimer, &QTimer::timeout, this, [this] {
        // Record BEFORE closing: reject() runs the completion synchronously
        // through finished(), which reads this to pick the reply word.
        m_expired = true;
        reject();
    });

    m_countdownTimer = new QTimer(this);
    m_countdownTimer->setInterval(1000);
    connect(m_countdownTimer, &QTimer::timeout, this, [this] {
        const auto elapsed =
            std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - m_shownAt);
        m_countdownLabel->setText(QStringLiteral("\u23F1 %1").arg(formatRemaining(m_entryBudget - elapsed)));
    });
}

void PromptDialog::setAlternateEntryDeadline(std::chrono::milliseconds budget)
{
    m_altEntryBudget = budget;
}

std::chrono::milliseconds PromptDialog::rebasedRemaining(std::chrono::milliseconds current,
                                                         std::chrono::milliseconds alternative,
                                                         std::chrono::milliseconds elapsed) noexcept
{
    if (alternative <= current) {
        return std::chrono::milliseconds::zero();
    }
    const auto remaining = alternative - elapsed;
    return remaining > std::chrono::milliseconds::zero() ? remaining : std::chrono::milliseconds::zero();
}

void PromptDialog::rebaseEntryDeadlineOnAlternative()
{
    // No clock to re-base: an unset deadline stays unset, and a window not yet
    // shown has not started one -- showEvent will arm it from m_entryBudget.
    if (m_deadlineTimer == nullptr || !m_deadlineTimer->isActive()) {
        return;
    }
    const auto elapsed =
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - m_shownAt);
    const auto remaining = rebasedRemaining(m_entryBudget, m_altEntryBudget, elapsed);
    if (remaining <= std::chrono::milliseconds::zero()) {
        return;
    }
    // One-way: m_entryBudget now IS the alternative's, so a second switch (and
    // switching back) finds nothing left to grant and leaves the clock alone.
    m_entryBudget = m_altEntryBudget;
    m_deadlineTimer->start(remaining);
    m_countdownLabel->setText(QStringLiteral("\u23F1 %1").arg(formatRemaining(remaining)));
}

bool PromptDialog::expired() const
{
    return m_expired;
}

void PromptDialog::showEvent(QShowEvent* event)
{
    QDialog::showEvent(event);
    if (m_deadlineTimer == nullptr || m_deadlineTimer->isActive()) {
        return;
    }
    // The holder's time starts HERE, not when the request was marshalled: what
    // elapses is exactly what they watch count down.
    m_shownAt = std::chrono::steady_clock::now();
    m_deadlineTimer->start(m_entryBudget);
    m_countdownTimer->start();
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
    rebaseEntryDeadlineOnAlternative();
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
