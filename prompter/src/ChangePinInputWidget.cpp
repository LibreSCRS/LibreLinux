// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "ChangePinInputWidget.h"

#include "SecretMemfd.h"

#include <KLocalizedString>

#include <QByteArray>
#include <QFormLayout>
#include <QLabel>
#include <QLineEdit>
#include <QRegularExpression>
#include <QRegularExpressionValidator>

#include <cstddef>
#include <string_view>

namespace LibreLinux::Prompter {

namespace {

// One secret-entry line edit with a numeric length-range validator — the
// same QRegularExpressionValidator pattern as PinInputWidget (QIntValidator
// would overflow past 9 digits).
QLineEdit* makePinEdit(int minLen, int maxLen, const char* objectName, QWidget* parent)
{
    auto* edit = new QLineEdit(parent);
    edit->setObjectName(QString::fromLatin1(objectName));
    edit->setEchoMode(QLineEdit::Password);
    edit->setMaxLength(maxLen);
    edit->setInputMethodHints(Qt::ImhDigitsOnly | Qt::ImhSensitiveData | Qt::ImhHiddenText);
    const auto pattern = QStringLiteral("^[0-9]{%1,%2}$").arg(minLen).arg(maxLen);
    edit->setValidator(new QRegularExpressionValidator(QRegularExpression(pattern), parent));
    return edit;
}

} // namespace

ChangePinInputWidget::ChangePinInputWidget(int currentMin, int currentMax, int newMin, int newMax,
                                           const QString& pinLabel, QWidget* parent)
    : InputWidgetBase(parent), m_currentEdit(makePinEdit(currentMin, currentMax, "currentPinEdit", this)),
      m_newEdit(makePinEdit(newMin, newMax, "newPinEdit", this)),
      m_confirmEdit(makePinEdit(newMin, newMax, "confirmPinEdit", this)), m_mismatchLabel(new QLabel(this))
{
    // %1 is the human-readable PIN role name (e.g. "signature PIN").
    // A "pin_<digits>" label is the agent-side selector synthesized for
    // records whose card profile carries no label — a machine identifier,
    // not a role name. Render the localized generic role for it, exactly
    // as for an absent label.
    static const QRegularExpression kSyntheticSelector(QStringLiteral("^pin_[0-9]+$"));
    const bool machineLabel = kSyntheticSelector.match(pinLabel).hasMatch();
    const QString role = (pinLabel.isEmpty() || machineLabel) ? i18nc("@item generic PIN role name", "PIN") : pinLabel;

    auto* layout = new QFormLayout(this);
    layout->addRow(new QLabel(i18nc("@label:textbox current PIN entry field", "Current %1:", role), this),
                   m_currentEdit);
    layout->addRow(new QLabel(i18nc("@label:textbox new PIN entry field", "New %1:", role), this), m_newEdit);
    layout->addRow(new QLabel(i18nc("@label:textbox new PIN confirmation field", "Confirm new %1:", role), this),
                   m_confirmEdit);

    // Inline mismatch error — hidden until an accept attempt with a confirm
    // entry that differs from the new PIN. Plain text, prompter chrome.
    m_mismatchLabel->setObjectName(QStringLiteral("confirmMismatchError"));
    m_mismatchLabel->setText(i18nc("@info:status inline error under the confirmation field",
                                   "The confirmation does not match the new %1.", role));
    m_mismatchLabel->setWordWrap(true);
    m_mismatchLabel->setTextFormat(Qt::PlainText);
    m_mismatchLabel->hide();
    layout->addRow(m_mismatchLabel);

    for (QLineEdit* edit : {m_currentEdit, m_newEdit, m_confirmEdit}) {
        connect(edit, &QLineEdit::textChanged, this, &InputWidgetBase::validityChanged);
    }
    // A stale mismatch error must clear as soon as either compared entry
    // changes — the user is correcting the input the error complained about.
    connect(m_newEdit, &QLineEdit::textChanged, this, &ChangePinInputWidget::clearConfirmMismatch);
    connect(m_confirmEdit, &QLineEdit::textChanged, this, &ChangePinInputWidget::clearConfirmMismatch);
    setFocusProxy(m_currentEdit);
}

ChangePinInputWidget::~ChangePinInputWidget()
{
    // Defence-in-depth scrub for the cancel path (capture never ran); the
    // authoritative cleansing happens at the sealed-memfd boundary.
    scrubEdit(m_currentEdit);
    scrubEdit(m_newEdit);
    scrubEdit(m_confirmEdit);
}

void ChangePinInputWidget::scrubEdit(QLineEdit* edit)
{
    // Same best-effort COW caveat as PinInputWidget::scrubEdit: overwrite
    // with same-length filler, then clear. Only the length is inspected —
    // the value itself is not consumed here.
    const int len = edit->text().size();
    if (len > 0) {
        edit->setText(QString(len, QLatin1Char('0')));
    }
    edit->clear();
}

QString ChangePinInputWidget::readCurrentFieldValue() const
{
    return m_currentEdit->text();
}

QString ChangePinInputWidget::readNewFieldValue() const
{
    return m_newEdit->text();
}

QString ChangePinInputWidget::readConfirmFieldValue() const
{
    return m_confirmEdit->text();
}

int ChangePinInputWidget::captureSecretFd()
{
    QByteArray utf8 = readCurrentFieldValue().toUtf8();
    const int fd = makeSealedSecretFd(std::string_view{utf8.constData(), static_cast<std::size_t>(utf8.size())});
    utf8.fill('\0');
    scrubEdit(m_currentEdit);
    return fd;
}

int ChangePinInputWidget::captureNewSecretFd()
{
    QByteArray utf8 = readNewFieldValue().toUtf8();
    const int fd = makeSealedSecretFd(std::string_view{utf8.constData(), static_cast<std::size_t>(utf8.size())});
    utf8.fill('\0');
    scrubEdit(m_newEdit);
    // The confirm buffer holds a copy of the new PIN and has served its
    // validation purpose — scrub it here, WITHOUT consuming its value.
    scrubEdit(m_confirmEdit);
    return fd;
}

bool ChangePinInputWidget::isValid() const
{
    return m_currentEdit->hasAcceptableInput() && m_newEdit->hasAcceptableInput() &&
           m_confirmEdit->hasAcceptableInput();
}

bool ChangePinInputWidget::confirmMatchesNew() const
{
    return readNewFieldValue() == readConfirmFieldValue();
}

void ChangePinInputWidget::showConfirmMismatch()
{
    m_mismatchLabel->show();
    m_confirmEdit->setFocus();
    m_confirmEdit->selectAll();
}

void ChangePinInputWidget::clearConfirmMismatch()
{
    m_mismatchLabel->hide();
}

} // namespace LibreLinux::Prompter
