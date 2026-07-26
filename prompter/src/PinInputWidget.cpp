// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "PinInputWidget.h"

#include "SecretMemfd.h"

#include <KLocalizedString>

#include <QByteArray>
#include <QFormLayout>
#include <QLabel>
#include <QLineEdit>
#include <QRegularExpressionValidator>

#include <cstddef>
#include <string_view>

namespace LibreLinux::Prompter {

PinInputWidget::PinInputWidget(int minLen, int maxLen, QWidget* parent)
    : InputWidgetBase(parent), m_edit(new QLineEdit(this))
{
    m_edit->setEchoMode(QLineEdit::Password);
    m_edit->setMaxLength(maxLen);
    m_edit->setInputMethodHints(Qt::ImhDigitsOnly | Qt::ImhSensitiveData | Qt::ImhHiddenText);
    const auto pattern = QStringLiteral("^[0-9]{%1,%2}$").arg(minLen).arg(maxLen);
    m_edit->setValidator(new QRegularExpressionValidator(QRegularExpression(pattern), this));

    auto* label = new QLabel(i18nc("@label:textbox PIN entry field", "PIN:"), this);
    auto* layout = new QFormLayout(this);
    layout->addRow(label, m_edit);
    connect(m_edit, &QLineEdit::textChanged, this, &InputWidgetBase::validityChanged);
    setFocusProxy(m_edit);
}

PinInputWidget::~PinInputWidget()
{
    // Defence-in-depth scrub: the authoritative cleansing happens at the
    // sealing-memfd boundary in captureSecretFd. This scrub only matters when
    // the dialog is cancelled (captureSecretFd never runs).
    scrubEdit();
}

void PinInputWidget::scrubEdit()
{
    // Force-overwrite the QLineEdit's internal buffer before clearing it, so a
    // bare clear() (which just resets the length) does not leave the secret
    // digits sitting in the freed-but-not-zeroed backing store. Overwrite with
    // a same-length run of filler, then clear.
    //
    // NOTE: QString/QByteArray are copy-on-write, so this is best-effort, NOT a
    // guarantee — Qt may have already vended a detached copy of the text
    // (signals, validators, the display buffer) whose storage we cannot reach.
    // True zeroization needs a QLineEdit replacement backed by LM Secure::*
    // (a zeroizing allocator); that secure-line-edit is the deferred SOTA
    // follow-up and is tracked separately.
    const int len = m_edit->text().size();
    if (len > 0) {
        m_edit->setText(QString(len, QLatin1Char('0')));
    }
    m_edit->clear();
}

int PinInputWidget::captureSecretFd()
{
    // Single staging path: take the text straight to UTF-8 with no retained
    // intermediate QString of our own, minimising the number of user-space
    // copies we have to chase (COW still applies — see scrubEdit()).
    QByteArray utf8 = m_edit->text().toUtf8();
    const int fd = makeSealedSecretFd(std::string_view{utf8.constData(), static_cast<std::size_t>(utf8.size())});
    // The bytes are now in the kernel-side sealed memfd; scrub the user-space
    // staging buffer and the widget's backing buffer (best-effort, COW caveat).
    utf8.fill('\0');
    scrubEdit();
    return fd;
}

bool PinInputWidget::isValid() const
{
    return m_edit->hasAcceptableInput();
}

} // namespace LibreLinux::Prompter
