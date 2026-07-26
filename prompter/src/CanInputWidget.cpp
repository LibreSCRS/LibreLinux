// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "CanInputWidget.h"

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

namespace {
constexpr int kCanLen = 6;
}

CanInputWidget::CanInputWidget(QWidget* parent) : InputWidgetBase(parent), m_edit(new QLineEdit(this))
{
    m_edit->setMaxLength(kCanLen);
    m_edit->setInputMethodHints(Qt::ImhDigitsOnly);
    m_edit->setValidator(new QRegularExpressionValidator(QRegularExpression(QStringLiteral("^[0-9]{6}$")), this));

    auto* label = new QLabel(i18nc("@label:textbox CAN — Card Access Number", "CAN:"), this);
    auto* layout = new QFormLayout(this);
    layout->addRow(label, m_edit);
    connect(m_edit, &QLineEdit::textChanged, this, &InputWidgetBase::validityChanged);
    setFocusProxy(m_edit);
}

CanInputWidget::~CanInputWidget()
{
    m_edit->clear();
}

int CanInputWidget::captureSecretFd()
{
    auto qstr = m_edit->text();
    QByteArray utf8 = qstr.toUtf8();
    const int fd = makeSealedSecretFd(std::string_view{utf8.constData(), static_cast<std::size_t>(utf8.size())});
    qstr.fill(QChar{});
    utf8.fill('\0');
    m_edit->clear();
    return fd;
}

bool CanInputWidget::isValid() const
{
    return m_edit->hasAcceptableInput();
}

} // namespace LibreLinux::Prompter
