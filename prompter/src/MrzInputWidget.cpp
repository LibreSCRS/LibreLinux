// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "MrzInputWidget.h"

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

// ICAO 9303 check-digit weighting (cyclic 7-3-1).
constexpr int kWeights[3] = {7, 3, 1};

int charValue(QChar c)
{
    if (c.isDigit())
        return c.digitValue();
    if (c == QLatin1Char('<'))
        return 0;
    // ICAO 9303: A=10, B=11, ..., Z=35.
    if (c.isLetter())
        return c.toUpper().toLatin1() - 'A' + 10;
    return -1; // invalid character — caller must reject
}

} // namespace

bool MrzInputWidget::checkDigitOk(const QString& fieldValue, QChar checkChar)
{
    if (!checkChar.isDigit())
        return false;
    int sum = 0;
    for (int i = 0; i < fieldValue.size(); ++i) {
        const int v = charValue(fieldValue.at(i));
        if (v < 0)
            return false;
        sum += v * kWeights[i % 3];
    }
    return (sum % 10) == checkChar.digitValue();
}

MrzInputWidget::MrzInputWidget(QWidget* parent)
    : InputWidgetBase(parent), m_documentNumber(new QLineEdit(this)), m_dateOfBirth(new QLineEdit(this)),
      m_dateOfExpiry(new QLineEdit(this))
{
    m_documentNumber->setMaxLength(10); // 9 chars + 1 check digit
    m_documentNumber->setValidator(
        new QRegularExpressionValidator(QRegularExpression(QStringLiteral("^[A-Z0-9<]{9}[0-9]$")), this));
    m_documentNumber->setInputMethodHints(Qt::ImhUppercaseOnly | Qt::ImhPreferLatin);

    m_dateOfBirth->setMaxLength(7); // YYMMDD + check digit
    m_dateOfBirth->setValidator(
        new QRegularExpressionValidator(QRegularExpression(QStringLiteral("^[0-9]{6}[0-9]$")), this));
    m_dateOfBirth->setInputMethodHints(Qt::ImhDigitsOnly);

    m_dateOfExpiry->setMaxLength(7);
    m_dateOfExpiry->setValidator(
        new QRegularExpressionValidator(QRegularExpression(QStringLiteral("^[0-9]{6}[0-9]$")), this));
    m_dateOfExpiry->setInputMethodHints(Qt::ImhDigitsOnly);

    auto* layout = new QFormLayout(this);
    layout->addRow(new QLabel(i18nc("@label:textbox MRZ document number incl. check digit",
                                    "Document number (incl. check digit):"),
                              this),
                   m_documentNumber);
    layout->addRow(new QLabel(i18nc("@label:textbox MRZ date of birth YYMMDD + check digit",
                                    "Date of birth (YYMMDD + check digit):"),
                              this),
                   m_dateOfBirth);
    layout->addRow(new QLabel(i18nc("@label:textbox MRZ date of expiry YYMMDD + check digit",
                                    "Date of expiry (YYMMDD + check digit):"),
                              this),
                   m_dateOfExpiry);

    for (auto* edit : {m_documentNumber, m_dateOfBirth, m_dateOfExpiry})
        connect(edit, &QLineEdit::textChanged, this, &InputWidgetBase::validityChanged);

    setFocusProxy(m_documentNumber);
}

MrzInputWidget::~MrzInputWidget()
{
    for (auto* edit : {m_documentNumber, m_dateOfBirth, m_dateOfExpiry})
        edit->clear();
}

int MrzInputWidget::captureSecretFd()
{
    auto doc = m_documentNumber->text();
    auto dob = m_dateOfBirth->text();
    auto exp = m_dateOfExpiry->text();
    // Concatenate to a real QString (not a QStringBuilder expression) so we
    // can scrub the joined buffer explicitly post-extraction.
    QString joined;
    joined.reserve(doc.size() + dob.size() + exp.size() + 2);
    joined.append(doc).append(QLatin1Char('\n')).append(dob).append(QLatin1Char('\n')).append(exp);

    QByteArray utf8 = joined.toUtf8();
    const int fd = makeSealedSecretFd(std::string_view{utf8.constData(), static_cast<std::size_t>(utf8.size())});

    doc.fill(QChar{});
    dob.fill(QChar{});
    exp.fill(QChar{});
    joined.fill(QChar{});
    utf8.fill('\0');
    for (auto* edit : {m_documentNumber, m_dateOfBirth, m_dateOfExpiry})
        edit->clear();
    return fd;
}

bool MrzInputWidget::isValid() const
{
    if (!m_documentNumber->hasAcceptableInput() || !m_dateOfBirth->hasAcceptableInput() ||
        !m_dateOfExpiry->hasAcceptableInput())
        return false;
    const auto doc = m_documentNumber->text();
    const auto dob = m_dateOfBirth->text();
    const auto exp = m_dateOfExpiry->text();
    return checkDigitOk(doc.left(9), doc.at(9)) && checkDigitOk(dob.left(6), dob.at(6)) &&
           checkDigitOk(exp.left(6), exp.at(6));
}

} // namespace LibreLinux::Prompter
