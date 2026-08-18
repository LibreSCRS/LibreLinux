// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "MrzInputWidget.h"

#include "SecretMemfd.h"

#include <KLocalizedString>

#include <QByteArray>
#include <QDate>
#include <QDateEdit>
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

// The MRZ document-number field is exactly nine characters; shorter numbers
// are legal and always travel '<'-padded.
constexpr int kDocumentNumberWidth = 9;

// Untouched-date sentinel: obviously not a real document date, so "never
// entered" is distinguishable from every legitimate value (the pre-agent
// client used the same convention).
const QDate kSentinelDate(1900, 1, 1);

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

QString mrzDate(const QDate& date)
{
    return date.toString(QStringLiteral("yyMMdd"));
}

} // namespace

QChar MrzInputWidget::computeCheckDigit(const QString& fieldValue)
{
    int sum = 0;
    for (int i = 0; i < fieldValue.size(); ++i) {
        const int v = charValue(fieldValue.at(i));
        if (v < 0)
            return QChar{};
        sum += v * kWeights[i % 3];
    }
    return QLatin1Char(static_cast<char>('0' + (sum % 10)));
}

bool MrzInputWidget::checkDigitOk(const QString& fieldValue, QChar checkChar)
{
    if (!checkChar.isDigit())
        return false;
    const QChar computed = computeCheckDigit(fieldValue);
    return !computed.isNull() && computed == checkChar;
}

MrzInputWidget::MrzInputWidget(QWidget* parent)
    : InputWidgetBase(parent), m_documentNumber(new QLineEdit(this)), m_dateOfBirth(new QDateEdit(kSentinelDate, this)),
      m_dateOfExpiry(new QDateEdit(kSentinelDate, this))
{
    m_documentNumber->setObjectName(QStringLiteral("mrzDocumentNumber"));
    m_documentNumber->setMaxLength(kDocumentNumberWidth); // check digit is computed, never typed
    m_documentNumber->setValidator(
        new QRegularExpressionValidator(QRegularExpression(QStringLiteral("^[A-Za-z0-9]{1,9}$")), this));
    m_documentNumber->setPlaceholderText(QStringLiteral("AB1234567"));
    m_documentNumber->setInputMethodHints(Qt::ImhUppercaseOnly | Qt::ImhPreferLatin);
    connect(m_documentNumber, &QLineEdit::textChanged, this, [this](const QString& text) {
        const QString upper = text.toUpper();
        if (upper != text) {
            m_documentNumber->setText(upper);
            return; // textChanged re-fires with the uppercased value
        }
        Q_EMIT validityChanged();
    });

    // The sentinel (minimum) date renders as a placeholder INVITATION, never
    // as a bizarre literal "01.01.1900" the user has to puzzle over.
    const QString pickDate = i18nc("@info:placeholder unset date entry", "select date");

    m_dateOfBirth->setObjectName(QStringLiteral("mrzDateOfBirth"));
    m_dateOfBirth->setCalendarPopup(true);
    m_dateOfBirth->setDisplayFormat(QStringLiteral("dd.MM.yyyy"));
    m_dateOfBirth->setMinimumDate(kSentinelDate);
    m_dateOfBirth->setSpecialValueText(pickDate);
    m_dateOfBirth->setMaximumDate(QDate::currentDate());
    connect(m_dateOfBirth, &QDateEdit::dateChanged, this, &InputWidgetBase::validityChanged);

    m_dateOfExpiry->setObjectName(QStringLiteral("mrzDateOfExpiry"));
    m_dateOfExpiry->setCalendarPopup(true);
    m_dateOfExpiry->setDisplayFormat(QStringLiteral("dd.MM.yyyy"));
    m_dateOfExpiry->setMinimumDate(kSentinelDate);
    m_dateOfExpiry->setSpecialValueText(pickDate);
    connect(m_dateOfExpiry, &QDateEdit::dateChanged, this, &InputWidgetBase::validityChanged);

    auto* layout = new QFormLayout(this);
    layout->addRow(
        new QLabel(i18nc("@label:textbox MRZ document number, without its check digit", "Document number:"), this),
        m_documentNumber);
    layout->addRow(new QLabel(i18nc("@label MRZ date of birth, calendar entry", "Date of birth:"), this),
                   m_dateOfBirth);
    layout->addRow(new QLabel(i18nc("@label MRZ date of expiry, calendar entry", "Date of expiry:"), this),
                   m_dateOfExpiry);

    setFocusProxy(m_documentNumber);
}

MrzInputWidget::~MrzInputWidget()
{
    m_documentNumber->clear();
    m_dateOfBirth->setDate(kSentinelDate);
    m_dateOfExpiry->setDate(kSentinelDate);
}

int MrzInputWidget::captureSecretFd()
{
    // Build the canonical fields: '<'-pad the document number to nine
    // characters and append the computed ICAO check digit to each field.
    QString doc = m_documentNumber->text().toUpper().leftJustified(kDocumentNumberWidth, QLatin1Char('<'));
    QString dob = mrzDate(m_dateOfBirth->date());
    QString exp = mrzDate(m_dateOfExpiry->date());

    // Concatenate to a real QString (not a QStringBuilder expression) so we
    // can scrub the joined buffer explicitly post-extraction.
    QString joined;
    joined.reserve(doc.size() + dob.size() + exp.size() + 5);
    joined.append(doc).append(computeCheckDigit(doc)).append(QLatin1Char('\n'));
    joined.append(dob).append(computeCheckDigit(dob)).append(QLatin1Char('\n'));
    joined.append(exp).append(computeCheckDigit(exp));

    QByteArray utf8 = joined.toUtf8();
    const int fd = makeSealedSecretFd(std::string_view{utf8.constData(), static_cast<std::size_t>(utf8.size())});

    doc.fill(QChar{});
    dob.fill(QChar{});
    exp.fill(QChar{});
    joined.fill(QChar{});
    utf8.fill('\0');
    m_documentNumber->clear();
    m_dateOfBirth->setDate(kSentinelDate);
    m_dateOfExpiry->setDate(kSentinelDate);
    return fd;
}

bool MrzInputWidget::isValid() const
{
    if (m_documentNumber->text().isEmpty() || !m_documentNumber->hasAcceptableInput())
        return false;
    const QDate dob = m_dateOfBirth->date();
    const QDate expiry = m_dateOfExpiry->date();
    return dob != kSentinelDate && dob <= QDate::currentDate() && expiry != kSentinelDate;
}

} // namespace LibreLinux::Prompter
