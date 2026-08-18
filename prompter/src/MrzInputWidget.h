// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once

#include "InputWidgetBase.h"

class QDateEdit;
class QLineEdit;
class QString;

namespace LibreLinux::Prompter {

/// Machine-readable-zone entry, human-shaped: the user types the document
/// number (up to 9 alphanumerics, WITHOUT its check digit) and picks the two
/// dates from calendar entries; the ICAO 9303 check digits and the `<`
/// filler padding are computed here, never typed.
///
/// @ref captureSecretFd emits the unchanged canonical payload — three
/// `\n`-separated fields (document number `<`-padded to 9 chars + check
/// digit, YYMMDD + check digit twice) matching the consumer's MRZ
/// credential-parsing contract. Only the human entry changed.
class MrzInputWidget : public InputWidgetBase
{
    Q_OBJECT
public:
    explicit MrzInputWidget(QWidget* parent = nullptr);
    ~MrzInputWidget() override;

    [[nodiscard]] int captureSecretFd() override;
    [[nodiscard]] bool isValid() const override;

    /// Pure ICAO 9303 check-digit verification: 7-3-1 cyclic weights on
    /// each character (digits = digit value, '<' = 0, A-Z = 10-35). Exposed
    /// for the validation unit test so the test does not need to drive the
    /// widget through synthetic input events.
    [[nodiscard]] static bool checkDigitOk(const QString& fieldValue, QChar checkChar);

    /// ICAO 9303 check digit for @p fieldValue under the same scheme as
    /// @ref checkDigitOk (the two share one weight walk — no drift).
    /// Returns a null QChar when @p fieldValue carries an invalid character.
    [[nodiscard]] static QChar computeCheckDigit(const QString& fieldValue);

private:
    QLineEdit* m_documentNumber;
    QDateEdit* m_dateOfBirth;
    QDateEdit* m_dateOfExpiry;
};

} // namespace LibreLinux::Prompter
