// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once

#include "InputWidgetBase.h"

class QLineEdit;

namespace LibreLinux::Prompter {

/// Machine-readable-zone fields — three entries per ICAO 9303:
///   * Document number (9 chars + 1 check digit, alphanumeric)
///   * Date of birth (YYMMDD + check digit)
///   * Date of expiry (YYMMDD + check digit)
///
/// Each field carries an ICAO 9303 check-digit validator.
/// @ref captureSecretFd concatenates the three fields with a single `\n`
/// separator matching the consumer's MRZ credential-parsing contract.
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

private:
    QLineEdit* m_documentNumber;
    QLineEdit* m_dateOfBirth;
    QLineEdit* m_dateOfExpiry;
};

} // namespace LibreLinux::Prompter
