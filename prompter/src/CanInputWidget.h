// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once

#include "InputWidgetBase.h"

class QLineEdit;

namespace LibreLinux::Prompter {

/// Card-access-number entry (numeric secret) — fixed 6-digit numeric.
class CanInputWidget : public InputWidgetBase
{
    Q_OBJECT
public:
    explicit CanInputWidget(QWidget* parent = nullptr);
    ~CanInputWidget() override;

    [[nodiscard]] int captureSecretFd() override;
    [[nodiscard]] bool isValid() const override;

private:
    QLineEdit* m_edit;
};

} // namespace LibreLinux::Prompter
