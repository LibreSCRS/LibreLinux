// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once

#include "InputWidgetBase.h"

class QLineEdit;

namespace LibreLinux::Prompter {

/// PIN entry widget: 4-8 digit numeric by default, range configurable via
/// the ctor. Uses @c QRegularExpressionValidator (NOT @c QIntValidator —
/// the latter overflows for max length > 9 and silently truncates).
class PinInputWidget : public InputWidgetBase
{
    Q_OBJECT
public:
    explicit PinInputWidget(int minLen, int maxLen, QWidget* parent = nullptr);
    ~PinInputWidget() override;

    [[nodiscard]] int captureSecretFd() override;
    [[nodiscard]] bool isValid() const override;

private:
    // Force-overwrite then clear the line-edit's backing buffer. Best-effort
    // (QString COW) — see the definition for the secure-line-edit follow-up.
    void scrubEdit();

    QLineEdit* m_edit;
};

} // namespace LibreLinux::Prompter
