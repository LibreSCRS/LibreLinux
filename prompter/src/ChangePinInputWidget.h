// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once

#include "InputWidgetBase.h"

#include <QString>

class QLabel;
class QLineEdit;

namespace LibreLinux::Prompter {

/// Three-field PIN change widget: current PIN + new PIN + confirmation.
///
/// Per-role bounds: the current field validates against the PRIMARY bounds,
/// the new AND confirm fields against the NEW bounds (a PIN change may widen
/// or narrow the permitted length range).
///
/// Secret containment: exactly TWO secrets ever leave this widget — the
/// current PIN via @ref captureSecretFd (the InputWidgetBase contract) and
/// the new PIN via @ref captureNewSecretFd. The confirm entry exists for
/// local validation only (@ref confirmMatchesNew); no accessor exposes it
/// and the payload-capture paths never consult it.
///
/// All reads of the three line-edit buffers funnel through the protected
/// virtual field-read seams so tests can inject recording subclasses that
/// pin the read-then-hide ordering and the confirm-containment rule.
class ChangePinInputWidget : public InputWidgetBase
{
    Q_OBJECT
public:
    /// @param currentMin/currentMax  Bounds of the CURRENT PIN field.
    /// @param newMin/newMax          Bounds of the new AND confirm fields.
    /// @param pinLabel               Human-readable PIN role name shown in
    ///                               the field labels; empty selects the
    ///                               generic "PIN" wording.
    ChangePinInputWidget(int currentMin, int currentMax, int newMin, int newMax, const QString& pinLabel,
                         QWidget* parent = nullptr);
    ~ChangePinInputWidget() override;

    /// Captures the CURRENT PIN into a sealed memfd (InputWidgetBase
    /// contract; the "primary" secret of the change_pin wire reply).
    [[nodiscard]] int captureSecretFd() override;

    /// Captures the NEW PIN into a sealed memfd (the "secondary" secret).
    /// Also scrubs the confirm buffer — its only purpose (validation) is
    /// complete once the new PIN is captured.
    [[nodiscard]] int captureNewSecretFd();

    /// True when all three fields pass their per-role bounds validators.
    /// Deliberately does NOT include the confirm==new comparison — the
    /// mismatch is an accept-time check with an inline error, so the user
    /// gets an explanation rather than a silently disabled button.
    [[nodiscard]] bool isValid() const override;

    /// Local validation: does the confirm entry equal the new PIN? The ONLY
    /// consumer of the confirm field's value.
    [[nodiscard]] bool confirmMatchesNew() const;

    /// Show the localized inline mismatch error below the confirm field.
    /// Cleared automatically as soon as the new or confirm entry changes.
    void showConfirmMismatch();

protected:
    // Field-read seams — the only paths that consume the line-edit values.
    // Virtual so tests can inject counting/ordering recorders.
    [[nodiscard]] virtual QString readCurrentFieldValue() const;
    [[nodiscard]] virtual QString readNewFieldValue() const;
    [[nodiscard]] virtual QString readConfirmFieldValue() const;

private:
    // Force-overwrite then clear @p edit's backing buffer. Best-effort
    // (QString COW) — same caveat as PinInputWidget::scrubEdit.
    void scrubEdit(QLineEdit* edit);
    void clearConfirmMismatch();

    QLineEdit* m_currentEdit;
    QLineEdit* m_newEdit;
    QLineEdit* m_confirmEdit;
    QLabel* m_mismatchLabel;
};

} // namespace LibreLinux::Prompter
