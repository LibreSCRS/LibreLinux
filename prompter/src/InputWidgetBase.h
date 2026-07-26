// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once

#include <QWidget>

namespace LibreLinux::Prompter {

/// Common base for credential-capture widgets shown by @ref PromptDialog.
/// Each subclass owns one or more QLineEdits whose contents are written
/// straight into a sealed memfd via @ref captureSecretFd — this is the only
/// path the secret bytes ever take through the prompter address space, by
/// design.
class InputWidgetBase : public QWidget
{
    Q_OBJECT
public:
    explicit InputWidgetBase(QWidget* parent = nullptr);
    ~InputWidgetBase() override;

    /// Capture the secret into a sealed memfd and return the fd. MUST be
    /// called BEFORE the widget is hidden or disabled — the dialog scope
    /// must keep this widget alive across the call. The widget also clears
    /// its internal QLineEdit buffer best-effort post-capture.
    ///
    /// @returns A non-negative file descriptor on success, -1 on failure.
    ///          The caller takes ownership: it MUST either pass the fd to
    ///          sdbus::UnixFd (which dup()s and closes the original) or
    ///          close the fd directly. The fd has F_SEAL_SHRINK |
    ///          F_SEAL_GROW | F_SEAL_WRITE applied — readers can only
    ///          mmap()/read() the bytes.
    [[nodiscard]] virtual int captureSecretFd() = 0;

    /// True when the captured input passes the widget's validator and is
    /// ready to submit. The dialog connects this to the OK button enabled
    /// state via @ref validityChanged.
    [[nodiscard]] virtual bool isValid() const = 0;

Q_SIGNALS:
    /// Emitted whenever @ref isValid would return a different value than
    /// last time (or whenever the underlying input changes — the dialog
    /// rechecks on every emission, so coarse signalling is fine).
    void validityChanged();
};

} // namespace LibreLinux::Prompter
