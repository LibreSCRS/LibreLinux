// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once

#include <QDialog>
#include <QString>
#include <QStringList>

#include <functional>

class QDialogButtonBox;
class QLabel;

namespace LibreLinux::Prompter {

class ChangePinInputWidget;
class InputWidgetBase;

/// Modal dialog that hosts exactly one of {Pin, Can, Mrz, ChangePin}
/// InputWidget, selected by the @c kind string passed to the prompter's
/// D-Bus method. The dialog title, description, requester label, and
/// artifact label are driven by the @c options dictionary the agent supplied.
///
/// Lifetime contract (single-secret kinds): the caller invokes @ref exec,
/// then while the dialog is still alive calls @ref captureSecretFd to write
/// the still-visible secret into a sealed memfd (the
/// widget's QLineEdit buffer must not be torn down before the read).
///
/// Multi-secret contract (Kind::ChangePin): the accept path validates the
/// confirmation and captures BOTH secrets (current + new) into sealed memfds
/// BEFORE the dialog hides (read-then-hide); the caller collects them
/// afterwards via @ref takeSecretFdPair. The confirm entry never leaves the
/// dialog — @ref SecretFdPair deliberately has no third slot.
///
/// External cancellation contract: PrompterService::CancelCurrent dispatches
/// QMetaObject::invokeMethod(dlg, "reject", Qt::QueuedConnection) from the
/// D-Bus worker thread. The inherited @c QDialog::reject is a public slot
/// reachable through Qt's meta-object system; PromptDialogRejectTest pins
/// this so a future subclass override that hides the slot is caught at
/// build time.
class PromptDialog : public QDialog
{
    Q_OBJECT
public:
    struct Options
    {
        QString title;
        QString description;
        QString requester;
        QString artifact;
        // UNTRUSTED per-document display names of a batch signing request
        // (the wire's `artifacts` RequestSecret option). Rendered in the
        // SAME top-of-dialog zone as `description` above — plain, unframed —
        // and deliberately NEVER inside the "Requested by an application"
        // group below: that box also holds `artifact`, the TRUSTED
        // closed-vocabulary category token ("signature-batch" for a batch),
        // and folding a client-controlled file list into that visually
        // labelled box would let it borrow the box's implied trust. Empty
        // for every prompt that is not a batch sign.
        QStringList artifacts;
        int minLength = 4; // applies to PIN; default range 4-8
        int maxLength = 8;

        // Retry context (the wire's `attempt`/`last_error` RequestSecret
        // options): 0 / empty on the first-ever prompt for a card;
        // populated on a re-prompt after the card rejected the value
        // collected last time. `lastError` carries a msgKey, not display
        // text -- buildLayout() maps it to a localized inline error line
        // shown above the input widget. Single-secret kinds only
        // (Kind::ChangePin has its own confirm-mismatch inline error).
        int attempt = 0;
        QString lastError;

        // Kind::ChangePin only — per-role bounds (primary drives the current
        // field; new drives the new AND confirm fields) + display-only labels.
        int primaryMinLength = 4;
        int primaryMaxLength = 8;
        int newMinLength = 4;
        int newMaxLength = 8;
        QString cardLabel;
        QString pinLabel;
    };

    enum class Kind { Pin, Can, Mrz, ChangePin };

    /// Exactly TWO captured secrets — current (primary) + new (secondary).
    /// The confirm entry is validation-only and never leaves the dialog;
    /// keeping this struct at two members is a compile-level containment
    /// guarantee (tests destructure it with a two-name structured binding).
    struct SecretFdPair
    {
        int primaryFd = -1;   ///< current PIN; sealed memfd, -1 if absent
        int secondaryFd = -1; ///< new PIN; sealed memfd, -1 if absent
    };

    /// Test seam: overrides construction of the Kind::ChangePin widget so
    /// recording subclasses can be injected. Production passes none and gets
    /// the real ChangePinInputWidget.
    using ChangePinWidgetFactory = std::function<ChangePinInputWidget*(const Options&)>;

    /// @param kind    Widget family to instantiate.
    /// @param opts    Caller-supplied metadata (display strings + numeric
    ///                range hints). All fields are optional.
    /// @param factory Kind::ChangePin widget factory override (tests only).
    PromptDialog(Kind kind, const Options& opts, QWidget* parent = nullptr, ChangePinWidgetFactory factory = {});
    ~PromptDialog() override;

    /// Capture the secret into a sealed memfd and return the fd. MUST be
    /// called BEFORE the dialog tears the widget down (i.e. while the
    /// PromptDialog instance is still alive). Returns -1 if the underlying
    /// memfd syscall fails. Single-secret kinds only.
    [[nodiscard]] int captureSecretFd();

    /// Hand over the two sealed secrets captured by the accept path
    /// (Kind::ChangePin). Ownership of the fds transfers to the caller; a
    /// second call (or a call after reject) returns {-1, -1}.
    [[nodiscard]] SecretFdPair takeSecretFdPair();

    /// Accept override (Kind::ChangePin): blocks acceptance with an inline
    /// error while the confirmation differs from the new PIN.
    void accept() override;

private:
    void buildLayout(const Options& opts);
    void wireValidity();

    InputWidgetBase* m_widget;
    ChangePinInputWidget* m_changePinWidget = nullptr; // alias of m_widget for Kind::ChangePin
    QDialogButtonBox* m_buttons;
    SecretFdPair m_captured;
};

} // namespace LibreLinux::Prompter
