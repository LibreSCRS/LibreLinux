// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once

#include <QDialog>
#include <QString>
#include <QStringList>

#include <chrono>
#include <functional>

class QDialogButtonBox;
class QLabel;
class QTimer;
class QPushButton;

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
/// Non-modal by design (see the constructor): more than one credential window
/// can stand at once, and a window that took focus would collect the rest of a
/// secret the holder was typing into ANOTHER card's field.
///
/// External cancellation contract: PrompterService's dismissal dispatches
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

        // The wire's `alt_kinds` RequestSecret option, lifted verbatim: the
        // alternative credential kinds the CALLER declared it can also consume
        // for this operation. A plain value carry with no policy attached —
        // whether any of them is actually offered is decided by the service,
        // once, where the requested kind is also in scope; the dialog itself
        // reads only @ref offerMrzSwitch below. Empty for every caller that
        // does not opt in (i.e. every caller today).
        QStringList altKinds;

        // Render an in-dialog switch between the CAN form and the passport MRZ
        // form. Set by the service iff the request asked for a CAN *and* its
        // `alt_kinds` named the MRZ kind. The dialog makes no policy decision
        // of its own: it renders the affordance iff this flag is set, and the
        // service mints its distinct "the user switched" status off the same
        // flag, so what is offered and what can be answered cannot diverge.
        bool offerMrzSwitch = false;

        // Which reader raised this prompt (the wire's reader_* options).
        // TRUSTED, agent-owned: the agent owns the roster and is the only layer
        // that can tell a dual-interface unit's two slots apart. `interface` is
        // a CLOSED vocabulary token, never prose -- the dialog says it in the
        // holder's language. `full` is the literal PC/SC name, shown behind a
        // details affordance because it is long enough to push the entry field
        // off a small screen. All three empty on a prompt whose reader could
        // not be resolved, and then no reader row is rendered at all.
        QString readerModel;
        QString readerInterface;
        QString readerFull;

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

    /// Start the entry clock. The holder's time begins when the window is on
    /// screen, not when the request was marshalled.
    void showEvent(QShowEvent* event) override;

    /// Arm this window's own entry deadline. @p budget is a DURATION; it starts
    /// when the window is SHOWN, so what elapses is exactly what the holder
    /// watches count down and transport latency is not charged to them. A zero
    /// (or absent) budget means NO deadline -- never an instant expiry.
    ///
    /// The window enforces it itself and closes on expiry. That is the belt
    /// against a dismissal that never arrives, which is precisely today's
    /// defect: a window left standing with nobody reading it.
    void setEntryDeadline(std::chrono::milliseconds budget);

    /// Arm what the ALTERNATIVE form is worth, for a window that offers the
    /// in-dialog switch. @p budget is a DURATION measured from the same instant
    /// as setEntryDeadline's -- the moment the window is SHOWN -- so taking the
    /// switch re-bases the clock on the larger budget instead of adding a fresh
    /// one on top of what has already been spent. A switched window therefore
    /// lives the LONGER of the two budgets, never their sum, which is what
    /// keeps it inside the longest deadline the transport is pinned against.
    ///
    /// Zero (or never called) leaves the clock exactly as setEntryDeadline
    /// armed it: an agent that predates the option sends no such budget, and
    /// its windows must behave as they always have.
    void setAlternateEntryDeadline(std::chrono::milliseconds budget);

    /// The clock's new remaining time when the holder takes the offered switch:
    /// @p alternative minus @p elapsed -- what the window has ALREADY been
    /// standing -- never a fresh copy of @p alternative. A window switched at
    /// 1:50 into a 2:00 budget that then restarted a full 5:00 would stand for
    /// 6:50, and the transport carrying the prompt is pinned to outlive 5:00,
    /// not 6:50.
    ///
    /// Returns zero, meaning "leave the clock alone", when @p alternative
    /// grants no more than @p current (including switching BACK to the shorter
    /// form: time already granted is never taken back) and when the window has
    /// already outlived @p alternative -- a negative interval would read to a
    /// QTimer as "fire now" and close the window on the switch itself.
    ///
    /// Pure and static: this is the whole arithmetic, testable without a
    /// running clock, whose default coarse type reports intervals up to 5%
    /// above nominal and so cannot measure it.
    [[nodiscard]] static std::chrono::milliseconds rebasedRemaining(std::chrono::milliseconds current,
                                                                    std::chrono::milliseconds alternative,
                                                                    std::chrono::milliseconds elapsed) noexcept;

    /// True once this window closed itself on its deadline rather than being
    /// answered or dismissed.
    [[nodiscard]] bool expired() const;

    /// Ask for the window's share of attention WITHOUT taking focus: a
    /// taskbar/notification hint, never an activation. A window that opened
    /// behind others would otherwise run its whole entry deadline in silence
    /// and read to the holder as "nothing happened".
    void announce();

    /// How many times @ref announce was called. The EFFECT is only observable
    /// on a real desktop, but the mechanism is assertable offscreen -- and a
    /// window that announces nothing is the failure mode worth catching.
    [[nodiscard]] int announcementsRequested() const;

    /// True while the MRZ form is the ACTIVE input widget — either because the
    /// prompt asked for an MRZ outright, or because a CAN prompt offered the
    /// switch (@ref Options::offerMrzSwitch) and the user took it. The service
    /// combines it with the offer to decide which status the reply carries; a
    /// prompt that never offered a switch cannot report a switched outcome.
    [[nodiscard]] bool mrzChosen() const;

private:
    void buildLayout(const Options& opts);
    void wireValidity();

    /// Toggle the active input widget between the CAN and MRZ forms IN PLACE
    /// (same layout slot) and re-frame the dialog for the kind now shown. Only
    /// reachable from the switch affordance, which exists only under
    /// @ref Options::offerMrzSwitch.
    void swapInputKind();
    /// Re-base the running clock on the alternative form's budget. Idempotent
    /// and one-way: it only ever LENGTHENS the window, so switching back does
    /// not take back time already granted, and a second switch changes nothing.
    void rebaseEntryDeadlineOnAlternative();

    /// Drop the retry-context error line, if one is shown. It described the
    /// attempt made with the PREVIOUS form's credential, so it must not
    /// survive a swap and accuse a form the user has not submitted yet.
    void clearRetryError();

    Kind m_kind;
    Options m_opts; ///< non-secret request metadata; re-read when re-framing
    InputWidgetBase* m_widget;
    ChangePinInputWidget* m_changePinWidget = nullptr; // alias of m_widget for Kind::ChangePin
    QDialogButtonBox* m_buttons;
    QPushButton* m_switchButton = nullptr; // null unless Options::offerMrzSwitch
    QLabel* m_kindHint = nullptr;          // null unless Options::offerMrzSwitch
    QLabel* m_retryError = nullptr;        // null unless Options::attempt > 0
    QLabel* m_readerFullLabel = nullptr;   // null unless Options::readerFull is set
    SecretFdPair m_captured;
    int m_announcements = 0;

    // The window's own entry clock. m_deadlineTimer fires once and closes the
    // window; m_countdownTimer only repaints the remaining time. Both are
    // started from showEvent, never from the constructor -- the holder's time
    // begins when they can see the window.
    QTimer* m_deadlineTimer = nullptr;
    QTimer* m_countdownTimer = nullptr;
    QLabel* m_countdownLabel = nullptr;
    std::chrono::milliseconds m_entryBudget{0};
    // What the offered alternative form is worth, measured from the same
    // instant as m_entryBudget. 0 = the caller offered no budget for it.
    std::chrono::milliseconds m_altEntryBudget{0};
    std::chrono::steady_clock::time_point m_shownAt{};
    bool m_expired = false;
};

} // namespace LibreLinux::Prompter
