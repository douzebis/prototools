// SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

use super::super::*;
use super::support::*;

#[test]
fn q_confirmation_is_cancelled_by_any_other_key() {
    let decoded = Decoded {
        lines: Vec::new(),
        tree: Vec::new(),
        root_type: "google.protobuf.Empty".to_string(),
        blob: Vec::new(),
        wrapper_offset: 0,
        style_hints: Vec::new(),
    };
    let mut app = App::new(
        decoded,
        "empty.pb",
        PathBuf::from("empty.pb"),
        2,
        DescriptorContext::empty_for_test(),
        ThemeKind::Dark,
    );
    app.splash = false;

    app.handle_key(KeyEvent::new(KeyCode::Char('q'), KeyModifiers::NONE));
    assert!(!app.should_quit);
    assert!(app.quit_confirm);

    app.handle_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
    assert!(!app.should_quit);
    assert!(!app.quit_confirm);
    assert!(app.message.is_empty());

    // A fresh `q` press re-arms confirmation from scratch.
    app.handle_key(KeyEvent::new(KeyCode::Char('q'), KeyModifiers::NONE));
    assert!(app.quit_confirm);
    app.handle_key(KeyEvent::new(KeyCode::Char('q'), KeyModifiers::NONE));
    assert!(app.should_quit);
}

/// Spec 0113 D31: `Ctrl-Z` sets `should_suspend` (the actual
/// `SIGTSTP`/terminal dance lives in `run_loop`/`suspend`, outside
/// `App`'s own unit-testable surface) — checked centrally, so it
/// fires uniformly regardless of a pending quit confirmation, and
/// leaves that confirmation untouched.
#[test]
#[cfg(unix)]
fn ctrl_z_sets_should_suspend_without_disturbing_quit_confirm() {
    let decoded = Decoded {
        lines: Vec::new(),
        tree: Vec::new(),
        root_type: "google.protobuf.Empty".to_string(),
        blob: Vec::new(),
        wrapper_offset: 0,
        style_hints: Vec::new(),
    };
    let mut app = App::new(
        decoded,
        "empty.pb",
        PathBuf::from("empty.pb"),
        2,
        DescriptorContext::empty_for_test(),
        ThemeKind::Dark,
    );
    app.splash = false;

    app.handle_key(KeyEvent::new(KeyCode::Char('q'), KeyModifiers::NONE));
    assert!(app.quit_confirm);

    app.handle_key(KeyEvent::new(KeyCode::Char('z'), KeyModifiers::CONTROL));
    assert!(app.should_suspend);
    assert!(!app.should_quit);
    assert!(
        app.quit_confirm,
        "Ctrl-Z must not disturb a pending quit confirmation"
    );
}

/// The splash screen is transparent to keyboard input (spec 0113 D22
/// amendment): the very first keypress both dismisses it and is
/// processed as a real command, rather than being swallowed.
#[test]
fn splash_dismissing_keypress_is_also_processed_as_a_command() {
    let mut app = message_node_app();
    assert!(app.splash);
    app.term_width = 120;

    app.handle_key(KeyEvent::new(KeyCode::Char('t'), KeyModifiers::NONE));
    assert!(!app.splash);
    assert_eq!(app.override_target, Some(0));
}

/// `F1` opens the help overlay; `q`, `Esc`, or `F1` closes it — `?` is
/// no longer bound to help, since it now belongs to in-pane search.
#[test]
fn f1_opens_and_closes_the_help_overlay() {
    let mut app = message_node_app();
    app.splash = false;

    app.handle_key(KeyEvent::new(KeyCode::F(1), KeyModifiers::NONE));
    assert!(app.help_open);

    app.handle_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
    assert!(!app.help_open);

    app.handle_key(KeyEvent::new(KeyCode::F(1), KeyModifiers::NONE));
    assert!(app.help_open);
    app.handle_key(KeyEvent::new(KeyCode::F(1), KeyModifiers::NONE));
    assert!(!app.help_open);
}

/// Spec 0126 G1: `F1` opens the help overlay regardless of what
/// currently has focus — `manage_focus`, `override_focus`, and an
/// open `command_buffer` all used to swallow it before reaching the
/// main match arm's own `F1` handling.
#[test]
fn f1_opens_help_regardless_of_focus() {
    let mut app = message_node_app();
    app.splash = false;

    app.manage_focus = true;
    app.handle_key(KeyEvent::new(KeyCode::F(1), KeyModifiers::NONE));
    assert!(app.help_open);
    app.help_open = false;

    app.override_focus = true;
    app.handle_key(KeyEvent::new(KeyCode::F(1), KeyModifiers::NONE));
    assert!(app.help_open);
    app.help_open = false;
    app.override_focus = false;

    app.command_buffer = Some(String::new());
    app.handle_key(KeyEvent::new(KeyCode::F(1), KeyModifiers::NONE));
    assert!(app.help_open);
}

/// Spec 0114 §3: `Tab` toggles focus between the main pane and the
/// open override pane; main-pane navigation keys are inert while the
/// override pane has focus.
#[test]
fn tab_toggles_focus_between_main_and_override_panes() {
    let mut app = message_node_app();
    app.splash = false;
    app.term_width = 120;
    app.handle_key(KeyEvent::new(KeyCode::Char('t'), KeyModifiers::NONE));
    assert!(app.override_focus);

    app.handle_key(KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE));
    assert!(!app.override_focus);
    assert_eq!(app.override_target, Some(0)); // pane stays open

    app.handle_key(KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE));
    assert!(app.override_focus);
}

/// Item 3 (spec 0139 follow-up): `Enter` on a main-pane node with an
/// applicable override (active, here — the fixture's seeded root
/// entry) opens the management pane, same as pressing `o` directly.
#[test]
fn enter_opens_the_management_pane_when_an_override_applies() {
    let mut app = message_node_app();
    app.splash = false;
    app.term_width = 120;

    app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
    assert!(app.manage_open);
    assert!(app.manage_focus);
    assert_eq!(app.override_target, None);
}

/// Item 3 (spec 0139 follow-up): `Enter` on a main-pane node with
/// neither an active nor an applicable-inactive override opens the
/// selection pane instead, same as pressing `t` directly.
#[test]
fn enter_opens_the_override_pane_when_no_override_applies() {
    let mut app = message_node_app();
    app.splash = false;
    app.term_width = 120;
    while !app.overrides.entries().is_empty() {
        app.overrides.remove(0);
    }

    app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
    assert!(app.override_focus);
    assert_eq!(app.override_target, Some(0));
    assert!(!app.manage_open);
}
