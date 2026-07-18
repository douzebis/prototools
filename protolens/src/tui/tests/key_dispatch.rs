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

/// Item 14 (2026-07-17 feedback): `Ctrl-Left`/`Ctrl-Right` pan the
/// override pane and the manage pane, mirroring the main pane's own
/// Ctrl-Left/Ctrl-Right (spec 0113 D24) and the mouse's Shift-wheel/
/// native horizontal-scroll pan already available for these panes
/// (`mouse.rs`'s
/// `override_and_manage_panes_pan_independently_of_the_main_pane`).
#[test]
fn ctrl_left_right_pan_the_override_and_manage_panes() {
    let mut app = message_node_app();
    app.splash = false;
    app.term_width = 120;

    app.handle_key(KeyEvent::new(KeyCode::Char('t'), KeyModifiers::NONE));
    assert!(app.override_focus);

    app.handle_key(KeyEvent::new(KeyCode::Right, KeyModifiers::CONTROL));
    assert_eq!(app.override_pan_offset, PAN_STEP);
    app.handle_key(KeyEvent::new(KeyCode::Left, KeyModifiers::CONTROL));
    assert_eq!(app.override_pan_offset, 0);

    app.close_override();
    app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
    assert!(app.manage_focus);

    app.handle_key(KeyEvent::new(KeyCode::Right, KeyModifiers::CONTROL));
    assert_eq!(app.manage_pan_offset, PAN_STEP);
    app.handle_key(KeyEvent::new(KeyCode::Left, KeyModifiers::CONTROL));
    assert_eq!(app.manage_pan_offset, 0);
}

/// 2026-07-18 feedback item 2: `Ctrl-Up`/`Ctrl-Down` pan the override
/// pane's candidate list vertically without moving the highlight,
/// bounded so the highlighted row never leaves view.
#[test]
fn ctrl_up_down_pan_the_override_pane_without_moving_the_highlight() {
    let mut app = message_node_app();
    app.splash = false;
    app.override_focus = true;
    app.override_target = Some(0);
    app.override_candidates = (0..30).map(|i| (format!("cand.Type{i}"), None)).collect();
    app.override_list_height = 5;
    app.override_highlight = 19;
    // Start at the bottom edge of the 5-row window, same as after a
    // normal `clamp_scroll_to_visible` pass following cursor movement.
    app.override_scroll = 15;

    app.handle_key(KeyEvent::new(KeyCode::Down, KeyModifiers::CONTROL));
    assert_eq!(
        app.override_scroll, 19,
        "Ctrl-Down must reveal rows below, capped at the highlight's own row"
    );
    assert_eq!(
        app.override_highlight, 19,
        "panning must not move the highlight"
    );

    app.handle_key(KeyEvent::new(KeyCode::Down, KeyModifiers::CONTROL));
    assert_eq!(
        app.override_scroll, 19,
        "further Ctrl-Down is a no-op once the highlight reaches the top edge"
    );

    app.handle_key(KeyEvent::new(KeyCode::Up, KeyModifiers::CONTROL));
    assert_eq!(
        app.override_scroll, 15,
        "Ctrl-Up must reveal rows above, capped so the highlight stays visible"
    );
    assert_eq!(app.override_highlight, 19);

    app.handle_key(KeyEvent::new(KeyCode::Up, KeyModifiers::CONTROL));
    assert_eq!(
        app.override_scroll, 15,
        "further Ctrl-Up is a no-op once the highlight reaches the bottom edge"
    );
}

/// 2026-07-18 feedback item 2: `Ctrl-Up`/`Ctrl-Down` pan the manage
/// pane's list vertically without moving the highlight, bounded so the
/// highlighted row never leaves view. Uses 30 distinct-origin entries
/// (each gets its own `Header` row, spec 0117 §3 amendment) and asks
/// `manage_highlighted_row()` for the resulting row instead of
/// predicting the sort order, since `OverrideOrigin::label()` sorts
/// lexicographically (not numerically) on the embedded field number.
#[test]
fn ctrl_up_down_pan_the_manage_pane_without_moving_the_highlight() {
    let mut app = message_node_app();
    app.splash = false;
    app.manage_open = true;
    app.manage_focus = true;
    for field in 1..=30 {
        app.overrides.activate(
            OverrideOrigin::PathField {
                path: "/".to_string(),
                field,
            },
            None,
        );
    }
    let target_field = 15;
    let target_idx = app
        .overrides
        .entries()
        .iter()
        .position(|e| {
            e.origin
                == OverrideOrigin::PathField {
                    path: "/".to_string(),
                    field: target_field,
                }
        })
        .unwrap();
    app.manage_highlight = target_idx;
    app.manage_list_height = 5;
    let target_row = app.manage_highlighted_row();
    app.manage_scroll = target_row.saturating_sub(4);

    app.handle_key(KeyEvent::new(KeyCode::Down, KeyModifiers::CONTROL));
    assert_eq!(
        app.manage_scroll,
        (target_row.saturating_sub(4) + PAN_STEP).min(target_row),
        "Ctrl-Down must reveal rows below, capped at the highlight's own row"
    );
    assert_eq!(
        app.manage_highlight, target_idx,
        "panning must not move the highlight"
    );

    app.manage_scroll = target_row; // top edge
    app.handle_key(KeyEvent::new(KeyCode::Up, KeyModifiers::CONTROL));
    assert_eq!(
        app.manage_scroll,
        target_row
            .saturating_sub(PAN_STEP)
            .max(target_row.saturating_sub(4)),
        "Ctrl-Up must reveal rows above, capped so the highlight stays visible"
    );
    assert_eq!(app.manage_highlight, target_idx);
}
