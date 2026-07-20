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
        root_type_deferred: false,
    };
    let mut app = App::new(
        decoded,
        "empty.pb",
        PathBuf::from("empty.pb"),
        2,
        DescriptorContext::empty_for_test(),
        ThemeKind::Dark,
        None,
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
        root_type_deferred: false,
    };
    let mut app = App::new(
        decoded,
        "empty.pb",
        PathBuf::from("empty.pb"),
        2,
        DescriptorContext::empty_for_test(),
        ThemeKind::Dark,
        None,
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
    // 2026-07-19 feedback item 4: pan is now clamped on the right by
    // the widest visible row — set up a candidate list/pane width with
    // plenty of room to pan by a full `PAN_STEP` twice over, so the
    // clamp itself doesn't interfere with this test.
    app.override_candidates = vec![("cand.SomeVeryLongTypeNameHere".to_string(), None)];
    app.override_list_height = 5;
    app.side_area = Rect::new(0, 0, 5, 10);

    app.handle_key(KeyEvent::new(KeyCode::Right, KeyModifiers::CONTROL));
    assert_eq!(app.override_pan_offset, PAN_STEP);
    app.handle_key(KeyEvent::new(KeyCode::Left, KeyModifiers::CONTROL));
    assert_eq!(app.override_pan_offset, 0);

    app.close_override();
    app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
    assert!(app.manage_focus);
    app.manage_list_height = 5;
    app.side_area = Rect::new(0, 0, 5, 10);

    app.handle_key(KeyEvent::new(KeyCode::Right, KeyModifiers::CONTROL));
    assert_eq!(app.manage_pan_offset, PAN_STEP);
    app.handle_key(KeyEvent::new(KeyCode::Left, KeyModifiers::CONTROL));
    assert_eq!(app.manage_pan_offset, 0);
}

/// 2026-07-19 feedback items 1/2: `Ctrl-Up`/`Ctrl-Down` pan the override
/// pane's candidate list vertically without moving the highlight,
/// bounded only by the content itself (`0` at the top, `total -
/// list_height` at the bottom) — no longer tied to keeping the
/// highlighted row in view.
#[test]
fn ctrl_up_down_pan_the_override_pane_without_moving_the_highlight() {
    let mut app = message_node_app();
    app.splash = false;
    app.override_focus = true;
    app.override_target = Some(0);
    app.override_candidates = (0..30).map(|i| (format!("cand.Type{i}"), None)).collect();
    app.override_list_height = 5;
    app.override_highlight = 19;
    app.override_scroll = 15;
    let max_scroll = 30 - 5; // total candidates - list_height

    app.handle_key(KeyEvent::new(KeyCode::Down, KeyModifiers::CONTROL));
    assert_eq!(
        app.override_scroll,
        (15 + PAN_STEP).min(max_scroll),
        "Ctrl-Down must pan toward the content's own bottom edge"
    );
    assert_eq!(
        app.override_highlight, 19,
        "panning must not move the highlight"
    );

    app.handle_key(KeyEvent::new(KeyCode::Down, KeyModifiers::CONTROL));
    assert_eq!(
        app.override_scroll, max_scroll,
        "further Ctrl-Down stops at the content's own bottom edge"
    );

    app.handle_key(KeyEvent::new(KeyCode::Up, KeyModifiers::CONTROL));
    assert_eq!(app.override_scroll, max_scroll.saturating_sub(PAN_STEP));
    assert_eq!(app.override_highlight, 19);

    app.override_scroll = 0;
    app.handle_key(KeyEvent::new(KeyCode::Up, KeyModifiers::CONTROL));
    assert_eq!(
        app.override_scroll, 0,
        "Ctrl-Up stops at the content's own top edge"
    );
}

/// 2026-07-19 feedback items 1/2: `Ctrl-Up`/`Ctrl-Down` pan the manage
/// pane's list vertically without moving the highlight, bounded only by
/// the content itself (`0` at the top, `total - list_height` at the
/// bottom) — no longer tied to keeping the highlighted row in view.
/// Uses 30 distinct-origin entries (each gets its own `Header` row,
/// spec 0117 §3 amendment).
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
    app.manage_scroll = 10;
    let total_rows = app.manage_display_rows().len();
    let max_scroll = total_rows - 5;

    app.handle_key(KeyEvent::new(KeyCode::Down, KeyModifiers::CONTROL));
    assert_eq!(
        app.manage_scroll,
        (10 + PAN_STEP).min(max_scroll),
        "Ctrl-Down must pan toward the content's own bottom edge"
    );
    assert_eq!(
        app.manage_highlight, target_idx,
        "panning must not move the highlight"
    );

    app.manage_scroll = max_scroll;
    app.handle_key(KeyEvent::new(KeyCode::Down, KeyModifiers::CONTROL));
    assert_eq!(
        app.manage_scroll, max_scroll,
        "further Ctrl-Down stops at the content's own bottom edge"
    );

    app.manage_scroll = 0;
    app.handle_key(KeyEvent::new(KeyCode::Up, KeyModifiers::CONTROL));
    assert_eq!(
        app.manage_scroll, 0,
        "Ctrl-Up stops at the content's own top edge"
    );
    assert_eq!(app.manage_highlight, target_idx);
}

/// Spec 0144 G1/G2: `v` resolves the FQDN under focus from whichever
/// pane currently has it — the override candidate pane here — and
/// (with `DescriptorContext::empty_for_test()`'s empty pool) reports
/// G3's "unknown type" outcome.
#[test]
#[cfg(unix)]
fn v_in_override_pane_reports_unknown_type_for_unresolvable_candidate() {
    let mut app = message_node_app();
    app.splash = false;
    app.override_focus = true;
    app.override_target = Some(0);
    app.override_candidates = vec![("test.SomeType".to_string(), None)];
    app.override_highlight = 0;

    app.handle_key(KeyEvent::new(KeyCode::Char('v'), KeyModifiers::NONE));
    assert_eq!(app.message, "unknown type: test.SomeType");
}

/// Spec 0144 G2: the `None` sentinel row (alphabetic-mode row 0) has
/// no declaration to jump to — `v` must not even attempt a lookup.
#[test]
#[cfg(unix)]
fn v_in_override_pane_is_a_no_op_for_the_none_sentinel() {
    let mut app = message_node_app();
    app.splash = false;
    app.override_focus = true;
    app.override_target = Some(0);
    app.override_candidates = vec![("protolens_internal.None".to_string(), None)];
    app.override_highlight = 0;

    app.handle_key(KeyEvent::new(KeyCode::Char('v'), KeyModifiers::NONE));
    assert_eq!(app.message, "no declaration to jump to here");
}

/// Spec 0144 G2: the manage pane's highlighted entry's own type is
/// resolved, independent of the override pane/cursor.
#[test]
#[cfg(unix)]
fn v_in_manage_pane_reports_unknown_type_for_the_highlighted_entry() {
    let mut app = message_node_app();
    app.splash = false;
    app.manage_open = true;
    app.manage_focus = true;
    app.overrides.activate(
        OverrideOrigin::PathField {
            path: "/".to_string(),
            field: 1,
        },
        Some("test.ManageType".to_string()),
    );
    app.manage_highlight = app
        .overrides
        .entries()
        .iter()
        .position(|e| e.r#type.as_deref() == Some("test.ManageType"))
        .unwrap();

    app.handle_key(KeyEvent::new(KeyCode::Char('v'), KeyModifiers::NONE));
    assert_eq!(app.message, "unknown type: test.ManageType");
}

/// Spec 0144 G2: with neither pane focused, `v` falls back to the
/// main-pane cursor node's own type.
#[test]
#[cfg(unix)]
fn v_in_main_pane_reports_unknown_type_for_the_cursor_node() {
    let mut app = message_node_app();
    app.splash = false;

    app.handle_key(KeyEvent::new(KeyCode::Char('v'), KeyModifiers::NONE));
    assert_eq!(app.message, "unknown type: google.protobuf.DescriptorProto");
}

/// Spec 0144 G2: a scalar main-pane node carries no `type_fqdn` at
/// all — `v` is a no-op, not a lookup failure, when it also has no
/// active override and no parent schema to fall back to (2026-07-18
/// fix: `fqdn_under_focus` now also consults those, mirroring
/// `status_type_label`, so an enum-typed scalar can resolve — see
/// `v_in_main_pane_resolves_an_enum_scalars_natural_type` below).
#[test]
#[cfg(unix)]
fn v_in_main_pane_is_a_no_op_for_a_scalar_node() {
    let mut app = sibling_leaves_app(&["field: 1"]);
    app.splash = false;
    // This fixture's single node sits at path "/" (root-level, no
    // parent) — drop the seeded root-type override entry first, or
    // it would accidentally match that node and mask the no-op case
    // this test targets.
    while !app.overrides.entries().is_empty() {
        app.overrides.remove(0);
    }

    app.handle_key(KeyEvent::new(KeyCode::Char('v'), KeyModifiers::NONE));
    assert_eq!(app.message, "no declaration to jump to here");
}

/// Regression test (2026-07-18 feedback): `v` on an enum-typed scalar
/// field with no active override must resolve the field's own
/// natural enum type and attempt a lookup — previously
/// `fqdn_under_focus` read only `span.type_fqdn` (always `None` for
/// scalars) for the main-pane branch, so this always reported "no
/// declaration to jump to here" even though `status_type_label`
/// already resolved and displayed the same FQDN on the status line.
#[test]
#[cfg(unix)]
fn v_in_main_pane_resolves_an_enum_scalars_natural_type() {
    let (mut app, durability_idx) = enum_field_fixture();
    app.cursor = durability_idx;
    assert!(app.proto_root.is_none());

    app.handle_key(KeyEvent::new(KeyCode::Char('v'), KeyModifiers::NONE));
    assert_eq!(
        app.message,
        "no proto root configured; set one with :proto-root <dir> or -I/--proto-root"
    );
}

/// Spec 0144 G2 (`fqdn_under_focus` doc comment): the internal,
/// non-real `decode::MESSAGE_SET_ITEM_FQDN` placeholder is never
/// registered as a real message — `v` must treat it the same as "no
/// type at all", not surface a confusing "unknown type" message.
#[test]
#[cfg(unix)]
fn v_is_a_no_op_for_the_internal_message_set_item_fqdn() {
    let mut app = message_set_fixture();
    let item_idx = app
        .tree
        .iter()
        .position(|n| n.span.type_fqdn.as_deref() == Some(decode::MESSAGE_SET_ITEM_FQDN))
        .expect("fixture must contain a MessageSet Item node");
    app.cursor = item_idx;

    app.handle_key(KeyEvent::new(KeyCode::Char('v'), KeyModifiers::NONE));
    assert_eq!(app.message, "no declaration to jump to here");
}

/// Spec 0144 G3/G4: a real, resolving FQDN (`type_as_fixture`'s
/// `test.Inner`) clears G3's own check, but with no `proto_root`
/// configured `v` stops at G4 with a clear message.
#[test]
#[cfg(unix)]
fn v_reports_missing_proto_root_when_type_resolves_but_none_is_configured() {
    let (mut app, inner_idx, _id_idx) = type_as_fixture();
    app.cursor = inner_idx;
    assert!(app.proto_root.is_none());

    app.handle_key(KeyEvent::new(KeyCode::Char('v'), KeyModifiers::NONE));
    assert_eq!(
        app.message,
        "no proto root configured; set one with :proto-root <dir> or -I/--proto-root"
    );
    assert!(app.pending_editor_open.is_none());
}

/// Spec 0144 G4: a configured `proto_root` under which the resolved
/// file doesn't actually exist reports "proto source not found"
/// rather than silently arming the editor handoff.
#[test]
#[cfg(unix)]
fn v_reports_proto_source_not_found_when_the_file_is_missing_under_proto_root() {
    let (mut app, inner_idx, _id_idx) = type_as_fixture();
    app.cursor = inner_idx;
    let proto_root = std::env::temp_dir().join("protolens-v-test-missing-root");
    app.proto_root = Some(proto_root.clone());

    app.handle_key(KeyEvent::new(KeyCode::Char('v'), KeyModifiers::NONE));
    assert_eq!(
        app.message,
        format!(
            "proto source not found: test_type_as.proto (under proto-root {})",
            proto_root.display()
        )
    );
    assert!(app.pending_editor_open.is_none());
}

/// Spec 0144 G1-G4: the full happy path — a resolving FQDN, a
/// configured `proto_root`, and the resolved `.proto` file actually
/// present — arms `pending_editor_open` (the fixture carries no
/// `source_code_info`, so `locate_declaration` falls back to line 1,
/// column 1 — see `neovim::locate_declaration`'s own doc comment).
#[test]
#[cfg(unix)]
fn v_arms_pending_editor_open_when_the_proto_source_is_found() {
    let (mut app, inner_idx, _id_idx) = type_as_fixture();
    app.cursor = inner_idx;
    static COUNTER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let proto_root = std::env::temp_dir().join(format!("protolens-v-test-root-{n}"));
    std::fs::create_dir_all(&proto_root).unwrap();
    let proto_path = proto_root.join("test_type_as.proto");
    std::fs::write(&proto_path, "").unwrap();
    app.proto_root = Some(proto_root.clone());

    app.handle_key(KeyEvent::new(KeyCode::Char('v'), KeyModifiers::NONE));
    std::fs::remove_dir_all(&proto_root).unwrap();

    let req = app
        .pending_editor_open
        .expect("must arm pending_editor_open");
    assert_eq!(req.path, proto_path);
    assert_eq!(req.line, 1);
    assert_eq!(req.col, 1);
}

/// Glitch reported 2026-07-18: a missing `nvim` binary must not crash
/// protolens — the failure is reported via `app.message` and the TUI
/// keeps running. Runtime-probes for a real `nvim` first and skips
/// gracefully instead of assuming this sandbox's `PATH` lacks it — a
/// real `nvim` would otherwise be spawned and block on `waitpid`.
#[test]
fn open_editor_reports_a_missing_nvim_instead_of_crashing() {
    if std::process::Command::new("nvim")
        .arg("--version")
        .output()
        .is_ok()
    {
        eprintln!("skipping: a real nvim is present on PATH");
        return;
    }
    let mut app = empty_app();
    // `open_editor` requires `io::Error: From<B::Error>` (it propagates
    // real I/O errors via `?`) — `TestBackend`'s `Error` is `Infallible`,
    // which doesn't convert, so a `CrosstermBackend` over an in-memory
    // buffer is used instead; it never touches a real terminal.
    let mut terminal = Terminal::new(CrosstermBackend::new(Vec::new())).unwrap();
    let req = neovim::EditorRequest {
        path: PathBuf::from("/tmp/protolens-test-does-not-exist.proto"),
        line: 1,
        col: 1,
    };
    // The return value itself isn't asserted: `enable_raw_mode_and_reenter`
    // (called on the way out, regardless of the branch below) talks to the
    // *real* process stdout/stdin, which isn't a tty under `cargo test`
    // and can legitimately fail here — a pre-existing, orthogonal
    // limitation of this sandboxed test run, not something Glitch 1's fix
    // is responsible for. What this test verifies is that the missing-
    // `nvim` spawn failure itself doesn't propagate as an `Err` (the
    // actual crash reported) but is instead converted to a message.
    let _ = neovim::open_editor(&mut terminal, &mut app, req);
    assert!(app.message.contains("cannot launch nvim"));
    assert!(matches!(app.editor_state, neovim::EditorState::NotRunning));
}
