// SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

use prototext_core::helpers::{WT_LEN, WT_VARINT};
use prototext_core::serialize::render_text::NodeSpan;
use ratatui::backend::TestBackend;

use super::*;

/// Regression test: a legitimately-empty decode (e.g. reopening an
/// extracted `google.protobuf.Empty`, or any all-default submessage —
/// decoding zero bytes yields zero `TreeNode`s, not an error) must not
/// panic on the first `render()` call or on keypresses, now that
/// `main.rs` no longer refuses to open such a blob.
#[test]
fn empty_tree_renders_and_handles_keys_without_panicking() {
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

    let backend = TestBackend::new(80, 24);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|frame| app.render(frame)).unwrap();

    // Dismiss the startup splash first (any key), then exercise a
    // handful of keys that are unguarded `self.tree[...]` indexing
    // sites for a non-empty tree.
    app.splash = false;
    for code in [
        KeyCode::Down,
        KeyCode::Up,
        KeyCode::Left,
        KeyCode::Right,
        KeyCode::Char('z'),
        KeyCode::Char('x'),
        KeyCode::End,
    ] {
        app.handle_key(KeyEvent::new(code, KeyModifiers::NONE));
    }
    terminal.draw(|frame| app.render(frame)).unwrap();

    app.handle_key(KeyEvent::new(KeyCode::Char('q'), KeyModifiers::NONE));
    assert!(!app.should_quit);
    app.handle_key(KeyEvent::new(KeyCode::Char('q'), KeyModifiers::NONE));
    assert!(app.should_quit);
}

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

/// A passive status message auto-dismisses once `MESSAGE_TIMEOUT` has
/// elapsed since it was set — detected by `track_message_timeout`
/// (called from `render`) noticing an expired `message_deadline`.
#[test]
fn message_auto_dismisses_after_timeout() {
    let mut app = empty_app();
    app.splash = false;
    let backend = TestBackend::new(80, 24);
    let mut terminal = Terminal::new(backend).unwrap();

    app.message = "pattern not found: xyz".to_string();
    terminal.draw(|frame| app.render(frame)).unwrap();
    assert!(app.message_deadline.is_some());
    assert_eq!(app.message, "pattern not found: xyz");

    // Not yet expired: still showing on a later render.
    terminal.draw(|frame| app.render(frame)).unwrap();
    assert_eq!(app.message, "pattern not found: xyz");

    // Force expiry (real time never actually elapses in a unit test).
    app.message_deadline = Some(Instant::now() - Duration::from_millis(1));
    terminal.draw(|frame| app.render(frame)).unwrap();
    assert!(app.message.is_empty());
    assert!(app.message_deadline.is_none());
}

/// A message never auto-dismisses while the bottom bar is actively
/// serving as a text-entry prompt (`command_buffer`) or a pending `q`
/// quit confirmation — both are actively awaiting a keypress, unlike
/// a plain notice.
#[test]
fn message_is_not_dismissed_while_a_prompt_or_quit_confirm_is_active() {
    let mut app = empty_app();
    app.splash = false;
    let backend = TestBackend::new(80, 24);
    let mut terminal = Terminal::new(backend).unwrap();

    app.message = "some notice".to_string();
    app.command_buffer = Some(String::new());
    terminal.draw(|frame| app.render(frame)).unwrap();
    app.message_deadline = Some(Instant::now() - Duration::from_millis(1));
    terminal.draw(|frame| app.render(frame)).unwrap();
    assert_eq!(
        app.message, "some notice",
        "prompt active: must not dismiss"
    );

    app.command_buffer = None;
    app.quit_confirm = true;
    app.message_deadline = Some(Instant::now() - Duration::from_millis(1));
    terminal.draw(|frame| app.render(frame)).unwrap();
    assert_eq!(
        app.message, "some notice",
        "quit_confirm active: must not dismiss"
    );
}

#[test]
fn resolve_command_prefix_and_exact_match() {
    assert_eq!(resolve_command("extract"), Ok("extract"));
    assert_eq!(resolve_command("e"), Ok("extract"));
    assert!(resolve_command("zzz").is_err());
    // "type-as" is itself a prefix of "type-as-raw" — exact match
    // must still win (spec 0114 §7).
    assert_eq!(resolve_command("type-as"), Ok("type-as"));
    assert_eq!(resolve_command("type-as-raw"), Ok("type-as-raw"));
    assert!(resolve_command("type-a").is_err());
}

#[test]
fn longest_common_prefix_examples() {
    assert_eq!(longest_common_prefix(&["extract", "extra"]), "extra");
    assert_eq!(longest_common_prefix(&["extract"]), "extract");
    assert_eq!(longest_common_prefix(&[]), "");
    assert_eq!(longest_common_prefix(&["abc", "xyz"]), "");
}

fn empty_app() -> App {
    let decoded = Decoded {
        lines: Vec::new(),
        tree: Vec::new(),
        root_type: "google.protobuf.Empty".to_string(),
        blob: Vec::new(),
        wrapper_offset: 0,
        style_hints: Vec::new(),
    };
    App::new(
        decoded,
        "empty.pb",
        PathBuf::from("empty.pb"),
        2,
        DescriptorContext::empty_for_test(),
        ThemeKind::Dark,
    )
}

/// Spec 0113 D26: `Tab` on a unique-matching command-name prefix
/// completes it in full.
#[test]
fn tab_completes_the_unique_command_name() {
    let mut app = empty_app();
    app.splash = false;
    app.handle_key(KeyEvent::new(KeyCode::Char(':'), KeyModifiers::NONE));
    app.handle_key(KeyEvent::new(KeyCode::Char('e'), KeyModifiers::NONE));
    app.handle_key(KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE));
    assert_eq!(app.command_buffer.as_deref(), Some("extract"));
    assert_eq!(app.command_cursor, "extract".chars().count());
}

/// Spec 0113 D26: once a space precedes the cursor, `Tab` is a silent
/// no-op for commands with no argument completion — `:extract` has
/// none (spec 0114 §7 only adds argument completion for `:type-as`'s
/// FQDN argument, exercised separately).
#[test]
fn tab_is_a_no_op_once_past_the_first_space() {
    let mut app = empty_app();
    app.splash = false;
    app.handle_key(KeyEvent::new(KeyCode::Char(':'), KeyModifiers::NONE));
    for c in "extract ".chars() {
        app.handle_key(KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE));
    }
    app.handle_key(KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE));
    assert_eq!(app.command_buffer.as_deref(), Some("extract "));
}

/// Spec 0113 D26: repeated `Tab` cycles forward through a multi-
/// candidate list, wrapping around; `Shift-Tab` (`BackTab`) cycles
/// backward. Exercised directly against `handle_tab_key`/a synthetic
/// `CompletionState` (real multi-candidate cycling is also reachable
/// end-to-end via `:type-as`/`:type-as-raw`, spec 0114 §7 — see
/// `resolve_command_prefix_and_exact_match` and the `type_as_command_*`
/// tests below).
#[test]
fn tab_cycles_forward_and_shift_tab_cycles_backward() {
    let mut app = empty_app();
    app.command_buffer = Some("xy".to_string());
    app.command_cursor = 2;
    app.completion = Some(CompletionState {
        token_start: 0,
        suffix: String::new(),
        candidates: vec![
            "xyalpha".to_string(),
            "xybeta".to_string(),
            "xygamma".to_string(),
        ],
        index: None,
    });
    app.handle_tab_key(true);
    assert_eq!(app.command_buffer.as_deref(), Some("xyalpha"));
    app.handle_tab_key(true);
    assert_eq!(app.command_buffer.as_deref(), Some("xybeta"));
    app.handle_tab_key(false);
    assert_eq!(app.command_buffer.as_deref(), Some("xyalpha"));
    // Wraps backward past the start.
    app.handle_tab_key(false);
    assert_eq!(app.command_buffer.as_deref(), Some("xygamma"));
}

/// A single-node tree whose root is a message/group node — the
/// minimal fixture needed to exercise `t`'s override-target
/// validation (spec 0114 §1).
fn message_node_app() -> App {
    let lines: Vec<String> = vec!["message_type {".to_string(), "}".to_string()];
    let node = TreeNode {
        span: NodeSpan {
            field_number: 4,
            raw_range: 0..10,
            text_range: 0..2,
            level: 0,
            type_fqdn: Some("google.protobuf.DescriptorProto".to_string()),
            is_message: true,
            packed_record_start: None,
            wire_type: WT_LEN,
            natural_annotation: None,
        },
        parent: None,
        first_child: None,
        last_child: None,
        next_sibling: None,
        prev_sibling: None,
        doc_next: None,
        doc_prev: None,
        rendered_as: None,
    };
    let decoded = Decoded {
        lines,
        tree: vec![node],
        root_type: "google.protobuf.FileDescriptorProto".to_string(),
        // Tag `0x22` = field 4 << 3 | WT_LEN(2), length varint `0x08`
        // = 8, then 8 zero payload bytes — a real, `raw_range`-
        // consistent blob, needed since spec 0132's live preview now
        // splices this node's contents at pane-open time.
        blob: vec![0x22, 0x08, 0, 0, 0, 0, 0, 0, 0, 0],
        wrapper_offset: 0,
        style_hints: vec![Vec::new(); 2],
    };
    App::new(
        decoded,
        "test.pb",
        PathBuf::from("test.pb"),
        2,
        DescriptorContext::empty_for_test(),
        ThemeKind::Dark,
    )
}

/// `n` document-order-linked scalar sibling nodes at the root level
/// (spec 0113 D16: root-level nodes are sibling-linked despite having
/// no `parent`), one line of text each — the minimal fixture for
/// exercising main-pane search (spec 0114 §4, extended from the
/// override pane), which walks `doc_next`/`doc_prev`.
fn sibling_leaves_app(texts: &[&str]) -> App {
    let lines: Vec<String> = texts.iter().map(|s| s.to_string()).collect();
    let n = lines.len();
    let tree: Vec<TreeNode> = (0..n)
        .map(|i| TreeNode {
            span: NodeSpan {
                field_number: i as u64 + 1,
                raw_range: (i * 10)..(i * 10 + 5),
                text_range: i..i + 1,
                level: 0,
                type_fqdn: None,
                is_message: false,
                packed_record_start: None,
                wire_type: WT_VARINT,
                natural_annotation: None,
            },
            parent: None,
            first_child: None,
            last_child: None,
            next_sibling: (i + 1 < n).then_some(i + 1),
            prev_sibling: i.checked_sub(1),
            doc_next: (i + 1 < n).then_some(i + 1),
            doc_prev: i.checked_sub(1),
            rendered_as: None,
        })
        .collect();
    let decoded = Decoded {
        lines,
        tree,
        root_type: "google.protobuf.FileDescriptorProto".to_string(),
        blob: Vec::new(),
        wrapper_offset: 0,
        style_hints: Vec::new(),
    };
    App::new(
        decoded,
        "test.pb",
        PathBuf::from("test.pb"),
        2,
        DescriptorContext::empty_for_test(),
        ThemeKind::Dark,
    )
}

/// Spec 0114 §1/§2: `t` opens the override pane for a message-shaped
/// cursor node and moves focus there; a second `t` (from either
/// pane's focus) closes it again.
#[test]
fn t_opens_and_closes_the_override_pane_on_a_message_node() {
    let mut app = message_node_app();
    app.splash = false;
    app.term_width = 120;

    app.handle_key(KeyEvent::new(KeyCode::Char('t'), KeyModifiers::NONE));
    assert_eq!(app.override_target, Some(0));
    assert!(app.override_focus);

    // `t` from override-pane focus closes it too.
    app.handle_key(KeyEvent::new(KeyCode::Char('t'), KeyModifiers::NONE));
    assert_eq!(app.override_target, None);
    assert!(!app.override_focus);
}

/// `q` closes the override pane (not just blurs focus, unlike
/// `Tab`).
#[test]
fn override_pane_q_closes_pane() {
    let mut app = message_node_app();
    app.splash = false;
    app.term_width = 120;

    app.handle_key(KeyEvent::new(KeyCode::Char('t'), KeyModifiers::NONE));
    assert_eq!(app.override_target, Some(0));
    assert!(app.override_focus);

    app.handle_key(KeyEvent::new(KeyCode::Char('q'), KeyModifiers::NONE));
    assert_eq!(app.override_target, None);
    assert!(!app.override_focus);
}

/// Spec 0134 G1: the override selection pane no longer has a `z`/`Z`
/// kind-rotation key — pressing either is a no-op (no message, no
/// panic, pane stays open); `Enter` always creates a `Path`-kind
/// origin.
#[test]
fn override_pane_z_is_a_noop() {
    let mut app = message_node_app();
    app.splash = false;
    app.term_width = 120;

    app.handle_key(KeyEvent::new(KeyCode::Char('t'), KeyModifiers::NONE));
    assert!(app.override_focus);

    let message_before = app.message.clone();
    app.handle_key(KeyEvent::new(KeyCode::Char('z'), KeyModifiers::NONE));
    assert_eq!(app.message, message_before);
    assert!(app.override_focus, "pane must stay open");
    app.handle_key(KeyEvent::new(KeyCode::Char('Z'), KeyModifiers::NONE));
    assert_eq!(app.message, message_before);
    assert!(app.override_focus, "pane must stay open");

    app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
    let entry = app
        .overrides
        .entries()
        .iter()
        .find(|e| e.active)
        .expect("Enter must create an active entry");
    assert!(matches!(entry.origin, OverrideOrigin::Path { .. }));
}

/// Spec 0114 §1.2: `t` also opens the pane on a message/group node
/// whose type wasn't resolved by the schema (`type_fqdn: None`, as
/// produced by the unknown-LEN-field probe cascade) — this is the bug
/// reported during interactive testing of Task #17, where every node
/// looked scalar-shaped to `type_fqdn.is_none()` under a schema
/// declaring no fields for the target type.
#[test]
fn t_opens_the_override_pane_on_an_unresolved_message_node() {
    let lines: Vec<String> = vec!["1 {".to_string(), "}".to_string()];
    let node = TreeNode {
        span: NodeSpan {
            field_number: 1,
            raw_range: 0..2,
            text_range: 0..2,
            level: 0,
            type_fqdn: None,
            is_message: true,
            packed_record_start: None,
            wire_type: WT_LEN,
            natural_annotation: None,
        },
        parent: None,
        first_child: None,
        last_child: None,
        next_sibling: None,
        prev_sibling: None,
        doc_next: None,
        doc_prev: None,
        rendered_as: None,
    };
    let decoded = Decoded {
        lines,
        tree: vec![node],
        root_type: "google.protobuf.Empty".to_string(),
        // Tag `0x0A` = field 1 << 3 | WT_LEN(2), length varint `0x00`
        // = 0, zero payload bytes — a real, `raw_range`-consistent
        // blob, needed since spec 0132's live preview now splices
        // this node's contents at pane-open time.
        blob: vec![0x0A, 0x00],
        wrapper_offset: 0,
        style_hints: vec![Vec::new(); 2],
    };
    let mut app = App::new(
        decoded,
        "test.pb",
        PathBuf::from("test.pb"),
        2,
        DescriptorContext::empty_for_test(),
        ThemeKind::Dark,
    );
    app.splash = false;
    app.term_width = 120;

    app.handle_key(KeyEvent::new(KeyCode::Char('t'), KeyModifiers::NONE));
    assert_eq!(app.override_target, Some(0));
    assert!(app.override_focus);
}

/// Spec 0114 §1: `t` on a scalar/leaf node (no `type_fqdn`) is a
/// no-op with a status-line message, no pane opens.
#[test]
fn t_is_a_no_op_on_a_scalar_node() {
    let lines: Vec<String> = vec!["value: 1".to_string()];
    let node = TreeNode {
        span: NodeSpan {
            field_number: 1,
            raw_range: 0..2,
            text_range: 0..1,
            level: 0,
            type_fqdn: None,
            is_message: false,
            packed_record_start: None,
            wire_type: WT_VARINT,
            natural_annotation: None,
        },
        parent: None,
        first_child: None,
        last_child: None,
        next_sibling: None,
        prev_sibling: None,
        doc_next: None,
        doc_prev: None,
        rendered_as: None,
    };
    let decoded = Decoded {
        lines,
        tree: vec![node],
        root_type: "test.Scalar".to_string(),
        blob: Vec::new(),
        wrapper_offset: 0,
        style_hints: Vec::new(),
    };
    let mut app = App::new(
        decoded,
        "test.pb",
        PathBuf::from("test.pb"),
        2,
        DescriptorContext::empty_for_test(),
        ThemeKind::Dark,
    );
    app.splash = false;
    app.term_width = 120;

    app.handle_key(KeyEvent::new(KeyCode::Char('t'), KeyModifiers::NONE));
    assert_eq!(app.override_target, None);
    assert!(app.message.contains("not a message/group"));
}

/// 2026-07-14 feedback: `t` must not refuse a plain string/bytes
/// field just because it isn't schema-typed as a message — it's
/// still `WT_LEN`-wire and may in practice carry an embedded
/// submessage the schema doesn't know about, so the user should be
/// free to attempt reinterpreting it.
#[test]
fn t_opens_the_override_pane_on_a_length_delimited_scalar_field() {
    let lines: Vec<String> = vec!["value: \"hi\"".to_string()];
    let node = TreeNode {
        span: NodeSpan {
            field_number: 1,
            raw_range: 0..4,
            text_range: 0..1,
            level: 0,
            type_fqdn: None,
            is_message: false,
            packed_record_start: None,
            wire_type: WT_LEN,
            natural_annotation: None,
        },
        parent: None,
        first_child: None,
        last_child: None,
        next_sibling: None,
        prev_sibling: None,
        doc_next: None,
        doc_prev: None,
        rendered_as: None,
    };
    let decoded = Decoded {
        lines,
        tree: vec![node],
        root_type: "test.Scalar".to_string(),
        blob: vec![0x0A, 0x02, b'h', b'i'],
        wrapper_offset: 0,
        // One entry per `lines` (spec 0132's live preview now
        // splices this node at pane-open time, which requires
        // `line_styles` to stay index-aligned with `lines`).
        style_hints: vec![Vec::new(); 1],
    };
    let mut app = App::new(
        decoded,
        "test.pb",
        PathBuf::from("test.pb"),
        2,
        DescriptorContext::empty_for_test(),
        ThemeKind::Dark,
    );
    app.splash = false;
    app.term_width = 120;

    app.handle_key(KeyEvent::new(KeyCode::Char('t'), KeyModifiers::NONE));
    assert_eq!(app.override_target, Some(0));
}

/// Spec 0114 §2: `t` refuses to open the pane below the minimum
/// terminal width.
#[test]
fn t_refuses_below_the_minimum_terminal_width() {
    let mut app = message_node_app();
    app.splash = false;
    app.term_width = MIN_OVERRIDE_WIDTH - 1;

    app.handle_key(KeyEvent::new(KeyCode::Char('t'), KeyModifiers::NONE));
    assert_eq!(app.override_target, None);
    assert!(app.message.contains("too narrow"));
}

/// Spec 0114 §3.2: sort mode defaults to `Inferred` on open, and `a`
/// toggles between the two modes.
#[test]
fn override_sort_defaults_to_inferred_and_a_toggles_it() {
    let mut app = message_node_app();
    app.splash = false;
    app.term_width = 120;
    app.handle_key(KeyEvent::new(KeyCode::Char('t'), KeyModifiers::NONE));
    assert_eq!(app.override_sort, SortMode::Inferred);

    app.handle_key(KeyEvent::new(KeyCode::Char('a'), KeyModifiers::NONE));
    assert_eq!(app.override_sort, SortMode::Lexicographic);

    app.handle_key(KeyEvent::new(KeyCode::Char('a'), KeyModifiers::NONE));
    assert_eq!(app.override_sort, SortMode::Inferred);
}

/// Spec 0133 G3/G4: the main-pane `a` key toggles display of each
/// line's trailing `#@ ...` annotation, purely at render time — the
/// underlying `self.lines`/`self.line_styles` are untouched, so
/// toggling `a` twice restores byte-for-byte identical rendering.
/// Distinct from the override pane's own `a` (candidate sort,
/// exercised above) and the manage pane's own `a` (entry active
/// toggle) — this fixture has neither pane open, so only the
/// main-pane binding is reachable.
#[test]
fn a_toggles_the_main_pane_annotation_display() {
    let line = "  id: 5  #@ int32 = 1".to_string();
    let comment_start = line.find("#@").unwrap();
    let node = TreeNode {
        span: NodeSpan {
            field_number: 1,
            raw_range: 0..2,
            text_range: 0..1,
            level: 0,
            type_fqdn: None,
            is_message: false,
            packed_record_start: None,
            wire_type: WT_VARINT,
            natural_annotation: None,
        },
        parent: None,
        first_child: None,
        last_child: None,
        next_sibling: None,
        prev_sibling: None,
        doc_next: None,
        doc_prev: None,
        rendered_as: None,
    };
    let decoded = Decoded {
        lines: vec![line.clone()],
        tree: vec![node],
        root_type: "test.Msg".to_string(),
        blob: vec![0x08, 0x05],
        wrapper_offset: 0,
        style_hints: vec![vec![(comment_start..line.len(), SyntaxRole::Comment)]],
    };
    let mut app = App::new(
        decoded,
        "test.pb",
        PathBuf::from("test.pb"),
        2,
        DescriptorContext::empty_for_test(),
        ThemeKind::Dark,
    );
    app.splash = false;

    assert!(app.annotations);
    assert_eq!(app.render_line_content(0), line);

    app.handle_key(KeyEvent::new(KeyCode::Char('a'), KeyModifiers::NONE));
    assert!(!app.annotations);
    assert_eq!(app.render_line_content(0), "  id: 5");
    let spanned: String = app
        .render_line_spans(0)
        .iter()
        .map(|s| s.content.as_ref())
        .collect();
    assert_eq!(spanned, "  id: 5");

    app.handle_key(KeyEvent::new(KeyCode::Char('a'), KeyModifiers::NONE));
    assert!(app.annotations);
    assert_eq!(app.render_line_content(0), line);
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

/// Regression test (2026-07-15 feedback): `EnableMouseCapture` turns
/// on any-motion tracking, so real terminals send a bare `Moved`
/// event on essentially every pixel the cursor crosses, with no
/// click at all — a pure `Moved` event must not dismiss the splash
/// screen (nor clear a status message), unlike every other mouse
/// event kind, which legitimately counts as user input (spec 0113
/// D28).
#[test]
fn bare_mouse_move_does_not_dismiss_the_splash_screen() {
    let mut app = message_node_app();
    app.main_area = Rect::new(0, 0, 40, 20);
    assert!(app.splash);

    app.handle_mouse(MouseEvent {
        kind: MouseEventKind::Moved,
        column: 0,
        row: 0,
        modifiers: KeyModifiers::NONE,
    });
    assert!(app.splash, "a bare mouse move must not dismiss the splash");

    app.handle_mouse(MouseEvent {
        kind: MouseEventKind::Down(MouseButton::Left),
        column: 0,
        row: 0,
        modifiers: KeyModifiers::NONE,
    });
    assert!(
        !app.splash,
        "an actual click must still dismiss the splash, same as before"
    );
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

/// Feedback (2026-07-15): mouse wheel and Shift-wheel scroll the `F1`
/// help overlay when the pointer hovers over it, instead of leaking
/// through to the main pane drawn underneath.
#[test]
fn mouse_wheel_scrolls_the_help_overlay_when_hovered() {
    let mut app = message_node_app();
    app.splash = false;
    app.main_area = Rect::new(0, 0, 40, 20);
    app.help_open = true;
    app.help_area = Rect::new(5, 5, 30, 10);

    let cursor_before = app.cursor;
    app.handle_mouse(MouseEvent {
        kind: MouseEventKind::ScrollDown,
        column: 10,
        row: 6,
        modifiers: KeyModifiers::NONE,
    });
    assert_eq!(app.help_scroll, 1);
    assert_eq!(
        app.cursor, cursor_before,
        "must not also scroll the main pane underneath"
    );

    app.handle_mouse(MouseEvent {
        kind: MouseEventKind::ScrollDown,
        column: 10,
        row: 6,
        modifiers: KeyModifiers::SHIFT,
    });
    assert_eq!(app.help_scroll, 2, "Shift-wheel scrolls it too");

    app.handle_mouse(MouseEvent {
        kind: MouseEventKind::ScrollUp,
        column: 10,
        row: 6,
        modifiers: KeyModifiers::NONE,
    });
    assert_eq!(app.help_scroll, 1);

    // Hovering outside the overlay (but still over the main pane)
    // must not touch `help_scroll` — it falls through to the pane
    // underneath instead.
    app.handle_mouse(MouseEvent {
        kind: MouseEventKind::ScrollDown,
        column: 1,
        row: 1,
        modifiers: KeyModifiers::NONE,
    });
    assert_eq!(app.help_scroll, 1, "unhovered help overlay must not react");
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

/// Spec 0126 G2: Shift-Down/Shift-Up alias `J`/`K`'s sibling-skip
/// move, no-op-with-message on a childless-of-siblings node either
/// way.
#[test]
fn shift_down_up_alias_sibling_skip_move() {
    let mut app = message_node_app();
    app.splash = false;

    let start = app.cursor;
    app.handle_key(KeyEvent::new(KeyCode::Char('J'), KeyModifiers::NONE));
    let via_j = app.cursor;

    app.cursor = start;
    app.handle_key(KeyEvent::new(KeyCode::Down, KeyModifiers::SHIFT));
    assert_eq!(app.cursor, via_j, "Shift-Down must match J's result");

    app.cursor = via_j;
    app.handle_key(KeyEvent::new(KeyCode::Char('K'), KeyModifiers::NONE));
    let via_k = app.cursor;

    app.cursor = via_j;
    app.handle_key(KeyEvent::new(KeyCode::Up, KeyModifiers::SHIFT));
    assert_eq!(app.cursor, via_k, "Shift-Up must match K's result");
}

/// `Outer { repeated int32 vals = 1; }`, packed, 3 elements (`5, 6,
/// 7`), document order — spec 0124's shared fixture: gives a
/// `PathField`/`FqdnField` origin (parent path `/`, field `1`) 3
/// matches, and a `Path` origin (e.g. `/2`) exactly 1 match. Uses a
/// packed *scalar* repeated field (one `NodeSpan` per element, spec
/// 0115) rather than a repeated message field, to keep the fixture's
/// tree shape simple (no nested-message decode involved).
fn repeated_scalar_fixture() -> (App, Vec<usize>) {
    use prost::Message as _;
    use prost_types::field_descriptor_proto::{Label, Type};
    use prost_types::{
        DescriptorProto, FieldDescriptorProto, FileDescriptorProto, FileDescriptorSet,
    };

    use crate::decode::{decode, DescriptorContext};

    let outer_desc = DescriptorProto {
        name: Some("Outer".to_string()),
        field: vec![FieldDescriptorProto {
            name: Some("vals".to_string()),
            number: Some(1),
            label: Some(Label::Repeated as i32),
            r#type: Some(Type::Int32 as i32),
            ..Default::default()
        }],
        ..Default::default()
    };
    let file = FileDescriptorProto {
        name: Some("test_repeated_scalar.proto".to_string()),
        package: Some("test".to_string()),
        message_type: vec![outer_desc],
        syntax: Some("proto3".to_string()),
        ..Default::default()
    };
    let fds = FileDescriptorSet { file: vec![file] };

    static COUNTER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let descriptor_path =
        std::env::temp_dir().join(format!("protolens-tui-repeated-scalar-descriptor-{n}.pb"));
    std::fs::write(&descriptor_path, fds.encode_to_vec()).unwrap();
    let mut ctx = DescriptorContext::load(&descriptor_path).unwrap();
    std::fs::remove_file(&descriptor_path).unwrap();

    // vals: field 1 (tag 0x0A, LEN/packed), length 3, payload
    // [0x05, 0x06, 0x07] (three one-byte varint elements).
    let blob = [0x0Au8, 0x03, 0x05, 0x06, 0x07];
    let decoded = decode(&blob, &mut ctx, Some("test.Outer"), 2).unwrap();
    let mut app = App::new(
        decoded,
        "test.pb",
        PathBuf::from("test.pb"),
        2,
        ctx,
        ThemeKind::Dark,
    );
    app.splash = false;
    app.term_width = 120;

    let mut items: Vec<usize> = app
        .tree
        .iter()
        .enumerate()
        .filter(|(_, n)| n.span.packed_record_start.is_some())
        .map(|(i, _)| i)
        .collect();
    items.sort_by_key(|&i| app.positional_path(i));
    assert_eq!(items.len(), 3, "fixture must contain 3 packed elements");
    (app, items)
}

/// Spec 0124 G1: Left/Right in the manage pane circulate the
/// main-pane cursor among the fields the highlighted entry's origin
/// matches, with wraparound, never touching focus; a zero-match
/// origin is a no-op.
#[test]
fn manage_pane_left_right_circulate_affected_fields() {
    let (mut app, items) = repeated_scalar_fixture();
    app.manage_focus = true;
    app.manage_open = true;

    // `PathField` origin: parent `/`, field `1` -> all 3 elements.
    let origin = OverrideOrigin::PathField {
        path: "/".to_string(),
        field: 1,
    };
    app.overrides.activate(origin, None);
    app.manage_highlight = app.overrides.entries().len() - 1;

    app.cursor = items[0];
    app.handle_key(KeyEvent::new(KeyCode::Right, KeyModifiers::NONE));
    assert_eq!(app.cursor, items[1]);
    app.handle_key(KeyEvent::new(KeyCode::Right, KeyModifiers::NONE));
    assert_eq!(app.cursor, items[2]);
    app.handle_key(KeyEvent::new(KeyCode::Right, KeyModifiers::NONE));
    assert_eq!(app.cursor, items[0], "Right must wrap around");
    app.handle_key(KeyEvent::new(KeyCode::Left, KeyModifiers::NONE));
    assert_eq!(app.cursor, items[2], "Left must wrap around");
    assert!(app.manage_focus, "focus must not change");

    // Zero-match origin: no-op.
    app.overrides.activate(
        OverrideOrigin::PathField {
            path: "/".to_string(),
            field: 99,
        },
        None,
    );
    app.manage_highlight = app.overrides.entries().len() - 1;
    let before = app.cursor;
    app.handle_key(KeyEvent::new(KeyCode::Right, KeyModifiers::NONE));
    assert_eq!(app.cursor, before, "zero matches must be a no-op");
}

/// Spec 0134 G2: a single derivable candidate is used even when the
/// main-pane cursor isn't on the node that produced it — rotating
/// onto a colliding origin deactivates the other entry (existing
/// `activate`-style invariant, reused unchanged).
#[test]
fn manage_pane_z_single_candidate_resolves_without_cursor_match() {
    let (mut app, items) = repeated_scalar_fixture();
    app.manage_focus = true;
    app.manage_open = true;

    let path_origin = OverrideOrigin::Path {
        path: app.positional_path(items[0]),
    };
    app.overrides.activate(path_origin.clone(), None);
    app.manage_highlight = app.overrides.entries().len() - 1;

    // Also seed a colliding PathField entry (parent `/`, field `1`),
    // active, so the rotation-collision path is exercised.
    let collide_origin = OverrideOrigin::PathField {
        path: "/".to_string(),
        field: 1,
    };
    app.overrides.activate(collide_origin.clone(), None);
    let collide_idx = app.overrides.entries().len() - 1;
    assert!(app.overrides.entries()[collide_idx].active);

    // `path_origin` only ever matches `items[0]` itself, so there is
    // exactly one candidate under `PathField` regardless of where
    // the cursor sits — put it elsewhere to confirm the single
    // candidate is used anyway.
    app.cursor = items[1];
    let entry_idx = app
        .overrides
        .entries()
        .iter()
        .position(|e| e.origin == path_origin)
        .expect("original Path entry must still exist");
    app.manage_highlight = entry_idx;
    app.handle_key(KeyEvent::new(KeyCode::Char('z'), KeyModifiers::NONE));

    // `handle_key` leaves `manage_highlight` on the rotated entry
    // (spec 0124 G2) — look it up by index, not by origin: two
    // entries now share `collide_origin` (the rotated one and the
    // pre-existing one it collided with), so origin alone is
    // ambiguous.
    let rotated = &app.overrides.entries()[app.manage_highlight];
    assert_eq!(rotated.origin, collide_origin);
    assert!(rotated.active, "rotated entry must stay active");
    assert!(!rotated.auto, "rotation always resets auto to false");
    let other = app
        .overrides
        .entries()
        .iter()
        .filter(|e| e.origin == collide_origin)
        .count();
    assert_eq!(other, 2, "duplicates now coexist under the same origin");
    assert_eq!(
        app.overrides
            .entries()
            .iter()
            .filter(|e| e.origin == collide_origin && e.active)
            .count(),
        1,
        "only one entry per origin stays active"
    );
    assert!(app.manage_pending_kind.is_none());
}

/// Spec 0134 G2/G3: 2+ distinct candidates with the cursor not on
/// any of them prompts instead of resolving; a same-key retry with
/// the cursor unchanged advances to the next kind in the barrel
/// instead of repeating the identical ambiguous outcome.
#[test]
fn manage_pane_z_ambiguous_candidates_advance_on_repeated_press() {
    let (mut app, items) = repeated_scalar_fixture();
    app.manage_focus = true;
    app.manage_open = true;

    let fqdn_origin = app
        .origin_for_kind(items[0], OverrideKind::FqdnField)
        .expect("field's parent type is known");
    app.overrides.activate(fqdn_origin.clone(), None);
    app.manage_highlight = app.overrides.entries().len() - 1;

    let outside = app
        .tree
        .iter()
        .position(|n| n.parent.is_none())
        .expect("root node must exist");
    app.cursor = outside;

    // FqdnField -> Path: all 3 packed elements derive distinct Path
    // origins, and the cursor isn't on any of them -> ambiguous.
    app.handle_key(KeyEvent::new(KeyCode::Char('z'), KeyModifiers::NONE));
    assert_eq!(app.message, "z: pick an override target (<-/->)");
    assert_eq!(
        app.overrides.entries()[app.manage_highlight].origin,
        fqdn_origin,
        "entry unchanged while ambiguous"
    );
    assert!(app.manage_pending_kind.is_some());

    // Same key, cursor still unchanged -> advances Path -> PathField.
    // All 3 elements share the same parent/field, so PathField
    // dedups to a single candidate and resolves immediately even
    // though the cursor still isn't on any of them.
    app.handle_key(KeyEvent::new(KeyCode::Char('z'), KeyModifiers::NONE));
    let expected = OverrideOrigin::PathField {
        path: "/".to_string(),
        field: 1,
    };
    assert_eq!(
        app.overrides.entries()[app.manage_highlight].origin,
        expected
    );
    assert!(app.manage_pending_kind.is_none());
}

/// Spec 0134 G2/G3: moving the main-pane cursor between two `z`
/// attempts retries the same stuck kind (instead of advancing past
/// it) and resolves via the cursor-match branch.
#[test]
fn manage_pane_z_ambiguous_then_resolved_via_cursor_move() {
    let (mut app, items) = repeated_scalar_fixture();
    app.manage_focus = true;
    app.manage_open = true;

    let fqdn_origin = app
        .origin_for_kind(items[0], OverrideKind::FqdnField)
        .expect("field's parent type is known");
    app.overrides.activate(fqdn_origin.clone(), None);
    app.manage_highlight = app.overrides.entries().len() - 1;

    let outside = app
        .tree
        .iter()
        .position(|n| n.parent.is_none())
        .expect("root node must exist");
    app.set_cursor(outside);

    app.handle_key(KeyEvent::new(KeyCode::Char('z'), KeyModifiers::NONE));
    assert_eq!(app.message, "z: pick an override target (<-/->)");

    // Move the cursor onto one of the affected nodes, then retry —
    // must retry the same `Path` attempt (not advance to
    // `PathField`) and resolve via the cursor match.
    app.set_cursor(items[1]);
    app.handle_key(KeyEvent::new(KeyCode::Char('z'), KeyModifiers::NONE));
    let expected = OverrideOrigin::Path {
        path: app.positional_path(items[1]),
    };
    assert_eq!(
        app.overrides.entries()[app.manage_highlight].origin,
        expected
    );
    assert!(app.manage_pending_kind.is_none());
}

/// 2026-07-16 feedback: a real movement-tracking signal
/// (`cursor_moves`), not just comparing the cursor's numeric
/// position — a Down-then-Up round trip that lands back on the
/// exact same node still counts as movement, so a same-key `z`
/// retry afterward retries the same stuck kind instead of wrongly
/// treating it as "cursor unchanged" and advancing past it.
#[test]
fn manage_pane_z_down_then_up_round_trip_counts_as_movement() {
    let (mut app, items) = repeated_scalar_fixture();
    app.manage_focus = true;
    app.manage_open = true;

    let fqdn_origin = app
        .origin_for_kind(items[0], OverrideKind::FqdnField)
        .expect("field's parent type is known");
    app.overrides.activate(fqdn_origin.clone(), None);
    app.manage_highlight = app.overrides.entries().len() - 1;

    let outside = app
        .tree
        .iter()
        .position(|n| n.parent.is_none())
        .expect("root node must exist");
    app.set_cursor(outside);

    app.handle_key(KeyEvent::new(KeyCode::Char('z'), KeyModifiers::NONE));
    assert_eq!(app.message, "z: pick an override target (<-/->)");
    assert!(app.manage_pending_kind.is_some());

    // Down then Up returns the cursor to the exact same node — but
    // it is still a real move, unlike a plain numeric-equality
    // check on `self.cursor` alone would conclude.
    app.move_down();
    app.move_up();
    assert_eq!(app.cursor, outside, "back at the same position");

    app.handle_key(KeyEvent::new(KeyCode::Char('z'), KeyModifiers::NONE));
    assert_eq!(
        app.message, "z: pick an override target (<-/->)",
        "must retry the same kind, not advance"
    );
    assert_eq!(
        app.overrides.entries()[app.manage_highlight].origin,
        fqdn_origin,
        "entry unchanged - still ambiguous on retry"
    );
}

/// Spec 0134 G2: when no kind (other than the entry's own) applies
/// to any affected node — e.g. the wrapper root, which has no
/// parent so `PathField`/`FqdnField` both error — `z` writes "no
/// <kind> override target", leaves the entry unchanged, and clears
/// the pending state; repeating `z` reproduces the identical
/// outcome.
#[test]
fn manage_pane_z_no_target_aborts_when_no_kind_applies() {
    let (mut app, _items) = repeated_scalar_fixture();
    app.manage_focus = true;
    app.manage_open = true;

    let root_idx = app
        .tree
        .iter()
        .position(|n| n.parent.is_none())
        .expect("root node must exist");
    let root_origin = OverrideOrigin::Path {
        path: app.positional_path(root_idx),
    };
    app.overrides.activate(root_origin.clone(), None);
    app.manage_highlight = app.overrides.entries().len() - 1;
    app.cursor = root_idx;

    app.handle_key(KeyEvent::new(KeyCode::Char('z'), KeyModifiers::NONE));
    assert_eq!(app.message, "z: no path-field override target");
    assert_eq!(
        app.overrides.entries()[app.manage_highlight].origin,
        root_origin
    );
    assert!(app.manage_pending_kind.is_none());

    app.handle_key(KeyEvent::new(KeyCode::Char('z'), KeyModifiers::NONE));
    assert_eq!(app.message, "z: no path-field override target");
}

/// Rotating an *active* entry's origin kind runs `render_overrides`,
/// which can auto-seed a brand-new entry elsewhere in the tree (Any/
/// MessageSet auto-expansion) — re-sorting the whole collection out
/// from under the index `rotate_origin` already returned.
/// `manage_highlight` must still land on the just-rotated entry, not
/// whichever row the reshuffle happens to leave at that stale index
/// (feedback, 2026-07-16).
#[test]
fn manage_pane_z_rotation_survives_a_concurrent_auto_seed_reshuffle() {
    use prost::Message as _;
    use prost_types::field_descriptor_proto::{Label, Type};
    use prost_types::{
        DescriptorProto, FieldDescriptorProto, FileDescriptorProto, FileDescriptorSet,
    };

    use crate::decode::{decode, DescriptorContext};

    let any_msg = DescriptorProto {
        name: Some("Any".to_string()),
        field: vec![
            FieldDescriptorProto {
                name: Some("type_url".to_string()),
                number: Some(1),
                label: Some(Label::Optional as i32),
                r#type: Some(Type::String as i32),
                ..Default::default()
            },
            FieldDescriptorProto {
                name: Some("value".to_string()),
                number: Some(2),
                label: Some(Label::Optional as i32),
                r#type: Some(Type::Bytes as i32),
                ..Default::default()
            },
        ],
        ..Default::default()
    };
    let any_file = FileDescriptorProto {
        name: Some("google/protobuf/any.proto".to_string()),
        syntax: Some("proto3".to_string()),
        package: Some("google.protobuf".to_string()),
        message_type: vec![any_msg],
        ..Default::default()
    };
    let payload_msg = DescriptorProto {
        name: Some("Payload".to_string()),
        field: vec![FieldDescriptorProto {
            name: Some("label".to_string()),
            number: Some(1),
            label: Some(Label::Optional as i32),
            r#type: Some(Type::String as i32),
            ..Default::default()
        }],
        ..Default::default()
    };
    let container_msg = DescriptorProto {
        name: Some("Container".to_string()),
        field: vec![
            FieldDescriptorProto {
                name: Some("val".to_string()),
                number: Some(1),
                label: Some(Label::Optional as i32),
                r#type: Some(Type::Int32 as i32),
                ..Default::default()
            },
            FieldDescriptorProto {
                name: Some("payload".to_string()),
                number: Some(2),
                label: Some(Label::Optional as i32),
                r#type: Some(Type::Message as i32),
                type_name: Some(".google.protobuf.Any".to_string()),
                ..Default::default()
            },
        ],
        ..Default::default()
    };
    let acme_file = FileDescriptorProto {
        name: Some("acme.proto".to_string()),
        syntax: Some("proto2".to_string()),
        package: Some("acme".to_string()),
        dependency: vec!["google/protobuf/any.proto".to_string()],
        message_type: vec![payload_msg, container_msg],
        ..Default::default()
    };
    let fds = FileDescriptorSet {
        file: vec![any_file, acme_file],
    };

    static COUNTER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let descriptor_path = std::env::temp_dir().join(format!(
        "protolens-tui-manage-z-reshuffle-descriptor-{n}.pb"
    ));
    std::fs::write(&descriptor_path, fds.encode_to_vec()).unwrap();
    let mut ctx = DescriptorContext::load(&descriptor_path).unwrap();
    std::fs::remove_file(&descriptor_path).unwrap();

    // Container {
    //   val: 42,
    //   payload: Any { type_url: "type.googleapis.com/acme.Payload",
    //                   value: Payload { label: "hi" } },
    // }
    let label = b"hi";
    let mut payload_bytes = vec![0x0au8, label.len() as u8];
    payload_bytes.extend_from_slice(label);
    let type_url = b"type.googleapis.com/acme.Payload";
    let mut any_bytes = vec![0x0au8, type_url.len() as u8];
    any_bytes.extend_from_slice(type_url);
    any_bytes.push(0x12);
    any_bytes.push(payload_bytes.len() as u8);
    any_bytes.extend_from_slice(&payload_bytes);
    let mut blob = vec![0x08u8, 0x2A]; // field 1, VARINT, value 42
    blob.push(0x12); // field 2, LEN
    blob.push(any_bytes.len() as u8);
    blob.extend_from_slice(&any_bytes);

    let decoded = decode(&blob, &mut ctx, Some("acme.Container"), 2).unwrap();
    let mut app = App::new(
        decoded,
        "test.pb",
        PathBuf::from("test.pb"),
        2,
        ctx,
        ThemeKind::Dark,
    );
    app.splash = false;
    app.term_width = 120;

    let val_idx = app
        .tree
        .iter()
        .position(|n| n.span.field_number == 1)
        .expect("must find the val node");

    // `App::new` already ran one `render_overrides` pass, which
    // auto-seeded the Any field's `value` — undo that seeding so it
    // starts out unexpanded again (no entry for it at all), letting
    // the `z`-triggered pass below re-seed it as a *fresh* entry and
    // reshuffle the collection out from under `manage_highlight`.
    let any_entry_idx = app
        .overrides
        .entries()
        .iter()
        .position(|e| e.auto)
        .expect("Any field must have been auto-seeded by App::new");
    app.overrides.remove(any_entry_idx);

    // Seed `val` as an explicit, active `Path` override — mirroring
    // what the override pane would do.
    let val_origin = override_pane::OverrideOrigin::Path {
        path: app.positional_path(val_idx),
    };
    app.overrides.activate(val_origin.clone(), None);
    app.manage_highlight = app
        .overrides
        .entries()
        .iter()
        .position(|e| e.origin == val_origin)
        .unwrap();
    app.manage_focus = true;
    app.manage_open = true;
    app.cursor = val_idx;
    assert_eq!(
        app.overrides.entries().len(),
        2,
        "root + val, Any field's auto-expansion not seeded yet: {:#?}",
        app.overrides.entries()
    );

    // Rotate: Path -> PathField. Since the rotated entry is active,
    // `handle_key` also runs `render_overrides`, which (for the
    // first time) walks into the still-unexpanded Any field and
    // auto-seeds a brand-new entry for it, reshuffling the whole
    // sorted collection.
    app.handle_key(KeyEvent::new(KeyCode::Char('z'), KeyModifiers::NONE));

    assert_eq!(
        app.overrides.entries().len(),
        3,
        "the Any field's auto-expansion must have been re-seeded by \
         the same render_overrides pass: {:#?}",
        app.overrides.entries()
    );
    let expected_origin = override_pane::OverrideOrigin::PathField {
        path: "/".to_string(),
        field: 1,
    };
    let highlighted = &app.overrides.entries()[app.manage_highlight];
    assert_eq!(
        highlighted.origin,
        expected_origin,
        "manage_highlight must still point at the just-rotated entry, \
         not the newly auto-seeded Any entry: {:#?}",
        app.overrides.entries()
    );
    assert!(highlighted.active, "rotated entry must stay active");
}

/// Spec 0124 G3: `d` duplicates the highlighted entry as a new,
/// always-inactive copy; the original and the copy coexist.
#[test]
fn manage_pane_d_duplicates_highlighted_entry_as_inactive() {
    let (mut app, items) = repeated_scalar_fixture();
    app.manage_focus = true;
    app.manage_open = true;

    let origin = OverrideOrigin::Path {
        path: app.positional_path(items[0]),
    };
    app.overrides.activate(origin.clone(), None);
    let orig_idx = app.overrides.entries().len() - 1;
    app.manage_highlight = orig_idx;

    let before_len = app.overrides.entries().len();
    app.handle_key(KeyEvent::new(KeyCode::Char('d'), KeyModifiers::NONE));
    assert_eq!(app.overrides.entries().len(), before_len + 1);
    let new_idx = app.manage_highlight;
    assert!(!app.overrides.entries()[new_idx].active, "copy is inactive");
    assert_eq!(app.overrides.entries()[new_idx].origin, origin);

    // Activating the copy deactivates the original (existing
    // invariant, not new code).
    app.overrides.toggle_active(new_idx);
    let active_count = app
        .overrides
        .entries()
        .iter()
        .filter(|e| e.origin == origin && e.active)
        .count();
    assert_eq!(active_count, 1, "still at most one active entry per origin");
    assert!(app.overrides.entries()[new_idx].active);
}

/// `Enter` in the management pane closes it (returning focus to the
/// main pane), same as `Esc`/`o`.
#[test]
fn manage_pane_enter_closes_pane() {
    let (mut app, _items) = repeated_scalar_fixture();
    app.manage_focus = true;
    app.manage_open = true;

    app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
    assert!(!app.manage_open);
    assert!(!app.manage_focus);
}

/// `q` closes the management pane (not just blurs focus, unlike
/// `Tab`).
#[test]
fn manage_pane_q_closes_pane() {
    let (mut app, _items) = repeated_scalar_fixture();
    app.manage_focus = true;
    app.manage_open = true;

    app.handle_key(KeyEvent::new(KeyCode::Char('q'), KeyModifiers::NONE));
    assert!(!app.manage_open);
    assert!(!app.manage_focus);
}

/// Spec 0130 §G1: manage-pane entry rows render `auto == true`
/// entries in `manage_entry_style(true, ..)`'s color and
/// `auto == false` entries in `manage_entry_style(false, ..)`'s
/// distinct color (no `REVERSED` on either, since neither is
/// highlighted here).
#[test]
fn manage_pane_entries_style_auto_vs_manual_distinctly() {
    let (mut app, items) = repeated_scalar_fixture();
    app.manage_focus = true;
    app.manage_open = true;

    app.overrides.activate(
        OverrideOrigin::Path {
            path: app.positional_path(items[0]),
        },
        None,
    );
    let manual_idx = app.overrides.entries().len() - 1;
    app.overrides.activate_auto(
        OverrideOrigin::Path {
            path: app.positional_path(items[1]),
        },
        Some("auto.Type".to_string()),
    );
    let auto_idx = app
        .overrides
        .entries()
        .iter()
        .position(|e| e.auto)
        .expect("auto entry must exist");
    assert_ne!(manual_idx, auto_idx);
    // Neither entry is highlighted, so `REVERSED` doesn't interfere
    // with the bold/plain assertion below.
    app.manage_highlight = app.overrides.entries().len();

    let area = Rect::new(0, 0, 120, 40);
    let mut terminal = Terminal::new(TestBackend::new(area.width, area.height)).expect("terminal");
    terminal
        .draw(|frame| app.render_manage_pane(frame, area))
        .expect("render must not panic");
    let buffer = terminal.backend().buffer().clone();
    let inner = Block::bordered().inner(area);

    let rows = app.manage_display_rows();
    let row_fg = |entry_idx: usize| {
        let row = rows
            .iter()
            .position(|r| matches!(r, ManageRow::Entry(i) if *i == entry_idx))
            .expect("row must exist");
        let y = inner.y + row as u16;
        (inner.x..inner.x + inner.width)
            .map(|x| &buffer[(x, y)])
            .find(|c| !c.symbol().trim().is_empty())
            .expect("row must render some text")
            .fg
    };
    assert_eq!(
        Some(row_fg(auto_idx)),
        theme::manage_entry_style(true, app.theme).fg,
        "auto entry row must use the auto color"
    );
    assert_eq!(
        Some(row_fg(manual_idx)),
        theme::manage_entry_style(false, app.theme).fg,
        "manual entry row must use the manual color"
    );
    assert_ne!(
        row_fg(auto_idx),
        row_fg(manual_idx),
        "auto and manual entries must be visually distinct"
    );
}

/// Spec 0125 §G2: `Delete` on an `auto` entry still "in scope"
/// deactivates it instead of removing it, and shows the explanatory
/// message; `Delete` on an `auto` entry that has gone out of scope
/// (its ancestor's own override changed) actually removes it, same
/// as a manual entry.
#[test]
fn manage_pane_delete_deactivates_in_scope_auto_but_removes_out_of_scope_auto() {
    let mut app = message_set_fixture();
    app.manage_focus = true;
    app.manage_open = true;

    let item_idx = app
        .tree
        .iter()
        .position(|n| n.span.type_fqdn.as_deref() == Some(decode::MESSAGE_SET_ITEM_FQDN))
        .expect("Item group must be spliced to the synthetic MessageSetItem type");
    let item_path = app.positional_path(item_idx);
    let item_entry_idx = app
        .overrides
        .entries()
        .iter()
        .position(|e| matches!(&e.origin, OverrideOrigin::Path { path } if *path == item_path))
        .expect("tier-1 entry must exist");
    assert!(app.overrides.entries()[item_entry_idx].auto);
    assert!(app.overrides.entries()[item_entry_idx].active);

    let message_idx = app
        .tree
        .iter()
        .position(|n| n.span.type_fqdn.as_deref() == Some("ms_test.ExtPayload"))
        .expect("message field must resolve to ExtPayload");
    let message_path = app.positional_path(message_idx);
    let message_entry_idx = app
        .overrides
        .entries()
        .iter()
        .position(|e| matches!(&e.origin, OverrideOrigin::Path { path } if *path == message_path))
        .expect("tier-2 entry must exist");
    assert!(app.overrides.entries()[message_entry_idx].auto);

    // In-scope: `Delete` on the tier-1 entry deactivates, does not
    // remove.
    let before_len = app.overrides.entries().len();
    app.manage_highlight = item_entry_idx;
    app.handle_key(KeyEvent::new(KeyCode::Delete, KeyModifiers::NONE));
    assert_eq!(
        app.overrides.entries().len(),
        before_len,
        "in-scope auto entry must not be removed"
    );
    assert!(
        !app.overrides.entries()[item_entry_idx].active,
        "in-scope auto entry must be deactivated"
    );
    assert_eq!(
        app.message,
        "auto-derived override deactivated (still in scope — delete would \
         just recreate it; use 'a' or wait for it to go out of scope)"
    );

    // Deactivating tier-1 makes tier-2 no longer "in scope" (spec
    // 0120's demotion): `Delete` on the tier-2 entry now actually
    // removes it, same as a manual entry.
    assert!(!app.auto_entry_in_scope(&app.overrides.entries()[message_entry_idx].clone()));
    let before_len = app.overrides.entries().len();
    app.manage_highlight = message_entry_idx;
    app.handle_key(KeyEvent::new(KeyCode::Delete, KeyModifiers::NONE));
    assert_eq!(
        app.overrides.entries().len(),
        before_len - 1,
        "out-of-scope auto entry must be removed like a manual entry"
    );
}

/// Spec 0125 §G2: `Delete` on a manual (`auto == false`) entry is
/// unchanged — removes it outright, no special message.
#[test]
fn manage_pane_delete_removes_manual_entry_unchanged() {
    let (mut app, items) = repeated_scalar_fixture();
    app.manage_focus = true;
    app.manage_open = true;

    app.overrides.activate(
        OverrideOrigin::Path {
            path: app.positional_path(items[0]),
        },
        None,
    );
    let idx = app.overrides.entries().len() - 1;
    assert!(!app.overrides.entries()[idx].auto);
    app.manage_highlight = idx;

    let before_len = app.overrides.entries().len();
    app.handle_key(KeyEvent::new(KeyCode::Delete, KeyModifiers::NONE));
    assert_eq!(app.overrides.entries().len(), before_len - 1);
    assert!(
        !app.message.contains("auto-derived"),
        "manual delete must not show the auto-entry message: {}",
        app.message
    );
}

/// Spec 0125 §G3: `:save-overrides` then `:restore-overrides`
/// round-trips an `auto: true` entry's `auto` flag exactly, and a
/// pre-existing YAML file with no `auto` key still loads fine
/// (defaults to `false`).
#[test]
fn yaml_round_trips_auto_flag_and_defaults_false_when_absent() {
    let mut collection = override_pane::OverrideCollection::new();
    collection.activate_auto(
        OverrideOrigin::Path {
            path: "/".to_string(),
        },
        Some("pkg.Type".to_string()),
    );
    let yaml = collection.to_yaml("blobsha".to_string(), "descsha".to_string());
    assert!(
        yaml.contains("auto: true"),
        "auto: true must round-trip: {yaml}"
    );
    let (restored, _target) =
        override_pane::OverrideCollection::from_yaml(&yaml).expect("must parse");
    assert!(
        restored.entries()[0].auto,
        "restored entry must keep auto: true"
    );

    // Pre-existing file with no `auto` key at all.
    let legacy_yaml = "version: 1\n\
         target:\n  blob_sha256: blobsha\n  descriptor_set_sha256: descsha\n\
         overrides:\n  - path: /\n    type: pkg.Type\n    active: true\n";
    let (legacy, _target) =
        override_pane::OverrideCollection::from_yaml(legacy_yaml).expect("must parse legacy");
    assert!(
        !legacy.entries()[0].auto,
        "legacy file with no auto key must default to auto: false"
    );
}

/// Spec 0114 §3.2: `j`/`k` move the highlight, clamped to
/// `0..=candidates.len()` — row `0` is the pinned raw entry.
#[test]
fn override_highlight_movement_clamps_at_both_ends() {
    let mut app = message_node_app();
    app.splash = false;
    app.term_width = 120;
    app.handle_key(KeyEvent::new(KeyCode::Char('t'), KeyModifiers::NONE));

    app.override_candidates = vec![("a.B".to_string(), None), ("a.C".to_string(), None)];
    app.override_highlight = 0;

    app.handle_key(KeyEvent::new(KeyCode::Char('k'), KeyModifiers::NONE));
    assert_eq!(app.override_highlight, 0);

    app.handle_key(KeyEvent::new(KeyCode::Char('j'), KeyModifiers::NONE));
    assert_eq!(app.override_highlight, 1);
    app.handle_key(KeyEvent::new(KeyCode::Char('j'), KeyModifiers::NONE));
    assert_eq!(app.override_highlight, 2);
    app.handle_key(KeyEvent::new(KeyCode::Char('j'), KeyModifiers::NONE));
    assert_eq!(app.override_highlight, 2);
}

/// Spec 0114 §4: `/` searches forward, `?` searches backward, `n`
/// repeats the last search — wrapping around — and the pinned raw
/// entry (row `0`) is never matched.
#[test]
fn override_search_forward_backward_and_repeat_with_n() {
    let mut app = message_node_app();
    app.splash = false;
    app.term_width = 120;
    app.handle_key(KeyEvent::new(KeyCode::Char('t'), KeyModifiers::NONE));

    app.override_candidates = vec![
        ("pkg.Alpha".to_string(), None),
        ("pkg.Beta".to_string(), None),
        ("pkg.Gamma".to_string(), None),
        ("pkg.Beta2".to_string(), None),
    ];
    app.override_highlight = 0;

    app.handle_key(KeyEvent::new(KeyCode::Char('/'), KeyModifiers::NONE));
    for c in "beta".chars() {
        app.handle_key(KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE));
    }
    app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
    assert!(app.command_buffer.is_none());
    assert_eq!(app.override_highlight, 2); // pkg.Beta

    // `n` repeats forward, wrapping to the next match.
    app.handle_key(KeyEvent::new(KeyCode::Char('n'), KeyModifiers::NONE));
    assert_eq!(app.override_highlight, 4); // pkg.Beta2

    // Wraps back around to the first match.
    app.handle_key(KeyEvent::new(KeyCode::Char('n'), KeyModifiers::NONE));
    assert_eq!(app.override_highlight, 2); // pkg.Beta

    // `?` searches backward from the current highlight (pkg.Beta,
    // row 2) — skips itself, wraps to pkg.Beta2 (row 4).
    app.handle_key(KeyEvent::new(KeyCode::Char('?'), KeyModifiers::NONE));
    for c in "beta".chars() {
        app.handle_key(KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE));
    }
    app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
    assert_eq!(app.override_highlight, 4); // pkg.Beta2

    // No match leaves the highlight unchanged and sets a message.
    app.handle_key(KeyEvent::new(KeyCode::Char('/'), KeyModifiers::NONE));
    for c in "nope".chars() {
        app.handle_key(KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE));
    }
    app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
    assert_eq!(app.override_highlight, 4);
    assert!(app.message.contains("not found"));
}

/// Spec 0114 §4 (vim convention): confirming `/` or `?` with an empty
/// pattern re-uses the last active search pattern, searching in
/// whichever direction the key that opened this prompt requested —
/// which may differ from the direction the pattern was originally
/// searched in.
#[test]
fn override_search_with_no_argument_reuses_the_active_pattern() {
    let mut app = message_node_app();
    app.splash = false;
    app.term_width = 120;
    app.handle_key(KeyEvent::new(KeyCode::Char('t'), KeyModifiers::NONE));

    app.override_candidates = vec![
        ("pkg.Alpha".to_string(), None),
        ("pkg.Beta".to_string(), None),
        ("pkg.Gamma".to_string(), None),
        ("pkg.Beta2".to_string(), None),
    ];
    app.override_highlight = 0;

    app.handle_key(KeyEvent::new(KeyCode::Char('/'), KeyModifiers::NONE));
    for c in "beta".chars() {
        app.handle_key(KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE));
    }
    app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
    assert_eq!(app.override_highlight, 2); // pkg.Beta

    // `/<Enter>` with no typed pattern re-uses "beta", searching
    // forward from the current highlight — wraps to pkg.Beta2.
    app.handle_key(KeyEvent::new(KeyCode::Char('/'), KeyModifiers::NONE));
    app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
    assert_eq!(app.override_highlight, 4); // pkg.Beta2

    // `?<Enter>` with no typed pattern re-uses "beta" too, but now
    // searches backward from the current highlight.
    app.handle_key(KeyEvent::new(KeyCode::Char('?'), KeyModifiers::NONE));
    app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
    assert_eq!(app.override_highlight, 2); // pkg.Beta
}

/// Spec 0114 §4: `Esc` cancels an in-progress search without moving the
/// highlight, and `Backspace` on an empty buffer also cancels it.
#[test]
fn override_search_esc_and_empty_backspace_cancel() {
    let mut app = message_node_app();
    app.splash = false;
    app.term_width = 120;
    app.handle_key(KeyEvent::new(KeyCode::Char('t'), KeyModifiers::NONE));
    app.override_candidates = vec![("pkg.Alpha".to_string(), None)];
    app.override_highlight = 0;

    app.handle_key(KeyEvent::new(KeyCode::Char('/'), KeyModifiers::NONE));
    app.handle_key(KeyEvent::new(KeyCode::Char('x'), KeyModifiers::NONE));
    app.handle_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
    assert!(app.command_buffer.is_none());
    assert_eq!(app.override_highlight, 0);

    app.handle_key(KeyEvent::new(KeyCode::Char('/'), KeyModifiers::NONE));
    assert!(app.command_buffer.is_some());
    app.handle_key(KeyEvent::new(KeyCode::Backspace, KeyModifiers::NONE));
    assert!(app.command_buffer.is_none());
}

/// Spec 0117 §3, extended: `/`/`?` in the management pane share the
/// same `command_buffer` as main-pane/override-pane search
/// (spec-0133-adjacent rework), but `Enter` dispatches to
/// `jump_to_manage_match`, moving `manage_highlight` rather than the
/// main-pane cursor or the override pane's own highlight.
#[test]
fn manage_pane_search_forward_and_backward() {
    let (mut app, items) = repeated_scalar_fixture();
    app.manage_focus = true;
    app.manage_open = true;

    for (item, ty) in items.iter().zip(["pkg.Alpha", "pkg.Beta", "pkg.Gamma"]) {
        let origin = OverrideOrigin::Path {
            path: app.positional_path(*item),
        };
        app.overrides.activate(origin, Some(ty.to_string()));
    }
    app.manage_highlight = 0;

    app.handle_key(KeyEvent::new(KeyCode::Char('/'), KeyModifiers::NONE));
    assert!(app.command_buffer.is_some());
    for c in "gamma".chars() {
        app.handle_key(KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE));
    }
    app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
    assert!(app.command_buffer.is_none());
    assert_eq!(
        app.overrides.entries()[app.manage_highlight]
            .r#type
            .as_deref(),
        Some("pkg.Gamma")
    );

    app.handle_key(KeyEvent::new(KeyCode::Char('?'), KeyModifiers::NONE));
    for c in "alpha".chars() {
        app.handle_key(KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE));
    }
    app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
    assert_eq!(
        app.overrides.entries()[app.manage_highlight]
            .r#type
            .as_deref(),
        Some("pkg.Alpha")
    );
}

/// Spec 0114 §4, extended to the main pane: `/`/`?` open a search
/// prompt on the shared command-line row, `n` repeats the last search
/// in the same direction, and matches wrap around the document.
#[test]
fn main_pane_search_forward_backward_and_repeat_with_n() {
    let mut app = sibling_leaves_app(&["alpha: 1", "beta: 2", "gamma: 3", "beta2: 4"]);
    app.splash = false;
    app.term_width = 120;
    assert_eq!(app.cursor, 0); // alpha

    app.handle_key(KeyEvent::new(KeyCode::Char('/'), KeyModifiers::NONE));
    assert_eq!(app.command_buffer.as_deref(), Some(""));
    for c in "beta".chars() {
        app.handle_key(KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE));
    }
    app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
    assert!(app.command_buffer.is_none());
    assert_eq!(app.cursor, 1); // beta

    // `n` repeats forward, wrapping to the next match.
    app.handle_key(KeyEvent::new(KeyCode::Char('n'), KeyModifiers::NONE));
    assert_eq!(app.cursor, 3); // beta2

    // Wraps back around to the first match.
    app.handle_key(KeyEvent::new(KeyCode::Char('n'), KeyModifiers::NONE));
    assert_eq!(app.cursor, 1); // beta

    // `?` searches backward from the cursor (beta) — skips itself,
    // wraps to beta2.
    app.handle_key(KeyEvent::new(KeyCode::Char('?'), KeyModifiers::NONE));
    for c in "beta".chars() {
        app.handle_key(KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE));
    }
    app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
    assert_eq!(app.cursor, 3); // beta2

    // No match leaves the cursor unchanged and sets a message.
    app.handle_key(KeyEvent::new(KeyCode::Char('/'), KeyModifiers::NONE));
    for c in "nope".chars() {
        app.handle_key(KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE));
    }
    app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
    assert_eq!(app.cursor, 3);
    assert!(app.message.contains("not found"));
}

/// Spec 0114 §4 (vim convention), extended to the main pane:
/// confirming `/` or `?` with an empty pattern re-uses the last
/// active search pattern, searching in the newly chosen direction.
#[test]
fn main_pane_search_with_no_argument_reuses_the_active_pattern() {
    let mut app = sibling_leaves_app(&["alpha: 1", "beta: 2", "gamma: 3", "beta2: 4"]);
    app.splash = false;
    app.term_width = 120;

    app.handle_key(KeyEvent::new(KeyCode::Char('/'), KeyModifiers::NONE));
    for c in "beta".chars() {
        app.handle_key(KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE));
    }
    app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
    assert_eq!(app.cursor, 1); // beta

    // `/<Enter>` with no typed pattern re-uses "beta", forward.
    app.handle_key(KeyEvent::new(KeyCode::Char('/'), KeyModifiers::NONE));
    app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
    assert_eq!(app.cursor, 3); // beta2

    // `?<Enter>` with no typed pattern re-uses "beta" too, backward.
    app.handle_key(KeyEvent::new(KeyCode::Char('?'), KeyModifiers::NONE));
    app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
    assert_eq!(app.cursor, 1); // beta
}

/// Spec 0114 §4, extended to the main pane: `Esc` cancels an
/// in-progress search without moving the cursor, and `Backspace` on an
/// empty buffer also cancels it.
#[test]
fn main_pane_search_esc_and_empty_backspace_cancel() {
    let mut app = sibling_leaves_app(&["alpha: 1", "beta: 2"]);
    app.splash = false;
    app.term_width = 120;

    app.handle_key(KeyEvent::new(KeyCode::Char('/'), KeyModifiers::NONE));
    app.handle_key(KeyEvent::new(KeyCode::Char('x'), KeyModifiers::NONE));
    app.handle_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
    assert!(app.command_buffer.is_none());
    assert_eq!(app.cursor, 0);

    app.handle_key(KeyEvent::new(KeyCode::Char('/'), KeyModifiers::NONE));
    assert!(app.command_buffer.is_some());
    app.handle_key(KeyEvent::new(KeyCode::Backspace, KeyModifiers::NONE));
    assert!(app.command_buffer.is_none());
}

/// Spec 0114 §4's main-pane search directive: "search in main pane
/// requires main pane to be in focus" — while the override pane has
/// focus, `/`/`?`/`n` share the same `command_buffer` as main-pane
/// search (spec-0133-adjacent rework), but `Enter` dispatches to the
/// override pane's own `jump_to_override_match`, not the main pane's
/// `jump_to_match` — the main-pane cursor never moves.
#[test]
fn main_pane_search_keys_are_inert_while_override_pane_has_focus() {
    let mut app = message_node_app();
    app.splash = false;
    app.term_width = 120;
    app.handle_key(KeyEvent::new(KeyCode::Char('t'), KeyModifiers::NONE));
    assert!(app.override_focus);
    let cursor_before = app.cursor;

    app.override_candidates = vec![("pkg.Alpha".to_string(), None)];
    app.override_highlight = 0;

    app.handle_key(KeyEvent::new(KeyCode::Char('/'), KeyModifiers::NONE));
    assert!(app.command_buffer.is_some());
    for c in "alpha".chars() {
        app.handle_key(KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE));
    }
    app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
    assert!(app.command_buffer.is_none());
    assert_eq!(app.override_highlight, 1); // pkg.Alpha
    assert_eq!(app.cursor, cursor_before);
}

/// Spec 0114 §4's main-pane search directive: search matches against
/// the *current* rendered text (`self.lines`), so a range whose type
/// has been overridden is matched post-override, not against the
/// original rendering — there is no separate "original text" cache to
/// special-case.
#[test]
fn main_pane_search_matches_the_current_not_original_rendering() {
    let mut app = sibling_leaves_app(&["alpha: 1", "beta: 2"]);
    app.splash = false;
    app.term_width = 120;

    // Simulate an already-applied override splice (spec 0114 §5):
    // node 1's rendered line no longer contains "beta" at all.
    app.lines[1] = "pkg.Overridden { x: 1 }".to_string();

    app.handle_key(KeyEvent::new(KeyCode::Char('/'), KeyModifiers::NONE));
    for c in "beta".chars() {
        app.handle_key(KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE));
    }
    app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
    assert_eq!(app.cursor, 0); // unchanged — "beta" no longer present
    assert!(app.message.contains("not found"));

    app.handle_key(KeyEvent::new(KeyCode::Char('/'), KeyModifiers::NONE));
    for c in "overridden".chars() {
        app.handle_key(KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE));
    }
    app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
    assert_eq!(app.cursor, 1); // matches the overridden text
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

/// A mouse click landing in the main pane shifts keyboard focus back
/// to it without closing the still-open side pane (2026-07-14
/// feedback, item 3).
#[test]
fn mouse_click_in_main_pane_refocuses_without_closing_override_pane() {
    let (mut app, inner_idx, _) = type_as_fixture();
    app.cursor = inner_idx;
    app.handle_key(KeyEvent::new(KeyCode::Char('t'), KeyModifiers::NONE));
    assert!(app.override_target.is_some());
    assert!(app.override_focus);

    app.main_area = Rect::new(0, 0, 40, 20);
    app.side_area = Rect::new(60, 0, 40, 20);

    app.handle_mouse(MouseEvent {
        kind: MouseEventKind::Down(MouseButton::Left),
        column: 5,
        row: 0,
        modifiers: KeyModifiers::NONE,
    });

    assert!(
        !app.override_focus,
        "click in main pane must shift focus back to it"
    );
    assert_eq!(
        app.override_target,
        Some(inner_idx),
        "the override pane must stay open"
    );
}

/// Wheel scroll routes to whichever pane the mouse is hovering, not
/// whichever pane currently has keyboard focus (2026-07-14 feedback,
/// item 4).
#[test]
fn mouse_wheel_routes_by_hover_position_not_keyboard_focus() {
    let (mut app, inner_idx, _) = type_as_fixture();
    app.cursor = inner_idx;
    app.handle_key(KeyEvent::new(KeyCode::Char('t'), KeyModifiers::NONE));
    assert!(app.override_focus, "keyboard focus starts in the side pane");

    app.main_area = Rect::new(0, 0, 40, 20);
    app.side_area = Rect::new(60, 0, 40, 20);
    app.override_candidates = vec![("a.B".to_string(), None), ("a.C".to_string(), None)];
    app.override_highlight = 0;

    let cursor_before = app.cursor;
    app.handle_mouse(MouseEvent {
        kind: MouseEventKind::ScrollDown,
        column: 5,
        row: 0,
        modifiers: KeyModifiers::NONE,
    });
    assert_ne!(
        app.cursor, cursor_before,
        "hovering the main pane must scroll it, even though the side \
         pane still has keyboard focus"
    );
    assert_eq!(
        app.override_highlight, 0,
        "the unhovered side pane must not react"
    );

    let cursor_after_main_scroll = app.cursor;
    app.handle_mouse(MouseEvent {
        kind: MouseEventKind::ScrollDown,
        column: 65,
        row: 0,
        modifiers: KeyModifiers::NONE,
    });
    assert_eq!(
        app.cursor, cursor_after_main_scroll,
        "hovering the side pane must not move the main-pane cursor"
    );
    assert_eq!(
        app.override_highlight, 1,
        "hovering the side pane must scroll it"
    );
}

/// Spec 0127 §G2: Shift+wheel pans whichever pane the mouse is
/// hovering; plain wheel (no Shift) keeps scrolling vertically as
/// before.
#[test]
fn shift_wheel_pans_the_hovered_main_pane_plain_wheel_still_scrolls() {
    let (mut app, _items) = repeated_scalar_fixture();
    app.main_area = Rect::new(0, 0, 5, 20);
    app.side_area = Rect::new(60, 0, 40, 20);

    let cursor_before = app.cursor;
    app.handle_mouse(MouseEvent {
        kind: MouseEventKind::ScrollDown,
        column: 2,
        row: 0,
        modifiers: KeyModifiers::SHIFT,
    });
    assert_eq!(
        app.cursor, cursor_before,
        "Shift+wheel must pan, not move the cursor"
    );
    assert_eq!(app.pan_offset, PAN_STEP, "Shift+ScrollDown must pan right");

    app.handle_mouse(MouseEvent {
        kind: MouseEventKind::ScrollUp,
        column: 2,
        row: 0,
        modifiers: KeyModifiers::SHIFT,
    });
    assert_eq!(app.pan_offset, 0, "Shift+ScrollUp must pan left");

    app.handle_mouse(MouseEvent {
        kind: MouseEventKind::ScrollDown,
        column: 2,
        row: 0,
        modifiers: KeyModifiers::NONE,
    });
    assert_ne!(
        app.cursor, cursor_before,
        "plain wheel (no Shift) must still scroll vertically"
    );
    assert_eq!(app.pan_offset, 0, "plain wheel must not pan");
}

/// Spec 0127 §G2: native `ScrollLeft`/`ScrollRight` pan the hovered
/// pane without needing Shift.
#[test]
fn native_scroll_left_right_pans_without_shift() {
    let (mut app, _items) = repeated_scalar_fixture();
    app.main_area = Rect::new(0, 0, 5, 20);

    app.handle_mouse(MouseEvent {
        kind: MouseEventKind::ScrollRight,
        column: 2,
        row: 0,
        modifiers: KeyModifiers::NONE,
    });
    assert_eq!(app.pan_offset, PAN_STEP, "ScrollRight must pan right");

    app.handle_mouse(MouseEvent {
        kind: MouseEventKind::ScrollLeft,
        column: 2,
        row: 0,
        modifiers: KeyModifiers::NONE,
    });
    assert_eq!(app.pan_offset, 0, "ScrollLeft must pan left");
}

/// Spec 0127 §G1: the override pane and the manage pane each carry
/// their own `pan_offset`, independent of the main pane's and of each
/// other's.
#[test]
fn override_and_manage_panes_pan_independently_of_the_main_pane() {
    let (mut app, items) = repeated_scalar_fixture();
    app.main_area = Rect::new(0, 0, 40, 20);
    app.side_area = Rect::new(60, 0, 5, 20);

    app.manage_open = true;
    app.overrides.activate(
        OverrideOrigin::Path {
            path: app.positional_path(items[0]),
        },
        None,
    );
    app.handle_mouse(MouseEvent {
        kind: MouseEventKind::ScrollRight,
        column: 62,
        row: 0,
        modifiers: KeyModifiers::NONE,
    });
    assert_eq!(app.manage_pan_offset, PAN_STEP);
    assert_eq!(
        app.pan_offset, 0,
        "the main pane's pan_offset must be untouched"
    );

    app.manage_open = false;
    app.override_target = Some(items[0]);
    app.handle_mouse(MouseEvent {
        kind: MouseEventKind::ScrollRight,
        column: 62,
        row: 0,
        modifiers: KeyModifiers::NONE,
    });
    assert_eq!(app.override_pan_offset, PAN_STEP);
    assert_eq!(
        app.manage_pan_offset, PAN_STEP,
        "unrelated to the override pane's own offset"
    );
}

/// Spec 0127 §G1: a long `:command` buffer becomes pannable — typing
/// past the visible width auto-follows the cursor instead of clipping
/// it off-screen, and the same offset can also be panned manually via
/// hover + Shift+wheel/native horizontal scroll.
#[test]
fn long_command_buffer_is_pannable_and_keeps_cursor_visible() {
    let (mut app, _items) = repeated_scalar_fixture();
    app.splash = false;
    app.command_buffer = Some("a".repeat(80));
    app.command_cursor = 80;

    let backend = TestBackend::new(60, 24);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|frame| app.render(frame)).unwrap();

    let cmd_area = app
        .cmd_area
        .expect("command bar must be shown while typing");
    assert!(
        app.command_pan_offset > 0,
        "auto-follow must have panned to keep the cursor visible"
    );
    let cursor_x = cmd_area.x + (1 + app.command_cursor - app.command_pan_offset) as u16;
    assert!(
        cursor_x < cmd_area.x + cmd_area.width,
        "the cursor must stay within the visible command bar"
    );

    let offset_before = app.command_pan_offset;
    app.handle_mouse(MouseEvent {
        kind: MouseEventKind::ScrollLeft,
        column: cmd_area.x,
        row: cmd_area.y,
        modifiers: KeyModifiers::NONE,
    });
    assert!(
        app.command_pan_offset < offset_before,
        "hovering + ScrollLeft must pan the command bar left"
    );
}

/// Spec 0129 §G1/§G3: click-drag across N main-pane rows, release —
/// selects the whole `[start, end]` range in document order, and
/// `render` highlights every row in that range with `REVERSED`.
#[test]
fn drag_select_spans_multiple_main_pane_rows() {
    let mut app = sibling_leaves_app(&["alpha: 1", "beta: 2", "gamma: 3", "delta: 4"]);
    app.splash = false;
    app.main_area = Rect::new(0, 0, 40, 20);

    app.handle_mouse(MouseEvent {
        kind: MouseEventKind::Down(MouseButton::Left),
        column: 0,
        row: 1,
        modifiers: KeyModifiers::NONE,
    });
    assert_eq!(app.select_anchor, Some(1));
    assert_eq!(app.select_end, Some(1));

    app.handle_mouse(MouseEvent {
        kind: MouseEventKind::Drag(MouseButton::Left),
        column: 0,
        row: 3,
        modifiers: KeyModifiers::NONE,
    });
    assert_eq!(app.select_anchor, Some(1));
    assert_eq!(app.select_end, Some(3));

    let (count, text) = app.selected_text().expect("selection must be active");
    assert_eq!(count, 3);
    assert_eq!(text, "beta: 2\ngamma: 3\ndelta: 4");

    app.handle_mouse(MouseEvent {
        kind: MouseEventKind::Up(MouseButton::Left),
        column: 0,
        row: 3,
        modifiers: KeyModifiers::NONE,
    });
    assert_eq!(
        app.select_anchor,
        Some(1),
        "selection persists after release"
    );
    assert_eq!(app.select_end, Some(3));
    // Spec 0131 §G1/test plan item 3: mouse release no longer copies
    // by itself.
    assert!(
        app.message.is_empty(),
        "unexpected message: {}",
        app.message
    );

    // Spec 0131 §G1/test plan item 1: `Ctrl-C` copies the persisted
    // drag-selection. No working clipboard provider exists in this
    // (headless) test environment — the OSC 52 fallback path is
    // exactly what's exercised here, not a panic.
    app.handle_key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL));
    assert!(
        app.message == "3 line(s) copied to clipboard"
            || app.message == "3 line(s) copied to clipboard (OSC 52 fallback)",
        "unexpected message: {}",
        app.message
    );
}

/// Feedback (2026-07-15): a plain click (`Down`+`Up`, no drag, not
/// the second half of a double-click) must deselect any active
/// selection rather than leave a length-1 selection behind — this
/// replaces spec 0129 §G3's original "plain click always selects"
/// behavior (superseded; see `double_click_selects_the_clicked_line`
/// for the new, explicit way to select a single line by mouse).
#[test]
fn plain_click_with_no_drag_deselects() {
    let mut app = sibling_leaves_app(&["alpha: 1", "beta: 2", "gamma: 3"]);
    app.splash = false;
    app.main_area = Rect::new(0, 0, 40, 20);

    // Seed an existing drag-selection first, so this also proves a
    // later plain click clears a *pre-existing* selection, not just
    // "never selects in the first place".
    app.handle_mouse(MouseEvent {
        kind: MouseEventKind::Down(MouseButton::Left),
        column: 0,
        row: 0,
        modifiers: KeyModifiers::NONE,
    });
    app.handle_mouse(MouseEvent {
        kind: MouseEventKind::Drag(MouseButton::Left),
        column: 0,
        row: 2,
        modifiers: KeyModifiers::NONE,
    });
    app.handle_mouse(MouseEvent {
        kind: MouseEventKind::Up(MouseButton::Left),
        column: 0,
        row: 2,
        modifiers: KeyModifiers::NONE,
    });
    assert_eq!(app.select_anchor, Some(0));
    assert_eq!(app.select_end, Some(2));

    // A plain click on a different line (no drag) must clear it.
    app.handle_mouse(MouseEvent {
        kind: MouseEventKind::Down(MouseButton::Left),
        column: 0,
        row: 1,
        modifiers: KeyModifiers::NONE,
    });
    app.handle_mouse(MouseEvent {
        kind: MouseEventKind::Up(MouseButton::Left),
        column: 0,
        row: 1,
        modifiers: KeyModifiers::NONE,
    });
    assert_eq!(app.select_anchor, None, "plain click deselects");
    assert_eq!(app.select_end, None);
}

/// Feedback (2026-07-15): double-clicking a main-pane line (two
/// `Down`+`Up` clicks on the same line, in quick succession)
/// explicitly selects that line for copy. Crossterm reports `Down`
/// identically for single and double clicks, so this exercises the
/// app's own timestamp/position-based disambiguation
/// (`App::last_click`/`pending_double_click`).
#[test]
fn double_click_selects_the_clicked_line_for_copy() {
    let mut app = sibling_leaves_app(&["alpha: 1", "beta: 2"]);
    app.splash = false;
    app.main_area = Rect::new(0, 0, 40, 20);

    for _ in 0..2 {
        app.handle_mouse(MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: 0,
            row: 0,
            modifiers: KeyModifiers::NONE,
        });
        app.handle_mouse(MouseEvent {
            kind: MouseEventKind::Up(MouseButton::Left),
            column: 0,
            row: 0,
            modifiers: KeyModifiers::NONE,
        });
    }

    assert_eq!(app.select_anchor, Some(0), "double-click selects the line");
    assert_eq!(app.select_end, Some(0));
    assert!(
        app.message.is_empty(),
        "unexpected message: {}",
        app.message
    );

    let (count, text) = app.selected_text().expect("selection must be active");
    assert_eq!(count, 1);
    assert_eq!(text, "alpha: 1");

    app.handle_key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL));
    assert!(
        app.message == "1 line(s) copied to clipboard"
            || app.message == "1 line(s) copied to clipboard (OSC 52 fallback)",
        "unexpected message: {}",
        app.message
    );
}

/// Spec 0129 §G1/test plan item 3: dragging upward (end row above
/// start row) still copies the correct range in top-to-bottom
/// document order, not reversed.
#[test]
fn drag_select_upward_still_copies_top_to_bottom() {
    let mut app = sibling_leaves_app(&["alpha: 1", "beta: 2", "gamma: 3"]);
    app.splash = false;
    app.main_area = Rect::new(0, 0, 40, 20);

    app.handle_mouse(MouseEvent {
        kind: MouseEventKind::Down(MouseButton::Left),
        column: 0,
        row: 2,
        modifiers: KeyModifiers::NONE,
    });
    app.handle_mouse(MouseEvent {
        kind: MouseEventKind::Drag(MouseButton::Left),
        column: 0,
        row: 0,
        modifiers: KeyModifiers::NONE,
    });
    assert_eq!(app.select_anchor, Some(2));
    assert_eq!(app.select_end, Some(0));

    let (count, text) = app.selected_text().expect("selection must be active");
    assert_eq!(count, 3, "top-to-bottom order, not reversed");
    assert_eq!(text, "alpha: 1\nbeta: 2\ngamma: 3");

    app.handle_mouse(MouseEvent {
        kind: MouseEventKind::Up(MouseButton::Left),
        column: 0,
        row: 0,
        modifiers: KeyModifiers::NONE,
    });
    assert!(
        app.message.is_empty(),
        "unexpected message: {}",
        app.message
    );

    app.handle_key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL));
    assert!(
        app.message == "3 line(s) copied to clipboard"
            || app.message == "3 line(s) copied to clipboard (OSC 52 fallback)",
        "unexpected message: {}",
        app.message
    );
}

/// Spec 0131 §G1/test plan item 2: `Ctrl-C` with no active selection
/// copies exactly the cursor's current line.
#[test]
fn ctrl_c_with_no_selection_copies_cursor_line() {
    let mut app = sibling_leaves_app(&["alpha: 1", "beta: 2"]);
    app.splash = false;
    app.main_area = Rect::new(0, 0, 40, 20);

    assert_eq!(app.select_anchor, None, "no selection active yet");
    app.handle_key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL));
    assert_eq!(app.select_anchor, Some(0));
    assert_eq!(app.select_end, Some(0));
    assert!(
        app.message == "1 line(s) copied to clipboard"
            || app.message == "1 line(s) copied to clipboard (OSC 52 fallback)",
        "unexpected message: {}",
        app.message
    );
}

/// Spec 0131 §G2/test plan item 4: a clipboard-unavailable
/// environment (no provider reachable, as in this headless test
/// harness) produces the OSC 52 fallback message instead of
/// panicking.
#[test]
fn clipboard_unavailable_shows_fallback_message_without_panicking() {
    let mut app = sibling_leaves_app(&["alpha: 1"]);
    app.splash = false;
    app.main_area = Rect::new(0, 0, 40, 20);

    app.handle_mouse(MouseEvent {
        kind: MouseEventKind::Down(MouseButton::Left),
        column: 0,
        row: 0,
        modifiers: KeyModifiers::NONE,
    });
    app.handle_key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL));
    // This sandbox has no reachable clipboard provider, so the
    // failure branch is exactly what's exercised here.
    assert!(
        app.message == "1 line(s) copied to clipboard"
            || app.message == "1 line(s) copied to clipboard (OSC 52 fallback)",
        "unexpected message: {}",
        app.message
    );
}

/// Spec 0129 §G3: a fresh click starts a new selection, replacing
/// the old one; `Esc` clears an existing selection's highlight too.
#[test]
fn fresh_click_replaces_selection_esc_clears_it() {
    let mut app = sibling_leaves_app(&["alpha: 1", "beta: 2", "gamma: 3"]);
    app.splash = false;
    app.main_area = Rect::new(0, 0, 40, 20);

    app.handle_mouse(MouseEvent {
        kind: MouseEventKind::Down(MouseButton::Left),
        column: 0,
        row: 0,
        modifiers: KeyModifiers::NONE,
    });
    app.handle_mouse(MouseEvent {
        kind: MouseEventKind::Drag(MouseButton::Left),
        column: 0,
        row: 2,
        modifiers: KeyModifiers::NONE,
    });
    app.handle_mouse(MouseEvent {
        kind: MouseEventKind::Up(MouseButton::Left),
        column: 0,
        row: 2,
        modifiers: KeyModifiers::NONE,
    });
    assert_eq!(app.select_anchor, Some(0));
    assert_eq!(app.select_end, Some(2));

    app.handle_mouse(MouseEvent {
        kind: MouseEventKind::Down(MouseButton::Left),
        column: 0,
        row: 1,
        modifiers: KeyModifiers::NONE,
    });
    assert_eq!(
        app.select_anchor,
        Some(1),
        "a fresh click replaces the old selection"
    );
    assert_eq!(app.select_end, Some(1));

    app.handle_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
    assert_eq!(app.select_anchor, None, "Esc clears the selection");
    assert_eq!(app.select_end, None);
}

/// `Esc` closes the override pane regardless of which pane currently
/// has focus — same "works regardless of focus" treatment as `t`
/// (spec 0114 §8's key-bindings table).
#[test]
fn esc_closes_the_override_pane_from_either_focus() {
    let mut app = message_node_app();
    app.splash = false;
    app.term_width = 120;

    app.handle_key(KeyEvent::new(KeyCode::Char('t'), KeyModifiers::NONE));
    app.handle_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
    assert_eq!(app.override_target, None);

    app.handle_key(KeyEvent::new(KeyCode::Char('t'), KeyModifiers::NONE));
    app.handle_key(KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE));
    assert!(!app.override_focus);
    app.handle_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
    assert_eq!(app.override_target, None);
}

/// Spec 0114 §1.1: the virtual encompassing wrapper protobuf makes
/// "the node under the cursor" unambiguous even at the top level, and
/// display coordinates (byte ranges, positional paths) are corrected
/// back to exactly what they were pre-wrap. Mirrors the synthetic
/// `Outer { inner: Inner { id: 5 } }` fixture in
/// `extract::tests::extract_binary_message_round_trips_through_a_fresh_decode`.
#[test]
fn wrapper_offset_and_display_range_restore_pre_wrap_coordinates() {
    use prost::Message as _;
    use prost_types::field_descriptor_proto::{Label, Type};
    use prost_types::{
        DescriptorProto, FieldDescriptorProto, FileDescriptorProto, FileDescriptorSet,
    };

    use crate::decode::{decode, DescriptorContext};

    let inner_desc = DescriptorProto {
        name: Some("Inner".to_string()),
        field: vec![FieldDescriptorProto {
            name: Some("id".to_string()),
            number: Some(1),
            label: Some(Label::Optional as i32),
            r#type: Some(Type::Int32 as i32),
            ..Default::default()
        }],
        ..Default::default()
    };
    let outer_desc = DescriptorProto {
        name: Some("Outer".to_string()),
        field: vec![FieldDescriptorProto {
            name: Some("inner".to_string()),
            number: Some(1),
            label: Some(Label::Optional as i32),
            r#type: Some(Type::Message as i32),
            type_name: Some(".test.Inner".to_string()),
            ..Default::default()
        }],
        ..Default::default()
    };
    let file = FileDescriptorProto {
        name: Some("test_wrapper_offset.proto".to_string()),
        package: Some("test".to_string()),
        message_type: vec![outer_desc, inner_desc],
        syntax: Some("proto3".to_string()),
        ..Default::default()
    };
    let fds = FileDescriptorSet { file: vec![file] };

    let descriptor_path = std::env::temp_dir().join("protolens-tui-wrapper-offset-descriptor.pb");
    std::fs::write(&descriptor_path, fds.encode_to_vec()).unwrap();
    let mut ctx = DescriptorContext::load(&descriptor_path).unwrap();
    std::fs::remove_file(&descriptor_path).unwrap();

    // Inner: field 1 varint 5 -> tag 0x08, value 0x05.
    let inner_bytes = [0x08u8, 0x05];
    // Outer wraps it as field 1 (LEN): tag (1<<3)|2 = 0x0A, len 2.
    let blob = [0x0Au8, 0x02, inner_bytes[0], inner_bytes[1]];

    let decoded = decode(&blob, &mut ctx, Some("test.Outer"), 2).unwrap();
    // tag(1 byte) + length-varint(1 byte, blob.len() == 4 fits in 1 byte).
    assert_eq!(decoded.wrapper_offset, 2);
    assert_eq!(decoded.blob.len(), blob.len() + 2);

    let app = App::new(
        decoded,
        "test.pb",
        PathBuf::from("test.pb"),
        2,
        ctx,
        ThemeKind::Dark,
    );

    // The level-0 node is the wrapper's sole field, standing in for
    // the entire original message (spec 0114 §1.1) — it did not exist
    // pre-wrap.
    let outer_idx = app
        .tree
        .iter()
        .position(|n| n.span.type_fqdn.as_deref() == Some("test.Outer"))
        .expect("tree must contain the Outer stand-in node");
    // Its whole-message payload, offset-corrected, is exactly the
    // caller's original blob.
    assert_eq!(app.display_range(outer_idx), 0..blob.len());
    // The wrapper's own node displays as bare "/".
    assert_eq!(app.positional_path(outer_idx), "/");

    let inner_idx = app
        .tree
        .iter()
        .position(|n| n.span.type_fqdn.as_deref() == Some("test.Inner"))
        .expect("tree must contain the Inner submessage");
    // Byte offsets 2..4 of the *original* blob, not the wrapped one.
    assert_eq!(app.display_range(inner_idx), 2..blob.len());
    // Leading `/1` leg (descent into the wrapper's sole field) is
    // dropped — matches the path this node would have had pre-wrap.
    assert_eq!(app.positional_path(inner_idx), "/1");
}

/// `display_range` on a scalar node starts at the payload, same as a
/// message/group node: the field's own tag (and, for length-delimited
/// scalars, the length prefix) is stripped. A packed-repeated field is
/// the length-delimited case, but `IndexingTextSink::scalar_field`
/// pushes one `NodeSpan` *per element* (spec 0115), each already
/// bare-payload (`packed_record_start: Some(...)`) — so `display_range`
/// on one of those element nodes returns that element's own byte
/// unstripped, not the whole record's tag+length-stripped payload.
#[test]
fn display_range_strips_tag_and_length_for_scalars_including_packed() {
    use prost::Message as _;
    use prost_types::field_descriptor_proto::{Label, Type};
    use prost_types::{
        DescriptorProto, FieldDescriptorProto, FileDescriptorProto, FileDescriptorSet,
    };

    use crate::decode::{decode, DescriptorContext};

    let msg_desc = DescriptorProto {
        name: Some("Msg".to_string()),
        field: vec![
            FieldDescriptorProto {
                name: Some("id".to_string()),
                number: Some(1),
                label: Some(Label::Optional as i32),
                r#type: Some(Type::Int32 as i32),
                ..Default::default()
            },
            FieldDescriptorProto {
                name: Some("vals".to_string()),
                number: Some(2),
                label: Some(Label::Repeated as i32),
                r#type: Some(Type::Int32 as i32),
                ..Default::default()
            },
        ],
        ..Default::default()
    };
    let file = FileDescriptorProto {
        name: Some("test_display_range_scalars.proto".to_string()),
        package: Some("test".to_string()),
        message_type: vec![msg_desc],
        syntax: Some("proto3".to_string()),
        ..Default::default()
    };
    let fds = FileDescriptorSet { file: vec![file] };

    let descriptor_path =
        std::env::temp_dir().join("protolens-tui-display-range-scalars-descriptor.pb");
    std::fs::write(&descriptor_path, fds.encode_to_vec()).unwrap();
    let mut ctx = DescriptorContext::load(&descriptor_path).unwrap();
    std::fs::remove_file(&descriptor_path).unwrap();

    // id: field 1 varint 5 -> tag 0x08, value 0x05.
    // vals: field 2 (LEN, packed) tag (2<<3)|2 = 0x12, len 3, payload
    // [0x01, 0x02, 0x03] (three varint elements 1, 2, 3).
    let blob = [0x08u8, 0x05, 0x12, 0x03, 0x01, 0x02, 0x03];

    let decoded = decode(&blob, &mut ctx, Some("test.Msg"), 2).unwrap();
    let app = App::new(
        decoded,
        "test.pb",
        PathBuf::from("test.pb"),
        2,
        ctx,
        ThemeKind::Dark,
    );

    let id_idx = app
        .tree
        .iter()
        .position(|n| n.span.field_number == 1)
        .expect("tree must contain the id field");
    assert!(!app.tree[id_idx].span.is_message);
    // Tag (1 byte) stripped: just the varint value byte.
    assert_eq!(app.display_range(id_idx), 1..2);

    let vals_indices: Vec<usize> = app
        .tree
        .iter()
        .enumerate()
        .filter(|(_, n)| n.span.field_number == 2)
        .map(|(i, _)| i)
        .collect();
    // One NodeSpan per packed element (spec 0115), not one for the
    // whole record.
    assert_eq!(vals_indices.len(), 3);
    for idx in &vals_indices {
        assert!(!app.tree[*idx].span.is_message);
        assert!(app.tree[*idx].span.packed_record_start.is_some());
    }
    // Each element's own byte, already bare-payload — no further
    // tag/length stripping applied.
    assert_eq!(app.display_range(vals_indices[0]), 4..5);
    assert_eq!(app.display_range(vals_indices[1]), 5..6);
    assert_eq!(app.display_range(vals_indices[2]), 6..7);
}

/// Spec 0118 §4: `splice_override` regenerates a whole node (not just
/// its interior) into `self.lines`/`self.tree`, repeatable on the
/// same node (the design's key risk: post-order array contiguity does
/// not survive a *second* override of the same node, since the first
/// override's new nodes are appended at the array's end —
/// `splice_override` must never rely on it).
#[test]
fn apply_override_splices_tree_and_lines_repeatedly() {
    use prost::Message as _;
    use prost_types::field_descriptor_proto::{Label, Type};
    use prost_types::{
        DescriptorProto, FieldDescriptorProto, FileDescriptorProto, FileDescriptorSet,
    };

    use crate::decode::{decode, DescriptorContext};

    let leaf_desc = DescriptorProto {
        name: Some("Leaf".to_string()),
        field: vec![FieldDescriptorProto {
            name: Some("val".to_string()),
            number: Some(1),
            label: Some(Label::Optional as i32),
            r#type: Some(Type::Int32 as i32),
            ..Default::default()
        }],
        ..Default::default()
    };
    let node_desc = DescriptorProto {
        name: Some("Node".to_string()),
        field: vec![
            FieldDescriptorProto {
                name: Some("a".to_string()),
                number: Some(1),
                label: Some(Label::Optional as i32),
                r#type: Some(Type::Message as i32),
                type_name: Some(".test.Leaf".to_string()),
                ..Default::default()
            },
            FieldDescriptorProto {
                name: Some("b".to_string()),
                number: Some(2),
                label: Some(Label::Optional as i32),
                r#type: Some(Type::Int32 as i32),
                ..Default::default()
            },
        ],
        ..Default::default()
    };
    let outer_desc = DescriptorProto {
        name: Some("Outer".to_string()),
        field: vec![FieldDescriptorProto {
            name: Some("inner".to_string()),
            number: Some(1),
            label: Some(Label::Optional as i32),
            r#type: Some(Type::Message as i32),
            type_name: Some(".test.Node".to_string()),
            ..Default::default()
        }],
        ..Default::default()
    };
    let file = FileDescriptorProto {
        name: Some("test_apply_override.proto".to_string()),
        package: Some("test".to_string()),
        message_type: vec![outer_desc, node_desc, leaf_desc],
        syntax: Some("proto3".to_string()),
        ..Default::default()
    };
    let fds = FileDescriptorSet { file: vec![file] };

    let descriptor_path = std::env::temp_dir().join("protolens-tui-apply-override-descriptor.pb");
    std::fs::write(&descriptor_path, fds.encode_to_vec()).unwrap();
    let mut ctx = DescriptorContext::load(&descriptor_path).unwrap();
    std::fs::remove_file(&descriptor_path).unwrap();

    // Node payload: a = Leaf { val: 9 } (message, field 1), b = 42
    // (varint, field 2).
    let leaf_bytes = [0x08u8, 0x09];
    let node_payload = [0x0Au8, 0x02, leaf_bytes[0], leaf_bytes[1], 0x10, 0x2A];
    // Outer wraps Node as field 1 (LEN).
    let mut blob = vec![0x0Au8, node_payload.len() as u8];
    blob.extend_from_slice(&node_payload);

    let decoded = decode(&blob, &mut ctx, Some("test.Outer"), 2).unwrap();
    let mut app = App::new(
        decoded,
        "test.pb",
        PathBuf::from("test.pb"),
        2,
        ctx,
        ThemeKind::Dark,
    );

    let node_idx = app
        .tree
        .iter()
        .position(|n| n.span.type_fqdn.as_deref() == Some("test.Node"))
        .expect("tree must contain the Node submessage");
    let node_level = app.tree[node_idx].span.level;

    // Fold the "a" child before overriding, to verify the stale-fold
    // scrubbing (`collect_descendants` cleanup).
    let a_idx_before = app.tree[node_idx]
        .first_child
        .expect("Node has at least one child");
    app.folded.insert(a_idx_before);

    let assert_children = |app: &App, tag: &str| {
        let mut children = Vec::new();
        let mut cur = app.tree[node_idx].first_child;
        while let Some(c) = cur {
            children.push(c);
            cur = app.tree[c].next_sibling;
        }
        assert_eq!(children.len(), 2, "{tag}: expected two children (a, b)");
        for &c in &children {
            assert_eq!(
                app.tree[c].span.level,
                node_level + 1,
                "{tag}: child level must match pre-override nesting"
            );
        }
        assert_eq!(
            app.tree[children[0]].span.type_fqdn.as_deref(),
            Some("test.Leaf"),
            "{tag}: first child must resolve to test.Leaf"
        );
    };

    app.override_target = Some(node_idx);

    // 1) Re-typed as itself: idempotent structural round-trip.
    app.splice_override(node_idx, Some("test.Node".to_string()))
        .expect("re-typing as the same type must succeed");
    assert_children(&app, "re-typed as itself");
    assert_eq!(
        app.tree[node_idx].span.type_fqdn.as_deref(),
        Some("test.Node")
    );
    assert!(
        !app.folded.contains(&a_idx_before),
        "orphaned old child must be scrubbed from `folded`"
    );

    // 2) Raw override (no schema).
    app.splice_override(node_idx, None)
        .expect("raw override must succeed");
    assert_eq!(app.tree[node_idx].span.type_fqdn, None);

    // 3) Re-typed again, on top of two prior overrides — exercises
    // repeated overrides of the same node.
    app.splice_override(node_idx, Some("test.Node".to_string()))
        .expect("third override must still succeed");
    assert_children(&app, "re-typed a third time");

    // `line_to_node` must stay fully consistent with the doc chain:
    // every reachable node via `doc_next` from `first_node`, and
    // nothing else.
    let mut expected = HashMap::new();
    let mut cur = Some(app.first_node);
    let mut count = 0;
    while let Some(c) = cur {
        expected.insert(app.tree[c].span.text_range.start, c);
        count += 1;
        assert!(count <= app.tree.len(), "doc chain must not cycle");
        cur = app.tree[c].doc_next;
    }
    assert_eq!(app.line_to_node, expected);
}

/// Spec 0114 §5: `Enter` in the override pane applies the highlighted
/// row (the pinned raw entry, or a ranked candidate) and closes the
/// pane on success.
#[test]
fn enter_key_applies_override_and_closes_pane() {
    use prost::Message as _;
    use prost_types::field_descriptor_proto::{Label, Type};
    use prost_types::{
        DescriptorProto, FieldDescriptorProto, FileDescriptorProto, FileDescriptorSet,
    };

    use crate::decode::{decode, DescriptorContext};

    let inner_desc = DescriptorProto {
        name: Some("Inner".to_string()),
        field: vec![FieldDescriptorProto {
            name: Some("id".to_string()),
            number: Some(1),
            label: Some(Label::Optional as i32),
            r#type: Some(Type::Int32 as i32),
            ..Default::default()
        }],
        ..Default::default()
    };
    let outer_desc = DescriptorProto {
        name: Some("Outer".to_string()),
        field: vec![FieldDescriptorProto {
            name: Some("inner".to_string()),
            number: Some(1),
            label: Some(Label::Optional as i32),
            r#type: Some(Type::Message as i32),
            type_name: Some(".test.Inner".to_string()),
            ..Default::default()
        }],
        ..Default::default()
    };
    let file = FileDescriptorProto {
        name: Some("test_enter_override.proto".to_string()),
        package: Some("test".to_string()),
        message_type: vec![outer_desc, inner_desc],
        syntax: Some("proto3".to_string()),
        ..Default::default()
    };
    let fds = FileDescriptorSet { file: vec![file] };

    let descriptor_path = std::env::temp_dir().join("protolens-tui-enter-override-descriptor.pb");
    std::fs::write(&descriptor_path, fds.encode_to_vec()).unwrap();
    let mut ctx = DescriptorContext::load(&descriptor_path).unwrap();
    std::fs::remove_file(&descriptor_path).unwrap();

    // Outer { inner: Inner { id: 5 } }.
    let blob = [0x0Au8, 0x02, 0x08, 0x05];
    let decoded = decode(&blob, &mut ctx, Some("test.Outer"), 2).unwrap();
    let mut app = App::new(
        decoded,
        "test.pb",
        PathBuf::from("test.pb"),
        2,
        ctx,
        ThemeKind::Dark,
    );
    app.splash = false;
    app.term_width = 120;

    let inner_idx = app
        .tree
        .iter()
        .position(|n| n.span.type_fqdn.as_deref() == Some("test.Inner"))
        .expect("tree must contain the Inner submessage");
    app.cursor = inner_idx;

    // Row 0 (pinned raw entry): `Enter` clears the type and closes
    // the pane. `t`'s default Inferred sort mode leaves an unrelated
    // "no scoring graph" status message in this graph-less fixture —
    // clear it first so it can't be mistaken for an override error.
    app.handle_key(KeyEvent::new(KeyCode::Char('t'), KeyModifiers::NONE));
    assert!(app.override_target.is_some());
    app.message.clear();
    app.override_highlight = 0;
    app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
    assert!(app.override_target.is_none(), "pane must close on success");
    assert_eq!(app.tree[inner_idx].span.type_fqdn, None);
    assert!(app.message.is_empty(), "no error expected: {}", app.message);
    // Spec 0119 G3: `Enter` lands in the management pane instead of
    // just closing outright.
    assert!(app.manage_open, "must open the management pane (G3)");
    app.handle_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
    assert!(!app.manage_open);

    // A ranked candidate row: re-open, switch to lexicographic sort
    // (no scoring graph in this fixture), and select the first
    // candidate.
    app.cursor = inner_idx;
    app.handle_key(KeyEvent::new(KeyCode::Char('t'), KeyModifiers::NONE));
    app.override_sort = SortMode::Lexicographic;
    app.recompute_override_candidates();
    assert!(!app.override_candidates.is_empty());
    app.override_highlight = 1;
    let chosen = app.override_candidates[0].0.clone();
    app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
    assert!(app.override_target.is_none());
    assert_eq!(
        app.tree[inner_idx].span.type_fqdn.as_deref(),
        Some(chosen.as_str())
    );
}

/// Spec 0119 §G4: `f` in the management pane opens a rename buffer
/// pre-filled from the highlighted entry's current name; `Enter`
/// confirms, mutating the entry in place and — since the entry is
/// active — triggering a re-render whose header line picks up the
/// new name (the `(type, field_name)` re-splice gate).
#[test]
fn manage_pane_rename_updates_entry_and_rerenders_active_override() {
    let (mut app, inner_idx, _) = type_as_fixture();
    app.cursor = inner_idx;
    app.run_command("type-as test.Inner");
    assert_eq!(
        app.tree[inner_idx].span.type_fqdn.as_deref(),
        Some("test.Inner")
    );

    app.toggle_manage_pane();
    assert!(app.manage_open);
    let entry_idx = app
        .overrides
        .entries()
        .iter()
        .position(|e| e.active && e.r#type.as_deref() == Some("test.Inner"))
        .expect("type-as must have created an active entry for test.Inner");
    app.manage_highlight = entry_idx;

    app.handle_key(KeyEvent::new(KeyCode::Char('f'), KeyModifiers::NONE));
    assert!(app.manage_rename.is_some());
    for c in "custom_name".chars() {
        app.handle_key(KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE));
    }
    app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
    assert!(app.manage_rename.is_none());
    assert_eq!(
        app.overrides.entries()[entry_idx].name.as_deref(),
        Some("custom_name")
    );

    let line_idx = app.tree[inner_idx].span.text_range.start;
    let header = &app.lines[line_idx];
    assert!(
        header.contains("custom_name"),
        "expected the renamed field name in the re-rendered header: {header}"
    );
}

/// Builds the same `Outer { inner: Inner { id: 5 } }` fixture as
/// `enter_key_applies_override_and_closes_pane`, for the `:type-as`/
/// `:type-as-raw` command tests (spec 0114 §7).
fn type_as_fixture() -> (App, usize, usize) {
    use prost::Message as _;
    use prost_types::field_descriptor_proto::{Label, Type};
    use prost_types::{
        DescriptorProto, FieldDescriptorProto, FileDescriptorProto, FileDescriptorSet,
    };

    use crate::decode::{decode, DescriptorContext};

    let inner_desc = DescriptorProto {
        name: Some("Inner".to_string()),
        field: vec![FieldDescriptorProto {
            name: Some("id".to_string()),
            number: Some(1),
            label: Some(Label::Optional as i32),
            r#type: Some(Type::Int32 as i32),
            ..Default::default()
        }],
        ..Default::default()
    };
    let outer_desc = DescriptorProto {
        name: Some("Outer".to_string()),
        field: vec![FieldDescriptorProto {
            name: Some("inner".to_string()),
            number: Some(1),
            label: Some(Label::Optional as i32),
            r#type: Some(Type::Message as i32),
            type_name: Some(".test.Inner".to_string()),
            ..Default::default()
        }],
        ..Default::default()
    };
    let file = FileDescriptorProto {
        name: Some("test_type_as.proto".to_string()),
        package: Some("test".to_string()),
        message_type: vec![outer_desc, inner_desc],
        syntax: Some("proto3".to_string()),
        ..Default::default()
    };
    let fds = FileDescriptorSet { file: vec![file] };

    // Unique per call (this fixture is shared by several tests that
    // may run concurrently) to avoid one test's cleanup racing
    // another's read of the same path.
    static COUNTER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let descriptor_path =
        std::env::temp_dir().join(format!("protolens-tui-type-as-descriptor-{n}.pb"));
    std::fs::write(&descriptor_path, fds.encode_to_vec()).unwrap();
    let mut ctx = DescriptorContext::load(&descriptor_path).unwrap();
    std::fs::remove_file(&descriptor_path).unwrap();

    // Outer { inner: Inner { id: 5 } }.
    let blob = [0x0Au8, 0x02, 0x08, 0x05];
    let decoded = decode(&blob, &mut ctx, Some("test.Outer"), 2).unwrap();
    let mut app = App::new(
        decoded,
        "test.pb",
        PathBuf::from("test.pb"),
        2,
        ctx,
        ThemeKind::Dark,
    );
    app.splash = false;
    app.term_width = 120;

    let inner_idx = app
        .tree
        .iter()
        .position(|n| n.span.type_fqdn.as_deref() == Some("test.Inner"))
        .expect("tree must contain the Inner submessage");
    let id_idx = app.tree[inner_idx]
        .first_child
        .expect("Inner has at least one child");
    (app, inner_idx, id_idx)
}

/// Overriding a plain scalar (string) field into an incompatible
/// message type must not panic — it should apply the override and
/// surface the mismatch as ordinary `TYPE_MISMATCH`/`INVALID_*`
/// annotations in the interior, exactly like any other malformed
/// nested-message re-decode (feedback, 2026-07-16: `t` used to
/// panic on `natural_annotation`'s `.expect()`).
#[test]
fn splice_override_on_an_incompatible_scalar_does_not_panic() {
    use crate::decode::{decode, DescriptorContext};
    use prost::Message as _;
    use prost_types::field_descriptor_proto::{Label, Type};
    use prost_types::{
        DescriptorProto, FieldDescriptorProto, FileDescriptorProto, FileDescriptorSet,
    };

    let str_msg = DescriptorProto {
        name: Some("StrHolder".to_string()),
        field: vec![FieldDescriptorProto {
            name: Some("s".to_string()),
            number: Some(1),
            label: Some(Label::Optional as i32),
            r#type: Some(Type::String as i32),
            ..Default::default()
        }],
        ..Default::default()
    };
    let target_msg = DescriptorProto {
        name: Some("Target".to_string()),
        field: vec![FieldDescriptorProto {
            name: Some("id".to_string()),
            number: Some(1),
            label: Some(Label::Optional as i32),
            r#type: Some(Type::Int32 as i32),
            ..Default::default()
        }],
        ..Default::default()
    };
    let file = FileDescriptorProto {
        name: Some("incompat.proto".to_string()),
        package: Some("incompat".to_string()),
        message_type: vec![str_msg, target_msg],
        syntax: Some("proto3".to_string()),
        ..Default::default()
    };
    let fds = FileDescriptorSet { file: vec![file] };
    static COUNTER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let descriptor_path =
        std::env::temp_dir().join(format!("protolens-tui-incompat-override-{n}.pb"));
    std::fs::write(&descriptor_path, fds.encode_to_vec()).unwrap();
    let mut ctx = DescriptorContext::load(&descriptor_path).unwrap();
    std::fs::remove_file(&descriptor_path).unwrap();

    // StrHolder { s: "hello" }
    let label = b"hello";
    let mut blob = vec![0x0Au8, label.len() as u8];
    blob.extend_from_slice(label);
    let decoded = decode(&blob, &mut ctx, Some("incompat.StrHolder"), 2).unwrap();
    let mut app = App::new(
        decoded,
        "test.pb",
        PathBuf::from("test.pb"),
        2,
        ctx,
        ThemeKind::Dark,
    );
    app.splash = false;
    app.term_width = 120;

    let s_idx = app
        .tree
        .iter()
        .position(|n| n.span.field_number == 1)
        .expect("must find field 1");
    assert!(
        app.can_override(s_idx),
        "a WT_LEN scalar must be overridable"
    );

    app.splice_override(s_idx, Some("incompat.Target".to_string()))
        .expect("override onto an incompatible type must still succeed");
    assert!(
        app.lines
            .iter()
            .any(|l| l.contains("INVALID") || l.contains("TYPE_MISMATCH")),
        "mismatch must surface as an inline annotation, not a panic: {:?}",
        app.lines
    );
}

/// `Outer2 { grp: MyGroup { id: 5 } }`, with `grp` declared as a
/// genuine schema wire-group field (`Type::Group`) — unlike
/// `message_set_fixture`'s auto-expanded MessageSet group items,
/// this is directly schema-resolved from the start. Also registers
/// a same-shaped sibling type `NewGroup` to override `grp` into
/// (spec 0122 Test Plan item 2).
fn group_type_fixture() -> (App, usize) {
    // START_GROUP(5), id=5, END_GROUP(5) — minimal tag encoding.
    group_type_fixture_with_blob(&[0x2Bu8, 0x08, 0x05, 0x2Cu8])
}

/// Same schema as `group_type_fixture`, but with `grp`'s `START_GROUP`
/// tag encoded with one overhang byte (non-minimal varint: `0xAB, 0x00`
/// instead of the minimal `0x2B`) — exercises the `tag_ohb: 1` anomaly
/// modifier (spec 0122 Test Plan item 2, 3rd bullet).
fn group_type_fixture_with_tag_ohb() -> (App, usize) {
    group_type_fixture_with_blob(&[0xABu8, 0x00, 0x08, 0x05, 0x2Cu8])
}

fn group_type_fixture_with_blob(blob: &[u8]) -> (App, usize) {
    use prost::Message as _;
    use prost_types::field_descriptor_proto::{Label, Type};
    use prost_types::{
        DescriptorProto, FieldDescriptorProto, FileDescriptorProto, FileDescriptorSet,
    };

    use crate::decode::{decode, DescriptorContext};

    let my_group_desc = DescriptorProto {
        name: Some("MyGroup".to_string()),
        field: vec![FieldDescriptorProto {
            name: Some("id".to_string()),
            number: Some(1),
            label: Some(Label::Optional as i32),
            r#type: Some(Type::Int32 as i32),
            ..Default::default()
        }],
        ..Default::default()
    };
    let new_group_desc = DescriptorProto {
        name: Some("NewGroup".to_string()),
        field: vec![FieldDescriptorProto {
            name: Some("value".to_string()),
            number: Some(1),
            label: Some(Label::Optional as i32),
            r#type: Some(Type::Int32 as i32),
            ..Default::default()
        }],
        ..Default::default()
    };
    let outer_desc = DescriptorProto {
        name: Some("Outer2".to_string()),
        field: vec![FieldDescriptorProto {
            name: Some("grp".to_string()),
            number: Some(5),
            label: Some(Label::Optional as i32),
            r#type: Some(Type::Group as i32),
            type_name: Some(".test.MyGroup".to_string()),
            ..Default::default()
        }],
        ..Default::default()
    };
    let file = FileDescriptorProto {
        name: Some("test_group_type.proto".to_string()),
        package: Some("test".to_string()),
        syntax: Some("proto2".to_string()),
        message_type: vec![outer_desc, my_group_desc, new_group_desc],
        ..Default::default()
    };
    let fds = FileDescriptorSet { file: vec![file] };

    // Unique per call (this fixture is shared by several tests that
    // may run concurrently) to avoid one test's cleanup racing
    // another's read of the same path.
    static COUNTER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let descriptor_path =
        std::env::temp_dir().join(format!("protolens-tui-group-type-descriptor-{n}.pb"));
    std::fs::write(&descriptor_path, fds.encode_to_vec()).unwrap();
    let mut ctx = DescriptorContext::load(&descriptor_path).unwrap();
    std::fs::remove_file(&descriptor_path).unwrap();

    let decoded = decode(blob, &mut ctx, Some("test.Outer2"), 2).unwrap();
    let mut app = App::new(
        decoded,
        "test.pb",
        PathBuf::from("test.pb"),
        2,
        ctx,
        ThemeKind::Dark,
    );
    app.splash = false;
    app.term_width = 120;

    let grp_idx = app
        .tree
        .iter()
        .position(|n| n.span.type_fqdn.as_deref() == Some("test.MyGroup"))
        .expect("tree must contain the MyGroup submessage");
    (app, grp_idx)
}

/// Overriding a group field to a resolvable type must keep the
/// `group;` prefix in the header (spec 0122 Test Plan item 2, 1st
/// bullet).
#[test]
fn splice_override_on_a_group_field_keeps_the_group_prefix() {
    let (mut app, grp_idx) = group_type_fixture();
    app.splice_override(grp_idx, Some("test.NewGroup".to_string()))
        .unwrap();
    let header = &app.lines[app.tree[grp_idx].span.text_range.start];
    assert!(
        header.contains("#@ group; NewGroup = 5"),
        "expected group; NewGroup = 5 in header, got: {header:?}"
    );
}

/// The header-line patch (spec 0122 §2) usually changes the header's
/// byte length (e.g. bare `#@ group` growing into `#@ group; NewGroup
/// = 5`) — `line_styles`' per-line color buckets must stay aligned
/// with `self.lines`' actual text for every line *after* the header,
/// not just the header itself (2026-07-15 regression: colors drifted
/// starting right after the first patched `#@ group;` header,
/// because `hints_by_line` was bucketing hints computed against the
/// *cached* (unpatched) header length using the *patched* line
/// array's lengths).
#[test]
fn splice_override_keeps_colors_aligned_after_a_header_length_change() {
    let (mut app, grp_idx) = group_type_fixture();
    app.splice_override(grp_idx, Some("test.NewGroup".to_string()))
        .unwrap();
    let value_idx = app.tree[grp_idx]
        .first_child
        .expect("NewGroup has at least one child");
    let line_idx = app.tree[value_idx].span.text_range.start;
    let line = &app.lines[line_idx];
    let value_pos = line
        .find('5')
        .expect("value line must contain the scalar 5");
    assert!(
        app.line_styles[line_idx]
            .iter()
            .any(|(range, role)| *role == SyntaxRole::Number && range.contains(&value_pos)),
        "expected a Number-colored span covering the '5' in {line:?}, got {:?}",
        app.line_styles[line_idx]
    );
}

/// A group field carrying a `tag_ohb` anomaly modifier keeps that
/// modifier verbatim after being overridden to a different type (spec
/// 0122 Test Plan item 2, 3rd bullet).
#[test]
fn splice_override_on_a_group_field_keeps_the_tag_ohb_modifier() {
    let (mut app, grp_idx) = group_type_fixture_with_tag_ohb();
    let header_before = app.lines[app.tree[grp_idx].span.text_range.start].clone();
    assert!(
        header_before.contains("tag_ohb: 1"),
        "fixture must exercise the anomaly modifier, got: {header_before:?}"
    );
    app.splice_override(grp_idx, Some("test.NewGroup".to_string()))
        .unwrap();
    let header = &app.lines[app.tree[grp_idx].span.text_range.start];
    assert!(
        header.contains("#@ group; NewGroup = 5; tag_ohb: 1"),
        "expected group; NewGroup = 5; tag_ohb: 1 in header, got: {header:?}"
    );
}

/// Overriding a `WT_LEN` (non-group) field to a resolvable type must
/// NOT show a `group;` prefix (spec 0122 Test Plan item 2, 2nd
/// bullet).
#[test]
fn splice_override_on_a_wt_len_field_has_no_group_prefix() {
    let (mut app, inner_idx, _) = type_as_fixture();
    app.splice_override(inner_idx, Some("test.Outer".to_string()))
        .unwrap();
    let header = &app.lines[app.tree[inner_idx].span.text_range.start];
    assert!(
        header.contains("#@ Outer = 1"),
        "expected Outer = 1 in header, got: {header:?}"
    );
    assert!(
        !header.contains("group;"),
        "WT_LEN field override must not show group;: {header:?}"
    );
}

/// A nested (non-root) field's header line must keep its leading
/// indentation after `splice_override` — the spec 0122 header-patching
/// rewrite of `new_lines[0]` must not drop the indentation the
/// synthetic wrapper's own render already computed via
/// `initial_level` (2026-07-15 regression: header lines of overridden
/// nested nodes lost their indentation while sibling/interior lines
/// stayed correctly indented).
#[test]
fn splice_override_preserves_the_header_line_indentation() {
    let (mut app, inner_idx, _) = type_as_fixture();
    let start = app.tree[inner_idx].span.text_range.start;
    let indent_before = app.lines[start].len() - app.lines[start].trim_start().len();
    app.splice_override(inner_idx, Some("test.Outer".to_string()))
        .unwrap();
    let header = &app.lines[app.tree[inner_idx].span.text_range.start];
    let indent_after = header.len() - header.trim_start().len();
    assert!(
        indent_after > 0,
        "fixture must exercise a nested (indented) field"
    );
    assert_eq!(
        indent_after, indent_before,
        "header line lost its indentation after splice_override: {header:?}"
    );
}

/// Reverting a group field's override (`target: None`) must restore
/// bare `#@ group` — the synthetic wrapper's `"message"` placeholder
/// must not leak into the header (spec 0122 Test Plan item 2, 4th
/// bullet; user-approved fix, 2026-07-15).
#[test]
fn splice_override_reverting_a_group_field_restores_bare_group() {
    let (mut app, grp_idx) = group_type_fixture();
    app.splice_override(grp_idx, Some("test.NewGroup".to_string()))
        .unwrap();
    app.splice_override(grp_idx, None).unwrap();
    let header = &app.lines[app.tree[grp_idx].span.text_range.start];
    assert!(
        header.contains("#@ group"),
        "expected bare group in header, got: {header:?}"
    );
    assert!(
        !header.contains("message"),
        "reverted group header must not leak the synthetic \"message\" placeholder: {header:?}"
    );
}

/// The document root is field number 1 of the virtual encompassing
/// message — a `splice_override`-driven re-render of the root (any
/// retype, not just the initial `decode()` paint) must keep showing
/// its field number in the header line, same as
/// `decode_shows_the_root_field_number_in_the_header_line`
/// (`decode.rs`) covers for the initial paint.
#[test]
fn splice_override_shows_the_root_field_number_in_the_header_line() {
    let (mut app, _, _) = type_as_fixture();
    app.splice_override(app.first_node, Some("test.Outer".to_string()))
        .unwrap();
    assert!(
        app.lines[0].starts_with("1 "),
        "root header line must show the root field number: {:?}",
        app.lines[0]
    );
}

/// Retyping the document root *raw* (no schema, `target: None`) must
/// also keep showing its field number in the header line — the root
/// is not special-cased regardless of `target`.
#[test]
fn splice_override_raw_root_shows_the_field_number_in_the_header_line() {
    let (mut app, _, _) = type_as_fixture();
    app.splice_override(app.first_node, None).unwrap();
    assert!(
        app.lines[0].starts_with("1 "),
        "raw root header line must show the field number: {:?}",
        app.lines[0]
    );
}

/// Reproduces interactive-testing feedback (2026-07-14, post-D34): a
/// root node retyped raw (`None`) then retyped back to a real schema
/// must still expand its `Any` descendants — a bare re-splice of the
/// root shouldn't lose `Any` expansion the *initial* `render_overrides`
/// pass (spec 0120) got right. Fixture mirrors `decode.rs`'s own
/// `decode_leaves_any_fields_unexpanded_with_real_type_url_and_value_spans`.
#[test]
fn splice_override_reactivating_root_type_still_expands_any_fields() {
    use prost::Message as _;
    use prost_types::field_descriptor_proto::{Label, Type};
    use prost_types::{
        DescriptorProto, FieldDescriptorProto, FileDescriptorProto, FileDescriptorSet,
    };

    use crate::decode::{decode, DescriptorContext};

    let any_msg = DescriptorProto {
        name: Some("Any".to_string()),
        field: vec![
            FieldDescriptorProto {
                name: Some("type_url".to_string()),
                number: Some(1),
                label: Some(Label::Optional as i32),
                r#type: Some(Type::String as i32),
                ..Default::default()
            },
            FieldDescriptorProto {
                name: Some("value".to_string()),
                number: Some(2),
                label: Some(Label::Optional as i32),
                r#type: Some(Type::Bytes as i32),
                ..Default::default()
            },
        ],
        ..Default::default()
    };
    let any_file = FileDescriptorProto {
        name: Some("google/protobuf/any.proto".to_string()),
        syntax: Some("proto3".to_string()),
        package: Some("google.protobuf".to_string()),
        message_type: vec![any_msg],
        ..Default::default()
    };

    let payload_msg = DescriptorProto {
        name: Some("Payload".to_string()),
        field: vec![FieldDescriptorProto {
            name: Some("label".to_string()),
            number: Some(1),
            label: Some(Label::Optional as i32),
            r#type: Some(Type::String as i32),
            ..Default::default()
        }],
        ..Default::default()
    };
    let container_msg = DescriptorProto {
        name: Some("Container".to_string()),
        field: vec![FieldDescriptorProto {
            name: Some("payload".to_string()),
            number: Some(1),
            label: Some(Label::Optional as i32),
            r#type: Some(Type::Message as i32),
            type_name: Some(".google.protobuf.Any".to_string()),
            ..Default::default()
        }],
        ..Default::default()
    };
    let acme_file = FileDescriptorProto {
        name: Some("acme.proto".to_string()),
        syntax: Some("proto2".to_string()),
        package: Some("acme".to_string()),
        dependency: vec!["google/protobuf/any.proto".to_string()],
        message_type: vec![payload_msg, container_msg],
        ..Default::default()
    };
    let fds = FileDescriptorSet {
        file: vec![any_file, acme_file],
    };

    let descriptor_path =
        std::env::temp_dir().join("protolens-tui-splice-any-reactivate-descriptor.pb");
    std::fs::write(&descriptor_path, fds.encode_to_vec()).unwrap();
    let mut ctx = DescriptorContext::load(&descriptor_path).unwrap();
    std::fs::remove_file(&descriptor_path).unwrap();

    // Container { payload: Any { type_url:
    // "type.googleapis.com/acme.Payload", value: Payload { label:
    // "hello" } } }.
    let label = b"hello";
    let mut payload_bytes = vec![0x0au8, label.len() as u8];
    payload_bytes.extend_from_slice(label);
    let type_url = b"type.googleapis.com/acme.Payload";
    let mut any_bytes = vec![0x0au8, type_url.len() as u8];
    any_bytes.extend_from_slice(type_url);
    any_bytes.push(0x12);
    any_bytes.push(payload_bytes.len() as u8);
    any_bytes.extend_from_slice(&payload_bytes);
    let mut blob = vec![0x0au8, any_bytes.len() as u8];
    blob.extend_from_slice(&any_bytes);

    let decoded = decode(&blob, &mut ctx, Some("acme.Container"), 2).unwrap();
    let mut app = App::new(
        decoded,
        "test.pb",
        PathBuf::from("test.pb"),
        2,
        ctx,
        ThemeKind::Dark,
    );
    app.splash = false;
    app.term_width = 120;

    // 1) retype the root raw (no schema) — mirrors the interactive
    //    "override / with raw/no-type" step, driven through the same
    //    `overrides.activate` + `render_overrides` path the `Enter`
    //    key handler uses in the override pane (not a bare
    //    `splice_override` call, which bypasses the recursive pass
    //    entirely and would miss this bug).
    let root_origin = override_pane::OverrideOrigin::Path {
        path: "/".to_string(),
    };
    app.overrides.activate(root_origin.clone(), None);
    app.render_overrides(app.first_node);
    // 2) retype the root back to the real schema — mirrors
    //    reactivating `acme.Container` in the management pane.
    app.overrides
        .activate(root_origin, Some("acme.Container".to_string()));
    app.render_overrides(app.first_node);

    assert!(
        app.tree
            .iter()
            .any(|n| n.span.type_fqdn.as_deref() == Some("acme.Payload")),
        "Any field must still expand after retyping the root away and \
         back: {:#?}",
        app.lines
    );
    assert!(
        app.lines
            .iter()
            .any(|l| l.contains("label") && l.contains("hello")),
        "expanded Any payload's own field must appear in the \
         re-spliced text: {:?}",
        app.lines
    );
}

/// Builds the shared `Container { extensions: TestMessageSet { Item {
/// type_id: 100, message: ExtPayload { label: "hi" } } } }` fixture
/// used by both the auto-expansion test and the toggle/reactivate
/// regression test below.
fn message_set_fixture() -> App {
    use prost::Message as _;
    use prost_types::descriptor_proto::ExtensionRange;
    use prost_types::field_descriptor_proto::{Label, Type};
    use prost_types::{
        DescriptorProto, FieldDescriptorProto, FileDescriptorProto, FileDescriptorSet,
        MessageOptions,
    };

    use crate::decode::{decode, DescriptorContext};

    let message_set_msg = DescriptorProto {
        name: Some("TestMessageSet".to_string()),
        options: Some(MessageOptions {
            message_set_wire_format: Some(true),
            ..Default::default()
        }),
        extension_range: vec![ExtensionRange {
            start: Some(1),
            end: Some(536870912),
            ..Default::default()
        }],
        ..Default::default()
    };
    let ext_payload_msg = DescriptorProto {
        name: Some("ExtPayload".to_string()),
        field: vec![FieldDescriptorProto {
            name: Some("label".to_string()),
            number: Some(1),
            label: Some(Label::Optional as i32),
            r#type: Some(Type::String as i32),
            ..Default::default()
        }],
        ..Default::default()
    };
    let extension_field = FieldDescriptorProto {
        name: Some("ext_payload".to_string()),
        number: Some(100),
        label: Some(Label::Optional as i32),
        r#type: Some(Type::Message as i32),
        type_name: Some(".ms_test.ExtPayload".to_string()),
        extendee: Some(".ms_test.TestMessageSet".to_string()),
        ..Default::default()
    };
    let container_msg = DescriptorProto {
        name: Some("Container".to_string()),
        field: vec![FieldDescriptorProto {
            name: Some("extensions".to_string()),
            number: Some(2),
            label: Some(Label::Optional as i32),
            r#type: Some(Type::Message as i32),
            type_name: Some(".ms_test.TestMessageSet".to_string()),
            ..Default::default()
        }],
        ..Default::default()
    };
    let file = FileDescriptorProto {
        name: Some("ms_test.proto".to_string()),
        syntax: Some("proto2".to_string()),
        package: Some("ms_test".to_string()),
        message_type: vec![message_set_msg, ext_payload_msg, container_msg],
        extension: vec![extension_field],
        ..Default::default()
    };
    let fds = FileDescriptorSet { file: vec![file] };

    // Unique per call (this fixture is shared by several tests that
    // may run concurrently) to avoid one test's cleanup racing
    // another's read of the same path.
    static COUNTER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let descriptor_path = std::env::temp_dir().join(format!(
        "protolens-tui-message-set-expand-descriptor-{n}.pb"
    ));
    std::fs::write(&descriptor_path, fds.encode_to_vec()).unwrap();
    let mut ctx = DescriptorContext::load(&descriptor_path).unwrap();
    std::fs::remove_file(&descriptor_path).unwrap();

    // Container { extensions: TestMessageSet {
    //   Item { type_id: 100, message: ExtPayload { label: "hi" } }
    // } }.
    let ext_payload_bytes = [0x0au8, 0x02, b'h', b'i'];
    let mut item_bytes = vec![0x0bu8, 0x10, 100u8];
    item_bytes.push(0x1a);
    item_bytes.push(ext_payload_bytes.len() as u8);
    item_bytes.extend_from_slice(&ext_payload_bytes);
    item_bytes.push(0x0c); // END_GROUP
    let mut blob = vec![0x12u8, item_bytes.len() as u8];
    blob.extend_from_slice(&item_bytes);

    let decoded = decode(&blob, &mut ctx, Some("ms_test.Container"), 2).unwrap();
    let mut app = App::new(
        decoded,
        "test.pb",
        PathBuf::from("test.pb"),
        2,
        ctx,
        ThemeKind::Dark,
    );
    app.splash = false;
    app.term_width = 120;
    app
}

/// Regression test (spec 0120 §G2, post-bugfix): a MessageSet's
/// group-wire "Item" entries (field 1, `WT_START_GROUP`) must be
/// decomposed via the two-tier auto-expansion (tier 1: synthetic
/// `protolens_internal.MessageSetItem`; tier 2: the specific
/// extension type resolved from `type_id`) through `render_overrides`
/// — not corrupted into a flat raw scalar, which is what happened
/// before the fix (`render_overrides`'s `is_message` recursion gate
/// unconditionally spliced the group node with no matching tier,
/// poisoning the render via `extract::message_payload_range`'s
/// documented "leaves the trailing END_GROUP tag" behavior for
/// `WT_START_GROUP`). Also asserts both tiers land as real,
/// persisted, active `OverrideEntry` rows (spec 0120 redesign: no
/// longer a silent dynamic fallback).
#[test]
fn message_set_group_items_auto_expand_through_render_overrides() {
    let app = message_set_fixture();

    assert!(
        app.tree
            .iter()
            .any(|n| n.span.type_fqdn.as_deref() == Some("ms_test.ExtPayload")),
        "MessageSet Item's message must auto-expand to the resolved \
         extension type: {:#?}",
        app.lines
    );
    assert!(
        app.lines
            .iter()
            .any(|l| l.contains("label") && l.contains("hi")),
        "expanded MessageSet extension payload's own field must appear \
         in the spliced text: {:?}",
        app.lines
    );

    let item_idx = app
        .tree
        .iter()
        .position(|n| n.span.type_fqdn.as_deref() == Some(decode::MESSAGE_SET_ITEM_FQDN))
        .expect("Item group must be spliced to the synthetic MessageSetItem type");
    let item_path = app.positional_path(item_idx);
    assert!(
        app.overrides.entries().iter().any(|e| {
            e.active
                && matches!(&e.origin, OverrideOrigin::Path { path } if *path == item_path)
                && e.r#type.as_deref() == Some(decode::MESSAGE_SET_ITEM_FQDN)
        }),
        "tier-1 auto-expansion must be a real, persisted, active \
         override entry: {:#?}",
        app.overrides.entries()
    );
    assert!(
        app.overrides.entries().iter().any(|e| {
            matches!(&e.origin, OverrideOrigin::Path { path } if *path == item_path)
                && e.name.as_deref() == Some("Item")
        }),
        "tier-1 auto-expansion must be seeded with the display name \
         \"Item\" (mirroring prototext-core's native MessageSet \
         rendering), not the bare field number: {:#?}",
        app.overrides.entries()
    );
    assert!(
        app.lines
            .iter()
            .any(|l| l.trim_start().starts_with("Item {")),
        "the Item wrapper must render under the name \"Item\", not \
         its field number: {:?}",
        app.lines
    );

    let message_idx = app
        .tree
        .iter()
        .position(|n| n.span.type_fqdn.as_deref() == Some("ms_test.ExtPayload"))
        .expect("message field must resolve to ExtPayload");
    let message_path = app.positional_path(message_idx);
    assert!(
        app.overrides.entries().iter().any(|e| {
            e.active
                && matches!(&e.origin, OverrideOrigin::Path { path } if *path == message_path)
                && e.r#type.as_deref() == Some("ms_test.ExtPayload")
        }),
        "tier-2 auto-expansion must be a real, persisted, active \
         override entry: {:#?}",
        app.overrides.entries()
    );
}

/// Regression test (spec 0132 §G3 feedback, 2026-07-15): opening the
/// override pane on an ancestor of a MessageSet's `Item` group live-
/// previews that ancestor's subtree via a bare `splice_override`
/// call (§G2 non-goal: "no live nested Any/MessageSet preview"),
/// which discards the tier-1/tier-2 auto-expansion of every
/// descendant. Cancelling with `Esc` must fully restore it — not
/// just re-settle the ancestor node itself back to its own correct
/// type, but re-run the whole `render_overrides` recursion so
/// `ExtPayload` gets re-expanded too.
#[test]
fn esc_closing_the_override_pane_restores_nested_message_set_auto_expansion() {
    let mut app = message_set_fixture();
    let extensions_idx = app
        .tree
        .iter()
        .position(|n| n.span.type_fqdn.as_deref() == Some("ms_test.TestMessageSet"))
        .expect("extensions field must resolve to TestMessageSet");
    app.cursor = extensions_idx;

    app.handle_key(KeyEvent::new(KeyCode::Char('t'), KeyModifiers::NONE));
    assert_eq!(app.override_target, Some(extensions_idx));
    // The live preview's own `splice_override` call rebuilds the
    // subtree from scratch with no per-descendant overrides applied
    // (§G2 non-goal) — the rendered text must no longer show the
    // nested expansion for the duration of the pane being open.
    // (`splice_override` never removes orphaned descendant entries
    // from the flat `tree` Vec, only unlinks them — so `app.tree`
    // itself is not a reliable signal here; `app.lines`, what's
    // actually displayed, is.)
    assert!(
        !app.lines.iter().any(|l| l.contains("label")),
        "live preview must not still show the nested auto-expansion: {:?}",
        app.lines
    );

    app.handle_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
    assert_eq!(app.override_target, None);
    assert!(
        app.tree
            .iter()
            .any(|n| n.span.type_fqdn.as_deref() == Some("ms_test.ExtPayload")),
        "Esc-cancel must restore the nested MessageSet auto-expansion: {:#?}",
        app.lines
    );
    assert!(
        app.lines
            .iter()
            .any(|l| l.contains("label") && l.contains("hi")),
        "expanded MessageSet extension payload's own field must be back \
         in the rendered text: {:?}",
        app.lines
    );
}

/// Regression test for a bug found while implementing spec 0123's
/// test plan: `load_overrides` (`:restore-overrides`/batch
/// `--load-overrides`) wholesale-replaces `self.overrides` (spec
/// 0117 §4), which used to silently drop the document root's own
/// `seed_root` entry whenever the loaded file didn't carry one
/// itself (the normal case — nobody manually saves a `path: "/"`
/// override). Root's type is external input (CLI `--type`/auto-
/// inference) with no schema-derived fallback (`natural_type` has no
/// parent field descriptor to consult for the root), so losing it
/// reverted root to raw rendering — which cascaded: every ordinary,
/// never-explicitly-overridden descendant's own `natural_type` walks
/// up through its parent's *resolved* type to find its field's
/// schema type, so the whole document (not just root) went raw, and
/// spec 0120's tier-2 MessageSet auto-expansion candidacy gate
/// (which needs its un-overridden grandparent to still resolve as
/// MessageSet-typed) silently stopped firing even when its own
/// override entry was present, correct, and active. Fixed by
/// preserving the currently-resolved root type across the replace
/// when the loaded file doesn't define its own.
#[test]
fn load_overrides_without_a_root_entry_preserves_the_current_root_type() {
    let mut app = message_set_fixture();
    let (blob_sha256, descriptor_set_sha256) = app.target_hashes();

    // Deliberately omits any `path: "/"` entry — exactly the shape a
    // real `:save-overrides` produces is *not* what's being tested
    // here (that's covered by `save_and_restore_overrides_round_trips
    // _and_drops_unresolvable_entries`); this reproduces a
    // hand-authored/edited file, or any file saved before root ever
    // carried a resolved type.
    let yaml = format!(
        "version: 1\n\
         target:\n\
         \x20 blob_sha256: \"{blob_sha256}\"\n\
         \x20 descriptor_set_sha256: \"{descriptor_set_sha256}\"\n\
         overrides:\n\
         \x20 - path: \"/1/1\"\n\
         \x20   type: protolens_internal.MessageSetItem\n\
         \x20   active: true\n\
         \x20   name: Item\n\
         \x20 - path: \"/1/1/2\"\n\
         \x20   type: ms_test.ExtPayload\n\
         \x20   active: true\n"
    );
    static COUNTER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let path = std::env::temp_dir()
        .join(format!("protolens-tui-load-overrides-no-root-{n}.yaml"))
        .to_string_lossy()
        .into_owned();
    std::fs::write(&path, &yaml).unwrap();
    let warnings = app.load_overrides(&path).unwrap();
    std::fs::remove_file(&path).unwrap();

    assert!(warnings.is_empty(), "{warnings:?}");
    assert!(
        app.tree[app.first_node].span.type_fqdn.as_deref() == Some("ms_test.Container"),
        "root must keep its resolved type across a wholesale \
         override-collection replace, even though the loaded file \
         defines no root entry of its own: {:#?}",
        app.lines
    );
    assert!(
        app.lines
            .iter()
            .any(|l| l.contains("label") && l.contains("hi")),
        "tier-2 MessageSet auto-expansion must still take effect \
         after --load-overrides, not just tier-1: {:#?}",
        app.lines
    );
}

/// Round-trip regression test (spec 0122 Test Plan item 3 — the
/// original reported bug's exact scenario): decode a MessageSet
/// fixture, let `App::new`'s automatic Any/MessageSet overrides
/// (spec 0120) apply, extract the root as `#@ prototext` text (spec
/// 0123's batch-mode rendering), `encode_text_to_binary` it back to
/// binary, and assert byte-for-byte equality with the original blob.
/// Before spec 0122's fix, `splice_override`'s synthetic `WT_LEN`-only
/// re-decode dropped the MessageSet `Item` group's `#@ group`
/// annotation, so re-encoding lost the group's wire framing entirely.
#[test]
fn round_trip_extract_and_encode_preserves_message_set_group_framing() {
    let app = message_set_fixture();
    let root_idx = app.resolve_path("/").expect("tree must have a root");
    let text = app.extract_bytes(root_idx, ExtractFormat::Text);
    let reencoded = prototext_core::serialize::encode_text::encode_text_to_binary(&text);
    let original = &app.blob[app.wrapper_offset..];
    assert_eq!(
        reencoded, original,
        "round-trip through extract+encode must byte-for-byte match \
         the original blob"
    );
}

/// Regression test for the manage-pane toggle/reactivate bug reported
/// against spec 0120's auto-expansion seeding: deactivating a
/// MessageSet tier-1 (`MessageSetItem`) auto-derived override via
/// `toggle_active` (the manage pane's `a`/Space key) must actually
/// stick across a `render_overrides` pass — not be silently
/// resurrected, which is what happened when the seeding condition in
/// `render_overrides` only checked "no active override currently
/// resolves" rather than "no entry exists yet for this origin at
/// all". Also asserts that reactivating it re-splices the Item's
/// payload back to the expanded `ExtPayload` form.
#[test]
fn toggling_message_set_auto_override_off_and_on_sticks() {
    let mut app = message_set_fixture();

    let item_idx = app
        .tree
        .iter()
        .position(|n| n.span.type_fqdn.as_deref() == Some(decode::MESSAGE_SET_ITEM_FQDN))
        .expect("Item group must be spliced to the synthetic MessageSetItem type");
    let item_path = app.positional_path(item_idx);
    let entry_idx = app
        .overrides
        .entries()
        .iter()
        .position(|e| matches!(&e.origin, OverrideOrigin::Path { path } if *path == item_path))
        .expect("tier-1 entry must exist");

    // Deactivate, then re-render: the entry must stay inactive (not
    // be re-seeded), and the Item node must revert to its natural
    // (un-overridden) type.
    app.overrides.toggle_active(entry_idx);
    app.render_overrides(app.first_node);
    assert!(
        !app.overrides.entries()[entry_idx].active,
        "deactivating the tier-1 override must stick across a render \
         pass, not self-heal back to active: {:#?}",
        app.overrides.entries()
    );
    assert_eq!(
        app.tree[item_idx].span.type_fqdn.as_deref(),
        None,
        "Item node must render raw/natural once its override is \
         deactivated: {:#?}",
        app.lines
    );

    // Reactivate: the same entry (same index — `toggle_active` never
    // resorts) must come back active, and the Item's payload must
    // re-expand to ExtPayload.
    app.overrides.toggle_active(entry_idx);
    app.render_overrides(app.first_node);
    assert!(
        app.overrides.entries()[entry_idx].active,
        "reactivating the tier-1 override must stick: {:#?}",
        app.overrides.entries()
    );
    assert_eq!(
        app.tree[item_idx].span.type_fqdn.as_deref(),
        Some(decode::MESSAGE_SET_ITEM_FQDN),
        "Item node must re-expand once its override is reactivated: \
         {:#?}",
        app.lines
    );
    assert!(
        app.tree
            .iter()
            .any(|n| n.span.type_fqdn.as_deref() == Some("ms_test.ExtPayload")),
        "tier-2 auto-expansion must also come back after reactivating \
         tier-1: {:#?}",
        app.lines
    );
}

/// Regression test (2026-07-14 interactive feedback): deactivating a
/// MessageSet's tier-1 (`Item`) auto-derived override must also stop
/// honoring its tier-2 (`message`) auto-derived override, even though
/// the tier-2 entry itself is never touched — its derivation
/// (looking up the extension type from `type_id`) is only valid
/// while its parent still resolves as `MessageSetItem`, so it must
/// demote alongside its ancestor rather than keep rendering the stale
/// extension type. Previously, only deactivating an *outer* ancestor
/// override (e.g. an enclosing `Any`) cleared it — deactivating the
/// immediate tier-1 `Item` alone was not enough.
#[test]
fn deactivating_tier_1_demotes_the_still_active_tier_2_entry() {
    let mut app = message_set_fixture();

    let item_idx = app
        .tree
        .iter()
        .position(|n| n.span.type_fqdn.as_deref() == Some(decode::MESSAGE_SET_ITEM_FQDN))
        .expect("Item group must be spliced to the synthetic MessageSetItem type");
    let item_path = app.positional_path(item_idx);
    let item_entry_idx = app
        .overrides
        .entries()
        .iter()
        .position(|e| matches!(&e.origin, OverrideOrigin::Path { path } if *path == item_path))
        .expect("tier-1 entry must exist");
    let message_idx = app
        .tree
        .iter()
        .position(|n| n.span.type_fqdn.as_deref() == Some("ms_test.ExtPayload"))
        .expect("message field must resolve to ExtPayload");
    let message_path = app.positional_path(message_idx);
    let message_entry_idx = app
        .overrides
        .entries()
        .iter()
        .position(|e| matches!(&e.origin, OverrideOrigin::Path { path } if *path == message_path))
        .expect("tier-2 entry must exist");

    // Deactivate tier-1 only — tier-2's own entry is left untouched.
    app.overrides.toggle_active(item_entry_idx);
    app.render_overrides(app.first_node);

    assert!(
        app.overrides.entries()[message_entry_idx].active,
        "tier-2's own entry must remain active (untouched by \
         deactivating tier-1) — demotion must not mutate `active`: \
         {:#?}",
        app.overrides.entries()
    );
    // `app.tree` retains splice-abandoned/orphaned entries (never
    // referenced again but never removed from the `Vec` either — see
    // `splice_override`'s "abandon in place" pattern), so checking
    // for absence must go through the *rendered* text (`app.lines`),
    // which only ever reflects the current, live splice — not
    // `app.tree.iter()`, which could still find the old, no-longer-
    // reachable `ExtPayload` node from before this deactivation.
    assert!(
        !app.lines.iter().any(|l| l.contains("ExtPayload")),
        "tier-2's stale extension-type annotation must disappear \
         once its governing tier-1 ancestor is deactivated: {:?}",
        app.lines
    );

    // Reactivating tier-1 must bring tier-2 back without touching
    // tier-2's own entry.
    app.overrides.toggle_active(item_entry_idx);
    app.render_overrides(app.first_node);
    assert!(
        app.tree
            .iter()
            .any(|n| n.span.type_fqdn.as_deref() == Some("ms_test.ExtPayload")),
        "tier-2 must resume once its tier-1 ancestor is reactivated: \
         {:?}",
        app.lines
    );
}

/// Spec 0113 D33: the bold override hint applies to a node's own
/// header and (when it has children) footer line, but must not
/// cascade to descendant lines.
#[test]
fn line_has_active_override_marks_header_and_footer_but_not_children() {
    let (mut app, inner_idx, id_idx) = type_as_fixture();
    app.cursor = inner_idx;
    app.run_command("type-as test.Inner");
    assert_eq!(
        app.tree[inner_idx].span.type_fqdn.as_deref(),
        Some("test.Inner")
    );

    let header_line = app.tree[inner_idx].span.text_range.start;
    let footer_line = app.tree[inner_idx].span.text_range.end - 1;
    assert!(app.line_has_active_override(header_line));
    assert!(app.line_has_active_override(footer_line));

    let id_line = app.tree[id_idx].span.text_range.start;
    assert!(!app.line_has_active_override(id_line));
}

/// Spec 0114 §7: `:type-as <FQDN>` applies the override directly to
/// the cursor node, bypassing the override pane entirely — it must
/// never open (`override_target` stays `None` throughout).
#[test]
fn type_as_command_applies_override_bypassing_pane() {
    let (mut app, inner_idx, _) = type_as_fixture();
    app.cursor = inner_idx;
    app.run_command("type-as test.Inner");
    assert!(
        app.override_target.is_none(),
        "the pane must never open for :type-as"
    );
    assert_eq!(
        app.tree[inner_idx].span.type_fqdn.as_deref(),
        Some("test.Inner")
    );
    assert!(app.message.contains("test.Inner"));
}

/// Spec 0114 §7: `:type-as-raw` marks the cursor node's range as
/// explicitly raw, bypassing the pane.
#[test]
fn type_as_raw_command_marks_raw() {
    let (mut app, inner_idx, _) = type_as_fixture();
    app.cursor = inner_idx;
    app.run_command("type-as-raw");
    assert!(app.override_target.is_none());
    assert_eq!(app.tree[inner_idx].span.type_fqdn, None);
}

/// Spec 0114 §7/§5 step 1: `:type-as` on an ineligible node (neither
/// message/group nor length-delimited scalar) is refused with the
/// same message `t` gives.
#[test]
fn type_as_command_rejects_non_message_node() {
    let (mut app, _, id_idx) = type_as_fixture();
    app.cursor = id_idx;
    app.run_command("type-as test.Inner");
    assert!(
        app.message
            .contains("cannot override: not a message/group or length-delimited field"),
        "unexpected message: {}",
        app.message
    );
}

/// Spec 0114 §7: once the command-name token has unambiguously
/// resolved to `type-as`, `Tab` completes its FQDN argument against
/// `all_type_fqdns`.
#[test]
fn tab_completes_type_as_fqdn_argument() {
    let (mut app, _, _) = type_as_fixture();
    app.handle_key(KeyEvent::new(KeyCode::Char(':'), KeyModifiers::NONE));
    for c in "type-as test.In".chars() {
        app.handle_key(KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE));
    }
    app.handle_key(KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE));
    assert_eq!(app.command_buffer.as_deref(), Some("type-as test.Inner"));
}

/// Spec 0117 §4: `resolve_path` is the inverse of `positional_path`
/// for every node reachable from the root, and `None` for a path that
/// doesn't resolve against the current tree.
#[test]
fn resolve_path_is_the_inverse_of_positional_path() {
    let (app, inner_idx, id_idx) = type_as_fixture();
    let outer_idx = app
        .tree
        .iter()
        .position(|n| n.parent.is_none())
        .expect("tree must have a wrapper root");
    assert_eq!(
        app.resolve_path(&app.positional_path(outer_idx)),
        Some(outer_idx)
    );
    assert_eq!(
        app.resolve_path(&app.positional_path(inner_idx)),
        Some(inner_idx)
    );
    assert_eq!(app.resolve_path(&app.positional_path(id_idx)), Some(id_idx));
    assert_eq!(app.resolve_path("/99"), None);
}

/// Spec 0117 §4's restore-time validation: `origin_resolves` checks
/// each of the three origin kinds against the current tree/descriptor
/// pool.
#[test]
fn origin_resolves_checks_path_field_and_fqdn_field_origins() {
    let (app, inner_idx, _) = type_as_fixture();
    let inner_path = app.positional_path(inner_idx);

    assert!(app.origin_resolves(&OverrideOrigin::Path {
        path: inner_path.clone()
    }));
    assert!(!app.origin_resolves(&OverrideOrigin::Path {
        path: "/99".to_string()
    }));

    assert!(app.origin_resolves(&OverrideOrigin::PathField {
        path: inner_path.clone(),
        field: 1,
    }));
    assert!(!app.origin_resolves(&OverrideOrigin::PathField {
        path: inner_path,
        field: 99,
    }));

    assert!(app.origin_resolves(&OverrideOrigin::FqdnField {
        fqdn: "test.Inner".to_string(),
        field: 1,
    }));
    assert!(!app.origin_resolves(&OverrideOrigin::FqdnField {
        fqdn: "test.Inner".to_string(),
        field: 99,
    }));
    assert!(!app.origin_resolves(&OverrideOrigin::FqdnField {
        fqdn: "test.NoSuchType".to_string(),
        field: 1,
    }));
}

/// Spec 0117 §4: `default_save_overrides_path` mirrors
/// `default_extract_path`'s directory/stem derivation, but always
/// with a `.yaml` extension.
#[test]
fn default_save_overrides_path_uses_blob_stem_with_yaml_extension() {
    let (mut app, _, _) = type_as_fixture();
    app.blob_path = PathBuf::from("/tmp/some/target.pb");
    assert_eq!(app.default_save_overrides_path(), "/tmp/some/target.yaml");
}

/// Spec 0117 §4: `:save-overrides`/`:restore-overrides` round-trip the
/// collection through YAML, and restore silently drops an entry whose
/// origin no longer resolves against the current tree.
#[test]
fn save_and_restore_overrides_round_trips_and_drops_unresolvable_entries() {
    let (mut app, inner_idx, _) = type_as_fixture();
    app.overrides.activate(
        OverrideOrigin::PathField {
            path: app.positional_path(inner_idx),
            field: 1,
        },
        Some("test.Inner".to_string()),
    );
    // Doesn't resolve against this tree — must be dropped on restore.
    app.overrides.activate(
        OverrideOrigin::Path {
            path: "/99".to_string(),
        },
        None,
    );
    assert_eq!(app.overrides.entries().len(), 3); // root + the two above

    static COUNTER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let path = std::env::temp_dir()
        .join(format!("protolens-tui-save-restore-{n}.yaml"))
        .to_string_lossy()
        .into_owned();

    app.run_save_overrides(vec![&path]);
    assert!(
        app.message.starts_with("saved overrides to"),
        "unexpected message: {}",
        app.message
    );

    app.overrides = override_pane::OverrideCollection::new();
    app.run_restore_overrides(vec![&path]);
    std::fs::remove_file(&path).unwrap();

    assert!(
        app.message.starts_with("restored overrides from"),
        "unexpected message: {}",
        app.message
    );
    assert!(
        !app.message.contains("warning"),
        "unexpected warning: {}",
        app.message
    );
    assert_eq!(app.overrides.entries().len(), 2); // "/99" silently dropped
    assert!(!app
        .overrides
        .entries()
        .iter()
        .any(|e| matches!(&e.origin, OverrideOrigin::Path { path } if path == "/99")));
}

/// Spec 0117 §4: a target-hash mismatch on restore warns in the
/// message line but does not block the restore.
#[test]
fn restore_overrides_warns_on_hash_mismatch_without_blocking() {
    let (mut app, _, _) = type_as_fixture();
    let yaml = app
        .overrides
        .to_yaml("deadbeef".to_string(), "deadbeef".to_string());

    static COUNTER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let path = std::env::temp_dir()
        .join(format!("protolens-tui-restore-hash-mismatch-{n}.yaml"))
        .to_string_lossy()
        .into_owned();
    std::fs::write(&path, &yaml).unwrap();

    app.run_restore_overrides(vec![&path]);
    std::fs::remove_file(&path).unwrap();

    assert!(app.message.contains("warning"), "{}", app.message);
    assert!(app.message.contains("blob hash mismatch"));
    assert!(app.message.contains("descriptor-set hash mismatch"));
    assert_eq!(app.overrides.entries().len(), 1); // restore still applied
}

/// Spec 0117 §4: `Tab` completes `:save-overrides`/`:restore-overrides`'s
/// path argument against real directory entries, cycling on the
/// longest common prefix — no `!arg_prefix.contains(' ')` restriction,
/// unlike `:type-as`'s FQDN completer.
#[test]
fn tab_completes_filesystem_path_for_save_overrides_argument() {
    let (mut app, _, _) = type_as_fixture();
    let dir =
        std::env::temp_dir().join(format!("protolens-tui-fs-complete-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("alpha.yaml"), b"").unwrap();
    std::fs::write(dir.join("alphabet.yaml"), b"").unwrap();

    let prefix = format!("save-overrides {}/al", dir.to_string_lossy());
    app.handle_key(KeyEvent::new(KeyCode::Char(':'), KeyModifiers::NONE));
    for c in prefix.chars() {
        app.handle_key(KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE));
    }
    app.handle_key(KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE));
    let expected = format!("save-overrides {}/alpha", dir.to_string_lossy());
    assert_eq!(app.command_buffer.as_deref(), Some(expected.as_str()));

    std::fs::remove_dir_all(&dir).unwrap();
}
