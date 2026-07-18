// SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

use super::super::*;
use super::support::*;

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

/// Item 13 of 2026-07-17 feedback: the startup splash auto-dismisses
/// once `SPLASH_TIMEOUT` has elapsed, in addition to its existing
/// keypress/mouse dismissal — detected by `track_splash_timeout`
/// (called from `render`) noticing an expired `splash_deadline`.
#[test]
fn splash_auto_dismisses_after_timeout() {
    let mut app = empty_app();
    let backend = TestBackend::new(80, 24);
    let mut terminal = Terminal::new(backend).unwrap();

    assert!(app.splash);
    terminal.draw(|frame| app.render(frame)).unwrap();
    // Not yet expired: still showing on a later render.
    assert!(app.splash);

    // Force expiry (real time never actually elapses in a unit test).
    app.splash_deadline = Instant::now() - Duration::from_millis(1);
    terminal.draw(|frame| app.render(frame)).unwrap();
    assert!(!app.splash);
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

/// Spec 0133 G3/G4: the main-pane `a` key toggles display of each
/// line's trailing `#@ ...` annotation, purely at render time — the
/// underlying `self.lines`/`self.line_styles` are untouched, so
/// toggling `a` twice restores byte-for-byte identical rendering.
/// Distinct from the override pane's own `i` (candidate sort,
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

/// 2026-07-18 feedback: when the cursor rests on a node's own closing
/// `}` line (spec 0142), the status line's `L<n>` must report the
/// footer line's own number, not the header's.
#[test]
fn status_line_reports_the_footer_line_number_for_a_footer_resting_cursor() {
    let (mut app, inner_idx, _id_idx) = type_as_fixture();
    app.splash = false;

    let footer_line = app.tree[inner_idx].span.text_range.end - 1;
    app.cursor = inner_idx;
    app.cursor_footer = true;

    let backend = TestBackend::new(80, 24);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|frame| app.render(frame)).unwrap();

    let buffer = terminal.backend().buffer();
    let text: String = buffer.content.iter().map(|c| c.symbol()).collect();
    assert!(
        text.contains(&format!("L{}/", footer_line + 1)),
        "status line must report the footer's own 1-based line number: {text:?}"
    );
}
