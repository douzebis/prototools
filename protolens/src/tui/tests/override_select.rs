// SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

use super::super::*;
use super::support::*;

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
        None,
    );
    app.splash = false;
    app.term_width = 120;

    app.handle_key(KeyEvent::new(KeyCode::Char('t'), KeyModifiers::NONE));
    assert_eq!(app.override_target, Some(0));
    assert!(app.override_focus);
}

/// Spec 0135 §G3 (test plan item 12): `can_override`/`t` now accept a
/// plain `WT_VARINT` scalar node too — a wire-compatible primitive
/// override target (`:type-as sint32`, etc.) is available for it, so it
/// is no longer treated as ineligible the way it was pre-0135.
#[test]
fn t_opens_the_override_pane_on_a_varint_scalar_field() {
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
        // Tag `0x08` = field 1 << 3 | WT_VARINT(0), value varint `0x01`
        // — a real, `raw_range`-consistent blob, needed since spec 0132's
        // live preview now splices this node's contents at pane-open
        // time.
        blob: vec![0x08, 0x01],
        wrapper_offset: 0,
        style_hints: vec![Vec::new()],
    };
    let mut app = App::new(
        decoded,
        "test.pb",
        PathBuf::from("test.pb"),
        2,
        DescriptorContext::empty_for_test(),
        ThemeKind::Dark,
        None,
    );
    app.splash = false;
    app.term_width = 120;

    app.handle_key(KeyEvent::new(KeyCode::Char('t'), KeyModifiers::NONE));
    assert_eq!(app.override_target, Some(0));
    assert!(app.override_focus);
}

/// Regression test (spec 0135 follow-up, 2026-07-17): pressing `t` on
/// a plain primitive (non-message) field, then immediately `Esc`
/// (cancelling, no navigation in between), must leave the main-pane
/// rendering exactly as it was before `t` was pressed. Root-caused to
/// `natural_type` returning `None` for every non-message field kind,
/// which `resettle_node`'s no-active-override fallback treated as
/// "render raw" rather than "this field's own natural primitive
/// type" — reachable only once spec 0135 §G3 widened `can_override`
/// to plain scalar leaves in the first place.
#[test]
fn esc_after_t_on_a_primitive_field_restores_its_original_rendering() {
    let (mut app, _, id_idx) = type_as_fixture();
    app.cursor = id_idx;
    let line_idx = app.tree[id_idx].span.text_range.start;
    let original_line = app.lines[line_idx].clone();

    app.handle_key(KeyEvent::new(KeyCode::Char('t'), KeyModifiers::NONE));
    assert_eq!(app.override_target, Some(id_idx));

    app.handle_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
    assert_eq!(app.override_target, None);
    assert_eq!(
        app.lines[line_idx], original_line,
        "the field's rendering must be restored exactly, not left raw"
    );
}

/// Spec 0139 Step B.5 (2026-07-18 feedback): `t` on an enum-typed
/// scalar field with no active/matching override entry must open in
/// `Lexicographic` mode (no enum candidate can ever appear in
/// `Inferred` mode's message-shaped scoring) with the highlight
/// already on the field's own natural enum type — not the `None`
/// sentinel row.
#[test]
fn t_opens_on_an_enum_field_highlighting_its_own_natural_type() {
    let (mut app, durability_idx) = enum_field_fixture();
    app.cursor = durability_idx;

    app.handle_key(KeyEvent::new(KeyCode::Char('t'), KeyModifiers::NONE));
    assert_eq!(app.override_sort, SortMode::Lexicographic);
    assert_eq!(
        app.override_candidates[app.override_highlight].0,
        "test.Durability"
    );
}

/// Regression test (2026-07-18 feedback): pressing `t` on an
/// enum-typed scalar field, then immediately `Esc`, must leave the
/// main-pane rendering exactly as it was before `t` was pressed —
/// same bug class as `esc_after_t_on_a_primitive_field_...` above,
/// but for `Kind::Enum`, which `natural_type` excluded until this
/// fix (`resettle_node`'s no-active-override fallback demoted the
/// field to a raw record dump, permanently, since no other render
/// pass ever revisits a plain scalar leaf).
#[test]
fn esc_after_t_on_an_enum_field_restores_its_original_rendering() {
    let (mut app, durability_idx) = enum_field_fixture();
    app.cursor = durability_idx;
    let line_idx = app.tree[durability_idx].span.text_range.start;
    let original_line = app.lines[line_idx].clone();

    app.handle_key(KeyEvent::new(KeyCode::Char('t'), KeyModifiers::NONE));
    assert_eq!(app.override_target, Some(durability_idx));

    app.handle_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
    assert_eq!(app.override_target, None);
    assert_eq!(
        app.lines[line_idx], original_line,
        "the enum field's rendering must be restored exactly, not left raw"
    );
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
        None,
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

/// Spec 0114 §3.2: `i` toggles between the two sort modes. (Which mode
/// `t` opens the pane in initially is spec 0139's smart-open logic,
/// covered by its own tests below — `message_node_app` has no scoring
/// graph, so `t` opens directly in `Lexicographic` mode, spec 0139
/// G3.)
#[test]
fn override_i_toggles_the_sort_mode() {
    let mut app = message_node_app();
    app.splash = false;
    app.term_width = 120;
    app.handle_key(KeyEvent::new(KeyCode::Char('t'), KeyModifiers::NONE));
    assert_eq!(app.override_sort, SortMode::Lexicographic);

    app.handle_key(KeyEvent::new(KeyCode::Char('i'), KeyModifiers::NONE));
    assert_eq!(app.override_sort, SortMode::Inferred);

    app.handle_key(KeyEvent::new(KeyCode::Char('i'), KeyModifiers::NONE));
    assert_eq!(app.override_sort, SortMode::Lexicographic);
}

/// Spec 0139 Step A + mode-selection rule: an active override whose
/// type is a primitive keyword can never be present in the inferred
/// candidate list (by construction — `inferred_candidates` only ever
/// produces message/enum FQDNs), so `t` must fall through to opening
/// in `Lexicographic` mode with the highlight on that keyword's row.
#[test]
fn t_opens_on_active_primitive_override_in_lexicographic_mode() {
    let mut app = message_node_app();
    app.splash = false;
    app.term_width = 120;

    let origin = app.override_origin_for_kind(app.cursor).unwrap();
    app.overrides.activate(origin, Some("fixed32".to_string()));

    app.handle_key(KeyEvent::new(KeyCode::Char('t'), KeyModifiers::NONE));
    assert_eq!(app.override_sort, SortMode::Lexicographic);
    assert_eq!(app.override_candidates[app.override_highlight].0, "fixed32");
}

/// Spec 0139 Step A + mode-selection rule: an active override typed
/// raw (`Option::None`) opens in `Lexicographic` mode with the
/// highlight on the `None` sentinel row.
#[test]
fn t_opens_on_active_raw_override_on_the_none_sentinel_row() {
    let mut app = message_node_app();
    app.splash = false;
    app.term_width = 120;

    let origin = app.override_origin_for_kind(app.cursor).unwrap();
    app.overrides.activate(origin, None);

    app.handle_key(KeyEvent::new(KeyCode::Char('t'), KeyModifiers::NONE));
    assert_eq!(app.override_sort, SortMode::Lexicographic);
    assert_eq!(
        app.override_candidates[app.override_highlight].0,
        "protolens_internal.None"
    );
}

/// Spec 0139 Step B: no override is active for the cursor node, but
/// the management list holds an inactive entry whose origin exactly
/// matches it — `t` picks up that entry's type and applies the same
/// mode-selection rule as an active override would (spec 0139 §G1
/// "apply the rules of the preceding point").
#[test]
fn t_opens_on_first_inactive_matching_entry_when_none_is_active() {
    let mut app = message_node_app();
    app.splash = false;
    app.term_width = 120;
    // Drop the seeded root entry first — it shares this fixture's only
    // node's origin and would otherwise sort ahead of (or instead of)
    // the entry this test is specifically about.
    while !app.overrides.entries().is_empty() {
        app.overrides.remove(0);
    }

    let origin = app.override_origin_for_kind(app.cursor).unwrap();
    app.overrides
        .activate(origin.clone(), Some("int32".to_string()));
    let idx = app
        .overrides
        .entries()
        .iter()
        .position(|e| e.origin == origin && e.r#type.as_deref() == Some("int32"))
        .unwrap();
    app.overrides.toggle_active(idx);
    assert!(!app.overrides.entries()[idx].active, "must be inactive");

    app.handle_key(KeyEvent::new(KeyCode::Char('t'), KeyModifiers::NONE));
    assert_eq!(app.override_sort, SortMode::Lexicographic);
    assert_eq!(app.override_candidates[app.override_highlight].0, "int32");
}

/// Spec 0139 Steps C/D + G3: with neither an active nor an
/// applicable-inactive override, and no scoring graph loaded at all
/// (`message_node_app`'s fixture), `t` falls straight through to
/// `Lexicographic` mode (highlight on the `None` sentinel row) without
/// ever surfacing the "no scoring graph available" message — the
/// fallback already did what that message would have suggested.
#[test]
fn t_falls_back_to_lexicographic_silently_when_no_graph_and_no_match() {
    let mut app = message_node_app();
    app.splash = false;
    app.term_width = 120;
    app.message.clear();
    // `message_node_app`'s single node is also the seeded root
    // override's own target — remove it so neither Step A nor Step B
    // find a match, exercising Steps C/D in isolation.
    while !app.overrides.entries().is_empty() {
        app.overrides.remove(0);
    }

    app.handle_key(KeyEvent::new(KeyCode::Char('t'), KeyModifiers::NONE));
    assert_eq!(app.override_sort, SortMode::Lexicographic);
    assert_eq!(
        app.override_candidates[app.override_highlight].0,
        "protolens_internal.None"
    );
    assert!(
        !app.message.contains("no scoring graph"),
        "message must be suppressed on this auto-fallback path: {}",
        app.message
    );
}

/// Spec 0114 §3.2/spec 0137 §G4: `j`/`k` move the highlight, clamped to
/// `0..=candidates.len() - 1` — direct indexing, no pinned raw row.
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
    assert_eq!(app.override_highlight, 1);
}

/// Spec 0114 §4/spec 0137 §G4: `/` searches forward, `?` searches
/// backward, `n` repeats the last search — wrapping around — over
/// `override_candidates` directly, no pinned raw row excluded.
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
    assert_eq!(app.override_highlight, 1); // pkg.Beta

    // `n` repeats forward, wrapping to the next match.
    app.handle_key(KeyEvent::new(KeyCode::Char('n'), KeyModifiers::NONE));
    assert_eq!(app.override_highlight, 3); // pkg.Beta2

    // Wraps back around to the first match.
    app.handle_key(KeyEvent::new(KeyCode::Char('n'), KeyModifiers::NONE));
    assert_eq!(app.override_highlight, 1); // pkg.Beta

    // `?` searches backward from the current highlight (pkg.Beta,
    // index 1) — skips itself, wraps to pkg.Beta2 (index 3).
    app.handle_key(KeyEvent::new(KeyCode::Char('?'), KeyModifiers::NONE));
    for c in "beta".chars() {
        app.handle_key(KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE));
    }
    app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
    assert_eq!(app.override_highlight, 3); // pkg.Beta2

    // No match leaves the highlight unchanged and sets a message.
    app.handle_key(KeyEvent::new(KeyCode::Char('/'), KeyModifiers::NONE));
    for c in "nope".chars() {
        app.handle_key(KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE));
    }
    app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
    assert_eq!(app.override_highlight, 3);
    assert!(app.message.contains("not found"));
}

/// Spec 0132 §G2, extended (2026-07-17 feedback): a search-jump
/// (`/`/`?`/`n`/`p`) live-previews the reached candidate in the main
/// pane, same as arrow-key movement — not just silently moving the
/// highlight. Exercised indirectly: the fake candidate FQDNs used here
/// don't resolve against an empty descriptor context, so a preview
/// attempt surfaces as a "cannot preview override" message; before this
/// fix, a search-jump left the message untouched.
#[test]
fn override_search_jump_previews_the_reached_candidate() {
    let mut app = message_node_app();
    app.splash = false;
    app.term_width = 120;
    app.handle_key(KeyEvent::new(KeyCode::Char('t'), KeyModifiers::NONE));

    app.override_candidates = vec![
        ("pkg.Alpha".to_string(), None),
        ("pkg.Beta".to_string(), None),
    ];
    app.override_highlight = 0;
    app.message.clear();

    app.handle_key(KeyEvent::new(KeyCode::Char('/'), KeyModifiers::NONE));
    for c in "beta".chars() {
        app.handle_key(KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE));
    }
    app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
    assert_eq!(app.override_highlight, 1); // pkg.Beta
    assert!(
        app.message.contains("cannot preview override"),
        "search-jump must preview the reached candidate: {}",
        app.message
    );
}

/// `p` repeats the last search in the opposite direction (vim's `N`
/// counterpart to `n`).
#[test]
fn override_search_repeat_with_p_reverses_direction() {
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
    assert_eq!(app.override_highlight, 1); // pkg.Beta

    // `p` repeats backward (opposite of the forward `/` that set this
    // pattern), wrapping to pkg.Beta2.
    app.handle_key(KeyEvent::new(KeyCode::Char('p'), KeyModifiers::NONE));
    assert_eq!(app.override_highlight, 3); // pkg.Beta2

    // A second `p` continues backward, wrapping to pkg.Beta.
    app.handle_key(KeyEvent::new(KeyCode::Char('p'), KeyModifiers::NONE));
    assert_eq!(app.override_highlight, 1); // pkg.Beta
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
    assert_eq!(app.override_highlight, 1); // pkg.Beta

    // `/<Enter>` with no typed pattern re-uses "beta", searching
    // forward from the current highlight — wraps to pkg.Beta2.
    app.handle_key(KeyEvent::new(KeyCode::Char('/'), KeyModifiers::NONE));
    app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
    assert_eq!(app.override_highlight, 3); // pkg.Beta2

    // `?<Enter>` with no typed pattern re-uses "beta" too, but now
    // searches backward from the current highlight.
    app.handle_key(KeyEvent::new(KeyCode::Char('?'), KeyModifiers::NONE));
    app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
    assert_eq!(app.override_highlight, 1); // pkg.Beta
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

/// `p` repeats the last main-pane search in the opposite direction.
#[test]
fn main_pane_search_repeat_with_p_reverses_direction() {
    let mut app = sibling_leaves_app(&["alpha: 1", "beta: 2", "gamma: 3", "beta2: 4"]);
    app.splash = false;
    app.term_width = 120;

    app.handle_key(KeyEvent::new(KeyCode::Char('/'), KeyModifiers::NONE));
    for c in "beta".chars() {
        app.handle_key(KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE));
    }
    app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
    assert_eq!(app.cursor, 1); // beta

    // `p` repeats backward, wrapping to beta2.
    app.handle_key(KeyEvent::new(KeyCode::Char('p'), KeyModifiers::NONE));
    assert_eq!(app.cursor, 3); // beta2

    // A second `p` continues backward, wrapping to beta.
    app.handle_key(KeyEvent::new(KeyCode::Char('p'), KeyModifiers::NONE));
    assert_eq!(app.cursor, 1); // beta
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
    assert_eq!(app.override_highlight, 0); // pkg.Alpha
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
        None,
    );
    app.splash = false;
    app.term_width = 120;

    let inner_idx = app
        .tree
        .iter()
        .position(|n| n.span.type_fqdn.as_deref() == Some("test.Inner"))
        .expect("tree must contain the Inner submessage");
    app.cursor = inner_idx;

    // Spec 0137 §G4: inferred mode has no raw/`None` row at all, so
    // reaching raw via the pane requires alphabetic mode, where index
    // `0` is always the `None` sentinel. `Enter` there clears the
    // type and closes the pane.
    app.handle_key(KeyEvent::new(KeyCode::Char('t'), KeyModifiers::NONE));
    assert!(app.override_target.is_some());
    app.override_sort = SortMode::Lexicographic;
    app.recompute_override_candidates();
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
    // (no scoring graph in this fixture), and select the first real
    // message FQDN (spec 0137 §G4: index `0` there is `None`, `1..16`
    // are the primitive keywords, so the first message FQDN comes
    // after those).
    app.cursor = inner_idx;
    app.handle_key(KeyEvent::new(KeyCode::Char('t'), KeyModifiers::NONE));
    app.override_sort = SortMode::Lexicographic;
    app.recompute_override_candidates();
    assert!(!app.override_candidates.is_empty());
    let chosen = app.all_type_fqdns[0].clone();
    let row = app
        .override_candidates
        .iter()
        .position(|(f, _)| *f == chosen)
        .expect("chosen FQDN must be a candidate");
    app.override_highlight = row;
    app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
    assert!(app.override_target.is_none());
    assert_eq!(
        app.tree[inner_idx].span.type_fqdn.as_deref(),
        Some(chosen.as_str())
    );
}
