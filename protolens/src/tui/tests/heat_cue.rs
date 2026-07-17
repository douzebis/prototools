// SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

use super::super::heat_cue::{heat_cue_from_candidates, heat_level, HeatCueKind, HEAT_GLYPH};
use super::super::*;
use super::support::*;

/// Spec 0138 G5: the Fibonacci boundaries partition the score axis into
/// exactly 12 levels, each boundary itself belonging to the *lower*
/// level (`<=`), one past it starting the next.
#[test]
fn heat_level_bucket_boundaries() {
    let cases: &[(i64, u8)] = &[
        (i64::MIN, 1),
        (0, 1),
        (1, 1),
        (2, 2),
        (3, 3),
        (4, 4),
        (5, 4),
        (6, 5),
        (8, 5),
        (9, 6),
        (13, 6),
        (14, 7),
        (21, 7),
        (22, 8),
        (34, 8),
        (35, 9),
        (55, 9),
        (56, 10),
        (89, 10),
        (90, 11),
        (144, 11),
        (145, 12),
        (i64::MAX, 12),
    ];
    for &(score, expected) in cases {
        assert_eq!(heat_level(score), expected, "best_score = {score}");
    }
}

/// Spec 0138 G4 (amended): the `Mismatch` gate is `best > current`, not
/// `best >= current` — an equal score never produces a `Mismatch` cue.
/// (An equal score tied with another candidate instead produces a
/// `Tie` cue per G9 — see `tie_gate_fires_when_current_shares_the_top_
/// score_with_others` — so this test's own equal-score case must be a
/// unique optimum, with no other candidate to tie against, to stay a
/// true "no cue at all" case.)
#[test]
fn gate_requires_best_strictly_greater_than_current() {
    let candidates = vec![("b.Type".to_string(), 50)];
    assert!(heat_cue_from_candidates(&candidates, Some("b.Type")).is_none());

    let candidates = vec![("a.Type".to_string(), 51), ("b.Type".to_string(), 50)];
    let cue = heat_cue_from_candidates(&candidates, Some("b.Type")).unwrap();
    assert!(matches!(
        cue.kind,
        HeatCueKind::Mismatch {
            current: 50,
            best: 51
        }
    ));
}

/// Spec 0138 G3: a current type absent from the candidate list (raw,
/// primitive keyword, or vetoed) defaults `current_score` to `0`.
#[test]
fn current_score_defaults_to_zero_when_current_type_is_unranked() {
    let candidates = vec![("a.Type".to_string(), 5)];
    let cue = heat_cue_from_candidates(&candidates, Some("not.in.list")).unwrap();
    assert!(matches!(
        cue.kind,
        HeatCueKind::Mismatch {
            current: 0,
            best: 5
        }
    ));

    let cue_none_key = heat_cue_from_candidates(&candidates, None).unwrap();
    assert!(matches!(
        cue_none_key.kind,
        HeatCueKind::Mismatch { current: 0, .. }
    ));
}

/// Spec 0138 G9: when the current type already achieves the top score
/// but at least one other candidate ties it there, a `Tie` cue fires
/// instead of no cue at all — `tie_count` counts every candidate
/// sharing that top score, including the current one.
#[test]
fn tie_gate_fires_when_current_shares_the_top_score_with_others() {
    // Unique optimum (no other candidate ties the top score): no cue,
    // same as before G9 existed.
    let candidates = vec![("a.Type".to_string(), 50)];
    assert!(heat_cue_from_candidates(&candidates, Some("a.Type")).is_none());

    // Two-way tie at the top score, current is one of them.
    let candidates = vec![("a.Type".to_string(), 50), ("b.Type".to_string(), 50)];
    let cue = heat_cue_from_candidates(&candidates, Some("a.Type")).unwrap();
    assert!(matches!(cue.kind, HeatCueKind::Tie { tie_count: 2 }));

    // Three-way tie.
    let candidates = vec![
        ("a.Type".to_string(), 50),
        ("b.Type".to_string(), 50),
        ("c.Type".to_string(), 50),
    ];
    let cue = heat_cue_from_candidates(&candidates, Some("b.Type")).unwrap();
    assert!(matches!(cue.kind, HeatCueKind::Tie { tie_count: 3 }));
}

/// Spec 0138 G9: a `current_key` that merely defaults to `0` (not found
/// in `candidates` at all) must never produce a `Tie` cue, even if `0`
/// coincidentally equals `best` — `Tie` requires the current type to be
/// a genuine member of the tied top-scoring group, not a numeric
/// coincidence.
#[test]
fn tie_gate_requires_current_type_to_be_an_actual_candidate() {
    let candidates = vec![("a.Type".to_string(), 0), ("b.Type".to_string(), 0)];
    assert!(heat_cue_from_candidates(&candidates, Some("not.in.list")).is_none());
    assert!(heat_cue_from_candidates(&candidates, None).is_none());
}

/// Spec 0138 G8: no candidates at all (e.g. every candidate vetoed) is
/// absent, not a "level 0"/zero-score cue.
#[test]
fn absent_when_candidate_list_is_empty() {
    assert!(heat_cue_from_candidates(&[], Some("a.Type")).is_none());
}

/// Spec 0138 G8: absent whenever no scoring graph is loaded for the
/// session — even on an eligible node whose range isn't already cached
/// — since `heat_cue_for` has no way to populate the cache without one.
#[test]
fn absent_when_no_scoring_graph_is_loaded() {
    let (mut app, inner_idx, _id_idx) = type_as_fixture();
    assert!(
        app.ctx.graph.is_none(),
        "fixture must have no scoring graph"
    );
    let header_line = app.tree[inner_idx].span.text_range.start;
    assert!(app.heat_cue_for(header_line).is_none());
}

/// Spec 0138: `i` toggles `heat_cues_hidden`, suppressing the cue
/// without discarding `heat_cache` — verified by pre-populating the
/// cache directly (bypassing the need for a real scoring graph) so a
/// cue would otherwise be present.
#[test]
fn i_toggles_heat_cues_hidden() {
    let mut app = message_node_app();
    app.splash = false;
    let idx = 0;
    let range = extract::message_payload_range(
        &app.blob,
        &app.tree[idx].span.raw_range,
        app.tree[idx].span.packed_record_start,
    );
    app.heat_cache.insert(
        range,
        vec![
            ("other.Type".to_string(), 50),
            ("google.protobuf.DescriptorProto".to_string(), 10),
        ],
    );
    let header_line = app.tree[idx].span.text_range.start;

    assert!(!app.heat_cues_hidden);
    let cue = app.heat_cue_for(header_line).expect("cue must be present");
    assert!(matches!(
        cue.kind,
        HeatCueKind::Mismatch {
            current: 10,
            best: 50
        }
    ));

    app.handle_key(KeyEvent::new(KeyCode::Char('i'), KeyModifiers::NONE));
    assert!(app.heat_cues_hidden);
    assert!(app.heat_cue_for(header_line).is_none());

    app.handle_key(KeyEvent::new(KeyCode::Char('i'), KeyModifiers::NONE));
    assert!(!app.heat_cues_hidden);
    assert!(app.heat_cue_for(header_line).is_some());
}

/// End-to-end render check (spec 0138 N1): with a cue pre-cached (as
/// `i_toggles_heat_cues_hidden` above), the main pane's header row
/// shows `HEAT_GLYPH` in its own leading column and a trailing
/// ` [current/best]` suffix; hiding the cue reverts the leading column
/// to blank and drops the suffix, without otherwise disturbing the
/// line's own indentation.
#[test]
fn render_shows_the_glyph_column_and_suffix_when_a_cue_is_present() {
    let mut app = message_node_app();
    app.splash = false;
    let idx = 0;
    let range = extract::message_payload_range(
        &app.blob,
        &app.tree[idx].span.raw_range,
        app.tree[idx].span.packed_record_start,
    );
    app.heat_cache.insert(
        range,
        vec![
            ("other.Type".to_string(), 50),
            ("google.protobuf.DescriptorProto".to_string(), 10),
        ],
    );

    let area = Rect::new(0, 0, 80, 24);
    let mut terminal = Terminal::new(TestBackend::new(area.width, area.height)).unwrap();
    let inner = Block::bordered().inner(area);
    fn row_text(buffer: &ratatui::buffer::Buffer, inner: Rect, y: u16) -> String {
        (inner.x..inner.x + inner.width)
            .map(|x| buffer[(x, y)].symbol().to_string())
            .collect()
    }

    terminal.draw(|frame| app.render(frame)).unwrap();
    let header_row = row_text(terminal.backend().buffer(), inner, inner.y);
    assert_eq!(
        header_row.chars().next().unwrap(),
        HEAT_GLYPH,
        "leading column must show the glyph: {header_row:?}"
    );
    assert!(
        header_row.contains(" [10/50]"),
        "must show the current/best suffix: {header_row:?}"
    );

    app.heat_cues_hidden = true;
    terminal.draw(|frame| app.render(frame)).unwrap();
    let header_row = row_text(terminal.backend().buffer(), inner, inner.y);
    assert_eq!(
        header_row.chars().next().unwrap(),
        ' ',
        "leading column reserved but blank when hidden: {header_row:?}"
    );
    assert!(
        !header_row.contains('/'),
        "no suffix while hidden: {header_row:?}"
    );
}

/// End-to-end render check (spec 0138 N1/G9): with a `Tie` cue
/// pre-cached (current type tied for the top score with one other
/// candidate), the main pane's header row shows `HEAT_GLYPH` in its own
/// leading column and a trailing ` [<tie_count>]` suffix — distinct from
/// the `Mismatch` cue's ` [current/best]` (no `/`).
#[test]
fn render_shows_the_tie_count_suffix_when_tied_for_best() {
    let mut app = message_node_app();
    app.splash = false;
    let idx = 0;
    let range = extract::message_payload_range(
        &app.blob,
        &app.tree[idx].span.raw_range,
        app.tree[idx].span.packed_record_start,
    );
    app.heat_cache.insert(
        range,
        vec![
            ("google.protobuf.DescriptorProto".to_string(), 50),
            ("other.Type".to_string(), 50),
        ],
    );

    let area = Rect::new(0, 0, 80, 24);
    let mut terminal = Terminal::new(TestBackend::new(area.width, area.height)).unwrap();
    let inner = Block::bordered().inner(area);
    fn row_text(buffer: &ratatui::buffer::Buffer, inner: Rect, y: u16) -> String {
        (inner.x..inner.x + inner.width)
            .map(|x| buffer[(x, y)].symbol().to_string())
            .collect()
    }

    terminal.draw(|frame| app.render(frame)).unwrap();
    let header_row = row_text(terminal.backend().buffer(), inner, inner.y);
    assert_eq!(
        header_row.chars().next().unwrap(),
        HEAT_GLYPH,
        "leading column must show the glyph: {header_row:?}"
    );
    assert!(
        header_row.contains(" [2]"),
        "must show the tie-count suffix: {header_row:?}"
    );
    assert!(
        !header_row.contains('/'),
        "the Tie cue's suffix must not look like Mismatch's [current/best]: {header_row:?}"
    );
}

/// The cue is main-pane-only (spec 0138 N2/Test-plan): `heat_cue_for`
/// gates on `line_to_node`, which the override pane never populates its
/// own rows into, so a cached cue for a node never leaks into the
/// override pane's own rendering.
#[test]
fn cue_never_appears_in_the_override_pane() {
    let (mut app, inner_idx, _id_idx) = type_as_fixture();
    let range = extract::message_payload_range(
        &app.blob,
        &app.tree[inner_idx].span.raw_range,
        app.tree[inner_idx].span.packed_record_start,
    );
    app.heat_cache.insert(
        range,
        vec![
            ("other.Type".to_string(), 50),
            ("test.Inner".to_string(), 10),
        ],
    );
    app.cursor = inner_idx;
    app.toggle_override();
    assert!(app.override_target.is_some());

    let area = Rect::new(0, 0, 120, 24);
    let mut terminal = Terminal::new(TestBackend::new(area.width, area.height)).unwrap();
    terminal.draw(|frame| app.render(frame)).unwrap();
    // The main pane stays visible in its own (left) half of the split
    // while the override pane is open, so it's `app.side_area` — the
    // override pane's own region, populated by `render_override_pane`
    // — that must be searched, not the whole buffer.
    let side_area = app.side_area;
    let buffer = terminal.backend().buffer();
    let found = (side_area.x..side_area.x + side_area.width).any(|x| {
        (side_area.y..side_area.y + side_area.height)
            .any(|y| buffer[(x, y)].symbol() == HEAT_GLYPH.to_string())
    });
    assert!(!found, "heat glyph must never render in the override pane");
}
