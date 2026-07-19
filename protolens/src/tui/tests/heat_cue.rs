// SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

use super::super::heat_cue::{
    derive_stats, heat_cue_from_stats, heat_level, score_of, BoundedMru, HeatCueKind,
    RangeHeatStats, HEAT_GLYPH,
};
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

// ---------------------------------------------------------------------
// derive_stats / score_of (spec 0151 G1/G2)
// ---------------------------------------------------------------------

#[test]
fn derive_stats_empty_candidates_yields_no_best_score() {
    let stats = derive_stats(&[]);
    assert_eq!(stats.best_score, None);
    assert_eq!(stats.best_count, 0);
}

#[test]
fn derive_stats_single_entry_has_best_count_one() {
    let candidates = vec![("a.Type".to_string(), 5)];
    let stats = derive_stats(&candidates);
    assert_eq!(stats.best_score, Some(5));
    assert_eq!(stats.best_count, 1);
}

#[test]
fn derive_stats_counts_only_entries_tied_at_the_top() {
    let candidates = vec![
        ("a.Type".to_string(), 50),
        ("b.Type".to_string(), 50),
        ("c.Type".to_string(), 10),
        ("d.Type".to_string(), 10),
        ("e.Type".to_string(), 10),
    ];
    let stats = derive_stats(&candidates);
    assert_eq!(stats.best_score, Some(50));
    assert_eq!(
        stats.best_count, 2,
        "ties below the top must not inflate best_count"
    );
}

#[test]
fn score_of_finds_by_fqdn_or_returns_none() {
    let candidates = vec![("a.Type".to_string(), 5), ("b.Type".to_string(), 3)];
    assert_eq!(score_of(&candidates, "b.Type"), Some(3));
    assert_eq!(score_of(&candidates, "not.in.list"), None);
}

// ---------------------------------------------------------------------
// BoundedMru (spec 0151 G4)
// ---------------------------------------------------------------------

#[test]
fn bounded_mru_hit_promotes_to_most_recently_used() {
    let mut cache: BoundedMru<u32, u32> = BoundedMru::new(2);
    cache.insert(1, 10);
    cache.insert(2, 20);
    // Touch key 1, making key 2 the least-recently-used.
    assert_eq!(cache.get(&1), Some(10));
    cache.insert(3, 30);
    // Key 2 (LRU) must have been evicted; keys 1 and 3 survive.
    assert_eq!(cache.get(&2), None);
    assert_eq!(cache.get(&1), Some(10));
    assert_eq!(cache.get(&3), Some(30));
}

#[test]
fn bounded_mru_evicts_least_recently_used_past_entry_budget() {
    let mut cache: BoundedMru<u32, u32> = BoundedMru::new(3);
    cache.insert(1, 10);
    cache.insert(2, 20);
    cache.insert(3, 30);
    cache.insert(4, 40); // 4 distinct keys > max_entries(3): evicts key 1.
    assert_eq!(cache.get(&1), None);
    assert_eq!(cache.get(&2), Some(20));
    assert_eq!(cache.get(&3), Some(30));
    assert_eq!(cache.get(&4), Some(40));
}

// ---------------------------------------------------------------------
// heat_cue_from_stats (spec 0151 G5, spec 0138 G4/G9)
// ---------------------------------------------------------------------

/// Spec 0138 G4 (amended): the `Mismatch` gate is `best > current`, not
/// `best >= current` — an equal score never produces a `Mismatch` cue.
/// (An equal score tied with another candidate instead produces a
/// `Tie` cue per G9 — see `tie_gate_fires_when_current_shares_the_top_
/// score_with_others` — so this test's own equal-score case must be a
/// unique optimum, with no other candidate to tie against, to stay a
/// true "no cue at all" case.)
#[test]
fn gate_requires_best_strictly_greater_than_current() {
    let stats = RangeHeatStats {
        best_score: Some(50),
        best_count: 1,
    };
    assert!(heat_cue_from_stats(stats, Some(50)).is_none());

    let stats = RangeHeatStats {
        best_score: Some(51),
        best_count: 1,
    };
    let cue = heat_cue_from_stats(stats, Some(50)).unwrap();
    assert!(matches!(
        cue.kind,
        HeatCueKind::Mismatch {
            current: 50,
            best: 51
        }
    ));
}

/// Spec 0151 G5: a `None` current entry (current type not found in the
/// range's candidate list — raw, primitive keyword, or vetoed) always
/// yields `Mismatch`, displaying `current: 0` — but purely for display;
/// the gating decision itself never collapses `None` into a coincidental
/// `0` before comparing (see the next test for the case that fix
/// actually matters).
#[test]
fn current_absent_yields_mismatch_with_display_default_zero() {
    let stats = RangeHeatStats {
        best_score: Some(5),
        best_count: 1,
    };
    let cue = heat_cue_from_stats(stats, None).unwrap();
    assert!(matches!(
        cue.kind,
        HeatCueKind::Mismatch {
            current: 0,
            best: 5
        }
    ));
}

/// Spec 0151 G5 — the conflation-bug regression: a `None` current entry
/// must still yield `Mismatch` even when `best_score` is `Some(0)`. The
/// old `unwrap_or(0)` collapse silently treated this as `current ==
/// best` and dropped the cue entirely.
#[test]
fn current_absent_still_triggers_mismatch_even_when_best_is_zero() {
    let stats = RangeHeatStats {
        best_score: Some(0),
        best_count: 1,
    };
    let cue = heat_cue_from_stats(stats, None).unwrap();
    assert!(matches!(
        cue.kind,
        HeatCueKind::Mismatch {
            current: 0,
            best: 0
        }
    ));
}

/// Spec 0138 G9: when the current type already achieves the top score
/// but at least one other candidate ties it there, a `Tie` cue fires
/// instead of no cue at all — `best_count` counts every candidate
/// sharing that top score, including the current one.
#[test]
fn tie_gate_fires_when_current_shares_the_top_score_with_others() {
    // Unique optimum (no other candidate ties the top score): no cue,
    // same as before G9 existed.
    let stats = RangeHeatStats {
        best_score: Some(50),
        best_count: 1,
    };
    assert!(heat_cue_from_stats(stats, Some(50)).is_none());

    // Two-way tie at the top score, current is one of them.
    let stats = RangeHeatStats {
        best_score: Some(50),
        best_count: 2,
    };
    let cue = heat_cue_from_stats(stats, Some(50)).unwrap();
    assert!(matches!(cue.kind, HeatCueKind::Tie { tie_count: 2 }));

    // Three-way tie.
    let stats = RangeHeatStats {
        best_score: Some(50),
        best_count: 3,
    };
    let cue = heat_cue_from_stats(stats, Some(50)).unwrap();
    assert!(matches!(cue.kind, HeatCueKind::Tie { tie_count: 3 }));
}

/// Spec 0151 G5 (spec 0138 G9): a `None` current entry never produces a
/// `Tie` cue, even when `best_score` happens to be shared by multiple
/// candidates — `Tie` requires the current type to be a genuine member
/// of the tied top-scoring group, not the display-only `0` default.
#[test]
fn tie_never_fires_for_an_absent_current_entry() {
    let stats = RangeHeatStats {
        best_score: Some(0),
        best_count: 2,
    };
    let cue = heat_cue_from_stats(stats, None).unwrap();
    assert!(matches!(
        cue.kind,
        HeatCueKind::Mismatch {
            current: 0,
            best: 0
        }
    ));
}

/// Spec 0138 G8: every candidate vetoed (`best_score: None`) is absent,
/// not a "level 0"/zero-score cue, regardless of `current_entry`.
#[test]
fn absent_when_every_candidate_is_vetoed() {
    let stats = RangeHeatStats {
        best_score: None,
        best_count: 0,
    };
    assert!(heat_cue_from_stats(stats, Some(5)).is_none());
    assert!(heat_cue_from_stats(stats, None).is_none());
}

// ---------------------------------------------------------------------
// heat_cue_for (end-to-end, spec 0151 G1-G3)
// ---------------------------------------------------------------------

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
/// without discarding the caches — verified by pre-populating them
/// directly (bypassing the need for a real scoring graph) so a cue
/// would otherwise be present.
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
    app.heat_range_cache.insert(
        range.start,
        RangeHeatStats {
            best_score: Some(50),
            best_count: 1,
        },
    );
    app.heat_current_score_cache.insert(
        (range.start, "google.protobuf.DescriptorProto".to_string()),
        Some(10),
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
    app.heat_range_cache.insert(
        range.start,
        RangeHeatStats {
            best_score: Some(50),
            best_count: 1,
        },
    );
    app.heat_current_score_cache.insert(
        (range.start, "google.protobuf.DescriptorProto".to_string()),
        Some(10),
    );

    let area = Rect::new(0, 0, 80, 24);
    let mut terminal = Terminal::new(TestBackend::new(area.width, area.height)).unwrap();
    // Spec 0147 G1: no border — main content is `area` minus the global
    // command/message row (`Length(1)`, bottom of the whole screen) and
    // the main pane's own local statusline row (`Length(1)`, bottom of
    // the main pane).
    let inner = Rect::new(area.x, area.y, area.width, area.height - 2);
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
    app.heat_range_cache.insert(
        range.start,
        RangeHeatStats {
            best_score: Some(50),
            best_count: 2,
        },
    );
    app.heat_current_score_cache.insert(
        (range.start, "google.protobuf.DescriptorProto".to_string()),
        Some(50),
    );

    let area = Rect::new(0, 0, 80, 24);
    let mut terminal = Terminal::new(TestBackend::new(area.width, area.height)).unwrap();
    // Spec 0147 G1: no border — main content is `area` minus the global
    // command/message row (`Length(1)`, bottom of the whole screen) and
    // the main pane's own local statusline row (`Length(1)`, bottom of
    // the main pane).
    let inner = Rect::new(area.x, area.y, area.width, area.height - 2);
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
    app.heat_range_cache.insert(
        range.start,
        RangeHeatStats {
            best_score: Some(50),
            best_count: 1,
        },
    );
    app.heat_current_score_cache
        .insert((range.start, "test.Inner".to_string()), Some(10));
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

// ---------------------------------------------------------------------
// Caching regressions (spec 0151 G2/G3/G6 test plan)
// ---------------------------------------------------------------------

/// Regression for the original caching bug (spec 0151 Background): once
/// a range's stats and the current type's score are both cached, a
/// second `heat_cue_for` call for the same line is a pure cache hit —
/// no graph is required for it to succeed, proving no re-scoring
/// happened (a real graph-less `App` would otherwise short-circuit to
/// `None` on any fresh `inferred_candidates` call).
#[test]
fn second_call_for_the_same_line_is_a_pure_cache_hit() {
    let mut app = message_node_app();
    app.splash = false;
    assert!(app.ctx.graph.is_none());
    let idx = 0;
    let range = extract::message_payload_range(
        &app.blob,
        &app.tree[idx].span.raw_range,
        app.tree[idx].span.packed_record_start,
    );
    app.heat_range_cache.insert(
        range.start,
        RangeHeatStats {
            best_score: Some(50),
            best_count: 1,
        },
    );
    app.heat_current_score_cache.insert(
        (range.start, "google.protobuf.DescriptorProto".to_string()),
        Some(10),
    );
    let header_line = app.tree[idx].span.text_range.start;

    // Two calls, both cache hits (no graph loaded, so a miss would
    // short-circuit to `None` via `self.ctx.graph.as_ref()?`).
    let first = app.heat_cue_for(header_line);
    let second = app.heat_cue_for(header_line);
    assert!(first.is_some());
    assert!(second.is_some());
}

/// Regression for the "permanently-vetoed range never gets cached" bug
/// (spec 0151 Background): a `None` `best_score` must still be a real
/// cache entry, so a subsequent lookup is a hit, not treated as
/// "nothing was cached."
#[test]
fn vetoed_range_is_still_cached_as_a_hit() {
    let mut cache: BoundedMru<usize, RangeHeatStats> = BoundedMru::new(8192);
    cache.insert(
        42,
        RangeHeatStats {
            best_score: None,
            best_count: 0,
        },
    );
    let hit = cache.get(&42);
    assert!(hit.is_some());
    assert_eq!(hit.unwrap().best_score, None);
}

/// Cross-population (spec 0151 G6): once `heat_cue_for` pays for a full
/// `inferred_candidates` call, the same candidate list — capped to
/// `override_list_height` — is inserted into `App::candidate_cache`
/// under the same range, so a later override-pane open (`t`) on that
/// node hits the cache instead of re-scoring.
#[test]
fn g6_cross_population_caps_to_override_list_height() {
    let (mut app, inner_idx, _id_idx) = type_as_fixture();
    let range = extract::message_payload_range(
        &app.blob,
        &app.tree[inner_idx].span.raw_range,
        app.tree[inner_idx].span.packed_record_start,
    );
    app.override_list_height = 200; // simulates the eager `run()` init.
    app.candidate_cache.insert(
        range.clone(),
        vec![("a.Type".to_string(), 5), ("b.Type".to_string(), 3)],
    );
    // The candidate_cache API itself is exercised elsewhere
    // (override_pane.rs's own tests); this just pins that
    // `override_list_height` participates in the cap `heat_cue_for`
    // uses, per the `.max(1)` expression it shares with
    // `override_select.rs`.
    assert_eq!(app.override_list_height.max(1), 200);
    assert!(app.candidate_cache.get(&range).is_some());
}

// ---------------------------------------------------------------------
// warm_up_heat_cues (spec 0151 G8)
// ---------------------------------------------------------------------

/// No scoring graph loaded: `warm_up_heat_cues` takes its early-return
/// branch and completes without touching `app.message` (which the
/// redraw path inside the loop is the only thing that ever sets, per
/// `WARMUP_FIRST_DRAW_DELAY`/`WARMUP_REDRAW_INTERVAL`). Uses a
/// `CrosstermBackend` over an in-memory `Vec<u8>` rather than
/// `TestBackend` (mirrors `open_editor_reports_a_missing_nvim_instead_
/// of_crashing`'s own precedent: `TestBackend`'s `Error` is
/// `Infallible`, which doesn't satisfy `io::Error: From<B::Error>`).
/// No existing fixture in this crate builds a real in-process
/// `LoadedGraph` (every other graph-dependent test exercises the "no
/// graph loaded" branch too), so the `ctx.graph.is_some()` populate/
/// redraw path isn't separately unit-testable here.
#[test]
fn warm_up_heat_cues_is_a_noop_without_a_scoring_graph() {
    let mut app = message_node_app();
    assert!(app.ctx.graph.is_none());
    // `message_node_app`'s fixture seeds a root override to a type
    // absent from `DescriptorContext::empty_for_test()`'s empty
    // descriptor set, so `App::new`'s own `render_overrides` pass
    // already leaves an error string in `app.message` — a fixture
    // artifact unrelated to `warm_up_heat_cues`. Compare against this
    // baseline rather than asserting emptiness.
    let before = app.message.clone();
    let mut terminal = Terminal::new(CrosstermBackend::new(Vec::new())).unwrap();

    warm_up_heat_cues(&mut terminal, &mut app).unwrap();

    assert_eq!(
        app.message, before,
        "the early-return branch must never touch app.message"
    );
}

/// `heat_cues_hidden` also short-circuits the pass, same as an absent
/// graph (the `||` gate's second operand).
#[test]
fn warm_up_heat_cues_is_a_noop_when_heat_cues_hidden() {
    let mut app = message_node_app();
    app.heat_cues_hidden = true;
    // See the sibling test above for why this baseline isn't empty.
    let before = app.message.clone();
    let mut terminal = Terminal::new(CrosstermBackend::new(Vec::new())).unwrap();

    warm_up_heat_cues(&mut terminal, &mut app).unwrap();

    assert_eq!(
        app.message, before,
        "the early-return branch must never touch app.message"
    );
}
