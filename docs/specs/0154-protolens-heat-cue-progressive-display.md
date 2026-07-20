<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0154 — protolens heat cue: `score_one` fast path + progressive display

Status: implemented
App: protolens
Implemented in: 2026-07-20
Refs: docs/specs/0153-score-one-single-entry-fast-path.md (`score_one`,
      the primitive this spec's worker fast path consumes),
      docs/specs/0152-protolens-heat-cue-background-scoring-thread.md
      (`HeatRequestQueue`, `HeatCaches`, `heat_worker_loop` — the
      baseline this spec amends), `protolens/src/tui/heat_worker.rs`,
      `protolens/src/tui/heat_cue.rs`, `protolens/src/tui/render.rs`,
      `protolens/src/tui/override_apply.rs`, `protolens/src/override_pane.rs`

## Background

Spec 0152 gave protolens a background worker that scores every root
candidate against a range's bytes (`override_pane::inferred_candidates`,
i.e. a full `score_all` sweep) and caches the result, plus a per-node
"current type" score keyed by `(range start, fqdn)`. `heat_worker_loop`
decides whether a request is already satisfied with a single all-or-
nothing gate:

```rust
let already_done = covers_window && covers_current;
```

If *either* half is missing, the worker unconditionally reruns a full
`score_all` sweep over every root candidate — even when the window
(`by_range`) is already fully cached and only `current_key`'s score is
what's actually missing. This happens routinely: reopening a heat cue
after an override edit (the range's window was already scored when the
override pane was first opened, but the newly-selected type isn't
cached yet), and arrow-key navigation inside the override pane
(repeatedly changing which type is "current" against an already-fully-
cached window). Spec 0153's `score_one` now makes scoring exactly one
candidate cheap, so this waste can be avoided directly. The same all-
or-nothing gate exists in `heat_cue_resolve`'s synchronous no-worker
fallback (`heat_cue.rs`).

Independently, `App::heat_states: Vec<HeatState>` is a two-state enum,
`Pending` or `Resolved(Option<HeatCue>)` — a node's heat cue is either
"nothing known yet" or "everything known". This conflates two
independently-arriving pieces of information (`best`, from the window
sweep, and `current`, from the single-candidate lookup) into one
flag, so the TUI can only ever render `" [pending]"` (no glyph) until
*both* are ready, even though `best` alone is frequently available
first and is itself useful to show. `HeatCueKind::Mismatch`'s `current:
i64` field also silently conflates "vetoed" with a genuine score of
`0` (`heat_cue_from_stats`'s `None => ... current: 0` branch).

## Goals

- **G1. `override_pane::inferred_score(range_bytes, fqdn, graph) ->
  Option<i64>`** (`protolens/src/override_pane.rs`, next to
  `inferred_candidates`) — wraps `score_one` with the same
  `ScoringOpts::default()`/vetoed-filtering convention as
  `inferred_candidates`: returns `None` if the type isn't found in the
  graph *or* the entry is vetoed, `Some(score)` otherwise.
- **G2. Three-way gate in `heat_worker_loop`.** Replace the
  `covers_window && covers_current` boolean with a three-way branch:
  - `(true, true)` — already done, skip (unchanged).
  - `(true, false)` — window is cached but `current_key`'s score isn't:
    call `inferred_score` (G1) on `range_bytes`/`req.current_key`
    alone, and insert the result into `c.current_score` only. `by_range`
    and `c.complete` are left untouched.
  - `(false, _)` — window isn't cached: unchanged full-sweep path
    (`inferred_candidates` + `derive_stats`), which also derives
    `current_key`'s score for free from the same sweep, as today.
- **G3. Mirror G2 in `heat_cue_resolve`'s synchronous no-worker
  fallback** (`heat_cue.rs`) for symmetry: when `by_range`/`c.complete`
  already covers the window but `current_score` doesn't cover
  `current_key`, call `inferred_score` directly instead of the full
  `inferred_candidates` sweep.
- **G4. Restructure `HeatState`** from the `Pending`/`Resolved(Option
  <HeatCue>)` enum to a struct storing `best` and `current`
  independently, each a pending-vs-available union:
  ```rust
  pub(super) struct HeatState {
      best: Option<RangeHeatStats>,
      current: Option<Option<i64>>,
  }
  ```
  `best: None` = window not yet scored; `best: Some(stats)` = window
  scored (`stats.best_score: None` means every candidate was vetoed).
  `current: None` = current type's score not yet computed;
  `current: Some(None)` = computed and vetoed (or no resolvable
  current type at all); `current: Some(Some(c))` = computed, score
  `c`. "Settled" (no more per-frame rechecking needed) is a computed
  property, not a stored tag: `best.is_some_and(|b| b.best_score.is_none())
  || (best.is_some() && current.is_some())`.
- **G5. `HeatCueKind::Mismatch.current` becomes `Option<i64>`**
  (`None` = vetoed / no resolvable current type, distinct from a
  genuine score of `0`).
- **G6. Progressive display, sourced from `HeatState`.** The seven
  reachable states and their rendering (glyph = the colored
  `HEAT_GLYPH` dot; "settled" states never recheck):
  | `best` | `current` | Display | Glyph | Settled |
  |---|---|---|---|---|
  | `None` | any | `[?]` | no | no |
  | `Some(stats)`, `stats.best_score: None` | any | *(nothing)* | no | yes |
  | `Some(stats)` | `None` | `[?/{best}]` | no | no |
  | `Some(stats)` | `Some(None)` | `[-/{best}]` | yes (Mismatch) | yes |
  | `Some(stats)` | `Some(Some(c))`, `c < best` | `[{c}/{best}]` | yes (Mismatch) | yes |
  | `Some(stats)` | `Some(Some(c))`, `c == best`, `best_count > 1` | `[{tie_count}]` | yes (Tie) | yes |
  | `Some(stats)` | `Some(Some(c))`, `c == best`, `best_count == 1` | *(nothing)* | no | yes |

  There is no `[?/?]` state: whenever `best` is unknown, the display
  collapses to bare `[?]` regardless of `current`'s state, since
  Mismatch vs. Tie cannot be determined without `best`. The glyph
  appears only in the two fully-complete states that produce a cue
  (Mismatch, Tie) — never during any partial/pending state, even if
  `best` alone is known.
- **G7. `override_apply.rs`'s reset-on-edit logic** (currently
  `self.heat_states[idx] = heat_cue::HeatState::Pending;`) updates to
  construct the new all-pending struct (`HeatState { best: None,
  current: None }`, or a `Default`/`HeatState::pending()` equivalent).

## Non-goals

- **N1.** No change to `score_one`/`score_all` themselves (spec 0153
  is unchanged) — this spec only changes how protolens *calls* them.
- **N2.** No change to `HeatRequestQueue`'s push/merge/eviction
  semantics, or to `RangeHeatEntry`/`CompleteSlot`'s shapes — only the
  gate inside `heat_worker_loop`/`heat_cue_resolve` and the per-node
  `HeatState` change.
- **N3.** No change to `heat_level`'s Fibonacci bucketing or to
  `HEAT_GLYPH`/hue color choices (Red for Mismatch, Blue for Tie).
- **N4.** No change to `HeatCueKind::Tie` (`tie_count: usize` is
  already unambiguous — a tie can only be reported once both `best`
  and `current` are fully known, so it needs no partial-state
  handling).

## Specification

### `protolens/src/override_pane.rs`

```rust
pub(super) fn inferred_score(
    range_bytes: &[u8],
    fqdn: &str,
    graph: &ArchivedCompiledGraph,
) -> Option<i64> {
    let result = score_one(range_bytes, fqdn, graph, &ScoringOpts::default())?;
    if result.vetoed {
        None
    } else {
        Some(result.score())
    }
}
```

### `protolens/src/tui/heat_worker.rs`

`heat_worker_loop`'s gate becomes:

```rust
let covers_window = c.by_range.peek(&start).is_some_and(|e| e.top_n.len() >= req.end);
let covers_current = req.current_key.as_deref()
    .is_none_or(|k| c.current_score.peek(&(start, k.to_string())).is_some());

match (covers_window, covers_current) {
    (true, true) => {} // already done
    (true, false) => {
        let range_bytes = &blob[req.range.clone()];
        let key = req.current_key.as_deref().expect("covers_current false implies Some");
        let score = override_pane::inferred_score(range_bytes, key, graph);
        let mut c = caches.lock().unwrap_or_else(|e| e.into_inner());
        c.current_score.insert((start, key.to_string()), score);
    }
    (false, _) => {
        // unchanged full-sweep path (inferred_candidates + derive_stats),
        // populates by_range, current_score, and complete together.
    }
}
```

### `protolens/src/tui/heat_cue.rs`

`heat_cue_resolve`'s synchronous no-worker fallback gains the same
three-way branch, calling `inferred_score` in the `(true, false)` case
instead of `inferred_candidates`.

`HeatState`:

```rust
#[derive(Default, Clone, Copy)]
pub(super) struct HeatState {
    best: Option<RangeHeatStats>,
    current: Option<Option<i64>>,
}

impl HeatState {
    fn settled(&self) -> bool {
        match self.best {
            None => false,
            Some(stats) => stats.best_score.is_none() || self.current.is_some(),
        }
    }
}
```

`heat_cue_from_stats` is replaced by a function operating directly on
`HeatState`, implementing the G6 table — returning an enum (or
equivalent) distinguishing the seven display states so `render.rs` can
match on it directly, e.g.:

```rust
pub(super) enum HeatDisplay {
    Unknown,                          // [?]
    None,                             // nothing shown
    PendingCurrent { best: i64 },     // [?/{best}]
    Cue(HeatCue),                     // Mismatch or Tie, glyph shown
}
```

`HeatCueKind::Mismatch { current: Option<i64>, best: i64 }`.

### `protolens/src/tui/render.rs`

Renders each `HeatDisplay` variant per the G6 table: `Unknown` →
`" [?]"` (no glyph); `None` → nothing; `PendingCurrent { best }` →
`" [?/{best}]"` (no glyph); `Cue(HeatCue { kind: Mismatch { current:
None, best }, .. })` → `" [-/{best}]"` with glyph;
`Cue(HeatCue { kind: Mismatch { current: Some(c), best }, .. })` →
`" [{c}/{best}]"` with glyph; `Cue(HeatCue { kind: Tie { tie_count },
.. })` → `" [{tie_count}]"` with glyph (unchanged from today).

### `protolens/src/tui/override_apply.rs`

Line 869's reset becomes `self.heat_states[idx] = heat_cue::HeatState::default();`.

## Test plan

`protolens/src/tui/heat_worker.rs`'s `#[cfg(test)] mod tests`:

- **W-01.** When `by_range` already covers the window but
  `current_score` doesn't cover `current_key`, `heat_worker_loop`
  populates `current_score` without calling `inferred_candidates`
  (assert via the existing `TEST_INFERRED_CANDIDATES_CALLS` counter
  staying at 0, and `by_range`/`complete` unchanged).
- **W-02.** When the window isn't covered, the full-sweep path runs as
  before (`TEST_INFERRED_CANDIDATES_CALLS` increments), populating
  `by_range`, `current_score`, and `complete` together.

`protolens/src/tui/heat_cue.rs`'s test module:

- **H-01..H-07.** One test per row of the G6 table, constructing each
  `HeatState` shape directly and asserting the resulting `HeatDisplay`
  variant, including the `best_score: None` (all-vetoed) and
  `c == best && best_count == 1` (unique optimum) "nothing shown"
  cases.
- **H-08.** `heat_cue_resolve`'s synchronous fallback exercises the
  same `(true, false)` fast path as W-01 (no worker thread involved).

Existing `protolens` regression suite passes unchanged aside from the
`HeatState`/`HeatCueKind` shape updates propagating through
`override_apply.rs` and any snapshot/render tests referencing
`" [pending]"`; `cargo fmt --check` and `cargo clippy --all-targets`
clean.
