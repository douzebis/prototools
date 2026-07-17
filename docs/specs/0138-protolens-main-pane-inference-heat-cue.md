<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0138 — protolens: main-pane inference-mismatch heat cue

Status: draft
Refs: docs/specs/0114-protolens-range-type-override.md (override pane,
      `inferred_candidates`/`score_all` scoring precedent this spec
      reuses), docs/specs/0137-protolens-override-primitive-and-enum-
      candidates.md (unrelated — override-*pane* row styling; explicitly
      distinguished from this main-*pane* feature — see Non-goals),
      `prototext-graph/src/score/walk.rs` (`score_all`, `EntryScore`)
App: protolens

## Background

The override selection pane (spec 0114) already lets a user manually
compare a node's current effective type against `score_all`'s ranked
auto-inference candidates — but only by explicitly opening the pane on
that one node. There is no ambient signal in the main pane itself that
tells a user "this node's current type scores markedly worse than what
auto-inference could offer," so a mistyped or stale override, or a
node that was never typed at all, is easy to miss unless a user
happens to open the override pane on it.

This spec proposes a lazy, cached "heat cue": a per-node visual
indicator in the main pane, shown only when a node's current-type
score is significantly below the best score auto-inference finds for
that node's byte range. The exact visual form the cue takes within the
main pane (text tint, gutter glyph, border/margin decoration, etc.) is
deliberately left open — see Non-goals — this spec defines the
scoring/caching/gating/color model only.

## Goals

- G1: a new, third range-keyed cache (alongside `render_cache.rs`'s
  and `override_pane.rs`'s `CandidateCache`), storing one
  `Vec<(String, i64)>` per node's tag/length-stripped payload byte
  range — the exact shape `override_pane::inferred_candidates` already
  produces (calls `score_all`, sorts descending by score with FQDN
  tie-break, filters `vetoed`). Populated lazily: only when a node is
  actually rendered/displayed in the main pane's current viewport —
  never eagerly for the whole tree. The cache is independent of any
  active override on that node (it depends only on the byte range and
  the schema graph, not on the node's current type), so a single entry
  serves every subsequent lookup regardless of later override changes.
  MRU, byte-bounded eviction mirrors `CandidateCache`'s existing
  `get`/`insert` pattern (`override_pane.rs:105-148`).
- G2: `best_score(range)` = the cached vector's first (highest-score)
  entry's score, or "absent" if the vector is empty or no scoring
  graph is loaded for the session.
- G3: `current_score(range, current_type_fqdn)` = a linear-scan lookup
  of `current_type_fqdn` within that same cached vector, defaulting to
  `0` when not found — including when the node's current type is raw
  (`Empty`), a primitive keyword, or any FQDN the vetoed-filter
  excluded from the ranked list. Not itself cached: derived fresh from
  the single range-keyed vector on every lookup, so it stays correct
  automatically across override changes with no cache-invalidation
  logic needed.
- G4: gating — the cue is shown for a node if and only if
  `best_score(range)` is present **and**
  `current_score(range, current_type) < best_score(range) * 0.9`
  (current typing scores more than 10% below the best available
  candidate). Exact integer-vs-float comparison basis is an
  implementation-time detail (Specification proposes an
  integer-only form to avoid rounding ambiguity).
- G5: true-color brightness dimension — when the gate (G4) is
  triggered, the cue's brightness level (1–12) is selected by matching
  `best_score(range)` (**not** `current_score`) against the Fibonacci
  sequence `1, 2, 3, 5, 8, 13, 21, 34, 55, 89, 144` used as 11
  ascending boundaries. 11 boundaries partition the score axis into
  exactly 12 intervals, matching "12 levels" with no extension or
  reinterpretation needed:

  | Level | `best_score` range |
  |------:|---------------------|
  |   1   | `<= 1`              |
  |   2   | `(1, 2]`            |
  |   3   | `(2, 3]`            |
  |   4   | `(3, 5]`            |
  |   5   | `(5, 8]`            |
  |   6   | `(8, 13]`           |
  |   7   | `(13, 21]`          |
  |   8   | `(21, 34]`          |
  |   9   | `(34, 55]`          |
  |  10   | `(55, 89]`          |
  |  11   | `(89, 144]`         |
  |  12   | `> 144`             |

  Level 1 is dimmest/least urgent, level 12 brightest/most urgent — a
  higher best-available score means a stronger, more confident
  alternative typing exists, warranting a more attention-grabbing cue.
- G6: true-color 12-stop gradient tables — new, purpose-designed
  palettes (not reused from `theme.rs`'s existing VSCode-borrowed
  `SyntaxRole` colors, none of which form a natural 12-step heat ramp).
  Proposed stops, dimmest (level 1) to brightest (level 12):

  Dark theme ("ember → flame"):

  | Level | Hex       |
  |------:|-----------|
  |   1   | `#3D2020` |
  |   2   | `#4A2420` |
  |   3   | `#572822` |
  |   4   | `#6B2E22` |
  |   5   | `#7F3420` |
  |   6   | `#96391C` |
  |   7   | `#AD4018` |
  |   8   | `#C44913` |
  |   9   | `#DB540D` |
  |  10   | `#F06008` |
  |  11   | `#FF7A04` |
  |  12   | `#FFAC06` |

  Light theme ("pale → deep red", ColorBrewer OrRd-inspired, for
  contrast against a white/light background):

  | Level | Hex       |
  |------:|-----------|
  |   1   | `#FDEDE4` |
  |   2   | `#FCE0D0` |
  |   3   | `#FBD0B8` |
  |   4   | `#F8B89C` |
  |   5   | `#F49E7E` |
  |   6   | `#ED8261` |
  |   7   | `#E36749` |
  |   8   | `#D34E36` |
  |   9   | `#BE3826` |
  |  10   | `#A2231A` |
  |  11   | `#861210` |
  |  12   | `#6E1004` |

  These are draft proposals for review, not yet confirmed.
- G7: ANSI-16 fallback (terminals without truecolor support) — a
  simpler, independent 3-state mapping on the same `best_score`
  dimension, exactly as specified: `best_score <= 0` → absent (no
  cue); `best_score <= 13` → dark red (`Color::Red`); `best_score >
  13` → bright red (`Color::LightRed`). Not derived from the 12-level
  truecolor table above — its own coarse rule.
- G8: absent state — no cue is rendered at all (not a 13th color or
  distinct "level 0" glyph) whenever the gate (G4) is not triggered,
  including whenever `best_score(range)` itself is unavailable (no
  scoring graph loaded, or the range produced no non-vetoed
  candidates).

## Non-goals

- N1: the exact visual placement/mechanism of the cue within the main
  pane (text-color tint, gutter/margin glyph, border decoration, or
  otherwise) is explicitly left undetermined here — to be settled by
  a future spec or amendment before implementation.
- N2: no relation to, or reuse of, the override selection pane's own
  primitive/enum candidate-row styling (spec 0137 §G8). That feature
  colors rows *inside* the override pane's candidate list; this
  feature colors nodes in the *main* pane, is gated by an entirely
  different condition (best-vs-current score comparison, not row
  kind), and uses a separate, purpose-built palette.
- N3: no implementation in this pass — this spec is drafted for design
  review only. `Status` remains `draft` until a future session
  implements it.
- N4: no change to override-pane machinery, `splice_override`, or
  `OverrideEntry` — this is a purely additive, read-only main-pane
  rendering feature layered on top of existing scoring/graph
  infrastructure.
- N5: no eager whole-tree pre-computation — population is strictly
  lazy, triggered only by a node's actual main-pane display, mirroring
  `render_cache`/`CandidateCache`'s existing lazy-population
  convention (G1).

## Specification

### New cache (`override_pane.rs` or a new module)

A `InferenceScoreCache` (name TBD at implementation time) mirroring
`CandidateCache`'s exact struct shape and `get`/`insert` MRU,
byte-bounded eviction logic (`override_pane.rs:105-148`), keyed by
`Range<usize>` (tag/length-stripped payload range), storing
`Vec<(String, i64)>` — populated via a call to
`override_pane::inferred_candidates(range_bytes, graph)` the first
time a node's range is looked up, called only from the main-pane
render path when a node is actually within the visible viewport.

### `best_score` / `current_score` derivation

Both are plain helper functions (not further cached) operating on the
`Vec<(String, i64)>` returned by the cache lookup:

```
fn best_score(candidates: &[(String, i64)]) -> Option<i64> {
    candidates.first().map(|(_, score)| *score)
}

fn current_score(candidates: &[(String, i64)], current_type: &str) -> i64 {
    candidates
        .iter()
        .find(|(fqdn, _)| fqdn == current_type)
        .map(|(_, score)| *score)
        .unwrap_or(0)
}
```

### Gating (integer-only, avoiding float rounding)

```
current_score * 10 < best_score * 9
```
equivalent to `current_score < best_score * 0.9` without floating
point — exact form to be confirmed at implementation time.

### Brightness bucketing

A `fn heat_level(best_score: i64) -> u8` (1..=12) implementing G5's
table via a simple ascending comparison against
`[1, 2, 3, 5, 8, 13, 21, 34, 55, 89, 144]`, returning the first bucket
index whose upper bound is `>= best_score`, or `12` if `best_score >
144`.

### Color lookup

Two new `Color` tables (dark/light), analogous in structure to
`theme.rs`'s existing `dark_rgb`/`light_rgb` modules but *not* placed
alongside the `SyntaxRole`-driven ones, since this is not a
`SyntaxRole` — a new, dedicated lookup keyed by `heat_level` (1..=12),
with the G7 ANSI-16 fallback selected via `theme::supports_rgb`'s
existing detection chain, exactly as `theme::style_for` already
branches per-role today.

## Test plan

(Deferred to implementation time — this spec is draft-only. When
implemented, the test plan should cover: G1's lazy population trigger
and MRU eviction; G2/G3's absent/default-0 edge cases; G4's gate
arithmetic at and around the 10% boundary; G5's bucket boundaries at
each of the 11 Fibonacci values; G7's ANSI-16 3-state fallback; and
that the cue never appears in the override pane itself, only the main
pane.)
