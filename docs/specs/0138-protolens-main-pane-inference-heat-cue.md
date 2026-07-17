<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0138 — protolens: main-pane inference-mismatch heat cue

Status: implemented
Implemented in: 2026-07-17
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
- G4 (amended 2026-07-17): gating — the cue is shown for a node if
  and only if `best_score(range)` is present **and**
  `best_score(range) > current_score(range, current_type)` (the best
  available candidate strictly outscores the current typing). This
  replaces the original 10%-margin gate below with a simpler
  strictly-greater comparison, per follow-up feedback.

  ~~the cue is shown for a node if and only if `best_score(range)` is
  present **and** `current_score(range, current_type) <
  best_score(range) * 0.9` (current typing scores more than 10% below
  the best available candidate)~~
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
- G7 (amended 2026-07-17): ANSI-16 fallback (terminals without
  truecolor support) — a simpler 3-state mapping on the same
  `best_score` dimension, recalibrated per follow-up feedback:
  `best_score <= 3` → absent (no cue); `best_score <= 21` → dark red
  (`Color::Red`); `best_score > 21` → bright red (`Color::LightRed`).

  Interaction with the G4 gate (ambiguous in the follow-up feedback,
  resolved here): the G4 gate (`best_score > current_score`) still
  governs *whether* a cue is shown at all — a node whose current
  typing already matches the best-scoring candidate never shows a
  cue, on any terminal. The ANSI-16 thresholds above apply only
  *after* the gate has already passed, and serve two purposes: they
  select which of the two ANSI colors to use, and they impose an
  additional absence rule for low-confidence signals (`best_score <=
  3`) where the "best" candidate isn't a strong enough signal to be
  worth flagging even on a terminal that can't express the fine-
  grained truecolor ramp. Without this reading, a perfectly
  well-typed node (`current_score == best_score`, both large) would
  show a permanent bright-red cue forever on ANSI-16 terminals, which
  would contradict the feature's purpose — so G7's thresholds are
  best read as *narrowing* G4's gate on ANSI-16 terminals, not as an
  independent presence rule.
- G8: absent state — no cue is rendered at all (not a 13th color or
  distinct "level 0" glyph) whenever neither gate (G4 or G9) is
  triggered, including whenever `best_score(range)` itself is
  unavailable (no scoring graph loaded, or the range produced no
  non-vetoed candidates).
- G9 (added 2026-07-17, heat-cue refinements): a second, independent
  cue variant — the **Tie** cue (blue) — for the case G4's gate leaves
  unaddressed: the node's current typing already achieves the top
  score (`current_score == best_score`), but that top score is itself
  shared by at least one other candidate, so the current typing,
  though optimal, isn't the *unique* optimum. Gate: `current_score ==
  best_score` **and** the current type is an actual entry in
  `candidates` (not merely `current_score`'s `0` default coinciding
  with a `best_score` of `0`) **and** `tie_count > 1`, where
  `tie_count` = the number of candidates (including the current type
  itself) whose score equals `best_score`. G4 (`Mismatch`) and G9
  (`Tie`) are mutually exclusive by construction — `Mismatch` requires
  `best > current`, `Tie` requires `best == current` — so a node shows
  at most one cue, never both.
- G10: `Tie`'s brightness level reuses G5's `heat_level` bucketing
  unchanged, applied to the shared top score (`best_score`, which
  equals `current_score` in this branch) — "the same intensity the
  `Mismatch` cue would have had if it were present," per the
  2026-07-17 feedback that introduced G9.
- G11: true-color 12-stop `Tie` gradient tables — derived from G6's
  existing `Mismatch` (red) tables by swapping each stop's R and B
  channels, so the `Tie` gradient carries the exact same luminance
  progression as `Mismatch`'s, in a blue hue instead of red, rather
  than an independently-invented palette:

  | Level | Dark (`DARK_BLUE`) | Light (`LIGHT_BLUE`) |
  |------:|---------------------|------------------------|
  |   1   | `#20203D`           | `#E4EDFD`              |
  |   2   | `#20244A`           | `#D0E0FC`               |
  |   3   | `#222857`           | `#B8D0FB`               |
  |   4   | `#222E6B`           | `#9CB8F8`               |
  |   5   | `#20347F`           | `#7E9EF4`               |
  |   6   | `#1C3996`           | `#6182ED`               |
  |   7   | `#1840AD`           | `#4967E3`               |
  |   8   | `#1349C4`           | `#364ED3`               |
  |   9   | `#0D54DB`           | `#2638BE`               |
  |  10   | `#0860F0`           | `#1A23A2`               |
  |  11   | `#047AFF`           | `#101286`               |
  |  12   | `#06ACFF`           | `#04106E`               |

- G12: `Tie`'s ANSI-16 fallback mirrors G7's structure exactly, on the
  same `best_score` dimension, substituting blue for red: `best_score
  <= 3` → absent (no cue, same low-confidence narrowing as G7);
  `best_score <= 21` → dark blue (`Color::Blue`); `best_score > 21` →
  bright blue (`Color::LightBlue`). Interaction with the G9 gate is
  identical to G7's interaction with G4 (§G7's own explanation applies
  verbatim, substituting `Tie`/G9 for `Mismatch`/G4).

## Non-goals

- N1 (resolved 2026-07-17, suffix amended 2026-07-17 for G9's `Tie`
  cue): the visual placement is a dedicated leading column (one
  character wide, always reserved whether or not a cue is present, so
  node indentation never shifts) showing a single glyph, `●` (U+25CF
  BLACK CIRCLE), styled per G5/G6/G7 (`Mismatch`) or G10/G11/G12
  (`Tie`)'s per-node graduated level. The trailing suffix differs by
  cue kind: `Mismatch` appends ` [<current_score>/<best_score>]`,
  styled unconditionally in the *brightest* available red (truecolor
  level 12, or `Color::LightRed` on the ANSI-16 fallback) whenever the
  cue is present at all — not graduated by level, only the leading
  glyph is. `Tie` appends ` [<tie_count>]` instead, styled identically
  to a `true`/`false` boolean value (`style_for(SyntaxRole::Boolean,
  theme)`, reused directly rather than a new dedicated color) — per
  the 2026-07-17 feedback's explicit request for "the same styling as
  is currently used for a value `true`."
- N6 (added 2026-07-17): interaction with startup root-type
  auto-inference ties. `decode.rs::determine_root_type` already
  refuses to pick a winner on a top-score tie at startup (pre-existing
  behavior, unrelated to and unchanged by this spec — same convention
  the `prototext`/`reproto` CLIs use) — the root node is then decoded
  with no resolved type (`type_fqdn: None`). This interacts with G4
  "for free": the root's `current_type_key` resolves to `None`, which
  never matches any candidate FQDN, so `current_score` defaults to `0`
  and G4's `Mismatch` gate fires (assuming any non-vetoed candidate
  exists) — the root node shows a `Mismatch` cue, with no code change
  needed in either `determine_root_type` or `heat_cue.rs` to produce
  it.
- N2: no relation to, or reuse of, the override selection pane's own
  primitive/enum candidate-row styling (spec 0137 §G8). That feature
  colors rows *inside* the override pane's candidate list; this
  feature colors nodes in the *main* pane, is gated by an entirely
  different condition (best-vs-current score comparison, not row
  kind), and uses a separate, purpose-built palette.
- N3 (superseded 2026-07-17): originally deferred implementation to a
  future session — superseded by follow-up feedback explicitly
  requesting implementation now; see `Status`/`Implemented in` above.
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

Reuses `override_pane::CandidateCache` directly (a second instance,
`App::heat_cache`) rather than introducing a duplicate type — its
shape (`Range<usize> -> Vec<(String, i64)>`, MRU, byte-bounded
eviction) already matches G1 exactly, and nothing about it assumes
capped data. Populated via a call to
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

### Gating (amended 2026-07-17, see G4; G9 added 2026-07-17)

```
Mismatch: best_score > current_score
Tie:      best_score == current_score
          && current type is an actual `candidates` entry
          && tie_count(best_score) > 1
```

Mutually exclusive by construction (`>` vs. `==`) — a node shows at
most one cue.

### Brightness bucketing

A `fn heat_level(best_score: i64) -> u8` (1..=12) implementing G5's
table via a simple ascending comparison against
`[1, 2, 3, 5, 8, 13, 21, 34, 55, 89, 144]`, returning the first bucket
index whose upper bound is `>= best_score`, or `12` if `best_score >
144`.

### Color lookup

Two new `Color` tables per cue kind (dark/light for `Mismatch`, dark/
light for `Tie` — added 2026-07-17), analogous in structure to
`theme.rs`'s existing `dark_rgb`/`light_rgb` modules but *not* placed
alongside the `SyntaxRole`-driven ones, since this is not a
`SyntaxRole` — a dedicated lookup keyed by `heat_level` (1..=12) and a
`HeatHue` selector (`Red`/`Blue`), with the G7/G12 ANSI-16 fallback
selected via `theme::supports_rgb`'s existing detection chain, exactly
as `theme::style_for` already branches per-role today. The `Tie`
suffix's own color needs no such lookup — it reuses
`style_for(SyntaxRole::Boolean, theme)` directly (G9/N1).

### Visibility toggle

Pressing `i` (as in "inferred") in the main pane toggles
`App::heat_cues_hidden`, hiding/showing all heat cues without
discarding the cache.

## Test plan

Covers: G1's lazy population trigger; G2/G3's absent/default-0 edge
cases; G4's `Mismatch` gate around equality (`best_score ==
current_score` must not show a `Mismatch` cue — though it may still
show a `Tie` cue, see below — `best_score == current_score + 1` must
show `Mismatch`); G5's bucket boundaries at each of the 11 Fibonacci
values; G7's ANSI-16 3-state fallback and its interaction with the
gate; the `i` toggle; and that the cue never appears in the override
pane itself, only the main pane.

G9's `Tie` gate (added 2026-07-17): covered by
`tie_gate_fires_when_current_shares_the_top_score_with_others`
(two- and three-way ties both produce `HeatCueKind::Tie` with the
correct `tie_count`, including current) and
`tie_gate_requires_current_type_to_be_an_actual_candidate` (a
coincidental `0 == best_score` default, where the current type isn't
actually in `candidates`, must not produce a `Tie` cue). The
mutual-exclusivity of G4/G9 is exercised implicitly by every
`Mismatch`-asserting test continuing to pass unchanged (a genuine
unique-optimum, no-tie case never trips G9). `render_shows_the_tie_
count_suffix_when_tied_for_best` covers end-to-end rendering: the
glyph column and the ` [tie_count]` suffix (not ` [current/best]`)
appear on a node's header line when its cached candidates tie for the
top score. G10 (brightness reuse) and G11/G12 (blue palette/ANSI16
selection) are covered by `theme.rs`'s
`heat_style_uses_rgb_gradient_when_colorterm_truecolor` and
`heat_style_ansi16_fallback_thresholds`, both extended to assert that
`HeatHue::Red` and `HeatHue::Blue` select distinct colors (truecolor
and ANSI-16 alike) at the same level.
