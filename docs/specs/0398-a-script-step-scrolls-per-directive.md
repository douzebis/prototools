<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0398 — a script step reveals each directive's own target, lazily, in turn

Status: draft
App: protolens
Refs: docs/specs/0271-*.md (a step declares a view; S6/S10/S14);
      docs/specs/0279-*.md (S5: the end-of-step `node:` climb this spec
      removes);
      docs/specs/0397-path-highlight-and-script-focus.md (S2/S3/S5/S6:
      the lazy focus, too-tall rule, baseline, and select_lines range —
      all folded into the single end-of-step `script_focus` this spec
      breaks up and simplifies);
      docs/specs/0242-*.md (S7: a reveal is the minimum movement that
      brings a target on screen)

## Background

A script step applies its directives in YAML order (spec 0366) and then
calls `script_focus` **once, at the end**, keyed on the final cursor and
measuring that cursor's *whole subtree*. Two things are wrong with that.

- When a later directive moves the cursor, the end-of-step focus frames
  the wrong thing. The capture beat (`grehack2026/beats/capture`) is the
  reproduction: a step is `node: /` + `fold: ["/ 1", "/1 Z"]` +
  `search: /1`. `search: /1` highlights the `grid {` header — one line,
  already on screen at the rooted view — but leaves the cursor on `/1`,
  whose unfolded subtree (hundreds of cell rows) is far taller than the
  pane. The end-of-step focus measures that subtree, fires the too-tall
  rule, and pushes the root one row off the top. Measured with a
  tall-first-field fixture in a ten-row pane: `scroll_top = 1`, the root
  header at terminal row −1, the search hit at `(line, column, width) =
  (1, 2, 18)` — a single already-visible line.

- The single pass has no notion of directive *order*. A `node:` after a
  `search:`, or two reveals that disagree, have no defined composition.

The fix is to let each directive reveal its own target as it is applied.
What a step shows is then the composition of those reveals, in order, and
"show this, then show that" is the actual rule rather than an accident of
which directive ran last.

## Goals

- **G1.** Each directive brings *its own* target fully on screen, lazily,
  when it is applied — in the order the directives are written.
- **G2.** A reveal of something already fully visible does not scroll,
  whatever an unrelated node's extent is. The capture beat holds the root
  in place across its steps.

## Non-goals

- **N1.** No change to *what* a directive selects, highlights, or puts
  the caret on — only to the scrolling each one does.
- **N2.** The interactive `w` gesture's own re-anchor (spec 0397, in
  `set_wire_span`) is untouched; this spec is about the scripted path.

## Specification

- **S1. Each position-sensitive directive reveals its target when
  applied (G1).** The per-directive loop in `script_apply` already runs
  in YAML order; each directive now also reveals its target as part of
  being applied, from the scroll the previous directive left. There is no
  separate end-of-step focus pass, and no baseline snapshot (spec 0397 S5
  is subsumed: churn never accumulates because nothing re-measures the
  whole step after the fact).

- **S2. A reveal is lazy and minimal (G1, G2).** Given a target's extent
  in visible rows — its first and last on-screen rows — a reveal:
  - does nothing when the whole extent already lies within the viewport;
  - else scrolls the minimum that brings it on screen (spec 0242 S7);
  - else, when the extent is taller than the pane, puts its first row at
    the top of the viewport.

  This is the one rule; the directives differ only in the extent they
  hand it.

- **S3. The extents.**
  - `node:` → the node's own **visible subtree** (fold-aware,
    `lines_visible`). Not its ancestors: the spec 0279 S5 climb and its
    preceding-sibling caption are **removed** — a `node:` shows the node,
    nothing around it.
  - `select_line:` / `select_node:` / `select_lines:` → the **selection
    span**, first line through last.
  - `search:` → the **matched text**, which may span more than one line;
    the reveal covers the hit from its first to its last line.
  - `wire_*:` → unchanged: `set_wire_span` already re-anchors (N2).

- **S4. The last directive wins the display.** Reveals run in YAML order,
  each from the scroll the previous one left, so the step is framed by its
  **last** position-sensitive directive. This is not a separate rule — it
  falls out of S1 (reveal as applied) and S2 (each reveal is minimal, so
  earlier ones that still hold do not fight the last) — but it is the fact
  a beat author composes against: end a step with the directive whose
  target should frame it. The capture beat ends each step with `search:`,
  so the hit frames it; the anomalies beat ends with `select_line:` /
  `wire_lines:`, so the selection or wire span does.

- **S5. `node:` leads in practice.** A step places the caret with `node:`
  before it can `search:`, because a search runs *from* the cursor (its
  origin, spec 0357). So `node:` is naturally first and is therefore
  rarely the last reveal — which is correct: `node:` is there to seat the
  caret and give the search somewhere to start, not usually to frame the
  view. A step with no `search:`/`select:`/`wire:` after it is framed by
  `node:` alone, as before.

- **S6. Folds come first in practice.** A step that reveals a deep target
  folds the document down around it (`fold: ["/ 1", "/N Z"]`) before the
  reveal, so the target's own subtree is what is left to show. This is a
  beat-authoring convention, not a protolens rule, but it is why dropping
  the climb (S3) loses nothing: the context a reader needs is the folded
  siblings, which the reveal of a now-small target keeps on screen.

## Alternatives considered

### Keep the end-of-step focus; special-case the search hit

The smallest fix — when a search highlight is active, have the single
end-of-step `script_focus` measure the hit's line rather than the cursor
node — repairs the capture beat but keeps a model in which directive
order still does not matter. The per-directive reveal is what makes "do
each thing in turn" the rule.

### Keep the `node:` climb (spec 0279 S5)

The climb opens a deep `node:` target at its outermost fitting ancestor
and reaches over a preceding sibling, so a caption beside the target
stays on screen — which the anomalies beat relied on. It is dropped here
(S3) in favor of the uniform lazy reveal: with the beats' existing
`fold: ["/ 1", "/N Z"]` the folded siblings already sit on screen around
the revealed target, so the caption survives without a special rule, and
every directive then obeys one reveal rule instead of two. The anomalies
beat is re-checked under the new rule (test plan item 3); if a caption is
lost, it is restored in the beat, not by reviving the climb.

## Test plan

1. `a_search_hit_on_a_tall_node_does_not_scroll` — `node: /` +
   `fold: ["/ 1", "/N Z"]` + `search: /N` on a tall-first-field fixture
   leaves `scroll_top` at 0 and the root header at terminal row 0, for
   each top-level field.
2. `a_search_scrolls_minimally_to_an_offscreen_hit` — the same shape with
   the hit below the fold scrolls just enough to show the hit's line, no
   more (it lands on the last row, not the first).
3. `a_node_reveal_no_longer_climbs_to_an_ancestor` — a deep `node:`
   target that fits opens on its own subtree, with no ancestor pulled to
   the top; and the anomalies walk still resolves every position
   (`batch_script`), read back after the change.
4. The smuggle beat's byte-selection steps (spec 0397 S6) still reveal the
   whole selected range and still do not scroll between contiguous cells.

## Measured outcome

Filled in at implementation.
