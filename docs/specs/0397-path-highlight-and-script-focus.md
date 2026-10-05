<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0397 — a path match highlights its whole line; a script view scrolls only when it must

Status: implemented
Implemented in: 2026-10-05
App: protolens
Refs: docs/specs/0246-the-search-prompt-browses-history-and-rotates-matches.md
      (S9/S22: a path match was one stop owning a single cell);
      docs/specs/0273-*.md (a main-pane line's haystack is its path when
      the pattern is one);
      docs/specs/0279-*.md (S5: a script step declares a view, scrolled
      so the outermost fitting ancestor opens the pane);
      docs/specs/0396-prototext-is-canonical.md (the smuggle beat whose
      rehearsal surfaced both issues)

## Background

Rehearsing the GreHack "hidden bits" beat (spec 0396) turned up two
rough edges in how protolens handles a scripted path search.

- A path search (`/1/1/2`) highlighted only the **first character** of
  the matched line. The match names a node, not a span of text, so spec
  0246 S22 gave it `width: 1`. On screen that is a one-cell tick, not a
  legible "this line" highlight.
- A script step that searches a node deep inside a tall subtree (a cell
  in a ≥20×20 grid) scrolled that node to the top of the pane
  (`script_focus`, spec 0279 S5), pushing the message's own first lines
  (`grid {`, `rows {`, the first cell) off the top — so the presenter
  had to pan up by hand. The wire panel, which makes the node's row
  taller, made it worse. `script_focus` runs after the directives, on
  the post-search cursor, so a `node:` directive did not change this.

## Goals

- **G1.** A path match highlights the whole matched line, not one cell.
- **G2.** A script step does not scroll when the node it shows is already
  on screen; scrolls to reveal it when it is off screen; and when the
  node is simply too tall to fit, opens the pane on the node's own first
  line.

## Non-goals

- **N1.** No change to what a path match *selects* (the node) or where
  the caret lands (the row's first non-blank, spec 0235 S20) — only to
  the tint's width.
- **N2.** No change to the reader's own `clamp_scroll_to_cursor` rule,
  which is separate from a script step's declared view (spec 0279 S5).

## Specification

- **S1. A path match tints the whole line (G1).** In `sweep_test`, a
  path match reports `column` at the line's first non-blank and `width`
  spanning from there through the last non-blank of the rendered line
  (`text.trim_end()`), measured in characters, at least 1. The haystack
  is the same display text a text match uses, so the tint covers exactly
  what is drawn. The match still owns the node and lands the caret as
  before (N1).

- **S2. A visible node is not scrolled (G2).** In `script_focus`, before
  the ancestor climb, if the step's node is already fully on screen — its
  first drawn row at or below the current scroll top and its last drawn
  row at or above the bottom — return without changing the scroll. "Its
  last drawn row" includes the node's **visible** subtree (fold-aware,
  `lines_visible`) and, when a wire panel is open for the step, its wire
  rows: both are already folded into the row heights `script_focus`
  measures with, so no extra bookkeeping is needed.

- **S3. A too-tall node opens on its own first line (G2).** Still in
  `script_focus`, after S2: if the node's own extent (subtree + wire)
  is taller than the pane, set the scroll so the node's first line is
  the pane's top row, and stop — no ancestor climb and no preceding-
  sibling caption, since neither can fit above a node that already
  overflows.

- **S4. Otherwise, climb as before (spec 0279 S5).** When the node is off
  screen but fits, the existing rule stands: open the view at the
  outermost ancestor that fits, and reach back over its preceding
  sibling when the two still fit together.

## Alternatives considered

### Leave the path highlight one cell, fix it in the beat

A beat cannot widen the tint; the width is computed in `sweep_test`.
And a one-cell highlight reads as a cursor, not a selection, for every
path search, not only this beat's — so the fix belongs in protolens.

### Make `script_focus` always scroll minimally

Dropping the climb entirely (always "scroll just enough") reintroduces
the bug spec 0279 S5 was written against: a step's node lands on the
pane's last row with its subtree and wire off the bottom. The climb is
kept for the off-screen-but-fits case (S4); only the already-visible
(S2) and too-tall (S3) cases are new.

## Test plan

1. `a_path_match_highlights_the_whole_line`: a `/3` match on a scalar
   row reports a width equal to the line's content width, > 1.
2. `a_step_does_not_scroll_when_its_node_is_already_visible`: a step
   aimed at a node the previous step's view already shows in full leaves
   the scroll untouched.
3. `a_step_too_tall_to_fit_opens_on_its_own_first_line`: a step aimed at
   a node taller than the pane puts the node's first line at terminal
   row 0.
4. The existing `script_focus` tests (`a_step_leaves_room_below_its_node`,
   `a_step_keeps_the_row_above_its_subtree`) still pass: the off-screen
   climb (S4) is unchanged.

## Measured outcome

Measured 2026-10-05 on the development machine.

- S1: `a_path_match_highlights_the_whole_line` passes; the 130 search
  tests pass.
- S2/S3: the two new `script.rs` tests pass, and the two pre-existing
  `script_focus` view tests still pass (S4 unchanged).
- The smuggle beat (spec 0396), driven headlessly through protolens's
  `script` mode, no longer relies on the presenter panning up: cells 1
  and 2 and their wire sit below the message head, which stays on
  screen.
- The whole protolens suite passes; `cargo fmt --check` and clippy are
  clean.
