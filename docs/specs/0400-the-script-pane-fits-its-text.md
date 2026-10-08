<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0400 — the script pane fits its script; text is laid out for 120 columns

Status: draft
App: protolens (script pane), grehack2026 (beats)
Refs: docs/specs/0271-a-script-walks-the-reader-through-the-blob.md (S4:
      the pane's height — 25% of the terminal, clamped to 3..=12 — and
      its word-wrapped text, both of which this spec replaces;
      `--script-height`, which stays);
      docs/specs/0355-script-navigation-keybindings-overhaul.md (space
      pages through a step taller than the pane before advancing);
      docs/specs/0398-a-script-step-scrolls-per-directive.md (each
      directive's lazy reveal, measured against the main pane's height);
      docs/specs/0127-protolens-pan-all-panes.md (G2: Shift+wheel and the
      horizontal wheel pan horizontally)

## Background

The script pane's height ignores its text: 25% of the terminal's rows,
clamped to `3 ..= 12` (spec 0271 S4). A script of two-line steps leaves
most of the pane empty, rows the blob — the thing being explained —
could use; a long step is cut at 12 rows and has to be paged.

The pane word-wraps its text to the pane's width. Lines written wider
than the terminal break in the middle, which wrecks aligned blocks (the
smuggle beat's ASCII table and bit rows) and turns one row into two.

The beats were written to roughly 72–80 columns, so a step took more
rows than a wide terminal requires.

## Goals

- **G1.** The pane is as tall as the script's tallest step, and never
  taller than a third of the terminal. It keeps that height from step to
  step, so the document does not jump while stepping.
- **G2.** A line never breaks: what does not fit the pane's width is
  hidden, and reached by panning the pane horizontally.
- **G3.** Beat text is written for a 120-column line, so a step takes as
  few rows as a presentation terminal allows.
- **G4.** A step's directives reveal their targets against the main pane
  the step is actually drawn with (spec 0398).

## Non-goals

- **N1.** No reflow: protolens neither joins nor re-breaks the author's
  lines. The line breaks are the author's.
- **N2.** The `anomalies` beat (the deck's annex) and the grpconf2026
  beats are not rewrapped; they display under the new rules as they are.
- **N3.** No change to the separator, the step legend, or how space pages
  through a step taller than the pane (spec 0355).

## Specification

- **S1. One height per script (G1).** With navigation on and no
  `--script-height`, the pane's rows are

  ```
  min(max over the script's steps of the step's line count,
      max(1, terminal_rows / 3))
  ```

  with integer division. Lines no longer wrap (S2), so a step's height is
  its line count — independent of the terminal's width. The `3 ..= 12`
  clamp and its constants are removed. A step shorter than the pane
  leaves the rest of the pane blank; a step taller than the cap scrolls,
  and space pages through it before advancing, as today.
  `--script-height` still overrides the computation (spec 0271 S4), and
  navigation off still collapses the pane to zero rows.

- **S2. No wrap; the pane pans horizontally (G2).** The step's lines are
  drawn as written, cut at the pane's right edge. The pane keeps a
  horizontal offset, reset to 0 on every step change (like its vertical
  scroll), bounded by its widest line minus the pane's width. While the
  pointer is over the pane — the same focus PageUp/PageDown already use
  there — Shift+wheel and the horizontal wheel pan it (spec 0127 G2's
  gesture), and so do Alt-Left / Alt-Right. A line cut at the right edge
  shows `›` in the pane's last column, so the presenter sees that
  something is hidden.

- **S3. Reveals use the step's own geometry (G4).** A keypress that
  changes the step works in two phases: `script_apply` first applies the
  step — including spec 0398's reveals, which scroll the document so each
  target is visible — and only then is the frame redrawn. The reveals need
  the document area's height, and the only one at hand, `main_area`, was
  measured at the *previous* frame.

  When the pane is the same height in both frames, that is right — which
  S1 guarantees while stepping. It is wrong when Tab resumes navigation
  (spec 0355): the pane was zero rows while navigation was off, so the
  document area was taller; Tab applies the current step against that
  taller area, then the redraw brings the pane back and the area shrinks
  by the pane's height. A target revealed near the bottom ends up below
  the new bottom edge. (On a 37-row terminal with an 11-row pane: revealed
  at row 30 of about 34, then hidden once only about 23 rows remain.)

  So, before applying a step's directives, `script_apply` sets
  `main_area.height` to the height the coming frame will give it: the
  last frame's main-pane height, plus the pane rows that frame drew,
  minus the pane rows S1 gives now. The redraw then records the same
  value. This edge case predates the spec; S1 makes it the only one left.

- **S4. Beat text is written for 120 columns (G3).** Every line of a
  step's `text`, as the pane shows it (after YAML's indentation is
  stripped), fits in 120 display columns. The grehack2026 beats
  `capture`, `smuggle`, `smuggle2` and `logfile` are reflowed so:
  prose paragraphs re-broken to fill up to 120 columns, with balanced
  line lengths (no one-word last lines); aligned blocks (the key list,
  the ASCII table, the bit rows) and the 👋 lines kept as written;
  numbered items keep their hanging indent. Wording is unchanged.

## Alternatives considered

### One pane height per step

The pane as tall as the current step, capped at a third. Gives a short
step's rows back to the blob, but the document's top edge then moves at
every step by the difference in pane height — the jitter spec 0398's
lazy reveals work to avoid. Per script first; worth revisiting if a
script mixes very short and very long steps.

### Keep wrapping

Wrapping keeps every word on screen, but breaks aligned blocks and makes
a step's height depend on the terminal's width. With text written for
120 columns, a terminal at least that wide shows everything either way;
narrower, a cut line with a `›` marker reads better than a table broken
in two.

### Reflow the text in protolens

Join the author's lines into paragraphs and wrap them to the pane.
Needs a rule for which lines are preformatted — a markup the beats do
not have. Left out (N1).

## Test plan

1. `the_pane_fits_the_tallest_step`: a script whose steps have 2 and 5
   lines, in a 60-row terminal, gets a 5-row pane on both steps.
2. `the_pane_is_capped_at_a_third`: a 40-line step in a 60-row terminal
   gets a 20-row pane, and space pages before advancing.
3. `script_height_still_overrides`: `--script-height 5` gives five rows.
4. `a_long_line_is_cut_not_wrapped`: a 150-column line in a 100-column
   pane occupies one row, ends in `›`, and panning right shows its end.
5. `a_reveal_uses_the_resumed_panes_main_pane`: with navigation off,
   Tab resumes it; the step's `node:` target near the bottom of the main
   pane is on screen after the frame that draws the restored pane.
6. Every line of the four reflowed beats fits in 120 display columns
   (checked at reflow: widest 119, in `smuggle`).
7. Rehearsal: step through the deck on the presentation terminal, at the
   presentation font size. Measured there (kitty, `stty size`): 37 rows ×
   128 columns — wide enough for 120-column text, and a pane cap of 12
   rows (37 / 3), so each beat's tallest step should fit in 12 lines.

## Measured outcome

Filled in at implementation. Already done ahead of it: S4's reflow of the
four beats (widest line 119 columns; directives byte-identical to before).
