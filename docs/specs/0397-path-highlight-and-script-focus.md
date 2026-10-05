<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0397 — a path match highlights its whole line

Status: implemented
Implemented in: 2026-10-05
App: protolens
Refs: docs/specs/0246-the-search-prompt-browses-history-and-rotates-matches.md
      (S9/S22: a path match was one stop owning a single cell);
      docs/specs/0273-*.md (a main-pane line's haystack is its path when
      the pattern is one);
      docs/specs/0396-prototext-is-canonical.md (the smuggle beat whose
      rehearsal surfaced the issue);
      docs/specs/0398-a-script-step-scrolls-per-directive.md (**supersedes
      this spec's scroll half** — S2–S6 below described a single
      end-of-step `script_focus`, which 0398 replaced with a per-directive
      reveal; only the whole-line tint, S1, remains in force here)

## Background

Rehearsing the GreHack "hidden bits" beat (spec 0396) turned up a path
search (`/1/1/2`) that highlighted only the **first character** of the
matched line. The match names a node, not a span of text, so spec 0246
S22 gave it `width: 1`; on screen that is a one-cell tick, not a legible
"this line" highlight.

(The same rehearsal also turned up a scripted-scroll rough edge, which
this spec first addressed with a `script_focus` rework. That half was
superseded by spec 0398 — see the Specification note below.)

## Goals

- **G1.** A path match highlights the whole matched line, not one cell.

## Non-goals

- **N1.** No change to what a path match *selects* (the node) or where
  the caret lands (the row's first non-blank, spec 0235 S20) — only to
  the tint's width.

## Specification

- **S1. A path match tints the whole line (G1).** In `sweep_test`, a
  path match reports `column` at the line's first non-blank and `width`
  spanning from there through the last non-blank of the rendered line
  (`text.trim_end()`), measured in characters, at least 1. The haystack
  is the same display text a text match uses, so the tint covers exactly
  what is drawn. The match still owns the node and lands the caret as
  before (N1).

- **S2. A step can select a contiguous *range* of nodes.** A
  `select_lines: {from, to}` directive selects from `from`'s first line
  through `to`'s last line — the multi-node twin of `select_line`,
  mirroring `wire_lines`. Both ends resolve like any position; an
  unresolved end is a step diagnostic and selects nothing. The selection
  uses the existing two-ended `SelectionSpan` machinery (anchor at
  `from`'s header column 0, caret at `to`'s last line, full-line), so it
  needs no new selection state. How the range drives the view is spec
  0398 (each directive reveals its own target).

### Superseded: the scroll half (was S2–S6)

This spec first paired the path tint with a rework of how a script step
scrolls — a single end-of-step `script_focus` with an already-visible
shortcut, a too-tall rule, the spec 0279 ancestor climb, a pre-directive
baseline, and a range-aware extent. Spec 0398 replaced that whole model
with a per-directive lazy reveal and dropped the climb; the fields and
helpers those sections named no longer exist. The history is in `git
log`; the live rule is 0398.

## Alternatives considered

### Leave the path highlight one cell, fix it in the beat

A beat cannot widen the tint; the width is computed in `sweep_test`.
And a one-cell highlight reads as a cursor, not a selection, for every
path search, not only this beat's — so the fix belongs in protolens.

## Test plan

1. `a_path_match_highlights_the_whole_line`: a `/3` match on a scalar
   row reports a width equal to the line's content width, > 1.
2. `select_lines_parses_as_a_range_directive` /
   `select_lines_directive_spans_a_range_of_nodes` /
   `select_lines_with_an_unresolved_end_is_a_diagnostic`: the directive
   parses, selects `from`..`to`, and reports an unresolved end.

(The scroll tests this spec first listed moved to spec 0398.)

## Measured outcome

Measured 2026-10-05 on the development machine.

- S1: `a_path_match_highlights_the_whole_line` passes; the search tests
  pass.
- S2: the three `select_lines` tests pass.
- The whole protolens suite passes; `cargo fmt --check` and clippy are
  clean.

The scroll rework this spec first carried was superseded by spec 0398
the same day; its measured outcome lives there.
