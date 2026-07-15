<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0126 — protolens: F1 help and Shift-Up/Down regardless of pane focus

Status: implemented
Implemented in: 2026-07-15
Refs: protolens/todo.md (2026-07-15 feedback, items 3/5 — decisions this
      spec formalizes)
App: protolens

## Background

Two small, independent `handle_key` fixes, bundled into one spec because
both are trivial and were decided without further discussion:

- **F1** (help) is currently only reachable from the bottom of
  `handle_key`'s main-pane match arm (tui.rs ~2681) — every other branch
  checked earlier in the function (`help_open`, `command_buffer`,
  `override_focus`, `manage_focus`) returns before reaching it, so F1
  does nothing while any side pane has focus or a command line is open.
- **Shift-Up/Shift-Down** in the main pane should circulate the cursor
  among the current node's siblings — this already exists verbatim as
  `J`/`K` (`next_sibling`/`prev_sibling`, no-op-with-message when the
  node has no siblings), just not bound to the Shift-arrow chords, which
  are currently unused (`Shift-Left`/`Shift-Right` are fold/unfold-all,
  a different, non-conflicting pair).

## Goals

### G1 — F1 works regardless of focus

- Move the `F1` -> `help_open = true` (or toggle) handling to the same
  top tier of `handle_key` as the existing `Ctrl-Z`/`quit_confirm`
  checks — i.e. checked unconditionally before `help_open`/
  `command_buffer`/`override_focus`/`manage_focus` early-returns, so it
  fires no matter what currently has focus.
- No behavior change to what F1 *does* once triggered — only *when* it's
  reachable.

### G2 — Shift-Up/Shift-Down alias `J`/`K`

- Bind `KeyCode::Up` + `KeyModifiers::SHIFT` to the same handler
  `K` (`prev_sibling`) already calls; `KeyCode::Down` + `SHIFT` to the
  same handler `J` (`next_sibling`) already calls.
- Only active in the main pane (same scope `J`/`K` already have) — no
  change needed elsewhere.

## Non-goals

- No change to what F1's help screen displays, or to `J`/`K`'s existing
  behavior/messages — this spec only adds reachability (G1) and a key
  alias (G2), no new logic.
- No change to `Shift-Left`/`Shift-Right`'s existing fold/unfold-all
  behavior.

## Specification

- `handle_key` (tui.rs): move the F1 branch up to sit alongside the
  Ctrl-Z/quit_confirm checks near the top of the function.
- `handle_key`'s main match arm: add `(KeyCode::Up, SHIFT)` and
  `(KeyCode::Down, SHIFT)` arms calling the same functions as the
  existing `K`/`J` arms.

## Test plan

1. F1 opens/closes help while `override_focus` is true, while
   `manage_focus` is true, and while `command_buffer` is `Some(...)`.
2. Shift-Down on a node with next siblings moves to the next sibling
   (same result as `J`); Shift-Down on an only-child is a no-op with the
   same message `J` already produces. Same for Shift-Up/`K`.
3. `reuse lint` passes.
