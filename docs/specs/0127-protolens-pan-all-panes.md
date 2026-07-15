<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0127 — protolens: Shift+wheel/native horizontal-scroll pan, all panes

Status: implemented
Implemented in: 2026-07-15
Refs: protolens/todo.md (2026-07-15 feedback, item 4 — discussion and
      decisions this spec formalizes)
App: protolens

## Background

Horizontal pan (`pan_offset`/`pan_left`/`pan_right`, tui.rs 746-754) is
currently a single global field, wired only to `Ctrl-Left`/`Ctrl-Right`
and applied only to the main pane's rendered lines (`pan_spans(...,
self.pan_offset)` in `render`). Neither the override-selection pane, the
manage pane, nor the single-line command/message bar has any horizontal
scroll at all — the command/message bar in particular just silently
clips `cmd_text` (and can walk the terminal cursor off-screen) once it
exceeds the bar's width, confirmed by reading `render`'s bottom-bar
block (tui.rs ~3694-3719).

crossterm 0.28's `MouseEvent` already carries `modifiers: KeyModifiers`
on every event, including `ScrollUp`/`ScrollDown`, and separately
exposes native `ScrollLeft`/`ScrollRight` variants (real horizontal
wheel/trackpad/tilt-wheel input, no modifier needed) — both usable today
with no new dependency. By contrast, `MouseButton` has only
`Left`/`Right`/`Middle` at every crossterm version checked (0.27/0.28/
0.29) — back/forward side-button presses have no wire representation in
the X10/SGR terminal mouse-reporting protocols crossterm implements, so
they cannot reach the application at all, in any terminal. This spec
therefore only covers Shift+wheel and native `ScrollLeft`/`ScrollRight`.

## Goals

### G1 — per-pane pan state

- Add one `pan_offset: usize` field per pane that can now scroll
  horizontally: the existing main-pane field stays as-is; add a new one
  each for the override-selection pane, the manage pane, and the
  command/message bar. Each resets to `0` when its owning pane closes or
  its content changes in a way that invalidates the offset (mirroring
  how the main pane's `pan_offset` is already bounded by
  `max_visible_line_len()`).
- The command/message bar had no auto-scroll-to-cursor-while-typing
  behavior prior to this spec (confirmed while implementing — Background
  above already states this; there was nothing to "coexist with"). This
  spec adds one, sharing `command_pan_offset` with manual pan rather than
  using a second field: `render` clamps `command_pan_offset` each frame
  so the cursor position stays within the visible width whenever a
  command/search/rename buffer is actively being typed (mirroring the
  main pane's vertical `scroll_offset` auto-following the cursor row).
  Manual Shift+wheel/native-scroll pan on the same field still works when
  hovering the bar; it is simply re-clamped back into view on the next
  keystroke while typing, the same way manually scrolling the main pane
  vertically doesn't survive the next cursor move either.

### G2 — Shift+wheel and native ScrollLeft/ScrollRight pan whichever pane is under the pointer

- `handle_mouse`'s existing hover-based routing (already dispatches
  `ScrollUp`/`ScrollDown` to whichever pane the pointer is over,
  independent of keyboard focus) gains:
  - `ScrollUp`/`ScrollDown` + `KeyModifiers::SHIFT` -> pan
    left/right (by the same `PAN_STEP` the keyboard pan already uses)
    on the hovered pane's own `pan_offset`, instead of the normal
    vertical-scroll action.
  - `ScrollLeft`/`ScrollRight` (native, any/no modifiers) -> pan
    left/right on the hovered pane's own `pan_offset`, same as above.
- Side-button (back/forward) input: dropped from scope — not
  representable in crossterm's `MouseButton`/mouse-reporting model at
  all (see Background).

## Non-goals

- No change to existing keyboard `Ctrl-Left`/`Ctrl-Right` pan bindings —
  those keep working exactly as today for the main pane; this spec does
  not add keyboard pan bindings for the new panes (mouse-only for those,
  per item 4's own scope — it never asked for new keyboard chords).
- No side-button support of any kind (see Background) — confirmed
  dropped, not deferred pending a workaround.
- No change to vertical scroll behavior/keys.

## Specification

### `App` struct (tui.rs)

- New fields: `override_pan_offset: usize`, `manage_pan_offset: usize`,
  `command_pan_offset: usize`, each initialized to `0`.
- New field `cmd_area: Option<Rect>` — the bottom command/message bar's
  inner `Rect` as of the last `render()` call, `None` when the bar isn't
  shown at all (no `message`/command buffer to display). Needed for
  `handle_mouse` hover-detection the same way `main_area`/`side_area`
  already serve the main/side panes; `Option` (rather than
  `Rect::default()`) because, unlike the other two, this pane is
  routinely absent, not just zero-sized.
- `override_pan_offset`/`manage_pan_offset` are reset to `0` at every
  point that already resets `override_scroll`/`manage_scroll` (pane
  open, candidate-list recompute, `:restore-overrides`, etc.) — the same
  "content changes invalidate it" rule G1 describes, riding the existing
  reset call sites rather than adding new ones.
- Unlike the main pane's `pan_right` (clamped to
  `max_visible_line_len() - width`), `override_pan_offset`/
  `manage_pan_offset` pan right unclamped (`saturating_add`) — panning
  past the last visible character just renders a blank row, recoverable
  by panning left; adding an equivalent clamp for these short, single-
  line-per-row panes was judged not worth the extra complexity.

### `render` (tui.rs)

- Apply the override pane's `pan_offset` when rendering its rows
  (`render_override_pane`), the manage pane's when rendering its rows
  (`render_manage_pane`), and the command bar's when rendering
  `cmd_text`, the same way `pan_spans(..., self.pan_offset)` already
  applies to the main pane — each pane's own line(s) wrapped in a
  length-1 `Vec<Span>` before calling `pan_spans`, since none of the
  three render pre-split multi-span lines the way the main pane's syntax
  highlighting does.
- The command bar additionally computes the cursor's character position
  within `cmd_text` (`1 + command_cursor` while a command/search buffer
  is open, `RENAME_PREFIX.chars().count() + buf.chars().count()` while
  renaming) and clamps `command_pan_offset` so that position stays
  within the bar's visible width before rendering — the auto-follow
  behavior described in G1.

### `handle_mouse` (tui.rs)

- Extend the existing hover-routing match to handle `ScrollLeft`/
  `ScrollRight` (unconditional) and `ScrollUp`/`ScrollDown` with
  `modifiers.contains(KeyModifiers::SHIFT)` as pan actions on whichever
  pane's `pan_offset` corresponds to the hovered area (main, override,
  manage, or the command bar via the new `cmd_area`), falling through
  to the existing vertical-scroll behavior when the modifier isn't held
  and the event isn't a native horizontal-scroll one.

## Test plan

1. Hovering the main pane, Shift+`ScrollDown`/`ScrollUp` pans right/left
   (existing `pan_left`/`pan_right` semantics, just mouse-triggered);
   plain `ScrollDown`/`ScrollUp` (no Shift) still scrolls vertically as
   today.
2. Native `ScrollLeft`/`ScrollRight` pans the hovered pane without
   needing Shift.
3. Hovering the override pane / manage pane / command bar and
   Shift+wheel-ing pans that pane's own content independently of the
   main pane's `pan_offset`.
4. A long `:command` buffer becomes pannable — typing past the visible
   width no longer silently clips with the cursor invisible off-screen.
5. `reuse lint` passes.
