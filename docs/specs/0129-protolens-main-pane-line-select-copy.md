<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0129 — protolens: mouse-driven whole-line selection + OS clipboard copy

Status: implemented
Implemented in: 2026-07-15
Refs: protolens/todo.md (2026-07-15 feedback, item 9 — discussion and
      decisions this spec formalizes)
App: protolens

## Background

`handle_click` (tui.rs 3433+) already converts a main-pane mouse
click's screen row into a `line_idx` (`visible_rows[scroll_offset +
rel_row]`) and thence a tree node — the exact row-to-`line_idx` mapping
a drag-based selection needs. `self.lines: Vec<String>` is the
underlying full, untruncated `#@ prototext` text data model (one entry
per line); `render_line_content(line_idx)` already returns a given
line's full text (fold-marker-adjusted) independent of the rendered
viewport's pane borders, current horizontal pan (`pan_offset`), or
terminal width — exactly the source item 9 needs ("I don't need the
borders around panes, and if the text is truncated, I want to copy the
part that is hidden").

The user explicitly rejected relying on the terminal's own native
Shift+drag click selection (works on the rendered viewport only — wrong
source for the reasons above) and explicitly rejected a vim-style modal
visual-select (`v`/`V` + movement) keybinding scheme ("I always find
them difficult to remember") in favor of a purely mouse-driven
selection gesture, confirmed as: select whole lines only (no
character-level boundary), by dragging; copy goes to the real OS
clipboard (not an internal protolens clipboard); colors are not
preserved in the clipboard content (confirmed acceptable — destination-
app ANSI paste support is a property of the destination, and plain text
is the maximally-compatible choice).

No clipboard-access crate exists in this workspace yet.

## Goals

### G1 — drag-to-select whole lines in the main pane

- `MouseEventKind::Down(MouseButton::Left)` over the main pane (already
  routed to `handle_click`, which sets `self.cursor` to the clicked
  node/pane focus as today, unchanged) additionally starts a selection:
  `select_anchor: Option<usize>` set to the clicked `line_idx`,
  `select_end` set to the same value.
- `MouseEventKind::Drag(MouseButton::Left)` over the main pane updates
  `select_end` to the `line_idx` under the current row, using the same
  `visible_rows[scroll_offset + rel_row]` mapping `handle_click` already
  uses. Dragging is clamped to the pane's currently-visible rows for
  this first cut — dragging past the top/bottom edge does not
  auto-scroll (documented limitation, not attempted here).
- Selection is whole-line and column-independent: only `line_idx`
  (start/end row) matters, never the horizontal click/drag position
  within a line — satisfies "I want to copy whole lines, whether the
  actual cursor was pointing in the middle of the line or not."
- The selected range (`min(select_anchor, select_end)..=max(...)`) is
  rendered with a distinct highlight (reuse the cursor row's existing
  `Modifier::REVERSED` treatment, extended to every row in the range —
  no new style needed) — visible for the whole duration of the drag and
  persisting after release until replaced or cleared (see G3).
- `self.cursor` itself never moves during the drag (only the initial
  `Down`, via existing `handle_click`, moves it, same as today's plain
  click) — this is what makes "for all other operations than Copying,
  the selected lines would be equivalent as the first line" true for
  free: every other command already operates on `self.cursor`, which
  always sits on the anchor line, without any multi-line-awareness
  needing to be added to those commands.

### G2 — copy to the OS clipboard on release

- `MouseEventKind::Up(MouseButton::Left)` over the main pane, when a
  selection exists (`select_anchor.is_some()`): build the copied text as
  `render_line_content(i)` for each `i` in the selected range, joined
  with `\n` (full per-line text, fold markers included exactly as
  displayed, but no pane borders and no truncation — sourced from the
  data model, not the viewport), and write it to the real OS clipboard.
- New dependency: `arboard` (cross-platform OS clipboard access — X11/
  Wayland/macOS/Windows). A small helper, e.g. `fn copy_to_clipboard
  (text: &str) -> Result<(), arboard::Error>`, wraps `arboard::Clipboard
  ::new()?.set_text(text)`.
- On success: message bar shows `"N line(s) copied to clipboard"`. On
  failure (e.g. headless/no clipboard provider available in the current
  environment): message bar shows `"clipboard unavailable: {err}"`
  instead of panicking — this is a real, expected failure mode in some
  environments (CI, some remote sessions), not a bug to crash on.
- No ANSI/color escapes in the copied text — plain text only, per the
  user's explicit "OK to give up colors."

### G3 — selection lifecycle

- A selection persists (stays highlighted) after mouse-up, so the user
  can see exactly what was copied, until either:
  - A new `Down(MouseButton::Left)` in the main pane starts a fresh
    selection (replacing the old one — same event that already resets
    `select_anchor`/`select_end` per G1), or
  - `Esc` clears it (alongside whatever else `Esc` already clears, e.g.
    search state) — small addition to `handle_key`'s existing `Esc`
    branch.
- A plain click with no drag (mouse-down then mouse-up at the same
  `line_idx`, no `Drag` events in between) still produces a one-line
  "selection" and therefore still copies that single line to the
  clipboard on release — no special-casing needed, it falls out of G1/
  G2 naturally (`select_anchor == select_end`, range of length 1).

## Non-goals

- No character/column-level selection — whole lines only, confirmed by
  the user ("I don't want precise character boundary, but I want
  precise line selection indeed").
- No preserved colors/ANSI/RTF in the clipboard content.
- No paste support — protolens never needs to *receive* clipboard
  content for this feature, only send it; pasting elsewhere is the
  destination application's job (Ctrl-V/Shift-Ctrl-V there, outside
  protolens).
- No vim-style visual-line mode (`v`/`V`/`y`) — explicitly rejected by
  the user in favor of mouse-only selection.
- No selection support in the override-selection or manage side panes —
  main pane only, per the original request's scope.
- No auto-scroll while dragging past the visible pane edge — documented
  limitation (G1), not implemented in this first cut.
- No internal protolens clipboard/kill-ring — copy always targets the
  real OS clipboard directly.

## Specification

### `Cargo.toml`

- Add `arboard` as a new dependency of `protolens`, with
  `default-features = false` — the default `image`/`image-data` features
  pull in a full image-codec dependency chain (PNG/TIFF/JPEG) irrelevant
  to this spec's plain-text-only clipboard need; disabling them shrinks
  the new dependency footprint from ~33 to ~15 crates while retaining the
  platform clipboard backends actually needed (`x11rb` on Linux,
  `objc2-*` on macOS, `clipboard-win` on Windows).

### `App` struct (tui.rs)

- New fields: `select_anchor: Option<usize>`, `select_end: Option<usize>`
  (both `line_idx`, not screen row — `None`/`None` when no selection is
  active).

### `handle_mouse` (tui.rs)

- New helper `main_pane_line_idx(&self, col: u16, row: u16) -> Option
  <usize>` factored out of `handle_click`'s row-to-`line_idx` lookup
  (bounds-check against `main_area`, `visible_rows[scroll_offset +
  rel_row]`) — shared by `handle_click` and the new drag-select tracking
  below, avoiding duplicating the lookup as this section originally
  contemplated as a fallback.
- `Down(MouseButton::Left)` branch: after the existing `handle_click`
  call, also sets `select_anchor = select_end = self.main_pane_line_idx
  (event.column, event.row)` (`None` if the click somehow lands outside
  `main_area`, matching `handle_click`'s own no-op in that case).
- New match arms (checked when `over_main`, after the `Down` branch
  returns): `MouseEventKind::Drag(MouseButton::Left)` updates `select_end`
  via `main_pane_line_idx` when it resolves to `Some` (an out-of-bounds
  drag position leaves `select_end` untouched — the "no auto-scroll"
  behavior G1 documents falls out of this for free); `MouseEventKind::Up
  (MouseButton::Left)` calls `copy_selection_to_clipboard`, leaving
  `select_anchor`/`select_end` as-is so the highlight persists per G3.
- `selected_text(&self) -> Option<(usize, String)>`: builds the
  `render_line_content`-per-line, `\n`-joined text and line count for the
  current selection (`None` if none active) — split out from
  `copy_selection_to_clipboard` specifically so the text-building logic
  is unit-testable without depending on real OS clipboard access
  (unavailable in this repo's headless/CI test environment).
- `copy_selection_to_clipboard(&mut self)`: calls `selected_text`, then
  the free function `copy_to_clipboard(text: &str) -> Result<(),
  arboard::Error>` (`arboard::Clipboard::new()?.set_text(text)`), setting
  `self.message` to the success/failure text per G2.
- `Esc` (main pane, no override pane open): new unconditional match arm
  clearing `select_anchor`/`select_end`, added alongside the existing
  `Esc if self.override_target.is_some()` arm in the same match.

### `render` (tui.rs)

- When `select_anchor`/`select_end` are both `Some`, apply
  `Modifier::REVERSED` to every row in `min..=max` the same way the
  single cursor row already gets it (tui.rs ~3668-3672), instead of only
  the exact cursor row — the two conditions can coexist (cursor row is
  always inside or adjacent to the selection in practice, no special
  handling needed since `REVERSED` on an already-`REVERSED` span is a
  no-op).

## Test plan

1. Click-drag across N main-pane rows, release — clipboard contains the
   N lines' full text (via `render_line_content`), newline-joined,
   regardless of horizontal pan/truncation state at the time.
2. Plain click, no drag — clipboard contains exactly that one line's
   full text.
3. Dragging upward (end row above start row) still copies the correct
   range in top-to-bottom document order (not reversed).
4. Selection highlight persists after release; a subsequent fresh click
   starts a new selection and clears the old highlight; `Esc` clears an
   existing selection's highlight too.
5. Clipboard-unavailable path (mock/stub `arboard::Clipboard::new()`
   failure, or run under a headless test harness) shows the fallback
   message instead of panicking.
6. `reuse lint` passes (new `arboard` dependency needs its own license
   accounted for, if `reuse lint` checks `Cargo.lock`/vendored
   licenses — verify against this repo's existing convention for other
   third-party crates).
