<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0131 — protolens: explicit Ctrl-C copy key + OSC 52 clipboard fallback

Status: implemented
Implemented in: 2026-07-15
Refs: docs/specs/0129-protolens-main-pane-line-select-copy.md (G2's
      auto-copy-on-release, dropped by this spec; `selected_text`/
      `copy_selection_to_clipboard`/`copy_to_clipboard` machinery,
      reused by this spec),
      protolens/todo.md (2026-07-15 feedback round 2, item 3 —
      discussion and decisions this spec formalizes)
App: protolens

## Background

Spec 0129 shipped mouse-only copy: `MouseEventKind::Up(MouseButton::
Left)` (tui.rs ~3653) copies the current drag-selection automatically
on release, via `copy_selection_to_clipboard`, and there was no
keyboard-only way to copy at all. Follow-up feedback raised three
points:

- Over SSH (no X11/Wayland forwarding), `arboard::Clipboard::new()`
  fails — reproduced in this repo's own headless test sandbox with an
  X11-connection-timeout error, matching the user's own report.
- Copying should also work with no drag-selection active, from just the
  cursor's current main-pane line.
- There was no explicit keybinding for copy at all — and, per the
  discussion, an explicit key is wanted even for the mouse-selection
  case (decoupling "select" from "copy" into two clear steps, rather
  than copying implicitly on every mouse-up).

`selected_text()` (tui.rs ~3668) and `copy_selection_to_clipboard()`
(tui.rs ~3682) already implement the selection-to-clipboard machinery
this spec reuses unchanged; `copy_to_clipboard` (tui.rs ~4429) is the
`arboard`-based free function actually writing to the OS clipboard.
`cursor_display_row()` (tui.rs ~3800) resolves the cursor's `line_idx`
within `visible_rows` (`self.visible_rows[self.cursor_display_row()]`
gives the `line_idx` itself) — the exact lookup needed for the
cursor-line fallback.

`Ctrl-C` is confirmed unbound anywhere else in tui.rs today (no
existing `KeyCode::Char('c')` + `KeyModifiers::CONTROL` match arm).
Since protolens runs the terminal in raw mode (crossterm), `Ctrl-C`
arrives as a normal `KeyEvent`, not a process `SIGINT` — safe to bind
without any special signal handling.

OSC 52 is a terminal (not X-server) escape sequence
(`ESC ]52;c;<base64>\x07`, more precisely `\x1b]52;c;{base64}\x07`)
asking the *local* terminal emulator to set its own clipboard —
transparent through SSH with no `-X`/`-Y` forwarding needed. Support:
iTerm2, kitty, foot, WezTerm, tmux (with `set-clipboard on` and
passthrough), and Alacritty (configurable `osc52` permission level in
`alacritty.toml`: allow/deny/clipboard-only) all support it; plain
xterm does not by default.

## Goals

### G1 — `Ctrl-C` is the single, explicit copy key

- New main-pane keybinding, `Ctrl-C`: copies the active drag-selection
  if one exists (`select_anchor`/`select_end` both `Some` — unchanged
  `selected_text()` logic), else falls back to the cursor's own current
  line (`self.visible_rows[self.cursor_display_row()]`, treated as a
  length-1 selection for the copy) — same underlying
  `copy_to_clipboard` write and success/failure `self.message` text as
  today.
- `MouseEventKind::Up(MouseButton::Left)` (tui.rs ~3653) no longer
  calls `copy_selection_to_clipboard` — mouse release only finalizes/
  persists the drag-highlighted selection (unchanged G1/G3 behavior
  from spec 0129), it does not by itself write to the clipboard
  anymore. `Ctrl-C` becomes the sole trigger for the actual clipboard
  write, whether the selection came from a mouse drag or is just the
  cursor's line.
- No change to selection *tracking* itself (`Down`/`Drag` handling,
  `select_anchor`/`select_end`, highlight rendering, persistence, `Esc`
  clearing) — spec 0129's G1/G3 are otherwise unchanged. Drag direction
  (upward vs. downward) already normalizes via `min(anchor,
  end)..=max(...)` in both `selected_text()` and the render highlight,
  independent of this spec's changes.

### G2 — OSC 52 fallback when `arboard` fails

- `copy_to_clipboard(text: &str)` gains a fallback path: if
  `arboard::Clipboard::new()?.set_text(text)` fails, emit a raw OSC 52
  escape sequence (`\x1b]52;c;{base64(text)}\x07`, base64 via the new
  `base64` crate dependency) to stdout, best-effort — no error surfaced
  from the OSC 52 write itself (there is
  no reliable way to detect whether the terminal actually honored it),
  and the original `arboard` error is still what's reported as the
  final `Err` if both paths are attempted and the caller still needs to
  report `"clipboard unavailable"`.
- Exact success/failure reporting semantics for the dual-path case
  (message bar text when `arboard` fails but OSC 52 was attempted) are
  an open implementation detail — see Non-goals/Test plan; the safest
  default is to always report "N line(s) copied to clipboard (OSC 52
  fallback)" whenever `arboard` fails and OSC 52 was emitted, since
  there is no ack from the terminal either way, and staying silent
  about the fallback having been attempted at all would be more
  confusing than an optimistic message.

## Non-goals

- No true confirmation that OSC 52 was honored by the terminal — no
  terminal handshake/ack exists for this; the fallback is inherently
  best-effort/silent.
- No new keyboard binding for *selecting* a range without the mouse —
  per todo.md item 3's resolution, full-keyboard range selection stays
  out of scope for now (may become a separate future item).
- No change to spec 0129's G1 (drag-tracking) or G3 (selection
  lifecycle/`Esc`-clearing) beyond removing the auto-copy-on-`Up` call
  itself.
- No configurability of the OSC 52 fallback (e.g. a flag to disable
  it) — always attempted when `arboard` fails, per G2.

## Specification

### `tui.rs`

- `handle_key` (main pane, no override/manage pane focus): new arm,
  `KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL)
  => self.copy_current_selection_or_line()`.
- New method `copy_current_selection_or_line(&mut self)`: if
  `self.select_anchor.is_some()`, delegates to the existing
  `copy_selection_to_clipboard()` unchanged; else sets
  `select_anchor = select_end = Some(self.visible_rows[self
  .cursor_display_row()])` (a length-1 selection matching the cursor's
  line) before calling `copy_selection_to_clipboard()` — reuses
  `selected_text()`'s existing range logic rather than duplicating a
  single-line text-building path.
- `MouseEventKind::Up(MouseButton::Left)` (tui.rs ~3653): remove the
  `self.copy_selection_to_clipboard()` call; the arm becomes a no-op
  (selection state was already finalized by the preceding `Down`/
  `Drag` handling) — kept as an explicit empty match arm (not folded
  into `_ => {}`) with a comment explaining mouse-up intentionally does
  not copy anymore, for discoverability.
- `copy_to_clipboard(text: &str) -> Result<(), arboard::Error>`
  (tui.rs ~4429): on `arboard::Clipboard::new()?.set_text(text)`
  failure, additionally emit the OSC 52 sequence to stdout per G2
  before returning the original `Err` (so callers needing the
  underlying `arboard` error, if any, still get it) — or, per the
  message-bar semantics described in G2, `copy_selection_to_clipboard`
  itself (not `copy_to_clipboard`) may need to distinguish "arboard
  succeeded" from "arboard failed, OSC 52 attempted" to build the right
  message text; exact split between the two functions is an
  implementation detail to settle while coding, not fixed here.

## Test plan

1. `Ctrl-C` with an active drag-selection copies exactly that range
   (same content as spec 0129's existing drag-select test).
2. `Ctrl-C` with no selection active copies exactly the cursor's
   current line.
3. Mouse drag-and-release no longer copies by itself — `select_anchor`/
   `select_end` are set and the highlight persists, but the clipboard is
   unchanged until `Ctrl-C` is pressed.
4. `arboard`-unavailable path (mocked/stubbed failure, matching spec
   0129's own test 5) still surfaces a message rather than panicking,
   and the OSC 52 fallback sequence is emitted (assert on captured
   stdout bytes in a test harness, or equivalent).
5. `reuse lint` passes (any new base64-encoding dependency, if one is
   added, needs its own license accounted for).
