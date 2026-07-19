<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0147 — protolens: borderless panes with vim-style local statuslines and a global command/message line

Status: implemented
Implemented in: 2026-07-19
Refs: docs/specs/0127-protolens-pan-all-panes.md (§G1, the cursor-position
      convention and the "focused"/"unfocused" accent used throughout the
      bottom bar and pane borders this spec restructures),
      docs/specs/0136-protolens-status-line-type-display.md (the `type:
      {fqdn} [tag]` label and `format_fqdn_label` this spec reuses, only
      reformatted — see G2), docs/specs/0144-protolens-neovim-jump-to-
      definition.md (structural template for this spec's layout; also the
      most recent spec to add a new `self.message.clear()` call site, at
      `key_dispatch.rs`'s `v` handler — superseded by this spec's single
      top-of-`handle_key` clear), docs/protolens/design/help-and-chrome.md
      (§"Status bar reflects the cursor, not the whole document" — the
      design doc this spec's implementation will require updating, not
      superseding), docs/protolens/design/command-line.md (the design doc
      describing today's three-purpose shared bottom bar — likewise to be
      updated post-implementation), docs/protolens/design/main-pane.md,
      docs/protolens/design/override-select-pane.md,
      docs/protolens/design/manage-pane.md (each documents its pane's
      current bordered framing — all three need the border-removal
      updated post-implementation), 2026-07-18 discussion ("UI
      Organization" feedback proposing a message/status merge and a
      narrower command line; a follow-up asking this spec to resolve
      three open questions and articulate the command/message/status
      philosophy; a further follow-up, prompted by a comparison against
      vim's own split-window statusline/command-line convention,
      broadening the spec to remove pane borders entirely in favor of
      per-pane local statuslines plus a single global command/message
      row — including an explicit content proposal for all four
      statusline variants, confirmed and refined point-by-point)
App: protolens

## Background

**Today's framing.** Every pane — main, override-select, manage — is
drawn as an independently bordered box (`Block::bordered()`,
`BorderType::Rounded`, `render.rs:265-270`, `render_override_pane`
`render.rs:526-529`, `render_manage_pane` `manage_pane.rs:746-749`), each
costing 2 rows (top/bottom border) and 2 columns (left/right border) of
screen real estate. Each border's title carries identifying text (the
`self.header` string — `"protolens — {blob_label} — {root_type}"` — for
the main pane; `" Override — range [..) — sort: .. "` for the
override-select pane; `" Overrides (N entries) "` for the manage pane).
Below all of that sits a separate `Constraint::Length(3)` bordered bottom
bar (`render.rs:229-497`) that, depending on state, either:

- shows one `cmd_text` block (left, 60%) alongside a status block (right,
  40%), or
- shows only the status block (full width), when `cmd_text` is empty.

`cmd_text` (`render.rs:378-391`) is built by trying three sources in
order: `self.command_buffer` (an active `:` command or `/`/`?` search
being typed), `self.manage_rename` (an active management-pane rename
buffer), or `self.message` (a passive, transient notice — errors,
confirmations, the "quit?" prompt — assigned directly at ~20 call sites
across the TUI, with no dedicated setter). Only the first two are
genuine *text entry*: they own a blinking terminal cursor
(`render.rs:423-429`, `444-447`). `self.message`, by contrast, is
display-only, yet today forces the same 60/40 split and bordered
"command" box as an active edit — the wrong affordance, a notification
dressed up as an input prompt.

**Vim's contrasting model**, examined during the 2026-07-18 discussion:
each split window carries its own single-row *local statusline*
(reverse-video, no border) at its bottom edge, showing that window's own
buffer/position info; adjacent windows are divided by a one-character
column (`fillchars vert:│`) rather than a border box; a single *global*
command-line row, shared across the whole screen regardless of how many
windows are open, is used exclusively for typed `:`/`/`/`?` input and for
messages/errors — it never shows a per-window ruler. Focus is indicated
purely by the *intensity* of a window's own statusline color (active vs.
inactive highlight group), not by a distinct border.

This spec adopts that model for protolens: no borders anywhere, one local
statusline per pane, one global command/message row. Doing so also
resolves three concrete inconsistencies flagged in the same discussion:

1. **Timeout value**: `MESSAGE_TIMEOUT` (`mod.rs:84`) is
   `Duration::from_secs(4)`, but the proposal that started this spec
   states 3 seconds.
2. **Non-uniform dismiss-on-input**: `self.message.clear()` is called at
   `key_dispatch.rs:278`, but only on the path that falls through to
   *main-pane* key handling — a keypress consumed by
   `handle_override_key` or `handle_manage_key` never reaches that line,
   so a message set while one of those panes has focus lingers until
   either the main pane regains focus and a key is pressed there, or the
   timeout fires. `handle_mouse` (`mouse.rs:31`), by contrast, already
   clears `self.message` unconditionally at the top of every mouse
   event.
3. **Two narrower, redundant clear sites**: `command_line.rs:84` (the
   command-buffer's `Esc` arm) and `override_select.rs:144`
   (`open_override_on_default`, silently falling back from `Inferred` to
   `Lexicographic` mode) each clear `self.message` for a single call
   path — narrower special cases of the same "new input dismisses the
   old message" rule that (2) shows is not applied uniformly elsewhere.

## Goals

**The philosophy.** Three concepts share the bottom of the screen today
and are conflated into one bar and a set of near-identical bordered
boxes. This spec keeps them conceptually distinct and gives each exactly
one home:

- **A pane's local statusline** is *ambient, persistent information
  about that specific pane's own state* — for the main pane, where the
  cursor currently rests (path, type, byte range, line number); for the
  override-select pane, which field is being retyped and under which
  sort mode; for the manage pane, which override-group path is in view.
  It has no lifespan of its own — it simply reflects whatever that
  pane's own cursor/selection is resting on, continuously. It is *local*:
  each pane shows only its own state, never another pane's, and never
  anything global.
- **The command line** is for *active text entry* — the user is
  mid-keystroke into a `:` command, a `/`/`?` search pattern, or a
  management-pane rename. It is the only thing at the bottom of the
  screen that ever owns a terminal cursor. It is *global*: there is
  exactly one, regardless of how many panes are open, because a typed
  command or search is a property of the session, not of one pane.
- **A message** is a *transient notice about what just happened* — an
  error ("pattern not found"), a confirmation ("saved to overrides.pb"),
  or a prompt awaiting a yes/no answer ("quit? press q again..."). It is
  not something the user is typing; it is something protolens is telling
  the user, unprompted, as a side effect of an action. Like the command
  line, it is *global* — the result of a `:save-overrides` command
  belongs to the session, not to whichever pane happens to have focus
  when it completes — and for that reason a message and the command line
  share the same physical slot, the way vim's messages and typed
  commands share its one command-line row. A message has a natural,
  short lifespan: either the user's next input makes it irrelevant, or a
  few seconds pass and it is no longer news.

The key realization driving this spec: **locality** is the dividing
line. A pane's own position/selection info is local and belongs to that
pane's own statusline; commands and messages are global and belong to
one shared row at the very bottom of the screen, never duplicated
per-pane and never mixed with any pane's local ruler.

- **G1 (borderless panes).** Remove `Block::bordered()` from the main
  pane (`render.rs:265-270`), the override-select pane
  (`render_override_pane`, `render.rs:526-529`), and the manage pane
  (`render_manage_pane`, `manage_pane.rs:746-749`). Each pane's area
  splits vertically into `Constraint::Min(0)` (content, unchanged) above
  `Constraint::Length(1)` (that pane's own local statusline, replacing
  its former border's title text) — no title, no top/bottom/left/right
  border glyphs. This reclaims 1 net row of vertical space per pane
  (2 border rows → 1 statusline row) and the 2 columns each border used
  to cost horizontally.

  `self.main_area`/`self.side_area` (the inner, border-stripped `Rect`s
  `mouse.rs` uses for all click/drag hit-testing, e.g. `mouse.rs:55-56`,
  `283`, `304`, `327`) must be redefined to exclude the new local
  statusline row as well — today they already exclude the border; they
  must now equal each pane's `Min(0)` content split, not its full area,
  so that a click on a pane's own statusline row is not misinterpreted
  as a click on content row 0.

- **G2 (local per-pane statuslines).** Each pane's `Length(1)` row shows
  a single line of **plain, uniform styling only** — no per-span
  type-based color coding (unlike the main pane's body text or the
  override pane's candidate list, which keep their existing colors
  unaffected by this spec, see N7). The whole line uses one solid style,
  chosen the same way `pane_focus_style` chooses a border color today
  (`mod.rs:233-239`): the pane's own focused/unfocused accent, applied
  as the line's style (e.g. a reverse-video background) rather than a
  border color — this is how focus is now indicated, exactly mirroring
  vim's active/inactive statusline highlight.

  Content, confirmed per pane and mode:

  - **Main pane, full width** (no side pane open):
    `<file-name, not full path> <node-path> [(message|group|enum): ]<fqdn>`
    left-aligned, `[start..end)  L<curr-line>/<total-lines>`
    right-flushed. `<file-name>` is a new `App` field, `file_label:
    String`, storing `blob_label` (`App::new`'s second parameter,
    `mod.rs:838-840`) verbatim — `blob_label` is already a short filename,
    not a full path (`main.rs:181-183`: `cli.blob.file_name()`), but today
    it is only ever consumed into the combined `self.header` string
    (`mod.rs:864`, `"protolens — {blob_label} — {root_type}"`) and not
    retained on its own; `file_label` fixes that. `<node-path>` is
    `self.positional_path(self.cursor)`; the `(message|group|enum): `
    tag and `<fqdn>` are `self.status_type_label(self.cursor)`'s
    existing `{fqdn} [tag]`-suffixed output (`override_apply.rs:97-132`,
    `format_fqdn_label`), reformatted tag-first to match this template
    rather than carrying new data; the range and line-ruler are today's
    unchanged `self.display_range(self.cursor)` /
    `self.cursor_line()`/`self.lines.len()`.
  - **Main pane, half width** (a side pane is open): the same left-hand
    content as above, but **no right-flushed range/ruler** — dropped
    intentionally (confirmed): while a side pane has focus, precise
    byte-offset/line-ruler detail is secondary to the task at hand, and
    it remains recoverable by closing the side pane.
  - **Override-select pane, Inferred sort**:
    `<node-path> - inferred types` left-aligned,
    `L<curr-line>/<total-lines>` right-flushed, where `<node-path>` is
    the *target field's own* path (`self.positional_path(self
    .override_target)`, i.e. the same path the main pane showed when the
    pane was opened — confirmed), and the ruler counts rows within
    `self.override_candidates` (`self.override_highlight + 1` of
    `self.override_candidates.len()`).
  - **Override-select pane, Lexicographic sort**: identical, with
    `- all types` in place of `- inferred types` (replacing today's
    terser `sort: a-z` border-title wording with a plainer phrase).
  - **Manage pane**: `<origin-path> - type overrides` left-aligned,
    `L<curr-line>/<total-lines>` right-flushed, where `<origin-path>` is
    the currently-highlighted entry's (or header row's) grouping path,
    and the ruler counts rows within `self.manage_display_rows()`
    (`self.manage_highlighted_row() + 1` of the row count).

  **Truncation** (mimicking vim's own statusline truncation): the
  right-flushed ruler is always shown in full and never truncated; if
  the left-hand content would otherwise overlap it, the left-hand
  content is truncated and a single `<` marker is inserted at the cut
  point — the same convention vim uses (`'stl'`'s default `%<`) when a
  window is too narrow for its statusline's full content.

- **G3 (vertical separator between side-by-side panes).** When the
  override-select pane or the manage pane is open (mutually exclusive,
  spec 0117 §3), the main pane and the side pane are divided by a single
  `'│'`-filled column (`Constraint::Length(1)`) instead of each pane
  drawing its own left/right border. This column uses one fixed, neutral
  style — not focus-colored — since focus is already conveyed
  unambiguously by each side's own local statusline (G2).

- **G4 (global command/message row).** Replace today's `Length(3)`
  bordered bottom bar and its internal 60/40 split with a single,
  borderless, `Constraint::Length(1)` row spanning the full terminal
  width, always reserved (never collapsed/expanded — this avoids the
  main content jumping every time a message appears or disappears,
  matching vim's fixed-height command line). Its content:

  ```rust
  let cmd_text = match &self.command_buffer {
      Some(buf) => { ... }              // unchanged: ':'/'/'/'?' + buf
      None => match &self.manage_rename {
          Some(buf) => format!("{RENAME_PREFIX}{buf}"),
          None => self.message.clone(),
      },
  };
  ```

  — i.e. this row keeps trying the three sources in the same priority
  order as today's `cmd_text` (`render.rs:378-391`), but is now the
  *only* place any of the three ever renders: there is no more separate
  "status" block for this row to share space with, since cursor/position
  info has moved entirely to G2's local statuslines. When none of the
  three apply, the row renders blank (not hidden — the row itself is
  still reserved). No new styling is introduced for the message state:
  it uses the same plain accent as an idle empty row.

- **G5 (uniform dismiss-on-input).** Move the message-clearing step to
  the very top of `handle_key`, unconditionally, before any dispatch
  branch — right after `self.splash = false;`:

  ```rust
  pub fn handle_key(&mut self, key: KeyEvent) {
      self.splash = false;
      self.message.clear();
      // ... Ctrl-Z, quit_confirm, F1, command_buffer, ':', 'v',
      //     override_focus, manage_focus, main-pane dispatch ...
  }
  ```

  This resolves open question (2): every keypress, regardless of which
  pane has focus, now dismisses a stale message before its own handler
  runs — matching `handle_mouse`'s existing unconditional clear at the
  top of every mouse event, so keyboard and mouse input are uniform.

  This single top-of-function clear supersedes and makes redundant:
  - The late, main-pane-only clear at today's `key_dispatch.rs:278`
    (deleted).
  - `key_dispatch.rs:223`, inside the `quit_confirm` resolution block's
    "cancelled" arm (deleted — verified: on the keypress that calls
    `request_quit()`, the top-of-function clear fires *before*
    `request_quit()` sets the prompt, so it does not erase its own
    prompt; on the *following* keypress, the top-of-function clear fires
    first and wipes the prompt unconditionally, whether that keypress
    confirms, cancels, or does neither).
  - `command_line.rs:84` (the command-buffer `Esc` arm, deleted — the
    next keypress after `Esc` clears any stale message on its own via
    the new top-of-function rule regardless of which handler path it
    takes).
  - `override_select.rs:144` (`open_override_on_default`'s
    `Inferred`-to-`Lexicographic` silent fallback, deleted — this call
    happens *within* the same `handle_key` invocation that already ran
    the top-of-function clear moments earlier, so removing this line
    changes nothing observable).

- **G6 (3-second timeout).** Change `MESSAGE_TIMEOUT` (`mod.rs:84`) from
  `Duration::from_secs(4)` to `Duration::from_secs(3)`, resolving open
  question (1) in favor of the value explicitly stated in the original
  proposal. `track_message_timeout`'s exemption logic (never dismissed
  while `command_buffer`/`manage_rename`/`quit_confirm` is active,
  `render.rs:207-209`) is unchanged.

- **G7 (doc-comment and design-doc updates).** Update:
  - `track_message_timeout`'s doc comment (`render.rs:185-196`),
    `MESSAGE_TIMEOUT`'s doc comment (`mod.rs:79-84`), and the bottom-row
    layout block comment (`render.rs:362-376`) — all currently describe
    "the shared bottom command/message bar" and/or a 60/40 status split
    that no longer exists.
  - `docs/protolens/design/help-and-chrome.md`'s "Status bar reflects the
    cursor, not the whole document" section — rewritten around G2's
    per-pane local statuslines and G4's global command/message row,
    rather than one shared bottom bar.
  - `docs/protolens/design/command-line.md` — narrowed to describe the
    global command/message row only (G4), cross-referencing
    `help-and-chrome.md` for the local statuslines.
  - `docs/protolens/design/main-pane.md`,
    `docs/protolens/design/override-select-pane.md`,
    `docs/protolens/design/manage-pane.md` — each currently documents its
    pane's bordered framing; updated to describe the borderless
    layout + local statusline (G1/G2) and, for the two side panes, the
    vertical separator (G3).

## Non-goals

- **N1.** No queueing, history, or stacking of messages — `self.message`
  remains a single-slot field; a new message still simply overwrites
  whatever was there.
- **N2.** No change to which ~20 call sites assign `self.message`, nor
  to what they say. Only where the result is displayed and when it is
  cleared changes.
- **N3.** No change needed to the override pane's or management pane's
  own internal notices/prompts — they read/write `self.message` the same
  way and automatically inherit the new uniform dismiss-on-input rule
  from G5 without any pane-specific code.
- **N4.** No change to `quit_confirm`'s two-keypress prompt/resolve
  mechanism itself beyond removing its now-redundant explicit
  `self.message.clear()` (G5) — it still arms on `q`, still prompts via
  `self.message`, still resolves on the next keypress.
- **N5.** The splash screen and help overlay (`render_splash`,
  `render_help`, `render.rs:594-633`) **keep their existing bordered
  `Block::bordered()` popup style**, unaffected by G1 — they are floating
  modal overlays drawn on top of the persistent 3-pane layout, not tiled
  panes participating in it, and a border remains the right way to
  visually separate a floating popup from whatever is `Clear`-ed out
  behind it (the same reasoning vim/Neovim apply to their own floating
  windows, as opposed to tiled split windows). No other change to
  `self.splash`/`self.help_open` or their timeout/dismissal mechanisms.
  `self.header` itself is not removed (still used by `render_splash`,
  `render.rs:628`) — only its use as the main pane's border title goes
  away, per G2's new `file_label` field.
- **N6.** No interactivity added to the G3 vertical separator column
  (not draggable, no pane-resize) — purely a visual divider, same as
  vim's default `fillchars vert:│`.
- **N7.** No change to the existing type-based color coding *within* each
  pane's own content area — the main pane's syntax-role colors, the
  heat-cue glyphs/suffixes, the override pane's candidate-list colors
  (enum blue, auto/manual green, etc.), and the manage pane's row
  styling are all unaffected. G2's "plain styling only" rule applies
  strictly to the one-line local statusline itself, not to what it sits
  above.
- **N8.** No scrollbars or other new affordances are introduced anywhere
  by this spec.

## Specification

### `protolens/src/tui/render.rs`

Remove the main pane's `Block::bordered()` (today `render.rs:265-270`);
split `main_outer` into content (`Min(0)`) + a new `Length(1)`
statusline row instead. Build that row's text per G2's "main pane" cases
(full vs. half width, i.e. `right_outer.is_none()` vs. `is_some()`),
including the `<` truncation rule, and style it via a line-level
equivalent of `pane_focus_style(main_focused, self.theme)`.

Between `main_outer` and `right_outer` (when a side pane is open), insert
a `Length(1)` vertical column filled with `'│'`, styled with a fixed
neutral accent (G3), in place of each side's own left/right border.

`self.main_area` (`mod.rs:780`) must be set to the `Min(0)` content
split, not the former border-stripped `inner` rect — it now excludes one
additional row (the new local statusline) that it didn't have to exclude
before. `render_override_pane`/`render_manage_pane`'s equivalent
`self.side_area` assignment needs the same adjustment.

Replace the entire `Length(3)` bottom-bar block (today's `cmd_text` +
60/40 split + status block, `render.rs:378-482`) with a single
`Length(1)` row (G4):

```rust
let cmd_text = match &self.command_buffer {
    Some(buf) => {
        let prefix = match self.command_kind {
            CommandLineKind::Command => ':',
            CommandLineKind::Search(SearchDir::Forward) => '/',
            CommandLineKind::Search(SearchDir::Backward) => '?',
        };
        format!("{prefix}{buf}")
    }
    None => match &self.manage_rename {
        Some(buf) => format!("{RENAME_PREFIX}{buf}"),
        None => self.message.clone(),
    },
};
// no border, no split — one plain Length(1) row, always reserved,
// rendered blank when cmd_text is empty
```

`self.cmd_area` continues to be set from this row's `Rect` whenever
`command_buffer`/`manage_rename` is active (for cursor positioning,
unchanged from today's `render.rs:417`/`444-447`), and left `None`
otherwise.

Update `render_override_pane` (`render.rs:512-...`) and
`render_manage_pane` (`manage_pane.rs:743-...`) analogously: drop their
`Block::bordered()`/title, split their `area` into content + `Length(1)`
statusline, and render the G2 content/ruler for each (Inferred/
Lexicographic wording for the override pane; origin-path for the manage
pane).

Update the doc comments at `render.rs:185-196` (`track_message_timeout`)
and `render.rs:362-376` (bottom-row layout) per G7.

### `protolens/src/tui/mod.rs`

```rust
const MESSAGE_TIMEOUT: Duration = Duration::from_secs(3);
```

Update the doc comment at `mod.rs:79-83` per G7. Repurpose or replace
`pane_focus_style` (`mod.rs:233-239`) so its focused/unfocused
`Style` can be applied to a full-width statusline (background/reverse
accent) as well as to a border, since both now share the same
focus-accent convention.

Add a new field to `App` (near `header: String`, `mod.rs:777`):

```rust
/// Short filename (`App::new`'s `blob_label` parameter, already
/// stripped to a filename via `cli.blob.file_name()` — see
/// `main.rs`), retained standalone for the main pane's local
/// statusline (spec 0147 G2) — `self.header` alone is no longer
/// usable for this, since it also embeds "protolens — ... — {root_type}".
file_label: String,
```

set once in `App::new` from `blob_label` (`mod.rs:838-840`), alongside
the existing `header` assignment (`mod.rs:864`).

### `protolens/src/tui/key_dispatch.rs`

Add an unconditional clear at the top of `handle_key`, and remove the two
now-redundant clears:

```rust
pub fn handle_key(&mut self, key: KeyEvent) {
    self.splash = false;
    self.message.clear();

    #[cfg(unix)]
    if key.code == KeyCode::Char('z') && key.modifiers.contains(KeyModifiers::CONTROL) {
        self.should_suspend = true;
        return;
    }

    if self.quit_confirm {
        self.quit_confirm = false;
        if key.code == KeyCode::Char('q') {
            self.should_quit = true;
        }
        return;
    }

    // ... F1 / command_buffer / ':' / 'v' / override_focus / manage_focus ...

    // (the former `self.message.clear();` here, before the empty-tree
    // check, is deleted — the top-of-function clear already covers it)

    if self.tree.is_empty() {
        ...
```

(The `else { self.message.clear(); }` arm inside the `quit_confirm`
resolution block is deleted along with the standalone late clear — both
superseded by the top-of-function clear, per G5.)

### `protolens/src/tui/command_line.rs`

Remove the now-redundant clear in the `Esc` arm of `handle_command_key`:

```rust
KeyCode::Esc => {
    self.command_buffer = None;
    self.command_cursor = 0;
}
```

### `protolens/src/tui/override_select.rs`

Remove the now-redundant clear in `open_override_on_default`:

```rust
fn open_override_on_default(&mut self) {
    self.override_sort = SortMode::Inferred;
    self.recompute_override_candidates();
    if self.override_candidates.is_empty() {
        self.override_sort = SortMode::Lexicographic;
        self.recompute_override_candidates();
    }
}
```

### `docs/protolens/design/*`

Update `help-and-chrome.md`, `command-line.md`, `main-pane.md`,
`override-select-pane.md`, `manage-pane.md` per G7 once the code changes
above land — no code, prose only.

## Test plan

Existing tests requiring rewrites (all currently assume a bordered
bottom bar and/or a shared status block):

- `message_auto_dismisses_after_timeout` (`tests/render.rs`, ~line 64) —
  still asserts `app.message` clears itself after the deadline, but
  should assert the message text appears in the global command/message
  row rather than a shared status block.
- `message_is_not_dismissed_while_a_prompt_or_quit_confirm_is_active`
  (~line 112) — unaffected in mechanism (still exercises
  `track_message_timeout`'s exemption logic via `app.message_deadline`),
  re-pointed at the global row for the same reason as above.
- `status_line_reports_the_footer_line_number_for_a_footer_resting_cursor`
  (~line 234) — needs re-pointing at the main pane's own local
  statusline row (no longer a separate bordered "status" block).
- Any test asserting on border glyphs/titles for the main, override-
  select, or manage panes (e.g. searching rendered output for
  `"Override — range"`, `"Overrides ("`, or `self.header`'s text) needs
  updating to match the new local-statusline wording (G2) instead.

New tests needed:

- A message set while the override pane or management pane has focus is
  cleared by the *next* keypress handled by
  `handle_override_key`/`handle_manage_key` — covers G5's fix for open
  question (2). (Two variants, one per pane.) Suggested names:
  `message_is_dismissed_by_the_next_key_in_the_override_pane`,
  `message_is_dismissed_by_the_next_key_in_the_manage_pane`.
- `MESSAGE_TIMEOUT` is exactly 3 seconds — covers G6.
- Main pane's local statusline drops its right-flushed range/ruler when
  a side pane is open, and shows it when no side pane is open — covers
  G2's full-width/half-width distinction. Suggested name:
  `main_statusline_omits_the_ruler_when_a_side_pane_is_open`.
- Override-select pane's local statusline reads "inferred types" in
  `Inferred` mode and "all types" in `Lexicographic` mode — covers G2.
- Truncation: a narrow terminal width with a long node-path/fqdn still
  shows the right-flushed ruler in full, with a `<` marking the cut
  point on the left — covers G2's truncation rule.
- The vertical separator column between the main pane and an open side
  pane renders `'│'` the full height of `main_outer`/`right_outer` — covers G3.
- The global command/message row never grows/shrinks the main content
  area regardless of whether it's blank, showing a message, or showing
  active command entry — covers G4's fixed-height requirement.
- A click on a pane's own local statusline row (main, override-select,
  or manage) is not treated as a click on content row 0 of that pane —
  covers `main_area`/`side_area`'s redefinition to exclude the new
  statusline row.
