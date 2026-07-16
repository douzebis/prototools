<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0133 — protolens: dynamic annotations toggle (remove `--no-annotations`)

Status: implemented
Implemented in: 2026-07-16
Refs: docs/specs/0122-protolens-override-header-patching.md (`natural_
      annotation`/header-patching — `splice_override` keeps patching a
      real annotation into every spliced node's header unconditionally
      now, see G2),
      docs/specs/0116-tree-sitter-textproto-highlight-captures.md
      (`SyntaxRole`/`style_hints`, reused here to locate each line's
      trailing annotation without re-decoding)
App: protolens

## Background

`--no-annotations` is a CLI flag (`main.rs`), fixed for the whole
session: `App.annotations: bool` is set once at construction
(`App::new`) from `!cli.no_annotations` and never changes afterward.
It currently feeds into two things: `splice_override`'s
`DecodeRenderOpts.annotations` (so a freshly-spliced node's underlying
text does or doesn't carry `#@ ...`) and `default_extract_format`
(text when annotations are on, binary otherwise).

`prototext_core`'s renderer bakes `#@ ...` text directly into a line's
`String` at render time (a thread-local `ANNOTATIONS` flag consulted
deep inside the sink) — there is no separate "strip/add the trailing
annotation" step applied afterward, and no way to cheaply re-derive it
without a fresh render.

However, every rendered `#@ ...` annotation is, syntactically, a
`tree-sitter-textproto` **comment** (`grammar.js`: `comment: $ => seq
('#', /.*/)`, i.e. `#` to end of line — the grammar has no other use
of the comment token, since protolens's own rendered text never
otherwise contains a bare `#` outside a quoted string). `colorize.rs`
already parses every rendered line with this grammar and records each
capture's byte range in `App.line_styles` (`SyntaxRole::Comment` for
this one), purely for syntax-highlighting purposes today. That range
is exactly "where this line's trailing annotation starts, if it has
one" — already computed, already kept in sync with `self.lines` by
every code path that mutates either (`App::new`, `splice_override`).

This means annotations don't need to be a *decode-time* input at all
going forward: the underlying model (`self.lines`/`self.line_styles`,
and anything derived from them — extraction, search, clipboard copy)
can always carry full annotations, and a purely cosmetic *display-time*
step in the main pane can hide/show the trailing comment span per
line, using data that already exists. No re-decode, no cache
invalidation, no risk of the tree's node count changing (the "hide a
LEN-wire type-mismatched scalar field when annotations are off" `sink.
rs` behavior no longer applies to *anything* in protolens, since
`annotations` is always `true` at the render layer from now on).

## Goals

### G1 — annotations become an always-on decode-time input

- `decode::decode` (`decode.rs`): drop its `annotations: bool`
  parameter; the `DecodeRenderOpts` it builds always sets
  `annotations: true`. Every existing call site (`main.rs`,
  `extract.rs` tests, `decode.rs` tests, `tui.rs` tests) already passes
  `true` today — this just removes the now-pointless parameter.
- `splice_override` (`tui.rs` ~1996): `DecodeRenderOpts.annotations` is
  always `true` (was `self.annotations`).
- `splice_override`'s header-patching (`tui.rs` ~2037-2123, spec 0122
  §2): the `if !self.annotations { None } else { ... }` branch is
  removed — the patched annotation is now unconditionally computed
  (every spliced node's header always carries a real `#@ ...`), so
  `patched_annotation` becomes a plain `String`, not `Option<String>`.

### G2 — `App::new` always starts with annotations on

- `App::new` (`tui.rs`): drop its `annotations: bool` parameter (every
  existing call site already passes `true`); the constructed `App`
  always sets `annotations: true` directly.
- `App.annotations` stays a mutable `bool` field — from now on it's a
  pure *display* attribute, decoupled from what's actually baked into
  `self.lines`/`self.line_styles` (which always carry full
  annotations).

### G3 — `a` toggles the main pane's annotation display

- New main-pane-only key binding `a` (not reachable while
  `override_focus`/`manage_focus`, same guard every other main-pane-
  only binding already gets): `self.annotations = !self.annotations`.
  No re-render, no cache reset, no other state touched — the next
  frame's `render_line_content`/`render_line_spans` calls (G4) pick it
  up directly.
- Distinct from the override-selection pane's own `a` (candidate sort
  toggle) and the manage pane's own `a` (entry active toggle) — both
  unrelated, unchanged, gated behind their own focus checks already.

### G4 — display-time truncation

- New private helper, e.g. `fn annotation_start(&self, line_idx: usize)
  -> Option<usize>`: looks up `self.line_styles[line_idx]` for an entry
  whose role is `SyntaxRole::Comment` (at most one per line, per
  Background) and returns its byte-range start.
- `render_line_content`/`render_line_spans` (`tui.rs` ~4122/~4152):
  when `!self.annotations` and `annotation_start(line_idx)` returns
  `Some(pos)`, operate on `content[..pos].trim_end()` (byte length)
  instead of the full line — trimming the whitespace that used to
  separate the value from its annotation. `render_line_spans`
  additionally clips/drops any `self.line_styles[line_idx]` hint whose
  range extends past the truncated length before calling
  `segment_line`, so it never indexes past the shortened `content`.
  When `self.annotations` is `true`, or the line has no comment span,
  behavior is unchanged.
- Every other consumer of `self.lines`/`self.line_styles` (extraction,
  `:save-overrides`, search, `selected_text`/clipboard copy, the
  override/manage panes) is untouched — they don't go through
  `render_line_content`/`render_line_spans`, so they keep seeing full
  annotations regardless of the toggle, matching "only impacts the way
  lines are rendered in the main pane." (Clipboard copy does go
  through `render_line_content`, so it *does* follow the toggle — a
  deliberate WYSIWYG choice: `render_line_content` doc comment already
  documents this function as "how this line looks in the main pane
  right now.")

### G5 — remove `--no-annotations`

- Delete `Cli::no_annotations` (`main.rs`) and its doc comment.
- Delete the startup validation rejecting `--format text` combined
  with `--no-annotations` (`main.rs` ~144-148) — dead once the flag is
  gone.
- The `decode::decode`/`App::new` call sites drop the now-removed
  trailing argument (G1/G2).
- Batch mode's default extract format (`main.rs` ~262) simplifies to
  always `Text` — annotations are always present in the underlying
  render now (G1), so there is no longer any reason to default to
  binary. `default_extract_format` (`tui.rs` ~2847-2858) is deleted;
  its one call site (`run_extract`) uses `ExtractFormat::Text`
  directly.

## Non-goals

- No status-bar/header indicator of the current annotations state —
  the visible effect (whether `#@ ...` is shown) is its own feedback,
  same as the manage pane's silent active-flag toggle.
- No change to search (`/`, `?`, `n`), extraction, `:save-overrides`,
  or clipboard-copy *content sourcing* — they read `self.lines`
  directly (full annotations) or, for clipboard, `render_line_content`
  (display-accurate, see G4) — neither needs new code beyond G1-G4.
- No change to the override-selection or manage panes' own rendering.

## Specification

### `decode.rs`

- `pub fn decode(blob: &[u8], ctx: &mut DescriptorContext, type_override:
  Option<&str>, indent_size: usize) -> Result<Decoded, DecodeError>`
  (drops the trailing `annotations: bool` param); its `DecodeRenderOpts`
  literal sets `annotations: true` unconditionally.
- Update all call sites (`main.rs`, `extract.rs` tests, `decode.rs`
  tests, `tui.rs` tests) to drop the trailing `true` argument.

### `tui.rs`

- `App::new(...)` drops its `annotations: bool` parameter; the `App`
  struct literal sets `annotations: true` directly. Update all call
  sites (tests + `main.rs`) to drop the corresponding argument.
- `splice_override`: `DecodeRenderOpts.annotations: true` (was `self.
  annotations`); `patched_annotation` becomes an unconditionally-
  computed `String` (drop the `if !self.annotations` branch and the
  `Option` wrapper, adjusting `patched_first_line`'s construction and
  the later `new_self_span.natural_annotation = Some(format!("#@
  {patched_annotation}"))` assignment accordingly).
- Delete `default_extract_format`; `run_extract` uses `ExtractFormat::
  Text` directly, with an updated doc comment (no more "unless
  annotations are off" branch).
- New helper `fn annotation_start(&self, line_idx: usize) -> Option
  <usize>` (G4).
- `render_line_content`/`render_line_spans`: apply G4's truncation.
- `handle_key`'s main-pane match block: add `KeyCode::Char('a') =>
  self.annotations = !self.annotations,`.
- `HELP_TEXT`: document the new `a` binding.

### `main.rs`

- Remove `Cli::no_annotations` and its doc comment.
- Remove the `cli.no_annotations`-vs-`--format text` startup check.
- Update the `decode::decode`/`App::new` call sites (drop the removed
  argument).
- Batch default format: `None => extract::ExtractFormat::Text` (drop
  the `cli.no_annotations` arm); update the `Extract::format` field's
  doc comment (no more "or to `binary` when `--no-annotations` is
  set").

## Test plan

1. Start with annotations on (default); press `a` — main-pane lines
   lose their trailing `#@ ...` text (and its preceding whitespace);
   press `a` again — lines are byte-for-byte identical to before the
   first toggle.
2. Toggling `a` while the cursor is on an override-affected node still
   shows the override applied, correctly with/without its own
   annotation per the new state.
3. Toggling `a` never changes `cursor`, fold state, scroll position,
   or node count (G1's decode-time behavior no longer varies with
   annotations, so the historical "LEN-wire type-mismatch field
   disappears without annotations" `prototext-core` behavior no longer
   triggers for protolens).
4. `x`/`:extract`/`:save-overrides`/search/`:restore-overrides` are
   unaffected by the current `a` state — always operate on fully-
   annotated text.
5. Copying a text selection to the clipboard while annotations are
   toggled off omits the `#@ ...` text from the copied lines
   (WYSIWYG); toggled on, it's included.
6. `--no-annotations` no longer exists as a CLI argument
   (`protolens --help` doesn't mention it); `--format text` never
   errors out for this reason anymore.
7. Batch-mode extract's default format is always text.
8. `reuse lint` passes.
