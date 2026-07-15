<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0130 — protolens: manage-pane auto/manual entry color scheme

Status: implemented
Implemented in: 2026-07-15
Refs: docs/specs/0125-protolens-manage-pane-auto-manual-lifecycle.md
      (§G1, the coloring this spec replaces),
      protolens/todo.md (2026-07-15 feedback round 2, item 2 —
      discussion and decisions this spec formalizes)
App: protolens

## Background

Spec 0125 §G1 colors manage-pane entry rows using
`theme::style_for(SyntaxRole::Type, self.theme)`, toggling only
`Modifier::BOLD` to distinguish auto-derived entries (unbolded) from
manual entries (bolded) — same color (cyan on dark/blue on light)
either way. The user found this both aesthetically undesirable ("not
happy with cyan") and insufficiently distinguishable ("not enough
difference between cyan and bold cyan").

The user's first proposal — reuse `SyntaxRole::Attribute` (field-name
style) for auto entries and `SyntaxRole::Comment` for manual entries —
surfaced a real gap: `SyntaxRole::Attribute`'s ANSI-16 fallback style
(`theme.rs`'s `style_for_dark_ansi16`/`style_for_light_ansi16`) is
`Style::default()` (no color, no modifier at all) in both palettes, so
under a non-RGB terminal auto entries would render as unstyled plain
text. After discussion (todo.md item 2), the design settled on: reuse
`Comment`'s color values (not role) for auto entries (muted/
de-emphasized, fitting "secondary, machine-derived"), and a plain,
unbolded `Blue` for manual entries (fitting "primary, user-authored"),
with real ANSI-16 fallbacks for both, and no italic.

`SyntaxRole` (colorize.rs) is documented as strictly one variant per
`queries/highlights.scm` capture name — `RECOGNIZED_NAMES`/
`from_highlight_index` are parallel, index-matched arrays driven
directly by tree-sitter's own highlight configuration. Adding
manage-pane-only colors as new `SyntaxRole` variants would misuse that
invariant (no corresponding syntax capture exists, or ever will, for
"auto override entry" / "manual override entry"). This spec instead
adds a small, separate styling function in theme.rs, independent of
`SyntaxRole`.

## Goals

### G1 — dedicated auto/manual manage-pane color function

- New `theme::manage_entry_style(auto: bool, theme: ThemeKind) -> Style`
  (theme.rs), sitting next to `style_for` but outside the
  `SyntaxRole`/`RECOGNIZED_NAMES` machinery. Colors reused from
  existing `SyntaxRole` palette entries (not invented):
  - `auto == true`: `Comment`'s RGB colors verbatim (`#6A9955` dark /
    `#008000` light), ANSI-16 `DarkGray`, no `ITALIC` modifier (italic
    dropped — the user found it unneeded on top of the color change).
  - `auto == false` (manual): RGB colors matching `Boolean`'s existing
    values (`#569CD6` dark / `#0000FF` light — the palette's genuine
    "blue" entry, distinct from `Type`'s teal/cyan), ANSI-16 `Blue`
    (unbold), same color name in both dark and light themes (no
    per-theme substitution).
  - Same RGB-vs-ANSI-16 depth selection as `style_for` (`supports_rgb()`
    gate), for consistency.
- `render_manage_pane`'s `ManageRow::Entry` branch (tui.rs ~4285-4308)
  switches from `theme::style_for(SyntaxRole::Type, self.theme)` +/-
  `Modifier::BOLD` to `theme::manage_entry_style(auto, self.theme)`
  directly — no `BOLD` toggle needed, since the two colors are already
  visually distinct on their own at every palette depth. The
  highlighted row's `Modifier::REVERSED` treatment is unaffected,
  applied on top exactly as today.

## Non-goals

- No change to `SyntaxRole`, `RECOGNIZED_NAMES`, or
  `from_highlight_index` — this spec deliberately avoids touching the
  tree-sitter-highlight-driven enum, per the Background discussion.
- No change to main-pane field-name (`Attribute`) or comment
  (`Comment`) coloring — those roles, and their ANSI-16 fallback gap for
  `Attribute`, are untouched; this spec only adds a new, independent
  manage-pane-specific style.
- No change to `SyntaxRole::Type`'s own definition or its other call
  sites — `Type` continues to mean what it always has elsewhere.

## Specification

### `theme.rs`

- New `pub fn manage_entry_style(auto: bool, theme: ThemeKind) -> Style`:
  dispatches on `(theme, supports_rgb(), auto)`, returning the four RGB
  and four ANSI-16 combinations described in G1 (`ThemeKind::System` is
  a programming-error case here too, mirroring `style_for`'s own
  `unreachable!`).

### `tui.rs`

- `render_manage_pane`'s `ManageRow::Entry` branch: replace the
  `SyntaxRole::Type` + `BOLD`-toggle block with a single call to
  `theme::manage_entry_style(auto, self.theme)`; keep the existing
  `REVERSED`-on-highlighted-row logic unchanged.

## Test plan

1. Auto-derived and manual manage-pane entries render in visibly
   distinct colors (muted gray-green vs. blue) under both RGB and
   ANSI-16 depth, both themes.
2. Highlighted row still shows `REVERSED` layered on top of either
   color.
3. No `ITALIC` modifier appears on auto entries.
4. `reuse lint` passes.
