<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0125 — protolens: manage-pane auto/manual override coloring and lifecycle

Status: implemented
Implemented in: 2026-07-15
Refs: docs/specs/0117-protolens-override-collection.md (`OverrideEntry`,
      YAML `YamlEntry`/`to_yaml`/`from_yaml`),
      docs/specs/0120-protolens-any-messageset-as-auto-overrides.md
      (`auto` field, auto-seeding in `render_overrides`, `stale_auto_entry`
      demotion detection),
      docs/specs/0124-protolens-manage-pane-navigation.md (G2's "rotating
      resets `auto` to `false`" rule, part of the same policy this spec
      states in full),
      protolens/todo.md (2026-07-15 feedback, item 2 — discussion and
      decisions this spec formalizes)
App: protolens

## Background

`OverrideEntry::auto` (spec 0120) already distinguishes automatic
(seeded by internal Any/MessageSet expansion) from manual (explicitly
user-created) entries, but today that distinction is invisible in the
manage pane (`render_manage_pane` — plain, uncolored rows besides the
highlighted one) and session-only (never round-tripped through YAML —
`YamlEntry` has no `auto` field, so every `:restore-overrides`d entry
comes back `auto: false` regardless of its original state).

`Delete`/`Backspace` in the manage pane (`handle_manage_key`) does not
special-case `auto` today — it always succeeds. What makes deleting an
auto entry appear to fail is `render_overrides`'s auto-seeding logic
(tui.rs ~1600-1660), which checks only entry *presence*
(`already_seeded = entries().any(|e| e.origin == origin)`), not
`active` — a deleted-but-still-in-scope auto entry gets silently
re-derived and re-seeded on the very next render pass, which `Delete`
itself triggers. Deactivating (`a`) an auto entry, by contrast, already
"sticks" today, since the entry still exists and `already_seeded` stays
true. This spec makes that the documented, deliberate behavior instead
of an accident, adds the missing "no longer in scope" carve-out, and
surfaces the distinction visually and in the YAML format.

## Goals

### G1 — color-distinguish origin / auto / manual rows

- `render_manage_pane` gains three distinct styles for manage-pane rows
  (currently all plain, `Modifier::REVERSED` only on the highlighted
  row, which stays unchanged and layers on top of these):
  1. Origin header rows (`ManageRow::Header`) — default/unstyled, as
     today.
  2. Entry rows (`ManageRow::Entry`) where `auto == true` — plain
     (unbolded) `SyntaxRole::Type` color.
  3. Entry rows where `auto == false` — bold `SyntaxRole::Type` color.
- No new `theme.rs` infrastructure required. Implemented by reusing the
  existing `SyntaxRole::Type` color (`theme::style_for(SyntaxRole::Type,
  self.theme)` — already dark/light + RGB/ANSI16-aware) rather than a
  new hardcoded color, differing only in the `Modifier::BOLD` bit: manual
  entries add it, auto entries strip it.

### G2 — `Delete` deactivates auto entries still in scope, deletes those that aren't

- `handle_manage_key`'s `Delete`/`Backspace` branch gains an `auto`
  check on the highlighted entry:
  - If `entry.auto == false`: unchanged — remove it outright.
  - If `entry.auto == true` and the entry is still "in scope" (i.e. it
    would be re-seeded by `render_overrides`'s auto-expansion pass if
    removed — same predicate `render_overrides`'s own
    `stale_auto_entry`/`auto_expand_type` staleness check already
    computes, exposed as a small shared helper instead of duplicated):
    do not remove it. Instead, deactivate it (same effect as `a` on an
    active auto entry) and write to the message bar: `"auto-derived
    override deactivated (still in scope — delete would just recreate
    it; use 'a' or wait for it to go out of scope)"`.
  - If `entry.auto == true` but it is *not* currently in scope (e.g. a
    parent node's override changed such that this entry's type no
    longer applies — the same condition `stale_auto_entry` already
    detects and demotes on the next render) — actual deletion proceeds
    exactly like a manual entry.
- This reuses, rather than duplicates, the existing staleness predicate:
  extract the comparison `render_overrides` already performs (currently
  inlined around tui.rs ~1600-1660: `auto_expand_type(idx) == Some(entry
  .r#type)` for the node the entry's origin resolves to) into a
  standalone method, `fn auto_entry_in_scope(&mut self, entry: &
  OverrideEntry) -> bool`, called from both `render_overrides` (unchanged
  behavior) and the new `Delete` handling (new caller). Lives on `App`
  (tui.rs), not `OverrideCollection` (override_pane.rs) as originally
  drafted here — `auto_expand_type` needs `&mut self` access to the live
  tree/descriptor pool (`ctx.pool_mut()` for MessageSet's
  `register_message_set_item`), which `OverrideCollection` has no access
  to. Auto-seeded entries only ever have a `Path` origin (auto-seeding
  always calls `activate_auto` with `OverrideOrigin::Path`), so a single
  `resolve_path` lookup suffices — no need for `manage_affected_nodes`'s
  multi-match enumeration.

### G3 — persist `auto` through YAML

- `YamlEntry`'s three variants each gain an `auto: bool` field,
  `#[serde(default, skip_serializing_if = "is_false")]` — identical
  pattern to the existing `active` field, so old files without the key
  still load fine (`auto` defaults to `false`, preserving today's
  behavior for pre-existing saved files) and new files only grow a line
  when `auto` is actually `true`.
- `to_yaml`/`from_yaml` round-trip `auto` like every other field — no
  special-casing; `run_save_overrides`/`run_restore_overrides` need no
  changes beyond what falls out of `YamlEntry` gaining the field.
- This flips today's "restore always yields `auto: false`" behavior
  (spec 0120's original, deliberate design) to "restore preserves
  whatever `auto` was at save time" — a conscious behavior change,
  confirmed as wanted (todo.md item 2).

## Non-goals

- No change to the *auto-seeding* trigger condition itself (still
  presence-based, `already_seeded`) — G2 only changes what `Delete` does
  with an in-scope auto entry, not when/how auto-seeding happens in the
  first place.
- No new manage-pane key beyond the existing `a` (deactivate) — G2 makes
  `Delete` conditionally behave like `a` for in-scope auto entries, it
  does not introduce a separate keybinding for that case.
- No change to `OverrideEntry::name`/other fields' YAML
  presence — only `auto` is added.

## Specification

### `override_pane.rs`

- `YamlEntry` (all 3 variants): add
  `#[serde(default, skip_serializing_if = "is_false")] auto: bool,`.
- `to_yaml`: include `auto` when constructing each `YamlEntry`.
- `from_yaml`: `auto` flows through automatically via `#[serde(default)]`
  once the field exists on the struct — restored entries now carry
  whatever `auto` was saved, not a hardcoded `false`.

### `tui.rs`

- `App::auto_entry_in_scope(&mut self, entry: &OverrideEntry) -> bool`:
  factored out of `render_overrides`'s existing staleness comparison
  (see G2 above for why it lives here, not on `OverrideCollection`).
- `render_overrides`'s existing staleness/demotion block: replace its
  inlined comparison with a call to `self.auto_entry_in_scope(&entry)`.
- `handle_manage_key`'s `Delete`/`Backspace` branch: gate on `entry.auto`
  and `self.auto_entry_in_scope(&entry)` per G2 above.
- `render_manage_pane`: apply the two new `Style`s per G1, via
  `theme::style_for(SyntaxRole::Type, self.theme)` plus/minus
  `Modifier::BOLD`.

## Test plan

1. G1: manual and auto entries render in visibly distinct styles;
   highlighted row still shows `REVERSED` layered on top of either.
2. G2: `Delete` on an in-scope auto entry deactivates it (does not
   remove it from `entries()`), message bar shows the explanatory text.
3. G2: `Delete` on an auto entry that has gone out of scope (parent
   override changed) actually removes it.
4. G2: `Delete` on a manual (`auto == false`) entry — unchanged, removes
   it outright, no message.
5. G3: `:save-overrides` then `:restore-overrides` round-trips an
   `auto: true` entry's `auto` flag exactly (currently would silently
   reset to `false` — this is the regression test for the behavior
   change).
6. G3: loading a pre-existing YAML file saved before this spec (no
   `auto` key present) still loads successfully with `auto: false` for
   every entry.
7. `reuse lint` passes.
