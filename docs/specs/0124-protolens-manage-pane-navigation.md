<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0124 — protolens: manage-pane field circulation, kind rotation, duplication

Status: implemented
Implemented in: 2026-07-15
Refs: docs/specs/0117-protolens-override-collection.md (`OverrideCollection`,
      `OverrideOrigin`, `activate`/`activate_impl`, `toggle_active`),
      docs/specs/0119-protolens-override-fidelity-and-workflow.md
      (manage-pane `e`/`a` keys, `manage_highlight`),
      protolens/todo.md (2026-07-15 feedback, items 1/6/7 — discussion and
      decisions this spec formalizes)
App: protolens

## Background

Three related manage-pane (`o` key, `handle_manage_key`) ergonomics
requests share the same underlying machinery — resolving an
`OverrideOrigin` to the main-pane node(s) it currently matches — and were
discussed and decided together in `protolens/todo.md`'s 2026-07-15
feedback (items 1, 6, 7).

1. Given the entry currently highlighted in the manage pane
   (`manage_highlight`), circulate the main-pane cursor among the fields
   that entry's origin currently resolves to, without touching focus.
2. Given the manage pane's currently-highlighted entry, rotate its
   `OverrideOrigin`'s kind (`Path` -> `PathField` -> `FqdnField` -> `Path`,
   same rotation `handle_override_key`'s `z` already does for a *pending*
   origin) in place, re-deriving the origin from the main-pane cursor's
   current position.
3. Allow multiple `OverrideCollection` entries to share the same origin
   (at most one active at a time, already an existing invariant — see
   below), with a `d` key to duplicate the highlighted entry as a new,
   inactive copy.

None of these require new resolution primitives from scratch:
`override_origin_for_kind(idx)` (tui.rs 2059-2088) already computes, for
a given main-pane node index and a `OverrideKind`, what origin that node
would have — reused as-is by item 6. `OverrideCollection::activate_impl`
(override_pane.rs) already deactivates every *other* entry sharing an
origin when one is activated/toggled, regardless of `r#type` — this
existing "at most one active entry per origin" invariant is exactly what
makes item 3's "duplicates OK, only one active" requirement already safe
today; the only missing piece is a `duplicate` method that pushes a raw
clone bypassing `activate_impl`'s look-up-by-`(origin,type)` dedup.

## Goals

### G1 — circulate affected main-pane fields from the manage pane

- New keys in `handle_manage_key`, active whenever `manage_focus` and the
  manage pane is non-empty: **Left-arrow** moves the main-pane cursor to
  the *previous* node whose origin matches the highlighted entry's
  origin, in document order; **Right-arrow** moves to the *next* one.
  Both roll over (from the last match, Right-arrow goes to the first;
  from the first, Left-arrow goes to the last).
- Matching is by `OverrideOrigin` equality against the highlighted
  entry's `origin` — same semantics `origin_resolves`/
  `resolve_active_override_entry` already use elsewhere, just enumerating
  *all* matches instead of testing one candidate or resolving the single
  "current" one.
- If the origin has zero matches in the current tree, the main-pane
  cursor does not move (no error message needed — this is a normal,
  expected state e.g. right after `:restore-overrides` silently drops an
  unresolvable entry per spec 0117 §4's existing policy).
- Neither key changes `manage_focus`/`override_focus` — the manage pane
  keeps keyboard focus throughout, only `self.cursor` (and consequently
  the main pane's scroll position) changes.
- Per-kind enumeration cost (documented, not a design concern — typical
  document sizes make all three cheap in practice):
  - `Path`: at most one match, via the existing `resolve_path`.
  - `PathField`: scan the children of the one parent node
    `path` resolves to.
  - `FqdnField`: no shortcut available — a full document-order walk,
    since a message type of a given FQDN can recur anywhere in the tree.

### G2 — `z` rotates an existing entry's kind

- New key in `handle_manage_key`: **`z`**, active when the manage pane is
  focused and the main-pane cursor currently sits on a node whose origin,
  under *some* kind, matches the highlighted entry's current origin (see
  membership test below) — i.e. the cursor must currently be "on a field
  affected by" the highlighted entry, mirroring item 1's enumeration but
  as a membership test rather than a full walk (short-circuits on first
  match, only needs to answer yes/no plus which node's own origin to
  reuse as the rotation's basis).
- If the cursor is not on such a field, `z` does nothing to the entry and
  writes an error to the message bar: `"z: main-pane cursor is not on a
  field affected by the selected override"`.
- If it is: rotate `OverrideKind` the same way `handle_override_key`'s
  `z` does (`OverrideKind::next()`), recompute the entry's `origin` via
  `override_origin_for_kind(self.cursor)` under the new kind, and:
  - Preserve the entry's `active` state as-is.
  - If the entry being rotated is itself `active` and the newly-computed
    origin collides with another currently-active entry elsewhere, that
    other entry is deactivated — this is not new logic, it is
    `OverrideCollection`'s existing `activate`/`toggle_active` invariant
    (every other entry sharing an origin is deactivated when one
    activates), reused unchanged. If the entry being rotated is
    *inactive*, rotating it onto an origin that already has an active
    entry elsewhere does not touch that other entry — the two simply
    coexist (this is item 3/G3's world).
  - Always reset `auto` to `false` on the rotated entry — changing an
    override's origin is a deliberate user action, same "explicit action
    pins it manual" rule `activate`/`toggle_active` already apply
    elsewhere (see spec 0125 for the full `auto` semantics this rule is
    part of).
  - Re-run `render_overrides` afterward (same as other manage-pane
    mutations) and keep `manage_highlight` on the rotated entry.

### G3 — allow duplicate-origin entries; `d` duplicates

- `OverrideCollection` gains a `duplicate(&mut self, idx: usize) -> usize`
  method: pushes a raw clone of `entries[idx]` with `active` forced to
  `false` (bypassing `activate_impl`'s existing `(origin, type)` look-up,
  which would otherwise just reactivate the original instead of adding a
  new entry), keeps `auto`/`name`/`r#type` as-is, then `sort()`s and
  returns the new entry's post-sort index.
- New key in `handle_manage_key`: **`d`**, active when the manage pane is
  focused and non-empty — duplicates the highlighted entry, re-renders,
  and moves `manage_highlight` to the new (always-inactive) copy.
- No change needed to `manage_display_rows`/the header-grouping logic —
  it already groups by adjacent same-origin runs and tolerates more than
  one entry per run.
- No change needed to `toggle_active`/`activate`'s existing dedup-safety
  — already correct for this case (confirmed in Background above).

## Non-goals

- No change to `handle_override_key`'s own `z` (the *pending*,
  not-yet-created override's kind rotation in the selection pane) —
  G2 is a distinct code path for an *existing* manage-pane entry.
- No new "jump to override pane and start editing" behavior on
  Enter/double-match — per the todo.md discussion, Enter was dropped
  entirely from scope in favor of Left/Right-arrow only.
- No change to how duplicate entries are *rendered* beyond what already
  works (no new coloring here — see spec 0125 for auto/manual coloring,
  a separate concern).

## Specification

### `handle_manage_key` (tui.rs) additions

- `KeyCode::Left`/`KeyCode::Right`: implement G1 via a new helper,
  `manage_affected_nodes(&self, origin: &OverrideOrigin) -> Vec<usize>`
  (document-order list of matching main-pane node indices, per the
  per-kind strategies above), then move `self.cursor` to the
  previous/next entry in that list relative to its current position (or
  the nearest one if `self.cursor` isn't itself in the list), with
  wraparound. No-op (no message) if the list is empty.
- `KeyCode::Char('z')`: implement G2. Reuse `manage_affected_nodes`'
  membership (or a short-circuiting sibling, `cursor_is_affected_by`) for
  the gating check.
- `KeyCode::Char('d')`: implement G3 via `OverrideCollection::duplicate`.

### `OverrideCollection::duplicate` (override_pane.rs)

```rust
pub fn duplicate(&mut self, idx: usize) -> usize {
    let mut clone = self.entries[idx].clone();
    clone.active = false;
    self.entries.push(clone);
    self.sort();
    // recompute idx of the pushed clone after sort()
}
```

## Test plan

1. G1: `PathField`/`FqdnField` entries with 0/1/many matches — Left/
   Right-arrow cycles correctly, rolls over, no-ops on zero matches,
   never changes `manage_focus`.
2. G1: `Path` entry — at most one match, Left/Right both land there (or
   no-op if unresolvable).
3. G2: cursor not on an affected field — `z` leaves the entry/origin
   unchanged, message bar shows the error text.
4. G2: cursor on an affected field, entry active, rotation collides with
   another active entry elsewhere — the other entry is deactivated, the
   rotated entry stays active with the new origin, `auto` reset to
   `false`.
5. G2: same but entry inactive — no other entry is touched.
6. G3: `duplicate` on an active entry — new entry is inactive, both
   coexist in `entries()`, `activate`-ing the new one deactivates the
   original (existing invariant, not new code).
7. `reuse lint` passes.
