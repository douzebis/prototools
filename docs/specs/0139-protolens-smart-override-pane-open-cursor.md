<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0139 — protolens: smart sort-mode/cursor positioning when opening the override pane via `t`

Status: implemented
Implemented in: 2026-07-17
Refs: docs/specs/0114-protolens-tui.md (override pane, `t`, inferred vs
      alphabetic sort modes), docs/specs/0117-protolens-override-
      management-pane.md (`OverrideCollection`, `OverrideOrigin`,
      management pane), docs/specs/0124-protolens-override-kind-
      rotation.md (`origin_for_kind`), docs/specs/0132-protolens-
      override-pane-live-preview-and-default-target.md (§G1's current,
      partial "active override takes priority" default-highlight
      logic — this spec supersedes it), docs/specs/0134-protolens-
      override-kind-mutation-rework.md, docs/specs/0137-protolens-
      override-primitive-and-enum-candidates.md (`None` sentinel,
      row-0 retirement), 2026-07-17 feedback (`manage_pane.rs`'s
      `initial_manage_highlight`, whose branch 2 this spec reuses)
App: protolens

## Background

Pressing `t` opens the override selection pane on the node under the
cursor. Today (`override_select.rs`'s `toggle_override`) it always:

1. Resets `override_sort` to `SortMode::Inferred` unconditionally.
2. Calls `recompute_override_candidates()` (populates the Inferred-mode
   candidate list, ranked by score).
3. If the cursor node has an *active* override
   (`resolve_active_override_entry`), searches for that type's row
   within whatever `override_candidates` recompute just produced —
   spec 0132 §G1's "priority (1)". If found, moves the highlight
   there; if not found (the active type isn't in the Inferred list —
   e.g. it's a primitive keyword, or was filtered out as `vetoed`),
   the highlight silently stays at Inferred's own default (top score),
   even though the active type is nowhere visible in that mode.
4. Otherwise the highlight is simply whatever `recompute_override_
   candidates` defaults to (Inferred mode, row 0 = top score, or an
   empty list with a "no scoring graph available" message when no
   graph is loaded).

This never opens in Lexicographic (alphabetic) mode, and never
consults the override *management* list for a currently-inactive
entry that would still apply to this node if activated — both gaps
the user wants closed, with an explicit mental model: "show me the
type most relevant to this node, wherever it lives."

The user's request (verbatim):

> In the main pane, when pressing `t` to enter the override selection
> pane:
> - If the current node in the main pane is currently impacted by an
>   override:
>   - If the corresponding type is available in the "inferred list"
>     for this node, open the inferred list, and point the cursor to
>     the given type
>   - Else open the global ("alphabetic") list, and point the cursor
>     to the given type
> - Else, if the current node in the main pane could be impacted by a
>   currently inactive override, pick the first such override in the
>   override management list, and consider the associated type: apply
>   the rules of the preceding point
> - Else, if the inferred list for this node is not empty, open the
>   inferred list and position the cursor on the first item (high
>   scores)
> - Else, open the alphabetic list and position the cursor on the
>   first item
>
> Btw: previously we artificially added an initial `<raw / no type>`
> item at the top of the inferred list. This can be removed now, and
> will be soon superseded by the "fake" primitive type `Empty` [now
> `None`, spec 0137's rename] that will be selectable from the
> alphabetic list.

The "Btw" note is already moot: spec 0137's row-0 retirement already
removed the pinned `<raw / no type>` row, and the `None` sentinel
already occupies row 0 of the alphabetic list as an ordinary entry
(spec 0137 §G1/§G4) — no action needed here beyond confirming it.

### Prior art this spec reuses rather than reinvents

`manage_pane.rs`'s `initial_manage_highlight` (opened via `o`) already
solves the "does an entry, active or not, apply to this node"
question, in priority order:

```rust
fn initial_manage_highlight(&self) -> usize {
    if self.overrides.entries().is_empty() {
        return 0;
    }
    if let Some(i) = self.resolve_active_override_entry_index(self.cursor) {
        return i;
    }
    let candidates: Vec<OverrideOrigin> = [
        OverrideKind::Path,
        OverrideKind::PathField,
        OverrideKind::FqdnField,
    ]
    .into_iter()
    .filter_map(|k| self.origin_for_kind(self.cursor, k).ok())
    .collect();
    self.overrides
        .entries()
        .iter()
        .position(|e| candidates.contains(&e.origin))
        .unwrap_or(0)
}
```

Its second branch — "the first entry, in the pane's own lexicographic
display order, whose origin would resolve against the cursor node
under *some* `OverrideKind`, even though none currently is active" —
is *exactly* the user's second bullet ("could be impacted by a
currently inactive override... pick the first such override in the
override management list"). This spec factors that branch out into a
shared helper rather than re-deriving equivalent-but-subtly-different
matching logic.

This list-order matching is deliberately *not* the same
`Path > PathField > FqdnField` kind-priority order Step A/
`resolve_active_override_entry` uses for *active* entries — confirmed
during review (2026-07-17): Step A's priority order exists because, at
most, one *active* entry can genuinely apply per kind, and picking
among them needs a tie-break; Step B is working with *inactive*
entries instead, where reusing `o`'s own established, already-
reviewed selection order is the more consistent choice than inventing
a second, different "first" for the same underlying data.

## Goals

- G1: `toggle_override` (`override_select.rs`) picks `override_sort`
  and the initial `override_highlight` via the following unified
  algorithm, replacing today's unconditional-Inferred-then-search
  logic (spec 0132 §G1 is superseded/subsumed by step A below):

  **Step A** — an *active* override applies to the cursor node
  (`resolve_active_override_entry(self.cursor)` is `Some(entry)`):
  candidate type = `entry.r#type` (`None` = raw). Go to the
  mode-selection rule (below).

  **Step B** — else, some *inactive* entry's origin would apply to
  the cursor node if activated: extract the shared "first matching
  entry, in `overrides.entries()`'s own order" helper out of
  `initial_manage_highlight`'s second branch (see Background), call
  it with `self.cursor`. If it returns `Some(i)`, candidate type =
  `self.overrides.entries()[i].r#type`. Go to the mode-selection rule.
  (By construction, since Step A already found no *active* match,
  every entry this helper can find here is necessarily inactive — no
  separate `!e.active` filter is needed, but implementers may add one
  defensively.)

  **Step C/D** — else (neither A nor B produced a candidate type): no
  mode-selection rule runs; use whatever `recompute_override_
  candidates()` already defaults to when called in `SortMode::
  Inferred` (row 0 = top score) *if* that call produces a non-empty
  list; otherwise switch to `SortMode::Lexicographic` and recompute
  (row 0 = the `None` sentinel) — see G3 for the "non-empty" check and
  message-suppression detail.

  **Mode-selection rule** (shared by Steps A and B, given a candidate
  type `fqdn_or_raw: Option<String>`):
  1. Set `override_sort = SortMode::Inferred`, call
     `recompute_override_candidates()`, then force the *complete*
     (not capped-preview) list via `upgrade_active_override_to_
     complete()` (G2) before searching.
  2. Compute `key = fqdn_or_raw.unwrap_or_else(|| "protolens_internal.None".to_string())`.
  3. If `key` is found in `override_candidates`, set `override_
     highlight` to that row and stop — opened in Inferred mode.
  4. Else, set `override_sort = SortMode::Lexicographic`, call
     `recompute_override_candidates()` again, and search again. This
     second search is guaranteed to succeed: Lexicographic's candidate
     set is the fixed universe of every selectable type (`None`
     sentinel + the 15 primitive keywords + `all_type_fqdns`, which is
     the same message/enum FQDN set `key` must have come from) — set
     `override_highlight` to that row. Opened in Lexicographic mode.

- G2: the mode-selection rule's Inferred-list membership check must
  use the *complete* ranked list, not whatever possibly-capped preview
  `candidate_cache` last served (`recompute_override_candidates`'s own
  doc comment: toggling into Inferred mode can reuse a capped
  preview). A capped preview could omit `key` even though the
  complete list contains it further down, causing a false "not
  found" that would incorrectly open Lexicographic mode instead.
  Calling `upgrade_active_override_to_complete()` (a no-op if already
  complete) before the membership check avoids this.

- G3: Step C/D's "inferred list is not empty" check (`recompute_
  override_candidates()` called in `SortMode::Inferred` yields a
  non-empty `override_candidates`) covers two distinct "empty" causes
  identically — no scoring graph loaded at all (`self.ctx.graph` is
  `None`), and a graph that is loaded but produced zero non-`vetoed`
  candidates for this node's byte range. In *both* cases, Step C/D
  falls through to opening Lexicographic mode directly (row 0 = the
  `None` sentinel). Confirmed 2026-07-17: the "no scoring graph
  available for inferred order; press 'i' for alphanumeric" message
  that `recompute_override_candidates` sets in the no-graph case must
  **not** surface to the user in this auto-fallback path, since `t`
  already performed exactly that fallback automatically; showing the
  message would be redundant/confusing. (Manually pressing `i` to
  switch to Inferred mode on a graph-less session is untouched — that
  message still fires there, as today.)

- G4: opportunistic fix, discovered while drafting this spec: that
  same message currently reads `"...press 'a' for alphanumeric"` — a
  stale reference to the sort-toggle key predating item 1's rename to
  `i` (`docs/specs/... 1. ... use i ... rather than a`). Fix the
  string to say `'i'` while this code path is touched anyway.

- G5: opportunistic fix, also discovered while drafting this spec:
  `mouse.rs`'s `handle_override_click` still computes `let total_rows
  = self.override_candidates.len() + 1;` — an old pinned-row-0-era
  `+1` offset that spec 0137's row-0 retirement should have removed
  but didn't. Unrelated to this spec's own algorithm, but fixed
  alongside it (confirmed 2026-07-17: fold both incidental fixes in
  rather than filing separately).

## Non-goals

- N1: no change to `can_override`'s eligibility rules, the
  `MIN_OVERRIDE_WIDTH` narrow-terminal refusal, or the "close the
  management pane first" mutual-exclusion behavior — `toggle_override`
  keeps every existing guard before this spec's algorithm runs.
- N2: no change to `initial_manage_highlight`'s own priority order or
  behavior (`o` key) — only its second branch's matching logic is
  factored into a shared helper; the manage pane's own highlight
  selection is otherwise untouched.
- N3: no change to `preview_override_highlight` itself, nor to when
  `toggle_override` calls it (still once, at the end, on whatever row
  the algorithm above lands on).
- N4: no change to `OverrideCollection`'s sort order, `OverrideOrigin`
  matching (`origin_for_kind`, `origin_is_at_or_under`), or any
  activation/deactivation semantics — this spec only changes what
  `toggle_override` does with information those existing primitives
  already expose.
- N5: no change to item 3's ask (`Enter`/double-click triggering `t`
  or `o`) — tracked separately; this spec covers only `t`'s own
  cursor-positioning, which item 3 will then be able to delegate to
  once implemented.

## Specification

### New shared helper (`manage_pane.rs` or `override_apply.rs`)

Factor `initial_manage_highlight`'s second branch out into:

```rust
/// The first entry in `overrides.entries()`'s own display order whose
/// origin would resolve against `idx` under *some* `OverrideKind`
/// (`Path`/`PathField`/`FqdnField`), regardless of whether that entry
/// is currently active. Shared by `initial_manage_highlight` (`o`
/// key) and `toggle_override`'s smart-open logic (`t` key, spec
/// 0139).
pub(super) fn first_entry_matching_origin_candidates(&self, idx: usize) -> Option<usize> {
    let candidates: Vec<OverrideOrigin> = [
        OverrideKind::Path,
        OverrideKind::PathField,
        OverrideKind::FqdnField,
    ]
    .into_iter()
    .filter_map(|k| self.origin_for_kind(idx, k).ok())
    .collect();
    self.overrides
        .entries()
        .iter()
        .position(|e| candidates.contains(&e.origin))
}
```

`initial_manage_highlight` calls this and falls back to `.unwrap_or(0)`
exactly as its current inline version does — no behavior change there.

### `override_select.rs`'s `toggle_override`

Restructure the block currently spanning "Spec 0132 §G1: priority
(1)..." through the trailing `preview_override_highlight()` call (see
Background's excerpt) into Steps A/B/C/D and the mode-selection rule
from G1, using the new helper for Step B and
`upgrade_active_override_to_complete()` for G2's complete-list check.
The final `self.preview_override_highlight()` call stays, unconditional,
at the very end.

### `recompute_override_candidates`'s no-graph message (G3/G4)

The existing no-graph branch:

```rust
None => {
    self.message = "no scoring graph available for inferred order; press 'a' \
                     for alphanumeric"
        .to_string();
    Vec::new()
}
```

becomes (G4's string fix):

```rust
None => {
    self.message = "no scoring graph available for inferred order; press 'i' \
                     for alphanumeric"
        .to_string();
    Vec::new()
}
```

G3's suppression is achieved at the *call site* in `toggle_override`,
not inside `recompute_override_candidates` itself (which has other,
legitimate callers — e.g. the `i` key toggle — where the message
should still fire): after calling `recompute_override_candidates()` in
Step C/D's Inferred attempt, if `override_candidates` came back empty,
clear `self.message` before switching to Lexicographic mode and
recomputing again, e.g.:

```rust
self.override_sort = SortMode::Inferred;
self.recompute_override_candidates();
if self.override_candidates.is_empty() {
    self.message.clear();
    self.override_sort = SortMode::Lexicographic;
    self.recompute_override_candidates();
}
```

(Exact placement/helper extraction left to implementation time — this
illustrates the required behavior.)

## Test plan

1. Cursor on a node with an active override whose type is present in
   that node's *complete* inferred candidate list → `t` opens in
   Inferred mode, highlight on that type's row.
2. Cursor on a node with an active override whose type is a primitive
   keyword (never present in the inferred list, by construction) → `t`
   opens in Lexicographic mode, highlight on that keyword's row.
3. Cursor on a node with an active override whose type is a message
   FQDN that inferred scoring `vetoed` for this byte range (present in
   the alphabetic universe, absent from the inferred list) → `t` opens
   in Lexicographic mode, highlight on that FQDN's row.
4. Same as test 1, but the type is present only beyond what a stale
   `candidate_cache` preview would have shown — confirms G2's
   `upgrade_active_override_to_complete()` call prevents a false
   Lexicographic fallback.
5. Cursor on a node with an active override whose type is raw
   (`Option::None`) → `t` opens in Lexicographic mode, highlight on
   the `None` sentinel row (row 0).
6. Cursor on a node with *no* active override, but the management list
   holds an inactive entry whose origin exactly matches the node
   (`Path`, `PathField`, or `FqdnField`) → `t` opens per the
   mode-selection rule applied to that entry's type (mirroring tests
   1-3's two outcomes).
7. Same as test 6, but two inactive entries share a matching origin
   under different `OverrideKind`s (e.g. one `Path` match and one
   `FqdnField` match) — confirms the *first* one in `overrides.
   entries()`'s own list order is picked, matching `o`'s existing,
   already-reviewed `initial_manage_highlight` behavior (list order,
   not kind-priority order).
8. Cursor on a node with neither an active nor an applicable-inactive
   override, non-empty inferred list → `t` opens in Inferred mode,
   highlight on the top-scored row (unchanged from today).
9. Cursor on a node with neither, and an empty inferred list because
   every candidate was `vetoed` (graph loaded, zero non-vetoed
   results) → `t` opens in Lexicographic mode, highlight on the `None`
   sentinel row, with no stray "no scoring graph" message.
10. Cursor on a node with neither, and no scoring graph loaded at all
    → `t` opens in Lexicographic mode directly, no message shown.
    Manually pressing `i` afterward (or in an unrelated session with
    no active/inactive match at all) still shows the no-graph message
    as today.
11. `first_entry_matching_origin_candidates` unit-tested directly (or
    indirectly via both `o`'s and `t`'s call sites) to confirm
    `initial_manage_highlight`'s own behavior is unchanged by the
    extraction.
12. G5's `mouse.rs` fix: `handle_override_click`'s row-hit-testing
    behaves identically before/after removing the stale `+ 1` (a
    regression check that no off-by-one existed to compensate for it).
13. `cargo fmt --check`, `reuse lint`, full test suite pass.
