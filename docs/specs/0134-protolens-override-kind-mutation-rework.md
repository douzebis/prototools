<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0134 — protolens: override-kind creation/mutation rework

Status: implemented
Implemented in: 2026-07-16
Refs: docs/specs/0117-protolens-override-collection.md (`OverrideKind`,
      `OverrideOrigin`, per-kind derivation), docs/specs/0119-protolens-
      override-fidelity-and-workflow.md (selection-pane `z`), docs/specs/
      0124-protolens-manage-pane-navigation.md (G1 `manage_affected_nodes`/
      Left-Right, G2 manage-pane `z`/`Z` — reworked here), docs/specs/0125-
      protolens-manage-pane-auto-manual-lifecycle.md (`auto` reset on
      rotation, unchanged)
App: protolens

## Background

Two independent `z`/`Z` key bindings exist today, both rotating
`OverrideKind` (`Path -> PathField -> FqdnField -> Path -> ...`,
spec 0117 §2):

1. **Selection pane** (`t`, `handle_override_key`): rotates
   `App.override_kind`, the kind a *not-yet-created* override will be
   given once `Enter` applies it. Defaults to `Path` at startup
   (`App::new`) but can be rotated away before the first `Enter`.
2. **Manage pane** (`o`, `handle_manage_key`, spec 0124 G2): rotates an
   *existing* entry's origin in place, rederived from the main-pane
   cursor's current position — but only when the cursor already sits on
   a node the entry currently affects (`manage_affected_nodes`
   membership test). If not, `z`/`Z` does nothing but write `"z:
   main-pane cursor is not on a field affected by the selected
   override"` to the message line — every subsequent `z`/`Z` press
   repeats the identical check and the identical failure until the user
   manually repositions the cursor (e.g. via spec 0124 G1's Left/Right).

Feedback (2026-07-16): every new override should always be created as
kind `Path` — the selection pane's own per-creation kind choice is
removed entirely (goal 1 below). Separately, the manage pane's `z`/`Z`
is judged too strict: it should attempt to work out the mutated
origin's target(s) itself from all the nodes the entry currently
affects, only falling back to asking the user (via the main-pane cursor
and the message line) when the answer is genuinely ambiguous — and it
should never get permanently stuck repeating an unresolvable rotation
(goal 2 below).

## Goals

### G1 — remove the override selection pane's `z`/`Z`

- `handle_override_key`: delete the `z`/`Z` match arm entirely.
- `App.override_kind` is removed (its only remaining possible value was
  always `Path` once G1 lands — nothing left to track).
- `override_origin_for_kind(idx)` (used by the selection pane's `Enter`
  handler to build the origin a new override is `activate`d with)
  always derives a `Path` origin now: `self.origin_for_kind(idx,
  OverrideKind::Path)`.
- `render_override_pane`'s title drops the `— kind: {…} (z to rotate)`
  segment — nothing to show or rotate any more.
- `HELP_TEXT`'s "Override pane" section drops its `z / Z` two-line
  entry.
- `next_valid_origin` (spec 0119/0124's helper — "rotate `kind` towards
  `to_next`/`to_prev`, skipping kinds that don't apply") loses its only
  other caller once G2 replaces the manage pane's own use of it (see
  below) — deleted entirely, not just its selection-pane call site.

### G2 — manage pane `z`/`Z`: forgiving multi-candidate resolution

Replaces spec 0124 G2's strict single-node gating. Whenever `z`/`Z` is
pressed while the manage pane is focused and non-empty, targeting the
highlighted entry:

1. Let `origin` = the highlighted entry's *current* origin, `entry_kind`
   = `origin.kind()`.
2. Let `affected` = `manage_affected_nodes(&origin)` (spec 0124 G1's
   existing helper, unchanged): the nodes affected by `origin` as it
   stands *right now*, before any rotation.
3. Determine `attempt_kind` — the kind this key press evaluates:
   - If `App.manage_pending_kind` is `Some((p, k, last_cursor))` with
     `p == origin` (a still-live unresolved attempt against this same
     entry, see G3):
     - `self.cursor == last_cursor` — the main-pane cursor has **not**
       moved since that attempt — `attempt_kind` = one more step past
       `k`, in this key's direction (`z` = `k.next()`, `Z` =
       `k.prev()`). This is what keeps a run of same-key presses moving
       through the 3-kind barrel instead of repeating an identical
       failure forever.
     - `self.cursor != last_cursor` — the cursor **has** moved since
       that attempt (e.g. via Left/Right) — `attempt_kind = k`: retry
       the exact kind the previous attempt was stuck on (regardless of
       whether this press is `z` or `Z`), since the new cursor position
       may now resolve it.
   - Otherwise (no live pending attempt for this origin — first press
     since highlighting this entry, or the previous attempt succeeded)
     — `attempt_kind` = one step from `entry_kind` (`z` =
     `entry_kind.next()`, `Z` = `entry_kind.prev()`).
4. Build `candidates`: for each node in `affected`, attempt
   `origin_for_kind(node, attempt_kind)`; keep the `Ok` results, in
   `affected`'s document order, deduplicated by `OverrideOrigin`
   equality (distinct nodes can legitimately derive the same
   `FqdnField` origin, e.g. two sibling instances of the same repeated
   field).
5. Resolve, in priority order:
   - `candidates` is empty:
     - Let `other_kind` be the third `OverrideKind` — neither
       `entry_kind` nor `attempt_kind` (there are only three kinds
       total, so this is unambiguous). Build `other_candidates` the
       same way (step 4) for `other_kind`.
     - `other_candidates` is *also* empty (e.g. the entry is on
       `fqdn:field` and both `path` and `path:field` derive nothing) →
       write `"z: no override target"` to the message line; entry
       unchanged; **abort**: clear `manage_pending_kind` — there is
       nothing left to try under any kind, so no further attempt needs
       tracking.
     - `other_candidates` is non-empty → write `"z: no override
       target, try again for {other_kind.label()}"` to the message
       line (naming the one remaining kind that does have candidates);
       entry unchanged; set `manage_pending_kind = Some((origin,
       attempt_kind, self.cursor))`.
   - `self.cursor` is in `affected` and `origin_for_kind(self.cursor,
     attempt_kind)` succeeds → use that origin (even if `candidates`
     has other entries too — an on-cursor match always wins).
   - `candidates.len() == 1` → use that one candidate (even though the
     cursor isn't on the node that produced it).
   - Otherwise (2+ distinct candidates, no usable cursor match) → write
     `"z: pick an override target (<-/->)"` to the message line; entry
     unchanged; set `manage_pending_kind = Some((origin, attempt_kind,
     self.cursor))`.
6. On a successful resolution (either of the two middle bullets above):
   `rotate_origin` exactly as spec 0124 G2 already does today (preserve
   `active`; deactivate any other entry that now collides on the new
   origin if this entry is active; reset `auto` to `false`; re-render;
   relocate `manage_highlight` by `(origin, type)` identity, same
   post-render-reshuffle handling already in place). Clear
   `App.manage_pending_kind` back to `None`.

### G3 — "don't get stuck": pending-kind barrel state

- New `App` field `manage_pending_kind: Option<(OverrideOrigin,
  OverrideKind, usize)>` — the origin identity, the `attempt_kind`, and
  the main-pane cursor position (`self.cursor`) of the last unresolved
  `z`/`Z` attempt (G2 step 5's empty/ambiguous outcomes). `None`
  initially (`App::new`) and whenever cleared.
- Cleared back to `None`:
  - On every successful rotation (G2 step 6).
  - On the "abort" outcome — both alternate kinds empty (G2 step 5).
  - Whenever `manage_highlight` changes to a different entry, via any
    existing path (`j`/`k`, `PageUp`/`PageDown`, `Home`/`End`, search
    jump, mouse click/wheel, `d` duplicate, Delete/Backspace) — mainly
    a safety net for the rare case where two distinct entries share the
    same origin (duplicate entries, spec 0124 G3), so switching between
    them never inherits stale pending state.
- The "advance past a stuck kind" vs. "retry the same stuck kind"
  choice (G2 step 3) is driven entirely by comparing `self.cursor`
  against the cursor position recorded in `manage_pending_kind` — no
  separate reset step is needed for ordinary cursor movement (Left/
  Right, spec 0124 G1, unchanged): it's naturally observed the moment
  it's compared on the very next `z`/`Z` press.

## Non-goals

- No change to `manage_affected_nodes`, `origin_for_kind`,
  `rotate_origin`'s existing per-kind derivation, active-collision, or
  `auto`-reset behavior — all reused unchanged.
- No change to Left/Right (spec 0124 G1) itself — still circulates the
  main-pane cursor among nodes affected by the highlighted entry's
  *current* origin, still doesn't itself commit anything. G2/G3 only
  give its effect on `self.cursor` new significance for the *next*
  `z`/`Z` press.
- No change to how a brand-new override is *applied* once `Enter` is
  pressed in the selection pane (still `OverrideCollection::activate`)
  — only the *kind* it's created with (G1) changes.
- No change to `d` (duplicate), `a`/Space (toggle active), Delete/
  Backspace, search, or any other manage-pane key beyond `manage_
  pending_kind`'s reset (G3).
- No new UI affordance beyond the message-line text — no popup, no
  inline candidate list/count rendered anywhere.
- No change to `:type-as`/`:type-as-raw` (bypass the selection pane
  entirely already, unaffected by G1).

## Specification

### `tui.rs`

- Remove `App.override_kind` and its `App::new` initializer
  (`OverrideKind::Path`).
- Remove `handle_override_key`'s `KeyCode::Char('z') |
  KeyCode::Char('Z')` arm.
- `override_origin_for_kind(&self, idx: usize) -> Result<OverrideOrigin,
  String>`: body becomes `self.origin_for_kind(idx,
  OverrideKind::Path)`.
- `render_override_pane`: title `format!` drops `" — kind: {} (z to
  rotate)"` and the corresponding `self.override_kind.label()`
  argument.
- `HELP_TEXT`: delete the "Override pane" section's `z / Z` entry;
  rewrite the "Override management" section's `z / Z` entry to
  describe the new forgiving behavior (exact wording finalized at
  implementation time, summarizing G2/G3).
- New field `manage_pending_kind: Option<(OverrideOrigin, OverrideKind,
  usize)>` on `App`, `None` in `App::new`.
- `handle_manage_key`'s `KeyCode::Char('z') | KeyCode::Char('Z')` arm:
  reimplemented per G2.
- New private helper, e.g. `fn manage_kind_candidates(&self, affected:
  &[usize], kind: OverrideKind) -> Vec<OverrideOrigin>` (G2 step 4,
  reused for both `attempt_kind` and the empty-case `other_kind`
  look-ahead).
- New private helper, e.g. `fn third_kind(a: OverrideKind, b:
  OverrideKind) -> OverrideKind` (or equivalent inline match) — the
  `OverrideKind` that is neither `a` nor `b` (G2 step 5's `other_kind`).
- `next_valid_origin` deleted (both former call sites gone: G1 removes
  the selection pane's, G2 replaces the manage pane's).
- Every other site that reassigns `manage_highlight` (`move_manage_
  highlight`, `Home`/`End`, search-jump, mouse click/wheel handling,
  `duplicate`'s post-call reassignment, Delete/Backspace's post-remove
  clamp) additionally sets `self.manage_pending_kind = None` (G3).

### `override_pane.rs`

- No changes — `OverrideKind`/`OverrideOrigin`/`OverrideCollection`
  (`next`/`prev`/`label`, `rotate_origin`, etc.) are all reused as-is.

## Test plan

1. G1: pressing `z`/`Z` while the selection pane is focused is a no-op
   (no message, no state change, no crash); `Enter` always creates a
   `Path`-kind origin.
2. G1: `HELP_TEXT` no longer documents `z`/`Z` for the override
   (selection) pane.
3. G2 (fully empty / abort): an entry whose every other kind's
   candidate list is empty (e.g. an `fqdn:field` entry where both
   `path` and `path:field` derive nothing) → message `"z: no override
   target"`, entry unchanged, `manage_pending_kind` cleared; a further
   `z`/`Z` press reproduces the identical outcome (there is nothing
   else to try).
4. G2 (empty with a viable alternate): `attempt_kind`'s candidate list
   is empty but the third kind's is not → message `"z: no override
   target, try again for {label}"` naming that third kind;
   `manage_pending_kind` set; a same-key press with the cursor
   unchanged advances straight to that third kind and re-evaluates it
   (which may itself succeed, be ambiguous, or single-candidate,
   depending on the fixture).
5. G2 (cursor match): cursor on one of several affected nodes → that
   node's derived origin is used even though other affected nodes
   exist and would derive different origins.
6. G2 (single candidate): exactly one affected node yields a valid
   `attempt_kind` origin (others fail derivation, or there is exactly
   one affected node total) and the cursor is not on it → that one
   candidate is used anyway.
7. G2/G3 (ambiguous, no cursor movement): 2+ distinct valid candidates,
   cursor not on any of them → message `"z: pick an override target
   (<-/->)"`, entry unchanged; a same-key press with the cursor still
   unchanged advances to the next kind in the barrel instead of
   repeating the identical ambiguous outcome.
8. G2/G3 (ambiguous, then resolved via cursor): same starting point as
   7, but the main-pane cursor is moved (Left/Right) onto one of the
   affected nodes before the next `z`/`Z` press — that press retries
   `attempt_kind` (does not advance to a different kind) and succeeds
   via the cursor-match branch.
9. G3: `manage_pending_kind` is cleared by moving `manage_highlight` to
   a different entry, and by any successful rotation.
10. Existing spec 0124 G1 (Left/Right circulation) and G3 (duplicate)
    tests still pass unchanged.
11. `reuse lint` passes.
