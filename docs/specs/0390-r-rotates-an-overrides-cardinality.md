<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0390 — `r` rotates an override's cardinality

Status: implemented
Implemented in: 2026-10-04
App: protolens
Refs: docs/specs/0348-override-cmd-card-prefill.md (the
      per-entry explicit cardinality this spec edits, its
      optional → repeated → required order, and its normalization);
      docs/specs/0236-an-override-is-edited-as-one-command.md (`o`, and
      the "`o` then Enter changes nothing" rule, S6);
      docs/specs/0125-protolens-manage-pane-auto-manual-lifecycle.md
      (automatic and manual entries)

## Background

An override entry carries an explicit cardinality (spec 0348):
`cardinality: Option<Cardinality>`, where `None` means "as the schema
declares it" (`field_cardinality`, which falls back to `optional` when
nothing is declared). Today the only way to change it is a full
`:override <origin> --as <type> --cardinality <c>` line. In the override
management pane, that means `o`, then editing the line, then Enter.

The pane binds `s` and `r` to pre-filled `:save-overrides` and
`:restore-overrides` lines (`manage_pane.rs`). The main view has the same
two bindings (`key_dispatch.rs`).

While writing this spec, a latent bug turned up. The pane's `o` leaves
`--cardinality` out of its pre-filled line, so that an entry stored
without one stays that way (spec 0348 §S3). But Enter on a line with no
`--cardinality` calls `set_cardinality(idx, None)`. So `o` then Enter
silently clears an explicit cardinality, which breaks spec 0236 S6.
Nobody hits it today, because explicit cardinalities are rare. `r` would
make them common.

## Goals

- **G1.** In the management pane, `r` rotates the highlighted entry's
  cardinality one step: optional → repeated → required → optional. `R`
  rotates the other way, as `Z` does for origins.
- **G2.** The change takes effect at once, like the pane's other edits.
- **G3.** The pane shows each entry's explicit cardinality, so the
  effect of `r` is visible on the entry itself.
- **G4.** In the pane, `s` and `r` no longer pre-fill `:save-overrides`
  and `:restore-overrides`. The commands can still be typed in full, and
  the main view keeps both shortcuts.
- **G5.** `o` then Enter in the pane leaves an entry's cardinality as it
  was.

## Non-goals

- **N1.** No fourth "(schema)" state in the cycle. Normalization (S2)
  already brings an entry back to "as the schema declares it" when the
  rotation reaches the schema's value.
- **N2.** No change to `:override --cardinality` itself, nor to Tab
  rotation of its value (spec 0348 G4).
- **N3.** No new main-view binding. Rotating cardinality is an edit of a
  stored entry, which is what the management pane is for.

## Specification

- **S1. The keys.** In the management pane, with an entry highlighted:
  - `r` sets the entry's cardinality to the step after the one in
    effect: optional → repeated → required → optional.
  - `R` sets it to the step before.
  - "In effect" is the entry's explicit cardinality if it has one, else
    `field_cardinality` of the entry's subject node.

- **S2. Normalization.** As `:override` does (spec 0348 S5/S6), a result
  equal to `field_cardinality(subject)` is stored as `None`. Three
  presses of `r` therefore always come back to where they started,
  including to "as the schema declares it".

- **S3. When `r` does nothing.** `r` and `R` leave the entry unchanged,
  and set the status message, when:
  - the entry's origin matches no node in this document
    ("override matches nothing here: no field to take a cardinality
    from"). The subject node would otherwise fall back to the cursor
    (`origin_subject_node`), which is unrelated to the entry;
  - the subject node is the document root ("the root is not a field: it
    has no cardinality").

- **S4. Effect.** After a rotation:
  - the entry's `auto` flag is cleared, as `rotate_origin` does: an
    entry edited by hand is a manual entry (spec 0125);
  - the rendering is redone with `render_overrides`, as `D` does;
  - the status message names the result, e.g. "cardinality: repeated",
    or "cardinality: optional (as declared)" when it normalized to
    `None`.

  The method on the collection is `rotate_cardinality`, next to
  `rotate_origin`, built on `set_cardinality`.

- **S4a. Cardinality is part of a node's render provenance.**
  `render_overrides` re-renders a node only when its provenance changes
  (`resettle_node`). The provenance was `(type, field name)`, so a
  change of cardinality alone re-rendered nothing, whether it came from
  `r` or from an `:override` that changed only `--cardinality`. The
  provenance is now `(type, field name, explicit cardinality)`
  (`provenance.rs`). The table interns distinct values only, so this
  costs nothing per node.

- **S5. Display.** An entry row (`manage_type_line`) ends with the
  entry's explicit cardinality in brackets, e.g. `[repeated]`, when it
  has one. A `None` entry shows nothing, so the common case stays as it
  looks today.

- **S6. `s` and `r` in the pane.** The pane's `s` and `r` arms that
  pre-fill `:save-overrides` and `:restore-overrides` are removed; `r`
  now means S1, and `s` does nothing in the pane. The main view's
  bindings are unchanged.

- **S7. `o` keeps an explicit cardinality.** The pane's `o` adds
  `--cardinality <c>` to its pre-filled line when the entry has an
  explicit cardinality, and only then. Enter on that line stores the
  same value, so `o` then Enter changes nothing (G5). An entry with no
  explicit cardinality still gets a line without `--cardinality`, as
  spec 0348 §S3 intends.

- **S8. Help.** The pane's help (`help_text.rs`) drops the `s` and `r`
  pre-fill lines, keeps `:save-overrides <path>` and
  `:restore-overrides <path>`, and adds:
  `r / R            rotate the entry's cardinality (optional → repeated → required)`.

## Alternatives considered

### Keep `s` in the pane

Nothing else wants `s` in the pane. It goes anyway, so that save and
restore follow one rule in the pane: they are typed commands. A lone `s`
whose partner is now `r`-for-rotate would be a trap.

### A fourth "(schema)" step

It would make "as declared" a visible step of its own. But it is not a
cardinality, and normalization already returns to it (N1). It would
also make four presses, not three, the full turn.

### Rotate from the stored value only

Starting from `None` as if it were `optional` would make the first `r`
on a `repeated` field land on `repeated` again, which looks like `r`
did nothing. Starting from the cardinality in effect avoids that.

## Test plan

1. `r_rotates_forward_and_normalizes`: on an entry whose field is
   declared `optional`, `r` gives `Some(Repeated)`, then
   `Some(Required)`, then `None`.
2. `capital_r_rotates_backward`: from `None` on an `optional` field, `R`
   gives `Some(Required)`, then `Some(Repeated)`, then `None`.
3. `r_starts_from_the_declared_cardinality`: on a field declared
   `repeated` with no explicit cardinality, `r` gives `Some(Required)`.
4. `r_clears_auto`: rotating an automatic entry makes it manual.
5. `r_refuses_an_entry_that_matches_nothing` and
   `r_refuses_the_root`: the entry is unchanged and the status message
   is set.
6. `s_and_r_no_longer_prefill_save_and_restore_in_the_pane`: neither
   opens the command line in the pane; both still do in the main view.
7. `o_then_enter_keeps_an_explicit_cardinality`: an entry with
   `Some(Repeated)` keeps it through `o` then Enter (G5, the bug in the
   Background).
8. `the_row_shows_an_explicit_cardinality`: `manage_type_line` ends with
   `[repeated]` for `Some(Repeated)`, and has no bracket for `None`.

## Measured outcome

Implemented 2026-10-04.

- Before implementing, I checked that the document root shows no
  cardinality, with a throwaway test. On the root, `--cardinality
  repeated` and `required` leave the header `1 {  #@ Outer = 1`
  unchanged, while a nested field's header becomes `#@ repeated Inner =
  1` and `#@ required Inner = 1`. So S3's refusal on the root is
  correct.
- S4a was found while implementing: the first version of test 1 failed
  because the header did not change. The same gap affected `:override`
  with only `--cardinality` changed, so it predates this spec.
  `a_cardinality_only_override_rerenders_the_node` covers it.
- The help pane (`help_text.rs`) is the only place the pane's keys are
  documented; the man pages do not list them.
- Test plan 1–8 pass, plus the S4a test. All 1290 protolens tests pass
  locally; clippy and `cargo fmt --check` are clean. The Nix sandbox
  test run (`nix-build -A rust-tests`) passes in full: all 34 test
  binaries.
