<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# protolens — working todo / status

Not a spec — a running status board for in-flight feedback items, tracking
which spec/doc each one lives in, its decision status, and open questions
that block implementation. Update in place as items move
open -> decided -> implemented; delete an item once it's folded into a
spec as `Implemented` (don't let this file drift out of sync with the
specs it points at).

## Spec 0113 (`docs/specs/0113-protolens-tui-refinements.md`) — small UI items

D27/D28/D29/D30/D31/D32/D33/D34 implemented (2026-07-14) — see spec 0113
§D27/§D28/§D29/§D30/§D31/§D32/§D33/§D34 (folded out of this list per this
file's own convention).

## Spec 0119 (`docs/specs/0119-protolens-override-fidelity-and-workflow.md`)
— override fidelity + manage-pane workflow

`Status: implemented (2026-07-14)`. Four interrelated items sharing
`splice_override`'s synthetic-wrapper mechanics. G1/G2/G3/G4 implemented
(2026-07-14) — see spec 0119 §G1/§G2/§G3/§G4 (folded out of this list per
this file's own convention).

## Spec 0114 §1.3 (`docs/specs/0114-protolens-range-type-override.md`)
— widen override eligibility to length-delimited scalars

Implemented (2026-07-14) — see spec 0114 §1.3 (folded out of this list per
this file's own convention). The packed-repeated-element exclusion this
item's open design question worried about turned out to need no new
`NodeSpan`/design work at all: a packed element's own `wire_type` is
always the element's primitive kind, never `WT_LEN`, so the simple
`is_message || wire_type == WT_LEN` predicate already excludes it for
free.

## Spec 0120 (`docs/specs/0120-protolens-any-messageset-as-auto-overrides.md`)
— Any/MessageSet expansion as automatic overrides

Implemented (2026-07-14) — see spec 0120 (folded out of this list per this
file's own convention).

## 2026-07-15 feedback — 9 items

Discussed/decided (review comments below, resolved via inline `=>`
replies), split across specs 0124-0129. All 9 items implemented
(2026-07-15) — see spec 0124 §G1/§G2/§G3, spec 0125, spec 0126 §G1/§G2,
spec 0127, spec 0128, spec 0129 (folded out of this list per this file's
own convention).

### 6. Manage pane: `z` to rotate an entry's kind — spec 0124 G2

In the override management pane, a way to change the kind of the current
override. Proposal: re-use the same `z` key to rotate between kinds.

Notes:
- Rotating the kind would only work if the cursor on the main pane is
  currently on a field affected by the override. If not, an error
  message should be displayed in the command/message pane
- Rotating the kind would keep the state active/inactive of the override
  being manipulated. AND in case it leads to a "collision", it would
  deactivate the collided override

[[Shares machinery with item 1 (need the membership-test twin of item 1's
enumeration: "is main-pane cursor among this entry's affected fields"),
and reuses `override_origin_for_kind`'s existing per-kind path/fqdn
derivation logic.

On "collision → deactivate": I think this isn't a new rule, it's just
`OverrideCollection`'s existing invariant (`activate` already deactivates
every other entry sharing an origin) — it only bites if the entry being
rotated is itself active. If it's inactive, rotating it onto an origin
that already has an active entry elsewhere shouldn't touch anything (no
collision — they just coexist, this is exactly item 7's world). Confirm
that's your intent?
=> I confirm.

Open question: should rotating also reset `auto` to `false` (same
"explicit user action pins it manual" rule `activate` already follows),
or leave `auto` untouched since only `origin` is changing?
=> Yes: altering an override automatically change its nature to manual]]

### 7. Manage pane: allow duplicate entries, `d` to duplicate — spec 0124 G3

In the override management pane and elsewhere, allow duplicate entries
with the same origin, as long as only one is ever activated. This makes
sense with a workflow where you duplicate an entry, then adjust it by
changing its kind (say). Also add a key (`d`?) for duplicating an entry
in the override management pane. The entry is duplicated always inactive.

[[Good news: almost already supported by the data model. `OverrideCollection`
is a plain `Vec` with no uniqueness constraint, and `toggle_active`
already deactivates *every* entry sharing an origin regardless of
`r#type` when one is activated — so two literal duplicates (same origin
AND type) are already mutually-exclusive-safe today. The only gap is the
dedup-by-`(origin,type)` lookup inside `activate_impl`, which a dedicated
`duplicate(idx)` method (push a raw clone with `active: false`, bypassing
`activate_impl`) sidesteps entirely. The manage-pane header-grouping
logic already tolerates runs of same-origin entries too. Low-risk, will
implement as described.
=> Perfect]]
