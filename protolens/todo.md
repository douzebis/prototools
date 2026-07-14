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
