<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0077 — Varint range veto for non-enum scalar fields

**Status:** draft
**Implemented in:** —
**App:** scoring-graph

---

## Background

The scoring walk (spec 0042) already vetoes a candidate schema when a varint
field value falls outside the declared enum's range.  For non-enum varint
fields, however, all proto scalar types that share wire type 0 — `bool`,
`int32`, `int64`, `uint32`, `uint64`, `sint32`, `sint64` — are currently
collapsed into a single `VARINT` leaf in the scoring graph.  A value of, say,
`802` on field 1 happily matches a schema that declares field 1 as `bool`,
even though `bool` only allows `0` and `1`.

This was discovered during investigation of the `google.container.v1.NodeManagement`
stress-test warning, which reported 9 tied candidates.  Three of the ties are
expected (v1 / v1alpha1 / v1beta1 are structurally identical schemas).  The
other six — five `google.ads.googleads.vN.common.UserAttribute` variants and
`google.dataflow.v1beta3.FlexTemplateRuntimeEnvironment` — are false positives
caused exactly by this collapse: their fields 1 and 2 are `int64`/`int32` (for
`UserAttribute`) and `int32` (for `FlexTemplateRuntimeEnvironment`), but the
scoring graph stores all of them as plain `VARINT`, indistinguishable from
`NodeManagement`'s `bool` fields 1 and 2.

Note: the tie in the `NodeManagement` stress-test case is not resolvable by
this spec alone, because the test instance has values `1, 1` for its bool
fields — valid for every varint type.  The improvement is asymmetric: an
instance whose fields 1/2 carry values like `802` and `972` would correctly
be vetoed against `NodeManagement` (bool).  This matters for real-world
payloads and for instances of the false-positive schemas themselves.

---

## Goals

1. Introduce finer-grained varint leaf kinds in the scoring graph that carry
   enough range information to veto out-of-range values at scoring time.
2. Reduce false-positive ties in `list-schemas` output across the corpus.

## Non-goals

- Resolving ties where the instance values happen to fall within all competing
  ranges (e.g. the specific `NodeManagement` stress-test instance).
- Changing the treatment of enum fields (already handled via `enum_range`).
- Modifying the text rendering path in reproto.

---

## Specification

### §1 — Varint type taxonomy

Every proto scalar type that uses wire type 0 has a well-defined valid range
over the 64-bit varint value as decoded from the wire:

| Proto type | Signed? | Valid wire range (64-bit varint) |
|------------|---------|----------------------------------|
| `bool`     | —       | `{0, 1}` |
| `int32`    | yes     | `[0, 2³²−1]` on wire (two's-complement 32-bit, zero-extended to 64-bit for negative values) |
| `int64`    | yes     | `[0, 2⁶⁴−1]` (any 64-bit varint) |
| `uint32`   | no      | `[0, 2³²−1]` |
| `uint64`   | no      | `[0, 2⁶⁴−1]` (any 64-bit varint) |
| `sint32`   | zigzag  | `[0, 2³²−1]` on wire (zigzag-encoded; same as uint32 wire range) |
| `sint64`   | zigzag  | `[0, 2⁶⁴−1]` (any 64-bit varint) |

Grouping by distinct wire-range:

- **BOOL** — `{0, 1}`: veto if wire value > 1
- **VARINT32** — `[0, 2³²−1]`: veto if wire value > 0xFFFF_FFFF (already partially handled as non-canonical, but not a veto today)
- **VARINT64** — `[0, 2⁶⁴−1]`: never veto on range alone (any decoded varint fits)

`int32`, `uint32`, `sint32` all share range `[0, 2³²−1]` on the wire, so they
map to the same leaf kind.  `int64`, `uint64`, `sint64` accept any 64-bit
value, so they remain indistinguishable from each other.

### §2 — Changes to the scoring graph

Replace the single `VARINT` leaf kind with three new leaf kinds:

| New kind | Wire veto condition | Proto types |
|----------|---------------------|-------------|
| `BOOL`     | value > 1           | `bool` |
| `VARINT32` | value > 0xFFFF_FFFF | `int32`, `uint32`, `sint32` |
| `VARINT64` | (none)              | `int64`, `uint64`, `sint64` |

The existing `ENUM` kind is unchanged; enum fields continue to use the
`enum_range` mechanism.

In `ScoringKind` (load.rs):
- Remove `Varint`.
- Add `Bool`, `Varint32`, `Varint64`.

In `leaf_for_field` (graph.rs):
- Map `ScoringKind::Bool` → a new `LEAF_BOOL` sentinel.
- Map `ScoringKind::Varint32` → a new `LEAF_VARINT32` sentinel.
- Map `ScoringKind::Varint64` → `LEAF_VARINT64` (or reuse the old `LEAF_VARINT`
  sentinel value for backward compatibility).

`LeafAttrs` gains a `varint_kind` discriminant used during Hopcroft initial
partitioning so that `BOOL`, `VARINT32`, and `VARINT64` leaves are placed in
distinct equivalence classes from the start.

### §3 — Changes to the scoring walk

In the `WT_VARINT` arm of the walk (walk.rs), after decoding the raw 64-bit
value `val`:

```
match node.varint_kind {
    Bool    => if val > 1         { veto("bool value out of range") }
    Varint32 => if val > 0xFFFF_FFFF { veto("uint32 value out of range") }
    Varint64 => { /* no range veto */ }
    Enum    => { /* existing enum_range logic, unchanged */ }
}
```

The existing non-canonical handling for `int32` negative values
(`0x8000_0000..=0xFFFF_FFFF`) is preserved under `Varint32`.

### §4 — Changes to scoring-graph YAML emission (reproto)

The scoring-graph YAML emitter (reproto `--emit-scoring-graphs`) currently
writes `kind: VARINT` for all non-enum varint fields.  It must be updated to
emit `kind: BOOL`, `kind: VARINT32`, or `kind: VARINT64` based on the proto
field type:

| Proto field type | Emitted kind |
|------------------|--------------|
| `bool`           | `BOOL`       |
| `int32`, `uint32`, `sint32` | `VARINT32` |
| `int64`, `uint64`, `sint64` | `VARINT64` |

The `parse_kind` function in load.rs must accept the three new strings.  The
old `"VARINT"` string should be accepted for backward compatibility and treated
as `VARINT64` (the least restrictive interpretation).

### §5 — Hopcroft bisimulation impact

The finer leaf partition means that two schema states that previously collapsed
under Hopcroft (because both had a `VARINT` transition on some field) may now
remain distinct if one uses `BOOL` and the other `VARINT32`.  This is the
desired outcome: the bisimulation should reflect the true discriminating power
of the scoring walk.

---

## Open questions

- Should `VARINT` (legacy) map to `VARINT32` or `VARINT64` in the backward-
  compatibility fallback?  `VARINT64` is safer (never introduces new vetoes on
  old graph data); `VARINT32` would be more aggressive.  Recommendation:
  `VARINT64`.

- `sint32`/`sint64` use zigzag encoding, so the *semantic* value differs from
  the wire value.  The range veto operates on the raw wire varint, not the
  decoded signed value.  This is correct: the wire value for sint32 is still
  in `[0, 2³²−1]`, and a wire value > `0xFFFF_FFFF` is invalid regardless of
  zigzag interpretation.

---

## Testing

- Unit tests in `scoring-graph/src/score/tests.rs`: add cases for `BOOL` veto
  (value 2 on a bool field), `VARINT32` veto (value `2³²` on a uint32 field),
  and `VARINT64` pass-through (large value on an int64 field).
- Stress test: re-run `nix-build -A googleapis-tests` and verify that the
  number of tied-FQDN warnings does not increase, and ideally decreases.
