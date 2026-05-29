<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0077 — Varint leaf refinement: INT32 / UINT32 / UINT64 / RANGE

**Status:** implemented
**Implemented in:** 2026-05-29
**App:** scoring-graph

---

## Background

The scoring walk (spec 0042) vetoes a candidate schema when a varint field
value falls outside the declared enum's range.  For non-enum varint fields,
however, all proto scalar types that share wire type 0 — `bool`, `int32`,
`int64`, `uint32`, `uint64`, `sint32`, `sint64` — are currently collapsed into
a single `VARINT` leaf in the scoring graph.  A value of, say, `802` on field
1 happily matches a schema that declares field 1 as `bool`, even though `bool`
only allows `0` and `1`.

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

1. Replace the single `VARINT` leaf kind with finer-grained kinds that carry
   enough wire-range information to veto out-of-range values at scoring time.
2. Generalise the existing `ENUM` dynamic leaf (with its `(i32, i32)` range)
   into a unified `RANGE` leaf that also covers `bool`.
3. Reduce false-positive ties in `list-schemas` output across the corpus.

## Non-goals

- Resolving ties where the observed values happen to fall within all competing
  ranges (e.g. the specific `NodeManagement` stress-test instance with values
  `1, 1`).
- Per-field range annotations on non-enum scalar fields (future work; the
  edge-label encoding type bits described in §6 are reserved for that).
- Modifying the text rendering path in reproto.
- Removing the `--no-strict-ranges` escape hatch in favour of per-corpus
  configuration (future work).

---

## Specification

### §1 — Varint type taxonomy

Every proto scalar type that uses wire type 0 has a well-defined valid range
over the 64-bit varint value as decoded from the wire:

| Proto type | Encoding    | Valid wire value (64-bit) |
|------------|-------------|---------------------------|
| `bool`     | unsigned    | `{0, 1}` |
| `int32`    | 2's compl.  | `[0, 0x7FFF_FFFF]` ∪ `[0xFFFF_FFFF_8000_0000, 0xFFFF_FFFF_FFFF_FFFF]` |
| `uint32`   | unsigned    | `[0, 0xFFFF_FFFF]` |
| `sint32`   | zigzag      | `[0, 0xFFFF_FFFF]` |
| `int64`    | 2's compl.  | `[0, 0xFFFF_FFFF_FFFF_FFFF]` (any 64-bit varint) |
| `uint64`   | unsigned    | `[0, 0xFFFF_FFFF_FFFF_FFFF]` (any 64-bit varint) |
| `sint64`   | zigzag      | `[0, 0xFFFF_FFFF_FFFF_FFFF]` (any 64-bit varint) |

Note that `int32` negative values are sign-extended to 64 bits before varint
encoding, producing 10-byte wire representations with the upper 32 bits all
set.  This distinguishes `int32` from `uint32`/`sint32` at the wire level: a
wire value in `[0x8000_0000, 0xFFFF_FFFF_7FFF_FFFF]` is invalid for all three
(it does not correspond to any valid `int32`, `uint32`, or `sint32` value).

`uint32` and `sint32` have identical valid wire ranges and identical veto
conditions; they are wire-indistinguishable at the scoring level.  Similarly,
`int64`, `uint64`, and `sint64` all accept any 64-bit varint and are
wire-indistinguishable.

### §2 — New leaf kind taxonomy

The single `VARINT` fixed leaf is replaced by three new fixed leaves, and the
existing `ENUM` dynamic leaf is renamed `RANGE` and extended to cover `bool`:

| Leaf kind | Fixed/dynamic | Covers | Wire veto condition |
|-----------|---------------|--------|---------------------|
| `INT32`   | fixed         | `int32` | val in `(0x7FFF_FFFF, 0xFFFF_FFFF_8000_0000)` — the invalid gap |
| `UINT32`  | fixed         | `uint32`, `sint32` | val > `0xFFFF_FFFF` |
| `UINT64`  | fixed         | `int64`, `uint64`, `sint64` | none |
| `RANGE`   | dynamic       | `bool`, enum fields | val outside `[min, max]` |

`RANGE` leaves carry a `(i32, i32)` range, allocated dynamically by
`LeafRegistry` (one entry per unique `(min, max)` pair, shared across all
fields with the same range).  `bool` maps to the RANGE entry `[0, 1]`.

The existing non-varint fixed leaves (`LEAF_I64`, `LEAF_LEN`, `LEAF_STRING`,
`LEAF_I32`) are unchanged.

### §3 — Changes to ScoringKind and LeafRegistry (load.rs, graph.rs)

In `ScoringKind` (load.rs):
- Remove `Varint`, `Enum`.
- Add `Int32`, `Uint32`, `Uint64`, `Range`.

`ScoringField.enum_range` is renamed `range` and now also carries the `[0, 1]`
range for `bool` fields.

In `LeafRegistry` (graph.rs):
- Rename `enum_sentinel` → `range_sentinel`; rename `enum_ranges` → `ranges`.
  Type stays `Vec<(i32, i32)>`.
- Replace `LEAF_VARINT` with three new fixed sentinel constants `LEAF_INT32`,
  `LEAF_UINT32`, `LEAF_UINT64`.  `NUM_FIXED_LEAVES` increases from 5 to 7.
  The sentinel layout (descending from `u32::MAX`) becomes:

```
u32::MAX      = LEAF_I32
u32::MAX - 1  = LEAF_STRING
u32::MAX - 2  = LEAF_LEN
u32::MAX - 3  = LEAF_I64
u32::MAX - 4  = LEAF_UINT64   (was LEAF_VARINT)
u32::MAX - 5  = LEAF_UINT32   (new)
u32::MAX - 6  = LEAF_INT32    (new)
u32::MAX - 7  = (gap — matches pre-existing sentinel arithmetic)
u32::MAX - 8  = RANGE leaf 0  ← dynamic RANGE leaves start here
u32::MAX - 9  = RANGE leaf 1
...
```

The gap at `u32::MAX - 7` mirrors the pre-existing gap at `u32::MAX - 5` in
the old layout (between `LEAF_VARINT` and dynamic enum leaf 0).  It is an
artefact of the sentinel allocation formula and is harmless.

All sites that hard-code `NUM_FIXED_LEAVES` (currently 5) or the dynamic-leaf
offset formula `u32::MAX - 5 - 1 - idx` must be updated to reflect 7 fixed
leaves and the new offset `u32::MAX - 7 - 1 - idx`.

In `leaf_for_field` (graph.rs):
- `ScoringKind::Int32`  → `LEAF_INT32`
- `ScoringKind::Uint32` → `LEAF_UINT32`
- `ScoringKind::Uint64` → `LEAF_UINT64`
- `ScoringKind::Range`  → `reg.range_sentinel(min, max)` (dynamic, as before
  for enums)

`LeafAttrs` renames `enum_range_idx` → `range_idx`; semantics unchanged
(0xFFFF = no range, otherwise index into `ranges`).

### §4 — Changes to the scoring walk (walk.rs)

A `ScoringOpts` struct is introduced in walk.rs to carry walk-behaviour flags:

```rust
pub struct ScoringOpts {
    /// If true (default), out-of-range RANGE values are vetoed.
    /// If false (--no-strict-ranges), they are non-canonical++ instead.
    pub strict_ranges: bool,
}

impl Default for ScoringOpts {
    fn default() -> Self { Self { strict_ranges: true } }
}
```

The signature of `score_all` gains an `opts` parameter:

```rust
pub fn score_all(pb: &[u8], graph: &ArchivedCompiledGraph, opts: &ScoringOpts) -> Vec<EntryScore>
```

`list_schemas_one` in run.rs gains the same parameter (display flags such as
`detailed_score` are kept separate as they are not scoring concerns):

```rust
pub fn list_schemas_one(
    pb_bytes: &[u8],
    graph: &LoadedGraph,
    path_label: &str,
    top: Option<usize>,
    detailed_score: bool,
    opts: &ScoringOpts,
    out: &mut dyn Write,
) -> Result<(), String>
```

`--no-strict-ranges` is added as a per-subcommand flag on both `Decode` and
`ListSchemas` in lib.rs.  It is a scoring concern, not a global CLI concern,
so it lives at subcommand level alongside `--detailed-score`.

The walk receives the `strict_ranges` flag from `opts` and uses it as follows:

The leaf kind is determined by `node.wire_type`:

- `wire_type == 0` and `range_idx == 0xFFFF` → UINT64
- `wire_type == 0` and `range_idx != 0xFFFF` → RANGE
- `wire_type == 8` → UINT32
- `wire_type == 9` → INT32

In the `WT_VARINT` arm, after decoding the raw 64-bit value `val`, replace the
current enum-only check with:

```
match leaf_kind {
    UINT64 => { /* no veto, no non-canonical */ }

    UINT32 => {
        if val > 0xFFFF_FFFF {
            veto("uint32/sint32 value out of 32-bit range")  // always veto
        }
    }

    INT32 => {
        if val > 0xFFFF_FFFF && val < 0xFFFF_FFFF_8000_0000 {
            veto("int32 value in invalid gap")               // always veto
        } else if val >= 0xFFFF_FFFF_8000_0000 {
            // val in [0xFFFF_FFFF_8000_0000, 0xFFFF_FFFF_FFFF_FFFF]:
            // canonical 10-byte encoding of a valid negative int32; not an error.
        } else if (0x8000_0000..=0xFFFF_FFFF).contains(&val) {
            // valid negative int32 encoded in 5 bytes instead of 10 (truncated)
            non_canonical += 1
        }
        // val in [0, 0x7FFF_FFFF]: canonical positive int32; no action.
    }

    RANGE => {
        if val >= (1u64 << 32) {
            veto("range field value out of 32-bit range")    // always veto
        } else {
            if (0x8000_0000..=0xFFFF_FFFF).contains(&val) {
                non_canonical += 1                           // truncated negative
            }
            let signed = val as i32 as i64;
            if signed < min as i64 || signed > max as i64 {
                if strict_ranges {
                    veto("range value outside declared range")
                } else {
                    non_canonical += 1
                }
            }
        }
    }
}
```

The 32-bit width check (`val > 0xFFFF_FFFF`) is always a veto, unaffected by
`--no-strict-ranges`.  Only the within-32-bit range check on RANGE leaves is
downgraded to non-canonical++ by the flag.

### §5 — Changes to scoring-graph YAML emission (reproto, serial.rs)

Both the reproto `--emit-scoring-graphs` emitter and `dump_compiled` in
serial.rs produce scoring-graph YAML.  Both must be updated to the same format
and kept in sync.

#### YAML format

Each node entry carries a `type` field with the exact proto type name.
`wire_type` and `is_string` are dropped — both are fully determined by `type`.
The `range` field is included only for `bool` and `enum` nodes; it is omitted
for all other types.

```yaml
- id: 42
  type: sint32

- id: 17
  type: bool
  range: [0, 1]

- id: 5
  type: enum
  range: [-1, 5]

- id: 11
  type: message
```

The loader maps `type` directly to the internal leaf kind and `wire_type`
discriminant stored in `NodeEntry`:

| `type` | Internal kind | `NodeEntry.wire_type` |
|--------|---------------|-----------------------|
| `int32` | INT32 | 9 |
| `uint32`, `sint32` | UINT32 | 8 |
| `int64`, `uint64`, `sint64` | UINT64 | 0 |
| `bool`, `enum` | RANGE | 0 |
| `string` | LEN_STRING | 2 |
| `bytes` | LEN | 2 |
| `float` | I32 | 5 |
| `double` | I64 | 1 |
| `message` | node (non-leaf) | 2 |
| `group` | node (non-leaf) | 3 |

Non-leaf (message/group) nodes appear in the YAML with `type: message` or
`type: group`; they carry no `range` field.

Range bounds are serialized as YAML flow sequences `[min, max]` with integer
values.  For `(i32, i32)` ranges all values fit comfortably in a 64-bit signed
integer; no overflow handling is required.

### §6 — Edge label encoding type bits (reserved)

The `label` byte on `TransitionEntry` currently uses bits 0–1 for cardinality
(0=optional, 1=required, 2=repeated).  The following bits are **reserved** for
future use to encode the wire interpretation of a RANGE leaf when per-field
range annotations are introduced:

- bit 2: width (0 = 32-bit, 1 = 64-bit)
- bits 3–4: encoding (00 = unsigned, 01 = 2's complement, 10 = zigzag)

These bits must be written as 0 and ignored by readers until a future spec
activates them.  When activated, they will allow a single `RANGE(u64, u64)`
leaf to be interpreted correctly (unsigned, signed, or zigzag-decoded) without
adding a discriminant field to `NodeEntry`.

### §7 — Hopcroft bisimulation impact

The finer fixed-leaf partition means that two schema states that previously
collapsed under Hopcroft (because both had a `VARINT` transition on some field)
may now remain distinct.  For example, a `bool` field (RANGE `[0,1]`) and an
`int32` field (INT32) on the same field number start in different Hopcroft
initial partition classes and cannot be merged.  This is the desired outcome:
the bisimulation reflects the true discriminating power of the scoring walk.

---

## Open questions

None at time of writing.

---

## Testing

Unit tests in `scoring-graph/src/score/tests.rs`:

- RANGE/bool, strict (default): wire value `2` on a `bool` field → vetoed.
- RANGE/enum, strict (default): wire value outside `[min, max]` → vetoed.
- RANGE/enum, `--no-strict-ranges`: wire value outside `[min, max]` →
  non_canonical++, not vetoed.
- RANGE, val >= `2³²`: vetoed even with `--no-strict-ranges`.
- UINT32: wire value `2³²` → vetoed (always).
- UINT32: wire value `0xFFFF_FFFF` → not vetoed.
- INT32: wire value `0x1_0000_0000` (in the 32-bit gap) → vetoed (always).
- INT32: wire value `0xFFFF_FFFF_8000_0000` (valid negative int32) →
  not vetoed, non_canonical++.
- INT32: wire value `0x7FFF_FFFF` → not vetoed, no non_canonical.
- UINT64: large value (`2⁶³`) on an `int64` field → not vetoed.

Stress test: re-run `nix-build -A googleapis-tests` and verify that the
number of tied-FQDN warnings does not increase, and ideally decreases.
