<!--
SPDX-FileCopyrightText: 2025 - 2026 Frederic Ruget <fred@atlant.is> <fred@s3ns.io> (GitHub: @douzebis)
SPDX-FileCopyrightText: 2025 - 2026 Thales Cloud Sécurisé

SPDX-License-Identifier: MIT
-->

# 0010 — protoc --decode compatibility for canonical wire input

**Status:** draft
**App:** prototext

---

## Problem

`prototext` aims to be a superset of `protoc --decode`: for canonical
wire-level input (no anomalies), its output should be byte-for-byte identical
to `protoc --decode` (modulo the annotation comment, which protoc does not
emit).

Two known divergences exist today:

### Divergence A — packed repeated fields

`protoc --decode` renders a packed repeated field as **N separate lines**, one
per element, identical to non-packed repeated fields:

```
int32Pk: 1
int32Pk: 2
int32Pk: 3
```

`prototext` renders packed fields using a bracket array syntax:

```
int32Pk: [1, 2, 3]  #@ repeated int32 [packed=true] = 85
```

This is a fundamental output format difference.

### Divergence B — non-canonical NaN values

`protoc --decode` renders all NaN values (canonical or not) as bare `nan`.

`prototext` currently renders non-canonical NaNs as `nan(0x…)`, which is not
valid protoc syntax and would be rejected by `protoc --encode`.

For **canonical** wire input, NaN values are always the canonical quiet NaN
(`0x7FC00000` for float, `0x7FF8000000000000` for double), which already
renders as bare `nan` — so divergence B does not affect canonical input.
It only matters for non-canonical NaN payloads, which are anomalies by
definition.

---

## Goals

- For canonical wire input, `prototext` output (without annotations) is
  byte-for-byte identical to `protoc --decode` output.
- Lossless round-trip is preserved for all wire input (canonical and
  non-canonical) when annotations are enabled.
- The annotation continues to carry all information needed for lossless
  re-encoding.

## Non-goals

- Matching `protoc --decode` output for non-canonical input (protoc cannot
  decode anomalies; this is out of scope by definition).
- Implementing `protoc --encode` compatibility on the encoding side (a
  separate concern).

---

## Proposal

### A. Packed field rendering

#### A.1 Decoder (wire → text)

Render each element of a packed field on its own line, using the field name,
exactly as protoc does:

```
int32Pk: 1
int32Pk: 2
int32Pk: 3
```

The annotation on the **first** element carries the full field declaration
and any anomaly modifiers. Subsequent elements carry a minimal annotation
(field declaration only, no repeated modifiers):

```
int32Pk: 1  #@ repeated int32 [packed=true] = 85
int32Pk: 2  #@ repeated int32 [packed=true] = 85
int32Pk: 3  #@ repeated int32 [packed=true] = 85
```

However, per-element anomaly modifiers (`packed_ohb`, `packed_truncated_neg`)
must be attached to the correct element.  The cleanest approach: emit one
annotation per element, carrying its own modifiers:

```
int32Pk: 1  #@ repeated int32 [packed=true] = 85
int32Pk: 2  #@ repeated int32 [packed=true] = 85; ohb: 3
int32Pk: 3  #@ repeated int32 [packed=true] = 85
```

Tag-level modifiers (`tag_ohb`, `TAG_OOR`, `len_ohb`) apply to the entire
packed field (the wire tag and the LEN payload), not to individual elements.
They belong on the first element's annotation:

```
int32Pk: 1  #@ repeated int32 [packed=true] = 85; tag_ohb: 2; len_ohb: 1
int32Pk: 2  #@ repeated int32 [packed=true] = 85
int32Pk: 3  #@ repeated int32 [packed=true] = 85
```

Empty packed field (`[]` today) becomes a zero-element sequence — nothing is
emitted. The wire bytes for an empty packed field (tag + len=0) are currently
rendered as `field: []`. Under the new scheme, nothing would appear in the
output. This is also what protoc does: an empty packed array produces no
output lines.

**Special case: `INVALID_PACKED_RECORDS`.**  If the packed payload cannot be
decoded (truncated varint, etc.), the field is rendered as a single
`INVALID_PACKED_RECORDS` line as today — no change.

#### A.2 Encoder (text → wire)

The encoder must recognize **N consecutive lines** with the same field name
annotated as `repeated … [packed=true]` and accumulate them into a single
packed LEN field:

```
int32Pk: 1  #@ repeated int32 [packed=true] = 85
int32Pk: 2  #@ repeated int32 [packed=true] = 85
int32Pk: 3  #@ repeated int32 [packed=true] = 85
```

→ tag `(85<<3)|2`, length 3, payload `[0x01, 0x02, 0x03]`.

The encoder already parses annotations to detect `is_packed` from the field
declaration.  The key change is that it must buffer consecutive packed
elements before writing the wire output.

**Ordering invariant:** In the prototext format, all elements of a packed
field are contiguous.  The encoder may assert this (interleaving packed
elements of different fields is not supported).

#### A.3 Impact on existing tests and fixtures

All existing packed fixture files must be regenerated to use the new per-line
format.  The `craft_a_matches_committed_fixtures` test (spec 0009) will catch
any divergence.

Existing round-trip tests that construct packed wire by hand
(`float_packed_noncanonical_nan_roundtrips`, etc.) continue to work — the
round-trip is wire→text→wire regardless of text format.

---

### B. Non-canonical NaN rendering

#### B.1 Current behaviour (recap)

Non-canonical NaN → value token `nan(0x7f800001)` (float) or
`nan(0xfff8000000000000)` (double).

Canonical NaN → value token `nan`.

#### B.2 Proposed change

Move the non-canonical NaN bit pattern from the **value token** into the
**annotation**:

```
floatOp: nan  #@ float = 22; nan_bits: 0x7f800001
```

For canonical NaN:

```
floatOp: nan  #@ float = 22
```

For a packed array with mixed NaNs:

```
floatPk: nan  #@ repeated float [packed=true] = 87
floatPk: nan  #@ repeated float [packed=true] = 87; nan_bits: 0x7f800001
floatPk: nan  #@ repeated float [packed=true] = 87; nan_bits: 0xffc00000
```

The value token is always bare `nan` — identical to protoc output.

The `nan_bits` modifier in the annotation carries the full 32-bit (float) or
64-bit (double) bit pattern, formatted as lower-case hex with `0x` prefix.

#### B.3 Encoder

The encoder parses `nan_bits: 0x…` from the annotation when the value is
`nan` and the field type is `float` or `double`, and uses the bit pattern
directly (with exponent forced to all-ones, as today).

When no `nan_bits` modifier is present, bare `nan` encodes as the canonical
quiet NaN (current behaviour).

#### B.4 Packed arrays

Per element: if a `nan_bits` modifier is present on the element's annotation
line, it applies to that element's encoding.

---

## Feasibility assessment

### A. Packed field rendering — feasibility

**Decoder side: moderate effort.**

The current `render_packed()` function produces a single line with `[...]`
syntax.  Replacing it with N individual scalar lines requires:
- Iterating over decoded elements one by one (already done internally).
- Calling `render_scalar()` for each element instead of accumulating into a
  bracket string.
- Distributing anomaly modifiers (tag_ohb, len_ohb on first element;
  per-element ohb on each respective element).

The `decode_packed_to_str()` function currently returns a `String`.  It
would need to be restructured to return an iterator or `Vec` of
`(value_str, modifiers)` pairs.  This is a moderate refactor of ~100 lines.

**Encoder side: significant effort.**

The current encoder processes one line at a time.  Recognising that N
consecutive lines form a single packed field requires lookahead or a
two-pass approach.

The encoder is currently line-driven (parses one field at a time in a loop).
To accumulate packed elements, it needs to:
1. Detect when a line has `[packed=true]` in its annotation.
2. Buffer elements until the field name changes or a non-packed line appears.
3. Emit the single wire LEN field at flush time.

This is a **significant structural change** to the encoder.  The encoder's
main loop currently has no lookahead.  An alternative is a two-pass approach:
collect all lines, group consecutive packed fields, then encode.

**Risk:** the encoder change touches the most complex part of the codebase.
Existing tests will catch regressions, but the refactor is non-trivial.

**Interaction with `INVALID_PACKED_RECORDS`:** the current single-line
fallback is unaffected — it stays as a single bytes-literal line.

**Empty packed fields:** currently emit `field: []`.  Under the new scheme,
an empty packed field produces no output.  The encoder must not try to emit
an empty packed LEN field when no elements are present.  Likely non-issue
since the encoder only writes what it reads.

### B. Non-canonical NaN in annotation — feasibility

**Low effort.**

This is essentially a revert of spec 0008's value-token approach, replacing
it with an annotation modifier.

**Decoder side:** in `format_float_protoc` / `format_double_protoc`, change
the non-canonical NaN branch to always return `"nan"`, and pass the bit
pattern up to the annotation layer instead.  The `render_scalar` call site
gains an optional `nan_bits` argument.

**Encoder side:** in `parse_num`, bare `nan` always produces canonical NaN.
The annotation parser gains a `nan_bits` key whose value overrides the bit
pattern.

**Packed arrays:** the per-element annotation already carries modifiers
(see A.1 above).  A `nan_bits` modifier per element fits naturally.

**Key concern previously identified:** the annotation approach does not work
for packed arrays when they are rendered as a single `[…]` line — there is
no per-element annotation slot.  **This concern goes away** if A (per-line
packed rendering) is implemented first, since each element then has its own
annotation.

**Conclusion:** B depends on A.  B alone (without A) reintroduces the
packed NaN problem.  The two changes must be implemented together.

---

## Summary

| Change | Compatibility impact | Effort | Depends on |
|--------|---------------------|--------|------------|
| A. Per-line packed rendering | Restores protoc compatibility for packed fields | Moderate (decoder) + Significant (encoder) | — |
| B. NaN bits in annotation | Restores protoc compatibility for canonical NaN; no impact on canonical input | Low | A |

**Recommended order:** implement A first, then B.  Neither is a blocker for
other work; both can be deferred until the test infrastructure from spec 0009
is in place, since that suite will make regressions visible immediately.

---

## Open questions

1. **Annotation on every element vs. first element only.**  Emitting the full
   field declaration on every line is verbose but unambiguous.  Emitting it
   only on the first element is more compact but requires the encoder to
   track "current packed field" state across lines.  Recommendation: emit on
   every element for simplicity; revisit if output verbosity is a concern.

2. **Empty packed fields.**  Should an empty packed field (`tag + len=0`)
   produce a comment-only line (`#@ repeated int32 [packed=true] = 85`) for
   discoverability, or silently produce no output?  protoc produces no
   output.  Recommendation: match protoc (no output).

3. **Interaction with `--no-annotations` mode.**  Without annotations, packed
   fields become indistinguishable from non-packed repeated fields in the
   text output.  The encoder has no way to know whether to emit a packed or
   non-packed wire encoding.  This is an existing limitation (not introduced
   by this spec) and is acceptable: without annotations, round-trip lossless-
   ness is only guaranteed for canonical input, and canonical packed fields
   re-encode correctly as packed if the schema says `[packed=true]`.

---

## References

- `prototext-core/src/serialize/render_text/packed.rs` — current packed renderer
- `prototext-core/src/serialize/render_text/helpers.rs` — `render_scalar`,
  `AnnWriter`
- `prototext-core/src/serialize/encode_text/mod.rs` — encoder main loop,
  `encode_packed_array_line`
- `prototext-core/src/serialize/common.rs` — `format_float_protoc`,
  `format_double_protoc`
- `prototext/fixtures/cases/test_varint_packed.pb` — current packed fixture
- `prototext/fixtures/cases/canonical_repeated.pb` — protoc repeated format
  reference
- docs/specs/0008-nan-encoding.md — NaN encoding (to be revised by this spec)
- docs/specs/0009-protocraft-and-e2e-tests.md — test infrastructure
