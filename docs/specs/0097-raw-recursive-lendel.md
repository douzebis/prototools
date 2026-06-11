<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0097 — Recursive LEN-delimited decoding for unknown fields

**Status:** implemented
**Implemented in:** 2026-06-11
**Amended:** 2026-06-11
**App:** prototext, prototext-core

---

## Background

`prototext decode` currently renders every unknown LEN-delimited field as
raw bytes, regardless of whether the payload is itself a valid protobuf
message.  `protoc --decode_raw` behaves differently: it attempts to parse
each LEN payload as a nested message and only falls back to bytes if the
parse is structurally invalid.

The open question at the bottom of spec 0088 anticipated this improvement.

---

## Goals

1. For every unknown LEN-delimited field (no schema, or field number
   absent from the schema), apply a three-step discovery heuristic:
   (1) try structural parse as a nested message, (2) fall back to UTF-8
   string, (3) fall back to bytes.
2. The recursion is unbounded in depth.
3. The type-inference path (`list-schemas`, auto-infer scoring) is
   unaffected.
4. Lossless round-trip is preserved.
5. When no descriptor is active, all fields are unknown — they must
   always be rendered regardless of `--no-annotations`.  This decouples
   `--raw` from `--no-annotations`: `--raw --no-annotations` produces
   field structure without wire-type comments.

## Non-goals

- Changing behavior for *known* fields (a field declared `bytes` stays
  bytes; `string` stays string; nested message stays nested message).
- Introducing a new CLI flag for this behavior.
- Changing the type-inference path in any way.
- Changing behavior for known fields under `--no-annotations` (they
  continue to be suppressed as before).

---

## Observations

### O1 — `--raw` and `schema = None` converge

With the heuristic applied unconditionally to all unknown LEN fields:

- **No descriptor**: every field is unknown → heuristic applies
  everywhere.
- **With descriptor + `--raw`**: known fields rendered per schema,
  unknown fields get the heuristic — identical to having no descriptor
  for those fields.
- **With descriptor, no `--raw`**: same as above.

`--raw` therefore remains equivalent to passing no descriptor, as it is
today.  No new `raw_recursive` flag is needed.

### O2 — Validity test without a separate pre-scan

A dedicated `looks_like_message(data) -> bool` pre-scan would traverse
`data` twice.  It is more efficient to have `parse_message` itself return
a malformity count alongside the decoded `ProtoTextMessage`.  A non-zero
count means "at least one field was structurally invalid"; the caller
discards the result and falls back to the next step.

The malformity count covers:

- Invalid wire tag type (`InvalidTagType`)
- Invalid varint encoding (`InvalidVarint`)
- Invalid/truncated fixed field (`InvalidFixed32`, `InvalidFixed64`)
- Truncated LEN field (`TruncatedBytes`, `InvalidBytesLength`)
- Unexpected END_GROUP outside a group (`InvalidGroupEnd`)
- Unterminated group — START_GROUP with no matching END_GROUP (`open_ended_group`)
- Bytes remaining after the last field (`next_pos < data.len()`)

Non-canonical bytes (overlong varints, out-of-range field numbers) are
**not** malformities — they are valid wire format and must not cause
fallback.

### O3 — Impact on `parse_message` signature

`parse_message` currently returns
`(ProtoTextMessage, usize, Option<WiretagResult>)`.
Adding a malformity count changes it to
`(ProtoTextMessage, usize, Option<WiretagResult>, u32)`.

All existing call sites are updated to ignore the new field.  The count
need not be exact; any positive value means "malformed."

### O4 — Type-inference path must not be affected

The type-inference path calls `score_all` on raw binary bytes — it never
calls `parse_message` or `decode_len_field` for scoring purposes.
The heuristic lives entirely inside the decode/render path and cannot
reach the scorer.  No special guard is needed; the separation is
structural.

### O5 — `--no-annotations` and schema presence

The rule "unknown fields are suppressed under `--no-annotations`" only makes
sense when a schema is present.  Without a schema every field is unknown, and
suppressing them all produces empty output — useless and surprising.

The correct rule is: **`--no-annotations` suppresses wire-type comments, not
field content**.  When no descriptor is active at a given nesting level, all
fields at that level must be rendered regardless of the annotations flag.

`schema_present` is derived from `all_schemas.is_some()` at each nesting
level and passed explicitly to `render_varint_field` and `render_scalar`.
`render_len_field` computes it locally from `all_schemas.is_some()`.
No thread-local is used — the value correctly tracks schema presence per
nesting level, not just at the render root.

This also decouples `--raw` from `--no-annotations`.  Previously `run.rs`
forced `annotations = true` in raw mode to avoid empty output.  With this
fix the forced override is removed: the renderer handles it structurally.

---

## Specification

### S1 — `parse_message` returns a malformity count

Change the return type of `parse_message` from

```rust
(ProtoTextMessage, usize, Option<WiretagResult>)
```

to

```rust
(ProtoTextMessage, usize, Option<WiretagResult>, u32)
```

where the `u32` is the number of malformed fields encountered (0 = clean).

Incremented once per field producing any of: `InvalidTagType`,
`InvalidVarint`, `InvalidFixed32`, `InvalidFixed64`, `InvalidBytesLength`,
`TruncatedBytes`, `InvalidGroupEnd`.

For recursive LEN probes the inner malformity count is **not** propagated
to the outer count.  Each level makes its own fallback decision
independently.

### S2 — Trailing bytes count as a malformity

When `parse_message` is invoked for a LEN payload probe, if
`next_pos < data.len()` after the parse returns, the probe is considered
failed (treat as malformed).

### S3 — Three-step cascade for unknown LEN fields

The "unknown field" condition is: `field_schema` is `None`.

The cascade is implemented in two places:

- **`render_len_field`** (in `prototext-core/src/serialize/render_text/helpers/len_field.rs`):
  the direct rendering path used by `prototext decode` (both `--raw` and schema-aware).
- **`decode_len_field`** (in `prototext-core/src/decoder/packed.rs`):
  the decoder path used for the lossless `ProtoTextMessage` tree (encode round-trip).

Both call `parse_message` directly with an empty schema for the probe in Step 1.
Using a separate probe call ensures that rendering failures inside a nested
message do not taint the malformity count of the enclosing message.

```
// Step 1: probe as message
(_, next_pos, _, malformities) = parse_message(data, 0, None, None, empty_schema, false)
if malformities == 0 and next_pos == data.len():
    render/store as nested message
    return

// Step 2: try UTF-8 string
if is_valid_utf8(data):
    render/store as string
    return

// Step 3: bytes
render/store as raw bytes
```

### S5 — Unknown fields always rendered when no descriptor is active

In each renderer (`render_varint_field`, `render_scalar`, `render_len_field`),
the `!annotations` suppression for unknown/wire fields is conditional on
`schema_present` being true.  `schema_present` is derived from
`all_schemas.is_some()` at the current nesting level and passed as an explicit
parameter — not via a thread-local — so it correctly reflects whether a
descriptor is active at each level of nesting.

In `run.rs`, the `let annotations = true;` override in the `--raw` branch is
removed.  The user-supplied `!no_annotations` value is passed through unchanged.

Effect:
- `prototext decode --raw file.pb` → field structure with wire-type comments
- `prototext decode --raw --no-annotations file.pb` → field structure, no comments
- `prototext decode --descriptor-set d.pb --no-annotations file.pb` → known
  fields only; unknown fields suppressed (unchanged behavior)

### S6 — E2E test: unknown LEN field decoded as nested message

A test `unknown_len_decoded_as_nested_message` in `prototext/tests/e2e.rs` verifies
the cascade against the knife schema (`SwissArmyKnife`).

The hand-crafted wire payload (16 bytes) contains:

- Field 25 (`int32Op`, known), varint 42.
- Field 9001 (unknown), LEN, whose payload is a valid protobuf message:
  field 1 varint 7 + field 2 string `"hello"`.

```
\xc8\x01          — tag: field 25, wire type 0
\x2a              — value: 42
\xca\xb2\x04      — tag: field 9001, wire type 2
\x09              — length: 9
\x08\x07          — inner field 1, varint 7
\x12\x05hello     — inner field 2, string "hello"
```

Assertions:

1. The decoded text contains `9001 {` — confirming the unknown LEN field
   is rendered as a nested message, not raw bytes.
2. The binary round-trip is lossless: `encode(decode(wire)) == wire`.

### S4 — Round-trip

The output must round-trip through `prototext encode` to the original
bytes.

- `MessageVal` nested messages use the existing brace format, already
  handled by the encoder.
- `StringVal` uses the existing quoted-string format, already handled.
- `WireBytes` is unchanged.

No changes to the encoder are required.

---

## Summary of changes

| File | Change |
|---|---|
| `prototext-core/src/decoder/mod.rs` | `parse_message` returns `u32` malformity count; OPEN_GROUP counts as malformity |
| `prototext-core/src/decoder/packed.rs` | `decode_len_field`: three-step cascade for unknown fields |
| `prototext-core/src/serialize/render_text/mod.rs` | None (no new thread-locals needed) |
| `prototext-core/src/serialize/render_text/varint.rs` | `render_varint_field`: add `schema_present` param; condition suppression on it |
| `prototext-core/src/serialize/render_text/helpers/scalar.rs` | `ScalarCtx`: add `schema_present` field; condition suppression on it |
| `prototext-core/src/serialize/render_text/helpers/len_field.rs` | Three-step cascade for unknown fields; condition suppression on `all_schemas.is_some()` |
| `prototext/src/lib.rs` | Remove broken `conflicts_with = "output_root"` from `in_place` in `Decode`/`Encode` |
| `prototext/src/run.rs` | Add `validate_not_in_place_and_output_root`; remove forced `annotations = true` in `--raw` branch |
| `scoring-graph/src/score/load.rs` | `from_static_bytes`: copy into `AlignedVec` to satisfy rkyv debug-mode alignment assert |
| `prototext/tests/roundtrip.rs` | Remove stale "test currently FAILS" comment |
| `prototext/tests/e2e.rs` | Add `unknown_len_decoded_as_nested_message` test (spec S6) |
| All `parse_message` call sites | Updated to ignore the new `u32` return value |
