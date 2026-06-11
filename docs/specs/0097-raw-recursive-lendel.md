<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0097 — Recursive LEN-delimited decoding for unknown fields

**Status:** draft
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

## Non-goals

- Changing behavior for *known* fields (a field declared `bytes` stays
  bytes; `string` stays string; nested message stays nested message).
- Introducing a new CLI flag for this behavior.
- Changing the type-inference path in any way.

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

### S3 — `decode_len_field` applies the three-step cascade for unknown fields

The "unknown field" condition is: `field_schema` is `None`.

```
if field_schema is None:
    // Step 1: probe as message
    (nested, next_pos, _, malformities) = parse_message(data, 0, None, None, ...)
    if malformities == 0 and next_pos == data.len():
        field.content = MessageVal(nested)
        return

    // Step 2: try UTF-8 string
    if is_valid_utf8(data):
        field.content = StringVal(data)
        return

    // Step 3: bytes
    field.content = WireBytes(data)
```

This replaces the current single-line fallback:

```rust
field.content = ProtoTextContent::WireBytes(data.to_vec());
```

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
| `prototext-core/src/decoder/types.rs` | None |
| `prototext-core/src/decoder/mod.rs` | `parse_message` returns `u32` malformity count |
| `prototext-core/src/decoder/packed.rs` | `decode_len_field`: replace single-line bytes fallback with three-step cascade |
| `prototext-core/src/serialize/mod.rs` | None |
| `prototext/src/run.rs` | None |
| All `parse_message` call sites | Updated to ignore the new `u32` return value |
