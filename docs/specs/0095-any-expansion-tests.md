<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0095 — `google.protobuf.Any` expansion tests

**Status:** implemented
**Implemented in:** 2026-05-31
**Refs:** `prototext/tests/roundtrip.rs` §10
**App:** prototext

---

## Background

The `render_as_text` function in `prototext-core` has an `expand_any` option
(spec 0089) that, when set, detects `google.protobuf.Any` fields and renders
them as:

```
payload {  #@ Any = 1
 type_url: "type.googleapis.com/acme.Payload"  #@ string = 1
 value {  #@ Payload = 2
  label: "hello"  #@ string = 1
 }
}
```

rather than as a raw LEN field with opaque bytes.

Despite `expand_any: true` appearing on virtually every test case in
`prototext/tests/roundtrip.rs`, no test fixture actually exercised the `Any`
expansion code path.  This spec adds that coverage.

---

## Goals

1. Add a reusable `any_schema()` helper that builds a `ParsedSchema`
   containing `google.protobuf.Any`, `acme.Container`, and `acme.Payload`.
2. Add a reusable `any_wire_bytes()` helper that produces the canonical wire
   encoding of `Container { payload: Any { … Payload { label: "hello" } … } }`.
3. Add six tests in `prototext/tests/roundtrip.rs`:
   - `any_field_expands_type_url_and_value` — substring checks for expansion.
   - `any_field_golden_annotated_output` — exact golden `#@` string comparison.
   - `any_field_no_expand_renders_value_as_bytes` — `expand_any: false` leaves
     value as raw bytes, not a nested block.
   - `any_field_roundtrip` — byte-for-byte round-trip.
   - `any_field_unresolvable_type_url_renders_value_as_bytes` — fallback when
     `type_url` cannot be resolved in the pool.
   - `any_field_value_before_type_url_renders_as_raw_len` — fallback when
     `value` appears before `type_url` in the wire encoding.

---

## Non-goals

- A golden `#@` string comparison (noted as a gap below; deferred).
- Testing `Any` inside a repeated field.
- Testing `Any` where `type_url` references a type not in the schema pool
  (fallback behaviour).
- Testing `Any` where `value` appears before `type_url` in the wire encoding
  (fallback behaviour).

---

## Specification

### §1 — Fixture: `any_schema()`

`parse_schema()` takes a `FileDescriptorSet` blob.  Building a schema that
includes `google.protobuf.Any` requires that `google/protobuf/any.proto` be
present in the `DescriptorPool` before the custom file that imports it.

`descriptor.pb` (compiled by `build.rs` into `OUT_DIR`) contains only
`google/protobuf/descriptor.proto` — `any.proto` is not included.  The helper
therefore:

1. Loads `descriptor.pb` via `DescriptorPool::decode` to seed the pool with
   `descriptor.proto` (so that the pool's internal file registry accepts
   further additions).
2. Adds a minimal `google/protobuf/any.proto` `FileDescriptorProto` by hand —
   `google.protobuf.Any` has exactly two fields: `type_url` (TYPE_STRING,
   field 1) and `value` (TYPE_BYTES, field 2).  This avoids needing a
   compiled `any.pb` in `OUT_DIR`.
3. Adds `acme.proto` containing:
   - `message Payload { optional string label = 1; }`
   - `message Container { optional google.protobuf.Any payload = 1; }`

   with `dependency: ["google/protobuf/any.proto"]`.
4. Calls `schema_from_pool(pool, "acme.Container")`.

### §2 — Fixture: `any_wire_bytes()`

Constructs the wire encoding manually, step by step:

```
Payload { label: "hello" }:
  [0x0a, 0x05, 'h', 'e', 'l', 'l', 'o']          (field 1 LEN, 5 bytes)

Any { type_url: "type.googleapis.com/acme.Payload",
      value:    <payload_bytes> }:
  [0x0a, 0x20, <32 bytes of type_url>]             (field 1 LEN)
  [0x12, 0x07, <payload_bytes>]                    (field 2 LEN)

Container { payload: <any_bytes> }:
  [0x0a, <len>, <any_bytes>]                       (field 1 LEN)
```

No binary files are committed; the bytes are synthesised at test runtime.

### §3 — Tests

#### TC-1: `any_field_expands_type_url_and_value`

Substring checks: output contains `type_url:`,
`type.googleapis.com/acme.Payload`, `value {`, and `hello`.

#### TC-1b: `any_field_golden_annotated_output`

Exact golden comparison against the full expected output:

```
#@ prototext: protoc
payload {  #@ Any = 1
 type_url: "type.googleapis.com/acme.Payload"  #@ string = 1
 value {  #@ Payload = 2
  label: "hello"  #@ string = 1
 }
}
```

Catches regressions in indentation, annotation format, or field ordering.

#### TC-2: `any_field_no_expand_renders_value_as_bytes`

`expand_any: false`.  With a schema, `Any` fields are still rendered (the
schema knows `type_url` and `value`), but `value` is a `bytes` field rendered
as a quoted byte string, not a `{ }` block.  Asserts `value {` absent,
`value:` present.

#### TC-3: `any_field_roundtrip`

`render_as_text` → `render_as_bytes`.  Asserts byte-for-byte equality with
original `any_wire_bytes()`.

#### TC-4: `any_field_unresolvable_type_url_renders_value_as_bytes`

Schema does NOT include `acme.Payload`.  The renderer partially expands: it
still emits `type_url:` and `value:` (because it knows the `Any` field
structure), but `value` is rendered as raw bytes rather than a nested block
(because the payload type cannot be resolved).  Asserts `value {` absent,
`type_url:` and `value:` present.

#### TC-5: `any_field_value_before_type_url_renders_as_raw_len`

Wire bytes have field 2 (`value`) before field 1 (`type_url`).
`scan_any_fields` returns `None` in this case; the whole `Any` field falls
back to raw LEN rendering.  Asserts `value {` absent.

---

## Gaps and follow-up work

None — all planned tests implemented.
