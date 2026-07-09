<!-- SPDX-FileCopyrightText: 2025-2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis) -->
<!-- SPDX-FileCopyrightText: 2025-2026 THALES CLOUD SECURISE SAS -->
<!--
SPDX-License-Identifier: MIT
-->

# prototext design

`prototext` is a lossless, bidirectional converter between binary protobuf wire
format and human-readable annotated text.  Its central guarantee:

> **binary → text → binary is byte-for-byte identical for any input**, including
> malformed, non-canonical, and schema-unknown messages.

---

## Crate layout

```
prototext-core/          — core library (no CLI dependency)
  src/
    lib.rs               — public API: render_as_text, render_as_bytes, parse_schema
    schema.rs            — ParsedSchema: prost-reflect wrapper
    serialize/
      common/            — value formatting, escaping, numeric codecs
      render_text/       — binary → annotated text (single-pass)
      encode_text/       — annotated text → binary (placeholder strategy)
    helpers/
      varint.rs          — parse_varint / write_varint_ohb
      wire.rs            — wire-type constants, write_tag
      codecs.rs          — decode_int32, decode_sint64, decode_fixed64, …

prototext/               — CLI binary and test infrastructure
  src/
    lib.rs               — Cli struct (clap), EMBEDDED_DESCRIPTOR
    run.rs               — run(), load_schema(), process()
    inputs.rs            — expand_path: glob/directory/file expansion
    main.rs              — entry point with shell completion
    protocraft/
      mod.rs             — test-only DSL: Tag, Integer, Message builder, macros
      craft_a.rs         — fixture definitions (ALL_FIXTURES registry)
  tests/
    e2e.rs               — end-to-end roundtrip tests
    roundtrip.rs         — unit roundtrip tests
    protocraft.rs        — harness=false binary: emit fixture bytes to stdout
```

---

## Render path: binary → text (single-pass)

**Entry**: `render_text::decode_and_render(bytes, schema, annotations, indent)`
→ `Vec<u8>`

This path does **not** materialise a `ProtoTextMessage`.  It parses wire bytes
and writes text output in a single recursive pass, avoiding the two-pass overhead
of decode-then-walk.

Output header:

```
#@ prototext: protoc
```

Per-field output (with annotations):

```
field_name: value   #@ [group;] wire_type; [field_decl;] [modifier;]*
```

- **Field name**: schema field name if known; numeric key otherwise.
- **Value**: formatted by type (`format_int32_protoc`, `format_double_protoc`,
  `escape_string_into`, etc.)
- **Annotation**: wire type, optional field declaration (`optional int32 = 1`),
  optional modifiers (`tag_ohb: 2`, `len_ohb: 1`, `MISSING: 3`, …)

Nested messages and groups open a `{` line and close with `}`, with indentation
tracking via an `RAII LevelGuard`.

Thread-locals hold render state: `ANNOTATIONS` (bool), `INDENT_SIZE` (usize),
`LEVEL` (usize), `CBL_START` (bool — close-brace-on-last).

Extension fields are resolved alongside regular fields; their display name is
`[pkg.ext_name]` (bracketed fully-qualified).

---

## Encode path: text → binary (placeholder strategy)

**Entry**: `encode_text::encode_text_to_binary(text: &[u8]) → Vec<u8>`

Input must begin with `#@ prototext:`.  Each field occupies exactly one line
(scalar) or a matched `{` / `}` pair (message / group).

### Annotation parsing

Each line is split at the last `   #@ ` separator.  The annotation is parsed
into an `Ann<'a>` struct:
- `wire_type: &str` — `"varint"`, `"bytes"`, `"fixed64"`, `"fixed32"`, `"group"`
- `field_number: Option<u64>`
- Field declaration: type name, packed flag, field number
- Modifiers: `tag_ohb`, `val_ohb`, `len_ohb`, `pack_size`, `nan_bits`,
  `MISSING`, `OPEN_GROUP`, `END_MISMATCH`, …

### Scalar fields

Dispatch by `ann.field_type`:
- Varint kinds: parse the text value → zigzag-encode (`sint32`/`sint64`) or
  direct → `write_varint_ohb(value, ann.val_ohb)`.
- Fixed32 / Fixed64: little-endian byte write.
- String / bytes: unescape → length-prefix → payload.
- Enums: use `ann.enum_scalar_value` if present (handles `ENUM_UNKNOWN`).
- NaN: `ann.nan_bits` overrides the parsed float value.

### Nested messages — placeholder strategy (Strategy C2)

The protobuf wire format requires the byte length of a nested message **before**
its content.  Since the length is not known when the opening `{` line is
processed, a placeholder is written:

```
┌──────────┬──────────────────┬──────────────────────────────┐
│ waste(1) │ next_ph (5 bytes)│ varint_room (5 + ohb bytes)  │
└──────────┴──────────────────┴──────────────────────────────┘
```

On the matching `}` line:
1. The child byte length is encoded as a varint (`k` bytes, 1 ≤ k ≤ 5).
2. Written flush-right inside the varint_room area.
3. `waste = placeholder_size - k` recorded in byte 0.
4. The placeholder is linked into a forward linked list via `next_ph`.

After the full message is serialised, a single compaction pass walks the
linked list left-to-right, copying real data over waste bytes, to produce a
contiguous output.  Total cost: O(n) in output size; each byte moved at most once.

### Groups

Groups use `START_GROUP` (wire type 3) and `END_GROUP` (wire type 4) tags instead
of length prefixes.  No placeholder is needed.  Anomaly modifiers (`OPEN_GROUP`,
`END_MISMATCH`, `end_tag_ohb`) are applied from the stack frame when the `}` line
is processed.

---

## Annotation format

The annotation comment preserves all wire-level information required for
exact re-encoding.  It follows the field value after `  #@ `.

```
field_name: value   #@ [group;] wire_type; [field_decl;] [modifier;]*
```

**Wire types**: `varint`, `bytes`, `fixed64`, `fixed32`, `group`

**Field declaration** (when schema is present):
```
optional int32 = 1
repeated string = 5
optional MyMsg = 3
optional Color(0) = 2        ← enum; numeric value overrides text on encode
repeated int32 [packed=true] = 4
```

**Modifiers**:

| Modifier | Meaning |
|---|---|
| `tag_ohb: N` | N overhanging bytes on the field tag varint |
| `val_ohb: N` | N overhanging bytes on the varint value |
| `len_ohb: N` | N overhanging bytes on the length varint |
| `end_tag_ohb: N` | N overhanging bytes on the END_GROUP tag |
| `pack_size: N` | number of packed elements on this line |
| `packed_ohb: [N, ...]` | per-element varint overhangs |
| `nan_bits: 0xHHHH` | non-canonical NaN bit pattern |
| `MISSING: N` | N bytes truncated from payload |
| `OPEN_GROUP` | no END_GROUP encountered |
| `END_MISMATCH: N` | END_GROUP had field number N (not the opening field) |
| `TAG_OOR` | field number is out of range (0 or > 2²⁹−1) |
| `ETAG_OOR` | END_GROUP field number out of range |
| `TYPE_MISMATCH` | varint value out of range for declared proto2 type |
| `ENUM_UNKNOWN` | enum value not in schema (informational only) |

Flags `TAG_OOR`, `ETAG_OOR`, `TYPE_MISMATCH`, `ENUM_UNKNOWN` are informational
and do not affect re-encoding.  All others are load-bearing.

---

## Schema integration

Schema is optional.  Without a schema, all fields are rendered with wire types
and numeric keys.

`ParsedSchema` wraps a prost-reflect `DescriptorPool`:
- `pool.get_message_by_name(fqn)` → `MessageDescriptor`
- `MessageDescriptor.get_field(n)` / `get_extension(n)` → `FieldDescriptor`
- `FieldDescriptor.kind()` → `Kind::Int32`, `Kind::Message(m)`,
  `Kind::Enum(e)`, …
- `FieldDescriptor.is_packed()` → packed repeated detection

The binary `EMBEDDED_DESCRIPTOR` (compiled `google/protobuf/descriptor.proto`)
is baked into the binary via `include_bytes!`, enabling out-of-the-box decoding
of `google.protobuf.*` types without an external schema file.

---

## CLI

```
prototext (-d | -e)
          [--descriptor-set FILE] [--type MSG]
          [--no-annotations]
          [--output FILE | --output-root DIR | --in-place]
          [--input-root DIR]
          [PATHS...]
```

`run.rs` handles three input modes:

1. **stdin** — single message from stdin; write to stdout or `--output`.
2. **Single file** — one path argument; write to stdout or `--output`.
3. **Batch** — multiple paths (glob/directory expansion); requires
   `--in-place` or `--output-root`.  Uses sponge semantics: all input files
   are read before any output file is written, so in-place conversion is safe
   even when input and output overlap.

Collision detection runs eagerly before any output is written.

---

## Protocraft (test infrastructure)

`protocraft` is a test-only DSL for constructing protobuf wire bytes
programmatically, including non-canonical and malformed encodings.

### Core types

```rust
Tag {
  field / field_num,        // field specifier
  wire_type: u8,            // u8::MAX = use method default
  ohb: u8,                  // overhanging bytes on tag varint
  length: usize,            // usize::MAX = use actual payload length
  length_ohb: u8,
}

Integer {
  unsigned: u64,            // raw bit pattern
  signed: i64,              // sign-extended
  zigzag: i64,              // zigzag-encoded
  short: bool,              // truncate to 32-bit (int32/enum)
  ohb: u8,
}

RawData<'a>(&'a [u8])       // verbatim bytes, bypasses encoding
```

### Fixture macro

```rust
fixture!(name, descriptor_expr;
    uint64!("fieldName", 42),
    int32!("count", -1),
    string!("label", "hello"),
    message!("nested"; ...),
    packed_varints!("ids", [1, 2, 3]),
    raw!(b"\x82\x06\x00"),
);
// expands to: pub fn name() -> Vec<u8> { ... }
```

All fixtures are registered in `ALL_FIXTURES: &[(&str, fn() -> Vec<u8>)]` and
exercised by the e2e roundtrip tests.

The `protocraft` test binary (harness=false) emits a named fixture's bytes to
stdout, enabling manual inspection:

```bash
cargo test --test protocraft -- hidden | prototext -d --descriptor-set <schema> --type SchemaHidden
cargo test --test protocraft -- hidden | protoc --decode=SchemaHidden fixtures/schemas/knife.proto
```

---

## Key design decisions

### Why single-pass render?

`decode_and_render` writes text directly while parsing binary through a `Sink`
trait — it never materialises an intermediate tree. This halves the number of
heap allocations for the text output path and avoids a second traversal.
`render_as_bytes` does not decode binary at all: it either passes raw binary
input through unchanged, or (when the input already carries the `#@
prototext:` text header) runs it through `encode_text::encode_text_to_binary`,
whose placeholder strategy is described below.

### Why the placeholder strategy for encode?

Strategy C2 (variable-size placeholder + forward compaction) avoids:
- Per-frame `Vec<u8>` allocation (Strategy A: copies child bytes into parent)
- `memmove` of the entire remaining buffer on close (Strategy B: 1-byte sentinel)
- Non-minimal varints in the output (Strategy C1: fixed 5-byte placeholder)

The compaction pass is O(n) total and moves each byte at most once.

### Why `usize::MAX` as a sentinel for `Tag.length`?

`Tag.length = usize::MAX` means "use the natural payload length".  An explicit
`Option<usize>` would be cleaner in isolation, but the intent in the source code
is that the length field is simply not set — `usize::MAX` communicates "absent"
without boxing.

### Why per-kind varint traits?

`IntoInt32`, `IntoInt64`, `IntoUint32`, `IntoUint64`, `IntoBool`, `IntoEnum`
are each implemented for exactly one primitive type, `Integer` (for ohb
overrides), and `RawData` (escape hatch).  This makes bare integer literals
unambiguous at call sites — `int32!("f", -1)` infers `-1` as `i32` without
requiring a `_i32` suffix.
