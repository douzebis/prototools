<!--
SPDX-FileCopyrightText: 2025 - 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
SPDX-FileCopyrightText: 2025 - 2026 THALES CLOUD SECURISE SAS

SPDX-License-Identifier: MIT
-->

# Annotation Format

This document describes the text representation emitted by `prototext -d`
(decode) and consumed by `prototext -e` (encode).

The format is a superset of the
[protobuf text format](https://protobuf.dev/reference/protobuf/textformat-spec/)
as produced by `protoc --decode`.  Every field line carries an inline
annotation comment (`#@`) that encodes enough information to reconstruct
the exact binary bytes on re-encoding.

---

## Human-readable description

### What a line looks like

Every field occupies one line (or, for nested messages/groups, an opening brace
line plus content lines plus a closing brace line).  The general layout is:

```
{indent}{field_name}: {value}  #@ {annotation}
```

For nested fields:

```
{indent}{field_name} {  #@ {annotation}
{indent}  {child fields…}
{indent}}
```

The two spaces before `#@` are the separator between value and annotation.
The annotation runs to end of line.

The file starts with a header line:

```
#@ prototext: protoc
```

### The annotation comment

The annotation encodes three kinds of information, always in this left-to-right
order:

```
#@ [wire_type;] [modifier: value;]* [label type = field_number;]
```

Each token ends with `;`.  All three parts are optional.

#### Part 1 — wire type

A keyword naming the binary wire type of the field as it appeared in the
original protobuf bytes.  Emitted only when the wire type is ambiguous
(unknown fields) or when it conflicts with the schema (invalid / mismatched
fields).  Omitted for known, well-typed fields because the wire type is
unambiguously implied by the proto type (`double` → always FIXED64, `int32`
→ always VARINT, etc.).

Possible values: `VARINT`, `FIXED64`, `BYTES`, `FIXED32`, `GROUP`,
`INVALID_TAG_TYPE`, `INVALID_VARINT`, `INVALID_FIXED64`, `INVALID_FIXED32`,
`INVALID_BYTES_LENGTH`, `TRUNCATED_BYTES`, `INVALID_PACKED_RECORDS`,
`INVALID_STRING`, `INVALID_GROUP_END`.

#### Part 2 — modifiers

Zero or more `name: value;` pairs describing non-canonical or invalid aspects
of the binary encoding.  See the modifier reference table below.

#### Part 3 — field declaration

Describes the schema entry for the field.  Format: `label type = field_number;`

- **label**: `optional`, `repeated`, or `required`.
- **type**: protobuf scalar type (`int32`, `string`, …) or message/group/enum
  name for compound types.  Packed repeated fields append ` [packed=true]`.
- **field_number**: the field's tag number in the `.proto` file.

Omitted for unknown fields (no schema match) and for mismatched fields (schema
type conflicts with wire type).  Emitted for invalid fields so schema context
is preserved.

For enum fields the type takes the form `EnumTypeName(numeric)` where `numeric`
is the raw wire value.  This ensures the round-trip encoder can reconstruct
the exact bytes without a schema lookup:

```
type: TYPE_STRING  #@ Type(9) = 5
```

### Modifier reference table

| Name | Value type | Severity | Meaning |
|---|---|---|---|
| `tag_overhang_count` | integer | yellow | Tag varint uses N extra continuation bytes (non-minimal encoding) |
| `tag_is_out_of_range` | `true` | red | Tag field number is 0 or ≥ 2²⁹ (reserved / invalid range) |
| `value_overhang_count` | integer | yellow | Value varint uses N extra continuation bytes |
| `length_overhang_count` | integer | yellow | Length-prefix varint uses N extra continuation bytes |
| `missing_bytes_count` | integer | red | Declared length exceeded available bytes; N bytes are missing |
| `mismatched_group_end` | integer | red | END_GROUP tag carries field number N instead of the opening tag's number |
| `open_ended_group` | `true` | red | GROUP field has no END_GROUP tag before end of buffer |
| `end_tag_overhang_count` | integer | yellow | END_GROUP tag varint uses N extra continuation bytes |
| `end_tag_is_out_of_range` | `true` | red | END_GROUP tag field number is 0 or ≥ 2²⁹ |
| `proto2_has_type_mismatch` | `true` | red | Wire type is VARINT but value is out of range for the declared proto type |
| `proto2_neg_int32_truncated` | `true` | yellow | Negative int32/enum encoded as 5-byte truncated varint (non-canonical) |
| `records_overhung_count` | `[N, N, …]` | yellow | Per-element overhang byte counts for packed repeated varints |
| `records_neg_int32_truncated` | `[bool, …]` | yellow | Per-element truncation flags for packed int32/enum |
| `ENUM_UNKNOWN` | (flag, no value) | yellow | Enum value is not in the schema's value table |

Yellow = non-canonical but losslessly recoverable.
Red = data integrity issue.

### Annotated examples

#### 1. Known scalar field

```
doubleOp: 2.718  #@ optional double = 21;
```

- LHS `doubleOp`: field name from schema.
- Value `2.718`: decoded float64.
- Annotation: `optional double = 21;` — label, proto type, tag number.
  Wire type (FIXED64) is omitted: unambiguously implied by `double`.

#### 2. Packed repeated field

```
floatRp: [1.5, 2.5, 3.5]  #@ repeated float [packed=true] = 42;
```

Bracket notation for the packed array.  `[packed=true]` indicates packed
wire encoding.

#### 3. Nested message

```
messageOp {  #@ optional SwissArmyKnife = 31;
  int32Op: 200  #@ optional int32 = 25;
}
```

Opening brace line carries the annotation.

#### 4. Group

```
GroupOp {  #@ GROUP; optional GroupOp = 30;
  uint64Op: 111  #@ optional uint64 = 130;
}
```

Wire type `GROUP` is always emitted for group fields (structurally distinct
from messages; must be preserved for re-encoding).

#### 5. Unknown field (no schema match)

```
999: 12345  #@ VARINT;
```

Field number on the LHS (no name available).  Wire type always emitted so
the encoder can reproduce the exact bytes.

#### 6. Non-canonical tag encoding (overhang)

```
stringOp: "hello"  #@ optional string = 29; tag_overhang_count: 2;
```

The tag varint was encoded with 2 extra `0x80` continuation bytes.  The value
is structurally valid; the encoding is just non-minimal.

#### 7. Invalid string (non-UTF-8 bytes in a declared string field)

```
10: "\342\200\224"  #@ INVALID_STRING; optional string = 10;
```

Field number on LHS (schema name not used because the value failed
validation).  Field declaration still emitted so schema context is available.

#### 8. Truncated bytes

```
99: "\001\002"  #@ TRUNCATED_BYTES; missing_bytes_count: 5; optional bytes = 99;
```

Length prefix declared 7 bytes but only 2 were available.

#### 9. Mismatched group end

```
GroupOp {  #@ GROUP; optional GroupOp = 30; mismatched_group_end: 31;
  …
}
```

The END_GROUP tag in the binary carried field number 31 instead of 30.

#### 10. Negative int32, truncated form

```
statusCode: -1  #@ optional int32 = 5; proto2_neg_int32_truncated: true;
```

Negative int32 stored as a 5-byte truncated varint rather than the
spec-compliant 10-byte sign-extended form.

#### 11. Enum field — known value

```
type: TYPE_STRING  #@ Type(9) = 5
```

Symbolic name as field value; raw numeric value `9` embedded in the
annotation so the encoder does not need a schema lookup.

#### 12. Enum field — unknown value

```
type: 99  #@ Type(99) = 5; ENUM_UNKNOWN
```

Value not present in the enum's value table.  Raw integer emitted; `ENUM_UNKNOWN`
flags the anomaly.

---

## String escaping

### `bytes` fields

Every byte is escaped according to its numeric value:

| Byte value | Emitted form |
|---|---|
| `\` (0x5C) | `\\` |
| `"` (0x22) | `\"` |
| `'` (0x27) | `\'` |
| `\n` (0x0A) | `\n` |
| `\r` (0x0D) | `\r` |
| `\t` (0x09) | `\t` |
| 0x20–0x7E (printable ASCII, excl. above) | literal byte |
| all others (0x00–0x1F, 0x7F–0xFF) | `\NNN` (3-digit octal) |

This matches `protoc --decode` exactly for bytes fields.

### `string` fields — deliberate divergence from `protoc --decode`

`protoc --decode` applies byte-level escaping to string fields, octal-escaping
every byte ≥ 0x80.  For a field containing `"café"` (UTF-8 `63 61 66 C3 A9`),
protoc emits `"caf\303\251"`.

`prototext` intentionally diverges: multi-byte UTF-8 sequences are emitted
as raw UTF-8.  The same field is rendered as `"café"`.

Control characters (0x00–0x1F) and DEL (0x7F) are octal-escaped in both
modes (matching protoc).

If the wire bytes of a `string` field are not valid UTF-8, `prototext` emits an
`INVALID_STRING` anomaly.

---

## Formal grammar

```
-- Top level
message := header NEWLINE field*
header  := "#@ prototext: protoc"

-- Field line
field      := field_name separator value "  #@ " annotation NEWLINE
           |  field_name "{" "  #@ " annotation NEWLINE field* "}" NEWLINE

field_name := IDENTIFIER | NUMBER

separator  := ":" | (nothing, if followed by "{")

value      := scalar_value | "[" scalar_value ("," scalar_value)* "]"

scalar_value := STRING | NUMBER | BOOL | IDENTIFIER

-- Annotation
annotation := annotation_body

annotation_body := field_decl
               |  wire_type ";" annotation_body?
               |  modifier ";" annotation_body?

field_decl := label? type "=" NUMBER ";"

label := "optional" | "repeated" | "required"

type := proto_scalar_type
     |  IDENTIFIER                          (message or group type)
     |  IDENTIFIER "(" NUMBER ")"           (enum type with numeric value)

proto_scalar_type := "double" | "float" | "int64" | "uint64" | "int32"
                  |  "fixed64" | "fixed32" | "bool" | "string" | "bytes"
                  |  "uint32" | "sfixed32" | "sfixed64" | "sint32" | "sint64"

wire_type := "VARINT" | "FIXED64" | "BYTES" | "FIXED32" | "GROUP"
          |  "INVALID_TAG_TYPE" | "INVALID_VARINT" | "INVALID_FIXED64"
          |  "INVALID_FIXED32" | "INVALID_BYTES_LENGTH" | "TRUNCATED_BYTES"
          |  "INVALID_PACKED_RECORDS" | "INVALID_STRING" | "INVALID_GROUP_END"

modifier := modifier_name ":" modifier_value
         |  "ENUM_UNKNOWN"

modifier_name  := IDENTIFIER

modifier_value := NUMBER | BOOL | "[" NUMBER ("," NUMBER)* "]"

-- Tokens
IDENTIFIER := /[a-zA-Z_][a-zA-Z0-9_]*/
NUMBER     := /-?[0-9]+(\.[0-9]+)?([eE][+-]?[0-9]+)?/ | "inf" | "-inf" | "nan"
STRING     := /"([^"\\]|\\.)*"/
BOOL       := "true" | "false"
NEWLINE    := /\n/
```

Notes:
- Whitespace (spaces, tabs) is ignored except within strings and at the `  #@ `
  separator (two spaces are required before `#@`).
- Newlines are significant and separate fields.
- Groups are distinguished from messages by the `GROUP;` prefix in the annotation.
- Field names can be identifiers (for known fields) or numbers (for unknown fields).
- The colon separator is optional before `{` for message/group values.

---

## Proposed grammar v2

### Design goals

1. **Compactness for the canonical case** — the common case (known field, no
   anomalies) should be as terse as possible; every canonical field carries an
   annotation so the saving multiplies across the whole file.
2. **Human readability** — anomalies should stand out visually; modifier names
   should be self-explanatory without consulting a reference.
3. **Consistency** — uniform naming convention for all modifiers; the same
   visual rule applied everywhere.
4. **Proximity to proto syntax** — field declarations should feel familiar to
   anyone who has read a `.proto` file.
5. **Protoc-compatible value side** — the part of each line *before* `#@`
   should match the output of vanilla `protoc` as closely as possible.
6. **High-performance hand-written parsing** — the Rust deserializer is
   performance-critical and hand-coded; the grammar must be designed so that
   every decision point can be resolved with minimal, ideally zero, look-ahead.

> **Priority note**: invalid and non-canonical fields are rare in practice.
> Compactness is less important for them than readability and consistency.
> Canonical-field shortening impacts every annotated field and therefore has
> far greater practical impact.

### Problems with the current format

| # | Problem | Example |
|---|---|---|
| P1 | Modifier names are very long (avg. 20 chars) | `tag_overhang_count: 2` |
| P2 | No visual distinction between invalidity and non-canonicality | `tag_is_out_of_range: true; tag_overhang_count: 2` — both look the same |
| P3 | Inconsistent naming style across modifiers | `mismatched_group_end` vs `open_ended_group` vs `tag_is_out_of_range` |
| P4 | Boolean modifiers carry a redundant `: true` | `open_ended_group: true` |
| P5 | `proto2_` prefix is opaque to most users | `proto2_has_type_mismatch`, `proto2_neg_int32_truncated` |
| P6 | `optional` repeated on the vast majority of annotations | `optional double = 21;` |
| P7 | Wire type `BYTES` shadows the proto type `bytes` | `999: "…"  #@ BYTES;` |
| P8 | No visual distinction between valid and invalid wire type names | `#@ VARINT;` vs `#@ INVALID_VARINT;` — similar look |
| P9 | Trailing `;` on last annotation token is noise | `optional double = 21;` |
| P10 | Field declaration comes last; modifiers buried before it | `#@ VARINT; tag_overhang_count: 2; optional string = 29;` |
| P11 | Double space before `#@` is a fragile hard-coded separator | `value  #@ ann` |

### Proposed changes

#### A. Lax grammar for whitespace

The parser should accept any leading indentation (spaces or tabs) and any
number of spaces (≥ 0) before `#@`.  The canonical emitted form continues to
use two spaces.

#### B. Annotation order: field declaration before modifiers

Move the field declaration immediately after the wire type, so schema context
is encountered before anomaly details.

```
current:   #@ [wire_type;] [modifier; …] [label type = N;]
proposed:  #@ [wire_type;] [label type = N;] [modifier; …]
```

#### C. Field declaration: drop `optional` as default

`optional` is the default proto label and appears on the vast majority of
fields.  Omitting it saves ~9 characters per canonical annotation without
losing any information.  `repeated` and `required` are retained spelled out.

```
current:   optional double = 21;      →   double = 21
current:   optional string = 29;      →   string = 29
current:   repeated float [packed=true] = 42;  (unchanged)
```

#### D. Wire type names: lower case for valid, ALL CAPS for invalid

| Category | Names |
|---|---|
| Valid wire types (lower case) | `varint`, `fixed64`, `bytes`, `fixed32`, `group` |
| Structural invalids (ALL CAPS) | `INVALID_TAG_TYPE`, `INVALID_VARINT`, `INVALID_FIXED64`, `INVALID_FIXED32`, `INVALID_LEN`, `TRUNCATED_BYTES`, `INVALID_PACKED_RECORDS`, `INVALID_STRING`, `INVALID_GROUP_END` |

#### E. Modifier case: ALL CAPS for invalidity, lower case for non-canonicality

Full renaming table:

| Current | Proposed | Category | Notes |
|---|---|---|---|
| `tag_overhang_count: N` | `tag_ohb: N` | non-canonical | `_ohb` = overhang bytes |
| `tag_is_out_of_range: true` | `TAG_OOR` | invalid | flag; `_OOR` = out of range |
| `value_overhang_count: N` | `val_ohb: N` | non-canonical | |
| `length_overhang_count: N` | `len_ohb: N` | non-canonical | |
| `missing_bytes_count: N` | `MISSING: N` | invalid | N bytes missing from truncated field |
| `mismatched_group_end: N` | `END_MISMATCH: N` | invalid | end tag carries field number N |
| `open_ended_group: true` | `OPEN_GROUP` | invalid | flag |
| `end_tag_overhang_count: N` | `etag_ohb: N` | non-canonical | |
| `end_tag_is_out_of_range: true` | `ETAG_OOR` | invalid | flag |
| `proto2_has_type_mismatch: true` | `TYPE_MISMATCH` | invalid | flag; `proto2_` prefix dropped |
| `proto2_neg_int32_truncated: true` | `truncated_neg` | non-canonical | flag |
| `records_overhung_count: [N, …]` | `packed_ohb: [N, …]` | non-canonical | |
| `records_neg_int32_truncated: [b, …]` | `packed_truncated_neg: [0|1, …]` | non-canonical | 0 = canonical, 1 = truncated |

### Proposed formal grammar

```
-- Lines are of one of three forms:
--   42: value   #@ annotation    (field number key → unknown/unrecognised field)
--   name: value #@ annotation    (field name key   → known scalar/bytes field)
--   name {      #@ annotation    (field name key   → known message or group)
--
-- The annotation structure is fully determined at the line level by the key
-- type (number vs. name), before the annotation is parsed.

annotation := SP* "#@" SP* annotation_body
SP         := " " | "\t"

-- Unknown-field annotation (line starts with a numeric key)
unknown_field_ann := wire_type [";" modifier (";" modifier)*]

-- Known-field annotation (line starts with a named key)
known_field_ann   := ["group" ";"] field_decl [";" modifier (";" modifier)*]

wire_type      := valid_wire_type | invalid_wire_type
valid_wire_type   := "varint" | "fixed64" | "bytes" | "fixed32" | "group"
invalid_wire_type := "INVALID_TAG_TYPE"    | "INVALID_VARINT"
                 |  "INVALID_FIXED64"      | "INVALID_FIXED32"
                 |  "INVALID_LEN"          | "TRUNCATED_BYTES"
                 |  "INVALID_PACKED_RECORDS" | "INVALID_STRING"
                 |  "INVALID_GROUP_END"

field_decl     := [label SP] type [SP "[packed=true]"] SP "=" SP NUMBER
label          := "repeated" | "required"   -- "optional" omitted (default)
type           := proto_scalar_type | IDENTIFIER | IDENTIFIER "(" NUMBER ")"
proto_scalar_type := "double" | "float" | "int64" | "uint64" | "int32"
                 |  "fixed64" | "fixed32" | "bool" | "string" | "bytes"
                 |  "uint32"  | "enum"   | "sfixed32" | "sfixed64"
                 |  "sint32"  | "sint64"

modifier       := invalid_modifier | noncanon_modifier
invalid_modifier  := invalid_flag | invalid_valued
invalid_flag      := "TAG_OOR" | "ETAG_OOR" | "OPEN_GROUP" | "TYPE_MISMATCH"
invalid_valued    := ("MISSING" | "END_MISMATCH") ":" INTEGER

noncanon_modifier := noncanon_flag | noncanon_valued
noncanon_flag     := "truncated_neg"
noncanon_valued   := ("tag_ohb" | "val_ohb" | "len_ohb" | "etag_ohb") ":" INTEGER
                 |  "packed_ohb"           ":" "[" INTEGER ("," INTEGER)* "]"
                 |  "packed_truncated_neg" ":" "[" BIT     ("," BIT)*     "]"
BIT := "0" | "1"
```

### Before / after comparison

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
CURRENT
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
doubleOp: 2.718  #@ optional double = 21;
floatRp: [1.5, 2.5]  #@ repeated float [packed=true] = 42;
messageOp {  #@ optional SwissArmyKnife = 31;
  int32Op: 200  #@ optional int32 = 25;
}
GroupOp {  #@ GROUP; optional GroupOp = 30;
  uint64Op: 111  #@ optional uint64 = 130;
}
999: 12345  #@ VARINT;
42: "hello"  #@ BYTES;
stringOp: "test"  #@ optional string = 29; tag_overhang_count: 2;
99: "\001\002"  #@ TRUNCATED_BYTES; missing_bytes_count: 5; optional bytes = 99;
10: "\342\200\224"  #@ INVALID_STRING; optional string = 10;
GroupOp {  #@ GROUP; optional GroupOp = 30; open_ended_group: true;
}
negInt: -1  #@ optional int32 = 5; proto2_neg_int32_truncated: true;
intPk: [1, -1, 2]  #@ repeated int32 [packed=true] = 7; records_neg_int32_truncated: [false, true, false];
18446744073709551615: 0  #@ VARINT; tag_is_out_of_range: true;

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
PROPOSED
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
doubleOp: 2.718  #@ double = 21
floatRp: [1.5, 2.5]  #@ repeated float [packed=true] = 42
messageOp {  #@ SwissArmyKnife = 31
  int32Op: 200  #@ int32 = 25
}
GroupOp {  #@ group; GroupOp = 30
  uint64Op: 111  #@ uint64 = 130
}
999: 12345  #@ varint
42: "hello"  #@ bytes
stringOp: "test"  #@ string = 29; tag_ohb: 2
99: "\001\002"  #@ TRUNCATED_BYTES; MISSING: 5
10: "\342\200\224"  #@ INVALID_STRING
GroupOp {  #@ group; GroupOp = 30; OPEN_GROUP
}
negInt: -1  #@ int32 = 5; truncated_neg
intPk: [1, -1, 2]  #@ repeated int32 [packed=true] = 7; packed_truncated_neg: [0, 1, 0]
18446744073709551615: 0  #@ varint; TAG_OOR
```

### Summary of annotation length changes

| Situation | Current | Proposed | Δ |
|---|---|---|---|
| Known optional scalar | `optional double = 21;` | `double = 21` | −35% |
| Known optional message | `optional SwissArmyKnife = 31;` | `SwissArmyKnife = 31` | −28% |
| Known repeated packed | `repeated float [packed=true] = 42;` | `repeated float [packed=true] = 42` | −3% |
| Invalid wire type (name only) | `INVALID_STRING;` | `INVALID_STRING` | −6% |
| Invalidity flag | `open_ended_group: true` | `OPEN_GROUP` | −55% |
| Invalidity flag | `tag_is_out_of_range: true` | `TAG_OOR` | −70% |
| Non-canonical flag | `proto2_neg_int32_truncated: true` | `truncated_neg` | −59% |
| Integer modifier | `tag_overhang_count: 2` | `tag_ohb: 2` | −43% |
