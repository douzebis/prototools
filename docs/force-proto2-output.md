<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# `--force-proto2-output` reference guide

`reproto --force-proto2-output` translates descriptor files to proto2 `.proto`
source regardless of the original syntax.  This guide covers the editions →
proto2 translation.  The proto3 → proto2 translation will be covered in a
later section.

The output is designed to be **wire-compatible** with the original: a binary
message encoded against the original schema can be decoded against the proto2
output and vice versa, with the same field identification and type assignments.

---

## File header

The output file starts with a `// WARNING[editions]` comment and a
`syntax = "proto2";` declaration.

```proto
// WARNING[editions]: editions file rendered as proto2 (--force-proto2-output)
syntax = "proto2";
```

The `edition = "2023";` line is dropped.  File-level `option features.X = Y;`
blocks are also dropped (see [Dropped features](#dropped-features) below).

---

## Field presence (`features.field_presence`)

Editions field presence maps to proto2 labels as follows.

| `field_presence`  | proto2 label |
|-------------------|--------------|
| `EXPLICIT`        | `optional`   |
| `IMPLICIT`        | `optional`   |
| `LEGACY_REQUIRED` | `required`   |

`IMPLICIT` and `EXPLICIT` both map to `optional` because the wire format is
identical: an unset field is simply absent from the encoded bytes, and the
runtime returns the default value when read.  The only difference is that
proto2 `optional` always exposes a `has_field()` accessor, whereas `IMPLICIT`
fields do not have one.  Reading an unset field behaves the same way in both
cases (returns the default value), so the translation is semantically safe for
the intended use cases of `IMPLICIT`.

`repeated` fields keep their `repeated` label unchanged.

**Example:**

```proto
// editions input
string implicit_field  = 1 [features.field_presence = IMPLICIT];
string explicit_field  = 2 [features.field_presence = EXPLICIT];
string required_field  = 3 [features.field_presence = LEGACY_REQUIRED];
repeated int32 ids     = 4;
```

```proto
// proto2 output
optional string implicit_field  = 1;
optional string explicit_field  = 2;
required string required_field  = 3;
repeated int32  ids             = 4;
```

---

## Message encoding (`features.message_encoding`)

| `message_encoding`  | proto2 rendering               |
|---------------------|--------------------------------|
| `LENGTH_PREFIXED`   | `optional MessageType field`   |
| `DELIMITED`         | `optional group GroupName = N` |

`DELIMITED` is the editions successor of proto2 group syntax.  The wire
encoding uses a different tag type (SGROUP/EGROUP, wire types 3/4) rather than
LENGTH_PREFIXED (wire type 2), so a faithful translation must emit a proto2
group block.

**Group naming:** the group name is derived from the field name by converting
it to CamelCase (e.g. `delimited_field` → `DelimitedField`).  If that name
collides with an existing nested message or enum name in the same scope, a
numeric suffix is appended (`DelimitedField2`, `DelimitedField3`, …), taking
the smallest available suffix ≥ 2.

The original message type (e.g. `Inner`) is always emitted as a standalone
`message` definition as well — its pool entry is unaffected.

**Example:**

```proto
// editions input
message Inner { int32 value = 1; }

message AllFeatures {
  Inner delimited_field = 5 [features.message_encoding = DELIMITED];
}
```

```proto
// proto2 output
message Inner {
  optional int32 value = 1;
}

message AllFeatures {
  optional group DelimitedField = 5 {
    optional int32 value = 1;
  }
}
```

---

## Repeated field encoding (`features.repeated_field_encoding`)

| `repeated_field_encoding` | proto2 annotation  | Notes                              |
|---------------------------|--------------------|------------------------------------|
| `PACKED`                  | `[packed = true]`  | proto2 default is unpacked         |
| `EXPANDED`                | _(none)_           | unpacked is already proto2 default |

The editions 2023 default for scalar repeated fields is `PACKED`.  Since proto2
defaults to unpacked, the `[packed = true]` annotation must be emitted
explicitly to preserve wire semantics whenever `PACKED` is in effect.

`EXPANDED` requires no annotation because unpacked is already the proto2
default.

**Example:**

```proto
// editions input
repeated int32 packed_ids   = 7 [features.repeated_field_encoding = PACKED];
repeated int32 expanded_ids = 4 [features.repeated_field_encoding = EXPANDED];
```

```proto
// proto2 output
repeated int32 packed_ids   = 7 [packed = true];
repeated int32 expanded_ids = 4;
```

---

## Oneofs

**Real oneofs** (two or more fields grouped in an explicit `oneof` block) are
preserved as-is in the proto2 output.  Each member field is rendered without a
label inside the `oneof` block, which is standard proto2 oneof syntax.

**Synthetic oneofs** are suppressed when present.  If a descriptor produced
from an editions file contains a single-member oneof whose name starts with `_`
and whose sole member has `IMPLICIT` presence, reproto treats it as a synthetic
oneof and renders the field directly at message level without the surrounding
`oneof` block.  (In practice, editions 2023 descriptors compiled by protoc do
not generate synthetic oneofs for singular fields the way proto3 does — this
path exists as a defensive measure for non-standard compilers or future protoc
changes.)

---

## Default values

Field defaults are preserved when `field_presence != IMPLICIT` (IMPLICIT
fields cannot have defaults):

```proto
// editions input
int32 with_default = 6 [features.field_presence = EXPLICIT, default = 42];
```

```proto
// proto2 output
optional int32 with_default = 6 [default = 42];
```

---

## Dropped features

The following editions features affect runtime validation or JSON behaviour
but have no effect on the wire format.  They are silently dropped when
`--force-proto2-output` is active; no per-field warning is emitted.

| Feature             | Editions meaning                            |
|---------------------|---------------------------------------------|
| `utf8_validation`   | Whether string fields are validated as UTF-8 at runtime |
| `json_format`       | Whether JSON serialization is supported      |
| `enum_type`         | Whether enum values are validated at runtime |

All `option features.X = Y;` blocks at file, message, or field level are
dropped from the output.

---

## Untranslatable constructs

For any editions construct where no wire-compatible proto2 translation exists,
reproto orphans the affected field: the field is replaced by a
`// WARNING[editions]: <reason>` comment and not emitted.  A squashed log
warning is also printed to stderr.  The process exits 0 — translation failures
are non-fatal.

Omitting the field is safer than emitting a wire-incompatible substitute:
an unknown field is passed through transparently by all runtimes, whereas a
mismatched wire type silently corrupts data.

---

# proto3 → proto2

When the input file uses `syntax = "proto3"` and `--force-proto2-output` is
active, reproto translates it to proto2 source.  The translation is simpler
than the editions case because proto3's field model is a subset of proto2's:
there are no groups, no extension ranges, no `import weak`, and no `required`
fields.

---

## File header

The output starts with a `// WARNING[downconvert]` comment and a
`syntax = "proto2";` declaration.

```proto
// original file used "proto3" syntax; rendered as proto2
syntax = "proto2";
```

The `syntax = "proto3";` line is replaced.

---

## Field labels

Proto3 has two kinds of singular field:

- **Implicit singular** — no `optional` keyword in the source, field is always
  serialised, no hazer.  In the descriptor: `label = LABEL_OPTIONAL`,
  `proto3_optional = false`.  Rendered as `optional` in proto2.

- **`optional` singular** — explicit `optional` keyword in the source, has a
  hazer (`has_*`).  In the descriptor: `label = LABEL_OPTIONAL`,
  `proto3_optional = true`.  Rendered as `optional` in proto2.

Both map to `optional` in proto2.  Presence semantics differ (proto3 implicit
singular has no hazer; proto2 `optional` does) but the wire format is
identical.

`repeated` fields keep their `repeated` label unchanged.

**Example:**

```proto
// proto3 input
string implicit_field = 1;
optional string optional_field = 2;
repeated int32 ids = 3;
```

```proto
// proto2 output
optional string implicit_field = 1;
optional string optional_field = 2;
repeated int32 ids = 3;
```

---

## Repeated field encoding (packed)

Proto3 packs repeated scalar fields by default.  Proto2 does not.  When a
repeated scalar field is effectively packed (`options.packed` is True or
implicitly True by proto3 default) and `[packed]` was not explicitly set in
the source, reproto emits `[packed = true]` to preserve wire semantics.

If `[packed = false]` was explicitly set in the proto3 source, it is emitted
as-is.

**Example:**

```proto
// proto3 input (packed by default)
repeated int32 ids = 1;
repeated int32 explicit_packed = 2 [packed = true];
repeated int32 explicit_unpacked = 3 [packed = false];
```

```proto
// proto2 output
repeated int32 ids               = 1 [packed = true];
repeated int32 explicit_packed   = 2 [packed = true];
repeated int32 explicit_unpacked = 3 [packed = false];
```

Note: `[packed = true]` is only emitted for repeated **scalar** fields (numeric
types and enums).  Repeated `string`, `bytes`, and `message` fields are not
packable; no annotation is added for them.

---

## Synthetic oneofs

Proto3 `optional` fields are represented in the descriptor with a synthetic
`oneof _fieldname {}` wrapper.  reproto detects and suppresses these: a
single-member oneof whose name starts with `_` and whose sole member has
`proto3_optional = true` is treated as synthetic.  The field is rendered
directly at message level as `optional`, without the surrounding `oneof` block.

Real oneofs (two or more members, or a single member without `proto3_optional`)
are preserved as `oneof` blocks in the output.

---

## Default values

Proto3 source cannot carry explicit default values (protoc does not populate
`default_value` in the descriptor).  Nothing is emitted.

---

## What proto3 does not have

The following constructs are absent from proto3 and therefore require no
special handling in the proto3 → proto2 translation:

| Construct                | Notes                                         |
|--------------------------|-----------------------------------------------|
| `required` fields        | Not valid in proto3; cannot appear in input   |
| Groups (`TYPE_GROUP`)    | Not valid in proto3; cannot appear in input   |
| Extension ranges         | Not valid in proto3; cannot appear in input   |
| `import weak`            | Not valid in proto3; cannot appear in input   |
| `features {}` options    | Not present in proto3 descriptors             |

Because proto2 allows all of the above, there is nothing to drop or translate
for these constructs — the translation is lossless for them by vacuity.
