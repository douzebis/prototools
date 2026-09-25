<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0370 — a packed record renders as packed, whatever the field declares

Status: implemented
Implemented in: 2026-09-25
App: prototext-core
Refs: docs/specs/0175-packed-and-expanded-repeated-scalars.md (the
      reader rule, already applied to scoring; its renderer non-goal is
      what this spec corrects);
      docs/specs/0267-packing-is-a-declaration-not-an-anomaly.md
      (`[packed=true]` states the declaration, `pack_size` the record);
      docs/prototext/PROST-ISSUES.md §1 (`is_packed()` wrong for proto3
      fields that carry options);
      docs/prototext/annotation-format.md (§ Packed field encoding)

## Background

Every repeated scalar field has two legal wire encodings, packed and
expanded, in proto2 and proto3 alike. The declaration picks the one a
*writer* uses. A reader must accept both. The protobuf encoding guide
puts it this way: "Protocol buffer parsers must be able to parse repeated
fields that were compiled as `packed` as if they were not packed, and
vice versa." The proto2 language guide adds: "In 2.3.0 and later, […]
parsers for packable fields will always accept both formats."

We checked this against Python protobuf 6.33.1 (upb). It parses a LEN
record on a proto2 `repeated int32 lane = 1` into `lane` values without
error, and re-serializes them expanded.

The renderer accepts only one direction. `render_len_field`
(`len_field.rs`, `use_packed`) takes the packed path only when
`fs.is_packed()` is true, or, for proto3, when `[packed=false]` is not
set. A packed record on a field declared expanded falls through to the
wire-type-mismatch arm:

| declared | wire | today |
|---|---|---|
| proto2 `repeated int32` | packed | `1: "\001\002\003"  #@ bytes; TYPE_MISMATCH` |
| proto3 `repeated int32 [packed=false]` | packed | same |
| proto2 `repeated int32 [packed=true]` | expanded | renders correctly |

The scorer already reads these records as packed (spec 0175), so the two
disagree. On `CONFIG_NETWORK_DEVICE_vars_software` against
`/tmp/g3.desc` (winner `NvlinkInfoEntry`, field
`NvlinkInfoLanes.lane`, proto2), the output shows 224 `TYPE_MISMATCH`
rows next to `# Score: 229  (matched: 229)`. The score counts each of
those records as a match, which is correct. The rows are what's wrong.
Spec 0175 left the renderer out of scope on the grounds that it
"already read[s] packed payloads". That holds only for fields declared
packed.

### The encoder keys packing on the declaration, not the record

`encode_text/mod.rs` rebuilds a packed record only when
`ann.is_packed && ann.pack_size.is_some()`. `ann.is_packed` is parsed
from `[packed=true]` in the field declaration, and the declaration is
rendered from `fi.is_packed()`, a fact about the schema. Widening the
renderer gate alone would therefore render
`lane: 1  #@ repeated int32 = 1; pack_size: 3`, and that re-encodes
expanded.

The same hole is live today through the prost workaround. For a proto3
field whose `FieldOptions` is present (PROST-ISSUES §1), the renderer
takes the packed path, but the declaration still omits
`[packed=true]`. Reproduction:

```
message M { repeated int32 lane = 1 [(tagx) = 7]; }   // proto3
input   0a 03 01 02 03
decode  lane: 1  #@ repeated int32 = 1; pack_size: 3   (+ 2 more lines)
encode  08 01 08 02 08 03                              ← not the input
```

### An invalid payload loses an overlong length prefix

`render_invalid` (`render_text/helpers/scalar.rs`) doesn't copy the
record verbatim. It writes the payload plus annotations, and the encoder
rebuilds the tag and the length from those annotations. It takes
`tag_ohb` but has no `len_ohb` parameter: it passes `None` to
`push_tag_modifiers`. The encoder already writes `len_ohb` back for
`INVALID_PACKED_RECORDS` and `INVALID_STRING`
(`encode_text/fields.rs`). The value just never arrives:

```
0a 81 00 80   proto2 [packed=true] int32   → 1: "\200"  #@ INVALID_PACKED_RECORDS → 0a 01 80
0a 81 00 ff   proto3 string                → 1: "\377"  #@ INVALID_STRING         → 0a 01 ff
```

Today, fields declared expanded escape this, because their LEN records
take the `TYPE_MISMATCH` path, which carries `len_ohb`:
`0a 81 00 80` on a proto2 `repeated int32` round-trips. S1 moves those
records to `INVALID_PACKED_RECORDS`, so without S5 this spec would turn
a lossless round trip into a lossy one.

## Goals

- **G1.** A LEN record on a repeated packable scalar field renders as a
  packed record, whether or not the field is declared packed and
  whatever its syntax: one line per element, with `pack_size: N` on
  the first.
- **G2.** Such a record round-trips byte-exactly, including the prost
  §1 case above, which fails today.
- **G3.** A LEN payload that the renderer can't decode as a packed run
  on such a field renders `INVALID_PACKED_RECORDS`, exactly as it
  already does for a field declared packed. The per-element validity
  rules don't change. They are stricter than the scorer's: a bool `2`
  is `INVALID_PACKED_RECORDS` here, but only an `out_of_range` penalty
  in `walk.rs`. Aligning the two is out of scope.
- **G4.** No input that round-trips byte-exactly today stops doing so.
  In particular, an `INVALID_PACKED_RECORDS` or `INVALID_STRING` record
  with an overlong length prefix round-trips, whatever the field
  declares.

## Non-goals

- **N1. Scoring.** Spec 0175 already made the scorer the correct
  reader. Whether a packed run of printable ASCII on a field declared
  expanded deserves a penalty is a separate heuristic question. It
  needs its own spec.
- **N2. The `[packed=true]` shown in the declaration.** It keeps saying
  what the schema declares (spec 0267). It stays subject to prost §1,
  which after this spec only affects what the annotation displays, not
  the bytes. Fixing the display is separate work.
- **N3. Strings, bytes, messages, groups.** Protobuf forbids packing
  them. A LEN record on a `repeated string` keeps its current path.
- **N4. `--no-annotations` output.** It doesn't promise a lossless
  round trip, and this spec doesn't change that.
- **N5. protolens's synthetic `[packed=true]`.** Spec 0219 S3 declares
  a synthetic override field `repeated [packed=true]`
  (`decode::packed_framing`) so that the renderer reads a LEN record
  as a packed run. After S1, `repeated` alone would be enough. The
  declaration stays: it is harmless, it is a documented decision, and
  removing it is a protolens change with its own wrapper-naming
  consequences (`warm_visible_override_wrappers`).

## Specification

- **S1. Renderer gate.** In `render_len_field`, `use_packed` becomes
  `is_repeated && is_packable_kind`. The declaration isn't consulted.
  Every sink sees `ScalarValue::Packed` exactly as it does today for a
  field declared packed, so the text renderer and the protolens tree
  (one `NodeSpan` per element, `sink.rs`) follow without further
  changes.
- **S2. Encoder trigger.** In `encode_text/mod.rs`, a packed record
  starts on `ann.pack_size == Some(n)` alone, and the `ann.is_packed`
  guard is dropped. `pack_size` is written only by `render_packed`, on
  the first element of a packed record, so it is exactly the fact the
  encoder needs. The empty-record path (`pack_size: 0` comment line)
  already keys on `pack_size` alone and is unchanged.
- **S3. Dead workaround code; the feature stays.** With S1,
  `raw_packed_option()` and `parent_file_syntax()`
  (`render_text/mod.rs`) lose their only caller. Delete them, and the
  `#[cfg(feature = "prost-bug-workaround")]` branches in
  `len_field.rs`. The `prost-bug-workaround` feature itself stays
  declared in `prototext-core/Cargo.toml` and enabled where it is today.
  Removing it would break the build of any dependent that enables it,
  which isn't worth it for a cleanup. Add a comment on its declaration:
  it gates nothing since spec 0370 and is kept for compatibility.
- **S4. Two documentation sentences become false; correct them.**
  - `docs/prototext/annotation-format.md`, § Part 2 — field declaration.
    Before:
    > **packed**: `[packed=true]` appended when the field uses packed
    > wire encoding.

    That is wrong after S1: `lane: 1  #@ repeated int32 = 1; pack_size: 3`
    is packed on the wire with no `[packed=true]`. After:
    > **packed**: `[packed=true]` appended when the schema declares the
    > field packed. It says nothing about the wire: a record that is
    > packed on the wire is marked by `pack_size: N` on its first
    > element, whatever the declaration says.

    § Packed field encoding also gets that line as an example.
  - `docs/specs/0175-packed-and-expanded-repeated-scalars.md`,
    Non-goals. Before: "`prototext`'s decoder and renderer. They already
    read packed payloads (spec 0016, `NodeSpan::packed_record_start`).
    This spec is scoring only." That holds only for fields declared
    packed. After: "`prototext`'s decoder and renderer. This spec is
    scoring only; the renderer's side of the same rule is spec 0370."
- **S5. `render_invalid` carries `len_ohb`.** `render_invalid` takes a
  `TagFacts` in place of its loose `tag_ohb`/`tag_oor`/
  `repeated_singular` parameters, and passes `tag.len_ohb` to
  `push_tag_modifiers` in place of `None`. (A separate `len_ohb`
  parameter would have been the eighth, which clippy rejects;
  `TagFacts` is the bundle every caller already holds.) The two
  length-prefixed callers carry a real `len_ohb`: `render_packed`
  (`INVALID_PACKED_RECORDS`) and the invalid-UTF-8 arm in `sink.rs`
  (`INVALID_STRING`). The other callers (`INVALID_VARINT`,
  `INVALID_FIXED64`, `INVALID_FIXED32`, `INVALID_LEN`,
  `INVALID_GROUP_END`) pass the `TagFacts` they are dispatched with,
  which `render_text/mod.rs` builds with `len_ohb: None` for every
  malformed kind; `INVALID_LEN` re-emits its broken prefix verbatim
  from the value bytes anyway. The encoder is unchanged.

### Visible consequences

These follow from S1, and are intended:

- **`--hide-unknown-fields`.** Today the mismatch arm (`sink.rs`)
  suppresses these records. After S1 they are ordinary values of a
  declared field, so they are shown. That matches `protoc --decode`,
  whose output this flag exists to reproduce.
- **`--no-annotations`.** Today the same arm emits nothing for these
  records, and the bytes are lost from the output. After S1 each
  element is printed as a value.
- **Extensions.** `FieldOrExt::Ext::is_packed()` is always false, so
  today no extension record takes the packed path, even one declared
  `[packed=true]`. After S1, a LEN record on a repeated packable
  extension does (test 10).

## Alternatives considered

### Print `[packed=true]` when the record is packed

This would fix the round trip with no encoder change. It was rejected
because it turns the declaration into a statement about one record. A
field whose records arrive in both encodings would print two different
declarations in one message, and the declaration would stop matching
the schema that protolens overrides and popups read it against (spec
0267 S1).

### Keep `TYPE_MISMATCH` and let the scorer charge for it

This contradicts the protobuf reader rule that both the scorer and
every compliant SDK follow. It would also flag the encoding a schema
change such as adding `[packed=true]` is designed to make safe.

## Test plan

All in `prototext/tests/packed_on_the_wire.rs`, over a descriptor set
built inline. Every test goes through one `roundtrip` helper that
asserts byte-exact re-encoding, so the round trip is part of each test
rather than a test of its own.

1. `packed_record_on_proto2_unpacked_field_renders_packed`: proto2
   `repeated int32`, input `0a 03 01 02 03`. Expect three `lane:` lines,
   `pack_size: 3` on the first, and no `TYPE_MISMATCH`.
2. `packed_record_on_proto3_packed_false_field_renders_packed`: the same
   with proto3 `[packed=false]`.
3. (Folded into 1 and 2: both encode back to the input bytes.)
4. `packed_record_with_prost_empty_options_roundtrips`: the §1
   reproduction above, with `FieldOptions` present but empty (the
   condition itself; no custom option is needed). It fails before S2.
5. `mixed_encodings_of_one_field_roundtrip`: an expanded record, a
   packed record, then an expanded one on the same field, in both
   declarations, byte-exact.
6. `invalid_packed_run_on_unpacked_field`: `0a 01 80` (varint runs past
   the payload) and a `repeated fixed32` record with a 3-byte payload
   (`12 03 01 02 03`). Expect `INVALID_PACKED_RECORDS`, and a
   byte-exact round trip.
7. `len_on_repeated_string_unchanged`: a LEN record on a
   `repeated string` still renders as a string (N3).
8. `invalid_packed_run_keeps_overlong_length`: `0a 81 00 80` and
   `12 83 00 01 02 03`, under both declarations. Expect
   `INVALID_PACKED_RECORDS; len_ohb: 1` and a byte-exact round trip.
   Before S5, the `[packed=true]` inputs lose the byte. With S1 but
   without S5, the expanded-declared inputs would too (G4).
9. `invalid_string_keeps_overlong_length`: proto3 `string`, input
   `0a 81 00 ff`. Expect `INVALID_STRING; len_ohb: 1` and a byte-exact
   round trip. Fails before S5.
10. `packed_record_on_repeated_extension_roundtrips`: a LEN record on a
    proto2 `repeated int32` extension, declared `[packed=true]` and
    declared expanded (`a2 06 02 01 02` on field 100). Expect packed
    element lines and a byte-exact round trip. Today both render
    `TYPE_MISMATCH`, because `FieldOrExt::Ext::is_packed()` is always
    false, so S1 is the first time extensions take the packed path.
11. `packed_element_edge_cases_roundtrip_on_unpacked_fields` (G4):
    proto2 fields declared expanded, one packed record each, all
    byte-exact on round trip:

    | field | payload | expected rendering |
    |---|---|---|
    | `bool` | `02` | `INVALID_PACKED_RECORDS` |
    | `bool` | `81 00` | `true`, `ohb: 1` |
    | `int32` | `80 80 80 80 20` (2³³, the 32-bit gap) | `INVALID_PACKED_RECORDS` |
    | `int32` | `ff ff ff ff 0f` | `-1`, `neg` |
    | `int32` | `ff ff ff ff ff ff ff ff ff 01` | `-1` |
    | `uint32` | `80 80 80 80 10` | `INVALID_PACKED_RECORDS` |
    | `sint32` | `80 80 80 80 10` | `INVALID_PACKED_RECORDS` |
    | enum | `05` (undeclared) | `5`, `ENUM_UNKNOWN` |
    | enum | `ff ff ff ff 0f` | `-1`, `neg; ENUM_UNKNOWN` |
    | `float` | `01 00 c0 7f` | `nan`, `nan_bits: 0x7fc00001` |
    | `int64` | `80 80 80 80 80 80 80 80 80 80 00` | `0`, `ohb: 10` |
    | `int64` | `80 80 80 80 80 80 80 80 80 80 01` | `INVALID_PACKED_RECORDS` |

    The same payloads on fields declared `[packed=true]` already render
    and round-trip this way with the current binary (checked
    2026-09-25). The test pins that the expanded declaration now takes
    the identical path.

## Measured outcome

Measured 2026-09-25, `--profile quick` build.

- `CONFIG_NETWORK_DEVICE_vars_software` against `/tmp/g3.desc`: 0
  `TYPE_MISMATCH` rows (224 before), 224 packed `lane` records with
  `pack_size`, `# Score: 229  (matched: 229)` unchanged. The 109 208-byte
  file round-trips byte-exactly.
- The new tests against the pre-0370 code (same test file, a worktree of
  the parent commit): 9 of 10 fail. The one that passes is test 7, the
  `repeated string` no-change guard, as intended.
- Workspace suite: all green. Two protolens tests
  (`open_editor_reports_a_missing_nvim_instead_of_crashing`,
  `warm_up_heat_cues_is_a_noop_without_a_scoring_graph`) failed at
  first, on this code and on the parent commit alike. That was a
  test-harness problem unrelated to this spec: `Terminal::new` read the
  real terminal's size, with no TTY and `TERM=xterm-kitty`. They now use
  a fixed viewport (`in_memory_crossterm_terminal`).
