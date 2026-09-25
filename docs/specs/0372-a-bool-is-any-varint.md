<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0372 — a bool is any varint: render it, keep the raw value

Status: implemented
Implemented in: 2026-09-25
App: prototext-core, protolens
Refs: docs/specs/0370-packed-on-the-wire-renders-as-packed.md (its G3
      records the renderer being stricter than the scorer on bool;
      this spec removes that gap);
      docs/specs/0371-packing-mismatch-is-neutral-evidence.md (its
      renderer/scorer parity, G3, relies on this spec landing first);
      docs/specs/0178-out-of-range-is-a-penalty-not-a-veto.md
      (`out_of_range`: the scorer's charge for a
      value outside a `Range` leaf, bool included)

## Background

On the wire a `bool` is a varint. Parsers read any non-zero value as
`true`: Python protobuf 6.33.1 (upb) parses `08 02` into `[True]` for a
`repeated bool`, and `10 02` into `True` for an `optional bool`.

The renderer rejects every value above 1, on both paths, while still
round-tripping the bytes:

| wire | today |
|---|---|
| `08 02` (expanded, `repeated bool b = 1`) | `1: 2  #@ varint; TYPE_MISMATCH` |
| `10 02` (`optional bool one = 2`) | `2: 2  #@ varint; TYPE_MISMATCH` |
| `0a 01 02` (packed) | `1: "\002"  #@ INVALID_PACKED_RECORDS` |

- expanded: `decode_varint_typed` (`render_text/varint.rs`) maps
  `Kind::Bool` with `val > 1` to `VarintKind::Mismatch`;
- packed: `decode_packed_varint_elems` (`render_text/packed.rs`) returns
  `Err` for a bool element above 1, and the whole record becomes
  `INVALID_PACKED_RECORDS`.

The scorer does not reject them. A bool is a `Range` leaf `(0, 1)`, so
`check_varint_value` (`walk.rs`) charges `out_of_range` (−15) for a
value it reads as outside `[0, 1]`, and vetoes only a value in the
32-bit gap. The renderer calls a *type* mismatch what the scorer calls a
legal, if unlikely, *value* — and for a packed run it discards a record
the scorer scores.

Bool is the only such case. Every other packed-element rejection in the
renderer (int32 in the 32-bit gap, uint32/sint32 above 32 bits, the enum
gap, fixed-width runs of the wrong length, unterminated or overlong
varints) is also a veto in the scorer (checked 2026-09-25).

## Goals

- **G1.** A varint on a `bool` field renders as that field, on the
  expanded and on the packed path alike: `false` for 0, `true` for
  anything else.
- **G2.** A value other than 0 or 1 keeps its raw number in a
  `bool_val: N` modifier, and the record round-trips byte-exactly.
- **G3.** After this spec, no run the scorer accepts renders as
  `INVALID_PACKED_RECORDS`, and no varint the scorer accepts on a
  declared scalar field renders as `TYPE_MISMATCH`.

## Non-goals

- **N1. The scorer.** Its bool rule is unchanged: `out_of_range` for a
  value outside `[0, 1]` as it reads it, a veto for the 32-bit gap.
  That veto is stricter than protobuf, where a gap value is still
  `true`. The renderer accepts every value (G1); a renderer that
  accepts more than the scorer breaks nothing, because a vetoed
  candidate has no score. Relaxing the veto is a separate scoring
  question.
- **N2. Other value checks.** Enum, int32 and uint32 handling stay as
  they are; they already agree with the scorer (see Background).
- **N3. `--no-annotations` output.** It prints `true` and cannot
  round-trip a `2`, as it cannot round-trip any other modifier.

## Specification

- **S1. Expanded.** In `decode_varint_typed`, `Kind::Bool` always yields
  `VarintKind::Bool`. `render_varint_field` renders the value with
  `format_bool_protoc(raw != 0)`, as today for 0 and 1, and pushes
  `bool_val: N` after the other value modifiers when `raw > 1`.
- **S2. Packed.** In `decode_packed_varint_elems`, `Kind::Bool` never
  returns `Err`. `PackedElem` gains `bool_val: Option<u64>`, set when
  the element is above 1. `write_packed_elem_ann` pushes it among the
  element-level modifiers (`ohb`, `neg`, `nan_bits`).
- **S3. Name and form.** `bool_val: N`, decimal. It follows `nan_bits`:
  the value is printed in its canonical text form, and the raw wire
  value that the text form cannot carry goes in a modifier.
- **S4. Encoder.** `encode_annotation.rs` parses `bool_val: N` into a new
  `Ann::bool_val: Option<u64>`. The two sites that write a bool literal
  in `fields.rs` — the `true`/`false` branch at the top of
  `encode_scalar_line` (expanded) and `encode_packed_elem`'s `"bool"`
  arm — write `bool_val` when present, and the canonical 0/1 otherwise.
  Overhang (`val_ohb` / per-element `ohb`) applies to whichever value is
  written. (`encode_num`'s `"bool"` arm serves a bool written as a
  number, never a literal, and the legacy `[v1, v2, …]` array form has
  one annotation per run; neither can carry `bool_val`, and neither
  changes.)
- **S5. protolens.** `bool_val` joins `annotation::NON_CANONICAL`, with a
  hover description: "a bool is true for any non-zero value; this one
  was written as N rather than 1". It sits in the same tier as
  `ENUM_UNKNOWN`, the renderer's counterpart of the same `out_of_range`
  charge. `reproto/tree-sitter-textproto/highlights.scm` gains it in its
  `@annotation.non_canonical` list: protolens colors annotations from
  that file, and `colorize`'s `every_keyword_is_colored_by_its_tier`
  fails until the two agree. (The dev shell compiles in a Nix-built copy
  of the file, fixed at shell entry; set
  `TREE_SITTER_TEXTPROTO_QUERIES_DIR=reproto/tree-sitter-textproto`, or
  re-enter the shell, to test an edit locally. `nix-build` rebuilds it.)
- **S6. Documentation.** `annotation-format.md` lists `bool_val` in the
  element-level modifier table, with an expanded and a packed example.
  Spec 0370's G3 gets a pointer: the bool example it gives no longer
  holds after this spec.
- **S7. Order.** Implement before spec 0371, whose renderer/scorer
  parity assumes G3.
- **S8. The anomaly fixture.** `prototext-core/tests/anomaly_fixture.rs`
  asserts that the renderer's vocabulary and what
  `tests/fixtures/anomalies.pb` produces are *equal*, so `bool_val` goes
  into its `VOCABULARY` (non-canonical group) and the fixture gains a
  record that produces it:
  - A new heading and wrapper after 2.b, `name: "2.c. A bool written as
    2 instead of 1."`. Section 2 is "Values that survive a round trip
    but not a re-encode", beside `nan_bits` (2.b), the pattern
    `bool_val` follows; section 3 is about schema evolution, which a
    bool written as 2 is not. Its header comment gains one sentence.
    Following 2.a's pattern, the wrapper holds the anomaly and its
    ordinary counterpart side by side: `message_type { field { name:
    "two" options { deprecated: true …; bool_val: 2 } } field { name:
    "canonical" options { deprecated: true } } }`
    (`FieldOptions.deprecated`, a bool, field 3). No other anomaly in
    the wrapper.
  - `tests/fixtures/anomalies.script` gains two 2.c steps. A wrapper's
    top-level position is twice its number, so inserting 2.c moves every
    later wrapper by 2: **every** later path in `fold`, `node`,
    `wire_node`, `wire_line` and `wire_lines` is renumbered.
  - `tests/fixtures/README.md`: "twenty-three readable headings" becomes
    twenty-four, and section 2's list gains `bool_val`.

### Visible consequences

- A bool field's out-of-range occurrence moves from a numeric key
  (`1: 2  #@ varint; TYPE_MISMATCH`) to its name
  (`b: true  #@ repeated bool = 1; bool_val: 2`).
- `--hide-unknown-fields` no longer hides it. That matches
  `protoc --decode`, which prints `true`.
- In protolens the node becomes an ordinary leaf of its declared field,
  so it takes the heat cue, hover and override behavior of one.

## Alternatives considered

### Render the number (`b: 2`)

Rejected: the text format accepts only `true`/`false`/`t`/`f`/`0`/`1`
for a bool, so the line would not parse outside prototext, and it would
not match `protoc --decode`, whose output the rendering follows.

### Keep rejecting, align the scorer instead (veto bool > 1)

Rejected: a veto is for what the wire format makes impossible, and a
bool `2` is legal (the principle in `docs/scoring-flaws.md`).

## Test plan

### New tests

In `prototext/tests/` (the inline-descriptor style of
`packed_on_the_wire.rs`), each case asserting the rendered line and a
byte-exact round trip. Tests 1–4 are the regression tests for this
bug: each must **fail on the parent commit** and pass after (checked
in a worktree of the parent, as for spec 0370). Test 5 is a no-change
guard and passes on both.

1. `bool_above_one_renders_true_with_bool_val`: `08 02` on
   `repeated bool`, `10 02` on `optional bool` → `true`, `bool_val: 2`.
2. `packed_bool_above_one_renders_true_with_bool_val`: `0a 03 00 01 02`
   → `false`, `true`, `true; bool_val: 2`.
3. `bool_val_with_overhang_roundtrips`: `08 82 00` (value 2, one
   overhang byte), expanded and packed.
4. `bool_large_values_roundtrip`: `0xFFFF_FFFF`, a 32-bit-gap value, and
   `u64::MAX` (10 bytes), expanded and packed — rendered `true` with
   their `bool_val`.
5. `canonical_bools_unchanged`: 0 and 1 carry no `bool_val`.
6. `renderer_accepts_whatever_the_scorer_accepts` (G3): for each
   packable kind, the edge-case values of spec 0370's test 11, scored
   against a graph built with `build_from_strings` for the same field
   and rendered against the same descriptor: whenever the scorer does
   not veto, the render has no `INVALID_PACKED_RECORDS` and no
   `TYPE_MISMATCH`.
7. The updated spec 0370 test 11 row: `bool 2` now expects
   `b: true  #@ repeated bool = 3; pack_size: 1; bool_val: 2`.
8. `every_step_lands_under_its_heading` (in
   `protolens/tests/batch_script.rs`): for every script step whose
   `node` lies under a top-level wrapper, the step's text cites the
   heading of that wrapper — the most specific `N.x.` (else `N.`) token
   in the text equals the prefix of the top-level `name` line just
   before the wrapper (a heading with no letter, `4.`, covers `4.a.`
   and `4.b.`). And every other path the step names — `wire_node`,
   `wire_line`, a `wire_lines` range, its `fold` entries — lies under
   the same wrapper. `anomalies_script_walks_without_a_broken_position`
   only catches a path that no longer resolves; after S8's shift by 2,
   almost every stale path still resolves, to the wrong anomaly. This
   test catches that, for this renumbering and every later one (spec
   0371 will need one for `packing_mismatch`).

### Existing suites that must stay green

- `prototext/tests/roundtrip.rs` and `packed_on_the_wire.rs` (with test
  7's row updated);
- `prototext-core/tests/anomaly_fixture.rs` (with S8's vocabulary and
  fixture);
- `protolens/tests/batch_script.rs`, plus test 8;
- protolens's `annotation` tests, notably `every_keyword_has_a_clause`
  (S5 gives `bool_val` its clause);
- the full workspace suite and `nix-build`.

## Measured outcome

Measured 2026-09-25, `--profile quick` build.

- New tests (`prototext/tests/bool_values.rs`) against the parent
  commit, in a worktree: tests 1–4 fail, test 5 passes (the no-change
  guard), and test 6 fails too, at its first case:
  `b = 0x2: the scorer accepts it, the renderer does not:
  1: 2  #@ varint; TYPE_MISMATCH`. All six pass after.
- Test 8 was written before the script was renumbered and failed on the
  stale script ("the step citing 3.a. has node /12/1/2, which lies
  under heading 2.c."). Its path check was added after a first
  renumbering pass missed the seven `wire_node` lines; with those lines
  reverted it fails with "the step at /18/1/1 names wire_node /16/1/1,
  under another wrapper".
- The fixture round-trips byte-exactly, and renders 24 headings.
- Workspace suite: 33 test binaries, all green; clippy clean with all
  features.
