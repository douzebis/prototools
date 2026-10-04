<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0384 — smuggle through plain VARINT fields

Status: implemented
Implemented in: 2026-10-03
App: grehack2026 (life-server, life-client), prototext-core
Refs: docs/specs/0377-the-server-reads-the-tags-as-sent.md (the covert
      channel this replaces: the BitField, the terminator framing,
      read_tags/encode_tags, the two codec callbacks, the field-record
      walk — all reused, only the per-record bit changes);
      docs/specs/0379-the-tags-carry-an-echo-handshake.md (the channel is
      bidirectional; request and response both carry a message);
      grehack2026/synopsis.md (CHANGE-REQ-1, the demo beat this serves:
      step 2, "Zoom into an anomaly with w")

## Background

The covert channel (spec 0377) hides one bit per field record in the
*tag* of that record: a tag written non-canonically (a redundant
continuation byte, `tag_ohb`) carries a `1`, a canonical tag a `0`. The
value is untouched, so the decoded `StepRequest` is unchanged and the
game plays normally.

The demo (synopsis step 2) stops on this anomaly with `protolens`'s wire
view (`w`) and explains it to the audience. A protobuf tag packs the
field number and the wire type into one varint (`(field_number << 3) |
wire_type`), so explaining "this tag has a spurious continuation bit"
means first explaining that hybrid packing, then that the varint of the
tag — not of a value — was padded. That is two ideas deep before the
trick itself.

A **value** varint is a plain base-128 number. A spurious continuation
bit on a value is the whole trick in one sentence, with nothing to
unpack first. The channel should ride value varints, so the wire-level
explanation is one idea, not three.

## Goals

- **G1.** The hidden bit of field record *i* rides the **value** of a
  plain VARINT field, not its tag: a value varint written with one
  redundant continuation byte (`val_ohb`, the value analogue of
  `tag_ohb`) carries a `1`, a canonical value a `0`. The decoded value,
  and so the decoded message, is unchanged (as 0377 G3).
- **G2.** The server recovers the same bit field it recovers today, so
  everything downstream of the recovered bytes — the factoring exchange
  (0382), the command/output channel (the synopsis's step 2) — is
  untouched. Only the carrier changes.
- **G3.** `protolens`'s wire view of a flagged field shows the anomaly as
  a value with a spurious continuation byte, explainable without
  reference to tag packing.

## Non-goals

- **N1. Carrying a bit on non-varint fields.** Only VARINT field records
  carry a bit now. In a life message the varint fields are the `cells`
  (each an enum, a varint), `generation`, and the `Range` scalars (`min`,
  `max`) — plenty for the demo's payload. Length-delimited records (the
  `grid`/`rows`/`rules` headers) and the rest are skipped, where before
  every field record counted. The payload still fits; see S4.
- **N2. Both carriers at once.** The tag carrier (0377) is removed, not
  kept beside the value carrier. One channel, one explanation.
- **N3. A new annotation.** `val_ohb` already exists in the prototext
  annotation format — the value analogue of `tag_ohb` — and the render
  already reports it. This spec reuses it; it does not add an annotation.
  (Confirm `val_ohb` round-trips through `render_as_bytes` before
  implementing — 0377 relied on `tag_ohb` doing so; if it does not, that
  gap is the first thing to fix.)
- **N4. Value overhang on a value that is already multi-byte.** A value
  needing two or more bytes anyway (a large `generation`, a `cells` enum
  is always one byte) is still padded by **one further** redundant byte
  to carry a `1`; the bit is "has one more continuation byte than the
  canonical encoding", not "is multi-byte". So the carrier does not
  collide with naturally large values.

## Specification

- **S1. The in-scope record is a VARINT field.** `in_scope` (0377 S3)
  gains a wire-type test: a field record is in scope only when it is a
  VARINT on the wire. The field-tag and packed-continuation rules are
  unchanged; a VARINT record is never a packed continuation in a life
  message (`cells` is unpacked, 0377 S1). The walk order stays
  depth-first render order.

  **How the test reads the wire type.** The annotation does *not* print a
  literal `VARINT` token for a *known* schema field: a known field renders
  as its field declaration (`generation: 5  #@ uint64 = 3`), where the
  wire type is implied by the schema type word, not spelled out. (The
  literal `wire_type` token — `varint`, `bytes`, … — appears only on
  *unknown*/raw-wire/type-mismatch lines, which a life message does not
  produce.) So the test maps the rendered type word to its wire type: the
  VARINT scalar type words — `int32`, `int64`, `uint32`, `uint64`,
  `sint32`, `sint64`, `bool`, and an enum (rendered as its enum type
  name, e.g. `CellState`) — are in scope; the length-delimited words
  (`string`, `bytes`, a nested message name like `Grid`/`Row`/`Rules`/
  `Range`) and the fixed-width words (`fixed32`/`sfixed32`/`float`,
  `fixed64`/`sfixed64`/`double`) are out. In a life message the in-scope
  set is exactly `cells` (the `CellState` enum), `generation` (`uint64`),
  and the `Range` scalars `min`/`max` (`uint32`); the message headers
  (`Grid`, `Row`, `Rules`, `Range`) are length-delimited and out.
  (`Topology`, an enum, would be in scope if a `Rules` carried a
  non-default `topology`, but the demo's rules leave it at the default, so
  it does not render as a field record.) Confirm at implementation that
  the enum case is caught — a `CellState` line renders with the enum type
  name, not a `uint*` word, so the test must treat a known enum field as
  VARINT (it is, on the wire). An over-narrow test that matched only the
  `uint*`/`int*`/`bool` words would drop every `cells` bit, which is most
  of the carrier.

- **S2. The bit is `val_ohb`, not `tag_ohb`.** `read_tags` reads
  `val_ohb` off each in-scope line instead of `tag_ohb`; `encode_tags`
  appends `; val_ohb: 1` (not `; tag_ohb: 1`) to the line a set bit
  selects, leaving the value canonical for a clear bit. The
  text-round-trip mechanism (render to text, edit the annotation,
  render back to bytes) is otherwise 0377's, unchanged. Rename the two
  functions `read_values`/`encode_values` (and `has_tag_ohb` →
  `has_val_ohb`) so the carrier is named for what it is; keep `REQUEST`,
  `RESPONSE`, `BitField` and the framing as they are.

- **S3. The value is unchanged.** One redundant continuation byte on a
  value varint re-encodes to the same number, exactly as a redundant byte
  on a tag re-encodes to the same tag (0377). The decoded `StepRequest` /
  `StepResponse` is identical, so the game is unchanged (G1, and 0377 G3).

- **S4. The payload still fits.** A 20×20 request's varint records are
  400 `cells`, `generation`, and four `Range` scalars (`min`/`max` of
  `birth` and `survival) = 405. The command/output payloads (short shell
  commands and their output) are tens of bytes, well under 405 bits. If a
  payload outruns the varint records, the tail is dropped as before (0377
  N5); the terminator may be lost and the recovered message truncated —
  the demonstration's limit, not the code's.

## Alternatives considered

### Keep the tag carrier and just change the on-screen narration

The synopsis could explain tag packing once and move on. Rejected:
CHANGE-REQ-1 is explicit that the *channel* should change so the
explanation is simpler, and the value carrier is strictly simpler to
narrate. The code change is small (the carrier, not the framing).

### Carry a bit on every field record's value, length-delimited included

A length-delimited record has no value varint to pad (its length prefix
is a varint, but padding the length is a `len_ohb`, a third idea). Only
VARINT records carry a bit (N1); the payload fits without the others.

### Add a dedicated hidden field to the schema

A reserved field carrying the payload as bytes would need the schema to
declare it and would show up in a faithful decode — the opposite of a
covert channel. The whole point (0377) is that the carrier is invisible
to a schema-faithful decoder.

## Test plan

1. `life::tags` (renamed): `encode_values` then `read_values`
   round-trips a message through a 20×20 request's VARINT fields; the
   spoiled bytes decode to the same `StepRequest` (value-preserving, G1).
   A `val_ohb` on one chosen `cells` element sets exactly its bit; the
   count equals the number of VARINT field records (not every record).
   The empty message round-trips through an all-false field (no
   terminator), recovered as empty (0377 S3a).
2. `in_scope` counts VARINT records only: a 1×2-grid request has two
   `cells`, four `Range` scalars and `generation` in scope, and the
   `grid`/`rows`/`rules` headers out of scope.
3. The factoring exchange (0382) and the command/output channel (step 2)
   still work end to end over the new carrier: the server recovers the
   same bytes it did over the tag carrier.
4. `smoke-test.sh`: the step-2 check (a command typed on the server
   surfaces its output) passes over the value carrier.
5. `protolens` shows a flagged field as a value with a spurious
   continuation byte (manual check against the demo capture; the `w`
   view).

## Measured outcome

Implemented 2026-10-03.

- `life::tags` now carries the channel on VARINT field **values**:
  `read_values`/`encode_values` read and write `val_ohb` (the value
  analogue of `tag_ohb`); `has_tag_ohb` became `has_val_ohb`. The tag
  carrier (`read_tags`/`encode_tags`) is gone (N2).
- `in_scope` gained `is_varint_field`, which maps the rendered schema type
  word to its wire type: VARINT scalars (`int32`…`bool`) and enums (named
  types rendered with a `(value)` suffix, e.g. `CellState(1)`) are in
  scope; message headers (a bare named type, no `(value)`), `string`,
  `bytes`, and the fixed-width scalars are out. Confirmed against the real
  render: a 1×2 request has 7 in-scope records (two `cells`, four `Range`
  scalars, `generation`) — the `Grid`/`Row`/`Rules` headers are out.
- `val_ohb` round-trips through `render_as_bytes` as N3 required (verified:
  it is parsed in `encode_annotation.rs` and written by `write_varint_ohb`
  in `fields.rs`), so no annotation gap needed fixing.
- End to end: the server smuggles `whoami`, the client runs it, the output
  rides back, and the server prints `experiment` — exactly the payload.
- A pre-existing latent bug surfaced and was fixed (see [[0385]] measured
  outcome): the client's `start` abandoned the in-flight worker on the
  empty command the server sends every idle step, wiping the one reply
  before a request could carry it. `start` now treats an empty command as
  a no-op.
