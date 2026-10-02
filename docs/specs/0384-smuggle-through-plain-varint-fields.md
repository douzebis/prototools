<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0384 — smuggle through plain VARINT fields

Status: draft
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
  gains a wire-type test: a field record is in scope only when its
  annotation says the wire type is VARINT. The field-tag and
  packed-continuation rules are unchanged; a VARINT record is never a
  packed continuation in a life message (`cells` is unpacked, 0377 S1).
  The walk order stays depth-first render order.

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

Filled in at implementation.
