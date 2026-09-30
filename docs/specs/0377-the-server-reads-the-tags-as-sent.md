<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0377 — the server reads the tags as sent

Status: draft
App: grehack2026 (life-server), prototext-core
Refs: docs/specs/0375-a-game-of-life-to-spy-on.md (the application this
      extends: the schema, the server, the embedded descriptor);
      docs/prototext/annotation-format.md (`tag_ohb`, the annotation
      that reports a non-canonical tag);
      docs/specs/0241-a-real-call-leaves-bytes-worth-opening.md (bobapp:
      prototext-core as a path dependency, and a tonic codec that sees
      the request as bytes)

## Background

A protobuf field tag is a varint. Its canonical encoding is the
shortest one; the same tag can also be written with redundant
continuation bytes — `0x88 0x00` for field 1 wire type 0, in place of
`0x08` — which every decoder accepts and re-encodes away. prototext
detects this and reports it: a tag carrying N redundant bytes is
annotated `tag_ohb: N` (`parse_wiretag` records it as `wfield_ohb`).

The workshop wants the server to show that what reaches it is the raw
wire, not a canonical re-encoding: it inspects the tag of every field of
each request, at every level of nesting, in the order the fields appear
on the wire, and reports for each whether the tag was canonical. Every
field record `prototext decode` would render as a line is one such tag —
the `grid {` and `rules {` headers, each `cells:` and each `rules`
scalar, `generation` — read depth-first, as the render prints them. A
later beat can make the client send non-canonical tags and watch the
server see them; this spec is only the server-side reading.

For the reading to have one entry per cell rather than one per row, the
schema stops packing `cells` (S1). A packed row is a single
length-delimited field holding all its cells under one tag; an unpacked
repeated field gives each cell its own field record, hence its own tag
and its own bit.

## Goals

- **G1.** Before it does anything else with a request, `life-server`
  decodes the raw bytes with the prototext library against the life
  schema, walks every field at every depth in wire (render) order, and
  decides for each whether its tag is canonical.
- **G2.** It stores those verdicts as a bit field — a boolean per field,
  in that order — backed by a byte array, and writes that byte array to
  stdout.
- **G3.** The game is unchanged: the request is still served, the
  response is still the next generation (spec 0375).

## Non-goals

- **N1. Acting on the verdicts.** The server reports them; it does not
  reject, warn about, or otherwise treat a non-canonical request
  differently. What a later beat does with them is separate work.
- **N2. Lines that are not field records.** A message's closing `}` is
  not a field and gets no bit. In a packed field only the first element
  is a field record (it carries the one tag); its later elements are
  values under that tag and get no bit of their own. S1 unpacks `cells`,
  so life requests hold no packed fields, but the rule is stated so the
  walk is unambiguous: one bit per field record, which is one bit per tag
  on the wire.
- **N3. Other non-canonical forms.** Only tag overhang is read, not
  value overhang (`val_ohb`), length overhang (`len_ohb`), truncated
  negatives, or the rest. The bit field answers one question per field:
  was its *tag* canonical.
- **N4. A wire format for the byte array.** Writing it to stdout is a
  demonstration, not an interface: nothing reads it back. Its layout
  (S4) is fixed only so the output is legible.

## Specification

- **S1. `cells` is unpacked.** In `life.proto`, `Row.cells` gains
  `[packed = false]`. proto3 packs repeated scalars by default; the
  option turns it off, so each cell is its own field on the wire, with
  its own tag. The grids stay small (spec 0375 caps them at 512 × 512),
  and the workshop is not bandwidth-bound, so the larger encoding does
  not matter. This changes the embedded descriptor, so protoscan and the
  spy's `--proto-path` see the unpacked declaration; the `packing_*`
  machinery (spec 0371) is not otherwise involved.

- **S2. The raw request reaches the reading.** The server sees the
  request's bytes before tonic decodes them, as bobapp does with a
  `tonic::codec::Codec` (spec 0241 S10): the reading happens in the
  codec's `Decoder`, on the bytes as received, and then the decoded
  `StepRequest` continues to the handler unchanged (G3). The life crate
  gains a path dependency on `prototext-core`, as bobapp has, so it stays
  out of the root workspace (spec 0375 S1).

- **S3. The reading.** Against a prototext `ParsedSchema` built once from
  the embedded descriptor (the server already reads it, spec 0375 S3),
  for `grehack.life.v1.StepRequest`:
  - the library walks the raw message and yields every field record, at
    every depth, in the order `prototext decode` would render it: a
    message's own header, then its children, depth-first, in wire order;
  - a field's tag is **canonical** when its tag overhang is zero, and
    **non-canonical** (bit set) when the tag carries one or more
    redundant continuation bytes (`tag_ohb ≥ 1`);
  - the verdicts form a sequence of booleans, one per field record, in
    that order. A request with no fields yields an empty sequence.

  The exact prototext-core entry point is an implementation choice. The
  arena (`build_arena` over the raw bytes) holds every node with its
  `raw_start` at the tag and its tree structure, which yields the
  depth-first order and each tag directly; a purpose-built recursive
  reader is also admissible. The spec fixes the result — one
  canonical/non-canonical verdict per field record, in render order —
  not the call.

- **S4. The bit field.** A `BitField` holds the verdicts, backed by a
  `Vec<u8>`: bit *i* is field *i*'s verdict, 1 for non-canonical, bit 0
  the most significant bit of byte 0 (big-endian bit order, so the bytes
  read left to right as the fields were sent). `n` fields occupy
  `n.div_ceil(8)` bytes; the last byte's unused low bits are zero. The
  type is a small, tested unit: `push(bool)`, `as_bytes() -> &[u8]`, and
  the bit count.

- **S5. To stdout.** For each request, after the reading and before the
  response is computed, the server writes the byte array to stdout: the
  raw bytes, followed by a newline, so successive requests are
  distinguishable and the stream stays a terminal-legible sequence of
  lines. Nothing parses it back (N4). The per-request log stays on
  stderr (spec 0375 S4), so stdout carries only these bytes.

## Alternatives considered

### Read the tags from the decoded message

prost decodes and discards the tag encoding: by the time there is a
`StepRequest`, the overhang is gone. The reading must see the raw bytes,
hence S2's codec.

### Keep `cells` packed

The walk descends anyway (G1), so a packed `cells` would still be read —
but as one field per row, its cells hidden inside a single packed record
whose later elements carry no tag. Unpacking (S1) gives one tag, and one
bit, per cell, which is the demonstration the workshop wants: many tags,
each independently canonical or not. It is also a one-line change the
workshop can point at in the `.proto`.

### A `Vec<bool>` instead of a byte-backed bit field

The task calls for a bit field backed by a byte array, and writing bytes
to stdout (G2, S4); a `Vec<bool>` is one byte per flag and has no byte
array to write. The `BitField` is the artifact.

## Test plan

1. `bitfield` unit tests: `push` then `as_bytes` for 0, 1, 7, 8 and 9
   fields; bit order (field 0 is the high bit of byte 0); the unused
   low bits of the last byte are zero.
2. A reading unit test over hand-built `StepRequest` bytes: an
   all-canonical request yields all-zero bits; the bit count equals the
   number of field records the render shows (grid header, each cell, each
   rules scalar, generation); a non-canonical tag written on one chosen
   field — a nested one, e.g. a single `cells` element — sets exactly its
   bit and no other; the order is depth-first render order, not
   field-number order.
3. In the image (a `grehack2026/smoke-test.sh` check): with `cells`
   unpacked, `life-client --steps` drives the server, and the server's
   stdout holds one byte-array line per request; a canonical client
   yields all-zero lines.
4. The game still runs (G3): the existing life smoke-test check still
   passes, the response is still the next generation.
5. protoscan on the binaries recovers the schema with `cells` unpacked
   (spec 0375's check still passes, the recovered `.proto` shows
   `[packed = false]`).

## Measured outcome

Filled in at implementation.
