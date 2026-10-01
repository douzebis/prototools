<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0377 — the server reads the tags as sent

Status: implemented
Implemented in: 2026-10-01
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

The workshop wants to show that what reaches the server is the raw wire,
not a canonical re-encoding, and that the choice of canonical-or-not per
tag is a channel of its own. So:

- the **server** inspects the tag of every field of each request, at
  every level of nesting, in the order the fields appear on the wire, and
  reports for each whether the tag was canonical. Every field record
  `prototext decode` would render as a line is one such tag — the
  `grid {` and `rules {` headers, each `cells:` and each `rules` scalar,
  `generation` — read depth-first, as the render prints them (S2–S5).
- the **client** does the inverse: it encodes a bit field of its own into
  those tags, making the *i*-th field record's tag non-canonical exactly
  when the *i*-th bit is set, so a hidden message rides the request's tag
  encodings without changing a single field value (S6–S7). The server's
  reading recovers the client's bit field.

The demonstration message is the bytes of `"Hello server!"`: the client
writes its bits into the tags, the server reads them back and, decoded,
they spell it again.

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
  response is still the next generation (spec 0375). The tags carry the
  hidden bit field, but every field *value* is what the game sent, so the
  server computes the same generation it would have.
- **G4.** The client encodes a given bit field into the tags of every
  request it sends: field record *i*'s tag is made non-canonical (one
  overhang byte) when bit *i* is set, canonical when clear. The bit field
  is the bytes of `"Hello server!"`. The server's reading (G1, G2)
  recovers it.

## Non-goals

- **N1. Acting on the verdicts.** The server reports them; it does not
  reject, warn about, or otherwise treat a non-canonical request
  differently. What a later beat does with them is separate work.
- **N2. Rendered lines that are not field records.** A message's closing
  `}` gets no bit — even a group's `}`, which does carry an END_GROUP tag
  on the wire; the render shows it as a bare brace with no field-tag
  annotation, and the reading skips it for simplicity. In a packed field
  only the first rendered line is a field record (it carries the one tag,
  and shows `pack_size`); its later element lines are values under that
  tag and get no bit. S1 unpacks `cells`, so life requests hold no packed
  fields, but the rule is stated (S3) so the reading is unambiguous: one
  bit per rendered field record, which is one bit per tag on the wire,
  the END_GROUP `}` aside.
- **N3. Other non-canonical forms.** Only tag overhang is read, not
  value overhang (`val_ohb`), length overhang (`len_ohb`), truncated
  negatives, or the rest. The bit field answers one question per field:
  was its *tag* canonical.
- **N4. A wire format for the byte array.** Writing it to stdout is a
  demonstration, not an interface: nothing reads it back. Its layout
  (S4) is fixed only so the output is legible.
- **N5. A bit field longer than the request has tags.** `"Hello server!"`
  plus the terminator (S3a) is 105 bits; a 20×20 request has about 425
  field records (S6), so it fits with room to spare. Bits beyond the
  field-record count are dropped (S6); growing the grid to carry an
  arbitrary payload is not a goal.

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
  `tonic::codec::Codec` (spec 0241 S10). The generated service is built
  against a codec (`codec_path`) that wraps the default prost codec and,
  in its `Decoder`, hands the raw message bytes to a callback the
  application installs, then decodes as usual, so the `StepRequest`
  continues to the handler unchanged (G3). The callback is the scope: the
  server installs one (it reads and reports); the client installs none,
  so its decoder is a plain pass-through. The life crate gains a path
  dependency on `prototext-core`, as bobapp has, so it stays out of the
  root workspace (spec 0375 S1).

- **S3. The reading, from the rendered text.** The server does not walk
  the wire itself. It renders the raw request as prototext text
  (`render_as_text` with annotations on, against a `ParsedSchema` built
  once from the embedded descriptor — the server already reads it, spec
  0375 S3 — for `grehack.life.v1.StepRequest`), and reads the verdicts
  off the rendered lines, top to bottom. That render *is* the depth-first
  wire order, and its per-line annotation already carries the tag
  overhang, so the library is the single source of truth for both order
  and canonicity.

  For each rendered line, from its `#@` annotation:
  - a line is **in scope** — one field record, one bit — when the
    annotation carries the field-tag part, `= N` (the field number).
    Lines with no such annotation are skipped: a closing `}`, the
    `#@ prototext:` header, a blank line, a malformed record
    (`INVALID_…`).
  - one exception, a **packed continuation**: a line whose annotation has
    `[packed=true]` but no `pack_size` is a later element of a packed
    record, a value under a tag already counted on the record's first
    line (which does carry `pack_size`, or is the empty-record line). It
    is skipped (N2). S1 unpacks `cells`, so life requests have none, but
    the rule keeps the reading exact.
  - an in-scope line's bit is **set** when its annotation contains the
    `tag_ohb` modifier (the tag carries redundant continuation bytes),
    and clear otherwise.

  The verdicts form a sequence of booleans, one per in-scope line, in
  render order. A request rendering no field records yields an empty
  sequence.

- **S3a. The terminator convention.** A request has more field records
  than the message has bits (S6), so the message's bits are followed by
  canonical padding, all zero. To mark where the message ends, the client
  appends a single `1` bit after the message's bits (S6); the server
  recovers the message as **every bit strictly before the last `1` bit**
  of the bitfield, and drops that terminator and the padding after it.

  The **empty message** is the special case: it is an all-false bitfield —
  every tag canonical, no terminator. The server, finding no `1` bit,
  recovers the empty message. So an empty message and "no message" are the
  same thing, which is right: a request with all-canonical tags carries
  nothing. Every non-empty message, by contrast, always ends in its
  terminator `1`, even one whose last data bit is itself `1`.

  The demo's payload is byte-aligned — 13 bytes, then the terminator — so
  the recovered bits regroup into `"Hello server!"`; the convention itself
  does not require a whole number of bytes.

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

### The client side

- **S6. The client encodes a bit field into the tags.** The bits are the
  bytes of the message, byte 0 first, each byte most significant bit
  first, followed by one `1` terminator bit (S3a); for `"Hello server!"`
  that is 104 + 1 = 105 bits. An empty message is the exception (S3a):
  zero bits, no terminator, so every tag stays canonical. The client
  rewrites each request so field record *i*'s tag is non-canonical when
  bit *i* is set, canonical when clear. It rewrites
  through the same text round trip the server reads through, so the two
  are symmetric and the library is again the one source of truth:
  - `render_as_text` the crafted request (annotations on), against the
    schema;
  - walk the rendered lines in order; for each in-scope line (S3's rule),
    take the next bit and, if set, append `; tag_ohb: 1` to that line's
    annotation (leave it untouched when clear or already non-canonical);
    stop when the bits run out, leaving later tags canonical;
  - `render_as_bytes` the modified text back to binary, which reproduces
    the overhang bytes; that binary is what goes on the wire.

  A 20×20 request renders about 425 field records — `grid`, 20 `rows`,
  400 `cells`, `rules` and its two ranges, `generation` — so the 105 bits
  fit with room to spare. If the bits outrun the field records, the tail
  is dropped (N5): the terminator may be lost, so the server then recovers
  a truncated message — the demonstration's problem, not the code's.

- **S7. The rewrite rides the same codec, on the encode side.** The
  client stub uses the same `codec_path` codec as the server (S2); its
  **encoder** is the natural place for S6, symmetric to the server's read
  on the **decoder**. The codec's encoder, when the application has
  installed an encode callback, prost-encodes the `StepRequest` to a
  temporary buffer, hands those canonical bytes to the callback, and
  emits what the callback returns; with no callback installed it emits
  the prost bytes unchanged. `life-client` installs the callback (apply
  S6 with the `"Hello server!"` bit field); `life-server` installs none,
  so its responses are emitted plainly. The rewrite changes only tag
  encodings, never a field value, so the server decodes the same
  `StepRequest` and the game is unchanged (G3). It applies to every
  request, for now; a flag to toggle it is future work.

  An explicit gRPC interceptor was considered and is not used: the codec
  already sits at the exact point — the last place the request is bytes —
  and a callback there mirrors the server's half with no extra layer.

- **S8. The server shows the smuggled message.** The server already reads
  the bitfield (S2–S5). It additionally applies S3a — the bits before the
  last `1` bit — and, when that message is non-empty, logs it to stderr
  beside the per-request line (`smuggled: Hello server!`), so the
  demonstration reads at a glance. An empty message (an all-canonical
  request, S3a) logs nothing, so a request carrying no smuggled payload is
  silent. stdout keeps the raw byte array (S5), the original artifact. A
  message that is valid UTF-8 is logged as text; one that is not is logged
  as its bytes in hex. This is reporting only (N1): the server still
  serves the same generation.

## Alternatives considered

### Read the tags from the decoded message

prost decodes and discards the tag encoding: by the time there is a
`StepRequest`, the overhang is gone. The reading must see the raw bytes,
hence S2's codec.

### Walk the wire in the server, not the rendered text

The server could re-parse the raw bytes itself (`parse_wiretag` over each
tag, recursing on message fields) and never render text. Rejected: it
duplicates, in a second place and a second way, the wire walk prototext
already does, and the two could drift on what counts as a field record or
what `tag_ohb` means. The render is the library's own answer to both
questions (S3); the server reads it rather than re-deriving it.

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

### A client interceptor, or sending raw bytes

A tower/gRPC interceptor could rewrite the serialized request, or the
client could bypass the stub and send a `Vec<u8>` through a bytes
pass-through codec. Both were rejected for S7's encode callback: the
codec is already at the last-bytes point and already installed on the
client stub, so a callback there needs no new layer and no change to how
the client calls `step`. The rewrite's byte-level work (add `tag_ohb`) is
the exact mirror of the server's read, through the same text round trip.

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
3. A round-trip unit test (S6, S3a): encode `"Hello server!"` plus the
   terminator into a 20×20 request's tags, re-encode, read the tags back
   (S3), take the bits before the last `1` (S3a) — they regroup into
   `"Hello server!"`. The re-encoded bytes decode to the same
   `StepRequest` as the original (value-preserving, G3). A message whose
   bits plus terminator outrun the field records is truncated, not an
   error (N5). The empty message round-trips through an all-false bitfield
   (no terminator), and the server recovers it as empty (S3a).
4. In the image (a `grehack2026/smoke-test.sh` check): `life-client
   --steps` drives the server over a 20×20 grid; the server's stderr
   shows `smuggled: Hello server!`.
5. The game still runs (G3): the existing life smoke-test check still
   passes, the response is still the next generation.
6. protoscan on the binaries recovers the schema with `cells` unpacked
   (spec 0375's check still passes, the recovered `.proto` shows
   `[packed = false]`).

## Measured outcome

Measured 2026-10-01 on the x86-64 NixOS VM, release build.

**The channel, end to end.** `life-client` hides `"Hello server!"` in
every request's tags (S6, S7); `life-server` recovers it (S3, S3a, S8) and
logs `smuggled: Hello server!` once per request, while the game runs
normally. Confirmed by a manual run (3 requests, 3 recovered messages, 3
generations) and by a `grehack2026/smoke-test.sh` check in the image.

**The reading (S1–S5).** A canonical 1×2-grid request renders 12 field
records — grid, rows, two cells, rules, birth and its min/max, survival
and its min/max, generation — and reads 12 zero bits, the count matching a
plain scan of the render. Rewriting `generation`'s one-byte tag as a
two-byte overhang encoding sets exactly bit 11. protoscan recovers the
schema with `cells` `[packed = false]`, so unpacking survives.

**The framing and round trip (S3a, S6).** 34 crate tests pass.
`frame_message` + `recover_message` round-trip a message with its
terminator, including one whose last data bit is `1`; the empty message is
an all-false field with no terminator and recovers as empty; padding after
the terminator is dropped. `encode_tags` then `read_tags` round-trips
`"Hi"` through a 5×5 request, and the spoiled bytes decode to the same
`StepRequest` (value-preserving, G3). A bit field longer than the field
records is truncated (N5).

**The interception (S2, S7).** tonic's generated service fixes `ProstCodec`
with no hook, so the codec is supplied through `codec_path`. The one codec
wraps both stubs: its decoder calls a decode callback (the server reads),
its encoder calls an encode callback (the client rewrites); each side
installs only its own, and with none the codec is a plain pass-through. The
decoder reads `src.chunk()` (the whole message, un-consumed) before
decoding; the encoder prost-encodes to a temp buffer, rewrites, and emits.

**The Nix build.** life's path dependency on prototext-core means its
derivation's source must be repo-rooted with a `postUnpack` into life/, as
bobapp does (spec 0241); a stale cache once hid this. Recorded as a
project memory.

**The Nix build.** life's path dependency on prototext-core means its
derivation's source must be rooted at the repository, not at life/, with a
`postUnpack` that enters life/ and sets `sourceRoot="."` — the technique
bobapp uses (spec 0241). Without it the build cannot read
`../../prototext-core/Cargo.toml`. (A stale cached build hid this at first:
the image kept the pre-dependency binary and silently dropped the reading.)

**The interception.** tonic's generated service fixes `ProstCodec` with no
hook, so the codec is supplied through `codec_path` (a build.rs option).
The codec wraps the prost codec and, in its decoder, calls an
application-installed callback with the raw bytes (`src.chunk()`, which is
the whole message, un-consumed) before decoding. The callback is the
scope: the server installs one, the client none, so the single generated
codec serves both and the client pays nothing. This is lighter than
splitting client and server codegen, and keeps prototext-core out of the
client's closure only in spirit — the dependency is the crate's — but the
client never renders.

**stdout (S5).** The bytes are written raw, newline-delimited, as the task
asked. A bit-field byte can be 0x0a, so a reader splitting on newlines
could miscount; nothing reads it back (N4), so this is left as specified.
Test plan items 5 done above; the manual walkthrough (a later beat
sending non-canonical tags) is future work (N1).
