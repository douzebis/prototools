<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0386 — the server writes a truncated protobuf log

Status: draft
App: grehack2026 (life-server)
Refs: docs/specs/0375-a-game-of-life-to-spy-on.md (the server, its flags,
      its embedded descriptor — which this log type must stay out of);
      docs/specs/0377-the-server-reads-the-tags-as-sent.md (the server
      already sees each request's raw bytes through the codec; the log
      records those);
      docs/specs/0387-a-request-and-a-response-score-apart.md (makes the
      log's two message types distinguishable by scoring — this spec
      defines the types, 0387 shapes them);
      grehack2026/synopsis.md (CHANGE-REQ-3, and step 3: "When we do not
      have a complete descriptor database")

## Background

The demo's step 3 puts the audience in the realistic position of holding
a protobuf blob with **no schema for it**: a server log file whose type
the client binary does not carry. The point is to show `protolens`
coping — recognizing substructures from their field shapes (heat cues)
and letting the user pin types (overrides) to reconstruct the record even
with a truncated tail.

For that to be a real demonstration, three things must hold at once:

- the log is a genuine protobuf, a message with `repeated Request` and
  `repeated Response` fields;
- the file **on disk is truncated** — its tail ends partway through a
  field — at the moment the audience reads it, which is right after the
  presenter kills the server with Ctrl-C. So the capture is not a
  carefully-timed sample of a running write; it is whatever the normal
  write discipline (S3) has left on disk when the process dies, and that
  is always a truncated protobuf — the discipline holds that as an
  invariant (`protoc --decode_raw` chokes on it);
- the log type's descriptor is **absent** from the client binary, and
  the server is built **without embedding its FDPs**, so neither the
  client-derived schema DB (`life.desc`) nor the server binary gives the
  type away.

Today the server (spec 0375) has no `--log-file` option; its only
persistent output is the per-request stderr line and the stdout bit
field. The spy writes `spy.log`, unrelated.

## Goals

- **G1.** `life-server --log-file <path>` writes a protobuf log of the
  traffic to `<path>`: a top-level message holding `repeated Request` and
  `repeated Response`, one entry appended per request and per response.
- **G2.** When the server is killed with Ctrl-C and the log read, the
  file on disk **always** ends partway through a length-delimited field —
  a truncated protobuf, guaranteed, not merely likely. The write
  discipline (S3) maintains the invariant that the bytes on disk end with
  a field's tag and length prefix promising more body than has been
  written, so `protoc --decode_raw` always chokes. No ordering of the
  kill and no lucky byte alignment is required.
- **G3.** The log type's descriptor is **not** reachable from the client:
  it is not in `life.proto` (which the client embeds, spec 0375), so the
  reconstructed `life.desc` has no `Request`/`Response`/log type.
- **G4.** The server is built **without embedding** the log type's FDPs,
  so `protoscan life-server` does not surface them either. The blob is
  schema-less from every angle the audience has.

## Non-goals

- **N1. A readable or stable log format.** The log exists to be an
  unknown, truncated blob (step 3). Nothing reads it back; its layout is
  fixed only enough to serve the demo. It is not an operational log.
- **N2. Logging without `--log-file`.** No path, no log. The per-request
  stderr line (0375) and the stdout bit field (0377) are unchanged and
  independent.
- **N3. The `Request`/`Response` field shapes.** What goes *in* each
  entry, and how to make the two score apart, is spec 0387. This spec
  defines the log container and the write discipline; 0387 shapes the two
  leaf types.
- **N4. Compressing or rotating the file.** A single growing file,
  truncated only in the sense of G2 (the last field is incomplete). No
  rotation, no size cap.
- **N5. A separate descriptor pool in the server.** The log type is
  compiled into the server for its own encoding, but its
  `FileDescriptorProto` must not land in the embedded blob (G4). This is
  a build-time exclusion, defined in S4; it does not mean a second
  runtime schema.

## Specification

- **S1. The flag.** `--log-file <path>` (none by default). When set, the
  server opens `<path>` for writing (truncating an existing file) at
  startup and logs to it (S2). A failure to open is reported on stderr
  and is fatal, like a bad `--listen`.

- **S2. What is logged.** The server already sees each request's raw
  bytes (0377 S2, the codec decode callback) and produces each response.
  Per step, it builds the wire bytes of two entries — a `Request` from the
  request and a `Response` from the response — as they would appear inside
  the top-level log message's `repeated` fields: each is the field tag,
  the length prefix, and the entry body. The field numbers: the top-level
  log message has `repeated Request request = 1` and `repeated Response
  response = 2`. The leaf shapes are spec 0387. These bytes concatenate,
  entry after entry, into a valid encoding of the growing log message —
  the server never re-encodes the whole message, it only appends (S3).

- **S3. The write discipline — stop inside the last entry's body (G2).**
  The server keeps a small in-memory carry buffer, and maintains one
  invariant: **what is on disk always ends with a complete tag + length
  prefix whose body is still incomplete.** That is exactly a truncated
  protobuf, so a kill at any moment leaves a truncated file with
  certainty (G2) — no probability, no alignment luck.

  Each step produces two entries (a `Request`, then a `Response`), each a
  `tag || length_prefix || body`. On each step:
  1. flush to disk everything buffered **except** the final held-back
     byte(s): concretely, write the previous step's held-back tail, then
     this step's `Request` entry in full, then the `Response` entry's tag
     and length prefix and all but the last byte of its body;
  2. keep the **last byte of the latest entry's body** (never fewer than
     one body byte, and never the whole body) in `carry`.

  So the file on disk always stops one or more body bytes short of the
  most recent entry's declared length: the last length prefix promises
  more than follows. The body is never empty by construction (an entry's
  wrapped `StepResponse` is always several bytes — a grid plus a
  generation, spec 0387), so there is always at least one byte to hold
  back; if an entry ever could be empty, hold back into the length prefix
  instead, which is equally truncating. On Ctrl-C the process dies with
  `carry` unwritten and the invariant intact — dropping `carry` *is* the
  truncation. No signal handler, no flush-on-exit.

  This lags the file behind the traffic by a byte or two and leaves the
  final `Response` body always incomplete on disk — which is fine: the
  log is a demo artifact, not an audit trail (N1). The test is not a
  probability check but the invariant itself: after any number of steps,
  `protoc --decode_raw` on the flushed bytes fails (test plan 2).

- **S4. The log type stays out of the embedded descriptor (G3, G4).** The
  log message and its `Request`/`Response` leaves are defined in a proto
  the server compiles for its own use (a `log.proto`, package to taste),
  **separate** from `life.proto`. `log.proto` **imports** `life.proto`
  (`import "grehack/life/v1/life.proto";`) and reuses the game's types —
  `StepRequest`, `StepResponse`, `Grid` — rather than redeclaring them, so
  the log records real traffic and its leaves are shaped against the
  existing schema (spec 0387 S1). The import does not change what the
  server embeds: the build (`build.rs`, spec 0375) writes the one
  `FileDescriptorProto` of `life.proto` into the embedded blob and
  **not** `log.proto`'s FDP. So `protoscan life-server` finds only the
  life schema (which the audience already has from the client); the log's
  own container and `Request`/`Response` types — the file that imports —
  are absent, so `life.desc` derived from the client has no matching root
  for the log. The client is not changed and never links `log.proto`.

  The subtlety the import introduces: embedding `life.proto` alone is
  fine (it is already public), but the demo's premise is that the *log*
  type is unknown. Keep the build writing only `life.proto`'s single FDP,
  not a descriptor set that would transitively pull `log.proto` in.
  Confirm after the change that `protoscan life-server` surfaces exactly
  the `life.proto` descriptor and nothing from `log.proto` (test plan 3).

## Alternatives considered

### Reuse `StepRequest`/`StepResponse` as the log entries

The log could hold `repeated StepRequest`/`repeated StepResponse`,
reusing the existing types. Rejected: those types *are* in the client's
schema DB, so the audience would score them immediately and step 3's
"no schema for it" premise collapses. The log needs its own types, absent
from the client (G3).

### Write the whole log message each flush

Re-encoding the full message and overwriting the file each time always
ends on a clean field boundary, so `--decode_raw` would succeed and the
truncation demonstration (step 3) would be lost. S3's hold-back-the-last-
body-bytes invariant is the point.

### Flush everything on Ctrl-C (a signal handler / Drop)

A clean shutdown that flushed `carry` before exiting would leave a
*complete* log — the opposite of what step 3 needs. There is deliberately
no flush-on-exit: the truncation is the unwritten `carry`, so the plain
kill produces the artifact (G2). (If some run flushes cleanly anyway —
e.g. the OS buffers differently — the presenter can just kill mid-game;
but the half-carry makes that unnecessary.)

### Split the buffer at its byte-midpoint

A draft held back the second half of each step's bytes, so the tail
*usually* sat inside an entry. Rejected for certainty: a byte-midpoint
can land on an entry boundary, leaving a clean, fully-decodable file
exactly when the demo needs a truncated one. S3's "always keep the last
entry's body incomplete" is an invariant, not a probability, so the
truncation is guaranteed (G2).

### Put the log type in `life.proto` with a build flag to strip it

One proto file, with the log messages excluded from the embedded FDP at
build time. Rejected as more fragile than a separate `log.proto`: a
single file makes it too easy for the log type to leak into the embedded
blob (G4) or into a future `reproto` of the server. A separate file keeps
the exclusion structural, not a flag someone can forget.

## Test plan

1. `--log-file` writes a file; without it, no file is written and the
   stderr/stdout outputs (0375, 0377) are unchanged.
2. After the server is driven over several steps and killed (SIGINT),
   the file on disk is a truncated protobuf: `protoc --decode_raw <
   <file>` fails (the unwritten `carry`, G2/S3). The determinism is a
   unit test on the invariant, not a sample: after feeding 1, 2 and N
   Request+Response pairs through the buffer, the flushed bytes always
   end with a length prefix whose body is short by at least one byte, and
   `--decode_raw` fails on them for every entry size tried (including the
   smallest the server can emit).
3. `protoscan life-server` surfaces only `life.proto`'s descriptor, not
   the log type (G4). `reproto` of the client, and the derived
   `life.desc`, has no `Request`/`Response`/log type (G3).
4. `protolens --descriptor-set life.desc <file>` opens the log, finds no
   matching root type, and (with spec 0387's shaping) recognizes the
   `Request`/`Response` substructures by heat cues and reconstructs the
   record under pinned-type overrides even past the truncated tail
   (manual, step 3).
5. `smoke-test.sh`: a step-3 check runs the server with `--log-file`,
   drives it, kills it with SIGINT, and asserts `--decode_raw` fails on
   the left-behind file while `protolens` with overrides reads it.

## Measured outcome

Filled in at implementation.
