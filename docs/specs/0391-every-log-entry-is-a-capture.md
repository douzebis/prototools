<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0391 — every log entry is a Capture

Status: draft
App: grehack2026 (life-server, teleprompt deck, beats)
Refs: docs/specs/0386-the-server-writes-a-truncated-protobuf-log.md (the
      log, its append-only framing and its always-truncated tail, all
      kept);
      docs/specs/0387-a-request-and-a-response-score-apart.md (the two
      entry types this spec replaces with one);
      docs/specs/0384-smuggle-through-plain-varint-fields.md (the
      non-canonical varints G5 keeps);
      docs/specs/0385-the-smuggled-payload-is-exactly-the-bytes.md (the
      command and its output, which `contraband` holds);
      docs/specs/0388-the-demo-runs-from-grehack2026.md (section 3 of the
      deck, which reads the log)

## Background

The server's traffic log (spec 0386) is a `LogFile` with two repeated
fields of two different types: `Request` entries at field 1 and
`Response` entries at field 2. Spec 0387 shaped those two types so that
their field shapes differ and scoring tells them apart.

The log is easier to present as one kind of record. A single entry type
also makes the section-3 reveal more direct: every entry has the same
layout, so once the audience understands one, they understand the file.

## Goals

- **G1.** Every log entry is a `Capture`, at one field of `LogFile`:
  `repeated Capture capture = 42`.
- **G2.** `Capture` has four optional fields:
  `StepRequest request = 1`, `StepResponse response = 2`,
  `uint64 generation = 3`, `string contraband = 666`.
- **G3.** One `Capture` per message on the wire: each step logs a
  request capture, then a response capture.
- **G4.** `contraband` is what the logged message itself hid: the
  command, in the capture of the response that smuggled it; the command's
  output, in the capture of the request that brought it back. Absent when
  the message hid nothing.
- **G5.** The log is faithful to the wire: each capture's
  `StepRequest`/`StepResponse` is the exact bytes that crossed the
  network, non-canonical varints included.

## Non-goals

- **N1.** No change to the framing or the truncation discipline of spec
  0386: entries are still appended as `tag || length || body`, and the
  file still always ends one byte short of a complete entry.
- **N2.** The log's descriptor is still not embedded in any binary (spec
  0386 G4). `Capture` is as unknown to the audience as the old types were.
- **N3.** Nothing replaces spec 0387's "the two types score apart":
  there is one type now.

## Specification

- **S1. `log.proto`.** In package `grehack.life.v1.log`:

  ```proto
  message Capture {
    optional grehack.life.v1.StepRequest  request    = 1;
    optional grehack.life.v1.StepResponse response   = 2;
    optional uint64                       generation = 3;
    optional string                       contraband = 666;
  }

  message LogFile {
    repeated Capture capture = 42;
  }
  ```

  `Request` and `Response` are removed. The scalars use proto3's
  `optional`, so a generation of 0 is still written, and an absent
  `contraband` means "nothing hidden", not "an empty string was hidden".

- **S2. What each step logs.** For a step with request `q` and response
  `r`, two captures, in this order:
  - `Capture { request: q, generation: q.generation, contraband: the
    output q brought back, if any }`;
  - `Capture { response: r, generation: r.generation, contraband: the
    command r smuggled, if any }`.

  The output is bytes (the command's stdout, exactly, spec 0385);
  `contraband` is a protobuf `string`, which must be UTF-8, so the output
  is stored through `String::from_utf8_lossy`. Short shell output such as
  `whoami`'s is UTF-8 already and is unchanged.

- **S2a. When a step is logged.** The step is logged when its response
  is *encoded*, not in the handler. tonic encodes a response only after
  the handler returns, and the encode callback (`tags::on_response`) is
  where the server picks the command the response smuggles. Logging in
  the handler would therefore give each response capture the previous
  response's command. The handler leaves the step in a one-slot
  `PENDING_STEP`, and the server's encode callback, `encode_and_log`,
  runs `tags::on_response`, then logs. One slot suffices because the
  client has one call in flight at a time. The old log (spec 0387's
  `Request.command`) had the same off-by-one.

  `tags::last_output` is reset on every request, so a request that hid
  nothing logs no contraband. Before, it was only set when a request
  carried a reply, so every later request would have repeated it.

- **S2b. The messages are the wire bytes.** A capture's `request` or
  `response` field holds, as its body, the message's bytes exactly as
  they crossed the network: the request as the server received it (the
  decode callback's input, kept by the server's `decode_and_keep`; the
  codec hands that callback the whole message, `src.chunk()`, as the
  covert channel already relies on, spec 0377 S2), the
  response as the server sent it (what `tags::on_response` returns).
  Re-encoding a decoded message would write it canonically and erase
  the covert channel's non-canonical varints (spec 0384). So the
  captures are encoded by hand (`log::captures_for_step`): field 1 or 2
  framed around the wire bytes, then `generation`, then `contraband` if
  any, in field-number order. The result is still a valid `Capture`:
  protobuf accepts non-canonical varints, so the embedded message
  decodes to the same values.

- **S3. Framing.** Both captures are framed at field 42. The tag is then
  two bytes (`0xd2 0x02`) rather than one. The response capture is the
  last entry of a step, so it is the one whose final body byte is held
  back (spec 0386 S3). It is never empty, since it always carries a
  `StepResponse`.

- **S4. The deck (section 3).** The narration after protolens no longer
  names `Request` and `Response`. It says that the heat cues recognize
  the game's own `StepRequest` and `StepResponse` inside each entry,
  that overrides pin them, and that an entry may also carry a string
  field the client's schema knows nothing about.

- **S5. `beats/logfile`.** The reminders follow S4: one kind of entry,
  the `StepRequest`/`StepResponse` substructures recognized by the heat
  cues, and the unknown string field to look at.

- **S6. Docs.** `synopsis.md` section 3 follows the deck.
  `log.proto`'s header comment describes `Capture`.

## Alternatives considered

### One capture per step, with both messages

Half as many entries, but then `contraband` would hold two payloads
travelling in opposite directions, and `request`/`response` would never
be optional in practice. Decided against with the user (2026-10-04).

### `bytes contraband`

Would keep the output byte-exact, but the field is meant to read as text
when someone finally decodes it, and the demo's payloads are text. A
`string` field shows as text in protolens even without a schema.

## Test plan

1. `log.rs`: `the_entry_is_tag_length_body` with field 42 (a two-byte
   tag), and `the_on_disk_file_is_always_a_truncated_protobuf` with two
   captures per step.
2. `a_step_logs_a_request_capture_then_a_response_capture`: the two
   captures, in order, decode as `Capture` with the right fields set and
   `contraband` only where the message hid something.
3. `a_capture_keeps_the_wire_bytes_verbatim`: a request whose varint is
   non-canonical is embedded byte for byte, and the capture still
   decodes to the same `StepRequest`.
4. `smoke-test.sh`'s spec 0386 check still passes (`protoc
   --decode_raw` fails on the log; protoscan finds no `log.proto` in the
   server).
5. By hand, after a `whoami` exchange: `protoc --decode_raw` fails on
   the log; `prototext decode --raw` shows field 42 entries, whose field
   666 holds `whoami` in a response capture and `experiment` in a later
   request capture; and exactly those two captures show non-canonical
   varints (`ohb`) inside their embedded message (G5).

## Measured outcome

Filled in at implementation.
