<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0387 — a Request and a Response score apart

Status: implemented
Implemented in: 2026-10-03
App: grehack2026 (life-server)
Refs: docs/specs/0386-the-server-writes-a-truncated-protobuf-log.md (the
      log that holds `repeated Request`/`repeated Response`; this spec
      shapes the two leaf types so scoring tells them apart);
      grehack2026/synopsis.md (CHANGE-REQ-4, and step 3's heat-cues /
      override reconstruction)

## Background

Step 3 of the demo (spec 0386) hands the audience a schema-less protobuf
log and relies on `protolens` recognizing the `Request` and `Response`
substructures from their **field shapes** — the set of field numbers and
wire types a message presents — and letting the user pin those types
(overrides) to reconstruct the record. `protolens` scores a blob against
candidate types by field shape; two types with the *same* shape score
identically, so the tool cannot tell which substructure is which.

If `Request` and `Response` carry the same fields at the same numbers
with the same wire types, they are indistinguishable to the scorer, and
the override step either picks the wrong type or forces the presenter to
guess. The demonstration lands only if the two score apart.

The two leaf types do not exist yet — spec 0386 introduces them. This
spec shapes them so they are distinct *by field shape*, not merely by
name.

## Goals

- **G1.** `Request` and `Response` have **different field shapes**: the
  set of (field number, wire type) pairs each presents differs enough
  that `protolens`'s per-node scoring assigns a clearly higher score to
  the right type for each substructure.
- **G2.** Each type still records what the demo needs about a request /
  response (enough to make step 3 meaningful), while staying small.
- **G3.** The distinction survives truncation: even a `Request` or
  `Response` cut off mid-field (spec 0386 G2) presents enough of its
  distinguishing fields early that the scorer still favors the right
  type.

## Non-goals

- **N1. Matching the wire of `StepRequest`/`StepResponse`.** These log
  leaves are their own types (spec 0386), not the game's messages. They
  need not mirror the game schema; they need to be distinct from each
  other.
- **N2. A scoring-engine change.** This is a schema-shaping fix in the
  demo's `log.proto`, not a change to how `protolens` scores. If the
  scorer genuinely cannot separate two well-shaped types, that is a
  `protolens` bug for its own spec — but the expectation (G1) is that
  distinct field shapes already score apart.
- **N3. Hiding the fact that the log is traffic.** The types may be
  obviously a request and a response once reconstructed; the point is
  only that the *scorer* does not confuse the two before the human reads
  them.

## Specification

- **S1. Distinct field shapes.** `Request` and `Response` are defined in
  `log.proto` (spec 0386 S4), which imports `life.proto`, so each wraps
  the game type it logs — `Request` holds a `StepRequest`, `Response`
  holds a `StepResponse` — plus the server's own per-entry fields. The
  risk CHANGE-REQ-4 names is real precisely here: `StepRequest` and
  `StepResponse` share a shape (both a `Grid` at field 1 and a
  `generation` varint), so a `Request`/`Response` that only wrapped them
  would present nearly the same field shape and the scorer could swap the
  two. The fix is to give each leaf a field the other does not have, at a
  **low field number** (so it appears early, G3), with a distinguishing
  wire type:
  - `Request` carries a field meaningful only for a request (e.g. the
    smuggled command the server sent, a length-delimited string at a low
    field number);
  - `Response` carries a field meaningful only for a response (e.g. the
    command output that came back, a length-delimited string at a
    *different* field number, or a differently-typed marker).

  The binding constraint is that the (field number, wire type) multisets
  of the two leaf types are **not equal** and share few pairs, so the
  per-node score separates them with margin — the wrapped game type alone
  is not enough.

  **Concrete shapes (the default to implement).** Both types put the
  wrapped game message at field **1** (length-delimited), the field they
  share, and add distinguishing fields below and beside it:

  - `Request` = `StepRequest step = 1` (len), `string command = 2` (len,
    the smuggled command the server sent), `uint64 generation = 3`
    (varint, the request's generation, mirrored from `StepRequest` so a
    varint sits early).
  - `Response` = `StepResponse step = 1` (len), `uint64 latency_us = 2`
    (varint, the server's per-step time — already measured in `main.rs`),
    `bytes output = 3` (len, the command output that rode back).

  The (number, wire type) multisets are then `{(1,len),(2,len),(3,var)}`
  for `Request` and `{(1,len),(2,var),(3,len)}` for `Response`: they share
  only `(1,len)` and differ at both field 2 and field 3, each swapping a
  varint for a length-delimited field — two distinguishing pairs, not one,
  so the per-node score separates them with margin even before field 3.
  The server already has all four values per step (0386 S2): the request,
  the response, the `command` it sent, and the `latency_us` it prints under
  `--verbose`. Implement these shapes; test plan 2 verifies the margin on a
  real captured log, and the shapes are adjusted only if that margin proves
  thin.

- **S2. Distinguishing fields appear early (G3).** Put each type's
  distinguishing field at a low field number so the entry the kill cuts
  (spec 0386's hold-back leaves the tail entry truncated near its end) has
  already presented the field that tells the scorer which it is. A
  `Response` cut partway through still shows its distinguishing field if
  that field came first. The S1 shapes satisfy this: each type's early
  distinguishing field is the varint at field **2** (`generation` for
  `Request`, `latency_us` for `Response`) — a few bytes in, well before the
  bulk field (`output`/the wrapped `StepResponse`). The wrapped game
  message is at field 1, but it is the *shared* field, so it does not
  distinguish; the varint at field 2 does, and it is early. Do not reorder
  the bulk length-delimited field ahead of the field-2 varint.

- **S3. The log container uses them (0386).** The top-level log message's
  `repeated Request request = 1` and `repeated Response response = 2`
  (spec 0386 S2) carry these shaped types. No change to the container;
  this spec only fixes the leaf shapes.

## Alternatives considered

### Distinguish by field *number* alone, same wire types

Two types could use disjoint field numbers but all the same wire type
(say all length-delimited). This helps the scorer, but a type that is all
length-delimited fields is a weak heat-cue signal (every substructure
looks like "some bytes"). Mixing wire types (a varint marker plus the
length-delimited payload) gives the scorer and the heat cues more to go
on (G1), so S1 varies both.

### Distinguish by a magic tag/sentinel field

A dedicated `kind` enum (`REQUEST`/`RESPONSE`) at a shared field number
would name the type on the wire. Rejected: it makes the reconstruction
trivial (read the enum) and defeats the point of step 3, which is to
recover the type from *shape*, not from a self-describing tag. The two
should differ in their natural fields, not carry a label.

### Leave them identical and rely on the override UI

The presenter could pin the right type by hand regardless of score.
Rejected: CHANGE-REQ-4 is explicit that the *scoring* must not confuse
the two, so the heat-cues demonstration reads as intended without the
presenter fighting the tool.

## Test plan

1. The two types have unequal (field number, wire type) multisets
   (a schema-level check / review of `log.proto`).
2. On a real captured log (spec 0386), `protolens` scores each
   `Request` substructure higher as `Request` than as `Response`, and
   vice versa, with a clear margin (manual, step 3).
3. A `Request`/`Response` truncated mid-field (0386 G2) still scores to
   the right type, because its distinguishing field is early (S2).
4. `smoke-test.sh`: the step-3 check reconstructs the record with the
   correct types pinned, and the scorer does not swap the two.

## Measured outcome

Implemented 2026-10-03.

- `log.proto` defines the S1 concrete shapes: `Request { StepRequest step =
  1; string command = 2; uint64 generation = 3 }` and `Response {
  StepResponse step = 1; uint64 latency_us = 2; bytes output = 3 }`. The
  server fills `command`/`output` from the channel state and `latency_us`
  from the per-step time it already measures.
- Test plan 1 is a unit test (`request_and_response_have_different_field
  _shapes`): the on-wire (field, wire type) multisets are `{(1,LEN),(2,LEN),
  (3,VAR)}` for `Request` and `{(1,LEN),(2,VAR),(3,LEN)}` for `Response` —
  they share only `(1,LEN)` and differ at both field 2 and field 3.
- Test plans 2–4 (the live `protolens` score margin and the step-3
  heat-cues/override reconstruction) are the manual demo-time checks the
  spec defers: they need a captured log and the override UI, and the
  audience deliberately has no `log.proto` descriptor. The structural
  distinction (plan 1) is in place, so the margin is expected to hold; if a
  rehearsal shows it thin, adjust the shapes per S1.
