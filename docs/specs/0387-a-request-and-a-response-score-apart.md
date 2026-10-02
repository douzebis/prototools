<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0387 — a Request and a Response score apart

Status: draft
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
  is not enough. [[At implementation: pick the distinguishing fields from
  what the server actually has per step (0386 S2), then verify the score
  margin on a real captured log — adjust the shapes if the margin is
  thin.]]

- **S2. Distinguishing fields appear early (G3).** Put each type's
  distinguishing field at a low field number so the entry the kill cuts
  (spec 0386's half-flush leaves the tail entry truncated at an arbitrary
  byte) has already presented the field that tells the scorer which it
  is. A `Response` cut partway through still shows its distinguishing
  field if that field came first. Do not place a type's only
  distinguishing field last — the wrapped `StepRequest`/`StepResponse`
  payload, which is the bulk and the shared part, can come after it.

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

Filled in at implementation.
