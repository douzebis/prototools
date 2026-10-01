<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0379 — the tags carry an echo handshake

Status: implemented
Implemented in: 2026-10-01
App: grehack2026 (life-server, life-client)
Refs: docs/specs/0377-the-server-reads-the-tags-as-sent.md (the tag
      channel this makes bidirectional: the BitField, the terminator
      framing, read_tags/encode_tags, and the codec's two callbacks)

## Background

Spec 0377 built a one-way tag channel: the client hides `"Hello server!"`
in each request's field tags, the server reads it. The channel is already
symmetric in principle — the codec has an encode hook and a decode hook,
and either side can install either (0377 S2, S7) — but only the request
direction is used, and the message is a fixed constant.

This turns it into a two-way handshake over both directions:

- the **server** picks a fresh small random number *N* for each response
  and smuggles `"hello client <N>"` into the response's tags;
- the **client**, having read that *N*, smuggles `"hi server <N>"` into
  its **next** request's tags, echoing the number back;
- the **server** reads the echo and checks it against the *N* it last
  sent, logging `echo ok` or `echo mismatch`.

Nothing in the game changes: the numbers ride the tag encodings, the
field values are the grid and rules as before (0377 G3).

## Goals

- **G1.** Each response carries `"hello client <N>"` in its tags, *N* a
  fresh random integer 0..=255 rendered as decimal.
- **G2.** Each request carries `"hi server <N>"`, *N* the number read from
  the previous response — except the request has nothing to echo yet (the
  first request, or a response that smuggled nothing), which smuggles the
  empty message (G4).
- **G3.** The server checks each request's echo against the *N* it last
  sent and logs `echo ok` or `echo mismatch`, beside its per-request line.
- **G4.** A side with nothing to say sends the empty message — an
  all-canonical message, no tags set (0377 S3a). The first request, before
  any response, smuggles nothing; a request whose previous response
  carried no number smuggles nothing.

## Non-goals

- **N1. More than one client.** The server tracks a single "last *N*
  sent", so it assumes the one client of the workshop demo (the server is
  started per participant, 0375 S8). Two clients at once would cross their
  echoes and log mismatches; out of scope. A connection renewal (0375 S4)
  does *not* cross them — the echo is matched by value, and the server's
  state survives the renewal — so one client is always consistent.
- **N2. Cryptographic or framed numbers.** *N* is one small integer in a
  human-readable string, for the demo. No nonce discipline, no replay
  protection, no structured payload.
- **N3. Keeping the fixed `"Hello server!"`.** The request message becomes
  the echo (G2); the spec 0377 constant is replaced, not kept alongside.
- **N4. A new wire or schema change.** This rides spec 0377's channel
  unchanged: same BitField, same terminator framing, same codec. `cells`
  stays unpacked (0377 S1), so responses have enough tags too — a response
  carries a `Grid` and a generation, about as many field records as a
  request, far more than `"hello client 255"` needs.

## Specification

- **S1. Both sides install both callbacks.** The codec already exposes an
  encode callback and a decode callback (0377 S2, S7); this uses all four:
  - **server:** decode callback reads a request's tags (echo check, S4) —
    as 0377 already does, extended; encode callback writes
    `"hello client <N>"` into the response (S2).
  - **client:** decode callback reads a response's tags (the incoming *N*,
    S3); encode callback writes `"hi server <N>"` into the request (S3).

  The callbacks are `fn` pointers with no captures (0377), so the state
  they share — the server's last-sent *N*, the client's last-received *N*
  — lives in a small module static, set by one callback and read by the
  other.

- **S2. The server smuggles a fresh number per response.** On each
  response, the server picks a random `u8` *N*, frames
  `format!("hello client {N}")` (0377 S3a) into the response's tags
  (`encode_tags`, 0377 S6), and records *N* as the last sent. The random
  source is the same lightweight generator the client already uses for its
  grid fill (0375 S5, an xorshift seeded from the clock); no new
  dependency.

- **S3. The client echoes it in the next request.** The client's decode
  callback reads each response's tags (`read_tags` then `recover_message`,
  0377 S3, S3a) and, when the message matches `hello client <N>`, stores
  *N* as "to echo". The client's encode callback, on the next request,
  frames `format!("hi server {N}")` from that stored *N* if present, else
  the empty message (G4); it clears the stored value after use, so a
  request is echoed at most once and a dropped response does not echo
  stale.

- **S4. The server checks the echo.** The server's decode callback reads
  each request's message; when it matches `hi server <N>`, it compares *N*
  with the last *N* the server sent and logs `echo ok` (equal) or
  `echo mismatch (sent M, got N)`. A request with no echo (the empty
  message, G4) logs nothing. This is reporting only (0377 N1): the game is
  unchanged.

- **S5. Parsing is strict and total.** A recovered message is interpreted
  only when it is exactly `hello client <decimal 0..=255>` or
  `hi server <decimal 0..=255>`; anything else (a truncated or absent
  message) is treated as "no number", so a garbled exchange logs nothing
  rather than panicking. The two prefixes are distinct, so neither side
  mistakes one direction for the other.

## Alternatives considered

### Carry the number in a field value instead of the tags

A spare field, or the `generation`, could hold *N* in the clear. Rejected:
the whole point is the tag channel (0377) — the handshake must leave every
field value untouched (G3 of 0377), and ride only the canonical-or-not
choice. Using a value would also change what the game computes.

### The client stores a queue of pending echoes

The client calls one request at a time and waits for each response (0375
S5), so at most one *N* is ever pending. A single slot (S3), cleared on
use, is enough; a queue would be machinery for a concurrency the client
does not have (N1).

### The server keys last-sent N by connection

A per-connection map would be needed for multiple clients. It is not
needed for one: the echo is tied to its number by value, carried in the
message, not by connection or position, and the server's "last N sent" is
one shared value that a connection renewal (0375 S4) does not reset. So
request *k+1* echoes response *k*'s number and the server still holds that
number across a renewal — they match. The only thing that crosses echoes
is a second concurrent client (N1), which the single static does not
handle.

## Test plan

1. A unit test of the parse/format pair (S5): `"hello client 42"` and
   `"hi server 42"` round-trip through format and parse; out-of-range and
   malformed strings parse as "no number"; the two directions do not
   cross-parse.
2. A client/server round-trip unit test over `life::tags`: encode
   `"hello client 7"` into a response's tags, read it back, and confirm
   the recovered number is 7; same for `"hi server 7"` in a request.
3. In the image (a `grehack2026/smoke-test.sh` check): `life-client
   --steps N` drives the server; the server's stderr shows `echo ok` for
   all but the first exchange, and no `echo mismatch`. The first request
   carries no echo (G4).
4. The game still runs (0377 G3): the existing life smoke-test check still
   passes.

## Measured outcome

Measured 2026-10-01 on the x86-64 NixOS VM, release build.

**End to end.** `life-server` driven by `life-client --steps 6 --size
20x20`: the server logged five `echo ok` lines — the first request carries
no echo (G4), so six requests give five — each with a different random N
(254, 221, 171, 146, 85), no `echo mismatch`, no `nothing was sent yet`.
The client read each `"hello client <N>"` off the response and echoed
`"hi server <N>"` in the next request; the server matched them. The game
ran unchanged.

**Tests.** 38 crate tests pass, clippy clean. The parse/format pair round-
trips and is strict (out-of-range, malformed, non-UTF-8, and cross-
direction all parse as "no number"); the handshake round-trips through
both a response's tags and a request's tags, value-preserving (0377 G3);
`random_u8` varies. The image smoke test (spec 0379's check) passes:
`life-server` driven in the container shows five `echo ok` and no mismatch.

**Shared state.** The callbacks are `fn` pointers, so each side's state is a
module static — the client's `TO_ECHO` (one `u16` slot, `NONE` = no echo),
the server's `LAST_SENT`. The decode-side hook, once server-only, is now
installed by both sides (`set_decode_callback`); each process has its own,
so they do not cross. Sizing: `"hello client 255"` / `"hi server 255"` are
at most 129 bits with the terminator; a 20×20 message has ~420 field
records (N4), so both fit.
