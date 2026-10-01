<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0379 — the tags carry an echo handshake

Status: implemented
Implemented in: 2026-10-01
App: grehack2026 (life-server, life-client)
Amended by: docs/specs/0382-the-client-factors-the-servers-number.md
        (the payload becomes "factor <N>" / "factors ..."; S2's stdin
        reader, S7 and S8 stay)
Refs: docs/specs/0377-the-server-reads-the-tags-as-sent.md (the tag
      channel this makes bidirectional: the BitField, the terminator
      framing, read_tags/encode_tags, and the codec's two callbacks);
      docs/specs/0375-a-game-of-life-to-spy-on.md (the server's flags and
      its per-request log line, S4, which S7 here puts behind
      `--verbose`); 0377 S5 (the raw bit field on stdout, also put
      behind `--verbose` by S7)

## Background

Spec 0377 built a one-way tag channel: the client hides `"Hello server!"`
in each request's field tags, the server reads it. The channel is already
symmetric in principle — the codec has an encode hook and a decode hook,
and either side can install either (0377 S2, S7) — but only the request
direction is used, and the message is a fixed constant.

This turns it into a two-way handshake over both directions:

- the **server** operator types a number *N* (0..=255) on the server's
  stdin, while the game is being served; the server smuggles
  `"hello client <N>"` into the next response's tags;
- the **client**, having read that *N*, smuggles `"hi server <N>"` into
  its **next** request's tags, echoing the number back;
- the **server** reads the echo and checks it against the *N* it last
  sent, logging `echo ok` or `echo mismatch`.

Nothing in the game changes: the numbers ride the tag encodings, the
field values are the grid and rules as before (0377 G3).

## Goals

- **G1.** *N* comes from the operator, not from the server: the server
  reads its stdin concurrently with serving the game RPCs, and when a
  line holding an integer 0..=255 arrives, the **next** response carries
  `"hello client <N>"` in its tags, *N* rendered as decimal. Each
  accepted number is sent once (S2); a response with no number pending
  smuggles the empty message (G4).
- **G2.** Each request carries `"hi server <N>"`, *N* the number read from
  the previous response — except the request has nothing to echo yet (the
  first request, or a response that smuggled nothing), which smuggles the
  empty message (G4).
- **G3.** The server checks each request's echo against the *N* it last
  sent and logs `echo ok` or `echo mismatch`, beside its per-request line.
- **G4.** A side with nothing to say sends the empty message — an
  all-canonical message, no tags set (0377 S3a). The first request, before
  any response, smuggles nothing; a request whose previous response
  carried no number smuggles nothing; a response sent while no operator
  number is pending smuggles nothing.
- **G5.** The server sanity-checks what the operator types: only an
  integer 0..=255 is accepted (S6); anything else is rejected with a note
  on stderr, and the game is never disturbed by bad input.
- **G6.** The server's terminal stays readable while the game runs:
  nothing is printed once per request unless `--verbose` is given (S7).
  That covers the per-request line on stderr (time, peer, grid size,
  generation, time spent; 0375 S4) and the raw bit field on stdout
  (0377 S5). The operator sees their own notes and the echo results, not
  one or two lines per generation.
- **G7.** The server can also start echoes on its own: with
  `--self-echo-percentage P`, each response that has no operator number
  waiting carries a random `"hello client <N>"`, *N* 0..=255, with
  probability P %. P = 0, the default, means never (S8).

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
- **N5. An interactive console.** The stdin reader takes one number per
  line, nothing else: no prompt, no line editing, no commands. stdout
  stays reserved for the raw bit fields (0377 S5), so the server prints
  no prompt there; its acknowledgements go to stderr (S6).

- **N6. A finer log level.** `--verbose` is a single on/off switch for
  both per-request outputs (S7). There are no log levels, no `-vv`, no
  filtering by peer or by message.
- **N7. A random stream that can be reproduced.** Spontaneous echoes
  (S8) use the same clock-seeded generator as before. There is no seed
  flag: the demo needs numbers that vary, not runs that can be replayed.

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

- **S2. The server smuggles the operator's number, once.** A one-slot
  static, `PENDING` (a `Slot`: an atomic `u16` with a `NONE` sentinel,
  the same type as `LAST_SENT`), holds the number the operator last entered
  and the server has not yet sent. The stdin reader (S6) stores into it;
  the server's encode callback, on each response, **takes** it (swap with
  `NONE`): if a number *N* was pending, it frames
  `format!("hello client {N}")` (0377 S3a) into the response's tags
  (`encode_tags`, 0377 S6) and records *N* as the last sent; if none was,
  it sends the empty message and leaves the last sent unchanged, so the
  echo check (S4) still holds the number the client is about to echo.

  Each number is sent once — on the first response after it is entered —
  and echoed once (S3), so one entry gives one `echo ok`. A number entered
  while another is still pending replaces it: the slot holds the latest
  entry, not a queue. The random draw (`life::tags::random_u8`) had no
  other user and is removed.

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

- **S6. The server reads N from stdin, beside the RPCs.** At startup,
  before serving, the server spawns a dedicated `std::thread` that reads
  stdin line by line (blocking `BufRead::lines` on `stdin().lock()`) for
  the life of the process. The tokio runtime serving the RPCs is not
  involved, so the game is served while the thread waits on input, and a
  slow operator never delays a step.

  Each line is sanity-checked, after trimming surrounding whitespace:
  - an **empty** line is ignored silently;
  - a line of one to three ASCII digits whose value is 0..=255 is
    **accepted** (leading zeros allowed: `007` is 7; the smuggled text
    uses the canonical decimal, S2): stored into `PENDING`, and
    acknowledged on stderr (`N=7 queued for the next response`);
  - anything else — a sign (`+5`, `-1`), a non-digit, a value above 255,
    more than three digits — is **rejected**: nothing is stored, and
    stderr says so (`rejected "abc": want an integer 0..=255`).

  The check is a small pure function (`parse_operator_n(&str) ->
  Option<u8>`, tested, S5's strictness) so the thread holds only the I/O.
  End of file on stdin (the server started with `</dev/null`, or in the
  background of a non-interactive shell) ends the thread quietly: the
  server keeps serving, and simply never smuggles a number. A read error
  does the same, after one note on stderr.

- **S7. `--verbose` gates the per-request output.** `life-server` gains
  `--verbose` (short `-v`), off by default. Without it, the server prints
  nothing once per request; with it, it prints, as before:
  - on stderr, the `Step` handler's per-request line
    (`HH:MM:SS.mmm <peer> <W>x<H> generation <G> in <T> µs`, 0375 S4);
  - on stdout, each request's raw bit field and its newline (0377 S5).
    The tags are still read on every request regardless of the flag,
    because the echo check (S4) needs them; only the write is skipped.

  This amends 0375 S4 and 0377 S5, which printed both unconditionally.
  Without `--verbose`, stdout stays empty. Everything else on stderr is
  printed regardless: the startup `serving …` line, `shutting down`, a
  `refused: …` line for a request rejected as invalid (rare, and worth
  seeing), the operator's `queued` and `rejected` notes (S6), and the
  echo results (S4). The flag is stored once in a module static (an
  `AtomicBool`) before serving starts, because the decode callback that
  writes the bit field is a capture-less `fn` pointer (S1).

- **S8. `--self-echo-percentage P`: spontaneous echoes.** `life-server`
  gains `--self-echo-percentage P`, an integer 0..=100, default 0. clap
  checks the range at startup, so `101` or `-1` is a usage error and the
  server does not start. P is stored once in a module static (an
  `AtomicU8`) before serving starts, because the encode callback is a
  capture-less `fn` pointer (S1).

  On each response, the encode callback chooses the number to send in
  this order:
  1. **An operator number is pending:** it is sent, as in S2. The
     operator always wins, and no roll is made.
  2. **Otherwise, roll:** with probability P % (a uniform draw in 0..100
     below P), the server picks a random *N* 0..=255 and sends
     `"hello client <N>"` exactly as it would an operator number: it
     records *N* as the last sent, so the echo check (S4) treats both
     kinds the same.
  3. **Otherwise:** the empty message (G4).

  So P = 0 never sends spontaneously, and P = 100 sends on every
  response with nothing pending. A spontaneous *N* is sent once, like
  any other: the next response rolls again. Under `--verbose` the server
  logs `  N=<N> sent spontaneously`; without it there is no note, and the
  `echo ok (<N>)` that follows (S4) is what shows the exchange.

  Spontaneous and operator echoes interleave without a mismatch. Each
  request's echo is checked (decode callback) before the response to
  that request is built (encode callback), so the last sent still holds
  the number that request answers. The client has no way to tell the two
  kinds apart, and does not need one.

  The random source is the generator removed by S2, brought back in the
  server's own `tags.rs` (it is server-only): an xorshift seeded from the
  clock (as in 0375 S5), its state kept in one `AtomicU64` so all tokio
  worker threads draw from a single stream. It yields both the
  percentage roll and *N*. To keep the S2 tests deterministic,
  `response_message` takes the roll as an argument: a closure that
  returns the spontaneous *N*, or none.

## Alternatives considered

### Send the per-request output to a file instead

A log file is one more thing to tell participants to `tail`, and
nothing reads the bit fields back (0377 N4). One flag that is off by
default makes the quiet case the normal one, and `--verbose` restores
the 0375 and 0377 output when someone wants to see the traffic.

### A separate flag for each output

Two switches (one for the stderr line, one for the stdout bytes) were
considered. Both are per-request noise with the same audience, someone
watching the traffic, so one flag covers both and there is one thing to
remember.

### Self-echo on a timer instead of per response

A timer cannot push anything: the server speaks only in responses (the
tag channel rides the RPC), so a "timed" echo would still wait for the
next response. A per-response probability is the natural unit, and its
rate grows with the client's step rate, which is what the participant
watching the traffic sees.

### A random N per response (the first implementation)

The server drew a fresh random *N* for every response. Replaced: the
workshop wants the operator to choose what crosses the channel and to
see that number come back, which a random draw does not show. With the
operator in charge, a response with nothing chosen carries nothing (G4),
which also shows that the channel is silent unless used.

### Re-send the operator's N on every response until a new one arrives

Rejected for send-once (S2): the client echoes each number once (S3), so
a sticky *N* would give an `echo ok` on every step and drown the one
exchange the operator caused. Send-once makes one entry produce exactly
one `hello client`, one `hi server`, one `echo ok`.

### Read stdin on the tokio runtime (`tokio::io::stdin`)

It works, but tokio's stdin is itself a blocking read on a background
thread; a plain `std::thread` says so directly, needs no task plumbing
into the server's `main`, and keeps the reader out of the RPC runtime.

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
3. In the image (a `grehack2026/smoke-test.sh` check): the server is fed
   its stdin through a pipe that, after the server is up, writes a
   rejected line (`300`), then an accepted one (`42`), then holds the
   pipe open; `life-client --steps 6` drives it. The server's stderr shows
   the rejection, the `queued` note, exactly one `echo ok (42)`, and no
   `echo mismatch`. A run with stdin at end of file (`</dev/null`) serves
   all steps and logs no echo (S6).
4. The game still runs (0377 G3): the existing life smoke-test check still
   passes.
5. A unit test of `parse_operator_n` (S6): `0`, `255`, `007`, ` 42 `
   accepted; `256`, `-1`, `+5`, `4 2`, `0x10`, `1000`, `abc` rejected;
   the empty line is distinguished from a rejection (ignored, no note).
6. A unit test of the send-once slot (S2): with no number pending, the
   encode callback sends the empty message and leaves the last sent
   unchanged; after one store, the next response carries `hello client
   <N>` and the one after carries nothing; two stores before a response
   send only the latter.

7. A unit test of S8's order: a pending operator number is sent and
   the roll is not called; with nothing pending, a roll that returns *N*
   sends `"hello client <N>"` and records *N* as the last sent; a roll
   that returns none sends the empty message. A test of the roll itself:
   P = 0 never fires and P = 100 always does, over many draws.
8. In the image (`smoke-test.sh`): `life-server --self-echo-percentage
   100 </dev/null` driven by `life-client --steps 6` logs five
   `echo ok` and no mismatch (the first request has nothing to echo,
   G4); `--self-echo-percentage 101` is refused at startup. The
   `/dev/null` run of test plan 3, at the default P = 0, still logs no
   echo.
9. S7: without `--verbose`, the server's stderr has no ` generation `
   line and its stdout is empty, while the echo still works (the tags
   are read regardless). With it, there is one ` generation ` line and
   one bit-field line per request. Folded into the existing smoke-test
   runs: test plan 3's count of six stdout lines now runs the server
   with `--verbose`.

## Measured outcome

Measured 2026-10-01 on the x86-64 NixOS VM, release build.

**The operator's N (S2, S6).** With the server's stdin on a FIFO, the
lines `300`, `abc`, an empty line and `42`, then `life-client --steps 4`:
the server logged `rejected "300"`, `rejected "abc"`, nothing for the
empty line, `N=42 queued for the next response`, and exactly one
`echo ok (42)` over the four exchanges. Responses with nothing pending
carried the empty message, so the next requests carried no echo. With
stdin at `/dev/null` the server served every step and logged no echo.
The image smoke test (test plan 3, both the piped and the `/dev/null`
runs) passes, with all 14 checks green.

**Tests.** Four server tests
cover `parse_operator_n` (accepts `0`, `255`, `007`, ` 42 `, a trailing
`\r`; rejects `256`, `-1`, `+5`, `4 2`, `0x10`, `1000`, `0255`, `abc`, a
non-ASCII digit), the empty line ignored versus rejected, and the
send-once slot (S2), using local `Slot`s rather than the process statics.

**`--verbose` and spontaneous echoes (S7, S8).** A server run with
`-v --self-echo-percentage 50`, `42` typed on stdin, and `life-client
--steps 12`: `42` was echoed first, then 6 spontaneous numbers were sent
in the 11 responses that followed, each logged `N=<N> sent
spontaneously` and echoed `ok`, with no mismatch; 12 ` generation `
lines on stderr and 12 bit-field lines on stdout. Without `--verbose`
the server prints neither, and stdout stays empty. The image smoke test
passes with all 15 checks green: the operator check now runs with
`--verbose` and counts 6 of each per-request line, the `/dev/null` run
checks the quiet default, and a new check finds 5 `echo ok` at
`--self-echo-percentage 100` and has `101` refused at startup. 52 crate
tests pass, clippy clean. The new tests cover the operator number winning
without a roll, a rolled N sent and recorded like an operator number,
P = 0 never and P = 100 always firing over 1000 draws, and draws that
vary.

**The handshake (S1, S3–S5).** The parse/format pair round-trips and is
strict (out-of-range, malformed, non-UTF-8, and cross-direction all parse
as "no number"); the handshake round-trips through both a response's tags
and a request's tags, value-preserving (0377 G3).

**Shared state.** The callbacks are `fn` pointers, so each side's state is a
module static — the client's `TO_ECHO` (one `u16` slot, `NONE` = no echo),
the server's `PENDING` and `LAST_SENT` (two `Slot`s, S2). The stdin thread
(S6) shares only `PENDING` with the callbacks. The decode-side hook, once server-only, is now
installed by both sides (`set_decode_callback`); each process has its own,
so they do not cross. Sizing: `"hello client 255"` / `"hi server 255"` are
at most 129 bits with the terminator; a 20×20 message has ~420 field
records (N4), so both fit.
