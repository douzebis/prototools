<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0385 — the smuggled payload is exactly the bytes

Status: implemented
Implemented in: 2026-10-03
App: grehack2026 (life-server, life-client)
Refs: docs/specs/0382-the-client-factors-the-servers-number.md (the
      exchange whose remnants this removes: the `factor`/`factors`
      messages, the awaited-N check, the stdout line);
      docs/specs/0383-the-number-42-runs-fortune.md (the `fortune `
      prefix and the 42 special case this removes);
      grehack2026/synopsis.md (CHANGE-REQ-2, and step 2's reading: the
      reconstructed bytes must be exactly the payload)

## Background

The demo (synopsis step 2) now frames the covert channel as
exfiltration: the server smuggles a shell command to the client, the
client runs it, and the output rides back the other way. The audience
reconstructs the smuggled bytes from the wire anomaly and maps them to
ASCII (the synopsis prints a lowercase-ASCII table for this). For that
reading to come out clean, the bytes on the wire must be *exactly* the
payload — no framing word, no special-cased number.

Two remnants of the earlier factoring exchange (specs 0382, 0383) still
sit in the payload and must go:

- **The `fortune ` prefix** on the client→server reply
  (`fortune_reply`, `parse_fortune_reply`). The reply is the command's
  output; the `fortune ` word is a leftover label. A listener
  reconstructing the response-side bytes gets `fortune whoami`'s output,
  not the output — nine stray bytes before the real thing.
- **The `42`/factorize special case.** `42` is still the one number that
  takes a factorization path (`FORTUNE_N`, `factorize(42, …)`), and the
  server still has a `factors …` branch that checks a factorization
  against an awaited N. In the exfiltration framing the server sends a
  command, not a number; the number path is dead weight that can surface
  `factors 2*3*7` instead of a command's output.

Confirmed in the tree: `fortune_reply` prepends `b"fortune "`;
`factoring.rs` holds `FORTUNE_N = b"42"` and factors it; the server's
`report_reply` still has the `factors …` / awaited-N branch and
`factors_are_right`.

## Goals

- **G1.** The client→server smuggled payload is exactly the command's
  output bytes: no `fortune ` prefix, nothing prepended or appended by
  the reply encoder.
- **G2.** No number is special-cased. Every server→client payload is
  treated the same way (run it as a command); there is no `42` branch, no
  factorization, and no awaited-N check on the reply.
- **G3.** The reconstructed bytes in the demo (both directions) are the
  literal payload, so the synopsis's ASCII table maps them with nothing
  to strip.

## Non-goals

- **N1. — none.** (The factoring library goes; see S5.)
- **N2. Changing the carrier.** The bit-field carrier is spec 0384's
  concern (plain VARINT fields). This spec changes only what bytes ride
  it.
- **N3. A newline/terminator convention change.** The framing (0377 S3a,
  the terminator bit) is unchanged; "exactly the bytes" means the
  *payload inside* the frame, not the frame.

- **N4. — none.** `life::factor` is deleted (S5), not kept unused.

## Specification

- **S1. The reply carries raw output.** `fortune_reply` /
  `parse_fortune_reply` lose the `fortune ` prefix: the reply is the
  command's output bytes, with the same control-byte handling as today
  (newlines kept, other ASCII control bytes → spaces, ends trimmed —
  spec 0383 S1, which stays, because it keeps a truncation cutting text
  not structure). Rename them to `command_output` /
  `parse_command_output` (or similar) so no caller reads `fortune` into
  the name. The empty output is the empty payload (today's `"fortune "`
  becomes the empty byte string).

- **S2. No special number.** Delete `FORTUNE_N` and the `n == FORTUNE_N`
  branch in `factoring.rs`: the worker runs every server→client payload
  as a command (spec 0380's `run_command`, `sh -c <payload>`) and sends
  the output back (S1). There is no factorization path in the client's
  smuggled-channel worker.

- **S3. The server prints what came back.** `report_reply` on the server
  drops the `factors …` branch, `factors_are_right`, and the awaited-N
  check: a reply is the command's output, printed as-is on stdout (the
  `Report::Stdout` path, step 2's terminal 1), with no N prefix and no
  label — exactly the raw bytes plus a trailing newline, which is what the
  current non-42 branch already emits (`report_reply(Some(b"360"), …)` →
  `Report::Stdout(b"be excellent\n")`). The step-2 narration confirms
  this: the worked example reconstructs `whoami` → the output, and "the
  answer surfaces on her terminal" is that stdout line. The one behavioral
  change here is that with the awaited-N check gone, output prints whenever
  *something* is awaited (any command was sent), not only when the awaited
  N is "not 42". The `Report::Stderr` note for "nothing was awaited" stays
  (a reply with no outstanding command is still noise worth flagging).

- **S4. The parsers no longer distinguish two reply kinds.** With the
  `factors …` reply gone, `is_reply` and the two-branch report collapse
  to one: every smuggled client→server message is command output. Remove
  `parse_factors_reply`, `factors_reply` and `render_factors` from the
  smuggled path.

- **S5. Delete `life::factor`.** The factoring module (spec 0382 S6:
  `mul_mod`, `is_prime`, `factorize`) and its tests are removed from the
  `life` crate, along with the last references to it (the client worker's
  factorization branch, the server's `factors_are_right` and the
  `factors …` parse/render). Nothing in the demo factors any more, so the
  code and its tests go with it; `git log` keeps spec 0382 and the module
  if either is ever wanted back.

## Alternatives considered

### Keep `42` as an Easter egg, drop only the prefix

CHANGE-REQ-2 asks for both: the prefix *and* the 42/factorize case. The
42 case produces `factors 2*3*7` on the wire, which the audience would
reconstruct as those literal bytes — demo noise exactly like the prefix.
Both go.

### Strip the `fortune ` prefix on the reading side only

The server (or a listener) could drop a known prefix after
reconstruction. Rejected: the point (G3) is that the wire bytes *are* the
payload, so the audience's reconstruction needs no post-processing. A
reader that has to know to strip `fortune ` is the problem, not the fix.

## Test plan

1. `life::tags`: the reply round-trips raw output bytes with no prefix;
   control-byte handling (0383 S1) is unchanged; the empty output is the
   empty payload.
2. `factoring.rs`: `start(b"42")` runs `42` as a command (like any other
   payload), not a factorization — there is no `FORTUNE_N` path.
3. Server `report_reply`: a reply is printed as the command's output;
   there is no `factors`/awaited-N branch.
4. `smoke-test.sh`: the step-2 check reconstructs the exact payload in
   both directions (e.g. `whoami` → the output, with no `fortune `
   prefix and no `factors …`).
5. The crate builds and its tests pass with `life::factor` and its
   tests gone (S5); nothing references the module.

## Measured outcome

Implemented 2026-10-03.

- `fortune_reply`/`parse_fortune_reply` → `command_output`/
  `parse_command_output`: the reply is the command's output bytes with no
  prefix (the `fortune ` label is gone, G1). Control-byte handling (0383
  S1) is kept; the empty output is the empty payload.
- `factoring.rs` → `command_channel.rs`, `Factoring` → `CommandChannel`:
  the worker runs every command via `run_command` (`sh -c <command>`) and
  returns its output. `FORTUNE_N` and the `factorize(42, …)` path are gone
  (G2). `run` passes the command straight to `run_command` (which already
  wraps `sh -c`), fixing the old double-wrap.
- Server `report_reply` takes a bool `awaited`: a reply is the command's
  output printed on stdout exactly (no N prefix, no label), or a stderr
  note when nothing was awaited. `factors_are_right`, `is_reply`,
  `parse_factors_reply`/`factors_reply`/`render_factors`, and `FORTUNE_N`
  are deleted (S3, S4).
- `life::factor` (the whole module and its tests) is deleted (S5); nothing
  references it, and the crate builds and tests pass without it.
- **Bug found and fixed:** the client abandoned its in-flight worker on the
  empty command the server sends every idle step, so the one real command's
  output was wiped before a request carried it back — the covert channel
  returned nothing end to end. `CommandChannel::start` now returns
  `Option<JoinHandle>` and is a no-op on an empty command, leaving the
  in-flight worker and any pending reply alone. Regression test:
  `a_stream_of_empties_does_not_wipe_a_pending_reply`. This bug predates
  these specs (inherited from the factoring worker) but only mattered once
  the round-trip was exercised end to end.
- Verified end to end (no `--verbose`): `whoami` → `experiment` on the
  server's stdout, with no `fortune`/`factors`/` = ` on the wire.
