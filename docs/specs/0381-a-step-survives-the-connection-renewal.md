<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0381 — a step survives the connection renewal

Status: implemented in part — S1, S2, S4 and S5 are done; a second
        failure measured afterwards (hyper "canceled", see Measured
        outcome) is open, and test plan item 4 waits on it
Implemented in: 2026-10-01 (S1, S2, S4, S5)
App: grehack2026 (life-client)
Refs: docs/specs/0375-a-game-of-life-to-spy-on.md (S4: the server renews
      each connection after `--max-connection-age`, for the spy; S5: the
      client's one-call-at-a-time loop and its headless `--steps` mode);
      docs/specs/0378-the-life-server-stops-panicking-on-connection-age.md
      (the server-side renewal bug, fixed; this is a client-side one);
      docs/specs/0379-the-tags-carry-an-echo-handshake.md (S3: the client's
      `TO_ECHO` slot, which a retry must not lose)

## Background

`life-server` closes each connection after `--max-connection-age` (default
10 s, spec 0375 S4) so a spy started mid-connection soon sees a full one.
The client reconnects on its own. A step that races a renewal can fail
without the server having computed it, so `Game::step` retries it once,
but only when `is_transport` (`life-client/main.rs`) recognizes the
failure: code `Unavailable`, or `Unknown` with "transport error" in the
message.

A failure it does not recognize stops the game. Left running in the TUI
at 10 gen/s on a 106×61 grid, the client paused at generation 5904 with:

```
error: calling /grehack.life.v1.Life/Step: Internal: h2 protocol error: http2 error
```

With `--max-connection-age 1` the same error came back at generation
6201. These two runs do not settle the cause. Ten times as many renewals
did not make the failure visibly sooner, which a race on each renewal
would predict, but one run of each is too few to measure a rate. The
renewal is the leading suspect because it is the one thing in this setup
that closes connections. A large request (a 106×61 grid is about 6500
unpacked cells) running into an HTTP/2 limit is the other candidate. S3
settles it by measurement before any retry is added.

How tonic builds that status (`tonic/src/status.rs`, at the pinned commit
of spec 0378):

- The message is `"h2 protocol error: "` followed by hyper's text for the
  error, which for every HTTP/2 failure is just `"http2 error"`. It says
  nothing about the cause.
- The code comes from the HTTP/2 reason (`code_from_h2`). `Internal`
  covers NO_ERROR, which is how a graceful close is reported, and also
  PROTOCOL_ERROR, INTERNAL_ERROR, FLOW_CONTROL_ERROR, SETTINGS_TIMEOUT,
  FRAME_SIZE_ERROR, COMPRESSION_ERROR and CONNECT_ERROR, which would be
  real bugs. Neither the code nor the message tells a renewal from a bug.
- The original error survives: `Status::source()` returns it, and its
  chain of underlying errors (`Error::source`) leads down through the
  `hyper::Error` to the `h2::Error`. That type reports the reason
  (`reason()`), whether it came from a GOAWAY or a stream reset
  (`is_go_away()`, `is_reset()`), and whether the server sent it
  (`is_remote()`).

A second defect sits in the existing retry. The client's encode callback
empties `TO_ECHO` when it builds a request (spec 0379 S3), so the retried
request carries no echo. Each retry that happens today silently drops one
`hi server <N>`.

## Goals

- **G1.** A step that fails because it raced a connection renewal is
  retried, and the game keeps running. A client left at 10 gen/s against
  `--max-connection-age 1` no longer stops with this error.
- **G2.** Any other HTTP/2 failure is not retried and still stops the game
  with an error, as it does today.
- **G3.** When a step fails, its error says which HTTP/2 condition caused
  it, so the next unexplained failure can be diagnosed from the status
  line alone.
- **G4.** A retried step carries the same echo as the attempt it replaces.

## Non-goals

- **N1. More than one retry, or a backoff.** The retry goes out on a new
  connection. Losing the race twice in a row means something else is
  wrong, and that should be shown, not hidden by further attempts.
- **N2. Changing the server.** The renewal is needed for the spy (spec
  0375 S4), and nothing on the server side closes the window (see
  Alternatives). The fix is client-side only.
- **N3. A response lost after the server handled its request.** If the
  server handled the first attempt and only its response was lost, the
  retry is still correct for the game: Step is a pure computation. But the
  echo handshake may then log one `echo mismatch`. In that case, the
  server may already have put a new N into the lost response and recorded
  it as the last sent, so the re-sent echo answers an older number. A
  GOAWAY that refuses a request, or a REFUSED_STREAM, means the server did
  not handle it (RFC 9113 §6.8 and §8.7), so this case cannot arise from
  them. It is accepted, not handled.
- **N4. Retrying in other gRPC clients of this repo.** The only other
  one, bobapp (`demo/bobapp`, spec 0241), makes a single call. It does
  not run a long call loop against a renewing server. (`life-spy`
  captures traffic and makes no gRPC calls.)

## Specification

- **S1. Find the HTTP/2 error behind a status.** A helper
  `h2_error(&tonic::Status) -> Option<&h2::Error>` follows the chain from
  `Status::source()` and returns the first error that downcasts to
  `h2::Error`. This needs `h2 = "0.4"` as a direct dependency of the life
  crate. It is already in the lock file (0.4.19, through hyper and tonic),
  so the build fetches nothing new and the image's closure does not change.
  The direct dependency must stay in the same semver range as hyper's, or
  the downcast silently fails: the two would then be different types. A
  comment next to the dependency says so.

- **S2. Name the HTTP/2 condition in the error (G3).** When a step finally
  fails, the error text gains a bracketed note built from S1's
  `h2::Error`, if there is one:
  `[h2 <kind> <REASON> <origin>]`, where
  - kind is `GOAWAY`, `RST_STREAM`, `reason` (a bare reason), or `io`;
  - REASON is the reason's `Debug` form (`NO_ERROR`, `REFUSED_STREAM`, …),
    omitted for `io`;
  - origin is `remote` (`is_remote()`), `library` (`is_library()`), or
    `local`.

  For example:
  `error: calling /grehack.life.v1.Life/Step: Internal: h2 protocol error:
  http2 error [h2 GOAWAY NO_ERROR remote]`. The text is the same in the
  TUI's status line and in headless mode's error exit.

- **S3. Measure before narrowing (G1, G2).** S2 is built first, and the
  reproduction is run: `life-server --max-connection-age 1`, the client
  in the TUI on a 106×61 grid at 10 gen/s until it fails. S2 then shows the condition the
  race produces. The measured condition is recorded in this spec's
  measured outcome, and S4's renewal case is narrowed to it. The
  candidates, in order of expectation:
  - GOAWAY, NO_ERROR, remote: the server's graceful close refused a
    request sent at the same moment. The server never handled it.
  - RST_STREAM, REFUSED_STREAM, remote: same, per stream. tonic maps it
    to `Unavailable`, which `is_transport` already retries, so this one is
    unlikely to be the observed failure.
  - RST_STREAM, NO_ERROR, remote: the server reset the stream while
    closing. The server may have handled the request (N3).

  A GOAWAY from the server confirms the renewal as the cause, because
  this server sends GOAWAY only when it closes a connection: at renewal
  or at shutdown. If the measurement shows something outside this list,
  the cause is not the renewal (for example a FLOW_CONTROL_ERROR or
  FRAME_SIZE_ERROR, pointing at the request's size). In that case the
  implementation stops after S2, which is useful on its own, and this
  spec is revised before going further.

- **S4. Retry only a renewal race (G1, G2).** `is_transport` is replaced
  by `is_renewal_race(&Status) -> bool`, true in two cases:
  - **today's cases, unchanged:** code `Unavailable`, or code `Unknown`
    whose message contains "transport error";
  - **the measured case (S3):** S1 finds an `h2::Error` that the server
    sent (`is_remote()`) and that matches the kind and reason S3
    measured.

  Everything else is not retried. That includes every other HTTP/2
  reason, any error h2 raised on its own (`is_library()`), and an
  `Internal` status with no `h2::Error` in its chain. These still stop
  the game with S2's note. A doc comment on `is_renewal_race` records the
  measured condition and points here.

- **S5. A retry carries the same echo (G4).** `Game::step` reads
  `TO_ECHO` before the first attempt. Before the retry, it stores that
  value back into the slot, so the retry's encode callback frames the
  same `hi server <N>`. Putting it back is correct because a failed
  attempt has no response, so the client's decode callback did not run
  and nothing newer is in the slot. This applies to every retry,
  including today's `Unavailable` ones, which have the same defect.
  `TO_ECHO` and `Game::step` are both in `life-client/main.rs`, so this
  needs no new interface.

- **S6. Still one retry (N1).** If the retry also fails, its error is the
  one shown, with S2's note.

## Alternatives considered

### Match on the status code or message text

Retrying every `Internal`, or every message containing "h2 protocol
error", is a one-line change. Rejected: `Internal` also carries
PROTOCOL_ERROR, FLOW_CONTROL_ERROR and other real faults, and the message
is the same `"http2 error"` for all of them. The retry would hide genuine
protocol bugs (against G2). The chain holds the exact condition (S1), so
there is no reason to guess from text.

### Disable or lengthen `max_connection_age`

Without renewal, a spy started late never sees a full connection (spec
0375 S4). A longer age only makes the failure rarer, which makes it
harder to diagnose when it does happen.

### A server-side setting

tonic's only other setting here, `max_connection_age_grace`, bounds how
long a graceful close may take before it is forced. It is unset, so the
close already waits for every request in flight; setting it could only
add forced closes. The graceful close itself uses GOAWAY. The window that
remains is a request sent on a connection the server has started to
close. That is inherent to closing a connection the client is actively
using, and the HTTP/2 and gRPC answer is for the client to retry a
request the server refused (gRPC calls this "transparent retry").

### Retry inside the codec or with tower middleware

A retry layer below the client stub would be hidden from the echo
handling and would need the request body re-encoded through the encode
callback anyway. `Game::step` already holds the request, already retries,
and is next to `TO_ECHO` (S5). The fix belongs there.

## Test plan

1. `h2_note_names_the_condition`: S2's note for an `h2::Error` built from
   a bare reason (`h2::Error::from(Reason::PROTOCOL_ERROR)`, wrapped by
   `Status::from_error`) reads `[h2 reason PROTOCOL_ERROR local]`. A
   status with no `h2::Error` in its chain gets no note.
2. `a_non_renewal_failure_is_not_retried`: `is_renewal_race` is false for
   that bare-reason status (not `is_remote()`), and for a plain
   `Status::internal("…")`. It stays true for today's `Unavailable` and
   `Unknown` "transport error" cases.
   h2 does not let outside code build a GOAWAY or remote-reset error, so
   the positive case of S4's new branch is tested end to end (items 4–5),
   not in a unit test.
3. `a_retry_restores_the_echo`: with `TO_ECHO` holding 7, run the S5
   sequence (read, encode a request, put the value back, encode again)
   and check that both requests carry `hi server 7`.
4. In the image (a `grehack2026/smoke-test.sh` check):
   `life-server --max-connection-age 1`, then a headless
   `life-client --steps K --size 106x61` (the reported size) against it,
   which must exit successfully. K is chosen at implementation so that the run crosses
   at least 60 renewals and the client before this fix fails it in 5 runs
   out of 5. Headless mode steps back to back and exits on the first
   error (spec 0375 S5), so its exit status is the whole check. K and the
   failure rate before the fix are recorded in the measured outcome. If
   no K makes the unfixed client fail reliably within a minute, the check
   is still added, since it guards against regressions, and the measured
   outcome says it does not reproduce the failure.
5. A manual run reproducing the report: the TUI on a 106×61 grid at
   10 gen/s against `--max-connection-age 1` reaches generation 15000
   (more than twice where both reported runs failed) without stopping.
   With the server's `--self-echo-percentage 100`, the server logs one
   `echo ok` for each step except the first, and no `echo mismatch`. The
   one exception would be a retry after RST_STREAM NO_ERROR (N3), which
   applies only if S3 measured that condition.

## Measured outcome

Measured 2026-10-01 on the x86-64 NixOS VM, release build, headless
client (`--steps`, back to back, about 45 steps/s on 106×61) against
`life-server --max-connection-age 1`.

**The cause (S3).** With S2's note, the client before S4 failed 5 runs
out of 5, after 2 to 6 s, every time with
`Internal: h2 protocol error: http2 error [h2 GOAWAY NO_ERROR remote]`:
the server's graceful close at renewal, the first candidate. S4 retries
exactly that condition. Headless reproduces it far faster than the TUI
at 10 gen/s, so the TUI run of S3 was not needed.

**With S4 and S5.** No GOAWAY failure reached the user in 5 runs, and
the handshake stayed clean (`--self-echo-percentage 100`: 17,386
`echo ok`, no mismatch). But every run then ended after 24 to 186 s
with a failure that has no `h2::Error` behind it, so outside S3's list:
`Cancelled: operation was canceled` 4 times (hyper's "canceled": a
request given up because its connection went away) and
`Cancelled: Timeout expired` once (the client's 5 s call timeout). The
GOAWAY failure had hidden them by always striking first. At the default
10 s age, two runs of 12,000 steps (about 64 renewals) finished
cleanly. At the rate measured at 1 s, the cancellation would still
appear at 10 s, after roughly 25 to 190 renewals.

Per S3, work stopped there. Test plan item 4 is not added yet: any step
count that makes the unfixed client fail reliably also hits the open
cancellation. Tests: 55 crate tests pass (items 1–3 among them), clippy
clean.
