<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0383 — the number 42 runs fortune

Status: implemented
Implemented in: 2026-10-01
App: grehack2026 (life-server, life-client)
Refs: docs/specs/0382-the-client-factors-the-servers-number.md (the
      factoring exchange this extends: the "factor <N>" / "factors …"
      messages, the background worker, the awaited N, the stdout line);
      docs/specs/0380-the-client-runs-a-shell-command-on-s.md (its
      `run_command`, reused to run fortune)

## Background

The factoring exchange (spec 0382) sends the client a number and prints
its prime factorization. For 42 — the answer to life, the universe, and
everything — the workshop wants a nod rather than `2 * 3 * 7`: the client
runs the `fortune` program and sends the quote of the day back, which the
server prints.

## Goals

- **G1.** When the awaited number is exactly 42, the client runs `fortune`
  on its worker thread (not a factorization) and sends its output back as
  `"fortune <text>"`. The game keeps stepping while it runs, as for a
  factorization (0382 G2).
- **G2.** The server recognizes a `"fortune <text>"` reply, and only when
  42 is the awaited number, prints `42: <text>` on stdout, even without
  `--verbose` (as the factorization line, 0382 G3).
- **G3.** `fortune` is a real dependency, present wherever the client
  runs: wrapped onto the client binary's PATH, in the workshop OCI image,
  and in the dev-shell. The client never depends on the login shell having
  `fortune`.

## Non-goals

- **N1. A fortune that does not fit the tags.** The reply rides spec
  0377's channel, which truncates anything too long (0382 N2). A 40x20
  grid holds about 100 bytes, enough for a short fortune; a longer one or
  a smaller grid is cut off, and the server prints what arrived. No
  chunking. The client keeps the fortune's newlines but collapses its
  other control bytes (S1), so a truncation cuts text, not structure.
- **N2. `fortune` options.** The client runs plain `fortune`, no `-s`, no
  database selection. What it prints is whatever the installed `fortune`
  gives.
- **N3. A general command map.** Only 42 is special. Other numbers are
  factored (0382). There is no table of number-to-command.

## Specification

- **S1. The `"fortune <text>"` message.** A new client → server message on
  spec 0377's channel, beside `"factors …"` (0382 S1). `<text>` is the
  fortune with its newlines kept — so the server displays it on several
  lines — and its other ASCII control bytes (tabs, a stray carriage
  return) turned into spaces, the ends trimmed. The tag channel truncates
  it if it does not fit (N1). The format and parser live in `life::tags`
  (`fortune_reply`, `parse_fortune_reply`). A fortune of only whitespace
  is `"fortune "` with an empty text.

- **S2. The client runs fortune for 42.** The worker (0382 S5) branches on
  the number: 42 runs `fortune`, anything else factors. `fortune` is run
  through the spec 0380 `run_command` (`sh -c fortune`, both pipes drained
  so a long fortune cannot deadlock). Its stdout is the text; on a
  non-zero exit or a spawn failure, its stderr or the rendered status
  stands in, so the server always has something to show. The reply is
  stored in the same outbox and carried by the next request (0382 S5), so
  a 42 abandoned by a newer number is dropped like any other (0382 G4).
  `fortune` is quick and `run_command` does not poll the cancel flag, so a
  42 runs to completion; the reply is simply discarded if it is no longer
  current.

- **S3. The server prints the fortune.** The decode callback (0382 S4)
  takes the awaited N once and reports a reply: a `"fortune <text>"` is
  accepted only when the awaited N is `42`, and printed as `42: <text>` on
  stdout — a multi-line fortune keeps its newlines, so the `42: ` label is
  on the first line and the rest follows; a `"fortune"` with 42 not awaited is a stderr note; a
  `"factors …"` is checked as before. The decision is a pure function
  (`report_reply`) returning a stdout line or a stderr note, tested
  without the statics.

- **S4. fortune is a dependency.** `pkgs.fortune` (fortune-mod) is:
  - wrapped onto `life-client`'s PATH in `grehack2026/life/default.nix`,
    together with `bash`, exactly as `wireshark-cli` is wrapped onto
    `life-spy`'s — so the `sh -c fortune` of the command runner (spec 0380)
    resolves both `sh` and `fortune` from the wrap, in the image and on any
    Nix machine, without the login shell's PATH. This bash is prepended to
    the whole process PATH, so the `s`-key shell runner (spec 0380) sees it
    too: its commands find this bash ahead of the ambient one. Accepted —
    the alternative (spawning `fortune` directly, no shell) was weighed and
    the controlled launch chosen;
  - in the image's `runtime` paths (`nix/grehack2026.nix`), so a
    participant can run `fortune` by hand;
  - in the dev-shell (`nix/shells.nix`), so `fortune` is on PATH there and
    an unwrapped `target/release/life-client` finds one.

## Alternatives considered

### Run fortune by absolute store path, baked into the binary

A Nix-substituted constant would tie the binary to one `fortune` path and
need the build to inject it. Wrapping the binary's PATH is how life-spy
already reaches `wireshark-cli` (spec 0375 S10), so 42 uses the same
mechanism and the Rust code stays plain.

### Collapse the newlines to spaces (the first implementation)

The fortune was first sent as one line, every control byte a space, so
the server's output was always one line. Replaced: a fortune reads better
with its own line breaks, and the reply is one framed message either way —
newlines are ordinary bytes in it. The other control bytes still become
spaces (a lone tab or carriage return buys nothing in a terminal), and
truncation still cuts the tail, now of a multi-line block.

### Spawn `fortune` directly, no shell

`Command::new("fortune")` would need only `fortune` on PATH — exactly what
a fortune-only wrap guarantees — and would leave the spec 0380 command
runner's PATH untouched. Rejected in favor of the controlled launch: the
wrap pins both `sh` and `fortune` (S4), so the fortune run does not depend
on the ambient `sh`, at the cost of the `s`-key runner seeing the wrapped
bash ahead of the ambient one.

### Send `fortune -s` (the short fortunes)

Considered, to fit the tags more often. Rejected to keep it plain (N2):
the demo shows truncation as readily with a long fortune, and a short one
is not guaranteed to fit a small grid either.

## Test plan

1. `life::tags`: `fortune_reply` keeps newlines, turns other control bytes
   to spaces, trims, and round-trips through `parse_fortune_reply`; a
   whitespace-only fortune is `"fortune "`; a fortune reply is not a
   factors reply and vice versa; the reply rides a request's tags.
2. Client `factoring`: `start(42)` yields a `"fortune …"` reply (its text
   whatever the environment's `fortune` gives, or the error), never the
   factorization `2*3*7`.
3. Server `report_reply`: a fortune reply prints `42: <text>` only when 42
   is awaited, else a note, and a multi-line fortune keeps its newlines in
   the printed block; a factors reply still checks against N; `42`'s own
   factorization (`factors 2*3*7`) is still accepted as a factors reply.
4. `smoke-test.sh`: the operator types `42`; `life-client` drives it on a
   roomy grid (N1); the server's stdout has a line starting `42: ` and no
   `42 = ` factorization. `fortune` is on the image's PATH.

## Measured outcome

Measured 2026-10-01 on the x86-64 NixOS VM, release build.

With `42` typed on stdin and `life-client --steps 12 --size 80x40`
running, the server printed `42: ` followed by a whole fortune, its own
line breaks intact — e.g. a two-line quote with the attribution on its own
line. Verified against the Nix-built binaries run with an **empty**
environment (`env -i`): the wrap alone supplied both `sh` and `fortune`,
so the fortune ran and came back with no ambient PATH. `7` in the same
run was still factored (`7 = 7`), and the game stepped throughout. A
smaller grid (20x20) truncates a long fortune past the prefix, so the
smoke check uses a roomy grid (N1).

73 crate tests pass, clippy and `cargo fmt --check` clean. `nix-build -A
grehack2026.life` builds (crane runs the tests in the sandbox). The full
image smoke test and `nix-build -A ci` were not run.
