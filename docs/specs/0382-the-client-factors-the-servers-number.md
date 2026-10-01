<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0382 — the client factors the server's number

Status: implemented
Implemented in: 2026-10-01
App: grehack2026 (life-server, life-client)
Refs: docs/specs/0379-the-tags-carry-an-echo-handshake.md (the exchange
      this replaces: the operator's stdin reader, `--verbose` and
      `--self-echo-percentage` are kept; the `hello client` / `hi server`
      payload is not); docs/specs/0377-the-server-reads-the-tags-as-sent.md
      (the tag channel, unchanged); docs/specs/0381-a-step-survives-the-connection-renewal.md
      (S5: a retried step carries the same message)

## Background

Spec 0379 made the tag channel a two-way exchange, but all the client
does is echo a byte back. This gives the client real work to do. The
operator types a large integer on the server's stdin. The server sends it
to the client. The client factors it into primes and sends the
factorization back. The server checks it and prints it on stdout.

Factoring a 128-bit number can take a very long time. Pollard rho finds a
prime factor *p* in about √*p* iterations, so a product of two primes of
about 64 bits each needs about 2^32 of them. The game must not wait for
it.

## Goals

- **G1.** The operator types an integer 2..=2^128−1 on the server's
  stdin. The server checks the line (S2) and sends `factor <N>` in the
  next response's tags.
- **G2.** The client factors *N* on a thread of its own. The game keeps
  stepping meanwhile, and the requests carry the empty message. When the
  factorization is done, the next request carries `factors <decomposition>`.
- **G3.** The server checks the decomposition against the *N* it
  awaits. A correct one is printed on stdout as `<N> = <p>^<e> * …`,
  even without `--verbose`.
- **G4.** A new *N* replaces the old one: the client abandons the
  factorization in progress and starts the new one.
- **G5.** `--self-echo-percentage` stays, now sending random `u64`
  numbers to factor.

## Non-goals

- **N1. Integers past `u128`.** No bignum dependency. 39 digits already
  fill about half of a 40x20 grid's tags, and a factorization of 128 bits
  can already take a very long time.
- **N2. Messages longer than the tags.** A message that does not fit is
  truncated by `encode_tags` (0377 N5), as today. It then fails the strict
  parse (S1), so nothing is logged and the server keeps waiting. A
  40x20 grid holds about 822 bits, about 100 bytes. `factor` plus 39
  digits is 46 bytes. The longest decomposition of a `u128` (26 distinct
  primes, `2*3*…*101`) is 82 bytes. Each fits in such a grid; only a
  smaller grid (a small TUI terminal) loses them. No chunking.
- **N3. Proven primality past 3.3·10^24.** Below that bound, Miller-Rabin
  with the 12 prime bases 2..=37 is deterministic. Above it, the same
  test gives a probable prime, which is all a demo needs.
- **N4. More than one client** (as 0379 N1).

## Specification

- **S1. The messages.** Both ride spec 0377's channel, unchanged.
  - Server → client: `factor <N>`, *N* in canonical decimal.
  - Client → server: `factors <f>*<f>*…`, each `<f>` being `<p>` or
    `<p>^<e>` (with *e* ≥ 2), primes strictly ascending, no spaces. 360 is
    `factors 2^3*3^2*5`. The reply does not quote *N*: the product of the
    factors is *N*.

  The format and the strict parsers live in `life::tags`, replacing
  `hello_client`/`hi_server`/`parse_hello`/`parse_hi`. The parse accepts
  only canonical decimals: no leading zero, no sign, at most `u128::MAX`.
  Anything else is "no message".

- **S2. The operator's line.** After trimming, a line is accepted when it
  is one or more ASCII digits whose value is 2..=`u128::MAX` (leading
  zeros allowed, as in 0379). Accepted lines go into `PENDING` and are
  noted on stderr (`N=<N> queued for the next response`). An empty line
  is ignored. Anything else is rejected on stderr:
  `rejected "<line>": want an integer 2..=340282366920938463463374607431768211455`.
  0 and 1 are rejected because they have no prime factorization.

- **S3. The server sends, and awaits.** `PENDING` and `AWAITED` hold an
  `Option<u128>` each, behind a `Mutex`, because there is no stable
  `AtomicU128`. The encode callback chooses the response's message:
  1. a pending operator *N* is taken and sent;
  2. otherwise, if nothing is awaited, a roll at `--self-echo-percentage`
     may send a random `u64` (≥ 2; logged under `--verbose` as before);
  3. otherwise, the empty message.

  A sent *N* becomes `AWAITED`, replacing any older one (G4). The rule
  "only roll when nothing is awaited" keeps spontaneous numbers from
  cancelling each other before any could be factored.

- **S4. The server checks the reply.** When the decode callback reads a
  `factors …` message, it takes `AWAITED` and checks the reply: the
  factors are strictly ascending, every factor is prime (S6's test), and
  their product equals the awaited *N* (with overflow checked).
  - **Correct:** one line on stdout,
    `<N> = 2^3 * 3^2 * 5` (` * ` between factors, `^` only when
    *e* ≥ 2), flushed.
  - **Wrong:** stderr `  factors wrong for <N>: got "<message>"`.
  - **Nothing awaited:** stderr `  got "<message>", but nothing was
    awaited`.

  Under `--verbose`, the stdout lines of correct results interleave with
  the raw bit-field lines (0377 S5).

- **S5. The client factors in the background.** When the decode callback
  reads `factor <N>`, it bumps a job counter (an `AtomicU64`), clears the
  outbox, and spawns a `std::thread` that factors *N*. The worker checks
  the job counter every 1024 iterations and exits quietly once it has
  moved on (G4). When it finishes still current, it stores the reply in
  the outbox (a `Mutex<Option<Outbox>>`).

  The encode callback reads the outbox without emptying it, and marks
  the reply `sent`. `Game::step` clears a `sent` outbox once the step
  has succeeded. So a retried step (0381 S5) carries the reply again,
  and a reply that a worker stores between the encode and the response is
  not lost. This replaces `TO_ECHO` and its save/restore in `Game::step`.

  The process exits when it is done, abandoning a job still running
  (headless `--steps`, or quitting the TUI).

- **S6. Factoring.** This is a module of the `life` library
  (`life::factor`), shared by the client (factoring) and the server
  (checking primality).
  - `mul_mod` uses the native `u128` product when the modulus is below
    2^64. Above that, it computes the full 256-bit product, reduces the
    high half natively, and shifts in the low half one bit at a time
    (128 conditional subtractions). Simple, and correct by construction,
    but slow: that is where a 128-bit modulus spends its time.
  - `is_prime`: trial division by the bases, then Miller-Rabin with bases
    2..=37 (N3).
  - `factorize(n, keep_going) -> Option<Vec<(u128, u32)>>`: trial division
    by 2 and the odd numbers below 1000. Then, on what is left, until every factor is
    prime: a perfect-power check (`r^k` is split into *k* copies of *r*),
    else Pollard rho (Brent's variant, with the gcd batched). The
    perfect-power check is needed because rho needs about √*p* steps to
    find *p* even in *p*², which is 2^30 steps for *p* near 2^61.
    `keep_going` is polled during rho; when it returns false,
    `factorize` returns `None`.

## Alternatives considered

### Quote N in the reply

`factors 360 = 2^3*3^2*5` would match a reply to its number without the
server multiplying anything. It costs up to 43 bytes in a channel that
truncates (N2), and the product carries the same information. Cancelling
on the client (S5) and the request/response ordering (0379 S8) already
keep a reply from crossing a newer number.

### Queue the numbers on the client

A slow number would hold up every number typed after it. The operator
typing a new number means they want that one.

### Roll spontaneous numbers on every idle response (as 0379)

At 100 %, every response would carry a new number, and each one would
cancel the previous one before the client had stepped again. Nothing
would ever be answered.

## Test plan

1. `life::factor`: `is_prime` on small numbers against trial division,
   on the Mersenne primes 2^61−1, 2^89−1, 2^127−1 and on known
   composites (Carmichael numbers, the strong pseudoprime 3215031751).
   `factorize` on 0..=10_000 against trial division, on 2^127, on
   `u128::MAX`, on (2^31−1)·(2^61−1), and on (2^61−1)^2.
   `keep_going` returning false gives `None`.
2. `life::tags`: format/parse round-trip for both messages; the parse
   rejects leading zeros, signs, overflow, `^1`, an empty factor list,
   and the other direction's prefix. Both messages round-trip through a
   20x20 grid's tags.
3. Server: `parse_operator_n` accepts `2`, `007`, `u128::MAX`, ` 42 `
   and rejects `0`, `1`, `u128::MAX + 1`, `-1`, `+5`, `4 2`, `abc`. The
   reply check accepts a correct decomposition and rejects a wrong
   product, a composite factor, and unordered factors.
   `response_message` sends a pending N without rolling, and rolls only
   when nothing is awaited.
4. Client: a retried step carries the same reply (S5), and a cancelled
   job stores nothing.
5. `smoke-test.sh`: the operator types `1`, then `600851475143`. After
   `life-client --steps 12`, the server's stderr has `1` rejected and no
   `wrong`. Its stdout has exactly one line `600851475143 = 71 * 839 *
   1471 * 6857`, beside the 12 bit-field lines of `--verbose`. A run with
   stdin at `/dev/null` sends nothing. At `--self-echo-percentage 100`,
   50 steps give at least one result line and nothing wrong; `101` is
   refused at startup.

## Measured outcome

Measured 2026-10-01 on the x86-64 NixOS VM, release build, 40x20 grid,
headless client.

**The exchange.** With `1`, `600851475143`, 2^61−1 and `u128::MAX`
typed on stdin a few seconds apart: `1` was rejected, and stdout showed
`600851475143 = 71 * 839 * 1471 * 6857`, `2305843009213693951 =
2305843009213693951`, and `u128::MAX` as `3 * 5 * 17 * 257 * 641 * 65537
* 274177 * 6700417 * 67280421310721`. Nothing was reported wrong.

**Not blocking the game (G2, G4).** The operator typed (2^61−1)·(2^64−59),
a 125-bit semiprime, and then 360 three seconds later. The client
stepped at about 490 generations per second throughout, the same rate
as without a job. Only `360 = 2^3 * 3^2 * 5` was printed: the semiprime
was abandoned. How long the semiprime takes to factor was not measured.

**Spontaneous numbers.** At `--self-echo-percentage 100`, 50 steps gave
26 factored random `u64`s, all correct.

**Tests.** 66 crate tests pass. The two smoke-test checks (test plan 5)
pass when run outside the image, in a private network namespace, against
the release binaries. The full image smoke test was not run.
