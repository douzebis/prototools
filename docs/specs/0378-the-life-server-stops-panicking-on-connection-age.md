<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0378 — the life server stops panicking on connection age

Status: implemented
Implemented in: 2026-10-01
App: grehack2026 (life-server)
Refs: docs/specs/0375-a-game-of-life-to-spy-on.md (S4, the server's
      max_connection_age that triggers the bug)

## Background

`life-server` sets tonic's `max_connection_age` (spec 0375 S4): it renews
each connection every 10 s so a spy started mid-connection catches up
within that window. On every renewal the server printed, on a worker
thread:

```
thread 'tokio-rt-worker' panicked at .../tonic-0.14.6/src/transport/server/mod.rs:891:20:
`async fn` resumed after completion
```

The cause is a tonic bug (grpc-rust issue #2522). `serve_connection` runs
a `loop { tokio::select! { … } }`; one branch polls the
`connection_timeout` future that implements `max_connection_age`. When it
fires (GracefulShutdown), the branch does not leave the loop, so a later
iteration polls the already-completed future again — which panics, since a
plain `async fn` future must not be resumed after returning `Ready`. The
sibling signal branch is wrapped in `Fuse` against exactly this; the
timeout branch was not.

tokio catches the per-task panic, so the server keeps serving and the
client reconnects — the effect is only noise — but it printed every few
seconds and looked alarming.

## Goals

- **G1.** `life-server` no longer panics when a connection reaches
  `max_connection_age`; the renewal behavior of spec 0375 S4 is
  unchanged.

## Non-goals

- **N1. A change to our code.** The bug is tonic's; the fix is tonic's.
  This spec only arranges to build against the fixed tonic.
- **N2. Fixing it for the whole repo.** Only `grehack2026/life` uses
  tonic (it and bobapp are the only tonic consumers, both outside the
  workspace); nothing else is affected, so the patch is scoped to the
  life crate's `Cargo.toml`.

## Specification

- **S1. Build against the fixed tonic commit.** The fix — wrap the
  timeout future in `Fuse`, mirroring the signal branch — is merged
  upstream (grpc-rust PR #2780, 2026-07-30) but unreleased: the latest
  crate is still tonic 0.14.6 (2026-05-07), which predates it. The life
  crate's `Cargo.toml` therefore carries

  ```toml
  [patch.crates-io]
  tonic = { git = "https://github.com/grpc/grpc-rust", rev = "bf9526a70c5479ef9afa8f70f9764290a088a659" }
  ```

  That commit is itself still version 0.14.6, so the patch applies cleanly
  and changes nothing but the one fix. crane vendors the git dependency
  from the `Cargo.lock`, so the Nix build needs no other change.

- **S2. Remove the patch when a fixed tonic is released.** When a tonic
  version greater than 0.14.6 ships the fix, drop the `[patch]` and bump
  the dependency. The comment in `Cargo.toml` says so.

## Alternatives considered

### Drop or re-implement max_connection_age

Avoiding tonic's feature would dodge the bug but weaken spec 0375 S4 (a
late spy would wait longer, or the server would grow its own connection
reaper). The feature is correct; only its polling is buggy, and upstream
has fixed it.

### Suppress the panic with a panic hook

A hook swallowing this one message would hide the noise, but also hide any
real panic, and leave the buggy re-poll in place. Building against the fix
removes the bug rather than masking it.

## Test plan

1. `life-server --max-connection-age 2` driven by a client for 300 steps
   (many renewals): the server prints no `async fn … resumed` panic, and
   serves every request.
2. The crate's tests and clippy pass against the patched tonic; the image
   smoke test (spec 0377's checks included) passes.

## Measured outcome

Measured 2026-10-01 on the x86-64 NixOS VM, release build.

Before the patch the server panicked on roughly every connection renewal.
After it, a 300-step run against `--max-connection-age 2` — crossing the
age boundary about 150 times — printed zero panics, served all 300
requests, and recovered all 300 smuggled messages (spec 0377). 34 crate
tests and clippy pass; `nix-build -A grehack2026.life` vendors the git
dependency and builds.
