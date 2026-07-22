<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0157 — protolens: optional `--descriptor-set` (schemaless launch)

Status: implemented
Implemented in: 2026-07-22
App: protolens

## Background

`protolens` currently hard-requires `--descriptor-set` at startup
(`main.rs`): if the flag is absent, it prints `"error: --descriptor-set
is required in v1 (no schemaless mode); pass --descriptor-set <path>"`
and exits, before even reading the target blob. This was a deliberate
v1 decision (spec 0111 Goal 2: no embedded/vendored fallback schema
for well-known types).

In practice, most of the decode/render/navigation pipeline is already
schema-agnostic by construction, and "nothing resolves" is already an
exercised, tested code path: an unresolved `--type`, a missing
`hopcroft.rkyv` scoring graph, or any individual unresolved subtree
all already render raw (numeric field tags, wire-type-guessed
keywords) today. `DescriptorContext::empty_for_test()` — an empty
`DescriptorPool`, no graph — already exists and is exercised
extensively by the TUI's own unit tests. What's actually missing is
narrow: the CLI-level gate itself, plus a handful of things keyed off
the `--descriptor-set` *path* specifically (the `hopcroft.rkyv`
sidecar lookup, the `--proto-root` stub-dir fallback, and the startup
splash text) rather than off the resolved pool.

This spec makes `--descriptor-set` optional, letting `protolens`
launch and raw-decode a blob with no schema at all — useful for a
first, exploratory look at an unfamiliar blob before any descriptor
set is available.

## Goals

- **G1.** `--descriptor-set` is no longer required. `main()`'s current
  hard gate (`main.rs`, right after `Cli::parse()`) is replaced: launch
  proceeds unconditionally, with `descriptor_set` used as
  `Option<&Path>` from that point on (`cli.descriptor_set.as_deref()`).
- **G2.** `--type` without `--descriptor-set` is a hard startup error
  (a type name cannot resolve against no pool at all): `"error: --type
  requires --descriptor-set"`, checked at the same point the old gate
  was, before reading the blob.
- **G3.** `DescriptorContext` gains a production (non-`cfg(test)`)
  schemaless constructor — `DescriptorContext::schemaless()`: empty
  `DescriptorPool`, `graph: None`, empty `raw_bytes`. Kept distinct
  from the existing `empty_for_test()` (same body) so the two call
  sites' intents — production schemaless launch vs. test scaffolding —
  stay distinguishable at the call site.
- **G4.** The `--proto-root` stub-dir auto-fallback (spec 0155 G2,
  `<descriptor-set-stub>/proto/`) only applies when `--descriptor-set`
  is given — `resolve_proto_root`'s `descriptor_set` parameter becomes
  `Option<&Path>`, `None` short-circuiting straight to the explicit
  `cli_proto_root` (unchanged if `Some`, `None` otherwise). An
  explicit `--proto-root` is still accepted and stored without
  `--descriptor-set` — it simply never gets used, since jump-to-
  definition has no resolved FQDN to look up without a schema.
- **G5.** The `cli.command.is_none()` startup splash (today's
  size/graph-sidecar messages) branches on `descriptor_set`: `Some`
  keeps today's messages; `None` prints one line, e.g. `"protolens: no
  --descriptor-set — decoding without a schema..."`.
- **G6.** Root-type resolution and rendering need no further code
  change: with `ctx.graph` always `None` in schemaless mode,
  `determine_root_type`'s existing "no graph" branch and `decode()`'s
  existing `root_type_deferred` computation already yield `root_type
  == "<raw / no type>"` and a fully raw-rendered tree, exactly as they
  do today for a real-but-inconclusive descriptor set. Covered by a
  new test confirming this end-to-end, not by new production code.
- **G7.** Batch `export --format=binary`/`--format=prototext` and
  `--format=descriptor-binary` all still work with no
  `--descriptor-set` loaded, needing no special-casing:
  `binary`/`prototext` export the raw/unresolved rendering of the
  target node exactly as for any other unresolved subtree today;
  `descriptor-binary` degrades every field to spec 0156 G6c's tier-4
  wire-type guess, same as it already does for any single unresolved
  field. `--format=descriptor-prototext` continues to hard-error via
  spec 0156 G7's existing "meta-schema not found in pool" path (an
  empty pool trivially has no `descriptor.proto`) — also no special-
  casing needed.

## Non-goals

- **N1.** No embedded/vendored fallback schema for well-known types —
  spec 0111 Goal 2 stands; schemaless mode is truly zero-schema, not
  "auto-register common WKTs".
- **N2.** No blob-only type inference. Root-type inference remains
  strictly `ctx.graph`-driven (a `hopcroft.rkyv` sidecar, which in
  turn requires a real `--descriptor-set`); schemaless mode never
  attempts to guess a message type from wire data alone.
- **N3.** No mid-session "attach a descriptor-set" command or reload.
  The schemaless/schema-ful choice is fixed for the process's
  lifetime, same as `--descriptor-set`'s path is already immutable
  post-launch today.
- **N4.** No `--descriptor-set`-less inference for `--proto-root`'s
  stub-dir fallback (G4) — only the explicit flag/env-var survive.

## Specification

### `protolens/src/main.rs`

- Right after `Cli::parse()`, replace the current hard gate:
  ```rust
  let cli = Cli::parse();
  let descriptor_set = cli.descriptor_set.as_deref();
  if descriptor_set.is_none() && cli.r#type.is_some() {
      eprintln!("error: --type requires --descriptor-set");
      return ExitCode::FAILURE;
  }
  ```
  (blob reading/conversion below this point is unchanged.)
- The `cli.command.is_none()` splash block: keep today's `Some(path)`
  body verbatim (size suffix, `hopcroft.rkyv` sidecar check, existing
  two message variants), add an `else` branch for `None` printing the
  one-line schemaless message (G5).
- `ctx` construction:
  ```rust
  let ctx_result = match descriptor_set {
      Some(path) => decode::DescriptorContext::load(path),
      None => Ok(decode::DescriptorContext::schemaless()),
  };
  let mut ctx = match ctx_result {
      Ok(ctx) => ctx,
      Err(e) => { eprintln!("error: {e}"); return ExitCode::FAILURE; }
  };
  ```
- `resolve_proto_root`'s signature: `descriptor_set: &Path` ->
  `descriptor_set: Option<&Path>`; body: `cli_proto_root.or_else(||
  { let d = descriptor_set?; let candidate =
  d.with_extension("").join("proto"); candidate.is_dir().then_some(candidate)
  })`. Call site: `resolve_proto_root(cli.proto_root.clone(),
  descriptor_set)` (now passing the already-`Option<&Path>` local).
- The four existing `resolve_proto_root` unit tests updated to pass
  `Some(&path)`/`None` for the second argument (was a bare `&Path`);
  no new test needed for the "no descriptor set at all" case — it's
  the same code path as today's "stub dir doesn't exist" case.
- No other line in `main()` reads `descriptor_set` as a bare `&Path`
  after this point (verified by inspection: everything downstream
  goes through `ctx`, not the path).

### `protolens/src/decode.rs`

- New constructor on `DescriptorContext`, alongside (not replacing)
  `empty_for_test()`:
  ```rust
  /// A schemaless `DescriptorContext` (spec 0157 G3): empty pool, no
  /// scoring graph. Used when `--descriptor-set` is absent — the
  /// production counterpart of `empty_for_test()` (same shape, kept
  /// separate so each call site's intent stays clear).
  pub(crate) fn schemaless() -> Self {
      DescriptorContext {
          pool: DescriptorPool::new(),
          graph: None,
          raw_bytes: Vec::new(),
      }
  }
  ```
- No change to `determine_root_type`, `decode()`, or any other
  function — G6's behavior already falls out of existing logic.

## Test plan

- `main.rs`: update the four existing `resolve_proto_root` tests for
  the new `Option<&Path>` signature.
- New CLI-level (subprocess) integration tests, in
  `protolens/tests/batch_export.rs` (the batch `export` subcommand
  needs no interactive TUI event loop, so it's the only launch mode
  scriptable via the existing black-box harness):
  - launching with no `--descriptor-set` and `export / --format
    binary` succeeds, producing the raw/unresolved rendering of the
    whole blob (mirrors an existing unresolved-subtree assertion
    style).
  - launching with no `--descriptor-set` and `export / --format
    descriptor-binary` (plus a matching `--load-overrides`, per spec
    0156 G9) succeeds, decodes, and every field's type is the tier-4
    wire-type guess (no schema to resolve against).
  - launching with no `--descriptor-set` and `export / --format
    descriptor-prototext` (plus `--load-overrides`) fails with a
    meta-schema-not-found error (spec 0156 G7's existing error path).
  - launching with no `--descriptor-set` but an explicit `--type`
    fails with `"--type requires --descriptor-set"`, before ever
    trying to read the blob.
