<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0102 — Extract `prototext-args` crate for fast man-page generation

**Status:** dropped
**App:** prototext

---

## Problem

The `deploy.yml` CI workflow (ThalesGroup) generates man pages by running:

```
$(nix-build -A prototext --no-out-link)/bin/prototext-gen-man man/man1
```

This builds the full `prototext` binary via the Crane pipeline, which takes
over 10 minutes on GitHub Actions because it compiles the entire workspace
from scratch: `prototext-core`, `prototext-graph`, prost, prost-reflect,
rkyv, and all their transitive dependencies.

The `prototext-gen-man` binary only needs the clap `Command` definition to
render the man page.  It calls `prototext::command()`, which calls
`Cli::command()` — a clap derive macro expansion.  Nothing from
`prototext-core` or `prototext-graph` is used at man-page generation time.

The reason the full crate is compiled is that the clap `Cli` struct lives in
`prototext/src/lib.rs`, which also re-exports `run`, `inputs`, `lazy_pool`,
`complete`, and the embedded binary blobs (`EMBEDDED_DESCRIPTOR`, `WKT_GRAPH`,
`WKT_INDEX`).  These pull in the heavy dependencies even though `gen_man.rs`
never uses them.

---

## Goals

1. Create a new `prototext-args` workspace crate containing only the clap
   `Cli` / `Command` struct definitions and the `command()` function.
2. `prototext-args` depends only on `clap`, `clap_complete`, and `prost` /
   `prost_types` (for the `complete_type_names` completer).
3. `prototext-gen-man` is moved into `prototext-args` as its sole binary
   target, depending only on `clap_mangen`.
4. A new Nix derivation `prototext-gen-man` builds only `prototext-args`,
   replacing the expensive `nix-build -A prototext` call in `deploy.yml`.
5. The `prototext` crate retains all existing runtime behaviour; it depends
   on `prototext-args` for the `Cli` struct.

---

## Non-goals

- Changing the generated man page content.
- Splitting `complete.rs` further (e.g. extracting path completers from the
  type-name completer).
- Removing `prototext-core` or `prototext-graph` from the `prototext` crate.
- Changing the `nix.yml` CI workflow (ThalesGroup or douzebis).

---

## Analysis

### What stays in `prototext-args`

- `src/lib.rs`: `Cli`, `Command` (the clap structs), `pub fn command()`
- `src/complete.rs`: all completer functions, including `complete_type_names`
  (which needs `prost` / `prost_types` to decode the embedded descriptor)
- `src/gen_man.rs`: the `prototext-gen-man` binary
- `EMBEDDED_DESCRIPTOR`: the `include_bytes!` blob and its `build.rs` copy
  logic (needed by `complete_type_names`)

### What stays in `prototext`

- `src/main.rs`: entry point, `CompleteEnv`, `run::run(cli)`
- `src/run.rs`, `src/inputs.rs`, `src/lazy_pool.rs`
- `WKT_GRAPH`, `WKT_INDEX` blobs (feature `wkt-db`)
- All dependencies on `prototext-core`, `prototext-graph`, `rkyv`,
  `prost-reflect`, `memmap2`, `serde`, `serde_yaml`, `walkdir`, `globset`

### Dependency graph after refactor

```
prototext-args
  ├── clap (derive)
  ├── clap_complete (unstable-dynamic)
  ├── clap_mangen          ← only needed by gen_man binary target
  ├── prost
  └── prost-types

prototext
  ├── prototext-args       ← new dep (provides Cli, command())
  ├── prototext-core
  ├── prototext-graph
  └── ... (unchanged)
```

`prototext-args` compile time is dominated by clap + prost; both are already
in `depsCache`, so `nix-build -A prototext-gen-man` only recompiles the thin
`prototext-args` crate itself — a matter of seconds.

---

## Specification

### S1 — Create `prototext-args/Cargo.toml`

New workspace member `prototext-args`:

```toml
[package]
name        = "prototext-args"
version     = "0.2.1"
edition     = "2021"
description = "CLI argument definitions for prototext (clap structs + man-page generator)"
license     = "MIT"
repository  = "https://github.com/ThalesGroup/prototools"

[[bin]]
name = "prototext-gen-man"
path = "src/gen_man.rs"

[dependencies]
clap          = { version = "4.5", features = ["derive"] }
clap_complete = { version = "4.5", features = ["unstable-dynamic"] }
clap_mangen   = "0.2"
prost         = "0.14"
prost-types   = "0.14"
workspace-hack = { version = "0.1", path = "../workspace-hack" }

[build-dependencies]
prost = "0.14"
```

`clap_mangen` is a dependency of the crate (not dev-only) because it is
used by the `prototext-gen-man` binary target, which is part of the published
crate.

### S2 — Populate `prototext-args/src/`

Move the following files verbatim from `prototext/src/` to
`prototext-args/src/`:

- `lib.rs` — `Cli`, `Command`, `command()`, module declarations for
  `complete` (keep `EMBEDDED_DESCRIPTOR`; drop `WKT_GRAPH`, `WKT_INDEX`,
  `run`, `inputs`, `lazy_pool`)
- `complete.rs` — unchanged
- `gen_man.rs` — unchanged

`prototext-args/src/lib.rs` must **not** re-export or reference anything from
`prototext-core` or `prototext-graph`.

### S3 — Add `build.rs` to `prototext-args`

Copy the `copy_prebuilt` portion of `prototext/build.rs` into
`prototext-args/build.rs`.  It must populate `$OUT_DIR/descriptor.pb` so that
`EMBEDDED_DESCRIPTOR` can `include_bytes!` it.

The `wkt-db` / `build_wkt_graph` section is **not** copied — `prototext-args`
has no WKT feature.

Point `cargo:rerun-if-changed` at `build.rs` and the prebuilt pb path only.

### S4 — Update `prototext/src/lib.rs`

- Remove the `Cli`, `Command`, `command()` definitions and the `complete`
  module declaration.
- Add `pub use prototext_args::{Cli, Command, command};` (or re-export
  selectively as needed by `main.rs`).
- Keep `EMBEDDED_DESCRIPTOR`, `WKT_GRAPH`, `WKT_INDEX`.
- Keep `pub mod run; pub mod inputs; pub mod lazy_pool;`.

### S5 — Update `prototext/Cargo.toml`

Add `prototext-args` as a dependency:

```toml
prototext-args = { path = "../prototext-args", version = "0.2.1" }
```

Remove `clap_mangen` from `prototext/Cargo.toml` (it moves to
`prototext-args`).

Remove `src/gen_man.rs` from the `[[bin]]` section and from the `include`
list.

### S6 — Update `Cargo.toml` (workspace root)

Add `"prototext-args"` to the `[workspace] members` list.

### S7 — Add `prototext-gen-man` Nix derivation

In `nix/rust.nix`, add a new derivation that builds only `prototext-args`:

```nix
prototextGenMan = crane.buildPackage (protocArgs // {
  src            = workspaceSrc;
  pname          = "prototext-gen-man";
  cargoArtifacts = depsCache;
  cargoExtraArgs = "-p prototext_args --bin prototext-gen-man --no-default-features";
  doCheck        = false;
  doNotPostBuildInstallCargoBinaries = true;
  installPhaseCommand = ''
    mkdir -p $out/bin
    cp target/release/prototext-gen-man $out/bin/
  '';
});
```

Export it from `nix/rust.nix`'s `in { ... }` block and expose it in
`default.nix` as `prototext-gen-man`.

### S8 — Update `deploy.yml`

Replace:

```yaml
$(nix-build -A prototext --no-out-link)/bin/prototext-gen-man man/man1
```

with:

```yaml
$(nix-build -A prototext-gen-man --no-out-link)/bin/prototext-gen-man man/man1
```

---

## Verification

1. `nix-build -A prototext-gen-man` completes in under 2 minutes on a cold
   cache (clap + prost already in `depsCache`).
2. `nix-build -A ci` passes — the full test suite is unaffected.
3. The generated `man/man1/prototext.1` is byte-for-byte identical before and
   after the refactor.
4. `nix-build -A prototext` still works and the `prototext` binary behaves
   identically.
5. `deploy.yml` CI on ThalesGroup completes the man-page generation step in
   under 2 minutes.

---

## Summary of changes

| File | Change |
|---|---|
| `prototext-args/Cargo.toml` | New crate |
| `prototext-args/src/lib.rs` | Moved from `prototext/src/lib.rs` (trimmed) |
| `prototext-args/src/complete.rs` | Moved from `prototext/src/complete.rs` |
| `prototext-args/src/gen_man.rs` | Moved from `prototext/src/gen_man.rs` |
| `prototext-args/build.rs` | New — `copy_prebuilt` only |
| `prototext/src/lib.rs` | Re-export `Cli`, `Command`, `command` from `prototext-args` |
| `prototext/Cargo.toml` | Add `prototext-args` dep; remove `clap_mangen`; remove `gen_man` bin |
| `Cargo.toml` | Add `prototext-args` to workspace members |
| `nix/rust.nix` | Add `prototextGenMan` derivation |
| `default.nix` | Expose `prototext-gen-man` attribute |
| `.github/workflows/deploy.yml` | Use `nix-build -A prototext-gen-man` |
