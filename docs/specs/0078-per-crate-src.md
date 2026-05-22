<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0078 — Precise source sets and per-crate incremental Crane builds

**Status:** implemented
**Implemented in:** 2026-05-22
**App:** nix

---

## Background

All Crane derivations in `nix/rust.nix` share a single `src` built in
`default.nix`.  This single `src` is imprecise in two ways:

1. **Too broad**: it covers the entire workspace, so any `.rs` change anywhere
   invalidates every derivation that depends on `src` — `depsCache`,
   `rustTests`, `rustClippy`, `prototext`, and all three PyO3 extensions.
   A full rebuild takes ~10 minutes.

2. **Polluted**: `target/` directories contain `.rs` and `.toml` build
   artefacts that pass the file filter, so local `cargo build` runs change the
   `src` hash and trigger spurious Nix rebuilds.  The current workaround is a
   manually-maintained subtractive list of `target/` paths.

Additional sources of imprecision compound the problem:

- **PyO3 double-compile**: `prototext-core` and `scoring-graph` are internal
  workspace dependencies of both regular binaries and PyO3 extensions.  Because
  the PyO3 extensions require `features = ["extension-module"]` on pyo3, Cargo
  treats them as distinct compilation units.  With a shared `src` and shared
  `cargoArtifacts`, Crane cannot reuse the compiled artifacts and compiles these
  crates twice.

- **Clippy artifact reuse**: `rustClippy` uses `cargoArtifacts = depsCache`.
  If the `src` hash differs between the `depsCache` derivation and the
  `rustClippy` derivation (even by one irrelevant file), Crane discards the
  cache and recompiles everything from scratch.  With a sloppy `src` this
  happens routinely.

The root cause of all these problems is the same: **imprecise inputs**.  Nix
rebuilds whenever any input changes; the solution is to make each derivation's
inputs exactly as large as needed — no more.

---

## Goals

1. Each Crane derivation receives a `src` that contains exactly the files it
   needs — no `target/` artefacts, no unrelated crates, no docs or demo files.
2. Changing a `.rs` file in one crate does not trigger a rebuild of unrelated
   crates.
3. `depsCache` is insensitive to `.rs` changes — only `Cargo.toml`/`Cargo.lock`
   changes invalidate it.
4. `rustClippy` reliably reuses `depsCache` artifacts without recompiling.
5. PyO3 extensions do not cause workspace crates to be compiled twice.
6. The `target/` subtractive exclusion list in `default.nix` is eliminated.

---

## Non-goals

- Changing the Cargo workspace structure.
- Per-crate dependency caches (one shared `depsCache` is correct and avoids
  rebuilding external deps multiple times).
- Migrating to flakes or any other Nix infrastructure change.

---

## Specification

### Source construction

Replace the single `src` in `default.nix` with focused per-derivation sources
using `pkgs.lib.fileset.toSource` + `crane.fileset.commonCargoSources`.

`lib.fileset` operates purely on files (not directory nodes), so `target/`
is naturally excluded — it is never in scope regardless of where it lives.
The subtractive `target/` exclusion list is dropped entirely.

Three source builders are needed:

**`depsSrc`** — for `depsCache` only; sensitive only to manifest changes:
```nix
depsSrc = pkgs.lib.fileset.toSource {
  root = ./.;
  fileset = crane.fileset.cargoTomlAndLock ./.;
};
```

**`workspaceSrc`** — for workspace-wide derivations (`rustFmt`, `rustClippy`,
`rustTests`); includes all crate sources and all fixture directories but
excludes `target/`:
```nix
workspaceSrc = pkgs.lib.fileset.toSource {
  root = ./.;
  fileset = pkgs.lib.fileset.unions [
    (crane.fileset.commonCargoSources ./.)
    ./prototext/fixtures
    ./reproto/src/reproto/tests/fixtures
    ./scoring-graph/tests/fixtures
    ./tests/fixtures
  ];
};
```

**`mkCrateSrc`** — for individual crate derivations:
```nix
mkCrateSrc = { crateDir, extraFixtures ? [] }:
  pkgs.lib.fileset.toSource {
    root = ./.;
    fileset = pkgs.lib.fileset.unions ([
      (crane.fileset.cargoTomlAndLock ./.)
      (crane.fileset.commonCargoSources crateDir)
    ] ++ extraFixtures);
  };
```

### Per-derivation source assignment

| Derivation        | `src`          | Notes                                      |
|-------------------|----------------|--------------------------------------------|
| `depsCache`       | `depsSrc`      | manifest-only; `.rs` changes have no effect |
| `rustFmt`         | `workspaceSrc` | workspace-wide                             |
| `rustClippy`      | `workspaceSrc` | workspace-wide; reuses `depsCache` cleanly |
| `rustTests`       | `workspaceSrc` | workspace-wide; includes all fixtures      |
| `prototextBare`   | `mkCrateSrc { crateDir = ./prototext; extraFixtures = [ ./prototext/fixtures ]; }` | |
| `prototext`       | same as `prototextBare` | |
| `prototextCodec`  | `mkCrateSrc { crateDir = ./prototext-pyo3; }` | |
| `fdpScanLib`      | `mkCrateSrc { crateDir = ./fdp-scan-pyo3; }` | |
| `scoringGraphLib` | `mkCrateSrc { crateDir = ./scoring-graph-pyo3; extraFixtures = [ ./scoring-graph/tests/fixtures ]; }` | |

### PyO3 double-compile

`prototext-pyo3` depends on `prototext-core`; `scoring-graph-pyo3` depends on
`scoring-graph`.  These internal crates are compiled once for the regular build
(rlib) and once for the PyO3 extension (with `extension-module` feature).

To avoid the double-compile, the PyO3 extension derivations should reuse
artifacts from `depsCache` (which already compiles all external deps with
`PYO3_PYTHON` and `RUSTFLAGS` set).  The key is ensuring that the `src` hash
seen by `depsCache` and by each PyO3 extension derivation is consistent —
which the per-derivation `src` approach achieves, since `depsCache` uses
`depsSrc` (manifest-only) and each extension uses `mkCrateSrc` for its own
directory only.

Whether Cargo still compiles internal workspace crates twice depends on whether
Cargo fingerprints match between the `depsCache` phase and the extension build
phase.  This should be verified empirically after implementing the src changes.

### Clippy

With `depsCache` built from `depsSrc` (manifest-only) and `rustClippy` built
from `workspaceSrc`, their `src` hashes will differ — but that is expected and
correct.  Crane uses `cargoArtifacts` (not `src`) to transfer the compiled
dependency cache between derivations.  The important invariant is that
`depsCache` and `rustClippy` use the same `Cargo.toml`/`Cargo.lock` content,
same `RUSTFLAGS`, same `PYO3_PYTHON`, and same Cargo flags — so the
fingerprints for external crates match and Crane can reuse them.

If clippy still recompiles from scratch after this change, investigate whether
`cargoExtraArgs` or feature flags differ between `depsCache` and `rustClippy`.

---

## Open questions

- ~~Does `crane.fileset.commonCargoSources ./.` for `workspaceSrc` still admit
  `target/` `.rs` files?~~  **Verified: yes** — 59 `target/` files are admitted
  when `commonCargoSources` is called with the workspace root.  `workspaceSrc`
  therefore needs explicit `target/` exclusions (same as the current approach),
  but `mkCrateSrc` derivations do not since each crate dir does not contain a
  `target/` at its own root.  For `workspaceSrc`, use
  `pkgs.lib.fileset.difference` to subtract the known `target/` trees, or
  accept the subtractive list only for the workspace-wide derivations
  (`rustFmt`, `rustClippy`, `rustTests`).

- ~~The `protoPatchPhase` generates `prototext/fixtures/prebuilt/*.pb`.~~
  **Verified: not an issue** — `prebuilt/` is a subdirectory of
  `prototext/fixtures/`, which is already included in `prototextBare`/
  `prototext` src.

---

## Implementation notes

- `crane.fileset.cargoTomlAndLock`, `crane.fileset.commonCargoSources` are
  available in the pinned crane version (`80ceeec`).
- `pkgs.lib.fileset.maybeMissing` can be used for fixture dirs that may not
  exist on a fresh checkout.
- After implementing, verify with `nix-diff` that changing a single `.rs` file
  in `scoring-graph` does not invalidate the `prototext` derivation.
