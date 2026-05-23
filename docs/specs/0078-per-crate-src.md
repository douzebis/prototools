<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0078 — Nix/Crane build system: dep-cache reuse and precise source sets

**Status:** partially implemented
**Implemented in:** 2026-05-22 (dep-cache reuse fix); per-crate src pending
**App:** nix

---

## Background

Spec 0066 overhauled `default.nix` and established design driver D1:

> **D1 — Compile each source file exactly once.**  A single shared `depsCache`
> covers the whole workspace.  No crate is compiled with different flags in
> different derivations — that would invalidate Cargo fingerprints and force a
> rebuild.

After the 0066 implementation, `prototextBare` and `prototext` were in practice
recompiling ALL external Rust dependencies on every build — `serde`, `typenum`,
`prost`, `rkyv`, `cfg-if`, and ~60 others — even though `depsCache` was
supposed to cache them.  The same `depsCache` was reused correctly by
`rustTests` and the PyO3 extensions, so the failure was specific to the prototext
binary derivations.

This spec documents the correct root-cause analysis of that failure, the fix
applied, and the remaining open work (precise per-crate source sets).

---

## Design drivers (from spec 0066, reproduced for reference)

### D1 — Compile each source file exactly once

A single shared `depsCache` covers the whole workspace.  No external dep is
compiled with different flags in different derivations — that would invalidate
Cargo fingerprints and force a rebuild.

The key invariant is: every Crane derivation that sets `cargoArtifacts =
depsCache` must invoke `cargo` with flags that produce **identical Cargo
fingerprints** for every external dep.  Fingerprints encode rustc version,
features, profile context (`unit_for`), path, and rustflags.  Any mismatch on
any field causes a cache miss and a full recompile of that dep.

### D2 — Fast `nix-build` iteration cycle

The `ci` target (linters + quick tests) must be cheap to rebuild after a
typical development change.  Derivation boundaries are drawn so that an
isolated source change invalidates the minimum number of downstream derivations.

### D4 — One source of truth per repeated pattern

Repeated structures are expressed once via a Nix helper function or named
constant.  Copy-pasted blocks drift apart under maintenance and create invisible
flag inconsistencies that break Cargo fingerprints.

---

## Root cause analysis: why `depsCache` was not reused

Two independent fingerprint mismatches caused `prototextBare` and `prototext`
to recompile all external deps from scratch.

### Cause 1 — Feature unification mismatch

Crane's `buildDepsOnly` (used for `depsCache`) internally runs
`cargo check --all-targets --workspace`, which unifies feature flags across
the entire workspace.  The 0066 implementation then built `prototextBare` using
`cargoExtraArgs = "-p prototext"`, which restricts the build to the `prototext`
package subtree.  Cargo computed the feature set for only that subtree — a
strict subset of the workspace union.

Concretely: crates like `syn` were requested with the `fold` feature in the
`--workspace` build (pulled in by `is-macro` → `rustpython-ast` →
`pyo3-stub-gen-derive`, a dependency of the PyO3 extensions), but without that
feature in the `-p prototext` build.

```
depsCache fingerprint for syn:   features = "[..., fold, ...]"
prototextBare fingerprint:       features = "[...]"   ← mismatch → recompile
```

**Fix layer 1: cargo-hakari / workspace-hack.**  Hakari generates a
`workspace-hack` crate that all workspace members depend on.  Its `Cargo.toml`
declares every external dep with the union of all features required across the
workspace.  With `workspace-hack` in place, both `--workspace` and `-p prototext`
invocations resolve to the same feature set for every dep — the `features`
field in every fingerprint is now identical.

### Cause 2 — Profile / `unit_for` mismatch

Even after hakari fixed the feature field, Cargo's `profile` hash in
fingerprints still differed.  The `profile` hash encodes the compilation
context, specifically the `unit_for` value — whether an artifact is being
compiled as a normal library, a test harness, a benchmark, or for a proc-macro
host.

`buildDepsOnly` uses `--all-targets`, which asks Cargo to compile each dep in
multiple profile contexts (normal lib, test, bench, proc-macro host) in a
single pass.  Each context produces a separate fingerprint entry.  A subsequent
`cargo build -p prototext` asks only for the normal-lib context, which is
assigned a **different `profile` hash** than any of the ones computed under
`--all-targets`.

Confirmed empirically by extracting and comparing fingerprint JSON files from
the `depsCache` and `prototextBare` tarballs:

```
depsCache   cfg-if profile hashes: 11322533822032096916, 11349332380231099618, 12093087204756198503
prototextBare (-p prototext):      cfg-if profile hash:   1783587453833569552
```

None of the `depsCache` hashes matched the one needed by `-p prototext` →
full recompile of `cfg-if` (and every other external dep).

A two-phase `buildPhaseCargoCommand` was attempted as an intermediate fix:
run `cargo build --workspace` first (to warm the cache with matching
fingerprints), then run `cargo build -p prototext --message-format
json-render-diagnostics` to produce the JSON install log.  This did not work:
the second `-p prototext` invocation still computed its own profile hashes,
independent of the first, and the `depsCache` fingerprints still didn't match.

**Fix layer 2: single `--workspace` invocation with manual `installPhaseCommand`.**
Drop the `-p prototext` scoped invocation entirely.  Use a single
`cargo build --workspace` — the same command `depsCache` was built with — so
all profile contexts match exactly.  Install the prototext binaries by copying
them directly by name in `installPhaseCommand`, bypassing the
`installFromCargoBuildLogHook` that required the JSON log (see Implementation
section for details).

### Why `rustTests` and PyO3 extensions were unaffected

- `rustTests` uses `cargoExtraArgs = "--no-default-features --workspace"` — the
  same scope as `depsCache` — so profile hashes match.
- PyO3 extensions use a custom `buildPhaseCargoCommand` with an explicit
  `-p <crate> --lib` invocation, but they chain off `rustTests`
  (`cargoArtifacts = rustTests`), not `depsCache`.  Their fingerprints are
  consistent within that chain.

---

## What was wrong with the original 0078 hypothesis

The original 0078 spec (titled "Precise source sets and per-crate incremental
Crane builds") identified the root cause as **imprecise `src` inputs**:
`workspaceSrc` being too broad caused cache misses whenever any file in the
workspace changed, even in unrelated crates.

This is a real inefficiency (D2), but it is **not** the cause of the dep
recompilation problem.  Crane uses `cargoArtifacts` (the tarball of the
previous build's `target/`) to transfer the compiled dep cache between
derivations, not `src`.  A change in `src` causes the derivation's own Nix
output hash to differ, triggering a fresh Nix build — but within that build,
Cargo still reuses artifacts from the decompressed `cargoArtifacts` tarball as
long as the Cargo fingerprints match.  The dep recompilation was happening
because fingerprints did **not** match, for the feature/profile reasons above,
entirely independently of `src` precision.

The per-crate `src` goal remains valid as a D2 (iteration speed) improvement,
but it is a separate problem from D1 (compile each dep once).

---

## Goals

### Already implemented (2026-05-22)

1. **D1 restored**: `prototextBare` and `prototext` now reuse `depsCache`
   without recompiling any external dep.  Only the 7 workspace crates are
   compiled in each derivation (~43 s, down from ~10 min).  The
   `target.tar.zst` artifact shrank from 67.9 MiB to 8.91 MiB.

2. **Feature unification**: `workspace-hack` (cargo-hakari) ensures every
   cargo invocation — regardless of scope — resolves the same feature set
   for every external dep.

3. **Profile consistency**: `prototextBare` and `prototext` use a single
   `cargo build --workspace` invocation, matching the profile contexts
   baked into `depsCache` by `buildDepsOnly`.

### Still to do

4. **Per-crate `src`** (D2): replace the single `workspaceSrc` used by
   `prototextBare`, `prototext`, and the PyO3 extensions with per-crate source
   sets, so that a `.rs` change in `scoring-graph` does not trigger a rebuild
   of `prototext`.  The `workspaceSrc` subtractive `target/` exclusion list
   is also eliminated in this step.

5. **`depsCache` on `depsSrc`** (D2, D1): switch `depsCache` to use
   `depsSrc` (manifest-only) as its `src`, so that `.rs` changes never
   invalidate the dep cache.  Currently `depsCache` uses `workspaceSrc` for
   Crane fingerprint-matching reasons; verify this is still necessary after
   the per-crate `src` change.

6. **`docs/nix-build-guide.md`** (spec 0066 S8): write the build system guide
   covering the correct Crane dep-cache strategy, the hakari maintenance
   workflow, the PyO3 extension pattern, the reproto codegen pipeline, and the
   `ci`/`full-tests` split.

---

## Non-goals

- Changing the Cargo workspace structure.
- Migrating to flakes.
- Changing any installed binary or Python package behaviour.

---

## Specification

### S1 — Single `--workspace` build for `prototextBare` and `prototext`

Both derivations use:

```nix
buildPhaseCargoCommand           = "cargoWithProfile build ${workspaceArgs}";
doNotPostBuildInstallCargoBinaries = true;
installPhaseCommand              = ''
  mkdir -p $out/bin
  cp target/release/prototext $out/bin/
  cp target/release/prototext-gen-man $out/bin/
'';
```

`workspaceArgs = "--no-default-features --workspace"`.  For `prototext` (full),
`--features wkt-db` is appended.

`doNotPostBuildInstallCargoBinaries = true` disables `installFromCargoBuildLogHook`,
which normally reads a JSON build log (produced by `--message-format
json-render-diagnostics`) to decide which binaries to install.  That hook
requires a scoped `-p prototext` invocation to produce the log, which breaks
fingerprint consistency.  The direct `cp` in `installPhaseCommand` is simpler
and avoids the issue entirely — the same pattern used by the PyO3 extensions.

### S2 — `workspace-hack` (cargo-hakari)

A `workspace-hack` crate is generated by `cargo hakari generate` and committed
to git (like `Cargo.lock`).  All workspace members declare it as a dependency:

```toml
[dependencies]
workspace-hack = { version = "0.1", path = "../workspace-hack" }
```

Hakari's `workspace-hack/Cargo.toml` lists every external dep with the
union of features required across all workspace members.  This ensures that
`-p <crate>` and `--workspace` cargo invocations compute identical feature sets
for every external dep.

**Maintenance:** run `cargo hakari generate && cargo hakari manage-deps` and
commit the result whenever the dependency graph changes (new crate, new
feature dependency).  `cargo hakari verify` can be added to CI to detect
stale `workspace-hack`.

### S3 — Per-crate `src` (pending)

Replace the single `workspaceSrc` used by per-derivation builds with focused
per-derivation sources using `pkgs.lib.fileset.toSource`:

```nix
mkCrateSrc = { crateDir, extraFixtures ? [] }:
  pkgs.lib.fileset.toSource {
    root    = ./.;
    fileset = pkgs.lib.fileset.unions ([
      (crane.fileset.cargoTomlAndLock ./.)
      (crane.fileset.commonCargoSources crateDir)
    ] ++ extraFixtures);
  };
```

`lib.fileset` operates on files (not directories), so `target/` is naturally
excluded.  The subtractive `target/` exclusion list in `workspaceSrc` is
eliminated.

Per-derivation `src` assignments:

| Derivation | `src` |
|---|---|
| `depsCache` | `workspaceSrc` (unchanged; `depsSrc` may be usable — verify) |
| `rustFmt`, `rustClippy`, `rustTests` | `workspaceSrc` |
| `prototextBare`, `prototext` | `mkCrateSrc { crateDir = ./prototext; extraFixtures = [ (fixtureFilter ./prototext/fixtures) ]; }` |
| `prototextCodec` | `mkCrateSrc { crateDir = ./prototext-pyo3; }` |
| `fdpScanLib` | `mkCrateSrc { crateDir = ./fdp-scan-pyo3; }` |
| `scoringGraphLib` | `mkCrateSrc { crateDir = ./scoring-graph-pyo3; }` |

Note: per-crate `src` reduces the Nix-level rebuild scope (D2), but does not
affect D1 (dep-cache reuse) since Crane transfers the dep cache via
`cargoArtifacts`, not via `src`.

### S4 — `docs/nix-build-guide.md` (pending)

Write `docs/nix-build-guide.md` covering:

- File layout: `default.nix` (thin entry point), `nix/rust.nix`,
  `nix/python.nix`, `nix/shells.nix`.
- The Crane dep-cache strategy: why `depsCache` is the keystone; the two
  fingerprint invariants (feature unification via hakari; profile consistency
  via `--workspace`); why `rustTests` and PyO3 extensions chain differently.
- The `workspace-hack` maintenance workflow.
- The `makePyo3Extension` pattern and how to add a new PyO3 crate.
- The reproto codegen pipeline (`reprotoSrc` → `reprotoSrcFull`).
- The `ci`/`full-tests` split and when to use each.
- Dev-shell conventions: what the shellHook does, what gets compiled locally.
- Platform notes: macOS `install_name_tool` path-length limit, `.so` vs
  `.dylib`.
- Limitations: Nix sandbox isolation; no artifact sharing between `nix-build`
  and `nix-shell`.

---

## Implementation notes

### Cargo fingerprint anatomy

Each Crane derivation that decompresses `cargoArtifacts` inherits a `target/`
directory whose `.fingerprint/` subdirectory contains one JSON file per
compilation unit.  A compilation unit is uniquely identified by: crate name,
version, `rustc` hash, `features` set, `profile` hash (encodes `unit_for`),
`path` hash, `deps` list, and `rustflags`.

Two cargo invocations reuse each other's artifacts only if **all** fields match.
The `profile` hash is particularly subtle: it encodes not just the
`--profile release` flag but also the *reason* a crate is being compiled
(normal lib vs. test harness vs. benchmark vs. proc-macro host).  `--all-targets`
causes Cargo to request all four contexts; a subsequent `-p <crate>` requests
only the context relevant to that crate — a strict subset, with different hashes.

### Why `depsSrc` may not be safe for `depsCache`

Crane's `buildDepsOnly` stub-replaces all workspace crate sources with dummy
`lib.rs` / `main.rs` files.  The resulting Cargo build graph is identical to a
full build in terms of external dep fingerprints.  If `depsCache` were built
from `depsSrc` (manifest-only) and a consuming derivation were built from
`workspaceSrc`, the `src` hashes would differ — but Crane uses `cargoArtifacts`
to transfer the cache, not `src`.  Whether `depsSrc` is safe for `depsCache`
therefore depends only on whether the Cargo fingerprints are stable, which they
are as long as `Cargo.toml`/`Cargo.lock` content is identical.  This should be
verified empirically after the per-crate `src` change.

---

## Verification

### D1 — dep recompilation eliminated (implemented)

Build log for `prototext-bare` after the fix:

```
cargo build --release --no-default-features --workspace
   Compiling workspace-hack v0.1.0
   Compiling prototext v0.2.0
   Compiling prototext-core v0.2.0
   Compiling fdp_scan_extension v0.2.0
   Compiling scoring-graph v0.1.0
   Compiling prototext_codec v0.1.0
   Compiling scoring_graph_extension v0.1.0
    Finished `release` profile [optimized] target(s) in 42s
```

7 workspace crates only.  Zero external deps recompiled.
`target.tar.zst`: 8.91 MiB (was 67.9 MiB).

### D2 — per-crate `src` (pending)

After implementing S3, verify with `nix-diff` that changing a single `.rs`
file in `scoring-graph` does not invalidate the `prototext` derivation.

---

## Test plan

- `nix-build -A ci` passes on all four CI platforms.
- `nix-build -A full-tests` passes.
- `reuse lint` passes.
- After S3: `nix-diff` confirms per-crate source isolation.
