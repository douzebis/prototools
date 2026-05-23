<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# Crane Recompilation Investigation — Resolved

## Problem

`prototextBare` and `prototext` were recompiling ALL external Rust deps
(`serde`, `typenum`, `prost`, `rkyv`, `cfg-if`, etc.) despite `depsCache`
supposedly caching them. The same deps compiled fine from cache in `rustTests`
and the PyO3 extensions.

## Confirmed Root Causes (two independent issues)

### 1. Feature unification mismatch

`depsCache` (`buildDepsOnly`) runs `cargo check --all-targets --workspace`,
which unifies feature flags across the entire workspace. When `prototextBare`
then ran `cargo build -p prototext`, Cargo computed the feature set only for
the `prototext` package subtree — a strict subset. Some crates (notably `syn`)
were requested with different feature sets in the two invocations (e.g. the
`fold` feature pulled in by `is-macro` → `rustpython-ast` → `pyo3-stub-gen-derive`
in the full workspace, but not in the `-p prototext` subtree).

Different feature flags → different Cargo fingerprint `features` field → cache
miss → recompile.

**Fix applied:** `cargo-hakari` / `workspace-hack` crate. Hakari generates a
`workspace-hack` crate that all workspace members depend on. Its `Cargo.toml`
lists every dep with the union of all features required by any crate in the
workspace. With it in place, a `-p prototext` build and a `--workspace` build
both resolve to the same feature set for every external dep.

### 2. Profile / `unit_for` mismatch

Even after hakari fixed feature hashes, Cargo's `profile` field in fingerprints
still differed. `buildDepsOnly` internally uses `--all-targets`, which causes
Cargo to compile each dep in multiple *profile contexts* (normal lib, test
harness, bench, proc-macro host). A subsequent `cargo build -p prototext`
needs deps only in the normal-lib context, which maps to a different
`profile` hash — so even with matching features, the fingerprints don't match.

Confirmed by extracting and comparing fingerprint JSON files from both tarballs:

```
depsCache   cfg-if profile hashes: 11322533822032096916, 11349332380231099618, 12093087204756198503
prototextBare (2-phase): cfg-if profile hash: 1783587453833569552
```

None of the depsCache hashes matched → full recompile.

**Fix applied:** replace the two-phase `buildPhaseCargoCommand` (which ran
`--workspace` then `-p prototext`) with a **single** `cargo build --workspace`
invocation. This uses the exact same flags as `depsCache`, so all profile
contexts match.

## Why the Original Two-Phase Approach Was Wrong

The first attempt used:
```bash
cargoWithProfile build --no-default-features --workspace   # phase 1
cargoWithProfile build --message-format json-render-diagnostics \
  --no-default-features -p prototext >"$cargoBuildLog"    # phase 2
```

Phase 2 (`-p prototext`) still computed a fresh set of profile hashes for all
deps even though phase 1 had already built them. Cargo's fingerprint for an
external dep encodes the *requesting crate's* compilation context, not just the
dep's own features. The second invocation's context (`-p prototext`, single
crate) differs from the first (`--workspace`, all crates) → new fingerprints →
recompile.

## Why `-p prototext` Was There in the First Place

Crane's `installFromCargoBuildLogHook` reads a JSON build log produced by
`--message-format json-render-diagnostics` to know which workspace binaries to
install in `$out/bin/`. Without a scoped `-p prototext` log, the hook would
see all workspace binaries.

## Why the Original Hypothesis Was Wrong

The memo previously attributed the recompilation to a source hash difference
from `.pb` files in `prototext/fixtures/prebuilt/`. This was disproved: even
with a stable source hash (after the patchPhase was already a no-op in later
tests), the recompilation persisted. The actual cause was feature/profile
fingerprint mismatch as described above.

## Final Fix

**Single `cargo build --workspace` + manual `installPhaseCommand`**, bypassing
`installFromCargoBuildLogHook` entirely — the same pattern the PyO3 extensions
already use.

```nix
buildPhaseCargoCommand           = "cargoWithProfile build ${workspaceArgs}";
doNotPostBuildInstallCargoBinaries = true;
installPhaseCommand              = ''
  mkdir -p $out/bin
  cp target/release/prototext $out/bin/
  cp target/release/prototext-gen-man $out/bin/
'';
```

Applied to both `prototextBare` and `prototext` (full, with `--features wkt-db`
appended to the workspace build).

## Verification

Build log for `prototext-bare` after the fix (2026-05-22):

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

7 compilation units — all workspace crates, zero external deps recompiled.

`target.tar.zst` size: **8.91 MiB** (vs 67.9 MiB in the broken two-phase
build) — only incremental workspace-crate artifacts stored.

## Changes Applied

- `workspace-hack/` — hakari-generated crate (committed to git, like Cargo.lock)
- `.config/hakari.toml` — hakari configuration
- `LICENSES/Apache-2.0.txt` — required by REUSE for `MIT OR Apache-2.0` license
- `REUSE.toml` — annotation block for hakari-managed files
- `Cargo.toml` — `workspace-hack` added as workspace member
- `prototext/Cargo.toml`, `prototext-core/Cargo.toml`, `fdp-scan-pyo3/Cargo.toml`,
  `prototext-pyo3/Cargo.toml`, `scoring-graph/Cargo.toml`,
  `scoring-graph-pyo3/Cargo.toml` — each gained `workspace-hack` dep
- `nix/rust.nix` — `prototextBare` and `prototext` use single `--workspace`
  build with `installPhaseCommand` direct copy

## Maintenance Notes

- Regenerate `workspace-hack/Cargo.toml` with `cargo hakari generate &&
  cargo hakari manage-deps` when the dep graph changes (new crates, new
  features). Commit the result.
- The `workspace-hack/` crate is intentionally committed (like `Cargo.lock`).
  It is NOT gitignored.
- `cargo hakari verify` can be added to CI to detect stale workspace-hack.
