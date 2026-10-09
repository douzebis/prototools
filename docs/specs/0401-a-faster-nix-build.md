<!--
SPDX-FileCopyrightText: Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0401 — a faster Nix build

Status: draft
App: build (default.nix, nix/*, .github/workflows/)
Refs: docs/specs/0402-a-nixpkgs-friendly-build.md (the conventions
        this must stay compatible with — it builds on the same
        committed WKT graph), prototext/wkt/prebuilt/README.md (the
        committed graph and its regeneration procedure),
        docs/specs/0374-a-workshop-image-for-every-laptop.md (S2: no
        cargo artifacts in the shipped closure)

## Background

Measured from the stored logs (`nix-store -l`) of one cold
`nix-build -A ci` on 12 cores, 2026-10-09. Derivations running in
parallel shared the CPU.

The critical path:

```
depsCache ~6 m ─▶ rustTests ~10.5 m ─▶ codec/graph ext ~1 m ─▶ wktRkyv (s)
   ─▶ fdp ext ~1 m + prototext (full) ~1 m ─▶ reproto ─▶ reproto tests, lint
```

That is about 20 minutes. Off the path, but competing for CPU:
`prototextBare` (6.5 m), `protolensUnwrapped` (6.5 m) and clippy. In
CI, the workshop image takes 26.5 minutes on arm64 (run 37899074900).

Why it takes so long:

1. **The pyo3 extensions are built from the test artifacts.**
   `makePyo3Extension` sets `cargoArtifacts = rustTests`
   (`rust.nix:410`). So `wktRkyv`, `prototext`, reproto and the
   workshop image all wait for the whole test suite to compile and
   run.
2. **The same workspace build happens twice.** `prototextBare` and
   `protolensUnwrapped` run the same `cargo build --release
   --workspace --features prebuilt-wkt` from the same deps cache. Each
   takes 6.5 minutes.
3. **Bootstrap stages.** The WKT graph is generated at build time
   (`wktRkyv`) by reproto, which needs the graph extension. The graph
   is then embedded in a second build of prototext (`prototext` full,
   `--features wkt-db`) and of `fdp_scan_lib`. Yet the committed copy
   in `prototext/wkt/prebuilt/` is **byte-identical** to the generated
   one (checked with `cmp`). Nothing checks that it stays that way: the
   README only describes a manual copy.
4. **Python → Rust coupling.** `reprotoSrc` is `builtins.path` over all
   of `reproto/` (`python.nix:45`). Any edit there, a doc included,
   regenerates `wktRkyv`, which rebuilds prototext (full) and the fdp
   extension.
5. **`reprotoBare` is vestigial.** `patch_reproto.sh` takes its path as
   `$1` and never uses it (line 32). The derivation only carries
   `patch/` to `reprotoSrcFull`.
6. **The extensions rebuild their dependencies.** `-p X --lib`
   (`rust.nix:416`) resolves features differently from the workspace,
   so `libc`, `hashbrown`, `pyo3`, `rand` and others (15 to 23 units)
   are rebuilt about 1 minute per extension. `workspace-hack` does not
   cover them.
7. **Tests compile with LTO.** `profile.release` is `codegen-units=1,
   lto="thin"`. `rustTests` spends 10m19s compiling and about 15
   seconds running.
8. **CI runs things one after another.** `nix.yml` runs `-A rust-fmt`,
   then `-A rust-clippy`, then `-A ci` as separate steps. `ci` already
   contains clippy, so the tests cannot start until clippy is done.

## Goals

- **G1.** One build of each shipped binary, `prototext` and
  `protolens`. Each shipped derivation compiles the workspace once.
- **G2.** No bootstrap stage on the path to a shipped output. The
  committed WKT graph is the only one shipped, and a check fails `ci`
  if it no longer matches what the code would generate.
- **G3.** Tests gate `ci`, not the packages. A package does not wait for
  the test suite to compile and run.
- **G4.** A pure-Python or documentation edit rebuilds no Rust.
- **G5.** Halve the cold critical path of `nix-build -A ci`, measured
  as in Background.

## Non-goals

- **N1.** Committing the other generated files: the fixtures in
  `prototext/fixtures/prebuilt/*.pb`, the `.pb` files of
  `reprotoSrcFull`, and the tree-sitter `parser.c`. Each takes seconds
  to generate and none of them is a bootstrap stage. Committing them
  adds sync checks for no measurable gain.
- **N2.** A shared binary cache (cachix or attic). It needs an account
  and a CI secret, which is a decision for the user, not the build.
  Magic Nix Cache stays. Whether it actually hits on warm runs has not
  been verified; that check belongs in the test plan, not in this
  spec.
- **N3.** Replacing crane. Its shared deps cache is the main reason the
  build is not slower still (spec 0402 N1).
- **N4.** Filling the `workspace-hack` gaps (Background item 6). S1
  removes the `-p` builds that need them. If it does not, reopen this.

## Specification

- **S1. One workspace build, everything installed from it.**
  - A single derivation, `workspaceBuild`, replaces `prototextBare`
    and `protolensUnwrapped`. It runs `cargo build --release
    --workspace --features prebuilt-wkt` once, on `depsCache`, and
    installs from that build:
    - the `prototext` and `protolens` binaries;
    - the three pyo3 `.so` files and their `.pyi` stubs (the
      `*_post_build` bins are already built there).
  - `prototext`, `protolens`, `protolensLean` and the three extension
    packages become thin derivations that copy their part out of
    `workspaceBuild`'s outputs (multiple outputs, or one `runCommand`
    each).
  - The rule of spec 0374 S2 still holds: no cargo artifacts in a
    shipped closure. `workspaceBuild` sets
    `doInstallCargoArtifacts = false`.
- **S2. The committed WKT graph is what ships.**
  - Every shipped Rust build uses `prebuilt-wkt`. `prototext` (full)
    and the `wkt-db` feature build go away, and `fdp_scan_lib` embeds
    the committed graph.
  - This is the model the upstream draft uses (spec 0402 S9).
- **S3. A fail-safe check on the committed graph.**
  - `wkt-rkyv` is still generated as today, but it is now a leaf: no
    shipped output depends on it.
  - A new check, `wkt-prebuilt-check`, runs `cmp` on its two files
    against `prototext/wkt/prebuilt/`, and fails with:

    ```
    prototext/wkt/prebuilt/ is stale. Refresh it with:
      cp $(nix-build -A wkt-rkyv)/{wkt,wkt_index}.rkyv prototext/wkt/prebuilt/
    ```

  - `ci` includes the check, so a stale copy fails `ci` the same way a
    failing test does.
  - After S4, `wkt-rkyv` no longer depends on the tests. That makes
    the `GRAPH_VERSION` bump in the prebuilt README an ordinary
    refresh, so the manual bootstrap section of that README is deleted.
    This must be confirmed by a real version bump, or a simulated one
    (test plan item 3).
- **S4. Extensions off the test artifacts.** Nothing has
  `cargoArtifacts = rustTests`. The extensions come from
  `workspaceBuild` (S1).
- **S5. `prebuilt/` is a build input to cargo.** `prototext/build.rs`
  emits `cargo:rerun-if-changed` for `wkt/prebuilt/*.rkyv` and
  `rerun-if-env-changed=WKT_RKYV`. This way an out-of-Nix
  `cargo build` picks up a refreshed copy.
- **S6. Drop `reprotoBare`.** `reprotoSrcFull` runs
  `${reprotoSrc}/patch/patch_reproto.sh` directly. The unused `$1`
  goes away.
- **S7. Narrow sources.** Build `reprotoSrc` with `lib.fileset`, from
  `src/`, `pyproject.toml` and `patch/` only. Check every Rust source
  fileset the same way: a Markdown file must not invalidate a Rust
  derivation.
- **S8. No LTO for tests.** A Cargo profile, `ci-test` (release
  without LTO, `codegen-units = 16`), is used by `rustTests` and
  clippy. It has its own deps cache, built in parallel with the
  release one.
  - Adopt it only if test plan item 4 shows at least a 40 % gain on
    `rustTests`. Otherwise drop this clause.
- **S9. CI in one build.** `nix.yml` keeps `rust-fmt` as a fast first
  step, then runs a single `nix-build -A ci`. The separate clippy step
  goes away.

## Compatibility with spec 0402

- S2 and S3 make the out-of-tree build ship the same WKT graph as the
  upstream draft. Both specs rely on the one committed copy, and S3 is
  what keeps it honest for both.
- S1 keeps crane (0402 N1). The upstream draft builds each package
  separately with `buildRustPackage`, so it gets none of S1's sharing,
  which is acceptable upstream.
- 0402's strictDeps, meta, `env.*` and `canExecute` guards apply
  unchanged to the S1 derivations.

## Alternatives considered

- **Keep the fresh graph and add only the check.** This closes the sync
  gap but keeps the bootstrap stages (G2) and the Python → Rust
  coupling (G4). The fresh graph and the committed one are
  byte-identical today, so the second build buys nothing.
- **Commit the whole `wktDb` (`wkt-db.desc`, `proto/`, the `.rkyv`
  files).** This would remove reproto from `wktDb`'s inputs too.
  `wktDb` is a leaf, so the gain is off the critical path, while the
  committed surface (and the S3 check) would grow from 2 files to a
  tree. Revisit if `wktDb` ever ends up on the critical path.
- **Build the extensions with `cargoArtifacts = workspaceBuild` and
  `-p X`.** This is cheaper to implement than installing from one
  build, but it keeps Background item 6: about 1 minute of dependency
  rebuilds per extension.

## Test plan

1. **Before/after timings.** A cold `nix-build -A ci` on the same
   12-core VM; record the critical path from `nix-store -l` timestamps.
   Target: ≤ 10 minutes (G5).
2. **Staleness check.** `nix-build -A wkt-prebuilt-check` passes. Flip
   one byte of `prototext/wkt/prebuilt/wkt.rkyv` and it fails, with the
   refresh command (S3).
3. **Format bump.** Bump `GRAPH_VERSION` on a scratch branch.
   `nix-build -A wkt-rkyv` succeeds, and the refresh command makes
   `ci` green again without the manual procedure (S3).
4. **Test profile.** `rustTests` compile time with and without
   `ci-test` (S8 decision).
5. **No Rust rebuild for Python.** Touch `reproto/README.md`, then
   `nix-build -A ci --dry-run`: no Rust derivation is listed (G4, S7).
6. **One build per binary.** `nix derivation show -r -A ci` contains
   one `cargo build --release` derivation for prototext/protolens
   (G1).
7. **Shipped closure.** `nix-build -A grehack2026.image` passes its
   closure check, and `grehack2026/smoke-test.sh` passes 18 of 18
   (spec 0374).
8. **CI cache.** A second run of `workshop-image.yml` on the same
   commit; record whether Magic Nix Cache made it a no-op (N2).

## Measured outcome

Filled in at implementation.
