<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0101 — Drop `protox` dependency

**Status:** implemented
**App:** prototext
**Implemented in:** 2026-06-16

---

## Problem

`protox` (a pure-Rust proto compiler) was introduced in spec 0022 so that
crates.io consumers could build `prototext` with `cargo build` alone — no
system `protoc` required.  The three `.pb` descriptor files needed by
`build.rs` would be compiled on the fly by `protox`.

Since then, the publication pipeline has evolved (spec 0098): `.crate`
tarballs are now assembled by the Nix `crates-io` derivation, which runs
`protoc` via `protoPatchPhase` before `cargo package`.  This means `protox`
is no longer the only way to get the `.pb` files into a publishable tarball.

However, `protox` is still required today because `fixtures/prebuilt/` is
gitignored, so `cargo package` does not include the `.pb` files in the
`.crate` tarball — crates.io consumers download a source tree with no `.pb`
files and no way to build without `protox`.

`protox` has become confusing:
- Nix builds already disable it (`--no-default-features`).
- nixpkgs disables it (`buildNoDefaultFeatures = true`).
- New MessageSet fixture schemas require proto2 extensions that `protox`
  cannot compile (it lacks full proto2 support).
- It introduces a non-trivial transitive dependency for a use-case that can
  be handled more simply.

---

## Goals

1. Remove `protox` and its Cargo feature flag from `prototext` entirely.
2. Ensure crates.io consumers can still build `prototext` with `cargo build`
   alone, with no external tools.
3. Ensure the nixpkgs package definition (`./nixpkgs`) continues to work
   unchanged.
4. Lay the groundwork for adding MessageSet fixture schemas compiled by
   `protoc` (not `protox`).

---

## Non-goals

- Changing the compiled output or runtime behaviour of `prototext`.
- Removing `protoc` from the Nix build environment (still needed for WKT
  compilation and for populating `fixtures/prebuilt/`).
- Supporting builds outside Nix without `protoc` for users who want to
  modify the `.proto` fixture schemas.

---

## Key insight

`cargo package` respects `.gitignore` by default, but it also respects an
explicit `include` list in `Cargo.toml`.  Files listed under `[package]
include` are always bundled, regardless of `.gitignore`.

By adding the prebuilt `.pb` files to `prototext/Cargo.toml`'s `include`
list, `cargo package` will embed them in the `.crate` tarball.  The
`crates-io` Nix derivation already runs `protoPatchPhase` (which populates
`fixtures/prebuilt/`) before `cargo package`, so the files will be present
and picked up.

The `build.rs` `copy_prebuilt` path already handles this case: it copies
`.pb` files from `fixtures/prebuilt/` (or from `DESCRIPTOR_PB` / `KNIFE_PB`
/ `ENUM_COLLISION_PB` env vars as a fast path).  No new `build.rs` logic is
needed — we only need to:

1. Make `copy_prebuilt` the sole code path (drop the `protox` branch).
2. Tell `cargo package` to include `fixtures/prebuilt/*.pb` via `include`.

---

## Specification

### S1 — Update `prototext/Cargo.toml`

Remove the `protox` optional build-dependency and feature flag.  Remove
`protox` from the `default` feature list.  Add an `include` list so
`cargo package` bundles the prebuilt `.pb` files:

```toml
[package]
# ... existing fields ...
include = [
  "src/**",
  "tests/**",
  "fixtures/schemas/**",
  "fixtures/prebuilt/descriptor.pb",
  "fixtures/prebuilt/knife.pb",
  "fixtures/prebuilt/enum_collision.pb",
  "wkt/**",
  "build.rs",
  "Cargo.toml",
]

[features]
default      = ["wkt-db"]
wkt-db       = []
prebuilt-wkt = []

[build-dependencies]
prost = "0.14"
# protox removed
```

### S2 — Simplify `prototext/build.rs`

Remove the `#[cfg(feature = "protox")]` branch entirely.  The `compile()`
helper and all `protox` imports go away.  Keep only the `copy_prebuilt` path,
now unconditional:

```rust
fn main() {
    let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR not set");
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR")
        .expect("CARGO_MANIFEST_DIR not set");

    copy_prebuilt(&out_dir, &manifest_dir);

    #[cfg(feature = "wkt-db")]
    build_wkt_graph(&out_dir, &manifest_dir);

    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=wkt/SOURCES");
    println!("cargo:rerun-if-changed=fixtures/schemas/knife.proto");
    println!("cargo:rerun-if-changed=fixtures/schemas/enum_collision.proto");
}
```

The `copy_prebuilt` function is unchanged: it reads from the env vars
(`DESCRIPTOR_PB`, `KNIFE_PB`, `ENUM_COLLISION_PB`) if set (Nix fast path),
otherwise copies from `fixtures/prebuilt/` (crates.io path, where the files
are now bundled via the `include` list).

### S3 — No changes to Nix files

`nix/rust.nix` already passes `--no-default-features` in `workspaceArgs`.
`default.nix` already defines `protoPatchPhase` which populates
`fixtures/prebuilt/`.  `nix/crates-io.nix` already applies `protoPatchPhase`
before `cargo package`.

None of these files need changes: the `--no-default-features` flag remains
valid (it disables `wkt-db` and `prebuilt-wkt` as before; it just no longer
has a `protox` feature to disable).

### S4 — No changes to the nixpkgs package

`nixpkgs/pkgs/by-name/pr/prototools/package.nix` already uses:

```nix
buildNoDefaultFeatures = true;
buildFeatures = [ "wkt-db" "prebuilt-wkt" ];
```

The `protox` feature no longer exists, so these flags remain valid with no
change.

### S5 — Mark spec 0022 as superseded

Update `docs/specs/0022-optional-protox.md`: change `Status` to
`superseded by spec 0101`.

---

## Verification

After implementation:

1. `nix-build -A ci` passes — `protox` is absent from the dependency graph.
2. `cargo build -p prototext` in the dev-shell succeeds (relies on
   `protoPatchPhase` having populated `fixtures/prebuilt/`).
3. Simulate a crates.io build: run `cargo package -p prototext --no-verify`
   inside the Nix sandbox, extract the tarball, confirm
   `fixtures/prebuilt/*.pb` are present, and verify `cargo build` succeeds
   from the extracted tarball with no external tools.
4. The nixpkgs package builds cleanly — no `protox`-related flags referenced.

---

## Summary of changes

| File | Change |
|---|---|
| `prototext/Cargo.toml` | Remove `protox` dep + feature; add `include` list |
| `prototext/build.rs` | Remove `#[cfg(feature = "protox")]` branch; keep only `copy_prebuilt` |
| `docs/specs/0022-optional-protox.md` | Status → superseded by spec 0101 |

No changes to `default.nix`, `nix/rust.nix`, `nix/crates-io.nix`, or
`nixpkgs/pkgs/by-name/pr/prototools/package.nix`.

---

## References

- `docs/specs/0022-optional-protox.md` — original `protox` opt-in spec (superseded)
- `docs/specs/0098-crates-io-publishing.md` — publication pipeline
- `prototext/build.rs` — current build script
- `prototext/Cargo.toml` — current feature flags
- `nix/crates-io.nix` — `.crate` packaging derivation
- `nixpkgs/pkgs/by-name/pr/prototools/package.nix` — nixpkgs package
