<!--
SPDX-FileCopyrightText: Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0402 — a nixpkgs-friendly build

Status: draft
App: build (default.nix, nix/*, nixpkgs/pkgs/)
Refs: docs/specs/0401-a-faster-nix-build.md (the speed work this must
        not undo — committed WKT graph, crane's artifact chain),
        prototext/wkt/prebuilt/README.md (the committed graph both
        specs build on)

## Background

No nixpkgs release packages prototools. 25.11 (our pin), 26.05 and
26.11 have no `prototext`, `protolens`, `reproto`, `fdp-scan` or
`protoscan` (`prototool` is an unrelated Uber tool). The maintainer
entry `douzebis` is already in `maintainer-list.nix`.

The repo holds an unsubmitted upstream draft in `nixpkgs/pkgs/`:

- `by-name/pr/prototools/package.nix`;
- three python-modules: `fdp-scan`, `prototext-codec` and `protoscan`.

When `nix/rust.nix` says "what nixpkgs already builds against", it
means this draft. The draft is stale:

- it pins 0.2.1 with the ThalesGroup homepage;
- it has no `protolens` and no `reproto`;
- the `fdp-scan` module would probably not build. The dependency in
  `fdp-scan-pyo3/Cargo.toml:20` turns on prototext's default
  features, not `prebuilt-wkt`, so `build.rs` would need `protoc` and
  `reproto`. That comes from reading the code; it has not been built.

These departures from the nixpkgs manual (pkgs/README.md,
CONTRIBUTING.md, rust.section.md, python.section.md) were found by an
audit against the 25.11 tree, on 2026-10-09:

| Topic | What the repo does |
|---|---|
| IFD | `default.nix:44` runs `callPackage (fetchgit crane)`. **Verified:** `nix-instantiate -A ci --option allow-import-from-derivation false` fails on `crane-….drv`. With crane pre-fetched, every top-level attribute evaluates with IFD off. |
| Rust builder | crane, which is not in nixpkgs. Upstream wants `buildRustPackage` with `cargoHash`. |
| Pinning | `default.nix:16-36` pins nixpkgs, plus a second pin just for `buf`. 26.05 ships buf 1.72, which is past the 1.61 fix that pin works around. |
| Shape | Every file takes `pkgs` wholesale (`import ./nix/rust.nix { pkgs … }`). Nothing is `callPackage`-shaped. |
| meta | reproto, protoscan, the pyo3 packages, wktDb and the tree-sitter derivations have none. `rust.nix:183,286` say `maintainers = [ ]  # add: douzebis once registered`. `rust.nix:174` puts the binary name in the description. Homepages disagree. |
| Versions | The evaluated names are `prototext-0.1.4` and `protolens-0.1.4`, but Cargo says 0.2.1 and 0.1.0. reproto and protoscan come out as 0.1.0, but pyproject says 0.2.1. `crates-io.nix` says 0.2.0. |
| Python | reproto and protoscan already set `pyproject = true`, but the pyo3 packages use `format = "pyproject"` (`rust.nix:446`) and the textproto package `format = "other"` (`python.nix:65`), both deprecated. `propagatedBuildInputs` should be `dependencies`. hatchling and setuptools sit in `buildInputs`/`nativeBuildInputs`, not `build-system`. pytest is in the package inputs. `types-protobuf` is a runtime dependency. The CLIs use `buildPythonPackage`. |
| Inputs | No `strictDeps`. `pythonBin` sits in `buildInputs` only to run `python3-config`. libpython is linked by a global `RUSTFLAGS -lpython` (`default.nix:187`), which contradicts pyo3's `extension-module`. |
| Phases | `patchPhase` is replaced wholesale (`default.nix:149`, `rust.nix:451`, no `runHook`). Variables sit at top level instead of under `env.*`. `postInstall` runs the fresh binaries (completions, man pages, stubs) with no `canExecute` guard, so a cross build breaks. `target/release/…` is hard-coded. |
| Tests | Every package has `doCheck = false`. Tests run as separate `runCommand`s, and none is exposed as `passthru.tests`. There is no `pythonImportsCheck` and no `versionCheckHook`. |
| Names | The `treeSitterTextproto*` derivations set `name`, not `pname` + `version`. |
| Format | Aligned `=` and leading commas; nixfmt would reject them. |

Already conformant, kept as is:

- `lib.fileset` filtering;
- every external input is a fixed-output fetch, so builds need no
  network;
- `makeWrapper`;
- the committed generated artifacts (`wkt/prebuilt/*.rkyv`, `.pyi`
  stubs, `descriptor.pb`). pkgs/README recommends exactly that as the
  way around IFD.

## Goals

- **G1.** The out-of-tree `default.nix` stays what it is — the
  developer and CI build, crane and all — but it no longer breaks a
  rule that costs nothing to follow: no IFD, correct metadata, strict
  inputs, cross-safe phases.
- **G2.** The upstream draft in `nixpkgs/pkgs/` is complete (all
  shipped tools) and is built by CI, so it cannot go stale again.
- **G3.** Both share one source of truth for versions and for the
  committed WKT graph.

## Non-goals

- **N1.** Replacing crane in `default.nix`. Its dependency cache and
  artifact chain are what spec 0401 relies on for speed; nixpkgs has
  no equivalent. Upstream gets its own `buildRustPackage` expression
  instead (S9).
- **N2.** Submitting the nixpkgs PR. This spec makes it possible; when
  to submit is a separate decision.
- **N3.** nixfmt across the whole repo. Only the files meant for
  upstream (`nixpkgs/pkgs/`) must pass it.
- **N4.** Following the `pythonPkgs` argument instead of the
  hard-coded Python version (`cp313`, `"3.13"`). It only matters when
  the pin changes, and the wheels in `pypi.nix` are 3.13 on purpose.
- **N5.** Repackaging the pyo3 extensions with `maturinBuildHook` in
  `default.nix`. Hatchling around a prebuilt `.so` works, and it reuses
  crane's build. The upstream draft uses the documented hook (S9).

## Specification

- **S1. No IFD.** Fetch crane at evaluation time with
  `builtins.fetchTarball { url; sha256; }`, not via
  `callPackage (fetchgit …)`. CI evaluates `ci` with
  `--option allow-import-from-derivation false`, so IFD cannot come
  back.
- **S2. One pin.** Drop the second nixpkgs pin used for `buf` when the
  main pin moves to ≥ 26.05. Until then, keep it, with its comment.
- **S3. Versions from the manifests.** Each package reads its version
  at evaluation time from its own `Cargo.toml` or `pyproject.toml`
  (`lib.importTOML`, which reads a source file and is not IFD). No
  version literal is left in `nix/`. `crates-io.nix` and `pypi.nix`
  read them the same way.
- **S4. meta on every installable output.**
  - Every output gets `description` (no binary name, no leading
    article), `homepage` (`https://github.com/douzebis/prototools`),
    `license = lib.licenses.mit` and `mainProgram` where there is one.
  - `maintainers = [ lib.maintainers.douzebis ]`.
  - `platforms = lib.platforms.unix`.
- **S5. Python conventions.**
  - Packages use `pyproject = true` with `build-system`.
  - Runtime dependencies go in `dependencies`.
  - `types-protobuf` and pytest go in `nativeCheckInputs`.
  - reproto and protoscan become `buildPythonApplication`.
  - Every Python package gets `pythonImportsCheck`.
- **S6. Strict inputs.**
  - `strictDeps = true` on every derivation.
  - Build tools go in `nativeBuildInputs`, libraries in `buildInputs`.
  - Drop the global `RUSTFLAGS -lpython`. Link libpython only where
    something embeds it, which may be nowhere. The test plan's closure
    check settles it.
- **S7. Cross-safe phases.**
  - Use `postPatch`, not `patchPhase`.
  - Put variables under `env`.
  - Guard every `postInstall` that runs a freshly built binary with
    `lib.optionalString (stdenv.buildPlatform.canExecute
    stdenv.hostPlatform)`.
  - Install from crane's or cargo's own output location, not a
    hard-coded `target/release`.
- **S8. Tests where nixpkgs looks for them.**
  - The existing `runCommand` checks stay; `ci` aggregates them.
  - Each check is also attached to its package as `passthru.tests`.
  - Binaries get `versionCheckHook`.
- **S9. The upstream draft is complete and built.**
  - Bring `nixpkgs/pkgs/` up to date:
    - prototools packages `prototext` and `protolens`, both with
      `--features prebuilt-wkt`;
    - add `reproto`;
    - fix `fdp-scan`'s features;
    - `pythonProtobuf` becomes `protobuf`;
    - `homepage` and `version` follow S3/S4, where the versions are
      literals, as upstream requires.
  - The draft must pass nixfmt.
  - A new attribute, `nixpkgs-draft`, `callPackage`s each draft file
    against the pinned nixpkgs. `src` is overridden to the local tree,
    so it builds today's code.
  - CI builds `nixpkgs-draft`.
- **S10. An overlay.** Add `overlay.nix`, which adds the S9 packages to
  any nixpkgs, so a user can compose them with their own pin.

## Alternatives considered

- **Port `default.nix` itself to `buildRustPackage`.** That would give
  one expression for both worlds. It is ruled out by speed:
  `buildRustPackage` rebuilds every dependency in every derivation. We
  have six cargo-built outputs plus clippy and tests, all sharing one
  crane deps cache (spec 0401).
- **Keep the draft untested and refresh it at submission time.** That
  is how it went stale (no protolens, broken fdp-scan). A draft nobody
  builds is not a draft.

## Test plan

1. `nix-instantiate -A ci --option allow-import-from-derivation false`
   evaluates (S1).
2. `nix-build -A nixpkgs-draft` builds every draft package, and each
   one's binary prints the manifest version (S3, S9).
3. `nixfmt --check nixpkgs/pkgs` is clean (S9).
4. `nix-store -qR $(nix-build -A prototext)` contains no libpython, and
   the pyo3 extensions still import in reproto's tests (S6).
5. `nix-build -A ci` is unchanged in what it runs. The `ci` linkFarm
   has the same set of check outputs as before, measured by listing it
   before and after.
6. A cross evaluation, `pkgsCross.aarch64-multiplatform`, of
   `prototext` gets past `postInstall` (S7). It is evaluated, not
   built, unless a builder is at hand.

## Measured outcome

Filled in at implementation.
