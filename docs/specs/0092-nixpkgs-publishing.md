<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0092 — Publishing prototools to nixpkgs

**Status:** draft
**Implemented in:** —
**App:** (build system / release — not app-specific)

---

## Background

nixpkgs is the package repository for the Nix ecosystem, with over 100,000
packages.  Publishing prototools there gives Linux and macOS users a
reproducible, one-command install path with no Python virtualenv management,
no Cargo toolchain, and full shell-completion and man-page support.

The project currently ships three user-facing CLI tools:

| Tool | Language | Runtime deps |
|---|---|---|
| `prototext` | Rust binary | none (self-contained) |
| `protoscan` | Python (Click) | `fdp_scan` PyO3 extension |
| `reproto` | Python (Click) | `prototext_codec` + `scoring_graph` PyO3 extensions, many Python libs, code-generation step |

And three PyO3 extensions (Rust `.so` files with Python bindings):

| Extension | Used by |
|---|---|
| `fdp_scan_lib` | `protoscan` |
| `prototext_codec_lib` | `reproto` |
| `scoring_graph_lib` | `reproto` |

---

## Design constraints

### C1 — `default.nix` remains the root for the GitHub repo

The existing `default.nix` / `nix/*.nix` build system is not modified for
nixpkgs purposes.  The nixpkgs `package.nix` is a separate file, maintained
alongside the source, that stands on its own.

### C2 — Single source of truth for generated artefacts

Binary artefacts that are expensive or complex to regenerate inside the
nixpkgs sandbox are committed to git.  The same committed files are used by
both the nixpkgs build and the crates.io/PyPI release paths.  Nix-specific
env-var overrides (e.g. `WKT_RKYV`) remain for the `default.nix` path, but
are not required by the nixpkgs path.

### C3 — No maturin in the build

The PyO3 extensions do not use maturin as their build tool — neither in
`default.nix` nor in the nixpkgs `package.nix`.  The shared build method is:
`cargo build --release --lib -p <crate>`, install the resulting `.so`.
This matches the existing `makePyo3Extension` pattern in `nix/rust.nix`.

### C4 — `.pyi` stubs committed to git

Type-stub `.pyi` files are committed to the repository next to the extension
source (e.g. `fdp-scan-pyo3/fdp_scan_lib/fdp_scan_lib.pyi`).  They are
regenerated locally by running `cargo run --bin fdp_scan_post_build` (etc.)
whenever the Rust API changes.  The nixpkgs build copies the committed stub
without running the stub-generator binary.

### C5 — No crane in the nixpkgs package

The nixpkgs `package.nix` uses only `rustPlatform` (available everywhere in
nixpkgs).  Crane is not a standard nixpkgs primitive and would complicate
review.  The sophisticated Crane pipeline in `default.nix` (shared dep cache,
artefact chaining) is not replicated; nixpkgs has its own caching layer.

---

## Phased roadmap

Publishing is split across three nixpkgs PRs to keep each one reviewable in
isolation.

### PR 1 — `prototools: init at <version>`

**Scope:** `prototext` (Rust binary) + `protoscan` (Python CLI) +
`fdp_scan` (PyO3 extension).

This scope is self-contained: no reproto dependency, no code-generation step,
no `tree-sitter-textproto` custom grammar, no circular bootstrap.

**New nixpkgs packages:**

| nixpkgs attribute | Type |
|---|---|
| `pkgs.prototools` | `symlinkJoin` of prototext + protoscan |
| `python3Packages.protoscan` | `buildPythonPackage` (setuptools) |
| `python3Packages.fdp-scan` | `buildPythonPackage` (cargo build --lib) |

Details in the Specification section below.

### PR 2 — `prototools: add reproto`

**Scope:** `reproto` (Python CLI) + `prototext_codec` + `scoring_graph`
PyO3 extensions + `tree-sitter-textproto` C extension.

See spec 0093 for the full design and implementation details.

---

## Goals (PR 1)

1. Add `prebuilt-wkt` Cargo feature to `prototext/Cargo.toml` and `build.rs`
   so the nixpkgs build can embed `wkt.rkyv` / `wkt_index.rkyv` from a
   committed path without calling `reproto` at build time (breaks the
   bootstrap cycle).
2. Commit `prototext/wkt/prebuilt/wkt.rkyv` and `wkt_index.rkyv` to git.
3. Commit `fdp_scan_lib.pyi` to git at the canonical path inside the
   `fdp-scan-pyo3` crate directory.
4. Write `pkgs/by-name/pr/prototools/package.nix` in the nixpkgs fork,
   packaging `prototext`, `fdp-scan`, and `protoscan`.
5. Add the maintainer entry to `maintainers/maintainer-list.nix`.
6. Verify `nix-build -A prototools` and `nix-build -A python3Packages.protoscan`
   pass on at least x86_64-linux and aarch64-linux.

---

## Non-goals (PR 1)

- `reproto` and its dependencies (PR 2).
- `prototext_codec` and `scoring_graph_lib` PyO3 extensions (PR 2).
- `treeSitterTextproto` (PR 2).
- Publishing to crates.io or PyPI.
- Modifying the existing `default.nix` / `nix/*.nix` build logic.
- nixpkgs tests beyond `pythonImportsCheck` (hardware not required).

---

## Specification (PR 1)

### §1 — `prebuilt-wkt` Cargo feature

#### §1.1 — `prototext/Cargo.toml`

Add a new feature:

```toml
[features]
default        = ["protox", "wkt-db"]
protox         = ["dep:protox"]
wkt-db         = []
prebuilt-wkt   = []          # use wkt/prebuilt/*.rkyv committed to git
```

`prebuilt-wkt` implies `wkt-db` in effect (both must be active together for
a useful build), but they are kept separate so that `wkt-db` retains its
existing meaning (embed the WKT graph) and `prebuilt-wkt` only controls
_how_ the graph files are obtained.

#### §1.2 — `prototext/build.rs`

In `build_wkt_graph()`, insert a new fast path at the top, before the
existing `WKT_RKYV` env-var check:

```rust
// Fast path: nixpkgs build — copy pre-generated files committed to git.
#[cfg(feature = "prebuilt-wkt")]
{
    let prebuilt = std::path::Path::new(manifest_dir).join("wkt/prebuilt");
    for (name, dst) in &[
        ("wkt.rkyv",       &wkt_rkyv_dst),
        ("wkt_index.rkyv", &wkt_index_dst),
    ] {
        let src = prebuilt.join(name);
        std::fs::copy(&src, dst)
            .unwrap_or_else(|e| panic!("failed to copy {name} from prebuilt: {e}"));
    }
    return;
}
```

Priority order in `build_wkt_graph()`:
1. `#[cfg(feature = "prebuilt-wkt")]` — copy from `wkt/prebuilt/` (nixpkgs)
2. `WKT_RKYV` env var set — copy from store path (`default.nix` full build)
3. Fall through — invoke `protoc` + `reproto` (crates.io / local dev)

The `#[cfg]` attribute ensures the `prebuilt-wkt` branch compiles away
entirely when the feature is not active, adding zero overhead to other build
paths.

#### §1.3 — Committed artefacts

Generate the files by running `nix-build -A prototext` (which exercises the
existing `wktRkyv` derivation) and copy from the store:

```
prototext/wkt/prebuilt/wkt.rkyv
prototext/wkt/prebuilt/wkt_index.rkyv
```

Add a `prototext/wkt/prebuilt/README.md` noting:
- These files are pre-generated by `nix-build -A prototext` and committed
  for use by the nixpkgs `package.nix` build.
- Regenerate whenever `reproto`'s scoring-graph format changes (rkyv version
  bump, Hopcroft algorithm change).
- The format is little-endian (rkyv `little_endian` feature) and therefore
  platform-independent.

Add a `.license` file (or entry in `REUSE.toml`) for the prebuilt directory.

### §2 — Committed `.pyi` stub for `fdp_scan_lib`

#### §2.1 — Location

Commit the stub at:

```
fdp-scan-pyo3/fdp_scan_lib/fdp_scan_lib.pyi
```

This is the path where `pyo3-stub-gen` writes it when
`cargo run --bin fdp_scan_post_build` is executed from the workspace root
with `CARGO_MANIFEST_DIR` pointing at `fdp-scan-pyo3/`.

#### §2.2 — Regeneration

Regenerate by running (inside the dev-shell):

```bash
cargo run --release --bin fdp_scan_post_build
```

Commit the updated file whenever the `fdp_scan` Rust API changes.

#### §2.3 — REUSE annotation

Annotate `fdp_scan_lib.pyi` with the project's standard copyright header via
`reuse annotate`.

### §3 — nixpkgs `package.nix` structure

The file lives at `pkgs/by-name/pr/prototools/package.nix` in the nixpkgs
fork.  It is a `callPackage`-style function returning a `symlinkJoin`.

High-level shape:

```
prototools = symlinkJoin {
  name  = "prototools-<version>";
  paths = [ prototext python3Packages.protoscan ];
  # protoscan already carries fdp-scan in its closure
};
```

The three constituent derivations are defined as `let` bindings within the
same file (or as separate `pkgs/development/python-modules/` entries — see
§3.3 for the decision).

#### §3.1 — `prototext` derivation

```nix
prototext = rustPlatform.buildRustPackage (finalAttrs: {
  pname   = "prototext";
  version = "<version>";

  src = fetchFromGitHub {
    owner = "douzebis";
    repo  = "prototools";
    tag   = "v${finalAttrs.version}";
    hash  = "sha256-...";
  };

  cargoHash = "sha256-...";

  # Disable protox (uses network at build time via the protox crate's
  # internal protoc bundling) and use the committed prebuilt-wkt files
  # instead of calling reproto at build time.
  buildNoDefaultFeatures = true;
  buildFeatures = [ "wkt-db" "prebuilt-wkt" ];

  # protoc is needed to compile fixture .pb files in patchPhase
  # (mirrors protoPatchPhase from nix/rust.nix).
  nativeBuildInputs = [ protobuf installShellFiles ];

  patchPhase = ''
    runHook prePatch
    mkdir -p prototext/fixtures/prebuilt
    protoc \
      --descriptor_set_out=prototext/fixtures/prebuilt/descriptor.pb \
      google/protobuf/descriptor.proto
    protoc \
      --descriptor_set_out=prototext/fixtures/prebuilt/knife.pb \
      --proto_path=prototext/fixtures/schemas \
      knife.proto
    protoc \
      --descriptor_set_out=prototext/fixtures/prebuilt/enum_collision.pb \
      --proto_path=prototext/fixtures/schemas \
      enum_collision.proto
    runHook postPatch
  '';

  # Tests require the full Crane pipeline (fixture .pb files, wktRkyv, etc.)
  # and are not run in the nixpkgs build.
  doCheck = false;

  postInstall = lib.optionalString
    (stdenv.buildPlatform.canExecute stdenv.hostPlatform) ''
    # Shell completions
    installShellCompletion --cmd prototext \
      --bash <(PROTOTEXT_COMPLETE=bash $out/bin/prototext | sed \
        -e 's|-o nospace -o bashdefault|-o nospace -o filenames -o bashdefault|g' \
        -e 's|words\[COMP_CWORD\]="$2"|local _cur="''${COMP_LINE:0:''${COMP_POINT}}"; _cur="''${_cur##* }"; words[COMP_CWORD]="''${_cur}"|') \
      --zsh  <(PROTOTEXT_COMPLETE=zsh  $out/bin/prototext) \
      --fish <(PROTOTEXT_COMPLETE=fish $out/bin/prototext)
    # Man page
    $out/bin/prototext-gen-man $out/share/man/man1
  '';

  meta = with lib; {
    description = "Lossless protobuf <-> enhanced textproto converter";
    homepage    = "https://github.com/douzebis/prototools";
    license     = licenses.mit;
    maintainers = with maintainers; [ douzebis ];
    mainProgram = "prototext";
    platforms   = platforms.unix;
  };
});
```

Notes:
- `buildNoDefaultFeatures = true` disables `protox` (which would try to
  compile `.proto` files using an embedded protoc binary obtained at
  crate-build time — unsuitable for an offline Nix build) and `wkt-db`'s
  default reproto invocation.
- `buildFeatures = [ "wkt-db" "prebuilt-wkt" ]` re-enables the WKT graph
  embedding using the committed `.rkyv` files.
- `doCheck = false`: the Rust test suite exercises fixture `.pb` files
  produced by the full Crane pipeline; it is not run here.
- The `postInstall` block is guarded by `canExecute` so cross-compilation
  (e.g. building for aarch64 on x86_64) does not fail trying to run the
  just-built binary.

#### §3.2 — `fdp-scan` PyO3 extension derivation

The extension is a `buildPythonPackage` that drives `cargo build --lib`
directly (no maturin, no crane).

```nix
fdp-scan = buildPythonPackage (finalAttrs: {
  pname   = "fdp-scan";
  version = "<version>";
  pyproject = true;

  inherit (prototext) src;   # same fetchFromGitHub

  cargoDeps = rustPlatform.fetchCargoVendor {
    inherit (finalAttrs) pname version;
    src = finalAttrs.src;
    hash = "sha256-...";
  };

  build-system = [ hatchling ];

  nativeBuildInputs = [
    cargo
    rustc
    rustPlatform.cargoSetupHook
  ];

  buildInputs = [ python3 ];

  env.PYO3_PYTHON = python3.interpreter;

  buildPhase = ''
    runHook preBuild
    cargo build --release --lib -p fdp_scan_extension \
      --offline \
      --frozen
    runHook postBuild
  '';

  installPhase = ''
    runHook preInstall
    site="$out/lib/${python3.libPrefix}/site-packages"
    mkdir -p "$site/fdp_scan_lib"
    # Rename lib<name>.{so,dylib} -> <name>.so (drop the "lib" prefix;
    # Python extension modules always use .so as the suffix, even on macOS).
    local libext
    libext=${lib.optionalString stdenv.isDarwin "dylib"}
    libext=''${libext:-so}
    cp "target/release/libfdp_scan_lib.$libext" \
       "$site/fdp_scan_lib/fdp_scan_lib.so"
    cp fdp-scan-pyo3/fdp_scan_lib/fdp_scan_lib.pyi \
       "$site/fdp_scan_lib/"
    cp fdp-scan-pyo3/fdp_scan_lib/__init__.py \
       "$site/fdp_scan_lib/"
    runHook postInstall
  '';

  pythonImportsCheck = [ "fdp_scan_lib" ];

  meta = with lib; {
    description = "Rust Python extension for scanning binaries for embedded protobuf blobs";
    homepage    = "https://github.com/douzebis/prototools";
    license     = licenses.mit;
    maintainers = with maintainers; [ douzebis ];
  };
});
```

Notes:
- `inherit (prototext) src` reuses the same `fetchFromGitHub` derivation —
  Nix deduplicates the fetch.
- The `.so` rename mirrors what `makePyo3Extension` does in `nix/rust.nix`.
  Python extension modules always use `.so` as their suffix even on macOS.
  The source library uses `.so` on Linux and `.dylib` on macOS; the
  `lib.optionalString stdenv.isDarwin` conditional selects the correct
  source extension at eval time (same pattern as `yb/package.nix`).
- `fdp_scan_lib/__init__.py` is confirmed present in the source tree.
- `cargoDeps` uses `rustPlatform.fetchCargoVendor` (the current
  nixpkgs-preferred approach for new packages; replaces `importCargoLock`).

#### §3.3 — Python package placement decision

Two options:

**Option A** — All three derivations (`prototext`, `fdp-scan`, `protoscan`)
defined as `let` bindings inside a single
`pkgs/by-name/pr/prototools/package.nix`, with `prototools` as the top-level
`symlinkJoin`.

**Option B** — Separate files:
- `pkgs/by-name/pr/prototools/package.nix` — `prototext` + `symlinkJoin`
- `pkgs/development/python-modules/fdp-scan/default.nix`
- `pkgs/development/python-modules/protoscan/default.nix`

Option B is more idiomatic for nixpkgs (Python modules live under
`python-modules/`) and makes PR 2 (adding `reproto`) cleaner — `reproto`
can simply add itself to the `symlinkJoin` without restructuring.  Option A
is simpler for PR 1 but would require splitting later.

**Decision:** Option B.  Use separate `python-modules/` files from the start.
`pkgs/by-name/pr/prototools/package.nix` becomes a thin combiner:

```nix
{ symlinkJoin, prototext, python3Packages }:
symlinkJoin {
  name  = "prototools-${prototext.version}";
  paths = [ prototext python3Packages.protoscan ];
  meta  = prototext.meta // { mainProgram = "prototext"; };
}
```

#### §3.4 — `protoscan` derivation

Plain `buildPythonPackage`, no Rust:

```nix
{ lib, buildPythonPackage, fetchFromGitHub, setuptools, wheel,
  click, protobuf, fdp-scan, installShellFiles, python3 }:

buildPythonPackage (finalAttrs: {
  pname   = "protoscan";
  version = "<version>";
  pyproject = true;

  src = fetchFromGitHub {
    owner = "douzebis";
    repo  = "prototools";
    tag   = "v${finalAttrs.version}";
    hash  = "sha256-...";
  };

  sourceRoot = "${finalAttrs.src.name}/protoscan";

  build-system = [ setuptools wheel ];

  dependencies = [ click protobuf fdp-scan ];

  nativeBuildInputs = [ installShellFiles ];

  doCheck = false;

  postInstall = lib.optionalString
    (stdenv.buildPlatform.canExecute stdenv.hostPlatform) ''
    installShellCompletion --cmd protoscan \
      --bash <(_PROTOSCAN_COMPLETE=bash_source $out/bin/protoscan)
    $out/bin/protoscan-gen-man $out/share/man/man1
  '';

  pythonImportsCheck = [ "protoscan" ];

  meta = with lib; {
    description = "Scan binary files for embedded protobuf FileDescriptorProto blobs";
    homepage    = "https://github.com/douzebis/prototools";
    license     = licenses.mit;
    maintainers = with maintainers; [ douzebis ];
    mainProgram = "protoscan";
    platforms   = platforms.unix;
  };
})
```

Note: `sourceRoot` points into the `protoscan/` subdirectory of the
monorepo source tree.

### §4 — Maintainer entry

`douzebis` is already registered in `maintainers/maintainer-list.nix` (added
as part of the `yb` package).  No maintainer commit is needed.

### §5 — Commit sequence for the nixpkgs PR

1. `prototools: init at <version>` — adds `package.nix`, `fdp-scan`, `protoscan`

### §6 — Source-repo changes (oss-prototools)

Before the nixpkgs PR can be written, the following must be committed to
the oss-prototools repository and included in the release tag:

| File | Action |
|---|---|
| `prototext/Cargo.toml` | Add `prebuilt-wkt` feature |
| `prototext/build.rs` | Add `prebuilt-wkt` fast path in `build_wkt_graph()` |
| `prototext/wkt/prebuilt/wkt.rkyv` | Commit generated file |
| `prototext/wkt/prebuilt/wkt_index.rkyv` | Commit generated file |
| `prototext/wkt/prebuilt/README.md` | Regeneration instructions |
| `fdp-scan-pyo3/fdp_scan_lib/fdp_scan_lib.pyi` | Commit generated stub |

REUSE compliance: run `reuse annotate` on the new files and `reuse lint`
before committing.

### §7 — PR 1 message draft

The PR title follows nixpkgs convention: `prototools: init at <version>`.

The body fills in the standard template and adds the context sections below.

---

```
prototools: init at <version>

This is **PR 1 of 2**.  It adds `prototools`, a monorepo of Protocol Buffer
utilities open-sourced by ThalesGroup
(https://github.com/ThalesGroup/prototools, 8 stars).

PR 1 (this PR) packages `prototext` and `protoscan`, together with the
`fdp-scan` PyO3 Rust extension they depend on.

PR 2 (follow-up) will add `reproto`, which requires additional Python
dependencies and a code-generation step; it is kept separate to limit review
surface.

---

### What this adds

**`pkgs.prototools`** — a `symlinkJoin` of:

- **`prototext`** — a Rust CLI that converts protobuf binary wire format to
  and from an enhanced textproto representation, with lossless round-trip.
  It embeds a pre-built Hopcroft scoring graph for all Well-Known Types,
  enabling automatic schema inference without a `.proto` file.

- **`protoscan`** — a Python CLI that scans arbitrary binary files for
  embedded `FileDescriptorProto` blobs.

**`python3Packages.fdp-scan`** — the PyO3 Rust extension that backs
`protoscan`.  Built by calling `cargo build --release --lib` directly (no
maturin) and installing the resulting `.so` alongside a committed `.pyi`
type stub.

---

### Notes

**`workspace-hack` crate**: the Cargo workspace uses
[`cargo-hakari`](https://docs.rs/cargo-hakari) to manage a `workspace-hack`
crate that deduplicates dependency feature unification across all crates,
ensuring they all depend on exactly the same set of inputs and speeding up
from-scratch builds.  This crate will appear in the vendored dependency tree
but has no effect on the built artefacts.  Happy to take a different approach
if reviewers have a preference.

**PyO3 build approach**: the `fdp-scan` extension is built with a manual
`cargo build --release --lib` rather than maturin, consistent with the
project's existing `default.nix` (which also drives `cargo build` directly).

**`.pyi` type stub**: `fdp_scan_lib.pyi` is a Python type stub (generated
from the Rust source via `pyo3-stub-gen`) committed to the source repository
and copied into `site-packages` alongside the `.so`.

---

## Things done

- Built on platform:
  - [ ] x86_64-linux
  - [ ] aarch64-linux
  - [ ] x86_64-darwin
  - [ ] aarch64-darwin
- Tested, as applicable:
  - [ ] NixOS tests
  - [ ] Package tests at `passthru.tests`
  - [ ] Tests in lib/tests or pkgs/test
- [ ] Ran `nixpkgs-review` on this PR
- [ ] Tested basic functionality of all binary files (./result/bin/prototext,
      ./result/bin/protoscan)
- Nixpkgs Release Notes
  - [ ] Package update: when the change is major or breaking
- NixOS Release Notes
  - [ ] Module addition
  - [ ] Module update
- [ ] Fits CONTRIBUTING.md, pkgs/README.md, maintainers/README.md and other READMEs
```

---

## Resolved questions

- **`.so` / `.dylib` portability in `fdp-scan` `installPhase`**: use
  `lib.optionalString stdenv.isDarwin` to select the extension, exactly as
  the existing `yb` package does (`pkgs/by-name/yb/yb/package.nix`).  The
  `installPhase` copies `libfdp_scan_lib.so` on Linux and
  `libfdp_scan_lib.dylib` on macOS, renamed to `fdp_scan_lib.so` in both
  cases (Python's import mechanism requires dropping the `lib` prefix and
  always uses `.so` as the suffix even on macOS for extension modules).

- **`workspace-hack` crate and nixpkgs reviewers**: no existing nixpkgs
  package in `pkgs/by-name/` uses `workspace-hack`.  The crate is a
  `cargo-hakari`-managed build-speed helper; its only content is a handful
  of deduplicated dependencies.  It will be present in the vendored
  `Cargo.lock` and `fetchCargoVendor` will vendor it correctly alongside all
  other crates — no special handling is needed at build time.  However,
  reviewers may raise an eyebrow at it.  The mitigation is a short comment
  in `package.nix` explaining that `workspace-hack` is a hakari-generated
  crate that accelerates local builds and is harmless in the nixpkgs vendor
  tree.  If reviewers object, the `workspace-hack` dependency can be removed
  from the relevant `Cargo.toml` files for the nixpkgs build via a
  `postPatch` substitution (replacing the `workspace-hack` dep line with an
  empty string), since nixpkgs vendors everything anyway and the build-speed
  benefit does not apply there.

- **`fdp_scan_lib/__init__.py`**: confirmed present at
  `fdp-scan-pyo3/fdp_scan_lib/__init__.py`.  The `installPhase` copies it
  unconditionally (no `|| true` needed).

- **`fetchCargoVendor` vs `importCargoLock`**: use `fetchCargoVendor`
  throughout.  It is the current nixpkgs-preferred approach for new packages
  (replaces the older `importCargoLock` pattern).  The `yb` package uses
  `cargoHash` (the `buildRustPackage` shorthand which internally calls
  `fetchCargoVendor`); for the `fdp-scan` PyO3 `buildPythonPackage` an
  explicit `cargoDeps = rustPlatform.fetchCargoVendor { … }` is used since
  `buildPythonPackage` does not have the `cargoHash` shorthand.
