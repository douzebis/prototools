<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0093 — nixpkgs PR 2: add reproto

**Status:** draft
**Implemented in:** —
**App:** (build system / release — not app-specific)

---

## Background

This spec covers PR 2 of the nixpkgs publishing roadmap defined in spec 0092.
PR 1 (spec 0092) added `prototools` (`prototext` + `protoscan` + `fdp-scan`).
PR 2 adds `reproto` and its three dependencies that are new to nixpkgs:

| New nixpkgs package | Type |
|---|---|
| `python3Packages.reproto` | `buildPythonPackage` (setuptools) |
| `python3Packages.prototext-codec` | `buildPythonPackage` (cargo build --lib) |
| `python3Packages.scoring-graph` | `buildPythonPackage` (cargo build --lib) |
| `python3Packages.tree-sitter-textproto` | `buildPythonPackage` (C, tree-sitter generate) |

All other Python runtime dependencies of `reproto` (`click`, `lark`,
`google-re2`, `protobuf`, `pyvis`, `pyyaml`, `rapidfuzz`, `rich`,
`tree-sitter`, `tree-sitter-language-pack`) are already in nixpkgs.

After PR 2, `pkgs.prototools` becomes a `symlinkJoin` of all three CLIs:
`prototext`, `protoscan`, and `reproto`.

---

## Design constraints

Same constraints as spec 0092 (C1–C5), plus:

### C6 — `.pb` files are pre-committed; no `patch_reproto.sh` in nixpkgs

`patch_reproto.sh` regenerates `resources/google/protobuf/*.pb` and
`reproto/variants/google-protobuf/**/*.pb` during the `default.nix` build.
These files are already committed to git (they are tracked and excluded from
the `reprotoSrc` snapshot only to avoid spurious rebuilds on local edits).

The nixpkgs `reproto` `buildPythonPackage` uses the committed `.pb` files
directly — no `protoc` invocation, no `patch_reproto.sh` needed.

### C7 — `.pyi` stubs for `prototext_codec_lib` and `scoring_graph_lib` must be committed

Analogous to `fdp_scan_lib.pyi` (committed in spec 0092 §2), the stubs for
the two remaining extensions must be committed before PR 2 can be written.

Paths:

```
prototext-pyo3/prototext_codec_lib/prototext_codec_lib.pyi
scoring-graph-pyo3/scoring_graph_lib/scoring_graph_lib.pyi
```

Regenerate with:

```bash
cargo run --release --bin prototext_codec_post_build
cargo run --release --bin scoring_graph_post_build
```

### C8 — `tree-sitter-textproto` is a new nixpkgs package

The grammar is sourced from
`github.com/PorterAtGoogle/tree-sitter-textproto` (commit `568471b`).
The `binding.c` and `textproto.pyi` files are committed to the oss-prototools
repo under `reproto/tree-sitter-textproto/`.  The nixpkgs package fetches the
upstream grammar source for `grammar.js` and `src/parser.c`, and copies
`binding.c` and `textproto.pyi` from the prototools source.

---

## Goals

1. Commit `.pyi` stubs for `prototext_codec_lib` and `scoring_graph_lib`.
2. Write `pkgs/development/python-modules/prototext-codec/default.nix`.
3. Write `pkgs/development/python-modules/scoring-graph/default.nix`.
4. Write `pkgs/development/python-modules/tree-sitter-textproto/default.nix`.
5. Write `pkgs/development/python-modules/reproto/default.nix`.
6. Update `pkgs/by-name/pr/prototools/package.nix` to add `reproto` to the
   `symlinkJoin`.
7. Verify `nix-build -A python3Packages.reproto` and `nix-build -A prototools`
   pass on x86_64-linux and aarch64-linux.

---

## Non-goals

- Modifying the existing `default.nix` / `nix/*.nix` build logic.
- Running the full reproto test suite in the nixpkgs build
  (the `.pb` codegen step makes `reprotoSrcFull` expensive to replicate;
  `pythonImportsCheck` is the nixpkgs baseline).
- Publishing to PyPI or crates.io.
- `googleapisTests` or `customTests`.

---

## Specification

### §1 — Commit `.pyi` stubs (oss-prototools repo changes)

#### §1.1 — `prototext_codec_lib.pyi`

Generate and commit:

```
prototext-pyo3/prototext_codec_lib/prototext_codec_lib.pyi
```

Regenerate command (inside the dev-shell):

```bash
cargo run --release --bin prototext_codec_post_build
```

REUSE: annotate with `reuse annotate` using the standard copyright header.

#### §1.2 — `scoring_graph_lib.pyi`

Generate and commit:

```
scoring-graph-pyo3/scoring_graph_lib/scoring_graph_lib.pyi
```

Regenerate command:

```bash
cargo run --release --bin scoring_graph_post_build
```

REUSE: same annotation.

### §2 — `tree-sitter-textproto` Python package

#### §2.1 — nixpkgs location

```
pkgs/development/python-modules/tree-sitter-textproto/default.nix
```

#### §2.2 — Build approach

The grammar source (`grammar.js`, `src/parser.c`) is fetched from the
upstream repository.  The `binding.c` and `textproto.pyi` files are taken
from the prototools source tree (they are committed at
`reproto/tree-sitter-textproto/`).

Build steps:
1. `tree-sitter generate` — produces `src/parser.c` (already present in the
   upstream tarball, so this step can be skipped if the fetched source
   includes it).
2. Compile `binding.c` + `src/parser.c` into a Python extension `.so` using
   the system C compiler with `python3-config --includes --ldflags`.
3. Install the `.so` and `textproto.pyi` into `site-packages/`.

```nix
{ lib, buildPythonPackage, fetchFromGitHub, python3, stdenv,
  tree-sitter, nodejs, prototools-src }:

buildPythonPackage {
  pname   = "tree-sitter-textproto";
  version = "0-unstable-2024-01-01";   # upstream has no releases
  format  = "other";

  # Upstream grammar (grammar.js + src/parser.c).
  src = fetchFromGitHub {
    owner = "PorterAtGoogle";
    repo  = "tree-sitter-textproto";
    rev   = "568471b80fd8793d37ed01865d8c2208a9fefd1b";
    hash  = "sha256-...";
  };

  nativeBuildInputs = [ tree-sitter nodejs ];
  buildInputs       = [ python3 ];

  buildPhase = ''
    runHook preBuild
    # binding.c and textproto.pyi come from prototools source.
    cp ${prototools-src}/reproto/tree-sitter-textproto/binding.c .
    tree-sitter generate
    $CC -shared -fPIC \
      -o textproto$(python3-config --extension-suffix) \
      binding.c src/parser.c \
      -I src \
      $(python3-config --includes --ldflags) \
      ${lib.optionalString stdenv.isDarwin "-undefined dynamic_lookup"}
    runHook postBuild
  '';

  installPhase = ''
    runHook preInstall
    site="$out/lib/${python3.libPrefix}/site-packages"
    mkdir -p "$site"
    cp textproto*.so "$site/"
    cp ${prototools-src}/reproto/tree-sitter-textproto/textproto.pyi "$site/"
    runHook postInstall
  '';

  pythonImportsCheck = [ ];   # no Python import — it's a native extension

  meta = {
    description = "Tree-sitter grammar for the protobuf text format (textproto)";
    homepage    = "https://github.com/PorterAtGoogle/tree-sitter-textproto";
    license     = lib.licenses.asl20;
    maintainers = with lib.maintainers; [ douzebis ];
  };
}
```

Open question: how to expose `prototools-src` as a fixed `fetchFromGitHub`
shared between all prototools packages.  Options:
- Pass it as a `callPackage` argument (requires wiring in `all-packages.nix`).
- Each package fetches independently (Nix deduplicates by hash).
- Define a `prototools-src` package in `pkgs/by-name/` that is just the
  fetched source.

**Decision:** each package fetches independently using the same
`fetchFromGitHub` call.  Nix content-addressing deduplicates the download.

#### §2.3 — License

The upstream `tree-sitter-textproto` grammar is licensed under Apache 2.0.
The `binding.c` and `textproto.pyi` committed to prototools are MIT.
The package `meta.license` should reflect the dominant license of the built
artefact (Apache 2.0, as the grammar C code is the bulk of the `.so`).

### §3 — `prototext-codec` PyO3 extension

#### §3.1 — nixpkgs location

```
pkgs/development/python-modules/prototext-codec/default.nix
```

#### §3.2 — Build approach

Same pattern as `fdp-scan` (PR 1): `cargo build --release --lib`, install
`.so` + committed `.pyi`.

The `prototext-codec` crate requires the same `patchPhase` as `prototext`
(compile `descriptor.pb`, `knife.pb`, `enum_collision.pb`) because
`prototext-pyo3/build.rs` links against `prototext` which uses them.

```nix
{ lib, buildPythonPackage, fetchFromGitHub, rustPlatform,
  python3, stdenv, protobuf }:

buildPythonPackage {
  pname     = "prototext-codec";
  version   = "0.2.0";
  format    = "other";
  pyproject = false;

  src = fetchFromGitHub {
    owner = "ThalesGroup";
    repo  = "prototools";
    tag   = "prototext-v0.2.0";
    hash  = "sha256-...";
  };

  cargoDeps = rustPlatform.fetchCargoVendor {
    inherit (finalAttrs) pname version src;
    hash = "sha256-...";
  };

  nativeBuildInputs = [
    rustPlatform.cargoSetupHook
    rustPlatform.rust.cargo
    rustPlatform.rust.rustc
    protobuf
  ];
  buildInputs = [ python3 ];

  patchPhase = ''
    runHook prePatch
    mkdir -p prototext/fixtures/prebuilt
    protoc --descriptor_set_out=prototext/fixtures/prebuilt/descriptor.pb \
           google/protobuf/descriptor.proto
    protoc --descriptor_set_out=prototext/fixtures/prebuilt/knife.pb \
           --proto_path=prototext/fixtures/schemas knife.proto
    protoc --descriptor_set_out=prototext/fixtures/prebuilt/enum_collision.pb \
           --proto_path=prototext/fixtures/schemas enum_collision.proto
    runHook postPatch
  '';

  buildPhase = ''
    runHook preBuild
    cargo build --release --lib -p prototext_codec_extension --offline --frozen
    runHook postBuild
  '';

  installPhase = ''
    runHook preInstall
    site="$out/lib/${python3.libPrefix}/site-packages/prototext_codec_lib"
    mkdir -p "$site"
    local ext=${lib.optionalString stdenv.isDarwin "dylib"}; ext=''${ext:-so}
    cp "target/release/libprototext_codec_lib.$ext" "$site/prototext_codec_lib.so"
    cp prototext-pyo3/prototext_codec_lib/prototext_codec_lib.pyi "$site/"
    cp prototext-pyo3/prototext_codec_lib/__init__.py "$site/"
    runHook postInstall
  '';

  pythonImportsCheck = [ "prototext_codec_lib" ];

  meta = {
    description = "Lossless protobuf decoder Python extension (PyO3)";
    homepage    = "https://github.com/ThalesGroup/prototools";
    license     = lib.licenses.mit;
    maintainers = with lib.maintainers; [ douzebis ];
  };
}
```

Open question: the exact Cargo package name (`-p` flag).  Confirm from
`prototext-pyo3/Cargo.toml`.

### §4 — `scoring-graph` PyO3 extension

#### §4.1 — nixpkgs location

```
pkgs/development/python-modules/scoring-graph/default.nix
```

#### §4.2 — Build approach

Same pattern as `prototext-codec`.  No `patchPhase` needed — the
`scoring-graph` crate does not depend on `prototext` or its fixture `.pb`
files.

```nix
buildPhase = ''
  cargo build --release --lib -p scoring_graph_extension --offline --frozen
'';

installPhase = ''
  site="$out/lib/${python3.libPrefix}/site-packages/scoring_graph_lib"
  mkdir -p "$site"
  local ext=...; ext=...
  cp "target/release/libscoring_graph_lib.$ext" "$site/scoring_graph_lib.so"
  cp scoring-graph-pyo3/scoring_graph_lib/scoring_graph_lib.pyi "$site/"
  cp scoring-graph-pyo3/scoring_graph_lib/__init__.py "$site/"
'';
```

Open question: confirm the exact Cargo package name from
`scoring-graph-pyo3/Cargo.toml`.

### §5 — `reproto` Python package

#### §5.1 — nixpkgs location

```
pkgs/development/python-modules/reproto/default.nix
```

#### §5.2 — Key design decision: no `patch_reproto.sh`

The `.pb` descriptor files consumed by `reproto` at runtime are already
committed to the source tree:

- `reproto/src/resources/google/protobuf/*.pb` — WKT descriptors
- `reproto/src/reproto/variants/google-protobuf/**/*.pb` — variant descriptors

These are included by `pyproject.toml` via `[tool.setuptools.package-data]`.
The nixpkgs build uses them as-is — no `protoc` invocation needed.

`patch_reproto.sh` regenerates them in the `default.nix` build only to
ensure they are in sync with whatever `pkgs.protobuf` version is in the
current nixpkgs channel.  For the nixpkgs package itself, the committed
files are the authoritative source.

#### §5.3 — `reprotoSrcFull` codegen step is not needed

The `reprotoSrcFull` derivation in `default.nix` seeds WKT `.proto` sources
from `pkgs.protobuf` into the source tree before `patch_reproto.sh` runs.
Since we skip `patch_reproto.sh`, this seeding step is also unnecessary.
The nixpkgs `reproto` build uses `sourceRoot` to point directly at the
`reproto/` subdirectory.

#### §5.4 — derivation sketch

```nix
{ lib, buildPythonPackage, fetchFromGitHub, setuptools, wheel,
  click, google-re2, lark, protobuf, pyvis, pyyaml, rapidfuzz, rich,
  tree-sitter, tree-sitter-language-pack,
  tree-sitter-textproto, prototext-codec, scoring-graph,
  installShellFiles, stdenv, pytestCheckHook }:

buildPythonPackage {
  pname   = "reproto";
  version = "0.2.0";
  pyproject = true;

  src = fetchFromGitHub {
    owner = "ThalesGroup";
    repo  = "prototools";
    tag   = "prototext-v0.2.0";
    hash  = "sha256-...";
  };

  sourceRoot = "${src.name}/reproto";

  build-system = [ setuptools wheel ];

  dependencies = [
    click google-re2 lark protobuf pyvis pyyaml rapidfuzz rich
    tree-sitter tree-sitter-language-pack
    tree-sitter-textproto prototext-codec scoring-graph
  ];

  nativeBuildInputs = [ installShellFiles ];

  doCheck = false;   # full test suite requires reprotoSrcFull codegen step

  postInstall = lib.optionalString (stdenv.buildPlatform.canExecute stdenv.hostPlatform) ''
    installShellCompletion --cmd reproto \
      --bash ${./reproto/src/reproto/completions.sh}
    $out/bin/reproto-gen-man $out/share/man/man1
    $out/bin/reproto-instantiate-schema-gen-man $out/share/man/man1
  '';

  pythonImportsCheck = [ "reproto" ];

  meta = {
    description = "Reconstruct .proto source files from compiled .pb descriptor sets";
    homepage    = "https://github.com/ThalesGroup/prototools";
    license     = lib.licenses.mit;
    maintainers = with lib.maintainers; [ douzebis ];
    mainProgram = "reproto";
    platforms   = lib.platforms.unix;
  };
}
```

Notes:

- `doCheck = false`: the reproto test suite requires `reprotoSrcFull`
  (WKT `.proto` sources from `pkgs.protobuf` compiled into `.pb` fixtures
  via `patch_reproto.sh`), and `protoc` + `buf` in PATH.  The codegen step
  is non-trivial to replicate in the nixpkgs sandbox.  `pythonImportsCheck`
  verifies the package loads and all extension imports resolve.
- Shell completion: `reproto` provides a hand-written `completions.sh` rather
  than a Click-generated one.  The nixpkgs build copies it directly.
- Man pages: two man pages are generated by installed entry-points
  (`reproto-gen-man` and `reproto-instantiate-schema-gen-man`).

### §6 — Update `prototools` `symlinkJoin`

`pkgs/by-name/pr/prototools/package.nix` is updated to include `reproto`:

```nix
{ symlinkJoin, prototext, python3Packages }:
symlinkJoin {
  name  = "prototools-${prototext.version}";
  paths = [
    prototext
    python3Packages.protoscan   # carries fdp-scan in its closure
    python3Packages.reproto     # carries prototext-codec, scoring-graph,
                                # tree-sitter-textproto in its closure
  ];
  meta = prototext.meta // {
    description = "Protocol Buffer utilities: prototext, protoscan, and reproto CLIs";
    mainProgram = "prototext";
  };
}
```

### §7 — Source-repo changes (oss-prototools) before PR 2

| File | Action |
|---|---|
| `prototext-pyo3/prototext_codec_lib/prototext_codec_lib.pyi` | Generate and commit |
| `scoring-graph-pyo3/scoring_graph_lib/scoring_graph_lib.pyi` | Generate and commit |

REUSE: `reuse annotate` on both files; `reuse lint` must be clean.

### §8 — Open questions

1. **`tree-sitter-textproto` `prototools-src` access**: confirmed that each
   nixpkgs package fetches the source independently (Nix deduplication by
   content hash).  `binding.c` and `textproto.pyi` are copied from the
   fetched prototools source.

2. **Cargo package names**: confirm exact `-p` flags from `Cargo.toml` files:
   - `prototext-pyo3/Cargo.toml` → package name for `--lib`
   - `scoring-graph-pyo3/Cargo.toml` → package name for `--lib`

3. **Shell completion for `reproto`**: `completions.sh` is a hand-written
   bash script committed at `reproto/src/reproto/completions.sh`.  In the
   nixpkgs build, `installShellCompletion` copies it using a store path
   reference.  Zsh and fish completions are not available (no hand-written
   versions; Click's auto-generation requires running the binary which may
   not work for cross-compilation).

4. **`reproto-instantiate-schema` man page**: the man page generator imports
   `reproto.instantiate_cli`, which imports `prototext_codec_lib`.  The
   `postInstall` guard (`canExecute`) ensures this only runs in native builds.

5. **`nixpkgs-review` verification**: PR 2 should be reviewed with
   `nixpkgs-review` on x86_64-linux and aarch64-linux before submission.

### §9 — PR 2 commit sequence

1. (oss-prototools) Commit `.pyi` stubs for `prototext_codec_lib` and
   `scoring_graph_lib`; update the release tag.
2. (nixpkgs) Single commit: `prototools: add reproto` — adds
   `tree-sitter-textproto`, `prototext-codec`, `scoring-graph`, `reproto`
   packages; updates `prototools` `symlinkJoin`.

### §10 — PR 2 message draft

```
prototools: add reproto

This is **PR 2 of 2**, following prototools: init at 0.2.0.

Adds `reproto` — a CLI that reconstructs `.proto` source files from
compiled `.pb` descriptor sets — together with its three new Python
dependencies:

- `prototext-codec`: PyO3 Rust extension for lossless protobuf decoding.
- `scoring-graph`: PyO3 Rust extension for Hopcroft scoring-graph compilation.
- `tree-sitter-textproto`: tree-sitter grammar for the protobuf text format.

`pkgs.prototools` is updated to include all three CLIs: `prototext`,
`protoscan`, and `reproto`.

All other Python runtime dependencies (`click`, `lark`, `google-re2`,
`protobuf`, `pyvis`, `pyyaml`, `rapidfuzz`, `rich`, `tree-sitter`,
`tree-sitter-language-pack`) are already in nixpkgs.

The PyO3 extensions follow the same `cargo build --release --lib` build
pattern used by `fdp-scan` in PR 1.  The `.pyi` type stubs are committed
to the source repository.

The reproto test suite requires a code-generation step (`patch_reproto.sh`)
that compiles WKT `.proto` sources using a specific `protoc` version; it is
not run in the nixpkgs build.  `pythonImportsCheck` confirms all three
extension modules load correctly.
```

---

## Things done

- Built on platform:
  - [ ] x86_64-linux
  - [ ] aarch64-linux
  - [ ] x86_64-darwin
  - [ ] aarch64-darwin
- [ ] `pythonImportsCheck` passes for `reproto`, `prototext_codec_lib`,
      `scoring_graph_lib`, `tree-sitter-textproto`
- [ ] `nix-build -A prototools` includes all three CLIs
- [ ] Ran `nixpkgs-review` on this PR
- [ ] Tested basic functionality: `reproto --help`, `reproto --version`
