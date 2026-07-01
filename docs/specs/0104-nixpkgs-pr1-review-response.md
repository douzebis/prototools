<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0104 — Respond to GaetanLepage's review of nixpkgs PR 1

**Status:** implemented
**Implemented in:** 2026-07-01
**App:** (nixpkgs packaging)

---

## Background

GaetanLepage reviewed nixpkgs PR #525997 ("prototools: init at 0.2.0") in
two batches: June 13 and June 20, 2026, and followed up with a private
message.

This spec records each comment, the investigation findings, and the planned
response or action.

---

## June 13 comments (already responded to with "Done")

These were addressed in the push of 2026-06-13.  Recorded here for
completeness.

### C1 — `protoscan`: `stdenv` not needed

> File: `pkgs/development/python-modules/protoscan/default.nix`
> Suggestion: remove `stdenv` from the argument list.

**Status:** done (accepted).

### C2 — `protoscan`: add `__structuredAttrs = true`

> File: `pkgs/development/python-modules/protoscan/default.nix` line 17
> Suggestion: add `__structuredAttrs = true;` alongside `pyproject = true;`.
> "Required for every new package added."

**Status:** done (accepted).

### C3 — `prototext-codec`: use `finalAttrs` pattern

> File: `pkgs/development/python-modules/prototext-codec/default.nix`
> Suggestion: `buildPythonPackage (finalAttrs: {`

**Status:** done (accepted).

### C4 — `prototext-codec`: add `__structuredAttrs = true`

> File: `pkgs/development/python-modules/prototext-codec/default.nix` line 18
> Suggestion: add `__structuredAttrs = true;`.

**Status:** done (accepted).

### C5 — `prototext-codec`: use `inherit (finalAttrs)` in `cargoDeps`

> File: `pkgs/development/python-modules/prototext-codec/default.nix`
> Suggestion: `inherit (finalAttrs) pname version src;`

**Status:** done (accepted).

### C6 — `prototext-codec`: remove `platforms` from `meta`

> File: `pkgs/development/python-modules/prototext-codec/default.nix`
> "This is set automatically by `buildPythonPackage`."

**Status:** done (accepted).

### C7 — `python-packages.nix`: use `inherit (pkgs) prototools` (×2)

> File: `pkgs/top-level/python-packages.nix`
> Suggestion: `inherit (pkgs) prototools;` (in both `fdp-scan` and
> `prototext-codec` call sites).

**Status:** done (accepted).

---

## June 20 comments (pending)

### C8 — `protoscan`: keep arguments sorted (nit)

> File: `pkgs/development/python-modules/protoscan/default.nix` line 31
> "Nit: keep sorted."
>
> Suggested ordering:
> ```nix
> {
>   lib,
>   stdenv,
>   buildPythonPackage,
>   prototools,
>   # build-system
>   setuptools,
>   # dependencies
>   click,
>   fdp-scan,
>   protobuf,
>   # nativeBuildInputs
>   installShellFiles,
>   # tests
>   pytestCheckHook,
> }
> ```

**Analysis:** straightforward nixpkgs style — group by role, alphabetical
within each group.  Accept and apply.  Note: `stdenv` was removed by C1;
omit it from the reordered list.

**Action:** reorder the argument list in
`pkgs/development/python-modules/protoscan/default.nix` to match (minus
`stdenv`).

### C9 — `fdp-scan`: try `pyproject = true` with `hatchling`

> File: `pkgs/development/python-modules/fdp-scan/default.nix` line 18
> "Have you tried the default install behavior? Set `pyproject = true`,
> set `sourceRoot = "${finalAttrs.src.name}/fdp-scan-pyo3"` and add
> `hatchling` to `build-system`. It should work."

**Investigation findings:**

Both `fdp-scan-pyo3/pyproject.toml` and `prototext-pyo3/pyproject.toml`
exist and declare **hatchling** as the build backend:

```toml
[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[tool.hatch.build.targets.wheel]
packages = ["fdp_scan_lib"]   # (or "prototext_codec_lib")
```

So Gaetan is exactly right on the backend choice.

However, hatchling alone cannot compile Rust.  The upstream Crane pipeline
(`nix/rust.nix`, `makePyo3Extension`) exploits a two-step trick:

1. **Crane compiles the `.so`** (`cargo build --release -p <crate> --lib`)
   and runs the post-build stub generator to produce `<libName>.pyi`.
2. **A `patchPhase` copies `.so` and `.pyi`** into the Python package
   subdirectory (`fdp_scan_lib/` or `prototext_codec_lib/`) alongside the
   committed `__init__.py`.
3. **hatchling then wraps** the pre-populated directory into a wheel (its
   `packages = ["fdp_scan_lib"]` directive makes it pick up whatever is in
   that directory, including the just-copied `.so`).

This is why hatchling works for the Crane pipeline: by the time hatchling
runs, the `.so` is already in place.  Hatchling's role is purely to assemble
the wheel metadata and directory layout — it is not asked to compile anything.

The same trick is valid in nixpkgs:
- Compile the `.so` with `cargo` / `rustc` / `cargoSetupHook` in
  `nativeBuildInputs` during a pre-build step.
- Copy the `.so` (and the committed `.pyi`) into the Python package
  subdirectory in a `preBuild` hook.
- Then let `buildPythonPackage` with `pyproject = true` and
  `build-system = [ hatchling ]` drive the actual install.
- The `.dist-info` is generated automatically by hatchling — no manual
  METADATA needed.

The committed `.pyi` files are already in the right location in the
upstream source tree:
- `fdp-scan-pyo3/fdp_scan_lib/fdp_scan_lib.pyi`
- `prototext-pyo3/prototext_codec_lib/prototext_codec_lib.pyi`

Note on the `.pyi` naming: the Crane pipeline uses `pyiName = "fdp_scan"`
and the `postBuildBin` writes `fdp_scan.pyi` at the crate root.  The
committed file is however `fdp_scan_lib/fdp_scan_lib.pyi` (inside the
package subdirectory, already renamed).  The nixpkgs build uses the
committed file directly — no renaming step needed.

---

## Private message from GaetanLepage

> Bonsoir !
> Oui je vais regarder ça demain, merci du rappel :)
>
> Petite question: Es-tu mainteneur de ces paquets ?
>
> C'est très étrange d'avoir à faire toutes ces adaptations. On package des
> milliers de paquets Python et on a (quasiment) jamais besoin d'avoir recours
> à faire de telles copies manuelles ou à patcher les fichier METADATA.
>
> J'imagine que tu t'aies fait aider par un LLM pour écrire ces dérivations.
> Je n'ai pas de problème avec ça, mais vu ce à quoi ressemble la sortie, j'ai
> peur que ça soit le résultat d'une hallucination au moins partiel
>
> Soit toute cette mécanique n'est pas nécessaire, soit les bibliothèques en
> question sont particulièrement mal packagées de base (upstream).
>
> En théorie, un paquet Python doit pouvoir s'installer depuis les sources avec
> un simple pip install.. C'est littéralement ce que fait buildPythonPackage.
> Donc je suis un petit peu perplexe face à une telle complexité

**Analysis:**

Gaetan is right.  The manual `cargo build`, manual `.so` copy, and manual
METADATA generation in the current derivations are all unnecessary.  The
upstream `pyproject.toml` files already declare hatchling, and hatchling
handles `.dist-info` automatically.  The complexity is a consequence of
writing the derivations without sufficiently studying the upstream packaging.

The one legitimate complication is that hatchling cannot compile Rust — but
that is handled cleanly by compiling the `.so` in a `preBuild` hook and
copying it into the package subdirectory before hatchling runs.  This is
identical to what the upstream Crane pipeline does.

**Draft reply to Gaetan (in French, to match his message):**

> Bonjour Gaétan, et merci pour ces retours très pertinents.
>
> Tu as tout à fait raison — les deux extensions PyO3 (`fdp-scan` et
> `prototext-codec`) ont bien un `pyproject.toml` avec hatchling comme
> backend.  La complexité actuelle est inutile.
>
> Ce que je n'avais pas bien compris : hatchling ne compile pas le Rust, mais
> l'upstream (via Crane) contourne ça en compilant le `.so` au préalable et en
> le copiant dans le sous-répertoire Python (`fdp_scan_lib/`) avant de laisser
> hatchling assembler la wheel.  Même mécanique applicable dans nixpkgs.
>
> Je vais refaire les deux dérivations proprement :
> `pyproject = true`, `sourceRoot` pointant vers le sous-répertoire pyo3,
> `build-system = [ hatchling ]`, et un `preBuild` qui compile le `.so` avec
> cargo et le copie en place.  Plus de METADATA manuel, plus de `installPhase`
> à la main.
>
> Oui, je suis bien le mainteneur upstream de ces paquets.

---

## Specification: revised nixpkgs derivations

### §1 — Upstream context

- `fdp-scan-pyo3/pyproject.toml`: hatchling backend,
  `packages = ["fdp_scan_lib"]`.
- `prototext-pyo3/pyproject.toml`: hatchling backend,
  `packages = ["prototext_codec_lib"]`.
- `.pyi` stubs are committed at:
  - `fdp-scan-pyo3/fdp_scan_lib/fdp_scan_lib.pyi`
  - `prototext-pyo3/prototext_codec_lib/prototext_codec_lib.pyi`
- `__init__.py` is committed at:
  - `fdp-scan-pyo3/fdp_scan_lib/__init__.py`
  - `prototext-pyo3/prototext_codec_lib/__init__.py` (to be verified)
- No `build.rs` in either pyo3 crate — the Rust build is a straightforward
  `cargo build --release --lib`.

### §2 — Revised `fdp-scan` derivation

```nix
buildPythonPackage (finalAttrs: {
  pname = "fdp-scan";
  inherit (prototools) version;
  pyproject = true;
  __structuredAttrs = true;

  inherit (prototools) src;
  sourceRoot = "${prototools.src.name}/fdp-scan-pyo3";

  cargoDeps = rustPlatform.fetchCargoVendor {
    inherit (finalAttrs) pname version src;
    hash = "sha256-…";
  };

  build-system = [ hatchling ];

  nativeBuildInputs = [
    cargo
    rustc
    rustPlatform.cargoSetupHook
    python
  ];

  buildInputs = [ python ];

  env.PYO3_PYTHON = python.interpreter;

  # Compile the Rust cdylib and copy it into the Python package subdirectory
  # where hatchling expects it (alongside the committed __init__.py and .pyi).
  preBuild = ''
    cargo build --release --lib -p fdp_scan_lib --offline --frozen
    cp target/release/libfdp_scan_lib${stdenv.hostPlatform.extensions.sharedLibrary} \
       fdp_scan_lib/fdp_scan_lib.so
  '';

  nativeCheckInputs = [
    pytestCheckHook
    protobuf
  ];

  enabledTestPaths = [ "tests/" ];

  pythonImportsCheck = [ "fdp_scan_lib" ];

  meta = {
    description = "Rust extension for scanning binaries for embedded protobuf FileDescriptorProto blobs";
    homepage = "https://github.com/ThalesGroup/prototools";
    license = lib.licenses.mit;
    maintainers = with lib.maintainers; [ douzebis ];
  };
})
```

Key points:
- `sourceRoot` scopes the build to `fdp-scan-pyo3/` — hatchling sees the
  `pyproject.toml` and `fdp_scan_lib/` package directory directly.
- `preBuild` compiles the `.so` and drops it into `fdp_scan_lib/` before
  hatchling runs.  The `.so` must be named `fdp_scan_lib.so` (Python import
  name, no `lib` prefix, always `.so` even on macOS for extension modules
  inside a package).
- `build-system = [ hatchling ]` — hatchling assembles the wheel, generates
  `.dist-info`, and handles the install.  No `installPhase`, no manual
  METADATA.
- `pyproject = false` is gone; `buildPythonPackage` now uses its standard
  PEP 517 path.
- `cargoDeps` still needed: `cargo build --offline` requires a vendor dir,
  set up by `cargoSetupHook`.  But `cargoSetupHook` runs from the workspace
  root; `sourceRoot` only affects the Python build, not the Cargo workspace.
  Need to verify that `cargoSetupHook` correctly finds the workspace
  `Cargo.lock` when `sourceRoot` is set.  If it does not, the `preBuild`
  must `cd ..` to the workspace root before calling `cargo build`.

### §3 — Revised `prototext-codec` derivation

Same structure as `fdp-scan` with:
- `pname = "prototext-codec"`
- `sourceRoot = "${prototools.src.name}/prototext-pyo3"`
- `build-system = [ hatchling ]`
- `preBuild` copies `prototools.fixtures` before `cargo build` (same as
  current buildPhase), then copies the `.so` into `prototext_codec_lib/`:

```nix
  preBuild = ''
    mkdir -p prototext/fixtures/prebuilt
    cp ${prototools.fixtures}/descriptor.pb     prototext/fixtures/prebuilt/
    cp ${prototools.fixtures}/knife.pb          prototext/fixtures/prebuilt/
    cp ${prototools.fixtures}/enum_collision.pb prototext/fixtures/prebuilt/
    cp ${prototools.fixtures}/message_set.pb    prototext/fixtures/prebuilt/
    cargo build --release --lib -p prototext_codec_lib --offline --frozen
    cp target/release/libprototext_codec_lib${stdenv.hostPlatform.extensions.sharedLibrary} \
       prototext_codec_lib/prototext_codec_lib.so
  '';
```

Note: the fixture paths (`prototext/fixtures/prebuilt/`) are relative to the
workspace root, not to `prototext-pyo3/`.  If `sourceRoot` changes the
working directory for the whole build, the `cd` dance mentioned in §2 may
apply here too.

### §4 — `sourceRoot` + `cargoSetupHook` interaction (resolved)

`cargoSetupHook` runs in two phases:

- `cargoSetupPostUnpackHook` (postUnpack, before `cd $sourceRoot`): unpacks
  the vendor tarball and writes `.cargo/config.toml` at the unpack root.
- `cargoSetupPostPatchHook` (postPatch, after `cd $sourceRoot`): validates
  `$(pwd)/${cargoRoot}/Cargo.lock` against the vendor copy.

With `sourceRoot = "…/fdp-scan-pyo3"` and `cargoRoot = ".."`:
- `.cargo/config.toml` is written at the unpack root (parent of fdp-scan-pyo3/).
  Cargo finds it by walking up the directory tree from the working directory ✓
- The Cargo.lock check looks at `$(pwd)/../Cargo.lock` = workspace root ✓
- `fetchCargoVendor` receives no `sourceRoot`/`cargoRoot`, so it also reads
  `Cargo.lock` from the workspace root — the two lockfiles match ✓

`CARGO_TARGET_DIR="$PWD/target"` redirects cargo's output directory into
the writable `fdp-scan-pyo3/` build dir.  Without it, cargo would write to
`../target/` (workspace root), which is read-only in the Nix sandbox.

### §5 — `__init__.py` in `prototext-pyo3` (already present)

`prototext-pyo3/prototext_codec_lib/__init__.py` already exists in the
upstream source, re-exporting all public symbols.  No upstream change needed.

### §6 — Fixture env vars for `prototext-codec` (cleaner than file copying)

`prototext-core/build.rs` has a fast path: when `DESCRIPTOR_PB` (and
siblings) are set, it copies the .pb files directly from those paths into
`OUT_DIR`, bypassing the `fixtures/prebuilt/` directory lookup entirely.
This avoids any need to write into the (read-only) source tree.

The env vars point directly to `prototools.fixtures` store paths, e.g.:
`/nix/store/…-prototools-fixtures/descriptor.pb`.

### §7 — Implementation status

All changes built and tested successfully:
- `fdp-scan`: 6/6 tests pass
- `prototext-codec`: 9/9 tests pass
- `protoscan`: 8/8 tests pass
- `prototools` (symlinkJoin): builds cleanly

### §8 — Actions remaining

1. **Push** the updated branch to the nixpkgs fork and force-push to PR #525997.
2. **Reply** to Gaetan on the PR with the draft reply above.
3. **Update** spec 0092 constraint C3 to clarify it applies only to
   `default.nix`, not to the nixpkgs packaging.

---

## Non-goals

- Addressing felbinger's earlier comments (already resolved).
- Copilot suggestions (not authoritative for nixpkgs review).
- PR 2 (`reproto`) changes.
