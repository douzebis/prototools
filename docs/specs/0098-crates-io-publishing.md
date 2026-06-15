<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0098 — Package publishing harness (crates.io + PyPI)

**Status:** draft
**App:** prototext, prototext-core, scoring-graph, reproto, protoscan

---

## Executive summary

Every push to `main` triggers the existing CI matrix (linux-x86_64,
linux-aarch64, macos-arm64, macos-x86_64).  This spec extends that
matrix to also build publishable artifacts and assemble them into a
single `release` artifact bundle.  Publishing is always a voluntary
manual step: the maintainer downloads one zip and runs one script.

### What gets published where

| Package | Destination | Type |
|---|---|---|
| `prototext-graph` | crates.io | Rust library (`.crate`) |
| `prototext-core` | crates.io | Rust library (`.crate`) |
| `prototext` | crates.io | Rust binary (`.crate`) |
| `prototext_graph_lib` | PyPI | Binary wheel (per platform) |
| `prototext_codec_lib` | PyPI | Binary wheel (per platform) |
| `fdp_scan_lib` | PyPI | Binary wheel (per platform) |
| `reproto` | PyPI | Pure Python wheel |
| `protoscan` | PyPI | Pure Python wheel |

### Publish workflow (maintainer view)

```
push to main
    → CI matrix builds artifacts on all 4 platforms
    → "assemble" job merges into one release/ bundle
    → maintainer downloads release/ artifact from GitHub Actions
    → CARGO_REGISTRY_TOKEN=... TWINE_PASSWORD=... ./release/publish.sh
```

One download, one command, done.

---

## Background

`prototext`, `prototext-core`, `reproto`, and `protoscan` are ready for
publication but no automated publishing process exists.  Two blockers
prevent a naive `cargo publish` today:

1. `scoring-graph` is a `path`-only dependency with no version — crates.io
   rejects path-only deps.
2. No Nix target packages the `.crate` files or `.whl` wheels, and no
   ready-to-run publish scripts exist.

The Python packages (`reproto`, `protoscan`) depend on PyO3 binary
extensions that must be compiled per platform.  The existing GitHub
Actions matrix already builds on all four target platforms
(linux-x86_64, linux-aarch64, macos-arm64, macos-x86_64), so wheel
production can be added to that matrix at low marginal cost.

---

## Goals

1. Rename `scoring-graph` to `prototext-graph` — a name suitable for
   crates.io that fits the `prototext-*` family.
2. Add `version = "0.2.0"` to `prototext-graph` (and update all references).
3. Add a `crates-io` Nix target that produces a self-contained output
   directory with the `.crate` tarballs and a parameter-less `publish.sh`.
4. Add a `pypi` Nix target (per-platform) that produces the platform's
   `.whl` files for `reproto`, `protoscan`, and their PyO3 extensions.
5. Extend `.github/workflows/nix.yml` to build the `pypi` target on each
   matrix platform and upload the wheels as GitHub Actions artifacts —
   but only on pushes to `main` (not on PRs, to control cost).
   The `crates-io` target is platform-independent and built on linux only.
6. Publishing to crates.io and PyPI is always a voluntary manual step —
   never triggered automatically by CI.

## Non-goals

- Publishing `scoring-graph-pyo3` / `prototext-pyo3` / `fdp-scan-pyo3` to
  crates.io (internal PyO3 glue, no standalone value).
- Automating token management — the user handles `CARGO_REGISTRY_TOKEN`
  and `TWINE_PASSWORD`.
- A separate publish CI job — publishing is done locally by the maintainer
  after downloading the artifacts.

---

## Observations

### O1 — crates.io publish order

crates.io requires dependencies to be published before their dependents:

```
prototext-graph  →  prototext-core  →  prototext
```

### O2 — `workspace-hack` is not a blocker

`workspace-hack` already carries `version = "0.1"` alongside its `path`.
Cargo rewrites it correctly during `cargo package`.

### O3 — `cargo package` vs `cargo publish`

`cargo package` produces a `.crate` tarball and performs all pre-flight
checks (path dep rewriting, manifest validation) without network access.
It is safe to run inside the Nix sandbox.  `cargo publish --crate-file`
then uploads a pre-built tarball — it requires network access and a valid
`CARGO_REGISTRY_TOKEN`, so it must run outside the sandbox.

### O4 — Path dep rewriting by Cargo

When `cargo package` processes a crate whose dependency has both `path`
and `version`, it strips the `path` field in the packaged manifest,
leaving only `version`.  This is Cargo's standard behaviour for workspace
publishing.  No manual manifest patching is needed as long as every
`path` dep also has a `version`.

### O5 — PyPI wheel structure

A `.whl` file is a zip archive with a specific directory layout:
`{name}-{version}.dist-info/` (metadata) and the package source tree.
For a PyO3 extension, the `.so` file produced by the Nix build is the
only platform-specific content; the rest is pure Python.  Nix can
assemble the wheel zip without `maturin` or any external wheel-building
tool.

### O6 — GitHub Actions cost

The existing matrix already runs on all 4 platforms for every push and
PR.  Adding `nix-build -A pypi` is cached by Magic Nix Cache, so
marginal cost is low on cache hits.  Gating the step on
`github.ref == 'refs/heads/main'` avoids running it on PRs, where it
is not needed.

### O7 — PyPI publish order

PyPI has no strict dependency ordering between packages, but the binary
extension wheels (`scoring_graph_lib`, `prototext_codec_lib`,
`fdp_scan_lib`) must be uploaded before `reproto` and `protoscan` so
that `pip install reproto` can resolve them.

---

## Specification

### S1 — Rename `scoring-graph` to `prototext-graph`

- Rename the directory `scoring-graph/` to `prototext-graph/`.
- Update `name` in `prototext-graph/Cargo.toml` to `prototext-graph`.
- Update all references in:
  - `Cargo.toml` (workspace members, workspace dep declaration)
  - `prototext/Cargo.toml`
  - `scoring-graph-pyo3/Cargo.toml`
  - `nix/rust.nix`, `default.nix`, `nix/python.nix`, `nix/shells.nix`
- Rust `use` / `extern crate` identifiers use the crate name with hyphens
  replaced by underscores: `prototext_graph`.  Update all `use` statements
  accordingly.

### S2 — Rename `scoring-graph-pyo3` to `prototext-graph-pyo3`

- Rename the directory `scoring-graph-pyo3/` to `prototext-graph-pyo3/`.
- Update `name` in `prototext-graph-pyo3/Cargo.toml` to
  `prototext_graph_lib` (lib) and `prototext_graph_post_build` (bin).
- Update all Python references:
  - `import scoring_graph_lib` → `import prototext_graph_lib` in all
    `.py` files under `reproto/`.
  - `scoring_graph_lib` → `prototext_graph_lib` in `pyproject.toml`
    files, `__init__.py`, and type stub files (`.pyi`).
- Update Nix references in `nix/rust.nix`, `nix/python.nix`,
  `default.nix`, and `nix/shells.nix`.
- Update `Cargo.toml` workspace members.

### S4 — Add version to `prototext-graph`

Add to `prototext-graph/Cargo.toml`:

```toml
version = "0.2.0"
```

Add `version = "0.2.0"` alongside the `path` field in every published
dependent:

```toml
# prototext/Cargo.toml
prototext-graph = { path = "../prototext-graph", version = "0.2.0" }
```

`scoring-graph-pyo3` is not published to crates.io, so its dep entry
stays path-only (name updated to `prototext-graph`, no `version` needed).

### S5 — `crates-io` Nix target

Add a `crates-io` derivation (in a new `nix/crates-io.nix` imported from
`default.nix`).  The derivation:

1. Takes `workspaceSrc` as input (same filtered source as the CI build).
2. Runs `cargo package -p prototext-graph --no-verify`.
3. Runs `cargo package -p prototext-core --no-verify`.
4. Runs `cargo package -p prototext --no-verify`.
5. Copies the three `.crate` files to `$out/`.
6. Writes `$out/publish.sh`:

```bash
#!/usr/bin/env bash
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
cargo publish --crate-file "$DIR/prototext-graph-0.2.0.crate"
sleep 15   # crates.io index propagation delay
cargo publish --crate-file "$DIR/prototext-core-0.2.0.crate"
sleep 15
cargo publish --crate-file "$DIR/prototext-0.2.0.crate"
```

Usage:

```bash
nix-build -A crates-io
CARGO_REGISTRY_TOKEN=<token> ./result/publish.sh
```

### S6 — `pypi` Nix target

Add a `pypi` derivation (per-platform, in `nix/pypi.nix` imported from
`default.nix`).  The derivation:

1. Assembles `.whl` files for:
   - `scoring_graph_lib` (PyO3 binary extension from `scoring-graph-pyo3`)
   - `prototext_codec_lib` (PyO3 binary extension from `prototext-pyo3`)
   - `fdp_scan_lib` (PyO3 binary extension from `fdp-scan-pyo3`)
   - `reproto` (pure Python + declares binary extension deps)
   - `protoscan` (pure Python + declares binary extension deps)
2. Writes `$out/publish.sh`:

```bash
#!/usr/bin/env bash
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
twine upload "$DIR"/*.whl
```

Usage (after collecting wheels from all 4 platforms into one directory):

```bash
TWINE_USERNAME=__token__ TWINE_PASSWORD=<token> ./publish.sh
```

### S7 — CI: build, assemble, and upload a single release artifact

Extend `.github/workflows/nix.yml` with two additions:

**Per-matrix-job step** (gated on `github.ref == 'refs/heads/main'`):

- Each matrix job runs `nix-build -A pypi` and uploads `./result/` as
  artifact `pypi-<os>` (e.g. `pypi-ubuntu-latest`,
  `pypi-macos-15-intel`).
- The `ubuntu-latest` job additionally runs `nix-build -A crates-io` and
  uploads `./result/` as artifact `crates-io`.

**New `assemble` job** (runs after all matrix jobs, on `main` only):

- Downloads all `pypi-*` and `crates-io` artifacts.
- Merges them into a single `release/` directory.
- Writes `release/publish.sh` covering the full publish sequence:

```bash
#!/usr/bin/env bash
# Usage: CARGO_REGISTRY_TOKEN=... TWINE_PASSWORD=... ./publish.sh
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"

echo "=== Publishing to crates.io ==="
cargo publish --crate-file "$DIR/prototext-graph-0.2.0.crate"
sleep 15
cargo publish --crate-file "$DIR/prototext-core-0.2.0.crate"
sleep 15
cargo publish --crate-file "$DIR/prototext-0.2.0.crate"

echo "=== Publishing to PyPI ==="
twine upload --username __token__ "$DIR"/*.whl
```

- Uploads `release/` as a single GitHub Actions artifact named `release`.

The maintainer downloads one zip, unpacks it, and runs one command.

---

## Summary of changes

| File | Change |
|---|---|
| `scoring-graph/` | Renamed to `prototext-graph/` |
| `prototext-graph/Cargo.toml` | `name = "prototext-graph"`, `version = "0.2.0"` |
| `Cargo.toml` | Update workspace member path and dep name |
| `prototext/Cargo.toml` | `prototext-graph = { path = ..., version = "0.2.0" }` |
| `scoring-graph-pyo3/` | Renamed to `prototext-graph-pyo3/`; lib/bin names updated |
| `prototext-graph-pyo3/Cargo.toml` | Update dep name to `prototext-graph` |
| `reproto/` Python files | `scoring_graph_lib` → `prototext_graph_lib` |
| All `.rs` files using `scoring_graph` | Update `use` to `prototext_graph` |
| `nix/rust.nix`, `default.nix`, `nix/python.nix`, `nix/shells.nix` | Update attribute and path references |
| `nix/crates-io.nix` (new) | `crates-io` derivation |
| `nix/pypi.nix` (new) | `pypi` derivation |
| `default.nix` | Expose `crates-io` and `pypi` attributes |
| `.github/workflows/nix.yml` | Add per-platform pypi/crates-io steps + `assemble` job |
