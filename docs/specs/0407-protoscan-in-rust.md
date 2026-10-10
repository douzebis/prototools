<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0407 — protoscan in Rust

Status: draft
App: protoscan, fdp-scan-pyo3
Refs: docs/specs/0405-prototools-in-nixpkgs-one-small-pr-at-a-time.md
      (S9 step 2: protoscan is nixpkgs PR 2, with prototext's shape; C2,
      the internal package); docs/specs/0406-bash-completion-from-the-raw-command-line.md
      (the bash completion protoscan gets); docs/specs/0239-the-schema-says-where-a-descriptor-ends.md
      and 0313 (the scanner's rules, unchanged)

## Background

protoscan finds the protobuf descriptors (`FileDescriptorProto`) embedded
in a binary, prints each one's file name, and with `--proto_out DIR`
writes each to `DIR/<name>.pb`.

It is a Python CLI of about 40 lines (`protoscan/src/protoscan/cli.py`)
around one call, `fdp_scan_lib.scan`, which is Rust exposed through pyo3
(`fdp-scan-pyo3/src/lib.rs`, about 600 lines with its tests). The Python
side does two things: the command line (click), and reading each found
descriptor's `name` (`descriptor_pb2`). Its man page comes from a second
script, `protoscan-gen-man`.

So the tool is Rust in all but its wrapper, and the wrapper costs:
- a Python package to build, test and publish (PyPI, nixpkgs);
- in nixpkgs, a Python application where a Rust one would do: PR 2 would
  have to bring the `fdp-scan` Python library with it (spec 0405 S9);
- click's bash completion, which spec 0406 does not cover.

## Goals

- **G1.** protoscan is a Rust binary, with the same command line and the
  same output: the same names printed, the same files written, the same
  exit status. The GreHack talk and anyone's scripts keep working
  (`--proto_out` included, deprecated: S3).
- **G2.** Its nixpkgs recipe has prototext's shape: one
  `buildRustPackage` from the same tag and the same `Cargo.lock`, with no
  Python (spec 0405 S9 step 2).
- **G3.** It gets what prototext has: the bash completion of spec 0406,
  zsh and fish completions, a man page, `--version`.
- **G4.** The scanner has one home, used by the CLI and by the Python
  extension alike.

## Non-goals

- **N1.** Changing what the scanner finds. Its rules (specs 0239, 0313)
  and its tests move unchanged.
- **N2.** reproto. It keeps using the scanner through the Python
  extension (`fdp_scan_lib`), for `reproto -I <blob>`.
- **N3.** New options. The only change is the spelling of `--proto_out`
  (S3).
- **N4.** Withdrawing the Python package from PyPI. Its published
  versions stay; it is simply not published again.

## Specification

- **S1. The scanner gets its own crate, `fdp-scan`** (library only), with
  `fdp-scan-pyo3/src/lib.rs`'s scanning code and its tests, unchanged.
  Its dependencies are those of the code it takes: prototext (for the
  embedded WKT graph) and prototext-graph. Its public function is
  `scan(data: &[u8]) -> Vec<(usize, usize)>`, today's `scan_bytes`.
- **S2. `fdp-scan-pyo3` becomes a thin wrapper:** the `scan` pyfunction
  calls `fdp_scan::scan`. The Python module, its stub and its behavior
  are unchanged, so reproto and the internal package see no difference.
- **S3. A new crate, `protoscan`** (binary only), depending on `fdp-scan`.
  - **Arguments:** `protoscan FILE [--proto-out DIR]`. `--proto-out` is
    the documented spelling, kebab case like every other long option of
    the tools (`--descriptor-set`, `--schema-db-out`…).
  - **`--proto_out` is deprecated:** still accepted, as a hidden alias
    (absent from `--help` and the man page), so existing scripts keep
    working; using it prints `warning: --proto_out is deprecated, use
    --proto-out` on stderr. `CHANGELOG.md` says so, and it is removed in
    a later release.
  - **Output:** for each descriptor found, in order, its `name` field on
    one line of stdout.
  - **With `--proto-out`:** each descriptor's bytes go to `DIR/<name>`,
    with a final `.proto` replaced by `.pb`, creating parent directories.
  - **Reading `name`:** `prost-types`' `FileDescriptorProto`, already a
    workspace dependency.
  - **Errors:** a missing or unreadable `FILE` is reported on stderr and
    exits non-zero, as clap does for its own errors.
- **S4. Completion, man page, version,** as for protolens:
  - `PROTOSCAN_COMPLETE=<shell> protoscan` prints the completion script,
    bash through `prototools-complete` (spec 0406);
  - `PROTOSCAN_GEN_MAN=<dir> protoscan` writes the man page (clap_mangen)
    and exits. One binary, no `protoscan-gen-man` beside it in `bin/`;
  - `protoscan --version` prints the workspace version.
- **S5. Tests:** the eight cases of `protoscan/tests/test_cli.py` become
  Rust integration tests of the binary (`protoscan/tests/cli.rs`),
  building their fixtures with `prost-types`, as the Python tests did
  with `descriptor_pb2`. The Python package and its tests are deleted.
- **S6. Our build:**
  - `default.nix`'s `protoscan` becomes the Rust binary, copied out of
    `workspaceBuild` with its completions and man page, like prototext;
  - `protoscanTests` and the protoscan wheel go;
  - the crates.io bundle adds `fdp-scan` and `protoscan`;
  - the GreHack image and the user shell take the new attribute
    unchanged;
  - `completionTests` gains protoscan.
- **S7. The internal package (spec 0405 C2):** its import check drops
  `python -c "import protoscan"`, in the same cycle. `fdp_scan_lib` still
  reaches it through reproto. Nothing else changes there: it never runs
  protoscan, only bundles it.
- **S8. nixpkgs PR 2,** staged as `nixpkgs/pkgs/by-name/pr/protoscan/package.nix`
  and built by `nixpkgs-staging` like prototext's:
  - the same shape as prototext's recipe, with `-p protoscan`;
  - `src`, `version` and `cargoHash` follow the next tag;
  - once prototext is in nixpkgs, it may take `inherit (prototext) src
    version cargoDeps;` (spec 0405 G3).

  It is opened after prototext's PR has been reviewed (spec 0405 S9), at
  the release that ships this spec.
- **S9. Docs:** the README's protoscan section (install via cargo or Nix,
  not pip) and `CHANGELOG.md`.

## Alternatives considered

### One `protoscan` crate, library and binary

Fewer crates, but Cargo has no binary-only dependencies: the Python
extension, which needs only the scanner, would compile clap, the
completion code and clap_mangen.

### A `protoscan-gen-man` binary, as prototext has

Consistent with prototext, but it ships a helper in `bin/` that users
never run, which a nixpkgs reviewer may question (see the prototext PR's
briefing). protolens's environment variable does the same job inside the
one binary.

### Keep the Python CLI

It works, but costs a Python package in PyPI and nixpkgs for 40 lines of
wrapper, and keeps click's bash completion, which has the problems spec
0406 fixed.

## Test plan

1. The eight CLI tests pass on the Rust binary (S5), plus one for the
   deprecated `--proto_out`: it still works, and warns on stderr.
2. The `fdp-scan` tests, moved from `fdp-scan-pyo3`, pass unchanged.
3. `fdp-scan-tests` (the Python extension's pytest suite) and
   `reproto-tests` pass unchanged (S2, N2).
4. On the binaries the talks scan (`protoscan life-client` in the
   GreHack deck, `protoscan bob/app` in the gRPConf one), the Rust and
   Python protoscan print the same names and write byte-identical `.pb`
   files.
5. `completionTests` passes for protoscan.
6. `nixpkgs-staging` builds the staged protoscan recipe.
7. `ci`, the image and its smoke test pass; the internal package builds
   with S7's change.

## Measured outcome

Filled in at implementation.
