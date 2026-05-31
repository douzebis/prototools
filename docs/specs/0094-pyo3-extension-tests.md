<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0094 — Unit tests for `fdp_scan_lib` and `prototext_codec_lib` PyO3 extensions

**Status:** draft
**Implemented in:** —
**App:** fdp-scan-pyo3, prototext-pyo3

---

## Background

`fdp_scan_lib` and `prototext_codec_lib` are the two PyO3 Rust extensions
that back the `protoscan` and `reproto` CLIs respectively.  Both are also
candidates for `python3Packages` entries in nixpkgs.

`fdp_scan_lib` currently has only `pythonImportsCheck` in the nixpkgs build.
`prototext_codec_lib` has no tests at all.  This spec adds behavioural test
suites for both, following the same approach used for `protoscan` (spec 0092):
tests live in the oss-prototools source tree; the nixpkgs build runs them via
`pytestCheckHook`.

No fixture files are committed.  All test inputs are synthesised in-process
using protobuf's Python API (`google.protobuf`), which is already a runtime
dependency of the test environments for both extensions.

---

## Goals

1. Write `fdp-scan-pyo3/fdp_scan_lib/tests/test_scan.py` — behavioural tests
   for `fdp_scan_lib.scan()`.
2. Write `prototext-pyo3/prototext_codec_lib/tests/test_codec.py` —
   behavioural tests for `format_as_text()`, `format_as_bytes()`, and
   `register_schema()`.
3. Add `__init__.py` files for both test packages.
4. Wire both test suites into the oss-prototools Nix build
   (`nix/python.nix`: new `fdpScanTests` and `prototextCodecTests` derivations,
   added to `ci` and `ci-no-clippy` targets in `default.nix`).
5. Update the nixpkgs `fdp-scan/default.nix` to run the tests via
   `pytestCheckHook` + `enabledTestPaths` (replacing `pythonImportsCheck`-only).

---

## Non-goals

- Testing the `SchemaHandle.schema_capsule()` / `from_capsule()` cross-extension
  protocol (requires two `.so` files loaded together; covered by the reproto
  integration tests).
- Adding a nixpkgs package for `prototext-codec` (tracked separately in
  spec 0092 PR 1).
- Tests for `scoring_graph_lib` (deferred to PR 2 / spec 0093).

---

## Specification

### §1 — `fdp_scan_lib` tests

#### §1.1 — Location

```
fdp-scan-pyo3/tests/test_scan.py
```

Tests live in a sibling `tests/` directory (not inside the `fdp_scan_lib/`
package), with no `__init__.py`.  This prevents pytest from adding
`fdp-scan-pyo3/` to `sys.path`, which would shadow the installed package
with the source tree (which has no `.so`).

#### §1.2 — API under test

```python
fdp_scan_lib.scan(buffer: bytes) -> list[tuple[int, int]]
```

Returns `(start, end)` byte-offset pairs for each `FileDescriptorProto`
candidate found in `buffer`.

#### §1.3 — Test cases

All fixtures are synthesised via `google.protobuf.descriptor_pb2.FileDescriptorProto`.

| ID | Description |
|---|---|
| TC-1 | Empty buffer → empty list |
| TC-2 | Buffer of zero bytes → empty list |
| TC-3 | Single FDP blob → one `(start, end)` pair; extracted slice round-trips through protobuf |
| TC-4 | Two concatenated FDP blobs → two pairs, correct byte ranges |
| TC-5 | FDP preceded by noise bytes + `0x00` terminator → FDP detected, correct offsets |
| TC-6 | Extracted slice from TC-3 deserialises to a `FileDescriptorProto` with the expected `name` field |

TC-3 and TC-6 together verify that the `(start, end)` slice is a valid,
round-trippable `FileDescriptorProto` binary.

### §2 — `prototext_codec_lib` tests

#### §2.1 — Location

```
prototext-pyo3/tests/test_codec.py
```

Same convention as `fdp_scan_lib`: sibling `tests/` directory, no
`__init__.py`, tests run against the installed package.

#### §2.2 — API under test

```python
format_as_text(data, schema=None, assume_binary=False,
               include_annotations=False, indent=1) -> bytes
format_as_bytes(data, assume_binary=False) -> bytes
register_schema(schema_data: bytes, root_message: str) -> SchemaHandle
```

#### §2.3 — Test cases

All fixtures synthesised in-process; no committed files.

Key behaviours discovered during implementation:

- Without a schema, `format_as_text` emits nothing for unknown LEN fields
  (it cannot distinguish bytes / string / nested message without schema
  information).  A minimal `FileDescriptorProto` with only a `name` field is
  entirely LEN-encoded, so the output is `b""` — correct, not a bug.
- The `#@ prototext:` header is only emitted when `include_annotations=True`.
  Without annotations a schema-aware render still emits field lines (e.g.
  `name: "test.proto"\n`), but without the header round-tripping via
  `format_as_bytes` is not possible.

`register_schema` expects a serialised `FileDescriptorSet` (not a bare
`FileDescriptorProto`).

| ID | Description |
|---|---|
| TC-1 | `format_as_text(b"")` → returns `b""` |
| TC-2 | `format_as_text(fdp_bytes)` (no schema, no annotations) → returns `b""` (unknown LEN fields silently omitted) |
| TC-3 | `format_as_text(fdp_bytes, include_annotations=True)` → starts with `b"#@ prototext:"` |
| TC-4 | Round-trip: `format_as_bytes(format_as_text(fdp_bytes, include_annotations=True))` == `fdp_bytes` |
| TC-5 | `format_as_bytes(binary, assume_binary=True)` returns the input unchanged (fast path) |
| TC-6 | `format_as_text` on already-textual input (starts with `#@ prototext:`) returns it unchanged (fast path) |
| TC-7 | `register_schema(fds_bytes, root_message)` returns a `SchemaHandle` without raising |
| TC-8 | `format_as_text(fdp_bytes, schema=handle, include_annotations=True)` output contains the field name as an annotation comment |

TC-4 is the core lossless round-trip guarantee.  TC-5 and TC-6 verify the
fast-path passthrough branches.  TC-8 verifies that schema-aware annotation
works end-to-end.

For TC-7 and TC-8: schema is a `FileDescriptorSet` wrapping
`FileDescriptorProto`'s own self-descriptor, synthesised via protobuf's
Python API.

### §3 — Nix wiring (oss-prototools)

Two new `runCommand` derivations in `nix/python.nix`, following the
`protoscanTests` pattern:

No `PYTHONPATH` override is needed — the installed packages are already on
the Python path via `withPackages`.  Tests run directly against the installed
extensions from the Nix store.

```nix
fdpScanTests = pkgs.runCommand "fdp-scan-tests" {
  buildInputs = [ (pythonPkgs.python.withPackages (_: [
    fdpScanLib
    pythonPkgs.protobuf
    pythonPkgs.pytest
    pythonPkgs."pytest-xdist"
  ])) ];
} ''
  pytest -p no:cacheprovider ${../fdp-scan-pyo3}/tests/ -x
  touch $out
'';

prototextCodecTests = pkgs.runCommand "prototext-codec-tests" {
  buildInputs = [ (pythonPkgs.python.withPackages (_: [
    prototextCodec
    pythonPkgs.protobuf
    pythonPkgs.pytest
    pythonPkgs."pytest-xdist"
  ])) ];
} ''
  pytest -p no:cacheprovider ${../prototext-pyo3}/tests/ -x
  touch $out
'';
```

Both are added to `default.nix`'s `ci` and `ci-no-clippy` targets and
exposed as `fdp-scan-tests` and `prototext-codec-tests` attributes.

### §4 — nixpkgs update (`fdp-scan/default.nix`)

Replace `pythonImportsCheck = [ "fdp_scan_lib" ]` with:

```nix
nativeCheckInputs = [ pytestCheckHook ];
enabledTestPaths = [ "fdp_scan_lib/tests/" ];
pythonImportsCheck = [ "fdp_scan_lib" ];
```

`prototext-codec` does not yet have a nixpkgs package (tracked in spec 0092
PR 1); its nixpkgs test wiring is deferred to that spec.

---

## Things done

- [ ] `fdp_scan_lib` test suite written and passing locally
- [ ] `prototext_codec_lib` test suite written and passing locally
- [ ] `fdpScanTests` derivation passes in `nix-build`
- [ ] `prototextCodecTests` derivation passes in `nix-build`
- [ ] `reuse lint` clean
- [ ] nixpkgs `fdp-scan` tests pass with `pytestCheckHook`
