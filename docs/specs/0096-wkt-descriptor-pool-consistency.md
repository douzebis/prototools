<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0096 — WKT descriptor pool / scoring graph consistency

**Status:** implemented
**Implemented in:** 2026-06-11
**App:** prototext, build system

---

## Background

The embedded `EMBEDDED_DESCRIPTOR` (pool used at decode time) and the
embedded `WKT_GRAPH` (Hopcroft scoring graph used at inference time) are
built from different source sets:

- `WKT_GRAPH` is derived from all 11 files listed in
  `prototext/wkt/SOURCES` (compiled with `--include_imports`).
- `EMBEDDED_DESCRIPTOR` is compiled from `google/protobuf/descriptor.proto`
  alone — no `--include_imports`, no other WKT files.

This inconsistency causes a hard failure when auto-inference returns a type
present in the graph but absent from the pool.  For example:

```
$ prototext decode /tmp/addressbook.pb
error: descriptor: message not found: root message
  'google.protobuf.BytesValue' not found in schema
  (available: google.protobuf.FileDescriptorSet, ...)
```

`BytesValue` lives in `google/protobuf/wrappers.proto`, which is in
`wkt/SOURCES` (and therefore in `WKT_GRAPH`) but not in the pool.

---

## Root cause

`protoPatchPhase` in `default.nix` and the `protox` branch of `build.rs`
compile `descriptor.pb` from a single source file.  `wktRkyv` and
`build_wkt_graph` in `build.rs` read `wkt/SOURCES` and compile all 11
files.  The two code paths are independent and can diverge silently.

---

## Goals

- The descriptor pool used at decode time contains exactly the same types
  as the Hopcroft scoring graph used at inference time.
- The single source of truth for "which WKT files are included" is
  `prototext/wkt/SOURCES`, as it is today for `WKT_GRAPH`.
- The fix is robust: adding a new file to `SOURCES` automatically updates
  both artifacts with no further changes required.

## Non-goals

- Improving the error message for missing types (separate issue).
- Falling back to raw decode when a type is absent from the pool (separate
  issue).

---

## Specification

### S1 — `default.nix`: compile `descriptor.pb` from `wkt/SOURCES`

In `protoPatchPhase`, replace the single-file `protoc` invocation that
produces `descriptor.pb`:

```
protoc \
  --descriptor_set_out=prototext/fixtures/prebuilt/descriptor.pb \
  google/protobuf/descriptor.proto
```

with one that compiles all files listed in `wktSources` (already read at
eval time) with `--include_imports`:

```
protoc \
  --descriptor_set_out=prototext/fixtures/prebuilt/descriptor.pb \
  --include_imports \
  <all files from wkt/SOURCES>
```

The `wktSources` list is already available in `default.nix` scope (defined
at line ~159).  Use `pkgs.lib.concatStringsSep` to interpolate it, exactly
as `wktRkyv` does.

### S2 — `build.rs` (`protox` path): compile `descriptor.pb` from `wkt/SOURCES`

In the `protox`-enabled branch of `main()`, replace:

```rust
compile(
    &["google/protobuf/descriptor.proto"],
    &[""],
    &out_dir,
    "descriptor.pb",
);
```

with a compile over all files from `wkt/SOURCES`, using the same
`sources_text` reading logic already present in `build_wkt_graph`:

```rust
let sources_path = Path::new(&manifest_dir).join("prototext/wkt/SOURCES");
// (adjust path: build.rs is in prototext/, so relative path is wkt/SOURCES)
let sources_text = std::fs::read_to_string(&sources_path)
    .expect("failed to read wkt/SOURCES");
let proto_files: Vec<&str> = sources_text
    .lines()
    .map(str::trim)
    .filter(|l| !l.is_empty())
    .collect();
compile(&proto_files, &[""], &out_dir, "descriptor.pb");
```

### S3 — No change to env-var names or Nix derivation names

`DESCRIPTOR_PB` continues to point to `descriptor.pb`; the file simply
contains the full WKT set instead of only `descriptor.proto`.  No new env
vars, no new Nix outputs.

### S4 — `prebuilt/descriptor.pb` must be regenerated

After the change, the committed prebuilt file
`prototext/fixtures/prebuilt/descriptor.pb` (used as fallback when neither
`protox` nor `DESCRIPTOR_PB` is available) must be regenerated with:

```bash
protoc \
  --descriptor_set_out=prototext/fixtures/prebuilt/descriptor.pb \
  --include_imports \
  $(cat prototext/wkt/SOURCES)
```

and committed.

---

## Invariant established

After this change, for any file `F` in `wkt/SOURCES`:

- Every type defined in `F` appears in the Hopcroft scoring graph
  (`WKT_GRAPH`).
- Every type defined in `F` appears in the descriptor pool
  (`EMBEDDED_DESCRIPTOR`).

Auto-inference can never return a type that the pool cannot resolve.
