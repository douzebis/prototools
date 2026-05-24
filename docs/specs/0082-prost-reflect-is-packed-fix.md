<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0082 — Fix `is_packed()` bug in prost-reflect and remove `prost-bug-workaround` feature

**Status:** draft
**App:** prototext-core / upstream prost-reflect

---

## Background

`prost-reflect` computes `is_packed` for a field descriptor as follows
(file `src/descriptor/build/resolve.rs`, lines 121–126 and 392–397 in
version 0.16.3, both identical):

```rust
let is_packed = cardinality == Cardinality::Repeated
    && kind.is_some_and(|k| k.is_packable())
    && (field
        .options
        .as_ref()
        .map_or(syntax == Syntax::Proto3, |o| o.value.packed()));
```

The logic is:

- If `options` is absent (`None`): fall back to `syntax == Proto3` — **correct**.
- If `options` is present (`Some`): use `o.value.packed()` — **buggy**.

`o.value` is a `prost_types::FieldOptions` struct.  `FieldOptions.packed` is
`Option<bool>` (field tag 2, optional).  When `options` is present in the
FileDescriptorSet but carries only unknown extension bytes (e.g. a custom
option annotation), prost deserializes `FieldOptions` with no `packed` entry.
`packed()` on a `prost_types::FieldOptions` is a generated accessor that
returns `self.packed.unwrap_or(false)` — it returns `false` for a missing
field.  The proto3 default (`true`) is therefore never applied.

This is documented in detail in `docs/PROST-ISSUES.md §1`, with a minimal
two-file reproducer.

### Upstream repository

`prost-reflect` is maintained by Andrew Hickman at
`https://github.com/andrewhickman/prost-reflect`.  The fix is a two-line
change in a single file.

### Current workaround

`prototext-core` carries a compile-time Cargo feature `prost-bug-workaround`
(enabled in the workspace `Cargo.toml`) that bypasses `is_packed()` for
proto3 repeated packable fields:

- `prototext-core/Cargo.toml` declares `prost-bug-workaround = []`.
- `prototext-core/src/serialize/render_text/mod.rs` adds `raw_packed_option()`
  and `parent_file_syntax()` helper methods gated on the feature.
- `prototext-core/src/serialize/render_text/helpers/len_field.rs` (lines
  74–101) uses `raw_packed_option() != Some(false)` instead of `is_packed()`
  when the feature is active.
- The workspace `Cargo.toml` enables the feature unconditionally via
  `prototext-core = { path = "prototext-core", features = ["prost-bug-workaround"] }`.

---

## Goals

1. Open a GitHub issue on `andrewhickman/prost-reflect` describing the bug
   with the minimal reproducer from `docs/PROST-ISSUES.md §1`.
2. Submit a pull request with a two-line fix to `resolve.rs`.
3. Once the fix is released and `prost-reflect` is bumped in this repo,
   remove the `prost-bug-workaround` feature and all associated code.

---

## Non-goals

- Fixing the `prost-reflect` editions non-support issue (that is a separate
  upstream effort tracked by `docs/PROST-ISSUES.md §2` and spec 0057).
- Changing any rendering behaviour: the fix restores the correct proto3
  default; no observable change in behaviour for callers that do not hit the
  bug.

---

## Specification

### §82.1 Upstream fix to `prost-reflect`

The fix is to replace the buggy closure in both instances in
`src/descriptor/build/resolve.rs`:

**Before (both sites):**
```rust
.map_or(syntax == Syntax::Proto3, |o| o.value.packed())
```

**After (both sites):**
```rust
.map_or(syntax == Syntax::Proto3, |o| o.value.packed.unwrap_or(syntax == Syntax::Proto3))
```

`FieldOptions.packed` is declared as `Option<bool>` in
`prost-types` (`prost-types-0.14.x/src/protobuf.rs`, tag 2, `optional`).
`unwrap_or(syntax == Syntax::Proto3)` restores the correct default: absent
`packed` means packed in proto3, unpacked in proto2.

The two fix sites are:

| Location | Context |
|---|---|
| `resolve.rs` lines 121–126 | Regular field descriptors (`resolve_field`) |
| `resolve.rs` lines 392–397 | Extension field descriptors (`resolve_extension`) |

### §82.2 GitHub issue

**Before opening the issue:** create a local `cargo new prost-reflect-is-packed-bug`
crate using the `Cargo.toml` and `src/main.rs` below, run `cargo run`, and
confirm that it prints `is_packed: false` and panics on the assertion.  Do not
open the issue until this has been verified.

Open an issue on `andrewhickman/prost-reflect` with:

- **Title:** `is_packed() returns false for proto3 repeated fields when FieldOptions is present but has no packed entry`
- **Labels (if available):** `bug`

**Body** — the issue must be self-contained (no external files, no `protoc`
required).  Build the triggering `FileDescriptorSet` programmatically using
`prost_types`, so the reproducer is a single `Cargo.toml` + `src/main.rs`:

`Cargo.toml`:
```toml
[package]
name  = "prost-reflect-is-packed-bug"
edition = "2021"

[dependencies]
prost         = "0.14"
prost-reflect = "0.16"
prost-types   = "0.14"
```

`src/main.rs`:
```rust
use prost::Message;
use prost_reflect::DescriptorPool;
use prost_types::{
    field_descriptor_proto::{Label, Type},
    DescriptorProto, FieldDescriptorProto, FieldOptions, FileDescriptorProto,
    FileDescriptorSet,
};

fn main() {
    // Build a minimal proto3 FileDescriptorSet in memory:
    //   syntax = "proto3";
    //   message Foo { repeated int32 values = 1; }
    //
    // The field carries FieldOptions that is present but has no `packed` entry
    // (all fields None / default).  This is what protoc emits when a custom
    // option annotation is present on the field but `packed` is not set.
    let fds = FileDescriptorSet {
        file: vec![FileDescriptorProto {
            name: Some("test.proto".into()),
            syntax: Some("proto3".into()),
            message_type: vec![DescriptorProto {
                name: Some("Foo".into()),
                field: vec![FieldDescriptorProto {
                    name: Some("values".into()),
                    number: Some(1),
                    label: Some(Label::Repeated as i32),
                    r#type: Some(Type::Int32 as i32),
                    // options is Some but has no `packed` field set.
                    // Expected: is_packed() == true  (proto3 default)
                    // Actual:   is_packed() == false (bug)
                    options: Some(FieldOptions::default()),
                    ..Default::default()
                }],
                ..Default::default()
            }],
            ..Default::default()
        }],
    };

    let bytes = fds.encode_to_vec();
    let pool = DescriptorPool::decode(bytes.as_slice()).unwrap();
    let msg  = pool.get_message_by_name("Foo").unwrap();
    let field = msg.get_field_by_name("values").unwrap();

    println!("is_packed: {}", field.is_packed()); // prints false — should be true
    assert!(field.is_packed(), "proto3 repeated int32 with empty FieldOptions must be packed");
}
```

Running `cargo run` prints `is_packed: false` and panics on the assertion.
The expected output is `is_packed: true`.

Include the root-cause explanation from `docs/PROST-ISSUES.md §1` (the
`map_or` / `packed()` analysis) and the proposed fix from §82.1.

### §82.3 Pull request

Steps:

1. **Clone** the fork of `andrewhickman/prost-reflect` locally.  The line
   numbers cited in §82.1 (121–126 and 392–397) are from version 0.16.3;
   verify that the same `map_or` expressions are present at those locations
   in the current `main` branch before applying the fix.
2. **Apply** the two-line fix from §82.1.
3. **Run** the existing test suite (`cargo test --all`) and confirm no
   regressions.
4. **Add** a test that exercises a proto3 repeated packable field with a
   present-but-empty `FieldOptions` and asserts `is_packed() == true`, placed
   alongside similar tests in the project's test harness.
5. **Submit** the PR targeting `main` (or the active development branch),
   referencing the issue opened in §82.2.

### §82.4 Local removal (after upstream release)

Once the fix is merged, tagged, and a new `prost-reflect` version is released:

1. Bump `prost-reflect` in `prototext-core/Cargo.toml` to the fixed version.
2. Remove `prost-bug-workaround = []` from `prototext-core/Cargo.toml`
   `[features]` block (lines 22–27).
3. Remove `features = ["prost-bug-workaround"]` from the workspace
   `Cargo.toml` `prototext-core` dependency (line 31).
4. Remove the `#[cfg(feature = "prost-bug-workaround")]` blocks from
   `prototext-core/src/serialize/render_text/mod.rs` (`raw_packed_option`,
   `parent_file_syntax` methods).
5. Remove the `#[cfg(feature = "prost-bug-workaround")]` / `#[cfg(not(...))]`
   conditional blocks from
   `prototext-core/src/serialize/render_text/helpers/len_field.rs` (lines
   74–101), replacing both branches with a single `fs.is_packed()` call.
6. Run `cargo test` and verify no regressions.
7. Update `docs/PROST-ISSUES.md §1` to note the fix (version, PR/issue link).
8. Update this spec status to `implemented`.

---

## References

- `docs/PROST-ISSUES.md §1` — bug description and minimal reproducer.
- `prototext-core/Cargo.toml` lines 22–27 — `prost-bug-workaround` feature declaration.
- `Cargo.toml` line 31 — workspace feature enablement.
- `prototext-core/src/serialize/render_text/mod.rs` lines 82–92 — `raw_packed_option` / `parent_file_syntax`.
- `prototext-core/src/serialize/render_text/helpers/len_field.rs` lines 74–101 — workaround branch.
- `prost-reflect-0.16.3/src/descriptor/build/resolve.rs` lines 121–126 and 392–397 — bug sites.
- `prost-types-0.14.x/src/protobuf.rs` line 693 — `pub packed: ::core::option::Option<bool>`.
