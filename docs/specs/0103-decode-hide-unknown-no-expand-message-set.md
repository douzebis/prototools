<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0103 — `--hide-unknown-fields` and `--no-expand-message-set` for `prototext decode`

**Status:** implemented
**Implemented in:** 2026-06-19
**App:** prototext

---

## Problem

### A — Unknown fields are silently hidden in `--no-annotations` mode

When `prototext decode` is given a schema (`--descriptor-set` + `--type`) and
`--no-annotations` is set, fields that are not present in the schema
(unknown fields, wire-type mismatches) are silently dropped from the output.
This is the current hardcoded coupling inside `prototext-core`:

```
// varint.rs:137
if !annotations && schema_present && (unknown || is_wire || is_mismatch) {
    return;  // silently dropped
}
```

The same suppression applies in `len_field.rs:43`:

```
if !annotations && schema_present {
    // unknown length-delimited field: skip
}
```

The suppression was introduced to make `--no-annotations` output
protoc-compatible.  But it conflates two orthogonal concerns:

- **Annotation control** — whether `#@` comment lines are emitted.
- **Unknown-field visibility** — whether fields absent from the schema appear
  in the output.

A user who wants clean, comment-free output but still wants to see unknown
fields currently has no way to achieve this.

### B — MessageSet expansion is coupled to `--no-expand-any`

MessageSet expansion (spec 0100) is gated on the `EXPAND_ANY` thread-local
flag (`len_field.rs:232`).  A user who wants to suppress MessageSet expansion
but still expand `google.protobuf.Any` fields has no way to do so.

---

## Goals

1. Add `--hide-unknown-fields` to `prototext decode`: when set, unknown /
   wire-type-mismatch fields are suppressed from the output even without
   `--no-annotations`.
2. Change the default behavior of `--no-annotations`: unknown fields are
   **shown** (as bare field numbers, without `#@` annotation lines) by
   default.  `--hide-unknown-fields` is required to suppress them.
3. Add `--no-expand-message-set` to `prototext decode`: suppresses inline
   MessageSet group expansion independently of `--no-expand-any`.
4. Update `RenderOpts` and `decode_and_render` in `prototext-core` to carry
   the two new knobs.
5. Update all tests to reflect the new default behavior.
6. Update the man page.

---

## Non-goals

- Changing `--raw` mode behavior: with no schema, every field is unknown by
  definition, so `--hide-unknown-fields` has no effect and is silently
  ignored.
- Changing `--no-expand-any` behavior (it continues to suppress both Any
  expansion and MessageSet expansion unless `--no-expand-message-set` is
  used to decouple them).
- Changing `protoc --decode` compatibility guarantees: `--no-annotations
  --hide-unknown-fields` together still produce protoc-compatible output,
  same as `--no-annotations` alone did before.

---

## Behavioral changes summary

| Mode | Before | After |
|---|---|---|
| `--no-annotations` (with schema) | unknown fields hidden | unknown fields shown as bare field numbers |
| `--no-annotations --hide-unknown-fields` | (same as above) | unknown fields hidden — same as old `--no-annotations` |
| `--no-expand-any` | suppresses both Any and MessageSet expansion | suppresses both (unchanged) |
| `--no-expand-message-set` | (flag did not exist) | suppresses MessageSet expansion only |
| `--no-expand-any --no-expand-message-set` | N/A | same as `--no-expand-any` alone |
| `--raw` + `--hide-unknown-fields` | N/A | `--hide-unknown-fields` silently ignored |

**Breaking change:** `--no-annotations` with a schema now shows unknown
fields where it previously hid them.  Users relying on protoc-compatible
output must add `--hide-unknown-fields`.

---

## Specification

### S1 — Extend `RenderOpts` in `prototext-core/src/lib.rs`

Add two fields to `RenderOpts`:

```rust
pub struct RenderOpts {
    pub assume_binary: bool,
    pub include_annotations: bool,
    pub indent: usize,
    pub expand_any: bool,
    /// When `true`, suppress fields not present in the schema (unknown fields,
    /// wire-type mismatches) from the output.  No effect when no schema is
    /// active (raw mode).  Default: `false` (show unknown fields).
    pub hide_unknown_fields: bool,
    /// When `true`, suppress inline expansion of MessageSet groups.
    /// Independent of `expand_any`.  Default: `false` (expand MessageSets).
    pub expand_message_set: bool,
}
```

Update `Default`:

```rust
impl Default for RenderOpts {
    fn default() -> Self {
        RenderOpts {
            assume_binary: false,
            include_annotations: false,
            indent: 1,
            expand_any: true,
            hide_unknown_fields: false,
            expand_message_set: true,
        }
    }
}
```

### S2 — Add `HIDE_UNKNOWN` and `EXPAND_MESSAGE_SET` thread-locals in `prototext-core/src/serialize/render_text/mod.rs`

Add alongside the existing thread-locals:

```rust
// When true, fields absent from the schema are suppressed (spec 0103).
pub(super) static HIDE_UNKNOWN: Cell<bool> = const { Cell::new(false) };
// When true, MessageSet groups are expanded inline (spec 0103).
pub(super) static EXPAND_MESSAGE_SET: Cell<bool> = const { Cell::new(true) };
```

Initialize them in `decode_and_render`:

```rust
HIDE_UNKNOWN.with(|c| c.set(hide_unknown_fields));
EXPAND_MESSAGE_SET.with(|c| c.set(expand_message_set));
```

Update the `decode_and_render` signature to accept the two new parameters
(or pass them via `RenderOpts` if the signature is refactored — either is
acceptable, but must be consistent with the existing `annotations` /
`expand_any` pattern).

### S3 — Update suppression logic in `varint.rs`

Replace the current suppression condition:

```rust
// Before
if !annotations && schema_present && (unknown || is_wire || is_mismatch) {
    return;
}
```

with:

```rust
// After
let hide = HIDE_UNKNOWN.with(|c| c.get());
if hide && schema_present && (unknown || is_wire || is_mismatch) {
    return;
}
```

The `annotations` flag no longer controls suppression.

### S4 — Update suppression logic in `len_field.rs`

Replace:

```rust
// Before
if !annotations && schema_present {
    // skip unknown length-delimited field
}
```

with:

```rust
// After
let hide = HIDE_UNKNOWN.with(|c| c.get());
if hide && schema_present {
    // skip unknown length-delimited field
}
```

Replace the MessageSet expansion gate:

```rust
// Before
if EXPAND_ANY.with(|c| c.get()) && is_message_set(&nested_msg_desc) {
```

with:

```rust
// After
if EXPAND_MESSAGE_SET.with(|c| c.get()) && is_message_set(&nested_msg_desc) {
```

Note: `--no-expand-any` currently suppresses both Any and MessageSet
expansion because the MessageSet check uses `EXPAND_ANY`.  After S4,
MessageSet expansion is controlled by `EXPAND_MESSAGE_SET` independently.
`--no-expand-any` sets `expand_any=false` but leaves `expand_message_set`
at its default `true`, so MessageSet expansion continues unless the user also
passes `--no-expand-message-set`.  This is a behavioral change for
`--no-expand-any` users with MessageSet data — document it in the man page.

### S5 — Add CLI flags in `prototext/src/lib.rs`

In the `Decode` variant of the `Command` enum, add:

```rust
/// Suppress fields not present in the schema (unknown fields, wire-type
/// mismatches).  Has no effect in --raw mode.
/// With --no-annotations, this restores protoc-compatible output.
#[arg(long = "hide-unknown-fields")]
hide_unknown_fields: bool,

/// Suppress inline expansion of MessageSet groups.
/// Independent of --no-expand-any.
#[arg(long = "no-expand-message-set", help_heading = "Advanced options")]
no_expand_message_set: bool,
```

### S6 — Wire flags through `run.rs`

In the `decode` arm of `run::run`, pass the new flags when constructing
`RenderOpts`:

```rust
RenderOpts {
    assume_binary,
    include_annotations: annotations,
    indent: 1,
    expand_any: !no_expand_any,
    hide_unknown_fields,
    expand_message_set: !no_expand_message_set,
}
```

### S7 — Update tests

The test `no_annotations_omits_unknown_fields` in
`prototext/tests/roundtrip.rs` (line 177) asserts that unknown fields are
omitted when `include_annotations: false`.  This assertion is now wrong.

Update it to two tests:

- `no_annotations_shows_unknown_fields_by_default`: verifies that with
  `include_annotations: false` and `hide_unknown_fields: false`, unknown
  fields **appear** as bare field numbers.
- `hide_unknown_fields_omits_unknown_fields`: verifies that with
  `hide_unknown_fields: true`, unknown fields are suppressed regardless of
  `include_annotations`.

Add a test for `--no-expand-message-set`:
- `no_expand_message_set_suppresses_expansion`: verifies that with
  `expand_message_set: false` and `expand_any: true`, a MessageSet field is
  rendered as a raw length-delimited blob rather than expanded inline.
- `expand_any_false_does_not_suppress_message_set`: verifies that with
  `expand_any: false` and `expand_message_set: true`, MessageSet expansion
  still occurs (documents the decoupling introduced by S4).

Any other tests that construct `RenderOpts` without the new fields will need
the struct updated to supply `hide_unknown_fields: false` and
`expand_message_set: true` explicitly (or via `..RenderOpts::default()`).

### S8 — Update the man page (`gen_man.rs` / `EXTRA_SECTIONS`)

Document `--hide-unknown-fields` and `--no-expand-message-set` in the
`EXAMPLES` section of `gen_man.rs`:

```
# Clean output without schema annotations, still showing unknown fields
prototext --descriptor-set my.desc decode --type com.example.Foo \
    --no-annotations foo.pb

# protoc-compatible output (annotations off, unknown fields suppressed)
prototext --descriptor-set my.desc decode --type com.example.Foo \
    --no-annotations --hide-unknown-fields foo.pb

# Suppress MessageSet expansion only (Any still expands)
prototext --descriptor-set my.desc decode --type com.example.Foo \
    --no-expand-message-set foo.pb
```

---

## Verification

1. `nix-build -A ci` passes (all tests green).
2. `prototext decode --no-annotations` with a schema and unknown fields in the
   input: unknown fields appear as bare field numbers in the output.
3. `prototext decode --no-annotations --hide-unknown-fields`: output is
   identical to old `--no-annotations` behavior (protoc-compatible).
4. `prototext decode --no-expand-message-set`: MessageSet fields rendered as
   raw blobs; Any fields still expanded.
5. `prototext decode --no-expand-any`: Any fields not expanded; MessageSet
   fields still expanded (behavior change from pre-spec — verify this is
   intentional and documented).
6. `prototext decode --raw --hide-unknown-fields`: flag silently ignored,
   all fields rendered as before.

---

## Summary of changes

| File | Change |
|---|---|
| `prototext-core/src/lib.rs` | Add `hide_unknown_fields`, `expand_message_set` to `RenderOpts` |
| `prototext-core/src/serialize/render_text/mod.rs` | Add `HIDE_UNKNOWN`, `EXPAND_MESSAGE_SET` thread-locals; initialize in `decode_and_render` |
| `prototext-core/src/serialize/render_text/varint.rs` | Replace `!annotations` guard with `HIDE_UNKNOWN` |
| `prototext-core/src/serialize/render_text/helpers/len_field.rs` | Replace `!annotations` guard with `HIDE_UNKNOWN`; replace MessageSet `EXPAND_ANY` gate with `EXPAND_MESSAGE_SET` |
| `prototext/src/lib.rs` | Add `--hide-unknown-fields`, `--no-expand-message-set` to `Decode` |
| `prototext/src/run.rs` | Wire new flags into `RenderOpts` construction |
| `prototext/tests/roundtrip.rs` | Update `no_annotations_omits_unknown_fields`; add new tests |
| `prototext/src/gen_man.rs` | Add examples for new flags |

---

## References

- `docs/specs/0089-any-expansion.md` — `google.protobuf.Any` expansion
- `docs/specs/0097-raw-recursive-lendel.md` — raw mode field rendering (spec 0097 S5)
- `docs/specs/0100-message-set-expansion.md` — MessageSet expansion
- `prototext-core/src/serialize/render_text/varint.rs` — varint suppression logic
- `prototext-core/src/serialize/render_text/helpers/len_field.rs` — len-field suppression and MessageSet gate
