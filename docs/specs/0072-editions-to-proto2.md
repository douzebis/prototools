<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0072 — Correct translation from editions to proto2

**Status:** implemented
**Implemented in:** 2026-05-20
**App:** reproto

---

## Purpose

`reproto --force-proto2-output` is meant to translate an editions-syntax
`FileDescriptorProto` into proto2 `.proto` source that is wire-compatible with
the original — that is, encoding and decoding the same binary blobs.  The
primary use case is interoperability with toolchains that do not yet support
editions (e.g. prost-reflect as of 2026).

Three bugs prevent this guarantee from holding.  This spec defines the correct
behaviour and the regression tests that must pass after the fix.

---

## Goals

1. **Bug 1 — IMPLICIT label:** `field_label()` under `--force-proto2-output`
   must emit `optional ` (not `''`) when
   `features.field_presence == FIELD_PRESENCE_IMPLICIT`.  The current output is
   invalid proto2 syntax (protoc rejects it).  There is no semantic loss:
   proto2 `optional` is wire-compatible with editions `IMPLICIT` for singular
   scalar and message fields.

2. **Bug 2 — DELIMITED group encoding:** a `TYPE_MESSAGE` field with
   `features.message_encoding == MESSAGE_ENCODING_DELIMITED` must be rendered
   as a proto2 group block, not as a plain `optional` field.  The wire encoding
   differs (`TYPE_GROUP` tag vs `TYPE_MESSAGE` tag), so the current output is
   not wire-compatible.

3. **Bug 3 — packed annotation for repeated scalars:** `packed_option()` under
   `--force-proto2-output` must consult `features.repeated_field_encoding` and
   emit `[packed = true]` for `PACKED` and `[packed = false]` for `EXPANDED`,
   following the same logic as the existing proto3→proto2 cross-syntax path.
   The current code returns `None` unconditionally for editions fields when
   `has_field` is False, silently dropping the packed annotation.

---

## Non-goals

- Changing behaviour when `--force-proto2-output` is not active.
- Translating editions `features {}` blocks that have no proto2 equivalent
  other than what is covered above (e.g. `utf8_validation`, `json_format`).
  These affect only runtime validation and JSON behaviour, not wire format;
  a `// WARNING[editions]` comment is emitted on the affected field or message
  and no log warning is raised.

---

## Specification

### Bug 1 — IMPLICIT → `optional`

In `syntax.py`, `field_label()`, the `features is not None` branch is reached
both when rendering editions files as editions (`target_syntax == "editions"`)
and when rendering them as proto2 (`--force-proto2-output`,
`target_syntax == "proto2"`).  The fix must only apply to the proto2 case:

```python
if features.field_presence == FIELD_PRESENCE_IMPLICIT:
    # Editions output: no label (presence expressed via features option).
    # Proto2 output (--force-proto2-output): 'optional' is the closest
    # wire-compatible equivalent.
    return '' if ctx.target_syntax == "editions" else 'optional '
```

The test `test_T3_field_label_editions_implicit` in `test_editions_rendering.py`
currently passes `ctx.target_syntax = "proto2"` (the `_ctx()` default) and
asserts `== ""`.  It must be split into two cases:
- `target_syntax = "editions"`: assert `== ""` (unchanged).
- `target_syntax = "proto2"`: assert `== "optional "`.

### Bug 2 — DELIMITED → group block

In editions, a field with `features.message_encoding == MESSAGE_ENCODING_DELIMITED`
is stored as `TYPE_MESSAGE` in the FDP (unlike legacy proto2 groups which use
`TYPE_GROUP`).  The rendering pipeline must detect this combination and emit
group syntax.

The lifeline is to mirror exactly what happens when reproto processes a native
proto2 group.  For a proto2 `TYPE_GROUP` field, `type_name` points to the
group's own implicit nested type — a distinct entry in the FDP's `nested_type`
list, with its own FQDN scoped to the enclosing message (e.g.
`.pkg.AllFeatures.DelimitedField`).  `from_ref()` finds that FQDN in the pool,
sets `is_group = True` on it, and everything works because the group type and
any standalone message are different pool entries.

For editions DELIMITED, protoc stores `type_name` pointing at the original
message type (`Inner`), not a synthetic group type.  The fix is to synthesise
the equivalent structure at reproto's load time: register a fresh
`ReDescriptorProto` in the pool under a new group FQDN, then treat the field
as if it were `TYPE_GROUP` pointing at that FQDN.  After this, the existing
group rendering path in `re_field.py` and `re_descriptor.py` requires no
further changes.

**Group naming:**

The group FQDN is `{enclosing_message_fqdn}.{GroupName}`.  `GroupName` is
derived from the field name and must not collide with any existing nested type
name in the enclosing message scope.  The naming pass requires visibility over
all DELIMITED fields of a message simultaneously, so it belongs in
`re_descriptor.py` at the point where a message's fields are processed — not
in `re_field.py:init_field` which operates per-field in isolation.

Algorithm, run once per message during loading:

1. Collect all names already occupying the enclosing scope: nested message
   names and nested enum names.
2. For each DELIMITED field in declaration order, compute the CamelCase of
   the field name as the initial candidate (e.g. `delimited_field` →
   `DelimitedField`).
3. If the candidate is not already in the occupied set, assign it and add it
   to the occupied set.  Otherwise try `{candidate}2`, `{candidate}3`, …
   taking the smallest suffix not already in the occupied set, then assign and
   add.
4. Assert that the resulting FQDN (`{enclosing_message_fqdn}.{GroupName}`) is
   not already present in the pool.  A collision would mean the input
   descriptor is malformed (proto2 syntax would have rejected a group and a
   same-named message in the same scope), so an assertion failure is
   appropriate rather than silent recovery.
5. Construct the synthetic group descriptor:
   - Call `ReDescriptorProto(ctx, Ref(synthetic_fqdn))` to register a stub
     under the synthetic FQDN.  This is the `Ref` path in `__new__`/`__init__`,
     which sets `fqdn` from the ref string and registers in the pool without
     deriving a name from any `DescriptorProto.name` field.
   - The `Ref` path does not set `prefix` (only the `Message` path does, via
     `parent.prefix + msg.name`).  Set it explicitly:
     `grp.prefix = Prefix(synthetic_fqdn)`.
   - Call `grp._initialize_from_message(ctx, msg._this, parent=msg._parent)`
     directly to populate its fields, enums, and nested types from the same
     underlying `DescriptorProto` as the shared `Inner` instance.  Child nodes
     will be registered in the pool under `{synthetic_fqdn}.{child_name}` —
     distinct from `Inner`'s children at `{inner_fqdn}.{child_name}`.
   - Set `grp.is_group = True`.
   This mirrors the internal state of a native proto2 group descriptor exactly.

   **Safety of the shared underlying data:** `_initialize_from_message`
   creates new `Re*` wrapper instances for every child (going through `__new__`
   with distinct FQDNs), so the group subtree and the `Inner` subtree are fully
   independent `Re*` object graphs — each with their own `is_reachable`,
   `is_summoned`, `is_pruned`, `targets`, `contains`, etc.  The only sharing is
   of the raw protobuf `DescriptorProto`/`FieldDescriptorProto` objects
   (`_this`), which are never mutated after construction.  All mutable pipeline
   state lives exclusively on the `Re*` wrappers.  This pattern — deep copy of
   `Re*` wrappers, shared read-only protobuf data — is novel in reproto but
   safe for exactly this reason.
6. Update the field's `type_name` to the synthetic FQDN and treat it as
   `TYPE_GROUP` for all subsequent pipeline stages.

The standalone message definition (`message Inner`) is always emitted
regardless — its pool entry is unaffected.  A redundant standalone definition
is harmless in proto2, and this avoids any "is this type referenced elsewhere?"
analysis.

**Failure mode — wire-incompatible untranslatable constructs:**

For any editions construct where no wire-compatible proto2 translation exists
(e.g. future edge cases not covered above):

1. Orphan the field: emit a `// WARNING[editions]: <reason> — field orphaned`
   comment in place of the field declaration.  The field is not emitted.
2. Emit a squashed log warning so the user sees a summary.
3. Exit 0 — translation failures are non-fatal.

Omitting the field is safer than emitting a wire-incompatible substitute:
an unknown field is passed through transparently by all runtimes, whereas a
mismatched tag silently corrupts data.

### Bug 3 — packed annotation

In `syntax.py`, `packed_option()`, extend the `features is not None` branch to
apply cross-syntax logic when the rendering target is proto2:

```python
if features is not None:
    if has_field:
        return "true" if effective_packed else "false"
    # Under --force-proto2-output (target=proto2, source=editions):
    # proto2 defaults to unpacked; emit annotation to preserve semantics.
    if ctx.target_syntax == "proto2":
        if effective_packed:
            return "true"
        return None   # EXPANDED: unpacked is proto2 default, no annotation needed
    return None
```

The tests `test_T5_packed_option_editions_packed_default` and
`test_T6_packed_option_editions_expanded` in `test_editions_rendering.py`
currently use `_ctx()` which defaults to `target_syntax = "proto2"`.  Their
assertions of `None` reflect editions-rendering behaviour (deferred to phase 3)
— but that behaviour only applies when `target_syntax == "editions"`.  The
tests must be updated:

- T5 and T6: add a `target_syntax = "editions"` variant that asserts `None`
  (the original deferred-to-phase-3 behaviour, now correctly scoped).
- T5 (PACKED, `target_syntax = "proto2"`): assert `"true"`.
- T6 (EXPANDED, `target_syntax = "proto2"`): assert `None` (unpacked is proto2
  default — no annotation needed).

---

## Implementation order

The three bugs are independent but Bug 2 is the riskiest — it mutates the
loading pipeline in a novel way (dual `Re*` subtrees over shared protobuf data)
and could cause regressions in the existing roundtrip and rendering tests.
Implement in the following order, running the full test suite after each step
before proceeding.

**Step 1 — Bug 3 (packed annotation):** purely additive change to
`packed_option()` in `syntax.py`, gated on `ctx.target_syntax == "proto2"`.
No existing code path is altered.  Update T5/T6 unit tests.  Run full suite.

**Step 2 — Bug 1 (IMPLICIT label):** one-line change to `field_label()` in
`syntax.py`, gated on `ctx.target_syntax == "editions"` vs `"proto2"`.
Split T3.  Run full suite — in particular T13 (editions golden) must still
pass unchanged.

**Step 3 — extend fixture and T13 golden:** add the `packed_ids` field (T8)
to `editions_rendering.proto` and update `editions_rendering.golden.proto`.
Run full suite — T13 must pass with the updated golden.

**Step 4 — Bug 2, group naming pass (re_descriptor.py only):** implement the
naming algorithm in `re_descriptor.py`.  At this stage it computes group names
and stores them on fields but does not yet construct any synthetic descriptor.
Run full suite — nothing should change in output yet.

**Step 5 — Bug 2, synthetic group descriptor construction (re_field.py):**
implement the pool registration and `_initialize_from_message` call.  This is
the high-risk step.  Run full suite immediately — pay particular attention to:
- All existing roundtrip tests (`test_roundtrip.py`)
- All existing editions rendering tests (`test_editions_rendering.py` T1–T13)
- `test_phases.py`, `test_summoning.py` — these exercise reachability
  propagation and could expose shared-state bugs

**Step 6 — add T14 golden and assert recompile:** add
`editions_rendering.force_proto2.golden.proto`, implement `test_T14`, assert
that the golden recompiles with `protoc`.  Run full suite.

If the full suite fails at any step, stop and diagnose before proceeding.  Do
not paper over failures by adjusting golden files without understanding the
root cause.

---

## Regression test

Add a golden test `test_T14_force_proto2_output_golden` to
`test_editions_rendering.py`, parallel to the existing `test_T13`.

**Fixture:** extend `editions_rendering.proto` to add one `PACKED` repeated
scalar field (covering Bug 3's `[packed = true]` case — `EXPANDED` is already
present):

```proto
// T8 — PACKED repeated field: [packed = true] must be emitted in proto2 output.
repeated int32 packed_ids = 7 [features.repeated_field_encoding = PACKED];
```

**Golden file:** `editions_rendering.force_proto2.golden.proto` — checked in
alongside the existing golden.  Expected content after the fix:

```proto
// editions_rendering.proto

// WARNING[editions]: editions file rendered as proto2 (--force-proto2-output)
syntax = "proto2";

package reproto.test.rendering;

message Inner {
  optional int32 value = 1;
}

message AllFeatures {
  optional string implicit_field = 1;
  optional string explicit_field = 2;
  required string required_field = 3;
  repeated int32 expanded_ids = 4;
  optional group DelimitedField = 5 {
    optional int32 value = 1;
  }
  optional int32 with_default = 6 [default = 42];
  repeated int32 packed_ids = 7 [packed = true];
}
```

Note: `expanded_ids` carries no annotation — EXPANDED maps to unpacked, which
is already proto2's default for repeated scalars, so no annotation is needed.

The test compiles `editions_rendering.proto` with `protoc`, runs reproto with
`--force-proto2-output`, and compares the output against this golden file.  It
also asserts that recompiling the golden file with `protoc` succeeds (exit 0) —
this guards against Bug 1 recurring (invalid proto2 syntax would be caught
here).

---

## Reference documentation

Add `docs/editions-to-proto2.md` — a user-facing reference document describing
the complete editions → proto2 translation rules applied by
`--force-proto2-output`.  It must cover:

- The mapping for each `field_presence` value (`IMPLICIT`, `EXPLICIT`,
  `LEGACY_REQUIRED`) to proto2 labels.
- The mapping of `message_encoding = DELIMITED` to group syntax, including the
  group naming algorithm.
- The mapping of `repeated_field_encoding` (`PACKED`, `EXPANDED`) to
  `[packed = true/false]` annotations.
- Wire-transparent features that are dropped with a `// WARNING[editions]`
  comment (`utf8_validation`, `json_format`).
- The failure mode for untranslatable constructs (field orphaned, squashed log
  warning, exit 0).

This document must be linked from:
- `reproto/README.md` under the `--force-proto2-output` flag description.
- The reproto manpage (`docs/man/reproto.1` or equivalent) under the same flag.

---

## Files changed

- `reproto/src/reproto/syntax.py` — Bug 1 and Bug 3 fixes
- `reproto/src/reproto/re_field.py` — Bug 2: fresh group descriptor instantiation
- `reproto/src/reproto/re_descriptor.py` — Bug 2: group naming pass
- `reproto/src/reproto/tests/test_editions_rendering.py` — update T3, T5, T6;
  add T14
- `reproto/src/reproto/tests/fixtures/editions_rendering.proto` — add T8 PACKED field
- `reproto/src/reproto/tests/fixtures/editions_rendering.golden.proto` — add T8 field
- `reproto/src/reproto/tests/fixtures/editions_rendering.force_proto2.golden.proto`
  — new golden file
- `docs/editions-to-proto2.md` — new reference document
- `reproto/README.md` — link to reference document
- `docs/man/reproto.1` (or equivalent) — link to reference document
- `docs/specs/0072-editions-to-proto2.md` — this file
