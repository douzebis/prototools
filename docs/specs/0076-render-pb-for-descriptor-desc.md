<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0076 — Semantically-correct FDP binary rendering for descriptor.desc

**Status:** draft
**App:** reproto

---

## Background

`reproto --build-schema-db` writes a `descriptor.desc` file (a
`FileDescriptorSet`) that `prototext` uses via prost-reflect to decode/encode
proto instances.  When the input corpus contains editions files, the current
`--prost-workaround` flag performs a shallow patch: it clears the `syntax` and
`edition` fields from the raw FDP but leaves all `FeatureSet` entries in place.
This silences the prost-reflect crash but produces an FDP that is structurally
inconsistent: the metadata says proto2 but field-level features still encode
editions semantics, so prost-reflect will misinterpret wire-format for any
field using a non-default feature (`LEGACY_REQUIRED`, `DELIMITED`,
`EXPANDED`, `IMPLICIT`).

Furthermore, the shallow patch is opt-in (`--prost-workaround`), creating a
foot-gun: users who forget the flag get a crash at runtime.

This spec replaces the shallow patch with a semantically-correct binary
rendering path that mirrors the existing text rendering path, and renames
`--prost-workaround` to `--force-proto2-for-editions` to better describe what
the flag actually does.

---

## Goals

1. Extend each `Re*` class's existing `render()` method with an optional
   binary output side-channel via `ctx.out_desc: DescOut | None`.  When set,
   `render()` additionally populates `ctx.out_desc.out` with the corresponding
   protobuf descriptor object, applying the same pruning, orphaning, summoning,
   and editions→proto2 translation decisions as the text path.  Binary output
   is thus always consistent with the rendered `.proto` text.
2. Use this binary side-channel unconditionally for all binary output paths —
   both `--emit-binary` (per-file `.pb` files in phase 7) and
   `--build-schema-db` (`descriptor.desc`). These are the only two binary
   output paths in reproto.
3. Rename `--prost-workaround` to `--force-proto2-for-editions`. The old name
   was misleading (implies a prost bug rather than a missing feature) and
   opaque (does not describe the transformation). The new name is symmetric
   with `--force-proto2-output`:
   - `--force-proto2-output` — all files → proto2 output
   - `--force-proto2-for-editions` — editions files → proto2 output only
   `--force-proto2-output` is a superset: if set, `--force-proto2-for-editions`
   is redundant but harmless.
4. `--force-proto2-for-editions` remains an explicit opt-in for rendering mode
   (written `.proto` files and `--emit-binary`). `--build-schema-db` forces it
   unconditionally: `descriptor.desc` is intended for consumption by
   prost-reflect, which does not yet support editions syntax (upstream PR
   #1347). Leaving editions FDPs untranslated in `descriptor.desc` would cause
   a runtime crash in prost-reflect, making the output unusable. This forced
   behaviour is guarded behind an `EDITIONS_COMPAT_REQUIRED = True` constant
   so it can be lifted in one place when prost-reflect gains editions support.

---

## Non-goals

- Adding a separate `render_pb()` method hierarchy — the design extends the
  existing `render()` path instead.
- Perfectly round-tripping source code info or comments — those are not
  meaningful in a binary descriptor.

---

## Architecture

### Key design principle: single render() call, dual output

The editions→proto2 translation logic must not be duplicated. Rather than
adding a parallel `render_pb()` method hierarchy, the existing `render()`
methods are extended with an optional binary output side-channel via
`ctx.out_desc: DescOut | None`.

`DescOut` is a minimal dataclass acting as a typed output slot — a second
return value without changing the `render()` signature:

```python
@dataclass
class DescOut:
    out: Message | None = None
```

When `ctx.out_desc` is `None`, `render()` behaves exactly as today (text
only). When `ctx.out_desc` is a `DescOut` instance, `render()` *also*
populates `ctx.out_desc.out` with the corresponding protobuf descriptor
object. An empty `DescOut` (`.out is None`) after the call means the node
produced no binary descriptor (e.g. a text-only construct like an anomaly
comment).

The caller creates a fresh `DescOut` before each recursive `render()` call
on a node that has a descriptor counterpart, reads `.out` after, and
assembles the parent descriptor. Accumulation into a `FileDescriptorSet` is
done entirely at the top-level caller — never inside `render()` itself.

```
Context  (target_syntax, force_proto2_for_editions, out_desc: DescOut | None, …)
    │
    ├─ shared:  _resolve_field_features()
    │           field_label()  packed_option()  should_render_default()  …
    │           _set_target_syntax()   ← extracted from render(), called once
    │
ReFileDescriptorProto.render(ctx)  →  (Block, Block)
    │  if ctx.out_desc: ctx.out_desc.out = FileDescriptorProto(…)
    │
    ├── ReDescriptorProto.render(ctx)
    │       if ctx.out_desc: ctx.out_desc.out = DescriptorProto(…)
    │       │
    │       └── ReFieldDescriptorProto.render(ctx)
    │               if ctx.out_desc: ctx.out_desc.out = FieldDescriptorProto(…)
    │               (label, type, packed, features — same helpers as text path)
    │
    ├── ReEnumDescriptorProto.render(ctx)
    │       if ctx.out_desc: ctx.out_desc.out = EnumDescriptorProto(…)
    │       └── ReEnumValueDescriptorProto.render(ctx)
    │               if ctx.out_desc: ctx.out_desc.out = EnumValueDescriptorProto(…)
    │
    └── ReServiceDescriptorProto.render(ctx)
            if ctx.out_desc: ctx.out_desc.out = ServiceDescriptorProto(…)
            └── ReMethodDescriptorProto.render(ctx)
                    if ctx.out_desc: ctx.out_desc.out = MethodDescriptorProto(…)
```

**Concrete illustration — field label translation:**

The `field_label()` helper is called once, its result used by both output
paths within the same `render()` call:

```python
label_str = field_label(ctx, self.this, is_oneof, features=field_features)
string += label_str                          # text path: append to string

if ctx.out_desc is not None:
    out_field = FieldDescriptorProto()
    out_field.label = field_label_enum(ctx, self.this, is_oneof, features=field_features)
    # … other binary fields …
    ctx.out_desc.out = out_field             # binary path: populate slot
```

`field_label_enum()` is a new helper in `syntax.py` that shares all the
decision logic of `field_label()` but returns the `FieldDescriptorProto.Label`
integer constant directly (e.g. `LABEL_REQUIRED`) rather than a string.  No
reverse-mapping from strings is needed.  The SDK already provides
`FieldDescriptorProto.LABEL_OPTIONAL`, `LABEL_REQUIRED`, `LABEL_REPEATED` as
named constants.

The same principle applies to `should_render_default` and the `target_syntax`
guard for features stripping: the boolean result already computed for the text
path is reused directly in the binary block.

For `packed_option`: the text path calls `packed_option()` to get a string
annotation; the binary path does **not** call `packed_option()` — it reuses
the `effective_packed` boolean (already computed just above in `re_field.py`)
directly as `options.packed = effective_packed`.  The `packed_option()` string
is an artefact of text rendering; the binary path needs the boolean, which is
already available.

**`_set_target_syntax()` — factoring out the one remaining duplication:**

The `target_syntax` selection logic at the top of `render()` is extracted
into a shared method on `ReFileDescriptorProto`:

```python
def _set_target_syntax(self, ctx: Context) -> None:
    ctx.syntax = fdp_syntax(self.this)
    if ctx.force_proto2_output:
        ctx.target_syntax = "proto2"
    elif ctx.force_proto2_for_editions and ctx.syntax == "editions":
        ctx.target_syntax = "proto2"
    elif ctx.syntax in ("proto2", "proto3", "editions"):
        ctx.target_syntax = ctx.syntax
    else:
        ctx.target_syntax = "proto2"
```

Both the text and binary paths call `self._set_target_syntax(ctx)` — but
since they share the same `render()` method, it is called exactly once per
file regardless.

### On not using the `#@ prototext:` round-trip

Rejected because:
- It would introduce a dependency on the prototext encoder inside reproto's
  binary output path.
- Float/double/bytes literal formatting in textproto has edge cases (NaN,
  Inf, octal escapes) that the direct descriptor approach avoids entirely.
- It would add a separate textproto-of-FDP rendering layer orthogonal to
  the existing `.proto` text renderer — more duplication, not less.

---

## Specification

### 1. Rename `--prost-workaround` → `--force-proto2-for-editions`

In `cli.py`:
- Rename the `@click.option` declaration and update its help text.
- Update the `_SECTIONS` dict key from `'--prost-workaround'` to
  `'--force-proto2-for-editions'` (controls help section grouping).
- Rename the `prost_workaround` parameter in `main()`.
- The old `--prost-workaround` name may be kept as a hidden alias for one
  release cycle to avoid breaking existing scripts.

In `context.py`: rename `prost_workaround` → `force_proto2_for_editions` in
the `Options` dataclass.

In `re_file.py` and `phases.py`: update all references to the renamed field.

### 2. `EDITIONS_COMPAT_REQUIRED` constant (`phases.py`)

```python
# prost-reflect does not yet support editions (upstream PR #1347).
# Set to False and remove guarded block once support is added.
EDITIONS_COMPAT_REQUIRED = True
```

### 3. `DescOut` dataclass (`context.py` or `base.py`)

```python
from __future__ import annotations
from dataclasses import dataclass, field
from google.protobuf.message import Message

@dataclass
class DescOut:
    out: Message | None = None
```

A `DescOut` instance is a typed output slot: a lightweight object (no hash
table) used to return the binary descriptor counterpart of a `render()` call
without changing any method signature.

Convention: if `out is None` after a `render()` call with `ctx.out_desc` set,
the node produced no binary descriptor (e.g. a text-only construct).

### 4. `ctx.out_desc` field (`context.py`)

```python
out_desc: DescOut | None = None
```

When `None` (the default): `render()` behaves exactly as today — text output
only. When set to a `DescOut` instance: `render()` additionally populates
`ctx.out_desc.out` with the corresponding protobuf descriptor object.

The caller is responsible for:
1. Creating a fresh `DescOut()` before each `render()` call where binary
   output is wanted.
2. Setting `ctx.out_desc` to that instance before the call.
3. Reading `ctx.out_desc.out` after the call.
4. Restoring `ctx.out_desc = None` after the call.

Only nodes that have a direct descriptor counterpart are called with
`ctx.out_desc` set. Text-only constructs (anomaly comments, orphan lines,
`Block` formatting) are never called with `ctx.out_desc` set and never
populate it.

### 5. Binary output additions to each `Re*` class

Each `Re*` class that has a descriptor counterpart gains a guarded block
inside its existing `render()` method. The guarded block runs only when
`ctx.out_desc is not None`.

**Copying options:** throughout this section, "copies `options`" means
`new_msg.options.CopyFrom(self.this.options)`, guarded by
`if self.this.HasField('options')`. `CopyFrom()` is the standard protobuf
deep-copy; direct assignment of composite fields is not supported in the
Python protobuf API.

**`ReFileDescriptorProto.render(ctx)`** — the `_set_target_syntax()` call
already sets `ctx.target_syntax` for both paths. The binary block:

- Constructs a fresh `FileDescriptorProto`.
- Copies `name`, `package`, `dependency`, `public_dependency`,
  `weak_dependency`.
- Sets `syntax`/`edition` fields per `ctx.target_syntax` (proto2: leave
  unset; proto3: set `"proto3"`; editions: copy as-is).
- Copies `options`; if `ctx.target_syntax != "editions"`, calls
  `ClearField("features")` on the copied options.
- For each summoned child node, calls `render()` with a fresh `DescOut` slot,
  reads the result, and appends to the appropriate repeated field
  (`message_type`, `enum_type`, `service`, `extension`).
- Does **not** copy `source_code_info`.
- Sets `ctx.out_desc.out = fdp`.

**`ReDescriptorProto.render(ctx)`** — binary block:

- Constructs a fresh `DescriptorProto`, copies `name`, `reserved_range`,
  `reserved_name`, `extension_range`.
- Copies `options`; if `ctx.target_syntax != "editions"`, calls
  `ClearField("features")` on the copied options.
- For each field, nested type, enum, extension, oneof: calls `render()` with
  a fresh `DescOut` slot and appends the result.
- Map-entry synthetic `nested_type` entries are included as-is (needed for
  correct map wire decoding).
- Sets `ctx.out_desc.out = msg`.

**`ReFieldDescriptorProto.render(ctx)`** — the main translation site.
The `field_label()`, `packed_option()`, `should_render_default()` calls
already run for the text path; the binary block reads their results:

- Constructs a fresh `FieldDescriptorProto`.
- Copies `name`, `number`, `type_name`, `extendee`, `json_name`.
- **Label**: calls `field_label_enum()` (new helper in `syntax.py`, same
  logic as `field_label()` but returns the SDK integer constant).
- **Type**: copies `self.this.type`; for editions `DELIMITED` + proto2
  target, substitutes `TYPE_GROUP`.
- **Packed**: writes `effective_packed` (already computed) to
  `options.packed`.
- **Default value**: copies `default_value` if `should_render_default()`
  (already evaluated).
- Copies all field options; if `ctx.target_syntax != "editions"`, calls
  `ClearField("features")` on the copied options.
- Sets `ctx.out_desc.out = field_proto`.

**`ReEnumDescriptorProto.render(ctx)`** / **`ReEnumValueDescriptorProto.render(ctx)`**:

- Copy `self.this` fields; if `ctx.target_syntax != "editions"`, call
  `ClearField("features")` on the copied options.
- Set `ctx.out_desc.out`.

**Oneof binary output (inline in `ReDescriptorProto.render(ctx)`):**

There is no separate `ReOneofDescriptorProto` class — oneofs are rendered
inline inside `ReDescriptorProto.render()`. The binary block there handles
oneofs: for each `oneof_decl` entry, construct a fresh `OneofDescriptorProto`,
copy `name` and `options`; if `ctx.target_syntax != "editions"`, call
`ClearField("features")` on the copied options; append to `msg.oneof_decl`.

**`ReServiceDescriptorProto.render(ctx)`** / **`ReMethodDescriptorProto.render(ctx)`**:

- Copy all fields from `self.this`; if `ctx.target_syntax != "editions"`,
  call `ClearField("features")` on the copied options.
- Set `ctx.out_desc.out`.

### 6. Replace `--emit-binary` passthrough with `ctx.out_desc` (`phases.py`)

The current `ctx.binary` branch in `_phase7_output` does a raw pool
passthrough *before* the `render()` call for the text path:

```python
# BEFORE — raw passthrough, no translation (pool FDP, not render() output):
file_descriptor = ctx.pool.FindFileByName(re_fdp.name)
fd_proto = FileDescriptorProto()
file_descriptor.CopyToProto(fd_proto)
content = fd_proto.SerializeToString()
# ... then separately: content_text = re_fdp.render(ctx)[0].flush(ctx)
```

Replace with a single `render()` call that produces both outputs:

```python
# AFTER — binary output from the same render() call as the text path:
slot = DescOut()
ctx.out_desc = slot
content_text = re_fdp.render(ctx)[0].flush(ctx)
ctx.out_desc = None
fd_proto = slot.out
content_binary = fd_proto.SerializeToString()
```

This ensures `--emit-binary` output is consistent with the rendered `.proto`
text for all inputs. There is no separate passthrough path.

Note: the `.pb` file write that currently precedes `render()` moves to after
it — the order within a single file's processing changes from
(binary-write, text-render, text-write) to (render-both, binary-write,
text-write). This has no observable effect on correctness.

### 7. Replace shallow patch in `_phase_build_schema_db` with `ctx.out_desc`

Current shallow patch (opt-in, semantically incorrect):

```python
if ctx.prost_workaround:
    for fdp in fds.file:
        if fdp.syntax == "editions":
            fdp.ClearField("syntax")
            fdp.ClearField("edition")
            _clear_features(fdp)
```

Replace with `render()` + `ctx.out_desc`, unconditional for all files.
When `EDITIONS_COMPAT_REQUIRED` is true, editions files are forced to proto2
via a temporary context override:

```python
# EDITIONS_COMPAT_REQUIRED: remove forced override once prost-reflect supports editions.
fds = FileDescriptorSet()
for raw_fdp in ctx.pool_db_fdps:   # topological order preserved
    re_fdp = ctx.find_file(raw_fdp.name)
    if re_fdp is None or not re_fdp.is_summoned:
        continue
    syntax = fdp_syntax(re_fdp.this)
    saved_force = ctx.force_proto2_for_editions
    if EDITIONS_COMPAT_REQUIRED and syntax == "editions":
        ctx.force_proto2_for_editions = True
    slot = DescOut()
    ctx.out_desc = slot
    re_fdp.render(ctx)   # text output discarded; binary output in slot
    ctx.out_desc = None
    ctx.force_proto2_for_editions = saved_force
    if slot.out is not None:
        fds.file.append(slot.out)
```

The iteration basis is `ctx.pool_db_fdps` (raw FDPs in topological insertion
order), not `ctx.nodes.values()` — the current code already uses
`ctx.pool_db_fdps` for building the `FileDescriptorSet`, so this preserves
the existing topological ordering that prost-reflect requires.

`_clear_features()` becomes dead code and is removed.

The `render()` call returns `(Block, Block)` which is discarded — pyright
will accept this silently since the return value is not assigned.

### 8. Context changes (`context.py`)

- `prost_workaround` renamed to `force_proto2_for_editions` in the `Options`
  dataclass and all references.
- `out_desc: DescOut | None = None` added as an instance attribute in
  `Context.__init__()`, alongside the existing runtime state attributes
  (`syntax`, `target_syntax`, `current_file`, …).  It is **not** a field on
  the `Options` dataclass — `Options` holds CLI-level configuration, while
  `out_desc` is per-render transient state.

No new context manager is needed. Callers save and restore context fields
directly (see §6 and §7 pseudocode).

---

## Files changed

| File | Change |
|---|---|
| `reproto/src/reproto/context.py` | Add `DescOut` dataclass; add `out_desc` field; rename `prost_workaround` → `force_proto2_for_editions` |
| `reproto/src/reproto/cli.py` | Rename `--prost-workaround` → `--force-proto2-for-editions` (keep old name as hidden alias) |
| `reproto/src/reproto/syntax.py` | Add `field_label_enum()` helper |
| `reproto/src/reproto/phases.py` | Add `EDITIONS_COMPAT_REQUIRED`; replace `--emit-binary` passthrough with `ctx.out_desc`; replace shallow patch in `_phase_build_schema_db` with `ctx.out_desc`; remove `_clear_features()` |
| `reproto/src/reproto/re_file.py` | Add `_set_target_syntax()`; add binary output block to `render()`; update `prost_workaround` references |
| `reproto/src/reproto/re_descriptor.py` | Add binary output block to `render()` (including oneof handling) |
| `reproto/src/reproto/re_field.py` | Add binary output block to `render()` — main translation site |
| `reproto/src/reproto/re_enum.py` | Add binary output block to `render()` |
| `reproto/src/reproto/re_enum_value.py` | Add binary output block to `render()` |
| `reproto/src/reproto/re_service.py` | Add binary output block to `render()` |
| `reproto/src/reproto/re_method.py` | Add binary output block to `render()` |

---

## Testing

### Strategy

Implementation proceeds incrementally. After each `Re*` class gains its binary
block, the existing `.proto` regression tests are re-run to confirm the text
path is unaffected.

### Regression guard (existing tests)

All existing tests pass unchanged. The `out_desc` field defaults to `None`, so
all current `render()` call sites are unaffected.

### New unit tests — binary output correctness

For editions inputs (the primary concern):

- `LEGACY_REQUIRED` field → `LABEL_REQUIRED` in output FDP.
- `DELIMITED` field → `TYPE_GROUP` in output FDP.
- `EXPANDED` repeated field → `options.packed = false` in output FDP.
- `IMPLICIT` field → `LABEL_OPTIONAL` in output FDP.
- No residual `features` entries anywhere in the output FDP when
  `target_syntax == "proto2"`.

For proto2/proto3 inputs: binary output is structurally equivalent to the raw
pool passthrough (same fields, modulo `source_code_info` which is intentionally
omitted).

### `--emit-binary` regression tests

Three cases are handled differently based on whether syntax translation occurs.

**Case 1 — no translation (proto2, proto3, editions without forced downconversion)**

Reuse the existing `_run_roundtrip` harness infrastructure, substituting
reproto's `emit.pb` for the protoc-recompiled `new.pb` in the comparison:

```
orig.pb  →(reproto --emit-binary)→  new.proto + emit.pb
check: orig.pb ≡ emit.pb  (field-level diff via pb_diff_fields,
                            allowing source_code_info)
```

`source_code_info` is intentionally omitted by reproto; no other fields
should differ for faithful inputs.

**Case 2 — proto3→proto2 (`--force-proto2-output`)**

The binary output is intentionally different from the input; `orig.pb ≡ emit.pb`
would always fail.  Use golden `.pb` fixtures instead, mirroring the T14
golden test for the `.proto` text path:

```
orig.pb  →(reproto --emit-binary --force-proto2-output)→  emit.pb
check: emit.pb ≡ golden.pb  (field-level diff)
```

The golden `.pb` file is produced once by running the test, verifying the
output manually, and checking it into `tests/fixtures/`.

**Case 3 — editions→proto2 (`--force-proto2-for-editions`)**

Same golden approach as case 2.  The fixture must exercise the four
non-default features: `LEGACY_REQUIRED`, `DELIMITED`, `EXPANDED`, `IMPLICIT`.
The golden `.pb` verifies specific translation decisions:

- `LEGACY_REQUIRED` field → `LABEL_REQUIRED`, no `features`.
- `DELIMITED` field → `TYPE_GROUP`, no `features`.
- `EXPANDED` repeated scalar → `options.packed = false`, no `features`.
- `IMPLICIT` field → `LABEL_OPTIONAL`, no `features`.

The `editions_rendering.proto` fixture already covers all four cases and can
serve as the input; the golden `.pb` is produced from its expected
`--force-proto2-for-editions` output.

### `--build-schema-db` integration test

Build `descriptor.desc` from a corpus containing editions files **without**
`--force-proto2-for-editions`; verify prost-reflect loads it without panic
(editions→proto2 applied unconditionally by `EDITIONS_COMPAT_REQUIRED`).

---

## Implementation plan

Implementation proceeds in the following ordered steps.  After each step that
touches a `render()` method, the full test suite is run to confirm the text
path is unaffected before moving to the next step.

**Step 1 — Rename `--prost-workaround` → `--force-proto2-for-editions`**

Files: `context.py`, `cli.py`, `re_file.py`, `phases.py`.  Purely mechanical
rename with no logic change.  Run full test suite.

**Step 2 — Add `DescOut` dataclass and `ctx.out_desc` field**

Files: `context.py`.  Add `DescOut` with `out: Message | None = None`; add
`out_desc: DescOut | None = None` to `Context.__init__`.  No behaviour change
(field is always `None` at this point).  Run full test suite.

**Step 3 — Add `field_label_enum()` to `syntax.py`**

Files: `syntax.py`.  New helper with the same decision logic as `field_label()`
but returns `FieldDescriptorProto.LABEL_*` integer constants.  Add unit tests
mirroring the existing T1–T4 tests for `field_label()`.  Run full test suite.

**Step 4 — `ReFileDescriptorProto`: extract `_set_target_syntax()`, add binary block**

Files: `re_file.py`.  Extract `_set_target_syntax()` from `render()` (no
logic change to the text path).  Add binary block at the end of `render()`:
construct `FileDescriptorProto`, fill scalar fields, copy options with
conditional `ClearField("features")`, iterate summoned children with fresh
`DescOut` slots.  Run full test suite.

**Step 5 — `ReDescriptorProto`: add binary block (including oneofs)**

Files: `re_descriptor.py`.  Add binary block to `render()`: construct
`DescriptorProto`, copy scalar fields and options, iterate fields/nested
types/enums/extensions with fresh `DescOut` slots, handle `oneof_decl`
inline.  Run full test suite.

**Step 6 — `ReFieldDescriptorProto`: add binary block**

Files: `re_field.py`.  Add binary block to `render()`: construct
`FieldDescriptorProto`, set label via `field_label_enum()`, copy type (with
DELIMITED→TYPE_GROUP substitution), set packed from `effective_packed`, copy
default_value if `should_render_default()`, copy options with conditional
`ClearField("features")`.  This is the most complex step.  Run full test suite.

**Step 7 — `ReEnumDescriptorProto` + `ReEnumValueDescriptorProto`: add binary blocks**

Files: `re_enum.py`, `re_enum_value.py`.  Straightforward field copies.
Run full test suite.

**Step 8 — `ReServiceDescriptorProto` + `ReMethodDescriptorProto`: add binary blocks**

Files: `re_service.py`, `re_method.py`.  Straightforward field copies.
Run full test suite.

**Step 9 — Wire up `--emit-binary` in `_phase7_output`**

Files: `phases.py`.  Replace raw pool passthrough with the single `render()`
call that populates both text and binary outputs.  Add `EDITIONS_COMPAT_REQUIRED`
constant.  Run full test suite including `--emit-binary` paths.

**Step 10 — Replace shallow patch in `_phase_build_schema_db`; remove `_clear_features()`**

Files: `phases.py`.  Replace the `ctx.prost_workaround` block with the
`ctx.pool_db_fdps`-based loop using `ctx.out_desc`.  Remove `_clear_features()`.
Run full test suite.

**Step 11 — Write new tests**

Add unit tests for binary output correctness (editions translations) and
`--emit-binary` regression test per the Testing section above.

---

## Future removal (when prost-reflect supports editions)

1. Set `EDITIONS_COMPAT_REQUIRED = False` in `phases.py`.
2. The forced `ctx.force_proto2_for_editions = True` override in
   `_phase_build_schema_db` becomes a no-op — editions FDPs pass through
   `render()` without forced proto2 translation, preserving their editions
   semantics in `descriptor.desc`.
3. The binary output block in `render()` remains in place and is still called
   unconditionally for all binary output. It is correct for proto2, proto3,
   and editions inputs.
4. `--force-proto2-for-editions` remains available as a user opt-in for
   rendering mode, for users who need proto2-compatible output regardless of
   prost-reflect support.

---

## Implemented in

<!-- filled in after implementation -->
