<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0086 — Canonize file output paths via variant import rules

**Status:** implemented
**Implemented in:** 2026-05-25
**App:** reproto

---

## Background

reproto processes descriptor sets whose file names may differ from the
canonical proto import paths.  For example, the `google2` variant rewrites
`net/proto2/proto/descriptor.proto` → `google/protobuf/descriptor.proto`
via `variant_import_rules`.  This rewrite is already applied to **import
statements inside files** (via `canonize_dependency()`) so that the
rendered `.proto` text says `import "google/protobuf/descriptor.proto"`.

However, the **file's own output path** is not canonized: the `.proto`
file is written to `out_repo/net/proto2/proto/descriptor.proto`, not
`out_repo/google/protobuf/descriptor.proto`.  This creates three
inconsistencies:

1. **IDE navigation breaks**: VS Code (and other editors) follow import
   strings to find source files.  If a file says
   `import "google/protobuf/descriptor.proto"` but the file lives at
   `net/proto2/proto/descriptor.proto`, the editor cannot resolve it.

2. **Scoring-graph YAML path mismatch**: `--emit-scoring-yaml` writes
   `net/proto2/proto/descriptor.yaml` while the schema DB index
   (`index.rkyv`) is keyed by `google/protobuf/descriptor.proto`.
   `prototext decode` fails with:
   ```
   error: 'net/proto2/proto/descriptor.proto' not found in FDS index
   ```

3. **In-memory YAML mismatch**: the YAML strings collected for
   `--build-schema-db` reference the original file name, causing the
   Hopcroft graph to use names inconsistent with the index.

The root cause is the same in all three cases: `re_fdp.name` (the
original input name) is used as the output path, while
`canonize_dependency(ctx, name)` — which already exists and correctly
implements the variant rewrite rules — is only called on import
references, not on the file's own name.

---

## Goals

1. The `.proto` output file path is canonized: written to
   `out_repo / canonize_dependency(ctx, re_fdp.name)`.
2. The scoring-graph YAML output path (`--emit-scoring-yaml`) is
   canonized to match.
3. The in-memory YAML strings for `--build-schema-db` use the canonized
   name.
4. The pool lookup (which must use the original name, since the pool was
   built from the original descriptor set) is not changed.
5. All three outputs are consistent with each other and with the import
   strings inside rendered `.proto` files.

---

## Non-goals

- Changing the scoring-graph YAML format.
- Canonizing `re_fdp.name` on the node itself (the node's identity in
  `ctx.nodes` stays keyed by the original name).
- Handling the `--keep-descriptor-path` flag differently — that flag
  already prevents `canonize_dependency` from rewriting the descriptor
  path, so it will continue to work correctly.

---

## Root cause

`canonize_dependency(ctx, name)` in `mappings.py` implements the full
variant import-rule rewrite logic.  It is currently called only when
rendering import statements inside a file.  It should also be called
when determining the **output path** of a file.

---

## Specification

### §86.1 — Canonize `.proto` output path in phase 7

In `_phase7_output`, replace:

```python
path = Path(re_fdp.name)
res_path = out_repo / path
```

with:

```python
from .mappings import canonize_dependency
canonical_name = canonize_dependency(ctx, re_fdp.name)
res_path = out_repo / Path(canonical_name)
```

The pool lookup (`ctx.pool.FindFileByName(re_fdp.name)` elsewhere in the
phase) is **not** changed — the pool is keyed by the original name.

### §86.2 — Canonize scoring-graph YAML path in `_phase_emit_scoring_graphs`

In `_phase_emit_scoring_graphs`, replace:

```python
proto_name = re_file.name
...
yaml_path = out_dir / Path(proto_name).with_suffix('.yaml')
```

with:

```python
proto_name = re_file.name          # used for pool lookup
from .mappings import canonize_dependency
canonical_name = canonize_dependency(ctx, proto_name)
yaml_path = out_dir / Path(canonical_name).with_suffix('.yaml')
```

### §86.3 — Canonize in-memory YAML name in `_phase_build_schema_db`

The in-memory mirror in `_phase_build_schema_db` also derives the YAML
key from `re_file.name`.  Apply `canonize_dependency` to the name used
as the YAML file identifier / output key, so that the scoring-graph
YAML strings fed to `build_graph()` use the canonized name.

### §86.4 — `canonize_dependency` is already correct

`canonize_dependency` already handles:

- `--keep-descriptor-path`: returns the variant path unchanged when the
  flag is set.
- Files with no matching rule: returns the name unchanged (no regression
  for non-renaming variants).
- Multiple chained rules with `continue: true`.

No changes to `canonize_dependency` itself are needed.

---

## Example

With the `google2` variant and `net/proto2/proto/descriptor.proto`:

| | Before | After |
|---|---|---|
| Pool lookup key | `net/proto2/proto/descriptor.proto` | `net/proto2/proto/descriptor.proto` (unchanged) |
| `.proto` output path | `out/net/proto2/proto/descriptor.proto` | `out/google/protobuf/descriptor.proto` |
| YAML output path | `out/net/proto2/proto/descriptor.yaml` | `out/google/protobuf/descriptor.yaml` |
| Import string in other files | `google/protobuf/descriptor.proto` | `google/protobuf/descriptor.proto` (unchanged) |
| Index key | `google/protobuf/descriptor.proto` | `google/protobuf/descriptor.proto` (unchanged) |

All four outputs are now consistent.  VS Code can follow
`import "google/protobuf/descriptor.proto"` to the file at that path.

---

## Files changed

- `reproto/src/reproto/phases.py` — apply `canonize_dependency` to the
  output path in phase 7, in `_phase_emit_scoring_graphs`, and in the
  in-memory YAML collection in `_phase_build_schema_db`

---

## References

- Spec 0045 — `--emit-scoring-yaml` original specification
- Spec 0068 — FDS index (`index.rkyv`)
- Spec 0080 — schema DB WKT completion
- `reproto/src/reproto/mappings.py` — `canonize_dependency()`
