<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0087 — Strip unresolvable field type_names before pool_db.Add()

**Status:** implemented
**Implemented in:** 2026-05-25
**App:** reproto

---

## Background

reproto's phase 2 (`_phase2_build_pool`) merges `FileDescriptorProto` objects
into a protobuf descriptor pool (`pool_db`).  Before adding a file to the pool,
`_strip_unresolvable_dependencies` removes import entries whose targets are
either absent from the input or were pruned as duplicate-symbol files (spec
0053).  The stripped imports are recorded on the topo-layer `ReFile` so that
phase 3 can carry them to the `ReFileDescriptorProto` node for orphan rendering
as commented-out `import` lines (spec 0053 / `re_file.py`).

However, `_strip_unresolvable_dependencies` only strips the `dependency[]`
array — it does **not** strip field `type_name` references that point to types
defined in a pruned (or absent) file.  When `pool_db.Add(fdp)` is then called,
the C extension raises a `TypeError` because the referenced types are not yet
in the pool.  The pool silently drops the entire file.  The file is never added
to `ctx.nodes`, so phase 5's reachability marking can never include it, and it
is never written to the output.

### Concrete example

Pruning `file:google/rpc/status.proto` causes
`google/cloud/audit/audit_log.proto` to disappear from the output, even though
`audit_log.proto` was a requested seed target.  The reason is that
`audit_log.proto` has a field `status` of type `.google.rpc.Status`; once
`status.proto` is pruned, that field's `type_name` is unresolvable, and
`pool_db.Add()` raises a `TypeError` for `audit_log.proto`.

The correct behaviour is:

1. Strip the unresolvable field from the FDP before `pool_db.Add()`.
2. Record the stripped field so the rendered `.proto` includes a `///` orphan
   comment at the right position in the message body.
3. Also handle service method `input_type` / `output_type` for completeness.

---

## Goals

1. Introduce `_strip_unresolvable_field_types(ctx, topo_file, fdp)` — a new
   helper called immediately after `_strip_unresolvable_dependencies`, before
   every `pool_db.Add()` call.
2. The helper strips any field (in any message at any nesting level) whose
   `type_name` is not resolvable in `pool_db` at the time of the call.
3. Stripped fields are recorded per message on the topo-layer `ReFile`, keyed
   by message FQDN, so that phase 3 can dispatch them to the matching
   `ReDescriptorProto` node in `ctx.nodes`.
4. At render time, each `ReDescriptorProto` emits `///` orphan comments for
   its own `stripped_fields` at the **start of the field section** — after any
   nested type / enum definitions, just before the first real field.
5. Service methods whose `input_type` or `output_type` is unresolvable are
   handled analogously: stripped and dispatched to the matching
   `ReServiceDescriptorProto` node for orphan rendering at the start of the
   service body.
6. `pool_db.Add()` succeeds for files that previously failed solely because of
   unresolvable `type_name` references.

---

## Non-goals

- Placing each orphaned field at its exact original position within the field
  list (too complex; placing them at the start of the field section is
  sufficient).
- Stripping enum value references or option extension type names.
- Changing the existing orphan-import rendering behaviour (spec 0053).
- Fixing the case where an entire file cannot be added to the pool for reasons
  other than unresolvable `type_name` references (out of scope).

---

## Data structures

### `StrippedField`

A lightweight record of a field that was stripped from a `DescriptorProto`:

```python
@dataclass
class StrippedField:
    number: int       # field number
    name: str         # field name
    type_name: str    # original FQDN (e.g. ".google.rpc.Status")
    label: str        # "optional" / "repeated" / "required" — converted
                      # directly from FieldDescriptorProto.label (the raw
                      # wire-format int enum), with no proto2/proto3
                      # heuristics applied.  The orphan comment is a
                      # best-effort vestige, not a faithful reconstruction.
```

### `StrippedMethod`

A lightweight record of a service method that was stripped:

```python
@dataclass
class StrippedMethod:
    name: str         # method name
    input_type: str   # original FQDN
    output_type: str  # original FQDN
```

### On `ReFile` (topo layer, `topology.py`)

```python
# Keyed by message FQDN (e.g. ".google.cloud.audit.AuditLog")
stripped_field_types: dict[str, list[StrippedField]]
# Keyed by service FQDN (e.g. ".google.cloud.audit.AuditService")
stripped_method_types: dict[str, list[StrippedMethod]]
```

Both are initialized to empty dicts.  They are the accumulation point during
phase 2; phase 3 dispatches their contents to the relevant `Re*` nodes.

### On `ReDescriptorProto` (`re_descriptor.py`)

```python
stripped_fields: list[StrippedField]  # initialized to []
```

### On `ReServiceDescriptorProto` (`re_service.py`)

```python
stripped_methods: list[StrippedMethod]  # initialized to []
```

---

## Specification

### §87.1 — `_type_name_resolvable(pool_db, type_name) -> bool`

A small helper:

```python
def _type_name_resolvable(pool_db, type_name: str) -> bool:
    """Return True if type_name (e.g. '.pkg.Foo') resolves in pool_db."""
    if not type_name:
        return True  # primitive field — no type_name
    name = type_name.lstrip('.')
    try:
        pool_db.FindMessageTypeByName(name)
        return True
    except KeyError:
        pass
    try:
        pool_db.FindEnumTypeByName(name)
        return True
    except KeyError:
        return False
```

### §87.2 — `_strip_unresolvable_field_types(ctx, topo_file, fdp)`

Called immediately after `_strip_unresolvable_dependencies(ctx, topo_file, fdp)`
and before every `pool_db.Add(fdp)` call in `_phase2_build_pool`.

Algorithm:

1. Walk all `DescriptorProto` messages in `fdp` recursively, tracking the FQDN
   of each message (package + dotted name path, e.g.
   `.google.cloud.audit.AuditLog`).
2. For each message, collect fields whose `type_name` is set and is NOT
   resolvable via `_type_name_resolvable`.
3. For each such field, create a `StrippedField` record and append it to
   `topo_file.stripped_field_types[message_fqdn]`.
4. Remove the field from the message's `field` repeated list (in-place
   deletion).
5. Walk all `ServiceDescriptorProto` in `fdp`.  For each method whose
   `input_type` or `output_type` is not resolvable, create a `StrippedMethod`
   record, append it to `topo_file.stripped_method_types[service_fqdn]`, and
   remove the method from the service's `method` list.
6. If any fields or methods were stripped and `not ctx.quiet`, emit a warning
   (see §87.6).

### §87.3 — Phase 3: dispatch stripped records to Re* nodes

In `_phase3_build_graph`, after all `Re*` nodes have been created for the file,
iterate over the two dicts on the topo-layer `ReFile` and push records to the
matching nodes in `ctx.nodes`:

```python
from .re_descriptor import ReDescriptorProto
from .re_service import ReServiceDescriptorProto

for msg_fqdn, fields in topo_file.stripped_field_types.items():
    node_fqdn = ReDescriptorProto.fqdn_from_ref(Ref(msg_fqdn))
    node = ctx.find_node(node_fqdn)
    if isinstance(node, ReDescriptorProto):
        node.stripped_fields.extend(fields)

for svc_fqdn, methods in topo_file.stripped_method_types.items():
    node_fqdn = ReServiceDescriptorProto.fqdn_from_ref(Ref(svc_fqdn))
    node = ctx.find_node(node_fqdn)
    if isinstance(node, ReServiceDescriptorProto):
        node.stripped_methods.extend(methods)
```

Each node owns its own orphans directly — no dict lookup is needed at render
time, and `re_fdp` does not need to be threaded through the render call chain.

### §87.4 — Render orphans in `re_descriptor.py`

`ReDescriptorProto.render()` currently emits fields after nested enum and
message definitions.  The rendering order becomes:

1. Nested enum definitions (existing).
2. Nested message definitions (existing).
3. `///` orphan comments for `self.stripped_fields` (new).
4. Real fields (existing).

Each `StrippedField` produces one orphan comment line:

```
/// <label> <type_name> <name> = <number>;
```

For example:

```
/// optional .google.rpc.Status status = 2;
```

If `self.stripped_fields` is non-empty, a blank divider is appended after the
orphan block (mirroring how orphan imports are separated in `re_file.py`).

### §87.5 — Render orphans in `re_service.py`

`ReServiceDescriptorProto.render()` emits methods.  Stripped methods appear as
orphan comments at the start of the service body (before real methods):

```
/// rpc <name> (<input_type>) returns (<output_type>);
```

### §87.6 — Warning

When `_strip_unresolvable_field_types` strips at least one field or method,
emit a warning (unless `ctx.quiet`).  Use the next available W-code after W3
(check existing taxonomy in `phases.py` before assigning):

```
Warning: stripped N unresolvable field type(s) from <filename>: <field_name>, ...
```

---

## Call-site changes in `_phase2_build_pool`

Every `pool_db.Add(fdp)` call is preceded by both strip helpers:

```python
_strip_unresolvable_dependencies(ctx, n, fdp)
_strip_unresolvable_field_types(ctx, n, fdp)   # new
ctx.pool_db.Add(fdp)
```

The existing `except TypeError` handler remains as a last-resort safety net.

---

## Files changed

- `reproto/src/reproto/topology.py` — add `stripped_field_types`,
  `stripped_method_types` to `File` / `ReFile`.
- `reproto/src/reproto/phases.py` — add `_type_name_resolvable`,
  `_strip_unresolvable_field_types`; update both `pool_db.Add` call sites;
  update phase 3 to dispatch stripped records to `Re*` nodes.
- `reproto/src/reproto/re_descriptor.py` — add `stripped_fields: list[StrippedField]`;
  render orphan comments at start of field section.
- `reproto/src/reproto/re_service.py` — add `stripped_methods: list[StrippedMethod]`;
  render orphan comments at start of service body.

---

## Example output

Before this spec, pruning `file:google/rpc/status.proto` and seeding on
`google/cloud/audit/audit_log.proto` produces **no output** for
`audit_log.proto`.

After this spec, `audit_log.proto` is emitted with the `status` field replaced
by an orphan comment at the start of the field section:

```proto
message AuditLog {
  /// optional .google.rpc.Status status = 2;

  string service_name = 7;
  string method_name = 8;
  // ...
}
```

---

## References

- Spec 0053 — pruned duplicate-symbol files and orphan import rendering
- Spec 0074 — prune / seed glob patterns
- `reproto/src/reproto/phases.py` — `_strip_unresolvable_dependencies`,
  `_phase2_build_pool`
- `reproto/src/reproto/re_file.py` — `stripped_dependencies` / orphan import
  rendering
- `reproto/src/reproto/re_descriptor.py` — message field rendering
- `reproto/src/reproto/re_service.py` — service method rendering
