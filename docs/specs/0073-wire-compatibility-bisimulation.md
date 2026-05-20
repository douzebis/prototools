<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0073 — Wire-compatibility bisimulation test for --force-proto2-output

**Status:** idea
**App:** reproto

---

## Purpose

Spec 0072 added a golden regression test (T14) that compares reproto's
`--force-proto2-output` output against a checked-in expected file.  This
catches textual regressions but does not directly verify the core guarantee:
that the proto2 translation is **wire-compatible** with the original editions
schema.

The idea is to add a stronger, semantic test:

```
editions.proto --protoc--> 1.pb --reproto --force-proto2-output--> proto2.proto --protoc--> 2.pb
```

and assert that `1.pb` and `2.pb` are wire-equivalent — i.e. any binary
message decodable against schema 1 is also decodable against schema 2 with
identical field identification, and vice versa.

---

## Goals

1. Define a notion of **wire-compatibility** between two `FileDescriptorSet`
   protos that is computable without encoding any actual messages.

2. Implement a checker and integrate it into the T14 test (or a new T15).

3. The checker must catch regressions for the three bugs fixed in spec 0072:
   - Bug 2 (DELIMITED → group changes wire type 2→3/4).
   - Bug 3 (PACKED missing changes wire type for repeated scalars).
   - (Bug 1 — IMPLICIT label — is not a wire issue; it is out of scope.)

---

## Non-goals

- Full Hopcroft bisimulation over arbitrary cyclic schemas (nice-to-have;
  a visited-set guard is sufficient for acyclic schemas, which covers all
  practical cases).
- Checking semantic preservation beyond wire type (e.g. default values,
  JSON names, proto3 optional semantics).

---

## Sketch

### Wire-type derivation

Define `wire_type(field) -> int` using the same rules as the scorer:

| field.type                          | packed? | wire type |
|-------------------------------------|---------|-----------|
| BOOL, INT32, SINT32, UINT32, ENUM   | -       | 0 (VARINT)|
| INT64, SINT64, UINT64               | -       | 0         |
| FIXED32, SFIXED32, FLOAT            | -       | 5         |
| FIXED64, SFIXED64, DOUBLE           | -       | 1         |
| STRING, BYTES, MESSAGE              | -       | 2         |
| GROUP                               | -       | 3 (SGROUP)|
| repeated scalar (any above)         | packed  | 2         |

For editions descriptors, `packed` must be derived from
`features.repeated_field_encoding` (as in spec 0072 Bug 3).
For proto2 descriptors, `packed` comes from `options.packed`.

### Skeleton function

```python
def field_skeleton(desc, pool, visited=frozenset()):
    result = set()
    for field in desc.field:
        wt = wire_type(field)
        if field.type in (TYPE_MESSAGE, TYPE_GROUP) and field.type_name not in visited:
            child_desc = pool[field.type_name]
            child = field_skeleton(child_desc, pool, visited | {field.type_name})
        else:
            child = None  # scalar or cycle sentinel
        result.add((field.number, wt, child and frozenset(child)))
    return frozenset(result)
```

Two descriptors are wire-compatible iff their skeletons are equal.

### Open questions

- How to handle the `Inner` message that appears both as a standalone
  `message Inner { }` in the proto2 output and as the body of
  `group DelimitedField`?  The editions schema has `Inner` reachable as a
  standalone message type; the proto2 schema has it reachable both as a
  standalone message and as the group body.  Are these the same type for
  bisimulation purposes?  Probably yes — but needs careful thought.

- For the group case: `--force-proto2-output` emits
  `optional group DelimitedField = 5 { ... }` with wire type SGROUP (3),
  while the editions schema has `Inner delimited_field = 5` with wire type
  LENGTH_PREFIXED (2).  These are intentionally **different** wire types —
  that is the whole point of DELIMITED translation.  So the bisimulation
  must be defined over the **output** semantics, not the input ones.
  Concretely: recompile `proto2.proto` with protoc and check that the
  resulting descriptor encodes the group field with wire type SGROUP, which
  is what a proto2 decoder would use.  The check is then:
  "can a message encoded by a proto2 encoder for schema 2 be decoded by a
  proto2 decoder for schema 2?" — which is trivially true — rather than
  cross-schema compatibility.  The real cross-schema check would require an
  editions-aware encoder/decoder, which is out of scope.
  This open question may significantly narrow the scope of what
  bisimulation can usefully assert here.

---

## Files to change

- `reproto/src/reproto/tests/test_editions_rendering.py` — add T15.
- Possibly a new `reproto/src/reproto/wire_compat.py` helper.
