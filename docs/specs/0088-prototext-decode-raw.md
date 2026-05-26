<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0088 — prototext decode --raw

**Status:** implemented
**Implemented in:** 2026-05-26
**App:** prototext

---

## Background

When `prototext decode` is given a binary protobuf without a `--type` flag it
runs auto-inference: it scores every type in the descriptor set and picks the
best match.  This is usually what the user wants, but there are two cases where
inference is unwanted:

1. **Demo / teaching context**: the presenter wants to show field numbers and
   wire types *before* introducing the schema, to demonstrate that the binary
   is opaque without a schema.  Today this is achieved by passing
   `--type google.protobuf.Empty`, which is an obscure trick that requires
   explanation and depends on `Empty` being present in the descriptor set.

2. **Diagnostic context**: the user suspects the schema DB is wrong and wants
   to see the raw wire structure regardless of what the scorer would pick.

The `--type google.protobuf.Empty` workaround is fragile (Empty must be in the
descriptor set) and confusing (audiences ask "why Empty?").

---

## Goals

1. Add a `--raw` flag to `prototext decode` that suppresses inference and type
   decoding entirely, rendering the binary as raw field-number / wire-type
   pairs.
2. `--raw` must not require a `--descriptor-set` to be present.
3. The output format must be valid proto-text that `prototext encode` can
   round-trip without loss.
4. Anomaly annotations (`-a`) must be compatible with `--raw`.

---

## Non-goals

- Changing the default inference behaviour.
- Outputting a schemaless JSON or hex representation.
- Implementing `--raw` for `prototext encode`.

---

## Specification

### CLI

```
prototext [--descriptor-set DESCRIPTOR] decode [--raw] [-a] [--type TYPE] FILE...
```

`--raw` and `--type` are mutually exclusive; passing both is an error.

`--raw` and `--descriptor-set` are independent; `--raw` does not require a
descriptor set and does not use one even if provided.

### Output format

With `--raw` the output uses field numbers as keys and wire-type suffixes as
type annotations, exactly as `prototext decode -a --type google.protobuf.Empty`
does today, but without requiring `Empty` to be in any descriptor set.

Example output for a two-field message:

```
1: "Frederic"      #@ len = 8
2: 42              #@ varint = 42
```

The rendering follows the existing anomaly-annotation format (spec 0024) so
that `prototext encode` can accept and round-trip the output.

### Built-in Empty type

As a complementary improvement, `google.protobuf.Empty` (and the minimal set
of WKTs required to parse it) should be available as built-in types in
`prototext decode` without a `--descriptor-set`, so that the existing
`--type google.protobuf.Empty` idiom continues to work for users who prefer
the explicit form.  This is a separate implementation task and may be tracked
independently.

---

## Implementation

### Core rendering

`prototext-core`'s `render_as_text(data, schema, opts)` already accepts
`schema: Option<&ParsedSchema>`.  When `None` is passed, `decode_and_render`
sets `root_desc = None` and `all_schemas = None`, and `render_message` renders
raw field-number / wire-type pairs.  This is the same schemaless path that
`prototext encode` uses internally (see `run.rs` lines 747/758).

**No changes to `prototext-core` are required.**

This is also why `--type google.protobuf.Empty` works today: `Empty` has no
fields, so `root_desc` carries no field descriptors and `render_message` falls
through to the same schemaless path.  `--raw` makes the intent explicit and
removes the dependency on `Empty` being present in the descriptor set.

### CLI changes (`prototext/src/lib.rs` or equivalent)

Add `--raw` as a boolean flag on the `decode` subcommand, mutually exclusive
with `--type`.

### `run_decode` changes (`prototext/src/run.rs`)

`run_decode` currently errors early if `type_name.is_none()` and no Hopcroft
graph is present:

```rust
return Err("schema DB is empty; cannot infer message type".into());
```

With `--raw`:

1. Bypass the `desc_ctx` requirement entirely — a `--descriptor-set` is not
   needed and should not be required.
2. Skip the `auto_infer` branch.
3. Call `process(data, true, assume_binary, None, annotations)` directly.

In code terms, the change is a guard at the top of `run_decode`:

```rust
if raw {
    // Schemaless path: render field numbers and wire types directly.
    for path in paths { /* read file, call process(..., None, ...) */ }
    return Ok(());
}
```

This keeps the existing auto-infer and `--type` paths entirely unchanged.

---

## Open questions

- Should `--raw` be the default when no `--descriptor-set` is provided and
  no `--type` is given?  Current behaviour: prototext uses its built-in WKT
  fallback descriptor.  Changing the default would be a breaking change;
  leave it as-is for now.
- Should nested `len`-delimited fields be recursively decoded (attempted parse
  as sub-messages) or shown as raw bytes?  Initial proposal: attempt recursive
  decode, same as the current Empty-based approach; fall back to raw bytes if
  the nested content is not valid proto wire format.
