<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0136 — protolens: status line shows the proto type of every field

Status: implemented
Implemented in: 2026-07-17
Refs: docs/specs/0114-protolens-tui.md (status line's original `type:
      {fqdn}` display, message/group only), docs/specs/0119-protolens-
      override-fidelity-and-workflow.md (`natural_type` fallback),
      docs/specs/0135-protolens-override-raw-tag-rewrap.md
      (`natural_type`'s primitive-`Kind` -> keyword mapping)
App: protolens

## Background

The status line (`render.rs`'s `render` method, bottom bar) currently
shows a `type: {fqdn}` fragment only for message/group nodes
(`node.span.type_fqdn`, populated only for message/group per
`NodeSpan`'s own doc comment) — a scalar leaf never shows its proto
type at all, even when the schema resolves one (e.g. a plain `int32`
field, or a field whose declared kind is an `enum`).

The user wants the proto type shown for *every* field when one is
resolvable — primitive, message, group, or enum alike — and nothing
shown when only wire-level typing is available (no schema, or an
unresolvable field).

## Goals

- G1: the status line always shows the field's *currently effective*
  proto type when one is resolvable, in place of today's message/
  group-only `type: {fqdn}` fragment.
- G2: primitive types (scalar, non-enum) display as a plain keyword,
  e.g. `type: int32` — no FQDN, no bracket tag.
- G3: message/group/enum types display as an FQDN, followed by a
  space and one of `[message]`, `[group]`, `[enum]`. A leading `.` is
  prepended only when omitting it would make the FQDN collide with a
  primitive keyword (see the collision-check set in the Specification
  below) — not unconditionally. This is expected to be rare in
  practice (e.g. a schema with a top-level, package-less message
  literally named `int32`); the common case (`pkg.Msg`, `Msg.Nested`,
  ...) shows no leading dot.
- G4: when no proto type is resolvable at all (only wire-level typing
  — e.g. an unresolved/unknown field, no descriptor set loaded, or a
  scalar leaf under an explicit "raw" override — see the pinned
  `<raw / no type>` override entry, spec 0118 §2), the status line
  shows nothing for the type fragment, exactly as today.
- G5: no color/styling change — the type fragment renders with the
  status line's existing default (unstyled) `Paragraph`, same as
  every other status-line fragment.

## Non-goals

- No change to the override selection pane's own type listing/
  candidate display (spec 0114 §3), the manage pane's entry listing
  (spec 0117 §3), or any other FQDN-formatted text elsewhere in the
  UI — this spec touches only the bottom status line.
- No change to `natural_type`'s own behavior (still excludes `Enum`,
  spec 0135's Non-goals, and remains the sole source of truth for
  override *splicing*) — the display-only helper this spec adds is a
  separate function; enum fields remain non-overridable via
  `:type-as`.
- No change to `NodeSpan::type_fqdn`'s population rules (still `None`
  for scalar fields) — this spec derives the scalar-leaf type label
  from existing schema/override-resolution helpers
  (`resolve_active_override`, `parent_field`) plus one new display-
  only helper, not by changing what `prototext-core` populates.
- No handling for the forward-looking "Empty" fake primitive type
  mentioned in review — per the user, `Empty` will translate to
  `None` in the main pane tree, so it needs no special case here.
  `Empty` (capitalized — message-type names, unlike primitive
  keywords, are capitalized) is reserved in the leading-dot
  collision-check set below purely so that a future top-level message
  literally named `Empty` won't visually collide with it. (Later
  amended: spec 0137 implemented this fake type under the name
  `Empty`, itself renamed to `None` per 2026-07-17 feedback — see the
  leading-dot collision check below, updated accordingly.)

## Specification

### Type-label resolution (new helper, e.g. `override_apply.rs` or
`render.rs`)

Unified rule for every node kind (primitive, message, group, enum
alike), matching the user's mental model: *look at the active
override; if none is active, look at the natural type (which may
itself be unresolvable — i.e. raw); render accordingly. An explicit
"raw" choice (active or natural) always means no label.*

For the node under the cursor (`self.tree[self.cursor]`):

1. If `span.is_message` is `true` (the node's *currently effective*
   type is already a message/group — `resettle_node` keeps
   `span.type_fqdn`/`is_message` in sync with the active override on
   every render pass, so no separate override lookup is needed here):
   - `span.type_fqdn` is always `Some(fqdn)` in this branch in
     practice (message/group nodes only reach the tree with a
     resolved type); label tag is `group` when `span.wire_type ==
     WT_START_GROUP`, else `message`.
2. Else (scalar leaf, `span.is_message == false`):
   - If `resolve_active_override(idx)` is `Some(inner)` (an override
     entry is active):
     - `inner == Some(keyword)`: label is the plain primitive
       `keyword` (G2). (An active override can only ever resolve to a
       primitive keyword here — never a message FQDN — since a
       message-targeted override would already have flipped
       `is_message` to `true`, caught by branch 1 above.)
     - `inner == None` (the pinned `<raw / no type>` entry is
       active): no label (G4).
   - Else (no active override at all): consult a new display-only
     helper, `natural_type_display(idx)` — identical to
     `natural_type(idx)`'s existing `parent_field(idx)?.kind()` match,
     *except* `Kind::Enum(desc) => Some(desc.full_name().to_string())`
     instead of `None` (the one deliberate difference from the real
     `natural_type`, which must stay untouched — see Non-goals):
     - `Some(keyword)` where `keyword` is one of the 15 primitive
       keywords: label is the plain keyword (G2).
     - `Some(fqdn)` where `fqdn` names a resolvable `EnumDescriptor`
       (looked up via `parent_field(idx).kind()` alongside the
       string, so the caller knows which case it is): label tag is
       `enum`.
     - `None` (no parent schema, field not declared): no label (G4).

### Leading-dot collision check

For any FQDN label (message/group/enum tag), prepend `.` only if the
bare `fqdn` string exactly equals one of the 15 primitive keywords
(`double`, `float`, `int32`, `int64`, `uint32`, `uint64`, `sint32`,
`sint64`, `fixed32`, `fixed64`, `sfixed32`, `sfixed64`, `bool`,
`string`, `bytes`) or the reserved `None` keyword (see Non-goals;
renamed from `Empty`, spec 0137 amendment).
Otherwise, no leading dot.

### `render.rs`

- Replace the current `type_label` computation (message/group-only,
  `node.type_fqdn`) with a call to the new helper above: `type:
  {label}` when a label is produced (`{keyword}` for a primitive,
  `{[.]fqdn} [{tag}]` for message/group/enum, one space before the
  bracket), empty string when no label — the surrounding status-line
  `format!` and its plain (unstyled) `Paragraph` rendering are
  otherwise unchanged (G5).

## Test plan

1. Cursor on a plain primitive scalar field (e.g. `int32`, no
   override active): status line shows `type: int32`.
2. Cursor on a message field: status line shows `type: pkg.Msg
   [message]` (no leading dot — no collision).
3. Cursor on a genuine wire-group field: status line shows `type:
   pkg.Msg [group]`.
4. Cursor on an enum-kind scalar field, no override active: status
   line shows `type: pkg.Color [enum]`.
5. Cursor on a scalar field actively overridden via `:type-as` to a
   different primitive (e.g. `int32` -> `fixed32`): status line
   reflects the override (`type: fixed32`), not the schema-declared
   type.
6. Cursor on a scalar field with the pinned `<raw / no type>` override
   entry active: status line shows no `type:` fragment.
7. Cursor on an unresolved/unknown field (no descriptor set, or a
   field not found in the schema): status line shows no `type:`
   fragment at all — same as an empty tree already handles via the
   "(empty — decoded to zero fields)" branch.
8. Cursor on a message/enum field whose bare (package-less) name
   collides with a primitive keyword (e.g. a top-level message named
   `int32`): status line shows `type: .int32 [message]`, with the
   leading dot.
9. `type:` fragment renders with default (unstyled) text in every
   case above — no color/bold applied.
10. `cargo fmt --check`, `reuse lint`, full test suite pass.
