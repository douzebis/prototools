<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0119 — protolens override fidelity and manage-pane workflow

Status: implemented (2026-07-14)
Refs: docs/specs/0114-protolens-range-type-override.md,
      docs/specs/0117-protolens-override-collection.md,
      docs/specs/0118-protolens-recursive-override-rendering.md
App: protolens

## Background

Spec 0118 generalized the single-node override splice (`splice_override`,
originally 0114 §1.1's document-root-only trick) to any node, by wrapping
the node's own payload as the sole field of a synthetic one-field message
and re-decoding it. That generalization surfaced two fidelity gaps and
motivated two workflow requests, all four collected here because they
share the same underlying mechanics (`splice_override`'s synthetic
wrapper, and the `OverrideEntry`/management-pane pair):

1. Deactivating a more specific override falls back to raw bytes instead
   of the node's natural inherited type.
2. The synthetic wrapper's sole field is unconditionally named `"root"`,
   which leaks into the rendered output and clobbers the node's real
   field name.
3. The override selection pane's `Enter` action closes the pane outright;
   the user would rather it hand off directly to the management pane.
4. There is no way to give an overridden field a custom display name
   (independent from its real field name or its `"root"` placeholder).

This is a **draft** — none of the four items below have started
implementation. Each has open design questions flagged inline; the intent
is to settle those through review before writing any code.

## Goals

- G1: deactivating (or never having) an active override on a node makes
  that node fall back to whatever type it would have had from its
  parent's schema, not to raw/unparsed bytes — raw rendering should only
  ever happen when there is genuinely no type information available at
  all (no active override, and no resolvable parent-schema field type).
- G2: `splice_override`'s synthetic wrapper field is named after the
  node's real field name whenever it's resolvable (from the parent's
  schema), instead of being unconditionally hardcoded to `"root"`.
- G3: pressing `Enter` in the override selection pane, after creating/
  activating an override, opens the override management pane with the
  just-affected entry highlighted, instead of just closing the pane.
- G4: an `OverrideEntry` can carry an optional user-supplied display name,
  editable from the management pane, shown next to the entry's type in
  the management pane's listing, and round-tripped through the YAML
  save/restore format.

## Non-goals

- Renaming/aliasing *unresolved* fields (no parent schema, no field name
  available at all) — G2 only addresses fields whose real name **is**
  resolvable; genuinely-unresolvable fields (and the true document root)
  fall back to the field number as a string instead (see G2).
- Any change to `path`/`path-field`/`fqdn-field` override *origin*
  semantics (0117 §1) — G4's name is a purely cosmetic, orthogonal
  per-entry attribute, not a new origin/scoping mechanism.
- Editing a node's real (schema-declared) field name — G4 is a display
  override, not a schema mutation; nothing about the underlying protobuf
  descriptor changes.

## Specification

### G1 — Natural-type fallback on override deactivation

**Status:** Implemented (2026-07-14)

**Root cause** (`protolens/src/tui.rs`): `render_overrides`/
`splice_override` treat "no active override entry matches this node"
(`resolve_active_override(idx) == None`) exactly the same as "an active
override entry explicitly says raw" (`resolve_active_override(idx) ==
Some(None)`) — both end up calling `splice_override(idx, None)`, which
means "decode with no schema at all," i.e. hard-coded raw. The former
case should instead mean "inherit whatever type this node would
naturally have had," which is not necessarily raw.

**Proposed design**: a new `natural_type(idx) -> Option<String>` helper:
if `idx`'s parent has a resolved `type_fqdn`, look up `idx`'s
`field_number` in the parent's `MessageDescriptor` via `prost_reflect`
(`get_field(number)` → `FieldDescriptor::kind()` → `Kind::Message(desc)`
gives the field's declared message type; a non-message kind, or a lookup
miss, yields `None`); if the parent has no resolved type, `natural_type`
is `None` too. The effective per-node type becomes:

```
match resolve_active_override(idx) {
    Some(explicit) => explicit,   // an active entry exists: honor it, incl. explicit "raw"
    None           => natural_type(idx),  // no active entry: inherit from parent's schema
}
```

This flattens `resolve_active_override`'s current `Option<Option<String>>`
return shape's consumption at the one call site that matters
(`render_overrides`) — worth checking whether `TreeNode::rendered_as`
(currently `Option<Option<String>>`, per spec 0118's provenance-tracking
design) can simplify back to a flat `Option<String>` once this lands,
since the outer-`Option` "was there an active entry at all" bit stops
being load-bearing once `natural_type` correctly captures "no override →
inherit, not raw." This simplification is **not required** for G1 itself
and could be deferred/dropped if it turns out to complicate anything
else spec 0118 built on the current shape.

**Confirming trace (the reported "hysteresis")**: deactivating `/1` alone
reverts it to raw, as expected from the root cause above — but
deactivating `/1`, then also deactivating `/` (root), then reactivating
`/` again, ends up rendering `/1` *correctly* (its natural type). This
looked at first like a second, deeper bug, but it's actually the same
root cause manifesting differently depending on *which* node gets
re-spliced:

- Deactivating `/1` alone re-splices only `/1` itself:
  `splice_override(idx, target.clone().flatten())` with `target == None`
  → `flatten()` → `None` → decode with no schema at all → raw. This is
  the direct manifestation of the bug.
- Deactivating, then reactivating, `/` (root) re-splices the *root*
  instead: `splice_override(root, Some(root_type))`. `splice_override`
  always performs a genuine recursive decode of the wrapped bytes under
  `root_type`'s real schema (`decode_and_render_indexed`, not a manual
  reconstruction) — so every descendant, including `/1`, is *freshly
  rendered from scratch under its real, schema-derived type* as a
  byproduct of the root splice, complete with brand-new `TreeNode`
  entries (`rendered_as: None`, per `splice_override`'s "abandon in
  place, push fresh" pattern). `render_overrides`'s subsequent recursion
  into these fresh children finds `resolve_active_override(new `/1`
  idx) == None` (no active entry) matches `rendered_as == None`
  (freshly initialized) — no mismatch, no further splice — so the
  correct, naturally-decoded rendering `decode_and_render_indexed`
  already produced is left untouched.

In other words: today, a node only renders "naturally" when it happens
to be freshly created as a side effect of an *ancestor's* splice: This
is exactly the gap `natural_type` closes — it makes `/1`'s own direct
deactivation path compute the same "natural" answer the ancestor-splice
path already gets by accident, rather than requiring a raw round trip.
No separate fix is needed beyond G1's `natural_type` design; the
ancestor-splice case will also keep working the same way it does today
(it never hits the `None`-target/raw path to begin with, since it starts
from a resolvable `Some(root_type)`).

### G2 — Preserve the real field name in overridden rendering

**Status:** Implemented (2026-07-14)

**Root cause** (`protolens/src/decode.rs`, `register_wrapper`): the
synthetic wrapper's sole `FieldDescriptorProto` always has `name:
Some("root".to_string())` (line 362), regardless of which node is being
wrapped. This is correct/intentional for `decode()`'s own document-root
wrapper (field number `1`, called from `decode.rs:412` — there genuinely
is no "real" field name at the true top level, `"root"` is a reasonable
synthetic label there), but wrong for `splice_override`'s per-node
wrapper (`tui.rs:1347`), where `idx` already has a real field, and the
synthetic wrapper's header line ends up literally reading `root: { ... }`
in place of the field's actual name.

**Proposed design**: give `register_wrapper` an explicit field-name
parameter instead of hardcoding `"root"`:

```rust
pub(crate) fn register_wrapper(
    pool: &mut DescriptorPool,
    field_number: u64,
    field_name: &str,
    target_desc: &MessageDescriptor,
) -> Result<MessageDescriptor, DecodeError>
```

- `decode.rs:412` (document root) switches from the hardcoded `"root"`
  to `"0"` — field number `0` is not a valid protobuf field number, which
  makes it a fitting sentinel for "this is the synthetic top-level
  wrapper, not a real field." This is a **behavior change** from today's
  `"root"` label.
- `splice_override` (`tui.rs:1347`) resolves the real name the same way
  G1's `natural_type` resolves the real *type*: via the parent's
  `MessageDescriptor::get_field(field_number)` → `FieldDescriptor::name()`
  — same lookup, same failure mode (no parent schema / lookup miss).
  When resolvable, pass the real name. When not resolvable, fall back to
  the field number as a string (e.g. `"2"`) — consistent with the
  document-root case above, and safe because protobuf field names can
  never be all-digits.
- **Correction found during implementation**: the wrapper's *message* name
  (`Wrapper_<field_number>_<fqdn>`) must also fold in `field_name`, not
  just `field_number`+`target_fqdn` — two different nodes can share the
  same field number and override target while having different real
  field names (e.g. field 1 named differently in two distinct parent
  messages). Without `field_name` in the registration key,
  `pool.get_message_by_name` would return the first-registered
  descriptor unchanged on the second call, silently reusing the wrong
  field name. (`splice_override`'s separate render-cache key,
  `(payload_range, target)`, is unaffected by this — `payload_range` is a
  byte offset into the document and is unique per node, so it can't
  collide across different `idx`s the way the pool-registration name
  could.)
- G1 and G2 share the exact same "look up this field on the parent's
  schema" lookup — worth factoring into one shared helper (e.g. returning
  the whole `FieldDescriptor`, from which both the type and the name are
  read) rather than two separate near-duplicate lookups.
- **Follow-up (2026-07-14, post-implementation feedback)**: the `"0"`
  sentinel itself turned out to be visually awkward once seen rendered
  (`0 {  #@ ... = 1`) — the document root has no real field name at all,
  so showing *any* placeholder token for it is worse than showing none.
  Fixed by stripping the literal `"0 "` prefix from the root's own
  rendered header line, in both `decode.rs`'s `decode()` (the initial
  paint) and `tui.rs`'s `splice_override` (any subsequent root retype) —
  done at the full-text level, before line-splitting/colorizing, so
  `NodeSpan::text_range`'s line-indexing (not byte-indexing, spec 0110)
  can't be desynced by shortening line 0 in place. `field_name_for`
  itself still returns `"0"` internally (used for cache keys and
  `rendered_as` provenance tracking) — only the final displayed text is
  stripped, and only for the true document root (`parent.is_none()`),
  not for a MessageSet/`Any` virtual container node (which also has
  `field_number: 0` per spec 0110's `NodeSpan` doc, but a real parent).

### G3 — `Enter` in the override selection pane opens the management pane

**Status:** Implemented (2026-07-14)

Today, `handle_override_key`'s `Enter` arm (`tui.rs:1633-1672`) creates/
activates the override, calls `render_overrides`, then
`self.close_override()`. Change the last step: instead of closing the
pane outright, call `toggle_manage_pane()`-equivalent logic to open the
management pane, with `manage_highlight` set to the index of the entry
that was just created/reactivated.

- Finding the target index: `OverrideCollection::activate` doesn't
  currently return the new/reactivated entry's index (it just mutates
  and re-sorts in place) — after `self.overrides.activate(origin,
  new_fqdn)`, look it up via `self.overrides.entries().iter().position(|e|
  e.origin == origin && e.r#type == new_fqdn)` (same origin/type pair
  just activated; unambiguous since `activate` guarantees at most one
  entry per origin is active, and this is the one).
- `close_override()`'s existing cleanup (candidate cache bookkeeping,
  clearing `override_inferred_raw`/`override_candidates_complete`/
  `override_target`/`override_focus`/`override_search`) still needs to
  run — this change only affects what happens *after* that cleanup, not
  whether it happens.

### G4 — Per-entry name override in the management pane

**Status:** Implemented (2026-07-14)

- **Implementation as built**: as designed above, plus one addition
  surfaced during implementation — `name` feeds into the *rendered
  text* itself (via `register_wrapper`'s field name), so it had to
  become part of two staleness-detection keys that previously keyed
  only on the resolved type: `TreeNode::rendered_as` (the
  `render_overrides` re-splice gate) widened from `Option<Option<
  String>>` to `Option<(Option<Option<String>>, String)>` (type,
  field name), and `RenderCache`'s key (`render_cache.rs`) widened
  from `(Range<usize>, Option<String>)` to `(Range<usize>,
  Option<String>, String)`. Without this, renaming an active entry
  from the management pane would silently fail to re-render (stale
  `rendered_as` match), and even a forced re-splice would hit a
  stale cache entry keyed on the old name. No explicit cache
  invalidation was needed beyond widening the key: a stale entry
  simply stops being looked up and is evicted later by ordinary MRU
  pressure. `OverrideCollection`'s own entry identity (used by
  `activate`'s find-or-create) deliberately stayed `(origin, type)` —
  `rename` is a direct in-place mutation via a new `rename(idx,
  name)` method, not a remove-and-recreate; `name` is not part of an
  entry's identity.

**Data model** (`protolens/src/override_pane.rs`): `OverrideEntry` gains
a new field:

```rust
pub struct OverrideEntry {
    pub origin: OverrideOrigin,
    pub r#type: Option<String>,
    pub active: bool,
    pub name: Option<String>,   // new: display-name override; None = keep real/default name
}
```

**Management pane key binding**: `e` (chosen to avoid colliding with the
pre-existing `n` "repeat last search" binding, `tui.rs:1735-1739`) in
`handle_manage_key` opens an inline text-entry prompt, pre-filled with
the highlighted entry's current `name` (empty if `None`), edited the
same way the existing command line already handles single-line text
editing. Confirming with `Enter` sets the entry's `name` to
`Some(buffer)` if non-empty, or `None` if the buffer was left empty
("keep the default"); `Esc` cancels without changing anything.

- **Display**: `manage_type_line` (`tui.rs:946-951`) currently renders
  `"  {marker} {type_label}"`. Extend to append the name, when set, to
  the right of the type — e.g. `"  {marker} {type_label}  as \"{name}\""`
  (exact separator/wording TBD).
- **Where the name takes effect**: both. It's shown/edited in the
  management pane's listing (above), and it also feeds into rendering —
  consumed at the same site G2 resolves the real field name, taking
  priority over the schema-derived real name when set. G2's
  fallback-to-real-name path becomes a fallback-to-*this*-name-if-set,
  else-real-name, else-field-number path.
- **YAML** (`protolens/src/override_pane.rs`'s `YamlEntry`/`to_yaml`/
  `from_yaml`): each of the three `YamlEntry` variants (`Path`,
  `PathField`, `FqdnField`) gains a `name: Option<String>` field,
  `#[serde(default, skip_serializing_if = "Option::is_none")]` (matching
  the existing `active` field's "only show up when non-default"
  convention, since most entries won't have a custom name).

## Open Issues

- G1/G2's `natural_type`/real-name lookups are proposed but not yet
  reviewed — flagging that `prost_reflect`'s `FieldDescriptor` API shape
  (`get_field`, `kind()`, `name()`) has only been confirmed by reading
  existing call sites elsewhere in the codebase, not re-verified against
  the crate docs for this exact use.
- G3: no open design questions identified — mechanism is a
  straightforward extension of the existing `toggle_manage_pane`/
  `close_override` plumbing.

## Files changed (anticipated)

- `protolens/src/decode.rs` — `register_wrapper` signature (new
  `field_name` parameter), one new call-site update in `decode()`.
- `protolens/src/tui.rs` — `render_overrides`/`splice_override` (G1's
  `natural_type` fallback and threading the real field name through to
  `register_wrapper`), `handle_override_key`'s `Enter` arm (G3),
  `handle_manage_key`'s new `e` arm (G4), `manage_type_line`
  (G4 display).
- `protolens/src/override_pane.rs` — `OverrideEntry`/`YamlEntry` (G4's
  new `name` field), `to_yaml`/`from_yaml` (G4 round-trip).
