<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0118 — protolens recursive override-driven rendering

Status: implemented
Implemented in: 2026-07-14
Refs: docs/specs/0097-raw-recursive-lendel.md,
      docs/specs/0114-protolens-range-type-override.md,
      docs/specs/0116-tree-sitter-textproto-highlight-captures.md,
      docs/specs/0117-protolens-override-collection.md
App: protolens

This started as a preliminary capture of a design discussion, written
down before it was fully settled. The design questions raised along the
way (the demotion gap, `NodeSpan::wire_type`) are now resolved — see §8
for the two remaining items, both explicitly deferred to implementation
time as non-blocking. Sections below reflect the settled design; treat
this as ready for the normal spec workflow (implement only Goals +
Specification, skip Non-goals) rather than a further round of design
discussion.

## Background

Spec 0117 built `OverrideCollection` (three kinds — `path` > `path-field`
> `fqdn-field`, decreasing priority) and a management UI, but explicitly
deferred wiring it into rendering (0117 Non-goals): only spec 0114 §5's
original one-shot `apply_override` (a single splice, triggered by `Enter`
in the override selection pane, on exactly the node under the cursor)
actually changes what's displayed. `path-field`/`fqdn-field` overrides —
whose entire purpose is to apply wherever a path/field or type/field
combination recurs, potentially at unbounded depth and in many places at
once — are currently recorded but inert.

This spec defines the rendering algorithm that consumes the *whole*
`OverrideCollection` recursively, replacing the single-node
`apply_override` codepath with a general one that discovers and applies
every matching override, at any depth, whenever the active override set
changes.

## Goals

- A recursive rendering function that, starting from the document root,
  determines each visitable node's applicable override (if any, by
  kind priority) and splices in a fresh render wherever one applies —
  reaching every depth, not just immediate children of the root.
- One uniform splice mechanic covering every target-shape change —
  retype, promotion, and demotion alike: no existing rendering (header,
  interior, or footer) is ever reused verbatim; the whole node is always
  regenerated as a freshly rendered field block. This is a deliberate
  simplification over an earlier draft that special-cased "already
  message-shaped, retyped to another message type" to reuse existing
  brace lines — that reuse was the root cause of task #34 (a stale `#@`
  type annotation surviving a retype); always regenerating fixes it as
  a byproduct, for every node, not just the root.
- Correctly detect a demotion (an override that used to apply to a
  node no longer applies) across repeated render passes, not just
  promotions/retypes — via per-node provenance tracking (§2.1).
- A caching design for the underlying `(range, type) -> IndexedText`
  decode step that stays a pure, override-collection-*oblivious*
  function — no versioning/epoch bookkeeping — matching
  `render_cache.rs`'s existing invariant ("no invalidation beyond
  ordinary MRU eviction needed, since a cached entry's key is tied to
  immutable input").
- Trigger the recursive pass on any change to the *active* override set
  (activate/deactivate/add-that-activates/remove-of-an-active-entry/
  restore-overrides) — not on every collection mutation (e.g. adding an
  inactive candidate doesn't trigger a re-render).
- Preserve as much App state as possible across a re-render pass (fold
  state, cursor position, scroll position) by extending the existing
  pointer-based incremental splice/orphan mechanism
  (`apply_override`/`collect_descendants`) rather than rebuilding
  `self.tree`/`self.lines` wholesale.

## Non-goals

- Optimizing the walk to skip unaffected subtrees when only a `path` or
  `path-field` override changed (whose affected scope is statically
  known, unlike `fqdn-field`). v1 always does a full walk on any
  active-set change; scoping the walk is left to a future spec if it
  proves necessary.
- Undo/redo of collection edits (already a 0117 non-goal, unchanged).
- Any change to `OverrideCollection`'s own data model, sorting, YAML
  format, or management-pane UI (spec 0117, unchanged).
- A user-visible trigger or indicator for the recursive pass — it is an
  internal consequence of override-collection mutations, not a new key
  binding or command.
- Wildcard/regex/range-based override origins (already excluded by
  0117).

## Specification

### §1 Root type resolution and initialization

Initialization changes from "decode once under the CLI/inferred root
type" (current `decode()`) to:

1. Decode the whole (wrapped) blob once in raw mode (`root_desc: None`).
   Per spec 0097, raw-mode decoding of unknown `LEN` fields already
   recursively probes them as nested messages wherever the bytes
   structurally parse as one, unbounded depth — so this initial render
   already has real (not flat) tree structure wherever that heuristic
   succeeds, before any override is considered.
2. Call the recursive render function (§3) on the root node.

The root's own override is whatever `OverrideCollection` resolves for
origin `Path { path: "/" }` — seeded at startup exactly as spec 0117 §1
already defines (from `--type`/inference, or none). No separate
CLI-driven decode path is needed any more; root-type resolution is just
"look up the root's active override," same as every other node.

### §2 Per-node override resolution

```rust
/// Resolves to the type (or `None` = raw) that should currently be
/// used to render `idx`'s payload, per the priority `Path >
/// PathField > FqdnField` (spec 0117), or `None` (no active override
/// applies — leave `idx` exactly as currently rendered).
fn resolve_active_override(&self, idx: usize) -> Option<Option<String>> {
    // Path: exact positional_path(idx) match.
    // PathField: parent's positional_path + idx's own field_number.
    // FqdnField: parent's type_fqdn + idx's own field_number.
    // Only ACTIVE entries are considered (at most one active entry
    // per origin, per spec 0117's invariant).
}
```

The outer `Option` distinguishes "no override found" (don't touch this
node) from "override found, whose type is `None`" (override found,
explicitly re-render as raw) — these are different outcomes.

No decoding is required to evaluate this per node: `positional_path`,
`TreeNode::parent`, `span.type_fqdn`, and `span.field_number` are all
already available on the existing tree, so this is a cheap, pure,
in-memory check.

### §2.1 Provenance (`TreeNode::rendered_as`)

Each `TreeNode` carries one extra field:

```rust
/// Which override (if any) currently produced this node's rendering —
/// `resolve_active_override`'s own return shape, but recorded at the
/// time of the *last* splice rather than freshly resolved: outer
/// `None` = never spliced by an override (still whatever the initial
/// raw decode, or an ancestor's splice, produced); `Some(None)` =
/// last spliced explicitly as raw; `Some(Some(fqdn))` = last spliced
/// under `fqdn`. Compared against a freshly resolved
/// `resolve_active_override(idx)` on every `render` pass (§3) to tell
/// "never touched" apart from "was touched, no longer applies" — see
/// §8's Demotion item for why this is needed.
rendered_as: Option<Option<String>>,
```

A freshly spliced-in node (§4/§7 — orphaned old descendants, appended
new subtree) starts with `rendered_as` set to whatever `target_type`
its own splice was performed under; every other field on `TreeNode`
(`parent`/`first_child`/etc.) is populated exactly as `apply_override`
already does today.

### §3 Recursive render function

```rust
fn render(&mut self, idx: usize) {
    let target = self.resolve_active_override(idx);
    if target != self.tree[idx].rendered_as {
        self.splice_override(idx, target.clone()); // §4
        self.tree[idx].rendered_as = target;
    }
    // Walk idx's current children — whichever they are: freshly
    // spliced in by the call just above, or inherited unchanged from
    // whatever produced idx's existing rendering (the initial raw
    // decode, or an ancestor's own override splice). Recurse only
    // into nodes that could possibly carry a nested override.
    let mut child = self.tree[idx].first_child;
    while let Some(c) = child {
        if matches!(self.wire_type_of(c), WT_LEN | WT_START_GROUP) {
            self.render(c);
        }
        child = self.tree[c].next_sibling;
    }
}
```

The comparison against `rendered_as` (§2.1) — rather than the original
`if let Some(target_type) = ...` — is what makes this correct across
repeated passes, not just the first one: it turns "is there an
override right now?" into "does what's-there still match what
should-be-there?", so a node whose override has been deactivated since
the last pass (`rendered_as: Some(Some(t))`, freshly resolved `target:
None`) is detected as needing a re-splice back to raw, not silently
skipped. See §8's Demotion item.

Two cases require no special-casing, falling out of the structure
above for free:

- A `VARINT`/`FIXED32`/`FIXED64` scalar is never recursed into — the
  `wire_type_of` guard filters it before the recursive call.
- A `LEN` node currently rendered as a scalar string/bytes (no override
  matching it) has `first_child: None` — the `while` loop body simply
  never executes for it. No explicit "early return" branch is needed.

This also means a non-overridden ancestor never blocks discovery of a
deeper override: the walk always continues into `LEN`/`GROUP` children
regardless of whether the current node itself had a match, so a
`fqdn-field` override several levels below an untouched ancestor is
still found and applied.

### §4 Splice mechanics

`splice_override(idx, target: Option<String>)` — `target` is the
resolved override's *type* (already unwrapped: §3 only calls this once
it has established `target != rendered_as`, i.e. that `idx` does need
re-splicing; the outer "should this even be touched" `Option` from §2
has already been consumed by that point). `None` means revert to raw;
`Some(new_type)` means retype/promote to `new_type`.

One case, always: there is no existing rendering of `idx` — header,
interior, or footer, whatever `idx`'s current shape happens to be —
that's safe to reuse. Generalize the existing `register_wrapper`/
`wrap_blob` machinery (spec 0114 §1.1, currently hardcoded to field
number `1` for the document root) to accept `idx`'s *real*
`field_number` and an `Option<&str>` type: wrap `idx`'s payload bytes
with a real tag+length for that field number
(`wrap_blob(field_number, payload)`), then call
`decode_and_render_indexed` on the wrapped bytes under `Some(wrapper)`
(a synthetic one-field message declaring `field_number` as `new_type`,
built by `register_wrapper`) when `target` is `Some(new_type)`, or
under `None` (no schema at all) when `target` is `None`. The `None`
case is exactly how the very first raw render at startup (§1) treats
every field before any override applies — the same unknown-field
cascade (message probe → UTF-8 string → bytes, spec 0097) — so a
demoted node ends up rendered exactly as if it had never been
overridden, not by any bespoke "collapse" logic.

Either way this produces a complete, correctly-labeled field rendering
(name/number, `#@` wire-type-and-short-type-name annotation, and
opening brace/interior/closing brace *only if the result is
message-shaped*) using the real renderer — no hand-rolled string
formatting, no annotation drift, and critically, no staleness: every
line of `idx`'s rendering (including its own header/footer) is freshly
generated on every splice, retype included. This fixes task #34 (a
stale `#@` type annotation surviving a retype) as a byproduct, for
every node — not just the document root, where the bug was originally
noticed. The *entire* old rendering of `idx` — one line or a whole
brace block, whichever it was — is replaced by this whole block; `idx`
keeps its own tree-array identity (so `cursor`/`folded`/back-jump state
referencing it stays valid), only its `span` (is_message/type_fqdn/
wire_type, per the freshly decoded root node) and its children (old
ones orphaned via `collect_descendants`, exactly as `apply_override`
already does — new ones appended and stitched in, same mechanism) are
replaced.

This goes through the render-cache lookup (§5) for the actual
`decode_and_render_indexed` call, keyed the same way `apply_override`
already keys it: `(payload_range, target)`.

### §5 Caching

`render_cache.rs`'s existing `RenderCache` (spec 0116 §8) is reused
**unchanged**: key `(Range<usize>, Option<String>)`, value `(Vec<String>,
Vec<NodeSpan>, Vec<StyleHint>)`. It remains a pure memo of "decode these
bytes under this type," computed *before* any override-driven splicing
of its own descendants happens — that splicing is performed by `render`
(§3) on `self.tree`/`self.lines` after the cache lookup returns, and is
entirely outside the cache's knowledge. Two calls with the same `(range,
type)` key always produce the same cached value regardless of what the
current override collection looks like, because the cache's value never
encodes anything about descendant overrides. No epoch/version key, no
invalidation beyond the existing byte-budget MRU eviction.

### §6 Trigger conditions

The recursive pass (`render(root_idx)`) re-runs whenever a mutation
changes the *active* override set:

- `Enter` in the override selection pane (creates/reactivates an
  override and activates it — spec 0117 §2).
- `a` in the management pane, when it activates an entry (and,
  transitively, deactivates whatever previously shared its origin).
- `a` in the management pane, when it deactivates the entry that was
  active for its origin (net effect: that origin now has no active
  override).
- `Delete`/`Backspace` in the management pane, when the removed entry
  was active.
- `:restore-overrides`, unconditionally (replaces the collection
  wholesale).

Mutations that do *not* change the active set (e.g. adding a new,
inactive candidate entry for an origin that already has a different
active entry) do not trigger a re-render.

### §7 State preservation

A re-render pass must not be a wholesale rebuild of `self.tree`/
`self.lines`/`self.folded`/cursor/scroll position — that would discard
fold state and cursor/scroll position for the entire document on every
override toggle, most of which affect a small, localized part of the
tree. Instead, `render` (§3) is a generalization of `apply_override`'s
existing mechanism: each `splice_override` call (§4) is the same
pointer-based incremental splice `apply_override` already performs
today (old descendants orphaned via `collect_descendants` and scrubbed
from `self.folded`, not removed — `Vec` indices of every *unrelated*
node stay stable; the new subtree is appended at the end of `self.tree`
and stitched into the `doc_next`/`doc_prev` chain). Applying this
per-match across the whole tree, rather than once per keypress, is the
only structural change — the splice primitive itself is unchanged.
`rendered_as` (§2.1) is set on `idx` immediately after each
`splice_override` call, and every freshly spliced-in descendant starts
with its own `rendered_as: None` (untouched by any override yet, same
as any node produced by the initial raw decode) — no separate
bookkeeping pass needed.

### §8 Open items

- **`NodeSpan::wire_type`** — RESOLVED: `pub wire_type: u32` added to
  `NodeSpan` (`prototext-core/src/serialize/render_text/sink.rs`),
  populated by `IndexingTextSink` at decode time: derived from
  `ScalarValue`'s variant for `scalar_field` (each packed element gets
  its *own* wire type, from the field's declared `Kind`, not the
  packed record's outer `WT_LEN`), from `NestedKind` for `begin_nested`,
  and hardcoded to `WT_LEN` for `begin_virtual_nested` (Any/MessageSet
  wrapper nodes — always message-shaped, so the exact value only
  matters for the `WT_LEN | WT_START_GROUP` recursion-eligibility
  check, which either value satisfies).
- **Demotion** — RESOLVED (design). Was bigger than a missing splice
  case: it's *not* a flaw in the recursive algorithm itself (§1-§3),
  which is override-collection-oblivious and stateless by construction
  — given a range and freshly resolved overrides, it always computes
  the one correct rendering. The gap was entirely a consequence of §7's
  *incremental* re-render strategy: reusing `self.tree`/`self.lines`
  and splicing only where an override currently applies (instead of
  discarding and rebuilding from a fresh raw decode every pass) means a
  node's *current* shape can be leftover from a previous pass's splice,
  and the original `if let Some(target_type) = resolve_active_override
  (idx)` check had no way to distinguish that ("was touched, no longer
  applies") from "never touched" — both read as `None`. (If every pass
  instead started from scratch, there would be no demotion problem at
  all — but that would give up §7's whole point, preserving fold/
  cursor/scroll state across a toggle.) Resolved by per-node
  provenance tracking, `TreeNode::rendered_as` (§2.1): `render` (§3)
  now compares the *freshly resolved* override against what actually
  produced the node's current rendering, not just whether one currently
  exists — so a deactivated override is detected and re-spliced back to
  raw, not silently skipped. Reverting to raw is folded into the single
  unified `target: Option<String>` splice mechanic (§4), not a bespoke
  "collapse" case: `target: None` renders `idx` under no schema at all
  (a plain `decode_and_render_indexed` call with `root_desc: None`),
  going through the same unknown-field cascade that produced the
  original raw render at startup, so a demoted node ends up looking
  exactly as if it had never been overridden (message-shaped or
  scalar-shaped, whichever the cascade decides — not necessarily the
  same shape it had before).
- **Generalizing `register_wrapper`/`wrap_blob`**: confirm the exact
  shape of the generalization (arbitrary `field_number` parameter, an
  `Option<&str>` type covering both the retype/promote case and the
  revert-to-raw case per §4's unification, presumably a
  per-`(field_number, target_fqdn_or_none)` cache-or-reuse of
  registered wrapper descriptors mirroring today's per-root-type reuse)
  once implementation starts.
- **Performance ceiling for `fqdn-field`-triggered full walks**: v1
  deliberately does not optimize this (Non-goals); no numbers exist yet
  for how large a document/how deep a schema this remains acceptable
  for. Revisit if it becomes a practical problem.
- **`line_to_node` rebuild cost**: confirmed non-issue for correctness
  — today's `apply_override` already does a full `line_to_node` clear +
  rebuild (walking the doc chain) after every splice, so it can never
  go stale. But it's an `O(tree size)` rebuild per splice; the
  recursive design (§3/§7) does many splices per active-set change
  instead of one, so a `fqdn-field` override matching at many nodes
  could make this rebuild dominate. Not a blocker (Non-goals already
  defers walk/perf optimization), but worth a single rebuild-at-the-end
  of the whole `render(root_idx)` pass rather than one per splice, if
  it turns out to matter in practice.

## Files changed (anticipated)

| File | Change |
|---|---|
| `protolens/src/decode.rs` | Initialization changes to raw-mode decode + `render(root_idx)`; `register_wrapper`/`wrap_blob` generalized to accept a field number and `Option<&str>` type; `TreeNode::rendered_as` (§2.1) added |
| `protolens/src/tui.rs` | `resolve_active_override`, recursive `render`/`splice_override` (replacing `apply_override` with the unified always-regenerate mechanic, §4 — fixes task #34 as a byproduct), wiring the §6 trigger conditions into every active-set-changing key/command handler |
| `protolens/src/override_pane.rs` | Possibly: a helper exposing "active entry for this origin" lookups by parent-path/parent-fqdn+field, if not already convenient from `OverrideCollection::entries()` |
| `prototext-core/src/serialize/render_text/sink.rs` | `NodeSpan::wire_type` (§8, resolved and implemented) |
