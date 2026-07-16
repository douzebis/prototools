<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# Asset: the document tree

*last verified: 2026-07-16*

## Executive summary

The document tree is protolens's own navigation structure, built once
over the flat list of fields `prototext_core` decoded and then kept
alive — and selectively rebuilt — for the rest of the session as the user
applies overrides. Two properties define almost everything about how it
behaves: nodes are stored in **post-order**, not document order, so a
parallel document-order chain is maintained explicitly; and an override
never rebuilds the whole tree, only **splices** the one affected subtree
in place. Understanding these two properties up front makes the rest of
the tree's code read as consequences rather than arbitrary choices.

## Technical detail

### Post-order storage, explicit document-order chain

`prototext_core::decode_and_render_indexed` returns its flat `NodeSpan`
list in post-order (a container's own entry comes *after* all of its
descendants) — a natural consequence of how a recursive-descent decoder
finishes a subtree before it can know that subtree's own final extent.
protolens's `build_tree` does not fight this; it accepts post-order as the
array's native layout (array index has no navigational meaning) and
separately threads a `doc_next`/`doc_prev` linked chain, sorted by each
node's actual `raw_range.start`, purely for document-order traversal.
Every "move to next/previous node" operation in the UI walks this chain,
never the array. `build_tree` itself is a single linear pass using a
stack of "subtree roots still being completed," an approach chosen
because it matches the post-order input directly rather than requiring a
second pass to reconstruct parent/child relationships.

### The splice: the tree's one mutation primitive

Once built, the tree is never rebuilt wholesale in response to an
override — that would invalidate every index a live UI element (cursor,
fold set, jumplist, override-collection origin) might be holding.
Instead, `splice_override` replaces exactly one node's own rendering and
descendants, in place, leaving that node's own array index — and every
untouched node's index — unchanged. Concretely, applying an override to
node `idx`:

1. Re-wraps `idx`'s payload bytes under the new target type (or leaves
   them unwrapped for a "raw" target) and decodes that in isolation —
   the same [synthetic-wrapper trick](target-blob.md) used for the whole
   document, applied locally.
2. Builds a small local tree over just that decode, and appends its
   nodes to the *end* of the global array — it does not attempt to
   reuse or renumber any existing slot.
3. Rewrites `idx`'s own entry to describe the new subtree's root (so
   anything referencing `idx` transparently sees the new content), and
   stitches the local tree's remaining nodes in as `idx`'s new
   descendants.
4. Splices the corresponding line range in the rendered text/style
   buffers, and shifts every downstream node's `text_range` by the
   resulting line-count delta.
5. Orphans the old subtree's nodes (they stay in the array, unreachable
   from any live pointer, and are scrubbed out of the fold set so stale
   entries can't hide unrelated content) rather than compacting the
   array.

This "always append, never renumber or compact" discipline is why a node
can be re-overridden any number of times over a session without ever
invalidating another node's index — the trade-off is that the array
grows monotonically and accumulates orphaned entries, which is accepted
as a cheap, session-scoped cost.

### `rendered_as`: provenance, not just "is there an override"

Each node's `rendered_as` field records *what it was last spliced as* —
not merely whether an override currently applies to it. This distinction
matters because the interesting question when deciding whether to
re-splice is never "is an override active right now," but "does the
currently active resolution (override, or its absence) differ from what's
already on screen." Comparing against stored provenance is what correctly
detects a *demotion* — an override that used to apply and no longer does
— and not just fresh promotions or retypes; a node whose override was
just removed still needs to fall back to its natural, schema-inferred
type, and `rendered_as` is what tells the render pass that a splice is
needed to make that happen.

### Any/MessageSet auto-expansion is a recursion-gate widening, not a special path

The render pass that walks the tree applying overrides (`render_overrides`
— described fully in [override-collection.md](override-collection.md))
normally only recurses into nodes already known to be message/group
shaped. Any and MessageSet fields start out as plain scalar (LEN-wire)
fields, which would ordinarily never be visited at all. Rather than give
these two shapes a separate traversal path, the recursion gate is widened
just enough to let exactly these two structural shapes through
(`is_auto_expand_candidate`), so that on first visit they can be
auto-resolved to a concrete type and folded into the ordinary override
machinery from then on. The gate is kept narrow deliberately: recursing
into *every* scalar LEN-wire field unconditionally was an earlier bug
(an ordinary string/bytes field being wrongly demoted to a raw dump), so
the condition is written to match only the two known Any/MessageSet field
shapes, not "any field that might conceivably be a message."
