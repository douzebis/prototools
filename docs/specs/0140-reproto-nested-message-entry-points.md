<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0140 — reproto: nested message types as scoring entry points

Status: implemented
Implemented in: 2026-07-17
Refs: docs/specs/0045-reproto-emit-graph.md (YAML `messages` dict — already
      includes nested types, predates the `entries` field so does not
      document it), docs/specs/0047-build-scoring-graph.md (amended by
      this spec — `entries`/root-entry wording), docs/specs/0043-hopcroft-db.md
      (amended by this spec — "one schema = one top-level message type"
      wording), docs/specs/0048-multi-entry-score.md (amended by this
      spec — background prose only, algorithm already entry-agnostic),
      docs/specs/0108-message-set-scoring-tier0.md (synthesized `Item`
      pseudo-node, explicitly excluded by this spec — see G3),
      `prototext-graph/src/score/walk.rs` (`score_all`, consumes
      `graph.roots` generically — no change needed)
App: reproto

## Background

The scoring graph's `entries` list (spec 0047) names the FQDNs that the
scoring walk (spec 0048) is allowed to try as *starting points* — i.e.
the set of types auto-inference may propose as the type of an entire
top-level byte blob. Today, in `reproto/src/reproto/phases.py`, this
list is built by iterating only `FileDescriptorProto.message_types_by_name`
— the file's top-level message declarations:

```python
entries = []
for msg_desc in fd.message_types_by_name.values():   # top-level only
    node = ctx.nodes.get(Fqdn(f'desc:.{msg_desc.full_name}'))
    if node is None or not node.is_pruned:
        entries.append(msg_desc.full_name)
entries.sort()
```

Nested message types (declared inside another message) are fully
present in the same YAML's `messages` dict — spec 0045 §2 already
covers them, they participate in the graph and are reachable by
recursion from a parent field — but they can never themselves be tried
as a root: a nested message type's wire encoding is not affected in
any way by its lexical nesting in the `.proto` source (nesting is a
namespacing construct only), so a byte blob that happens to be a
serialized `pkg.Outer.Inner` is currently invisible to auto-inference,
even though `pkg.Outer.Inner` is scored correctly whenever it's
*reached* via a field of some other message.

This restriction is duplicated (byte-for-byte identical logic) in two
call sites in `phases.py`: `_phase_build_schema_db` (feeds
`--build-schema-db`, used to build the checked-in WKT `.rkyv` files)
and `_phase_emit_scoring_graphs` (feeds `--emit-scoring-graph`, the
YAML-only output path).

Investigation for this spec confirmed the restriction lives **only**
in reproto (Python). The Rust scoring pipeline
(`prototext-graph/src/build_scoring_graph/{load,graph}.rs`,
`prototext-graph/src/score/walk.rs`) treats `entries`/`roots` generically
— it turns whatever FQDNs the YAML provides into `RootEntry` records
and scores them, with no independent top-level-only logic of its own.
There is therefore a single locus of change for this spec, not two:
despite the compiled `.rkyv` file also containing the (currently
top-level-only) root list, it does so purely by inheriting whatever
`entries` the YAML fed it — no rkyv-side code needs to change.

This spec deliberately grows the number of entries per file (every
nested message becomes a candidate root, not just top-level ones),
which grows both the YAML `entries` lists and the compiled `.rkyv`
root tables — and, transitively, exercises corners of the scoring
pipeline (entry-count limits, artifact sizes) that the current
top-level-only corpus never reaches. That growth is not an accepted
side effect to be minimized — it is the explicit point of this change:
we do not yet know whether the scoring database stays manageable and
usable once every nested type is a candidate entry, and this spec is
how we find out. See "Entry-count guard hardening" and "Build-path
verification and WKT regeneration" below for the two concrete risks
this raises and how they are addressed.

### Does the scoring walk still need the `MessageSet.Item` node?

Prior to finalizing this spec, it was asked whether the MessageSet
synthesized `Item` pseudo-node (spec 0108, see G3 below) is needed by
the scoring database at all, on the theory that `prototext-core`'s
MessageSet handling reads the `message_set_wire_format` option
directly and does not depend on any `Item` type existing.

That theory is correct for **decoding/rendering**, but that is a
different subsystem from what `Item` serves. Confirmed by reading
`prototext-core/src/serialize/render_text/helpers/message_set_field.rs`:

```rust
pub(in super::super) fn is_message_set(desc: &MessageDescriptor) -> bool {
    let msf = desc
        .descriptor_proto()
        .options
        .as_ref()
        .and_then(|o| o.message_set_wire_format)
        .unwrap_or(false);
    msf && desc.fields().count() == 0
}
```

This is a purely structural, option-based check — it has no
dependency on any `Item` FQDN, and `prototext-core` contains no
scoring code at all (confirmed by grep: the only "score" hit in
`render_text/` is an unrelated comment). So `prototext-core`'s
render/decode path genuinely does not need `Item` to exist.

However, `Item` is not scoring-graph plumbing left over from that
subsystem — it exists to serve a different one. Per spec 0108's own
rationale, `Item` gives the **scoring walk** (type auto-inference,
`prototext-graph`) real match credit for a MessageSet's `type_id`/
`message` sub-fields; without it, a MessageSet-flagged type falls
back to the generic, less precise `parse_group_blind` handling
(`unknowns += 1`, no veto) for those bytes. Removing `Item` would not
break decoding, but it would measurably reduce scoring precision for
MessageSet types specifically.

This spec does not change spec 0108's `Item` synthesis either way —
G3 (excluding `Item` from `entries`) holds regardless of whether
`Item` exists at all, since `Item` never corresponded to a real
`Descriptor` and was never a candidate entry point to begin with.

## Goals

- G1: `entries` (in both `_phase_build_schema_db` and
  `_phase_emit_scoring_graphs`) includes every non-pruned message
  type's FQDN in the file — top-level and nested alike — not just
  top-level ones. A type that appears as a key in that same YAML's
  `messages` dict (with the exception of G3's synthetic node) is
  eligible to be an entry.
- G2: implementation is a refactor, not a bolt-on second pass. Both
  `_collect(desc, messages, group_fqdns)` closures (currently
  near-identical, one per call site) already recurse into every
  nested message and already skip pruned nodes before adding to
  `messages`. Thread an `entries: list[str]` accumulator through this
  same recursion, appending `desc.full_name` at the same point the
  node is confirmed non-pruned and added to `messages` — replacing
  each call site's separate top-level-only `entries` loop entirely.
  This also fixes a latent inconsistency: today, a nested message's
  own pruned status is never consulted when building `entries` (since
  entries never looked past the top level); after this change, a
  pruned nested message is correctly excluded from `entries`, exactly
  as it is already excluded from `messages`.
- G3: the MessageSet synthesized `Item` pseudo-node
  (`_synthesize_message_set_item`, spec 0108) is added to `messages`
  as `{desc.full_name}.Item`, but does not correspond to any real
  `Descriptor` in the pool — it is fabricated purely to give the
  scoring walk match credit for a MessageSet's fixed wire layout.
  It must **not** become an entry: the `entries` accumulator (G2)
  only ever receives `desc.full_name` (the real message being
  processed), never the synthetic `item_fqdn` — `_synthesize_message_set_item`
  itself is not touched, since it never had access to (and doesn't
  need) the `entries` accumulator.
- G4: protoc-synthesized map-entry types (e.g. `Outer.FieldEntry`,
  generated for a `map<K, V>` field) correspond to real `Descriptor`
  objects reachable via `nested_types`, structurally identical to any
  other message. They are included as entries under G1/G2 with no
  special-casing — they are visited by the same recursion as any
  other nested type.
- G5: sort order and dedup-by-pruning behavior are otherwise
  unchanged — `entries` remains a sorted list of FQDNs, one per
  distinct message type per file.
- G6: the entry-count guard in `prototext-graph/src/score/walk.rs`
  (`score_all`'s `assert!(graph.roots.len() <= u16::MAX as usize, ...)`,
  guarding the `as u16` cast used to pack entry indices into
  `SmallVec<[u16; 4]>` for the multi-entry parallel walk) gains
  regression-test coverage confirming it panics — rather than
  silently wrapping/truncating — when entry count exceeds
  `u16::MAX`. This does not raise the ceiling (see N3); it hardens
  the existing guard against silent overflow now that this spec makes
  the ceiling meaningfully closer to reachable for a large corpus.
- G7: the checked-in WKT artifacts
  (`prototext/wkt/prebuilt/{wkt,wkt_index}.rkyv`) are regenerated and
  committed as part of landing this change, since they are consumed
  by a build path (see "Build-path verification and WKT regeneration"
  below) that has no CI automation and would otherwise silently drift
  stale relative to the new, larger `entries` produced by this spec.

## Non-goals

- N1: no change to `prototext-graph`'s Rust code
  (`build_scoring_graph/{load,graph}.rs`, `score/walk.rs`,
  `score/load.rs`) — confirmed during investigation that all of it
  already consumes `entries`/`roots` generically. `RootEntry` records
  are created for whatever FQDNs the YAML lists; nothing assumes
  top-level-only today, and nothing needs to change to accept the
  larger set this spec produces.
- N2: no change to the Hopcroft minimization algorithm itself
  (`build_scoring_graph/hopcroft.rs`) — it partitions nodes by
  structural equivalence regardless of whether a node is also a root;
  adding more roots changes which states get labeled as roots, not
  how partitioning proceeds.
- N3: no attempt to raise the existing hard
  `assert!(graph.roots.len() <= u16::MAX)` ceiling in
  `prototext-graph/src/score/walk.rs:171`, and no switch to a wider
  index type (entry indices are packed into `u16` for the multi-entry
  parallel walk, spec 0048). For the WKT corpus this remains a
  non-issue even with every nested type included (WKT is small —
  descriptor.proto and its dozen-odd sibling files). For a very large
  summoned corpus (many thousands of `.proto` files), the enlarged
  entry count brings this ceiling closer; addressing that by widening
  the index type is out of scope here, flagged as a known limitation,
  not a blocker — if a real corpus ever hits it, that is exactly the
  signal (per G6/G7) that this spec's changes need reverting or the
  index type needs widening in a follow-up spec. What IS in scope is
  hardening the existing guard so an overflow is loud, not silent —
  see G6. See "Real-world measurement: googleapis corpus" and
  "Preliminary analysis: widening the entry-index type" below for the
  actual googleapis-corpus margin measurement and a scoping analysis
  (not an implementation) of what a `u16`→`u32` follow-up would involve.
- N4: no UI/UX changes to protolens's override pane or heat-cue
  candidate-list rendering (specs 0114, 0138) to cope with longer
  candidate lists from deeply-nested schemas. Those lists getting
  longer for nested-heavy schemas is the intended effect of this
  spec, not a side effect to mitigate.
- N5: no change to how enums, services, or extensions are handled —
  unaffected, as before (spec 0045 §Non-goals).
- N6: no retroactive change to hand-authored test fixture YAML files
  under `prototext-graph/tests/fixtures/scoring/` or
  `prototext-graph/tests/fixtures/hopcroft/` — those are arbitrary,
  manually written graphs for exercising the Rust loader/Hopcroft/
  scorer in isolation, independent of what reproto happens to emit;
  since the Rust side treats `entries` generically (N1), they remain
  valid test inputs whether or not their `entries` lists happen to
  include only top-level-looking names.

## Specification

### `phases.py` — `_collect` accumulates `entries`

Both call sites' `_collect` closure changes from:

```python
def _collect(desc, messages, group_fqdns):
    msg_node = ctx.nodes.get(Fqdn(f'desc:.{desc.full_name}'))
    if msg_node is not None and msg_node.is_pruned:
        return
    fields_out = [...]
    _synthesize_message_set_item(desc, messages, fields_out)
    node_kind = 'GROUP' if desc.full_name in group_fqdns else 'LENDEL'
    messages[desc.full_name] = {'kind': node_kind, 'fields': fields_out}
    for nested in desc.nested_types:
        _collect(nested, messages, group_fqdns)
```

to:

```python
def _collect(desc, messages, group_fqdns, entries):
    msg_node = ctx.nodes.get(Fqdn(f'desc:.{desc.full_name}'))
    if msg_node is not None and msg_node.is_pruned:
        return
    fields_out = [...]
    _synthesize_message_set_item(desc, messages, fields_out)
    node_kind = 'GROUP' if desc.full_name in group_fqdns else 'LENDEL'
    messages[desc.full_name] = {'kind': node_kind, 'fields': fields_out}
    entries.append(desc.full_name)
    for nested in desc.nested_types:
        _collect(nested, messages, group_fqdns, entries)
```

Each call site's driving loop changes from two separate loops (one
building `messages` via `_collect`, one rebuilding `entries` from
`fd.message_types_by_name.values()`) to one:

```python
messages: dict = {}
entries: list[str] = []
for msg_desc in fd.message_types_by_name.values():
    _collect(msg_desc, messages, group_fqdns, entries)
entries.sort()
```

This removes the second, now-redundant top-level-only `entries` loop
from both `_phase_build_schema_db` (`phases.py:1515-1520`) and
`_phase_emit_scoring_graphs` (`phases.py:1849-1856`).

### YAML output

No schema/format change — `entries` remains a flat, sorted list of
FQDN strings under the `entries:` top-level key. Only the *contents*
of that list change (now includes nested types, per G1/G3/G4).

### Entry-count guard hardening

Investigation confirmed `prototext-graph/src/score/walk.rs`'s
`score_all` is the **sole** site in the repo that narrows an entry
count to `u16` (repo-wide grep for `as u16`, `u16::MAX`,
`roots.len()`, `entries.len()` found no other truncation site):

```rust
pub fn score_all(pb: &[u8], graph: &ArchivedCompiledGraph, opts: &ScoringOpts) -> Vec<EntryScore> {
    assert!(
        graph.roots.len() <= u16::MAX as usize,
        "entry count {} exceeds u16::MAX",
        graph.roots.len()
    );
    ...
    let initial_active = group_by_state(
        graph.roots.iter().enumerate()
            .map(|(i, r)| (r.state_id.to_native(), i as u16)),
    );
    ...
}
```

The `assert!` (not `debug_assert!`) already survives `--release`
builds and already turns an overflow into a loud panic rather than a
silent wraparound — so per G6, no code change is required to satisfy
"don't silently overflow." What's missing is regression-test coverage
proving it, which becomes worth having now that this spec makes entry
counts large enough that the ceiling is no longer purely academic.

Add a test to `prototext-graph/src/score/tests.rs` that constructs a
synthetic `Merged` (reusing the existing `make_merged()`-style
hand-built fixture pattern already used by that file) with more than
`u16::MAX` root entries, runs it through the real pipeline
(`graph::build` → `hopcroft::minimize` → `graph::compile`), and
asserts that `score_all` panics rather than silently truncating or
wrapping. This does not require a real corpus — the fixture can be
trivial states repeated many times.

### Build-path verification and WKT regeneration

There are two independent build paths that produce the WKT scoring
graph, and only one of them auto-regenerates:

1. **In-repo Nix build** (`nix-build -A prototext`, no `prebuilt-wkt`
   feature): `default.nix` builds a `wktRkyv` derivation
   (`pkgs.runCommand "wkt-rkyv"`, invoking `reproto --schema-db-out`
   via `python.reprotoBare`) fresh on every build, feeding it into the
   Crane `rust.prototext` workspace via `WKT_RKYV`/`WKT_INDEX` env
   vars consumed by `prototext/build.rs`. **This path already
   auto-regenerates** — confirmed by reading `default.nix` and
   `prototext/build.rs`. No action needed here; this spec's `entries`
   change flows through automatically on the next `nix-build`.
2. **`prebuilt-wkt` Cargo feature** (used by the nixpkgs
   `package.nix` build and crates.io-published `prototext`, per
   `prototext/wkt/prebuilt/README.md`): copies directly from the
   checked-in `prototext/wkt/prebuilt/{wkt,wkt_index}.rkyv` files.
   **This path does NOT auto-regenerate** — confirmed by grepping
   `.github/` workflows for `wkt.rkyv`/`wkt_index`/`prebuilt-wkt`:
   zero matches. There is no CI automation of any kind that rebuilds
   or staleness-checks these files; the checked-in `.rkyv` files are
   a fully manual, developer-run artifact.

Because path 2 has no safety net, regenerating and committing
`prototext/wkt/prebuilt/wkt.rkyv` and `wkt_index.rkyv` is a **hard
requirement** of landing this spec (G7), not an optional cleanup step.
Via the existing documented procedure
(`prototext/wkt/prebuilt/README.md`):

```bash
nix-build -A prototext 2>&1 | tee /tmp/nix-build-prototext.log
store=$(grep -oP '/nix/store/\S+-wkt-rkyv(?=/)' /tmp/nix-build-prototext.log | head -1)
cp "$store/wkt.rkyv"       prototext/wkt/prebuilt/wkt.rkyv
cp "$store/wkt_index.rkyv" prototext/wkt/prebuilt/wkt_index.rkyv
```

No other checked-in `.rkyv`/YAML artifacts were found to depend on
entry-point selection (test fixtures are hand-authored, N6).

### Real-world measurement: googleapis corpus

Before committing this spec's code changes, the full (unscoped) `nix-build`
was run once with the pre-0140 code (baseline, four separate store paths,
all identical — `registrationTime` 2026-07-09 and 2026-07-15) and once
with this spec's code (2026-07-17), producing two `googleapis-db`
Hopcroft-compiled graphs (`hopcroft.rkyv`) over the real, full googleapis
corpus (7771 `.proto` files). A throwaway diagnostic binary
(`LoadedGraph::roots.len()` / `transitions.len()` / max `state_id`, not
committed) was run against both:

| | Before (pre-0140) | After (this spec) | Δ |
|---|---|---|---|
| Roots (entry points) | 39,937 | 49,255 | **+9,318 (+23.3%)** |
| Transitions | 89,267 | 89,267 | unchanged |
| Max `state_id` | 17,572 | 17,572 | unchanged |
| `u16::MAX` margin | 25,598 (60.9% fill) | 16,280 (75.2% fill) | −9,318 |

Transitions and max `state_id` are identical before/after: nested message
types were already nodes in the graph (reachable via field recursion, per
Background), so this spec's change is purely additive to the *root* table
— it does not alter graph structure or size in any other dimension.

The build itself completed cleanly: exit code 0, no panic, no
`u16::MAX` overflow (grepped the full build log for
`panic|error|exceeds u16::MAX`, only match was an unrelated benign lint
summary line). The googleapis stress-test suite
(`tests/stress/test_stress.py::test_auto_infer`) reported 88 passed, 54
warnings — each warning is `--list-schemas returned N tied FQDNs
(max_ties=5)` for a specific real FQDN, with `N` up to 23,723–34,063 for
the worst cases (e.g. `google.ads.datamanager.v1.RetrieveRequestStatusRequest`,
`google.cloud.aiplatform.v1beta1.TFRecordDestination`). Per discussion,
these particular worst-case ties are attributed to auto-generated,
toy-like request/response message shapes in that corpus rather than a
general scoring-precision regression, and the tests still passed —
roughly half of the 88 tested protobufs had fewer than 5 tied candidates,
which is the target discriminability. This finding is not treated as a
blocker for this spec, but the entry-count margin consumption (a real
corpus's `u16::MAX` headroom shrinking from 60.9% to 75.2% fill from this
change alone) is a concrete, load-bearing data point for the "widening
the entry-index type" analysis below, and for any future spec that grows
`entries` further.

### Preliminary analysis: widening the entry-index type (not implemented)

N3 explicitly keeps raising the `u16::MAX` ceiling out of scope for this
spec. This subsection is a preliminary scoping analysis only — requested
after the googleapis measurement above showed a real corpus already at
75% fill — to inform whether/when a follow-up spec should do the work.
No code changes described here are made by this spec.

**Scope of the change.** The `u16` entry-index type is used **only** in
`prototext-graph/src/score/walk.rs` (confirmed by repo-wide grep for
`as u16` / `u16::MAX` / `SmallVec<[u16`; the only other `u16` hits in the
codebase — `protolens`'s terminal-coordinate casts, and
`build_scoring_graph/graph.rs`'s `range_idx` for spec 0077 varint-veto
ranges — are unrelated concepts). All ten sites are runtime, in-memory
structures local to the scoring walk:

- `ActiveEntry::entries: SmallVec<[u16; 4]>` (walk.rs:69)
- `WalkState::is_vetoed(&self, e: u16)` / `set_vetoed(&mut self, e: u16, ...)`
  (walk.rs:105, 110) — index into a `Vec<u64>` bitset, already
  width-agnostic internally (`e as usize`)
- `group_by_state(pairs: impl Iterator<Item = (u32, u16)>)` and its local
  `Vec<(u32, u16)>` (walk.rs:126-127)
- the `assert!(graph.roots.len() <= u16::MAX as usize, ...)` guard itself
  and the `i as u16` cast that produces the initial entry indices
  (walk.rs:171-172, 194)
- three more `Vec<(u32, u16)>` / `Vec<u16>` locals inside the LEN and
  START_GROUP branches of the walk (`child_pairs`, `recurse_into`,
  `stay_out_entries`; walk.rs:963, 1068-1069)

Nothing outside this file depends on the width: `EntryScore` (the public
output type) has no index field — entries are identified positionally,
by `Vec` order, which is width-independent. The on-disk `CompiledGraph`
format (`build_scoring_graph/serial.rs`) already stores `RootEntry.state_id`
as `u32` and the root table as a plain `Vec<RootEntry>` with no explicit
count-width field — so no serialization/`rkyv` format change is needed to
support more roots; the `u16` limit is purely a runtime packing choice
inside `score_all`'s walk, not a persisted-format constraint.

**Recommendation: `u32`, not `usize` or a batching scheme.** `u32`
matches `state_id`'s existing width (no third integer size introduced),
raises the ceiling to ~4.29 billion (no credible corpus gets remotely
close — even a corpus 1000x the size of the full googleapis stress
corpus measured above would be under 50 million entries), and only
modestly increases memory: `SmallVec<[u32; 4]>` doubles from 16 to 32
bytes inline, and the `Vec<(u32, u32)>` locals double their second field
— all transient, per-`score_all`-call allocations, not persisted state,
so the cost is negligible even at the largest corpus sizes seen so far.
`usize` would work identically on 64-bit but wastes 4 bytes per entry for
no benefit (there is no near-term scenario needing more than `u32::MAX`
entries) and introduces platform-width dependence for no reason. A
batching/paging scheme (splitting the parallel walk into multiple
`u16`-sized batches) was considered and rejected: it would require
correctly merging veto/occurrence state across batch boundaries for
negligible benefit over just widening one integer type — added
complexity with no corresponding advantage.

**Testing implication.** The current regression test
(`tc_of1_entry_count_over_u16_max_panics`, G6) constructs a real
`u16::MAX + 1`-entry graph through the full production pipeline — feasible
at ~65K entries. The same approach is **not** feasible at `u32::MAX + 1`
(~4.29 billion entries): building that many `RootEntry` records would
exhaust memory and take an impractical amount of time in a unit test. A
follow-up spec that performs this widening would need to either (a)
extract the bound check into a small free function
(`fn check_entry_count(n: usize) -> Result<(), String>` or similar) and
unit-test *that* directly with a fake `usize` argument rather than a
real graph, or (b) accept the practical-impossibility argument (no
integration test can build a `u32::MAX`-entry fixture; the assert is
reviewed by inspection instead) — a decision to make explicitly if/when
that spec is written, not implied by this analysis.

This is flagged as a concrete follow-up candidate, not an immediate
action: the googleapis corpus is at 75% fill today, not over the
ceiling, and G6's hardened assert means any future overflow fails loudly
at build time rather than corrupting results silently. But the margin
consumed by this spec alone (over a third of the previous headroom, for
one already-large real corpus) suggests the `u16→u32` follow-up should
not be deferred indefinitely.

## Test plan

`reproto/src/reproto/tests/test_emit_scoring_graphs.py`:

- **TC-1 amended**: `test_TC1_basic_emission`'s existing assertions
  (lines 133-135) currently assert nested types are absent from
  `entries` — flip to assert `"test.field.Outer.Middle"` and
  `"test.field.Outer.Middle.Inner"` **are** present.
- **New**: a pruned-nested-message fixture/case confirming a pruned
  nested type is excluded from both `messages` and `entries` (mirrors
  existing pruned-top-level coverage, extended one level down).
- **New**: a MessageSet fixture (reusing spec 0108's test fixtures)
  confirming the synthesized `{fqdn}.Item` key is present in
  `messages` but absent from `entries` (G3).
- **New**: a `map<K, V>` field fixture confirming the synthesized
  map-entry type's FQDN appears in both `messages` and `entries` (G4).
- **New**: confirm `entries` stays sorted and duplicate-free across a
  fixture with multiple nesting levels and multiple files.

`_phase_build_schema_db`'s copy of the same logic is exercised
indirectly via existing `--build-schema-db` integration tests (if
any) or via the WKT rebuild itself — no new dedicated unit test is
proposed for that call site beyond confirming both closures stay in
sync (ideally by factoring them into one shared helper if one doesn't
already exist as part of this change — a cleanup opportunity, not a
strict requirement).

`prototext-graph/src/score/tests.rs`:

- **New**: a synthetic-`Merged`-based test with more than `u16::MAX`
  root entries, asserting `score_all` panics rather than silently
  overflowing (G6).

## Open questions

- ~~Q1~~ Resolved: `.Item` exclusion (G3) and map-entry inclusion
  (G4) are settled — see "Does the scoring walk still need the
  `MessageSet.Item` node?" above. `prototext-core`'s decode path is
  confirmed independent of `Item`, but the scoring walk still relies
  on it for match precision; spec 0108's `Item` synthesis is
  unaffected by this spec either way, so G3/G4 hold as originally
  drafted.
- ~~Q2~~ Resolved: left as-is for this change, matching the current
  file's existing duplication convention — the two `_collect`
  closures remain separate. De-duplicating them is a follow-up
  cleanup opportunity, not required by this spec's goals.
