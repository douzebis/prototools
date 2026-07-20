<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0153 — `score_one`: cheap single-entry scoring fast path

Status: implemented
App: prototext-graph
Implemented in: 2026-07-20
Refs: docs/specs/0042-schema-score.md (the original single-entry `score()`,
      superseded by spec 0048 — this spec revives the single-entry use case
      but reuses spec 0048's multi-entry walk internals rather than
      resurrecting `score()`), docs/specs/0048-multi-entry-score.md
      (`score_all`, `score_message_multi`, `ActiveEntry` — all reused
      verbatim), `prototext-graph/src/score/walk.rs`, `prototext/src/run.rs`
      (`run_score`)

## Background

`prototext score --type <fqdn>` scores one binary protobuf against one
named type and prints a single result line. Its handler
(`prototext/src/run.rs::run_score`) implemented this by calling
`score_all` — which walks the wire bytes once against **every** root
entry in the compiled graph simultaneously (spec 0048) — and then
linearly filtering the resulting `Vec<EntryScore>` down to the one
entry actually requested.

`score_all`'s cost scales with the number of root candidates
(`graph.roots.len()`): before the walk even starts, it clones every
root's fqdn into a fresh `EntryScore` and sorts all `(state_id,
entry_index)` pairs by `state_id` (`group_by_state`, O(N log N)).  For
a large descriptor set — e.g. `googleapis.desc`, whose scoring graph's
`graph.roots` contains many thousands of entries (populated by
`reproto`'s `_collect`, which recursively adds every message type,
including nested ones, from every non-pruned file) — this overhead is
substantial even for a trivially small input blob.  Measured against
that graph: `decode --type ...` (no scoring at all) on a 2-byte blob
took 55ms; `score --type ...` on the same blob took 287ms — roughly
230ms of pure "initialize and walk every root" overhead unrelated to
the blob itself.

A second, independent inefficiency compounds this: inside
`score_message_multi`, two hot-path lookups did a linear `.iter()
.find()`/`.iter().any()` scan over `graph.nodes`/`graph.transitions`
per active entry per matched field — despite both tables already being
sorted (`(state_id, field_number)` and `state_id` respectively, per
the "Schema lookup" section's own documented invariant, already
exploited by `find_transition`/`node_wire_type` and by
`apply_cardinality_multi`'s `partition_point` idiom). This cost is
`O(active.len())` per lookup and therefore compounds with candidate
count — it also drags down `score_all`'s legitimate multi-candidate
callers (`list-schemas`, protolens's override pane), not just
`score_one`'s new single-candidate case.

## Goals

- **G1. `score_one(pb, fqdn, graph, opts) -> Option<EntryScore>`**
  (`prototext-graph/src/score/walk.rs`, exported from `score/mod.rs`)
  — scores `pb` against exactly one named root entry, reusing
  `score_message_multi`/`WalkState`/`ActiveEntry` verbatim (the walk
  itself is already agnostic to how many candidates it's given — see
  spec 0048's `score_message_multi`), seeded with a single-entry
  `ActiveEntry` instead of `group_by_state`'s full-root grouping.
  `fqdn` may be given with or without a leading dot; lookup compares
  both sides with `trim_start_matches('.')`, matching either form
  stored in `graph.roots`. Returns `None` if no root entry matches.
- **G2. Binary-search the two remaining linear scans.** Two new
  helpers, `find_node`/`state_has_transitions`, added next to
  `find_transition`/`node_wire_type` in the "Schema lookup" section,
  using the same `partition_point` idiom as
  `apply_cardinality_multi`:
  ```rust
  fn find_node(graph: &ArchivedCompiledGraph, state_id: u32) -> Option<&ArchivedNodeEntry> {
      let n = &graph.nodes;
      let start = n.partition_point(|e| e.state_id.to_native() < state_id);
      n.get(start).filter(|e| e.state_id.to_native() == state_id)
  }
  fn state_has_transitions(graph: &ArchivedCompiledGraph, state_id: u32) -> bool {
      let t = &graph.transitions;
      let start = t.partition_point(|e| e.state_id.to_native() < state_id);
      t.get(start).is_some_and(|e| e.state_id.to_native() == state_id)
  }
  ```
  Both call sites inside `score_message_multi` (the varint
  `Verdict::Found` branch's range/wire-type node lookup, and the
  `WT_LEN` `Verdict::Found` branch's message-vs-leaf classification)
  are rewritten to use these instead of `.iter().find()`/`.iter()
  .any()`. This benefits `score_all`'s existing callers too, not just
  `score_one`.
- **G3. `prototext score` uses `score_one`.** `run_score`'s per-input
  closure (renamed `score_input` to avoid shadowing the newly-imported
  `score_one`) calls `score_one(&binary, type_name, graph,
  scoring_opts)` directly instead of `score_all` plus a linear
  `.find()`. The "type not found" error path is unchanged (`None` →
  the same error message as before).

## Non-goals

- **N1.** `score_all` itself is unchanged, and remains the correct
  choice for every genuinely multi-candidate use (`prototext
  list-schemas`, protolens's override pane ranking) — this spec adds
  a second, narrower entry point, it does not replace the first.
- **N2.** No change to `HeatRequestQueue`/protolens's heat-cue worker
  — consuming `score_one` there is a separate follow-up (spec 0154).
- **N3.** No change to `ScoringOpts` itself, or to veto/cardinality
  semantics — `score_one` walks the exact same rules as `score_all`,
  just seeded with one root instead of all of them.

## Specification

### `prototext-graph/src/score/walk.rs`

```rust
pub fn score_one(
    pb: &[u8],
    fqdn: &str,
    graph: &ArchivedCompiledGraph,
    opts: &ScoringOpts,
) -> Option<EntryScore> {
    let want = fqdn.trim_start_matches('.');
    let root = graph.roots.iter().find(|r| r.fqdn.trim_start_matches('.') == want)?;

    let mut scores = vec![EntryScore {
        fqdn: root.fqdn.as_str().to_owned(),
        matches: 0, unknowns: 0, mismatches: 0, non_canonical: 0, vetoed: false,
    }];
    let mut entries: SmallVec<[u16; 4]> = SmallVec::new();
    entries.push(0);
    let initial_active = vec![ActiveEntry {
        state_id: root.state_id.to_native(),
        entries,
        occurrences: Vec::new(),
    }];

    let mut ws = WalkState::new(graph, &mut scores, opts);
    score_message_multi(pb, 0, initial_active, None, &mut ws);
    scores.pop()
}
```

Exported alongside `score_all` from `score/mod.rs`:
`pub use walk::{score_all, score_one, EntryScore, ScoringOpts};`.

### `prototext/src/run.rs`

```rust
use prototext_graph::score::{
    load::{load_graph, LoadedGraph},
    score_all, score_one, ScoringOpts,
};
// ...
let score_input = |data: &[u8]| -> Result<(bool, i64, u64, u64, u64, u64), String> {
    let binary = render_as_bytes(data, /* ... */)?;
    let result = score_one(&binary, type_name, graph, scoring_opts)
        .ok_or_else(|| format!("type '{}' not found in scoring graph", type_name))?;
    Ok((result.vetoed, result.score(), result.matches, result.unknowns,
        result.mismatches, result.non_canonical))
};
```

`score_all`'s two other call sites in `run.rs` (ranking-based
`list-schemas` support) are untouched.

## Test plan

`prototext-graph/src/score/tests.rs`, against the existing
`build_two_entry_graph` fixture (`Outer`/`Inner` roots):

- **SO-01.** `score_one` against one entry matches the corresponding
  entry from `score_all` on the same blob (same `matches`/`unknowns`/
  `mismatches`/`non_canonical`/`vetoed`).
- **SO-02.** `score_one` only walks the requested entry — a field that
  would veto a *different* root has no effect on the requested one.
- **SO-03.** `score_one` accepts a leading-dot fqdn, yielding the same
  result as the bare form.
- **SO-04.** `score_one` returns `None` for an fqdn absent from
  `graph.roots`.

Existing `prototext-graph`/`prototext` regression suites (43 + 8 +
existing `run.rs`-adjacent tests) pass unchanged; `cargo fmt --check`
and `cargo clippy --all-targets` clean.

**Empirical verification** (`googleapis.desc`, `google.firestore.v1.
CommitRequest`, the same repro used to discover the problem):
`prototext score --type ...` dropped from ≈287ms (a 2-byte blob) /
≈592ms (a 200KB blob) to ≈13ms.
