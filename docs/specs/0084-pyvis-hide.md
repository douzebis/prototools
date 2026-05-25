<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0084 — `--hide`: node filtering for pyvis graphs

**Status:** implemented
**Implemented in:** 2026-05-25
**App:** reproto

---

## Background

`--emit-pyvis` (spec 0083) renders the raw and Hopcroft-minimised scoring
graphs as self-contained HTML files.  For large schemas the graphs contain
many nodes that are not interesting for a specific demo or investigation —
in particular WKT message nodes (e.g. `google.protobuf.Timestamp`) that
are present only because some field references them, or entire sub-graphs
that clutter the view without adding insight.

`--seed` / `--prune` already control which nodes enter the schema DB, but
they are coarse instruments: pruning a file removes it from the output
entirely, including from the scoring graph.  A finer control is needed that
lets the user hide nodes from the **rendered HTML** without affecting the
scoring-graph data or the schema DB.

---

## Goals

1. Add `--hide FQDN` (repeatable) to the CLI.  Accepts only `desc:`-prefixed
   FQDNs and glob patterns (e.g. `desc:google.protobuf.*`).
2. Matched nodes are excluded from the pyvis HTML rendering (both the raw
   and the Hopcroft graph).  No effect on the schema DB, the `.rkyv` files,
   or the text `.proto` output.
3. Hidden nodes' **incident edges** are also dropped (both incoming and
   outgoing).
4. `--hide` is silently ignored when `--emit-pyvis` is absent.
5. `--hide` matches against the FQDNs listed in the `roots` section of the
   compiled YAML.  A node is hidden if **any** of its mapped FQDNs matches
   a hide pattern.
6. Filtering is applied inline during rendering — no reachability analysis,
   no graph traversal.  Disconnected sub-graphs after hiding are the user's
   responsibility.

---

## Non-goals

- Transitive hiding (hiding A does not automatically hide nodes that become
  unreachable after A is removed).
- Hiding leaf (wire-type sink) nodes specifically — `--with-leaf-nodes`
  already controls their visibility.
- Affecting `--prune` / schema DB output.
- Shell completion for `--hide` values.

---

## Specification

### §84.1 — CLI option

```
--hide PATTERN      (repeatable, type=str)
```

- Accepts only `desc:`-prefixed FQDNs and glob patterns:
  `desc:my.pkg.MyMsg`, `desc:google.protobuf.*`.
  `file:` patterns are rejected at parse time with a clear error, because
  the compiled YAML `roots` section only contains `desc:` entries.
- Passed to `Options` as raw strings (same as `--prune` / `--seed`).
- Normalised via the same `_normalise_fqdn()` helper used by
  `--seed` / `--prune`, in the `try:` block after `_normalise_fqdn` is
  defined — fixing the current ordering bug where the normalisation was
  called before the function was defined.
- Stored in `Options.pyvis_hide: tuple[str, ...]`.
- Section: `Diagnostics` (alongside `--emit-pyvis`, `--with-leaf-nodes`).
- Help text:
  `'desc: FQDN or glob to hide from --emit-pyvis graphs.  Matched nodes
  and their incident edges are dropped from the HTML; no effect on the
  schema DB.'`

### §84.3 — `render_scoring_graph` signature extension

Add `hide: tuple[str, ...] = ()` to `render_scoring_graph`:

```python
def render_scoring_graph(
    compiled_yaml: str,
    output_path: Path,
    title: str,
    node_colour: str,
    with_leaf_nodes: bool = False,
    hide: tuple[str, ...] = (),
) -> None:
```

### §84.4 — Filtering logic in `render_scoring_graph`

Filtering is applied **inline during rendering**, with no pre-pass:

1. **Build `state_fqdns`** from `roots` as usual (already done for tooltips).

2. **When adding a node:** check whether any FQDN in `state_fqdns[sid]`
   matches any pattern in `hide`.  If so, record `sid` in a local
   `hidden_ids: set[int]` and skip `net.add_node()`.

3. **When adding an edge:** skip `net.add_edge()` if `t['from']` or
   `t['to']` is in `hidden_ids`.

The existing `with_leaf_nodes` leaf-filtering logic is orthogonal and
unchanged: leaf states that survive hide filtering are still subject to
the `with_leaf_nodes` flag.

### §84.5 — FQDN matching

`render_scoring_graph` uses a minimal inline helper rather than importing
from `phases.py` (avoids a `show` → `phases` circular dependency):

```python
from pathlib import PurePosixPath

def _fqdn_matches_any(fqdn: str, patterns: tuple[str, ...]) -> bool:
    for p in patterns:
        if PurePosixPath(f'/{fqdn}').full_match(f'/{p}'):
            return True
    return False
```

Both `fqdn` (from `roots`) and `patterns` (from `ctx.pyvis_hide`) are in
the same normalised `desc:foo/bar/Baz` form, so no further transformation
is needed.

### §84.6 — Call sites in `phases.py`

Pass `ctx.pyvis_hide` to both `render_scoring_graph` calls:

```python
render_scoring_graph(
    initial_yaml, raw_path, 'Raw scoring graph', '#97fc9a',
    with_leaf_nodes=ctx.with_leaf_nodes,
    hide=ctx.pyvis_hide,
)
render_scoring_graph(
    compiled_yaml, hopcroft_path, 'Hopcroft graph', '#aaaaff',
    with_leaf_nodes=ctx.with_leaf_nodes,
    hide=ctx.pyvis_hide,
)
```

---

## Files changed

- `reproto/src/reproto/cli.py` — fix `_normalise_fqdn` ordering; `--hide`
  option already present; `pyvis_hide` normalisation moved to `try:` block
- `reproto/src/reproto/context.py` — `pyvis_hide` field already present
- `reproto/src/reproto/phases.py` — pass `hide=ctx.pyvis_hide` to both
  `render_scoring_graph` calls
- `reproto/src/reproto/show.py` — add `hide` parameter; filtering logic

---

## References

- Spec 0083 — `--emit-pyvis` implementation
- Spec 0074 — `--prune` / `--seed` glob pattern syntax
- `reproto/src/reproto/phases.py` — `fqdn_matches_any()` helper
