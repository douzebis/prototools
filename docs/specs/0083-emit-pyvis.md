<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0083 — `--emit-pyvis`: scoring graph visualisation

**Status:** draft
**App:** reproto

---

## Background

`reproto --graph FILE` currently calls `show.py`, which renders the FQDN
dependency graph filtered to hard-coded `midas`-related FQDNs.  This is
dead code for any other user.  The implementation is also broken: it calls
`net.set_template('local_assets/template.html')` against a template file
that does not exist in the repository.

A more useful visualisation would show the **scoring graph** — the
wire-type structure used by the schema-DB scorer — both before and after
Hopcroft minimisation.  This gives an intuitive picture of how many
structurally distinct message types exist in a schema and how many the
minimiser collapses.

The HTML output must be **self-contained**: no JavaScript or CSS fetched
from the Internet at display time or generation time.  pyvis supports this
via `cdn_resources='in_line'`, which reads JS/CSS from its own
`templates/lib/` directory (in the nix store alongside the pyvis package)
and inlines them directly into the HTML.  No network access is required
at any point.  The `set_template()` call in the current `show.py` is
actively harmful — it overrides this behaviour — and must be removed.

---

## Goals

1. Rename the CLI flag `--graph` to `--emit-pyvis`; keep it in the
   `Diagnostics` section of the help.
2. Replace the body of `show.py` with a single `render_scoring_graph`
   function called twice — once for the raw graph and once for the
   minimised graph.
3. Given `--emit-pyvis foo.html`, write:
   - `foo.html` — raw merged scoring graph (before Hopcroft)
   - `foo-hopcroft.html` — minimised scoring graph (after Hopcroft)
4. Both files must be fully self-contained HTML (no Internet dependency).
5. `--emit-pyvis` requires `--build-schema-db`; reproto exits with a clear
   error if `--build-schema-db` is absent.

---

## Non-goals

- Keeping any midas-specific filtering logic.
- Supporting `--emit-pyvis` without `--build-schema-db`.
- Notebook / IFrame output mode.
- Pagination or filtering of large graphs (the user controls graph size
  via `--seed` / `--prune`).

---

## Specification

### §83.1 — CLI rename

Rename `--graph` to `--emit-pyvis` everywhere:

- `cli.py`: option name, `SECTION_MAP` key, `output_only_mode` reference,
  parameter name in the command function signature.
- `reproto.py`: call site `ctx.graph` → `ctx.emit_pyvis`.
- `context.py`: attribute `graph` → `emit_pyvis`.
- Help text: `'Write scoring-graph visualisations to FILE and
  FILE-hopcroft (HTML/pyvis format); requires --build-schema-db'`.

### §83.2 — `build_graph()` API extension

Add `emit_initial_yaml: bool = False` to `build_graph()`:

```python
build_graph(
    scoring_graphs,
    emit_yaml=False,
    emit_initial_yaml=False,
    on_progress=None,
) -> tuple[bytes, str | None, str | None]
```

- `emit_yaml=True` — return compiled YAML of the **minimised** graph
  (post-Hopcroft) as the second element; unchanged from today.
- `emit_initial_yaml=True` — return compiled YAML of the **raw** graph
  (post-merge, pre-Hopcroft) as the third element.
- Both flags are independent.  When `False`, the corresponding element
  is `None`.

The compiled YAML format is the same in both cases (`states` /
`transitions` / `roots`), produced by `dump_compiled()`.  For the initial
graph, `dump_compiled()` is called on the `CompiledGraph` built before
Hopcroft runs; for the minimised graph, after.

On the Rust side, `build_from_strings()` gains a matching
`emit_initial_yaml: bool` parameter and returns
`(Vec<u8>, Option<String>, Option<String>)`.

When `--emit-pyvis` is set, `_phase_build_schema_db` calls `build_graph()`
with both `emit_yaml=True` and `emit_initial_yaml=True`.

### §83.3 — Single render function, called twice

Both compiled YAMLs share the same `states`/`transitions`/`roots` format.
`show.py` exposes one public function:

```python
def render_scoring_graph(
    compiled_yaml: str,    # states/transitions/roots format
    output_path: Path,
    title: str,
    node_colour: str,      # message-state node fill colour
) -> None:
```

Called twice from `_phase_build_schema_db`:

1. Pre-Hopcroft: `compiled_yaml` = `initial_yaml` from `build_graph()`,
   `output_path` = `foo.html`, `node_colour` = `#97fc9a` (green).
2. Post-Hopcroft: `compiled_yaml` = `compiled_yaml` from `build_graph()`,
   `output_path` = `foo-hopcroft.html`, `node_colour` = `#aaaaff` (blue).

The function parses the YAML with `yaml.safe_load()` and builds a pyvis
`Network` with `cdn_resources='in_line'`, `directed=True`,
`bgcolor="#222222"`.  Calls `barnes_hut()` and applies the physics options
from §83.6.  Does **not** call `set_template`.

**Compiled YAML format** (`states`/`transitions`/`roots`):

```yaml
states:
  - id: 0          # integer state ID
    wire_type: 2   # 0=varint, 1=i64, 2=len, 5=i32
    is_string: false
    enum_range: null  # or [min, max] for enum states
transitions:
  - from: 0
    field: 1       # field number
    label: optional  # optional / repeated / packed
    to: 1
roots:
  - fqdn: SomeMessage
    state: 0
```

**Node rendering:**

Each state in `states` becomes one node.  States that appear as `to`
targets of transitions but have no outgoing transitions are **leaf
states** (wire-type sinks).

| Kind | Shape | Colour | Size | Label |
|---|---|---|---|---|
| Non-leaf state | `dot` | `node_colour` | 20 | state `id` |
| Leaf state (wire_type=0) | `square` | `#ffcc44` | 12 | `varint` |
| Leaf state (wire_type=1) | `square` | `#ffcc44` | 12 | `i64` |
| Leaf state (wire_type=2, is_string=false) | `square` | `#ffcc44` | 12 | `len` |
| Leaf state (wire_type=2, is_string=true) | `square` | `#ff8844` | 12 | `string` |
| Leaf state (wire_type=5) | `square` | `#ffcc44` | 12 | `i32` |

Node tooltip = comma-separated list of FQDNs from `roots` that map to
this state (empty string if none).

**Edge rendering:**

Each entry in `transitions` becomes one directed edge from `from` to `to`.
Edge label: `f{field}`.  Edge colour by `label`:

| label | Colour |
|---|---|
| `optional` | `#4444ff` |
| `repeated` | `#44aaff` |
| `packed` | `#884488` |

### §83.4 — (removed)

Merged per-file YAML approach superseded by `emit_initial_yaml`.

### §83.5 — `show.py` rewrite

Remove all midas-specific code (`FOI`, `is_in`, `show_graph`).  Replace
with `render_scoring_graph` (§83.3) and a private helper:

```python
def _make_network(title: str) -> Network:
    """Create a pyvis Network with shared settings."""
```

that constructs the `Network(cdn_resources='in_line', ...)`, sets the
HTML page title to `title`, calls `barnes_hut()`, and applies the physics
options from §83.6.

### §83.6 — Physics options

Both graphs use Barnes-Hut with:

```json
{
  "physics": {
    "enabled": true,
    "barnesHut": {
      "gravitationalConstant": -8000,
      "centralGravity": 0.3,
      "springLength": 100,
      "springConstant": 0.04,
      "damping": 0.09,
      "avoidOverlap": 1
    },
    "minVelocity": 0.75
  }
}
```

(Same settings as the current `show.py`.)

### §83.7 — Error handling

If `--emit-pyvis` is given without `--build-schema-db`, reproto prints:

```
--emit-pyvis requires --build-schema-db
```

and exits with a non-zero status before any processing begins.

If `pyvis` is not importable, reproto prints a clear error and exits.

---

## Files changed

- `reproto/src/reproto/cli.py` — rename `--graph` → `--emit-pyvis`
- `reproto/src/reproto/context.py` — rename attribute `graph` → `emit_pyvis`
- `reproto/src/reproto/reproto.py` — update call site
- `reproto/src/reproto/phases.py` — pass `emit_yaml=True,
  emit_initial_yaml=True` when `--emit-pyvis` is set; call
  `render_scoring_graph` twice with `initial_yaml` and `compiled_yaml`
- `scoring-graph-pyo3/src/lib.rs` — add `emit_initial_yaml` parameter to
  `build_graph()`
- `scoring-graph/src/build_scoring_graph/mod.rs` — add
  `emit_initial_yaml` to `build_from_strings()`
- `reproto/src/reproto/show.py` — full rewrite

---

## References

- Spec 0044 §5 — original scoring-graph visualisation spec (Python prototype)
- Spec 0045 §2 — per-file scoring-graph YAML format
- `reproto/src/reproto/show.py` — current (broken) implementation
- `scoring-graph-pyo3/src/lib.rs` — `build_graph()` PyO3 binding
