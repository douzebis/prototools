<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0085 — Graph option renames: `--emit-scoring-yaml` / `--emit-scoring-html`

**Status:** implemented
**Implemented in:** 2026-05-25
**App:** reproto

---

## Background

reproto currently has two graph-related output options:

| Option | Output | Format |
|---|---|---|
| `--emit-scoring-graphs` | per-file scoring-graph YAML alongside `.proto` output | YAML |
| `--emit-pyvis FILE` | raw + Hopcroft scoring graph HTML visualisation | HTML |

The name `--emit-pyvis` exposes the implementation library (pyvis) rather
than the concept, and gives no hint of the output format.  `--emit-scoring-graphs`
uses `-graphs` (plural) as an awkward stand-in for "YAML files".

A future option `--emit-closure-html FILE` (not in scope here) will render
the FQDN dependency graph — seeds, summoned nodes, bridge imports — as an
interactive HTML visualisation.  Having two HTML graph options makes the
format/concept distinction important: a consistent `--emit-<concept>-<format>`
naming scheme avoids ambiguity now and leaves room for the future option.

---

## Goals

1. Rename `--emit-scoring-graphs` → `--emit-scoring-yaml`.
2. Rename `--emit-pyvis` → `--emit-scoring-html`.
3. Update all references in Python source, tests, and spec files.
4. Keep old names as hidden deprecated aliases so existing scripts do not
   break silently (emit a deprecation warning to stderr).

---

## Non-goals

- Implementing `--emit-closure-html` (future spec).
- Changing the behaviour or output of either option.
- Renaming internal Python identifiers beyond what is needed for clarity
  (e.g. `emit_scoring_graphs` in `Options` / `Context` is an internal name
  and may be renamed or left as-is at implementation discretion).

---

## Specification

### §85.1 — `--emit-scoring-yaml` (was `--emit-scoring-graphs`)

- CLI option: `--emit-scoring-yaml` (is_flag=True).
- Old name `--emit-scoring-graphs` kept as a hidden alias; when used, prints
  to stderr: `warning: --emit-scoring-graphs is deprecated; use --emit-scoring-yaml`.
- Help text (updated): `'Write per-file scoring-graph YAML files alongside
  .proto output under --output-root'` (unchanged in meaning).
- `_SECTIONS` key updated.
- Internal Python attribute `ctx.emit_scoring_graphs` may be renamed to
  `ctx.emit_scoring_yaml` or kept as-is.

### §85.2 — `--emit-scoring-html` (was `--emit-pyvis`)

- CLI option: `--emit-scoring-html FILE` (path, same semantics as `--emit-pyvis`).
- Old name `--emit-pyvis` kept as a hidden alias; when used, prints to stderr:
  `warning: --emit-pyvis is deprecated; use --emit-scoring-html`.
- Help text (updated): `'Write scoring-graph HTML visualisations to FILE
  (raw) and FILE-hopcroft (Hopcroft-minimised); requires --build-schema-db'`.
- `_SECTIONS` key updated.
- Internal Python attribute `ctx.emit_pyvis` renamed to `ctx.emit_scoring_html`.
- `output_only_mode` check updated.

### §85.3 — Companion options

`--with-leaf-nodes` and `--hide` are companions to `--emit-scoring-html`
(formerly `--emit-pyvis`).  Their names are unaffected.

### §85.4 — Future option (rationale, not implemented here)

`--emit-closure-html FILE` will render the FQDN dependency graph: which
nodes are seeds, which are summoned (reachable from seeds), which are bridge
imports (summoned only to keep the import chain compilable).  Pruned nodes
do not appear (they were excluded before the graph is built).  Edge colours
distinguish summon edges from bridge edges.  This option is not implemented
in this spec; it is listed here to confirm that the naming scheme
accommodates it without further renames.

---

## Files changed

- `reproto/src/reproto/cli.py` — rename options, add hidden aliases,
  add deprecation warnings, update `_SECTIONS`, `output_only_mode`,
  and `main()` signature
- `reproto/src/reproto/context.py` — rename `emit_pyvis` → `emit_scoring_html`
  (and optionally `emit_scoring_graphs` → `emit_scoring_yaml`)
- `reproto/src/reproto/reproto.py` — update attribute references
- `reproto/src/reproto/phases.py` — update attribute references
- `reproto/src/reproto/tests/test_roundtrip.py` — update `--emit-scoring-graphs`
  to `--emit-scoring-yaml`
- `reproto/src/reproto/tests/test_emit_scoring_graphs.py` — rename file and
  update option strings
- `docs/specs/0083-emit-pyvis.md` — note rename in a postscript
- `docs/specs/0084-pyvis-hide.md` — update option name references

---

## References

- Spec 0045 — original `--emit-scoring-graphs` specification
- Spec 0083 — `--emit-pyvis` implementation
- Spec 0084 — `--hide` companion option
