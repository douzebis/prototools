<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0111 — `protolens` v1: decode / navigate / extract

**Status:** draft
**Refs:** `docs/specs/0109-protolens-interactive-schema-inference.md`,
`docs/specs/0110-render-sink-unification.md`
**App:** protolens (new)

---

## Background

Spec 0109 laid out `protolens`'s full envisioned scope (interactive TUI,
per-node and per-field-number type override, candidate ranking via
`score_all`, unlimited undo, save-project/export-`.desc`). This spec narrows
to the first concretely buildable slice — **decode, navigate, extract a
node's raw bytes** — deferring everything else in spec 0109's design to
future work.

This slice depends on spec 0110's `IndexingTextSink` (a byte-offset index
pairing each rendered node with its raw byte range in the source protobuf,
its byte range in the rendered text, and its indentation level) and on
`decode_and_render`'s new `initial_level`/`emit_header` parameters. Spec 0110
is a hard prerequisite: this spec cannot start implementation until it lands.

---

## Goals

1. New Rust binary crate `protolens`, workspace member, depending on
   `prototext-core` in-process (no subprocess/FFI), per spec 0109's
   high-level design.
2. **Decode**: given a byte blob and a root `MessageDescriptor` (specified by
   the user at startup — v1 requires an explicit `--type`, no automatic
   best-guess ranking), render it via `IndexingTextSink`, producing both the
   rendered text and its offset index.
3. **Navigate**: `ratatui` + `crossterm` TUI. Arrow/`hjkl` cursor movement
   between index entries' start lines. Fold/unfold a subtree using its
   index-derived `[start_line, end_line]` span (folding collapses the range
   to a single summary line; per spec 0109, fold state is pure UI state, not
   undoable).
4. **Extract**: for the node under the cursor, use its `raw_range` to obtain
   the corresponding byte sub-slice of the source blob, and expose it (write
   to a file, or print to a status/output area) — enough for the user to
   independently feed it to another tool (e.g. `prototext decode --type X`)
   to test a hypothesis about its type. `protolens` itself does not re-decode
   or re-splice anything in v1 (see Non-goals).

## Non-goals

- Type override UI, candidate-ranking (`score_all` integration), unlimited
  undo, save-project/export-`.desc` — all remain future work per spec 0109's
  fuller design (its goals 3–7 are unimplemented after this spec).
- Automatic best-guess root-type selection (`list-schemas`-style ranking) at
  startup.
- In-place splice-and-replace of a node's rendering after a manual re-decode
  — even though spec 0110's initial-level parameter and `IndexingTextSink`'s
  index shape are deliberately designed to support this later, v1 stops at
  extracting raw bytes. Splicing a re-rendered replacement into the composite
  view and re-indexing the replaced subtree is deferred to the spec that
  introduces interactive override.
- Any change to `prototext-core`/`render_text` — spec 0110 is a fixed
  prerequisite, not something this spec revises.

---

## Specification

### §1 — `protolens` crate structure (v1)

New workspace member, binary crate:

```
protolens/
  Cargo.toml           — depends on prototext-core, prototext-graph, ratatui, crossterm
  src/
    main.rs             — CLI entry: blob path, --type <FQDN>, descriptor-set path(s)
    decode.rs            — thin wrapper: load blob + schema, call decode_and_render
                            with an IndexingTextSink, hand back (text, Vec<NodeSpan>)
    tui.rs                — ratatui app: render text pane, cursor/fold state, key handling
    extract.rs             — "extract" action: NodeSpan.raw_range -> byte slice -> file/stdout
```

No project-file format, no undo stack, no override picker in v1 — those land
with the spec that introduces interactive override (per Non-goals).

### §2 — v1 TUI interaction

- Arrow keys / `hjkl`: move cursor between `NodeSpan` start lines (sibling/
  parent/child navigation derived from index containment, per spec 0110 §3).
- `+`/`-` (or `zo`/`zc`-style): fold/unfold the node under the cursor, using
  its `text_range`-derived `[start_line, end_line]` — pure UI state, not part
  of the index/undo model (matches spec 0109 §"Navigation").
- An extract key/command (exact binding TBD during implementation, e.g. `x`
  or `:extract <path>`): writes the byte slice at the cursor node's
  `raw_range` to a user-specified file, or prints it (hex or base64, TBD) to
  a status area.

---

## Open Issues and Challenges

1. **v1's root-type input**: CLI flag only (`--type <FQDN>`), or a minimal
   startup schema-picker screen — leaning CLI-flag-only for v1, deferring any
   picker UI.
2. **Extract action's output format**: raw bytes to a file path, vs.
   hex/base64 to a status area, vs. both — not decided.
3. **`NodeSpan` shape**: spec 0110 leaves open whether emission-order
   `Vec<NodeSpan>` (relying on containment for structure) is sufficient for
   this spec's navigate/fold/unfold logic, or whether an explicit
   `parent_index` field is needed — to be settled once this spec's TUI
   navigation logic is actually implemented.

---

## Files changed (anticipated)

| File | Change |
|---|---|
| `protolens/` (new crate) | `Cargo.toml`, `src/main.rs`, `src/decode.rs`, `src/tui.rs`, `src/extract.rs` |
| `Cargo.toml` (workspace root) | Add `protolens` member |
