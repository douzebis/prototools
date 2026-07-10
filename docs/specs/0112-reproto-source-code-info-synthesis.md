<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0112 — reproto: synthesize `SourceCodeInfo` during decompilation

**Status:** draft
**Refs:** `docs/specs/0111-protolens-v1-decode-navigate-extract.md` (Open
Issue 5, Phase 5 — "Type definition assistance")
**App:** reproto

---

## Background

`reproto` decompiles *stripped* `FileDescriptorProto`s (no
`SourceCodeInfo`, since it's typically dropped from the descriptor sets
`reproto` receives) into `.proto` source text. Today's `.proto` output has
no location index tying a declaration (message, field, enum value, ...)
back to a `[line, column]` span in the emitted text — because there's
nothing to derive it from other than `reproto`'s own emission logic.

`reproto` does already have machinery that *consumes* `SourceCodeInfo` when
it happens to be present on the input (`reproto/src/reproto/source_info.py`,
`SourceCodeInfoMixin`): given a node, it computes the node's `path` (a
`google.protobuf.SourceCodeInfo.Location.path`-shaped list of field-number/
index pairs walked from the file root, e.g. `[4, <message index>]` for a
top-level message) and looks up any comments attached at that path. This
confirms `path` computation for arbitrary declaration nodes is already a
solved problem in `reproto` — what's missing is the *emission* side:
producing `Location` entries (a `path` plus a `span`) that describe
`reproto`'s own output, not a hypothetical `protoc`-recompiled one.

This spec is spun out of spec 0111's Open Issue 5: `protolens`'s planned
"type definition assistance" pane (Phase 5) wants to jump straight to a
type's declaration in its `.proto` file, including declarations reached
through import chains — the classic use for `SourceCodeInfo`. The
alternative considered in spec 0111 — recompiling the decompiled `.proto`
files with `protoc --include_source_info` to obtain this — was rejected
there as unnecessarily heavy (a full extra `protoc` invocation) and
carrying a nonzero (if unlikely) risk that the recompiled descriptor
diverges from the originally captured bytes. Having `reproto` synthesize
`SourceCodeInfo` itself, as a byproduct of decompilation it's already
doing, avoids both problems.

---

## Goals

1. `reproto` can optionally emit a `SourceCodeInfo` (as part of a
   `FileDescriptorProto`, in the same shape `protoc --include_source_info`
   would produce for the `.proto` text `reproto` itself wrote) alongside
   its normal `.proto` text output.
2. Each `Location.span` is accurate against the `.proto` text `reproto`
   actually wrote for that declaration — not an approximation, and not
   dependent on any external tool re-parsing the output.
3. This is additive: existing decompile behavior and output are unchanged
   unless the new synthesis is explicitly requested (e.g. a new flag).
4. Where `SourceCodeInfoMixin`'s existing comment-consumption logic already
   attaches `leading_comments`/`trailing_comments` from an *input*
   `SourceCodeInfo` (a rarer case — most inputs are stripped, but not
   never), synthesis must not lose or corrupt those when producing the
   *output* `SourceCodeInfo` — a declaration's original comments (if any)
   should still resolve correctly against the new spans.

## Non-goals

- The `protolens`-side consumption of this data (in-pane viewer, import
  navigation, `$EDITOR` fallback) — that's spec 0111 Phase 5's concern, not
  this spec's.
- Column-level (as opposed to line-level) precision beyond what's cheaply
  available from `reproto`'s own text-building — see Open Issues.
- Recompiling via `protoc` in any form — the explicit point of this spec is
  to avoid that path entirely.

---

## Specification (sketch — to be firmed up before implementation)

`reproto`'s text-building model (`reproto/src/reproto/text.py`) already
represents output as a sequence of `Block`/`BlockLine` objects, flushed to
a final string by `Block.flush()`, which iterates lines in order and
tracks nothing beyond current indentation. The natural extension:

- While flushing (or in an instrumented variant of `flush()`), track the
  1-based output line number reached after each `BlockLine` is written.
- Each `Block`/`BlockLine` sequence that represents one declaration's
  emitted text (e.g. the lines making up a `message Foo { ... }` block) is
  already associated, at construction time, with the node that produced
  it. Correlate that node's `_calculate_source_code_info_path()` (already
  implemented, `source_info.py`) with the `[start_line, end_line]` (or
  `[start_line, start_col, end_line, end_col]`, pending Open Issue 1 below)
  range the flush pass recorded for its lines, and emit one
  `SourceCodeInfo.Location` per declaration.
- Assemble the resulting `Location` list into a `SourceCodeInfo` and attach
  it either (a) to a full `FileDescriptorProto` mirroring what `protoc
  --include_source_info` would produce, written as a sidecar `.desc` file,
  or (b) some other output shape — undecided, see Open Issues.

---

## Open Issues and Challenges

1. **Span granularity**: `protoc`'s `SourceCodeInfo.Location.span` is
   `[start_line, start_column, end_line, end_column]` (0-based). `reproto`'s
   `Block`/`BlockLine` model tracks lines, not columns, today — column
   tracking would need each `BlockLine`'s rendered text length taken into
   account (indentation + text), which is mechanical but not yet
   implemented. Decide whether line-only spans (a 3-element span,
   `[start_line, end_line]`-equivalent, technically non-conformant with
   `protoc`'s own format but likely sufficient for `protolens`'s
   "jump to declaration" use case) are an acceptable v1 for this feature,
   with column precision as a later refinement.
2. **Output shape**: emit a full `FileDescriptorProto` with
   `source_code_info` populated (maximally compatible with anything
   expecting `protoc --include_source_info`-shaped input, e.g. potential
   future non-`protolens` consumers), vs. a lighter, `reproto`-specific
   sidecar format (e.g. a `path -> span` map) if the full
   `FileDescriptorProto` re-emission is itself nontrivial or heavy. Leaning
   towards the `FileDescriptorProto` shape for compatibility, but not
   decided.
3. **Comment interaction** (Goal 4): needs a concrete test case where the
   input `FileDescriptorProto` already carries `SourceCodeInfo` (comments)
   to verify the synthesized output doesn't disagree with
   `SourceCodeInfoMixin`'s existing path-based comment lookup — e.g. that
   both consult the same `path` computation and don't drift.
4. **Which nodes get a `Location`**: full parity with `protoc`'s own output
   (every field, enum value, oneof, etc., not just top-level
   messages/enums) vs. a pragmatic subset covering what `protolens`'s
   Phase 5 pane actually needs first. Leaning towards starting with the
   subset `protolens` needs (types, fields) and expanding later if useful
   elsewhere, but not decided.
5. **Performance**: whether tracking line/column state through `flush()`
   for every decompile run (even when synthesis isn't requested) has a
   measurable cost — should be zero-cost when the feature isn't invoked;
   not yet measured since no implementation exists.

---

## Files changed (anticipated)

| File | Change |
|---|---|
| `reproto/src/reproto/text.py` | `Block.flush()` (or a new instrumented variant): track output line (and possibly column) reached per `BlockLine` |
| `reproto/src/reproto/source_info.py` | New: emit `SourceCodeInfo.Location` entries from tracked spans + existing `_calculate_source_code_info_path()` |
| `reproto/src/reproto/cli.py` | New flag to opt into synthesis + sidecar output (exact name/shape TBD) |
