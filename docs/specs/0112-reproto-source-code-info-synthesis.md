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

## Feasibility investigation (2026-07-10)

Findings from reading `reproto`'s actual rendering code
(`re_file.py`, `re_descriptor.py`, `re_field.py`, `text.py`,
`context.py`), confirming the sketch above and resolving several Open
Issues below with evidence rather than guesswork:

1. **`BlockLine`-to-final-line mapping is 1:1, no flush()-time
   instrumentation needed.** `MAX_LINE_LENGTH`-driven wrapping (e.g. long
   method signatures in `re_method.py`, long option lists in
   `simple_types.py`) happens *at construction time* — a wrapped
   declaration becomes multiple `BlockLine`s up front, not one `BlockLine`
   later split by `flush()`. `Block.flush()` itself does no
   splitting/merging; it only conditionally *drops* `COMMENT`/`ORPHAN`
   lines (`ctx.redact_comments`/`ctx.redact_orphans`, both default
   `False`). So — as long as redaction is off — `len(out.lines)` at any
   point during the `render()` tree walk already equals the final
   (1-based) flushed line number of whatever gets appended next. This
   **simplifies the design**: spans can be computed directly during the
   existing top-down `render()` walk (record `len(out.lines)` before and
   after each child's `out.extend(child_block)` call), with no need to
   instrument `Block.flush()` separately as originally sketched.
2. **There is direct architectural precedent for this pattern.**
   `re_file.py`'s `render()` already threads an optional side-channel
   (`ctx.out_desc: DescOut | None`, spec 0076) through the whole render
   tree, populated in parallel with the text `Block` without changing any
   `render()` method's signature or return type. A `ctx.out_sci:
   SourceCodeInfoOut | None` slot, appending one `Location` per node as
   each `render()` call returns, is a straightforward extension of an
   already-proven mechanism — not a new architectural pattern.
3. **Redaction is the one real correctness hazard**, confirming and
   sharpening Open Issue (below, "Redaction interaction"): if
   `--redact-comments`/`--redact-orphans` are combined with synthesis, the
   line-count-during-construction no longer matches the flushed output
   (dropped lines shift everything after them). Synthesis must either be
   rejected when combined with those flags, or computed post-flush instead
   of during the walk in that specific combination.
4. **Output re-ordering is a non-issue, not a risk.** `re_descriptor.py`'s
   `render()` docstring documents that `reproto` emits elements in a
   *static, protoc-descriptor order* (all fields grouped, then nested
   messages, then nested enums, ...), not necessarily the original
   `.proto` source order. This does not threaten the design: the
   synthesized `SourceCodeInfo` describes spans in `reproto`'s *own*
   emitted text, not a claim about the original source file's order — so
   internal self-consistency (which is guaranteed by construction) is all
   that's required, not fidelity to some other ordering.
5. **`_calculate_source_code_info_path()` currently only covers message
   declarations** (`source_info.py`: path segments `[4, idx]` for
   top-level `message_type`, `[3, idx]` for `nested_type`). Full Goal-4
   coverage (fields, enums, enum values, oneofs, services, methods,
   extensions) needs this extended with the corresponding
   `FileDescriptorProto`/`DescriptorProto`/`EnumDescriptorProto`/
   `ServiceDescriptorProto` field numbers (`field=2`, `enum_type=4/5`,
   `service=6`, `extension=6/7`, `oneof_decl=8`, `method=2`, ...) — a
   larger, mechanical but nontrivial extension of existing code, not
   something to gloss over as "already solved" (correcting the Background
   section's slightly optimistic framing).
6. **`SourceCodeInfo` carries no file identity — and that's fine, because
   `FileDescriptorProto.name` already is a relative import path.**
   Checked the actual protobuf schema:
   `SourceCodeInfo` only has `repeated Location location`, and `Location`
   only has `path`, `span`, `leading_comments`, `trailing_comments`,
   `leading_detached_comments` — no file-path field anywhere. This is by
   design: `SourceCodeInfo` only ever exists as the `source_code_info`
   field *of* a specific `FileDescriptorProto`, so "which file" is
   established purely by containment. The relevant identity,
   `FileDescriptorProto.name`, is confirmed (by `reproto`'s own code) to
   already be the canonical, *relative* import-style path — never an
   absolute filesystem path:
   ```python
   # reproto/src/reproto/phases.py:1377-1378
   canonical_name = canonize_dependency(ctx, re_fdp.name)
   res_path = out_repo / Path(canonical_name)
   ```
   `reproto` writes each decompiled file to `<-O root>/<canonical relative
   name>` (e.g. `out_repo/google/protobuf/descriptor.proto`). So the
   "relative path + resolve the root just in time" model `protolens` wants
   is already exactly how the system works, today, with zero design change
   needed here: `protolens` has `FileDescriptorProto.name` from its own
   `--descriptor-set` corpus, and can independently choose, at runtime,
   whatever root directory the matching decompiled `.proto` tree lives
   under (typically wherever `reproto -O` wrote it) — the join is a plain
   path concatenation, entirely decoupled from the `SourceCodeInfo`
   mechanism itself.

## Specification (sketch — updated per feasibility investigation above)

- Add a `ctx.out_sci: SourceCodeInfoOut | None` side-channel, mirroring
  `ctx.out_desc`/`DescOut` (spec 0076) exactly: an optional mutable slot
  passed through the existing `render()` call tree, appended to (not
  restructuring any `render()` signature) when non-`None`.
- At each `render()` call site that currently does
  `out.extend(child_block)` for a node with a computable
  `_calculate_source_code_info_path()`, if `ctx.out_sci` is set: record
  `start_line = len(out.lines)` before the extend, `end_line =
  len(out.lines) - 1` after, and append a `SourceCodeInfo.Location(path=...,
  span=[start_line, end_line])` (extending to 4-element column spans is a
  later refinement — Open Issue 1).
- Guard against the redaction hazard (finding 3, above): reject the
  combination of synthesis with `--redact-comments`/`--redact-orphans` (or
  fall back to a slower post-flush line-counting pass in that case — TBD,
  see Open Issues).
- Extend `_calculate_source_code_info_path()` (or add sibling helpers) to
  cover the full node taxonomy needed for Goal 4 coverage, not just
  message declarations (finding 5, above).
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
5. **Performance**: resolved by the feasibility investigation for the
   common case — span tracking piggybacks on the existing `render()` walk
   (`len(out.lines)` snapshots), no separate pass or `flush()`
   instrumentation, so it should be close to zero-cost when
   `ctx.out_sci is None` (the default) and cheap when enabled. Not yet
   measured since no implementation exists, but no structural reason to
   expect a meaningful cost.
6. **Redaction interaction**: `--redact-comments`/`--redact-orphans`
   invalidate the "line count during construction equals final flushed
   line count" assumption the design relies on (finding 3, above) — needs
   a decision: reject the flag combination, or fall back to a slower
   post-flush counting pass when redaction is active.
7. **`_calculate_source_code_info_path()` coverage gap**: today only
   handles message declarations (finding 5, above); extending it to
   fields/enums/enum-values/oneofs/services/methods/extensions is real,
   non-trivial work, not a given — scope this explicitly against Open
   Issue 4 ("which nodes get a `Location`") rather than assuming it's
   free.
8. **File-path resolution for `protolens`'s consuming side** — resolved,
   no action needed here (finding 6, above): `SourceCodeInfo` never
   encodes a file path; `FileDescriptorProto.name` already is the
   relative, canonical import path, and `reproto` already lays out
   decompiled files on disk under that same relative path beneath
   whatever `-O` root the caller chooses. `protolens` (spec 0111 Phase 5)
   can join `name` with any root it picks at runtime — no coupling to this
   spec's synthesis work, and no open question left on this point.

---

## Files changed (anticipated)

| File | Change |
|---|---|
| `reproto/src/reproto/context.py` | New `SourceCodeInfoOut` dataclass + `ctx.out_sci` slot, mirroring `DescOut`/`ctx.out_desc` (spec 0076) |
| `reproto/src/reproto/re_file.py`, `re_descriptor.py`, `re_field.py`, `re_enum.py`, `re_service.py` | At each `render()` call site building a child's `Block`: snapshot `len(out.lines)` before/after, append a `Location` to `ctx.out_sci` when set |
| `reproto/src/reproto/source_info.py` | Extend `_calculate_source_code_info_path()` (or add siblings) to cover the full node taxonomy needed for Goal 4 (Open Issue 7) |
| `reproto/src/reproto/cli.py` | New flag to opt into synthesis + sidecar output (exact name/shape TBD); reject combination with `--redact-comments`/`--redact-orphans` per Open Issue 6, or implement the fallback |
