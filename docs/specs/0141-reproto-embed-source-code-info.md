<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0141 — reproto: embed synthesized SourceCodeInfo in crafted descriptor output

Status: implemented
Implemented in: 2026-07-17 (Step 1 — G1/G4/G5/G6/G7; Step 2 — G2/G3/G8)
Refs: docs/specs/0112-reproto-source-code-info-synthesis.md (superseded by
      this spec — feasibility investigation and `ctx.out_sci` sketch
      absorbed and refined here), docs/specs/0076-render-pb-for-descriptor-desc.md
      (amended by this spec — the `source_code_info` "omitted (intentional)"
      Non-goal and field-coverage row become conditional), docs/specs/0111-protolens-v1-decode-navigate-extract.md
      (Phase 5, "Type definition assistance" — protolens-side consumption,
      explicitly out of scope here), docs/specs/0068-lazy-fds-index.md
      (`index.rkyv` co-regeneration — unaffected coupling), `reproto/src/reproto/source_info.py`
      (`SourceCodeInfoMixin` — existing consumption-only path-computation
      logic, extended by this spec), `reproto/src/reproto/re_file.py`
      (`ReFileDescriptorProto.render()` — two-pass structure this spec's
      design depends on)
App: reproto

---

## Background

`reproto` decompiles (typically already-stripped) `FileDescriptorProto`s
into `.proto` source text, and — via spec 0076's `ctx.out_desc` side
channel — can also *craft* a matching binary `FileDescriptorProto`/`Set`
for `-b/--emit-binary` and `--schema-db-out`. That crafted binary output
today always strips `source_code_info`
(`re_file.py`: `fdp_out.ClearField('source_code_info')`), on the stated
rationale (spec 0076 Non-goals) that round-tripping it is "not meaningful
in a binary descriptor" — true for *round-tripping* an original
`SourceCodeInfo` (reproto's inputs are usually already stripped, so there
is nothing to round-trip), but leaves an opportunity on the table:
`SourceCodeInfo` describing reproto's *own emitted* `.proto` text is fully
knowable, since reproto controls that emission.

Spec 0111 (protolens) frames the target use case: a "type definition
assistance pane" that, given a message (or field, or enum) descriptor
encountered while decoding a wire message, shells out to `$EDITOR` at the
declaration's source location. Spec 0111 explicitly defers the mechanism
by which that source location becomes available to "its own design pass
in `reproto`'s spec lineage" — this spec is that design pass. protolens's
own consumption of the data (spawning `$EDITOR`, in-pane preview, etc.)
remains out of scope; see Non-goals.

Spec 0112 sketched this exact feature previously (draft, never
implemented) and did the initial feasibility legwork: it confirmed
`Block.flush()` (the text-assembly primitive) does no line splitting or
merging — it only ever *drops* whole lines (`COMMENT`/`ORPHAN` lines,
under `--redact-comments`/`--redact-orphans`) — so a line count taken
during construction equals the final flushed line count, *except* when
those redaction flags are active. This spec supersedes 0112, folding that
finding in along with one further structural discovery made while
investigating the actual `render()` call graph (see below), and refines
0112's open issues into concrete decisions.

### The two-pass `render()` structure

`ReFileDescriptorProto.render(ctx)` (`re_file.py`) does not build text and
binary output in the same pass. It:

1. Builds the actual `.proto` **text** output first (appending to the
   `out: Block` being returned) — this is the only pass that runs when
   `ctx.out_desc` is `None` (plain `.proto` emission, the common case).
2. Only if `ctx.out_desc is not None`, runs a **second**, separate pass
   that re-invokes each child's `render(ctx, ...)` a second time with a
   fresh nested `DescOut` slot, purely to reconstruct the binary
   descriptor tree. The `Block` returned by these second calls is
   discarded — only the side-channel `DescOut.out` is kept.

This matters because `SourceCodeInfo.Location.span` values must be line
numbers in the *final emitted text* — which is only fully known once the
first (text) pass has completed for the enclosing scope. Span computation
must therefore happen during the **first** pass (snapshotting
`len(out.lines)` before/after each child's text is appended, as 0112
proposed), and be *consumed* by the **second** pass when it assembles
`fdp_out.source_code_info`. This means the recorded spans must be threaded
from the first pass into the second pass — they cannot be recomputed fresh
during the second pass, because the second pass's own line-count
bookkeeping is against a `Block` that is thrown away.

### Update-radius findings (resolving "I don't have a clear view of the
update radius")

Investigation of the actual code establishes a narrow, well-bounded
change surface:

- **Exactly one call site gates the feature end-to-end**:
  `fdp_out.ClearField('source_code_info')` in `re_file.py`'s
  `render()`, second pass. Since `ctx.out_desc` already feeds *both*
  `-b/--emit-binary` and `--schema-db-out` (spec 0076's shared
  architecture), making this one call site conditional wires the feature
  into both output modes simultaneously — no separate plumbing needed per
  output mode.
- **Span computation touches many `render()` methods**, one per node kind
  that gets a `path` entry: `re_file.py` (file-level bookkeeping),
  `re_descriptor.py` (messages, nested messages — Step 1), `re_field.py`
  (fields, including extension fields, which share the same render()
  call site — Step 2), `re_enum.py`/`re_enum_value.py` (enums — Step 2),
  `re_service.py`/`re_method.py` (services/methods — Step 2). Each needs
  a snapshot-before/snapshot-after wrapper around its text-emission call,
  writing a `Location` into the new `ctx.out_sci` side channel.
- **`hopcroft.rkyv`/`wkt.rkyv` (compiled scoring graph) is unaffected.**
  It is built by `_phase_emit_scoring_graphs`, a wholly separate
  YAML-based code path that never touches `ctx.out_desc` or binary
  `FileDescriptorProto`s.
- **`index.rkyv`/`wkt_index.rkyv` (spec 0068's byte-span index into
  `descriptor.desc`) has its span *values* shift** (each FDP grows once
  `source_code_info` is populated, moving subsequent byte offsets), but
  is always regenerated in the same pass as `descriptor.desc` already
  (spec 0068), so there is no extra coupling risk — this is an expected,
  self-consistent side effect, not a new hazard. The index's *file size*
  is expected to be materially unchanged, since its records are
  fixed-width `(u64, u64)` offset pairs regardless of the underlying
  `.desc` file's size.
- **Zero Rust-side changes are required.** `prototext/src/lazy_pool.rs`
  (grepped for `source_code_info|ClearField|clear_source|strip`) performs
  no stripping — once reproto stops omitting the field, it becomes
  available to any Rust consumer (e.g. a future protolens feature) with
  no `prototext`/`protolens` code changes.

---

## Goals

Implementation is phased (see "Phasing" below); all node kinds share the
same `path`/`span` mechanism (Specification), so phasing is purely about
sequencing, not separate designs.

- **G1 (required, main goal, Step 1).** Synthesize `SourceCodeInfo.Location`
  entries for **message declarations** (top-level and nested) in crafted
  binary `FileDescriptorProto`/`Set` output: `path` (per the existing
  `SourceCodeInfoMixin._calculate_source_code_info_path()` convention) and
  a **protoc-compatible `span`** (line *and column* precision — see
  "Span computation"; reproto has full knowledge of its own emitted
  text's indentation and line composition, so there is no technical
  barrier to column precision, and it is included from Step 1, not
  deferred).
- **G2 (Step 2).** Extend synthesis to **enum declarations** (top-level
  and nested), reusing the same path/span mechanism.
- **G3 (Step 2).** Extend synthesis to **field declarations** — message
  fields, enum values, and extension fields (`extend Foo { ... }` blocks,
  file-level and nested). Extension fields use the exact same
  `ReFieldDescriptorProto.render()` call site as regular fields (see
  `_render_extend_blocks` in `re_descriptor.py`), so this rides on the
  same per-field mechanism as ordinary fields — the only difference is
  `path` (`FileDescriptorProto.extension`/field 7, or
  `DescriptorProto.extension`/field 6, instead of `DescriptorProto.field`/
  field 2).
- **G8 (Step 2).** Extend synthesis to **service and method
  declarations**.
- **G4.** Add a CLI flag controlling the feature, on by default (see
  Specification for exact name/semantics).
- **G5.** Wire synthesis into the single existing conditional
  `ClearField('source_code_info')` site in `re_file.py`, so both
  `-b/--emit-binary` and `--schema-db-out` gain the feature with one
  change.
- **G6.** Regenerate `prototext/wkt/prebuilt/wkt_index.rkyv` if its
  contents change (span *values* only — see Background); confirm
  `wkt.rkyv` is unaffected. Empirically verify both, mirroring spec
  0140's real-world-measurement methodology, rather than assuming.
- **G7.** Confirm and record that no `prototext`/`protolens` Rust-side
  changes are required for the synthesized data to become available at
  runtime.

### Phasing

- **Step 1**: G1 only (messages, full column precision, CLI flag, single
  `ClearField` wiring, WKT verification). This is the complete,
  independently shippable slice — protolens's main goal (jump to a
  message's declaration) is fully served by Step 1 alone.
  **Implemented 2026-07-17.**
- **Step 2**: G2/G3/G8 (enums, fields, services, methods). No new
  design — the same `ctx.out_sci`/span mechanism, applied to more
  `render()` call sites. **Not yet implemented.**

## Non-goals

- protolens-side consumption: spawning `$EDITOR`, an in-pane source
  viewer, import navigation, etc. — spec 0111 Phase 5's job, not this
  spec's.
- Round-tripping an *original*, protoc-parsed `SourceCodeInfo`
  (`leading_comments`/`trailing_comments`/`leading_detached_comments`
  text) — reproto's inputs are typically already stripped, so there is
  nothing to round-trip. This spec synthesizes new `Location`s describing
  reproto's own emitted text; it does not attempt to reconstruct or copy
  forward original comment text.
- Recompiling via `protoc` to obtain "real" `SourceCodeInfo` — rejected
  per 0111/0112: reproto is the authority on its own emitted text: no
  other tool has access to the line numbers reproto itself produces.
- A synthetic Location for the `extend Foo { ... }` block boundary
  itself (the surrounding brace lines) — there is no descriptor node for
  it; `protoc` doesn't reify it either. Only the individual extension
  fields inside get Locations (see G3).
- Any change to `_phase_emit_scoring_graphs`/`hopcroft.rkyv` — confirmed
  unaffected (Background), no changes proposed.

---

## Specification

### CLI flag

Add a `click` flag pair to `cli.py`, following the existing `-b`/`--schema-db-out`
section:

```
--source-info / --no-source-info   (default: --source-info)
```

When `--no-source-info` is passed, behavior is exactly today's (always
`ClearField('source_code_info')`). This is the only new flag; it applies
uniformly to both `-b/--emit-binary` and `--schema-db-out`, matching their
shared `ctx.out_desc` plumbing.

### `ctx.out_sci` side channel

> **Implementation note (Step 1, 2026-07-17):** the "snapshot
> `(start_line, start_col)`/`(end_line, end_col)` immediately, per
> node" design originally sketched below does not work for *nested*
> messages: a nested message's `render()` builds a local `Block`
> relative to its own start, not the file's absolute line count — that
> absolute position is only known once the parent has merged the local
> block upward via `Block.extend()`, which itself only happens after
> the nested `render()` call has already returned. Immediate line/col
> computation is therefore only correct for nodes whose `render()`
> writes directly into the file-level `out` block (none do, at any
> nesting depth beyond the top).
>
> The implemented design instead **defers** span computation: each
> covered `render()` call captures a `(path, open_line, close_line)`
> marker — using the *actual* `BlockLine` object references (identity,
> not position) bracketing its own emitted text — into
> `ctx.out_sci.pending`. Once the file's complete first-pass `out`
> block is fully assembled (all nesting levels merged upward), a
> **single** pass over `out.lines` builds an `id(line) ->
> flushed_line_number` index (honoring `_survives()`, below), and every
> pending marker — from every nesting level — is resolved against that
> one index. See `source_info.resolve_source_code_info_locations()` for
> the implementation; the rest of this section is updated to match.

Mirrors `ctx.out_desc` (spec 0076): a per-render() optional output slot,
threaded without changing `render()` signatures.

```python
@dataclass
class SourceCodeInfoOut:
    """Pending (path, open_line, close_line) markers, resolved once the
    file's first-pass `out` Block is fully assembled (see note above).
    `open_line`/`close_line` are the actual BlockLine objects bracketing
    the covered node's emitted text (identity-matched, not positional).
    """
    pending: list[tuple[list[int], BlockLine, BlockLine]] = field(
        default_factory=list
    )
```

`ctx.out_sci: SourceCodeInfoOut | None` is set once per file, at the top
of `ReFileDescriptorProto.render()`'s **first (text) pass**, gated by
`ctx.out_desc is not None` (i.e. binary output of some kind was
requested) AND the new `--source-info` flag being active. It is
populated during the first pass only.

**Before the second pass begins**, `re_file.py` resolves
`ctx.out_sci.pending` into concrete `Location`s (via
`resolve_source_code_info_locations()`) against the now-complete
first-pass `out`, saves the result to a local variable, and resets
`ctx.out_sci` to `None`. This is essential, not optional: the second
pass re-invokes the exact same child `render()` methods a second time
(see "The two-pass `render()` structure"), and since those methods gate
their marker-capture purely on `ctx.out_sci is not None`, leaving it set
during the second pass would cause every marker to be captured — and
appended — twice. Resetting to `None` before the second pass makes every
nested `render()` call's capture step a no-op automatically; the fix is
centralized in `re_file.py`, not scattered across every covered
`render()` method.

For each node kind covered by G1/G2/G3/G8, its `render()` method:

1. Computes its own `path`, as the caller-supplied prefix (an
   `sci_path` parameter, threaded down from the parent — see path-index
   note below) plus this node's own `[field_number, index]` pair. Only
   computed (non-`None`) when `ctx.out_sci is not None` **and** the node
   `is_summoned` — unsummoned/pruned (ORPHAN) nodes never get a
   `Location` (see "Redaction and pruning").
2. Renders its own text as today, then locates its own opening
   `BlockLine` (the first line it inserts, e.g. `message Foo {`) and
   its own *closing* `BlockLine` via `closing_line()` (see "Span
   computation" — **not** simply the block's last element).
3. If its own `sci_path` is non-`None`, appends `(sci_path, open_line,
   close_line)` to `ctx.out_sci.pending`.

This is a pure addition around existing emission logic — no change to
*what* text is emitted, only bookkeeping as a side effect.

**Path-index computation** mirrors the pre-existing (asymmetric)
filtering already used by the binary side-channel reconstruction, since
Location paths must match the *output* `fdp_out.message_type`/
`nested_type` indices, not the source `DescriptorProto`'s raw list
positions:

- Top-level messages (`re_file.py`): the binary loop filters `not
  message.is_group and message.is_summoned`, so the `[4, idx]` index is
  a running counter incremented only for qualifying messages — not the
  raw loop position.
- Nested messages (`re_descriptor.py`): the binary loop re-accumulates
  *every* `self.nested_type` entry unconditionally (no `is_group`/
  `is_map_entry`/`is_summoned` filter), so the `[3, idx]` index is
  simply the raw `enumerate()` position over `self.nested_type`.

**Unsummoned nested messages** technically still land in the binary
output (per the asymmetry above — the nested loop doesn't filter them),
but Step 1 deliberately never captures a `Location` for them: doing so
correctly would require accounting for `Block.flush()`'s ORPHAN-line
indentation adjustment (`spaces_to_remove = min(3, indent_spaces)`,
applied to the `///`-prefixed rendering of abandoned/pruned nodes),
which complicates column computation for low-indentation lines. A
missing `Location` is valid protobuf (best-effort); a wrong one is not.

### Span computation: line and column precision

`reproto` fully controls its own emission, so both line *and* column
precision are available with no new plumbing — `text.py`'s `BlockLine`
already carries everything `Block.flush()` needs to compute a line's
rendered column offset (`indent_spaces = line.level * TAB_SIZE`), and
that same formula is reused directly for span computation:

- `start_line`/`start_col`: the "flushed-equivalent" line index (below)
  and `level * TAB_SIZE` of the node's opening `BlockLine` (e.g.
  `message Foo {`).
- `end_line`/`end_col`: same, for the node's *closing* `BlockLine`,
  located via `closing_line()` — **not** the block's last element,
  since `render()` methods append a trailing blank divider line after
  the closing brace (`append_div_maybe()`), so `block[-1]` is often
  that blank line, not `}` itself:
  ```python
  def closing_line(block: Block) -> BlockLine:
      idx = len(block) - 1
      while idx > 0 and not block[idx].text:
          idx -= 1
      return block[idx]
  ```
  `end_col = level * TAB_SIZE + len(text)`.
- Span shape follows protoc's own convention: `[start_line, start_col,
  end_col]` (3-element) when `start_line == end_line`, else
  `[start_line, start_col, end_line, end_col]` (4-element) — maximizing
  compatibility with existing `SourceCodeInfo` consumers (protoc plugins,
  editors, `buf`, etc.) that assume this convention.
- All line/column values are 0-indexed, matching protoc's own
  `SourceCodeInfo` convention.

**"Flushed-equivalent" line counting** (this is what resolves the
redaction interaction, below) is computed **once**, in a single pass
over the file's complete first-pass `out` block (not per-node, and not
via a running snapshot — see the `ctx.out_sci` implementation note
above for why per-node snapshots don't work for nested nodes), building
an `id(line) -> flushed_line_number` index using the same survival
predicate `Block.flush()` uses internally:

```python
def _survives(line: BlockLine, ctx: Context) -> bool:
    if line.type == COMMENT:
        return not ctx.redact_comments
    if line.type == ORPHAN:
        return not ctx.redact_orphans
    return True  # CODE always survives
```

Each pending `(path, open_line, close_line)` marker is then resolved by
looking up `id(open_line)`/`id(close_line)` in that index. A marker
whose open or close line was itself redacted away (and so never
survives) is silently dropped — a missing `Location` is valid protobuf,
unlike a wrong one. Because the index is built from the file's actual
survival-filtered line sequence, spans stay correct under any
`--redact-comments`/`--redact-orphans` combination, matching exactly
what `flush()` will emit.

### Consumption in the second (binary) pass

`re_file.py`'s existing second pass already re-invokes each child's
`render()` a second time. Before that second pass starts, the
accumulated `ctx.out_sci.pending` markers from the first pass are
resolved into concrete `Location`s (against the now-complete first-pass
`out`), the result is saved to a local variable, and `ctx.out_sci` is
reset to `None` (see "`ctx.out_sci` side channel" above — this is what
prevents duplicate capture during the second pass). The saved list is
then assigned directly to `fdp_out.source_code_info.location`:

```python
sci_locations = None
if ctx.out_sci is not None:
    sci_locations = resolve_source_code_info_locations(
        out, ctx, ctx.out_sci.pending
    )
ctx.out_sci = None  # second pass must not re-capture
...  # second pass runs here, re-invoking children's render()
fdp_out.ClearField('source_code_info')
if sci_locations:
    fdp_out.source_code_info.location.extend(sci_locations)
```

### Redaction and pruning

Two distinct interactions were considered; both are fully resolved with
no flag-disabling behavior needed:

- **`--redact-comments`/`--redact-orphans`** cause `Block.flush()` to
  drop whole `COMMENT`/`ORPHAN` lines. Naively snapshotting raw
  `len(out.lines)` at construction time would diverge from the final
  rendered line numbers for any content emitted after a dropped line — a
  real correctness hazard (0112's original finding — it is *not* simply
  "goes without saying"). This is fully resolved by the
  "flushed-equivalent" line counting above: spans are always computed in
  terms of what `flush()` will actually emit, so synthesis stays correct
  — and stays on — regardless of these flags.
- **Pruned types/fields** (excluded from `messages`/`entries`, e.g. via
  `-p`/exclusion patterns) trivially never get a `render()` call in the
  first place, so no `Location` is ever recorded for them — this
  requires no special-casing, since `ctx.out_sci` is only ever populated
  from within a node's own `render()` call. **Unsummoned** (reachable
  but not directly requested — ORPHAN) nodes *do* still get a `render()`
  call, but Step 1 deliberately gates `Location` capture on
  `is_summoned` (see "`ctx.out_sci` side channel" above), so they behave
  the same way from this feature's point of view: no `Location`, no
  error.

### Artifact impact verification

Performed via `nix-build`'s `wktRkyv` derivation (the same one that feeds
`nix/rust.nix`'s `wktRkyv` parameter — temporarily exposed as a top-level
attribute for this measurement, then reverted), built once against the
pre-this-spec `reproto` code (via `git stash` of the reproto source
changes) and once against this spec's code. Both builds compile the same
11 `prototext/wkt/SOURCES` files with the same `protoc`/nixpkgs toolchain,
isolating the diff to reproto's own behavior.

| | Before | After | Δ |
|---|---|---|---|
| `schemas.desc` (`descriptor.desc`) size | 5,569 B | 5,900 B | +331 B |
| `wkt_index.rkyv` size | 3,584 B | 3,584 B | unchanged |
| `wkt.rkyv` (`hopcroft.rkyv`) size | 7,244 B | 7,244 B | unchanged |

`descriptor.desc` grows by 331 bytes total (synthesized `SourceCodeInfo`
for the WKT corpus's messages), exactly as expected. `wkt_index.rkyv`'s
*file size* is unchanged (fixed-width `(u64, u64)` span records, per
Background), but its span *values* shift — sample per-file span lengths
(bytes covered by each FDP within `descriptor.desc`):

| File | Before | After | Δ |
|---|---|---|---|
| `any.proto` | 228 | 242 | +14 |
| `api.proto` | 980 | 1,018 | +38 |
| `duration.proto` | 251 | 265 | +14 |
| `empty.proto` | 190 | 203 | +13 |
| `field_mask.proto` | 230 | 244 | +14 |
| `source_context.proto` | 250 | 264 | +14 |
| `struct.proto` | 738 | 776 | +38 |
| `timestamp.proto` | 255 | 269 | +14 |
| `type.proto` | 1,899 | 1,961 | +62 |
| `wrappers.proto` | 518 | 628 | +110 |

`type_to_file` (31 entries), `file_to_span` (10 entries) and `dep_graph`
(10 entries) coverage is identical before/after — only the span values
moved, confirming G6's prediction exactly. `prototext/wkt/prebuilt/
wkt_index.rkyv` was regenerated accordingly (see `prototext/wkt/prebuilt/
README.md`'s procedure) and committed as part of this change.

For `wkt.rkyv` (the Hopcroft scoring graph): a direct byte-for-byte
comparison turned out to be an unreliable signal — `nix-build --check`
independently confirmed the `wktRkyv` derivation is **not
byte-reproducible even with zero code changes** (a pre-existing,
unrelated non-determinism in the graph-compilation pipeline, likely
hash-seed-driven iteration order). Structural comparison was used
instead, via a throwaway diagnostic (not committed, mirroring spec
0140's methodology) loading both graphs with
`prototext_graph::score::load::load_graph` and comparing node/transition/
root counts and the sorted root-FQDN set:

| | Before | After |
|---|---|---|
| Nodes | 74 | 74 |
| Transitions | 242 | 242 |
| Roots | 61 | 61 |
| `num_states` | 74 | 74 |
| Root FQDN set | *(identical, sorted)* | *(identical, sorted)* |

Confirms `wkt.rkyv` is structurally unaffected, consistent with
Background's claim that `_phase_emit_scoring_graphs` never touches
`ctx.out_desc`/binary `FileDescriptorProto`s.

---

## Design decisions (resolved during spec review)

- **Comment text**: not carried forward. Synthesized `Location`s carry
  `path`+`span` only, no `leading_comments`/`trailing_comments` (see
  Non-goals). The primary use case (jump-to-declaration) only needs a
  location; the editor shows adjacent comments naturally once opened
  there.
- **Column precision**: fully supported from Step 1 (G1), not deferred —
  reproto already has everything needed (`BlockLine.level`/`text`); see
  "Span computation".
- **Redaction interaction**: resolved via "flushed-equivalent" line
  counting — no flag-disabling behavior needed; see "Redaction and
  pruning".
- **Phasing**: Step 1 = messages with full column precision (G1); Step 2
  = enums, fields, services, methods (G2/G3/G8); see "Phasing".
- **CLI flag**: `--source-info`/`--no-source-info`, default on. No
  existing `--no-*` precedent exists in reproto's `click` CLI today
  (only in `prototext`'s `clap`-based CLI — `--no-strict-ranges`,
  `--no-expand-any`), but `click`'s native boolean-pair flag syntax makes
  this idiomatic here too.

---

## Test plan

- Unit tests (Python): for a small fixture `.proto` with nested messages,
  verify `ctx.out_sci.locations` contains one `Location` per message
  with `path`+`span` (line *and* column) matching hand-computed values.
- Round-trip test: `--schema-db-out` on a fixture corpus, load the
  resulting `descriptor.desc` back into a `DescriptorPool`, verify
  `source_code_info.location` entries resolve to the expected message
  paths and that spans are non-empty, monotonically consistent (child
  spans nested within parent spans).
- `--no-source-info` regression: confirm output is byte-identical to
  pre-this-spec output when the flag is passed.
- Redaction-interaction test: `--redact-comments --redact-orphans
  --schema-db-out` (without `--no-source-info`) produces spans that
  still correctly point at the surviving (post-redaction) line numbers
  of each message — verified by loading the resulting `descriptor.desc`
  and cross-checking spans against the actual `.proto` text emitted in
  the same run.
- Pruning test: a fixture with an excluded/pruned message produces no
  `Location` for it and no error, confirming pruned nodes are silently
  skipped as a natural consequence of never calling their `render()`.
- G6 empirical check: WKT corpus before/after diff, per "Artifact impact
  verification" above.
