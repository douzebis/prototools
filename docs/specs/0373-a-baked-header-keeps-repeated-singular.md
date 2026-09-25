<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0373 — a re-rendered header keeps its `repeated_singular`

Status: draft
App: prototext-core, protolens
Refs: docs/specs/0343-the-last-one-wins-and-the-others-say-so.md (the
      mark, its frame-local state (A2), and A7's claim this spec
      corrects);
      docs/specs/0303-a-truncated-message-says-what-it-is-missing.md
      (`missing_payload_bytes`: the precedent for a header fact handed
      to a standalone render);
      docs/specs/0135-protolens-override-raw-tag-rewrap.md (G1: a
      spliced header line comes out of the
      renderer already correct; the only patch is the field-name
      placeholder);
      docs/specs/0249-a-large-document-answers-the-user-first.md (the
      bake that expands deferred bodies);
      docs/specs/0348-override-cmd-card-prefill.md (S5: an override
      entry's explicit cardinality)

## Background

`repeated_singular` marks a field the schema declares singular that
occurs again in the same frame. The renderer decides it in
`render_message` (`render_text/mod.rs`) from two frame locals,
`seen_mask` and `seen_fields` (spec 0343 A2), and writes it into the
row's `#@` text through `TagFacts`. It applies to every kind: scalar,
enum, message and group (0343 A1).

protolens loses it on a message or group header once the node has been
re-rendered. `expand_auto_fold` (the bake) and every type override go
through `splice_override`, which replaces the node's whole line range —
header included (`old_span.text_range = … node_lines(idx)`) — with a
render of that node **alone**. A lone render has no parent frame, so
"this field already appeared" is unknowable there. Header modifiers
drawn from the node's own bytes (`tag_ohb`, `len_ohb`) are recomputed
correctly; this one depends on the node's siblings and is lost.

Measured 2026-09-25 on `tests/fixtures/anomalies.pb`, with a temporary
protolens test: after draining `bake_step()`, the document equals the
unbounded render line for line (164 lines) **except one**, at every
budget that defers anything (5, 41):

```
unbounded:   source_code_info {  #@ SourceCodeInfo = 9; repeated_singular
baked:       source_code_info {  #@ SourceCodeInfo = 9
```

At budget 200 nothing is deferred and the two are identical.
`prototext decode` and `protolens export /` are correct.

Spec 0343 A7 held the loss to be temporary: "a mark deferred with it
arrives when the body does". That is true of marks *inside* a body. The
header's own mark belongs to the parent frame, which the re-render
never sees, so it does not arrive at all — and 0343 G1/G2 (every
charged unit visible on a row) fail for it.

Scalar rows are not affected: they are never re-rendered alone except
through a type override, which S4 covers.

## Goals

- **G1.** A node re-rendered by `splice_override` — bake, override
  commit, override preview — keeps the `repeated_singular` its header
  had in the parent's render.
- **G2.** After the bake has drained, protolens's document equals the
  unbounded render, line for line.
- **G3.** The fix adds no bytes to `NodeSpan` (pinned at 32).

## Non-goals

- **N1. Recomputing the verdict from siblings at splice time.** The
  parent frame's verdict is already known when the node is first
  rendered; recording it is cheaper and cannot drift from the renderer's
  rule.
- **N2. A cardinality override from repeated to singular.** The frame
  tracks only fields the *schema* declares singular (0343 A2), so a
  field declared repeated has no recorded verdict to carry. Its header
  stays unmarked, as it is today.
- **N3. `shadowed_scalar`.** Computed by protolens itself (0343 part B)
  and unaffected.
- **N4. The scorer.** Unchanged; this spec restores the rows it already
  expects (0343 G2).
- **N5. `protolens export /N` of a subtree.** The export is a new
  document whose root has no parent frame, so its root header is not
  expected to carry the mark.

## Specification

- **S1. Record the verdict on the node.** `NodeSpan::wire_and_label`
  uses bits 0–2 (wire type) and 3–4 (label); bits 5–7 are idle. Bit 5
  becomes `repeated_singular`: `IndexingTextSink` sets it from the
  `TagFacts` of the record that produced the node — `begin_nested` for
  a message or group, `scalar_field` for a scalar — the two span pushes
  that have the record's `TagFacts` in hand (a packed element's span has
  none to carry: a packed field is repeated). Accessor
  `NodeSpan::repeated_singular()` and setter
  `NodeSpan::set_repeated_singular(bool)`. `pack(wire_type, label)` is
  unchanged: it has 22 call sites and only these two ever set the bit.
  No new field; `size_of::<NodeSpan>()` stays 32. The existing readers
  are unaffected: `wire_type()` masks `0b111` and `label()` shifts then
  masks `0b11`, and `NodeSpan` derives no `PartialEq`, so nothing
  compares whole spans.
- **S2. Hand it to the lone render.** `DecodeRenderOpts` gains
  `header_repeated_singular: bool` (default `false`), documented beside
  `missing_payload_bytes`. `decode_and_render_indexed` hands it to the
  `IndexingTextSink`, which holds it and ORs it into `tag` on the
  **first** `scalar_field` or `begin_nested` it receives, then clears it
  (`take()`), so it never leaks onto inner rows. The OR happens in
  `IndexingTextSink` itself, **before** it both delegates to the inner
  `TextSink` and builds the span — not inside `TextSink`, where
  `missing_payload_bytes` is consumed. Otherwise the row would carry the
  mark while the span's bit stayed 0, and the *next* splice of the node
  (a type override after the bake) would lose it again. Done this way,
  the re-rendered node's own `NodeSpan` records it (S1) and every later
  splice carries it forward.
- **S3. `splice_override` sets it.** From `old_span.repeated_singular()`,
  on the commit path and the preview path alike (unlike
  `missing_payload_bytes`, which is commit-only because only the commit
  reframes). Only when the effective cardinality the splice renders
  under — the override entry's (0348 S5) or else the field's — is not
  `Repeated`: an override that makes the field repeated removes the
  mark with it.

  An override to raw (`target: None`) keeps the mark. Its row renders in
  the unknown-field style (`3 {  #@ message; …`), which
  `push_tag_modifiers` already supports. 0343 N5 ("unknown fields are
  never marked") does not apply: its reason is that no schema says the
  field is singular, whereas this verdict was made under the *parent's*
  schema, which a raw override of the child does not change.
- **S4. Type overrides.** No separate rule: an override is a splice, so
  S3 covers it. A repeated singular field overridden to another type is
  still the same field occurring again, and keeps the mark.
- **S5. The render cache.** No change: its key is
  `(payload_range, target, bool)`, and `payload_range` is the node's own
  byte range, so two nodes — a first occurrence and a repeat — never
  share an entry.
- **S6. Spec 0343.** A7 gains one sentence pointing here: the mark on a
  node's *own* header belongs to the parent frame, so a deferred node
  re-rendered alone needed it handed in.

## Alternatives considered

### Patch the header text after the splice

The splice already replaces the synthetic field's `"_"` placeholder
with the display name. Appending `; repeated_singular` the same way was
rejected: spec 0135 G1 holds that the header comes out of the renderer
already correct and keeps the placeholder as the one exception, and a
string edit would have to know where the modifier goes among the
others (`tag_ohb`, `TRUNCATED_MESSAGE`, …), which only the renderer
knows.

### Store the fact outside `NodeSpan`

A side table keyed by node index. Rejected: indices move on every
splice, which is exactly when the fact is needed, while a bit in the
span moves with it for free — and there are three idle bits.

## Test plan

1. `baked_document_equals_the_unbounded_render` (protolens): on
   `tests/fixtures/anomalies.pb` as `FileDescriptorProto`, for row
   budgets 5 and 41, drain `bake_step()` and compare `document_lines()`
   with the unbounded render. Fails before this spec at 5.c's
   `source_code_info` header, the only differing line.
2. `a_repeated_singular_message_keeps_its_mark_after_bake`
   (protolens): a minimal fixture — a message with a singular message
   field written twice — bounded so the second is deferred; after the
   bake its header carries `repeated_singular` and the first's does
   not. Fails before.
3. `a_type_override_keeps_repeated_singular` (protolens): override the
   second occurrence to another message type, commit and preview; the
   header keeps the mark. Fails before.
4. `a_cardinality_override_to_repeated_drops_the_mark` (protolens): an
   override entry with explicit repeated cardinality on the same node
   renders no mark (S3).
5. `a_raw_override_keeps_repeated_singular` (protolens): overriding the
   same node to raw (`target: None`) keeps the mark on its unknown-style
   header (S3).
6. `a_second_splice_keeps_repeated_singular` (protolens): bake the
   node, then override it; the mark survives both splices. Guards S2's
   placement: with the OR inside `TextSink` instead, the first splice
   would pass and this one would fail.
7. `header_repeated_singular_marks_only_the_outermost_record`
   (prototext-core): `decode_and_render_indexed` with the option set
   marks the outermost header and no inner row, and sets bit 5 on that
   node's span only.
8. `NodeSpan` stays 32 bytes: the compile-time
   `assert!(size_of::<NodeSpan>() == 32)` in `sink.rs` keeps building.

Tests 1–3, 5 and 6 must fail on the parent commit (checked in a worktree, as for
specs 0370 and 0372). Existing suites that must stay green: the
protolens bake, override, script and shadow tests; `anomaly_fixture`;
the full workspace suite and `nix-build`.

## Measured outcome

Filled in at implementation.
