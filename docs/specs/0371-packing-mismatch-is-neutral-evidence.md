<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0371 — a record whose packing contradicts its declaration scores net zero

Status: draft
App: prototext-graph, reproto, prototext-core, prototext, protolens
Refs: docs/specs/0175-packed-and-expanded-repeated-scalars.md (the reader
      rule and the one-match-per-packed-record rule this spec keeps;
      its S3 "What is *not* penalized" and "No `packed` flag" non-goals
      are what this spec reverses);
      docs/specs/0370-packed-on-the-wire-renders-as-packed.md (the
      renderer now reads every packed record; its N2 — the unreliable
      `[packed=true]` display — is fixed here as a side effect);
      docs/specs/0343-the-last-one-wins-and-the-others-say-so.md
      (`repeated_singular`: the precedent for a
      per-record schema-vs-wire verdict that the scorer charges and the
      encoder ignores);
      docs/prototext/PROST-ISSUES.md §1;
      docs/specs/0372-a-bool-is-any-varint.md (prerequisite: after it,
      no run the scorer accepts renders as `INVALID_PACKED_RECORDS`)

## Background

Every repeated scalar field has two legal wire encodings, and a reader
accepts both whatever the declaration says (spec 0175). The scorer does
so and gives no signal about which encoding the declaration names. Spec
0175 S3 chose this on purpose: proto3 declares packed by default, yet
expanded output from proto3 fields was expected to be routine.

In this project's use, schemas and blobs come from the same build. A
record whose packing contradicts its declaration is therefore strong
evidence that the candidate is wrong — and the scorer credits it as a
full match.

The case that exposed it: `CONFIG_NETWORK_DEVICE_vars_software` against
`/tmp/g3.desc`. The winner, `NvlinkInfoEntry`, scores
`229  (matched: 229)`. 224 of those matches are LEN records on
`NvlinkInfoLanes.lane`, a proto2 `repeated int32` declared expanded. The
payloads are ASCII text, and every byte below 0x80 is a one-byte
varint, so each record passes packed-run validation. The candidate's
whole score is made of records it explains only by reading text as a
packed int32 run in the encoding its own declaration does not name.

### What is already right (verified 2026-09-25)

A packed record scores one match, not one per element. `walk.rs`'s
`Verdict::FoundPacked` arm runs `matches += 1` once, after the element
loop; `packed_varint_run_matches` pins `s.matches == 1` for a
three-element run. On the file above, the 224 records hold 108 321
elements, and `matched` is 229 (224 records + 5 other fields). This
spec does not change that rule.

### Where the declaration is and is not known today

- **The compiled graph** does not store it. `reproto`'s
  `_scoring_kind` deliberately skips `field.is_packed`
  (`phases.py`), and `TransitionEntry.label` is only
  0/1/2 (optional/required/repeated).
- **Python protobuf** gets it right. `FieldDescriptor.is_packed`
  resolves proto2, proto3 and editions features, including the
  PROST-ISSUES §1 case: a proto3 `repeated int32` carrying a custom
  option reports `True`.
- **prost-reflect 0.16.3** gets it wrong for that case.
  `resolve.rs:121` computes `options.map_or(syntax == Proto3,
  |o| o.value.packed())`, so any `FieldOptions` at all turns a proto3
  default into `false`. Its `Syntax` has only `Proto2` and `Proto3`.
  Our `FieldOrExt::is_packed()` also hard-codes `false` for every
  extension. After spec 0370 nothing in the tree corrects any of this;
  today it only affects the `[packed=true]` shown in declarations.

## Goals

- **G1.** A wire record whose packing contradicts its field's
  declaration contributes **net zero** to the score: its match (+1) is
  offset by a new `packing` charge (−1). This holds in both directions:
  - a packed record on a field declared expanded — one charge per
    record;
  - an expanded occurrence of a field declared packed — one charge per
    occurrence, since each occurrence is a record.
- **G2.** The charge is **on by default** and can be turned off with a
  scoring option, for corpora whose writers do not follow the
  declaration.
- **G3.** Every record the scorer charges is marked on its rendered row,
  and every marked row is one the scorer charges: the renderer and the
  scorer use the same rule for "declared packed".
- **G4.** The charge is visible wherever the score is broken down: the
  `# Score:` header, `--detailed-score` YAML, `prototext score`, and the
  protolens score box.

## Non-goals

- **N1. A heavier weight.** At `non_canonical`'s −20, one discrepant
  record would outweigh an unknown field (−10) — a claim that a schema
  declaring the field with the other packing is less likely than one
  not declaring it at all. Net zero is decisive on the motivating case
  (229 → 5) without that claim. Revisit only with corpus evidence.
- **N2. Changing validation or vetoes.** Packed-run validation, the
  one-match rule and every veto stay as they are. A run that vetoes is
  never charged (a vetoed candidate has no score).
- **N3. Editions in the renderer.** The renderer never sees an editions
  file, so its rule covers proto2 and proto3 only (checked 2026-09-25):
  - prost-reflect 0.16.3 refuses one outright: `names.rs` maps any
    `syntax` other than absent/`proto2`/`proto3` to
    `DescriptorErrorKind::UnknownSyntax`.
  - `reproto --build-schema-db` rewrites editions files to proto2 while
    `EDITIONS_COMPAT_REQUIRED` is true (`phases.py`), and the binary
    descriptor it emits sets `options.packed = true` on every packable
    field whose resolved `repeated_field_encoding` is `PACKED`
    (`re_field.py`, binary output side-channel), clearing `features`.
  So an editions field declared PACKED reaches the renderer as proto2
  `[packed = true]`, and the graph — built by Python from the original
  editions file (S2) — says packed too. The two agree without an
  editions arm in S3.
- **N4. Heuristics on payload content** (e.g. "this packed run is all
  printable ASCII"). A separate question; this spec only compares
  encoding with declaration.
- **N5. `--no-annotations` output**, which marks nothing.

## Specification

### Declaration: one rule, two implementations

- **S1. The rule.** A field is *declared packed* iff it is repeated, its
  type is packable (a scalar numeric type, bool or enum), and:
  - proto2: `[packed = true]` is set;
  - proto3: `[packed = false]` is **not** set — regardless of any other
    options the field carries;
  - editions: its resolved `features.repeated_field_encoding` is
    `PACKED`.
- **S2. `reproto`.** A helper `fd_is_packed(field)` in
  `field_descriptor.py`, beside `fd_is_repeated`/`fd_is_required`,
  returns `field.is_packed` for a repeated packable field and `False`
  otherwise. `_scoring_yaml_doc` emits `packed: true` on every field it
  returns `True` for, and omits the key otherwise. Update the
  `_scoring_kind` docstring, which currently says the option is
  deliberately not consulted.
- **S3. Renderer.** `FieldOrExt::declared_packed()` in
  `render_text/mod.rs` implements S1's proto2/proto3 arms from the raw
  descriptor (`field_descriptor_proto().options…packed` and the parent
  file's syntax), for fields **and extensions**. It replaces every call
  of `FieldOrExt::is_packed()`, which is then deleted. The `[packed=true]`
  in the declaration annotation (`annotations.rs`) uses it too, which
  fixes spec 0370 N2.

### Graph

- **S4. Format.** `ScoringField` (`build_scoring_graph/load.rs`) gains
  `packed: bool`, read from the YAML key (`#[serde(default)]`, absent =
  `false`). `TransitionEntry` gains `declared_packed: u8` (0/1) after
  `child_wire_type`. The archived struct is 4-byte aligned, and its
  fields sit at `state_id@0 field_number@4 label@8 child_wire_type@9
  child_state_id@12` (measured with `offset_of!` on
  `ArchivedTransitionEntry`, rkyv 0.8, 2026-09-25): bytes 10–11 are
  alignment padding before `child_state_id`. The new byte takes offset
  10, so the struct stays 16 bytes and the table does not grow — the
  same move `child_wire_type` made in the 4 → 5 bump. `GRAPH_VERSION` goes 6 → 7, with a history
  entry beside the constant in `serial.rs`: a v6 file read as v7 would
  find padding garbage there and charge at random. Every `.rkyv` must be
  rebuilt, and the loader refuses the old ones with a version error:
  - `prototext/wkt/prebuilt/wkt.rkyv` is **committed**. Regenerate it
    with the procedure in `prototext/wkt/prebuilt/README.md`
    (`nix-build -A prototext`, copy `wkt.rkyv` from the `wkt-rkyv` store
    path) and commit it in the same change. `wkt_index.rkyv` is a
    separate format (`fds_index.rs`, `VERSION`) and does not change.
  - Every user's own `hopcroft.rkyv` must be rebuilt with `reproto`,
    e.g. `/tmp/g3/hopcroft.rkyv` for this spec's measured outcome.
- **S5. Why a new byte, not `label = 3`.** Rejected: `label == 2` is
  tested as "repeated" throughout the walk (`apply_cardinality_multi`,
  occurrence recording), and a fourth value would silently turn every
  packed-declared field into a non-repeated one wherever a site was
  missed.

### Scorer

- **S6. Counter.** `EntryScore` gains `packing: u64`.
  `EntryScore::score()` subtracts `1 * packing`. The doc comment on
  `score()` gains its rationale: weight 1 is exactly one match, so a
  charged record is accepted and neutral.
- **S7. Option.** `ScoringOpts` gains `packing_penalty: bool`, `true` in
  `Default`. When `false`, nothing is charged and the walk behaves
  exactly as today.
- **S8. Charging sites** (`walk.rs`), only when `packing_penalty`:
  - `Verdict::FoundPacked`, after the run has validated and the match
    is counted: if the transition's `declared_packed == 0`,
    `packing += 1` on every entry of the group. An empty packed run is
    charged too, on top of its existing `non_canonical`.
  - Every arm that counts a match for a non-LEN occurrence of a
    repeated packable leaf (`Verdict::Found` with `label == 2`): if
    `declared_packed == 1`, `packing += 1` on every entry.
  Both verdicts must carry the transition's `declared_packed`.
  `Verdict::Found(child_state_id, label)` gains it as a third field.
  `Verdict::FoundPacked(child_state_id, elem_wt)` carries the element
  wire type *instead of* a label, so it gains the byte too. Both are
  built at the one site that reads the transition (`walk.rs`, the
  verdict loop), where `tr` is in hand. A message or group child never
  has `declared_packed == 1` (S2 emits it for packable fields only), so
  the `Found` check needs no separate test for the leaf's kind.

### Reports

- **S9. Every consumer of the breakdown shows `packing`.**
  - `prototext/src/run.rs`: `inferred_header` adds `packing: N` after
    `truncated` when non-zero; `write_type_entry` with
    `detailed_score`; `run_score`'s `Breakdown`.
  - protolens: `ScoreBreakdown` (`override_pane.rs`) gains the field
    and its own copy of the formula gains `- self.packing`; the score
    box rows (`tui/popup.rs`) gain
    `(self.packing, "packing differs from the declaration", -1)`.
  - `fdp-scan-pyo3`: the test asserting that `protoc`-written
    descriptor records score clean (no unknowns, mismatches,
    `non_canonical` or `out_of_range`) also asserts `packing == 0`.
    `protoc` always writes packing as declared, so this is a
    real-world check of S2 and S8 for free.
  - `prototext/src/lib.rs`: the `--detailed-score` help text, which
    lists the dimensions.
  - `prototext-graph/examples/{group_probe,part_probe,part_work}.rs`:
    each sums the counters; they add `packing`.
  - Any other site found by grepping for `non_canonical` at
    implementation time.
- **S10. CLI.** Every `prototext` subcommand that takes
  `--no-expand-any` also takes `--no-packing-penalty` (help heading
  "Advanced options"), which sets `packing_penalty: false`. protolens
  takes the same flag and passes it to every `ScoringOpts` it builds
  (`sweep.rs`, `override_pane.rs`). `fdp-scan-pyo3` keeps the default.

### Rendering

- **S11. Keyword `packing_mismatch`.** Lower-case and in the
  non-canonical tier, like `repeated_singular`: both are per-record
  verdicts comparing schema with wire, charged by the scorer, and
  carrying no bytes. Emitted, whenever annotations are on (whatever
  `packing_penalty` says — the row states a fact, the flag chooses a
  policy):
  - on the **first element line** of a packed record whose field is not
    declared packed, after `pack_size`; and on the comment-only line of
    an empty one;
  - on **each** expanded occurrence line of a field declared packed.
  Not on `INVALID_PACKED_RECORDS`. Once spec 0372 has landed, every run
  the renderer rejects is one the scorer vetoes, so no charged record
  can land on such a line, and a vetoed candidate has no score to
  explain.
- **S12. Encoder.** `encode_annotation.rs` adds `packing_mismatch` to
  the flags it ignores, beside `repeated_singular`. **Required, not
  cosmetic:** the `_ =>` arm treats any other keyword as a wire-type
  name, so a missing entry breaks round-trips.
- **S13. protolens.** `packing_mismatch` joins `annotation::NON_CANONICAL`
  (its length constant grows by one) and gets a hover description in
  `annotation.rs`: "this record is packed, but the field is declared
  expanded (or the reverse); legal, but a writer following this schema
  would not produce it". It also joins the `@annotation.non_canonical`
  list in `reproto/tree-sitter-textproto/highlights.scm`: protolens
  colors annotations from that file, and `colorize`'s
  `every_keyword_is_colored_by_its_tier` fails until the two agree. (As
  in spec 0372: the dev shell compiles in a copy of the file fixed at
  shell entry, so test locally with
  `TREE_SITTER_TEXTPROTO_QUERIES_DIR=reproto/tree-sitter-textproto`.)
- **S14. Documentation.** `annotation-format.md` lists `packing_mismatch`
  in the modifier tables and adds an example in § Packed field
  encoding. Spec 0175 gets a one-line pointer from S3's "What is *not*
  penalized" to this spec.
- **S15. The anomaly fixture.** `prototext-core/tests/anomaly_fixture.rs`
  requires the renderer's vocabulary and what `tests/fixtures/anomalies.pb`
  produces to be *equal*, so `packing_mismatch` goes into its
  `VOCABULARY` (non-canonical group) and the fixture gains a record that
  produces it:
  - In section 4's `Location` (`SourceCodeInfo.Location`, whose `path`
    and `span` are both `repeated int32 [packed = true]` in
    `descriptor.proto`), a third run, **4.c**: `path` values written
    *expanded*, one tag each, each line marked `packing_mismatch`. It
    fits the section's theme exactly, and appending children at the end
    of that `Location` moves no existing path, so nothing in
    `anomalies.script` is renumbered.
  - The heading becomes `"4. Three runs below: …"`, the section's
    header comment describes the third run, and `anomalies.script`
    gains a 4.c step. The guard test `every_step_lands_under_its_heading`
    already accepts `4.c.` under the letterless heading `4.`.
  - Only one direction is shown. The other — a packed record on a field
    declared expanded — would need a top-level `public_dependency`
    record, which would shift every later wrapper; the vocabulary test
    needs the keyword once, not twice.
- **S16. Existing expectations that change.** Packed records on fields
  declared expanded gain `packing_mismatch` on their first element line,
  so these assertions change, and are **updated, not loosened**:
  `prototext/tests/packed_on_the_wire.rs` (tests 1, 2 and 4, and the
  test-11 table rows whose expected substring contains `pack_size`) and
  `prototext/tests/bool_values.rs` (its packed cases). `roundtrip.rs` and
  the protolens tests that mention `pack_size` only use fields declared
  packed and written packed, so they should not change; any that do are
  reported at implementation rather than edited silently.

## Alternatives considered

### Don't count the match (no new counter)

Same net effect, less code. Rejected: the score box would show fewer
matches with nothing explaining why, and G3's parity would have no
counter to compare the rows against.

### Charge only one direction

"Packed on an expanded declaration" is the direction that produced the
bogus winner. Rejected: the argument — writer and schema are in sync —
is symmetric, and charging one direction only would make the two legal
encodings of the same mismatch score differently, the asymmetry spec
0175 exists to avoid.

### Heavier weight

See N1.

## Test plan

1. `reproto`: `fd_is_packed` over the matrix proto2 default / proto2
   `[packed=true]` / proto3 default / proto3 `[packed=false]` / proto3
   default with a custom option (§1) / editions `PACKED` and `EXPANDED`
   / repeated string / singular int32; and the emitted YAML carries
   `packed: true` exactly where expected.
2. Rust, `declared_packed()`: the same matrix minus editions, including
   an extension of each packing and the §1 case (`FieldOptions` present
   but empty).
3. `prototext-graph`: `packed` YAML key round-trips into
   `TransitionEntry.declared_packed`; a v6 header is refused with a
   message naming both versions; `size_of::<TransitionEntry>()` is
   unchanged.
4. Scorer, with the packed test graph (`build_packed_graph`):
   - packed record, declared expanded → `matches == 1`, `packing == 1`,
     net 0;
   - three expanded occurrences, declared packed → `matches == 3`,
     `packing == 3`, net 0;
   - agreeing encodings in both directions → `packing == 0`;
   - `packing_penalty: false` → `packing == 0` everywhere;
   - invalid packed run → vetoed, `packing == 0`;
   - `packed_varint_run_matches` unchanged (still one match).
5. Renderer + encoder: rows carry `packing_mismatch` exactly per S11,
   and every case round-trips byte-exactly (the 0370 tests plus these).
6. Parity (G3): for the matrix of test 2 and each wire encoding, the
   number of `packing_mismatch` rows equals `EntryScore.packing`,
   scoring against a graph built from the same declarations — for every
   case the scorer does not veto, including a packed bool run holding a
   `2` on a field declared expanded (one `packing_mismatch` on the
   first element line after spec 0372; `out_of_range` + `packing` in
   the score).
7. Reports: header shows `packing: N`; `--detailed-score` YAML carries
   it; protolens `ScoreBreakdown::score()` equals `EntryScore::score()`
   on a charged case.
8. `fdp-scan-pyo3`'s clean-records test with its new `packing == 0`
   (S9).

### Regression checks

- Tests 4 (its charged cases), 5, 6 and 7 must **fail on the parent
  commit**, checked in a worktree as for specs 0370, 0372 and 0373.
  Tests 1–3 exercise new code (`fd_is_packed`, `declared_packed()`, the
  `packed` key) and cannot build there, which is expected.
- Existing suites that must stay green: the S16 files with their
  updated expectations; `anomaly_fixture` (S15); `batch_script`,
  including `every_step_lands_under_its_heading`; protolens's
  `annotation` and `colorize` tests; the `prototext-graph` score tests;
  the `reproto` scoring tests; the full workspace suite and `nix-build`.

## Measured outcome

Filled in at implementation. Expected: `NvlinkInfoEntry` on
`CONFIG_NETWORK_DEVICE_vars_software` drops from 229 to 5
(`matched: 229, packing: 224`), with 224 `packing_mismatch` rows; the
new winner to be recorded, whatever it is. Also to be recorded: how
many winners change across `../assets/` with the penalty on versus off.
