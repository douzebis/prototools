<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0396 — prototext is-canonical, and a single capture in the demo

Status: implemented
Implemented in: 2026-10-05
App: prototext, grehack2026 (teleprompt deck)
Refs: docs/specs/0384-smuggle-through-plain-varint-fields.md (the covert
      channel is a wire-level non-canonicity — overhang bytes on varints);
      docs/specs/0388-the-demo-runs-from-grehack2026.md (the deck, its
      captures); docs/specs/0393-only-dumpcap-runs-as-root.md (section 2's
      second capture and `life-client --paused`, which this supersedes);
      docs/specs/0395-the-teleprompt-deck-reads-more-easily.md (the deck's
      Eve section, reshaped again here)

## Background

The covert channel (spec 0384) hides bits in spurious continuation bytes
on varints — a *non-canonical* encoding that decodes to the same values,
so a schema-faithful decode shows nothing. prototext already detects
these as annotations (`tag_ohb`, `val_ohb`, `len_ohb`, over-encoded
lengths, truncated negatives, non-canonical NaN, `TRUNCATED_*`), but
there is no one command that answers "is this blob canonically encoded?"
without reading the full annotated decode.

In the demo, section 2 takes a *second, controlled* capture to put the
smuggled message at a known position, with `life-client --paused` and
fixed numbering (spec 0393 S5, 0388 S8). That is unnatural: Alice does
not control what Eve types or when, so she cannot arrange for the
contraband to land in a chosen capture. It is also an extra capture dance
on stage.

A simpler, truer flow: Alice takes **one** capture while Eve is already
using her hidden shell (section 2 part 1 shows that live), then scans the
captured messages for the one that is not canonically encoded.

## Goals

- **G1.** `prototext is-canonical <paths>` reports, per file, a verdict
  — `canonical` or `anomalous` — and, for an anomalous file, each kind of
  anomaly found and its count.
- **G2.** The exit status is 0 only if every file is canonical; non-zero
  if any file is anomalous.
- **G3.** What counts as an anomaly depends on the typing: it works with
  no schema (wire-level anomalies only) and, when `--descriptor-set` and
  a type are in force, also reports the anomalies that only a type reveals
  (wire/schema mismatches, invalid UTF-8, unknown enums, packing
  mismatches, non-canonical negatives, …). A blob read as packed floats
  and the same blob read as a message need not be judged alike.
- **G4.** The demo takes a single capture. Section 2 finds the smuggled
  message among the captured files with `is-canonical`, and the
  presenter opens the flagged one in protolens. No second capture, no
  `--paused`, no fixed numbering.

## Non-goals

- **N1.** `is-canonical` does not rewrite anything, and does not emit
  the canonical form. It reports; `decode` then `encode` already
  round-trips, and canonicalizing is a separate feature.
- **N2.** No new anomaly detection. It reports the anomalies prototext
  already annotates (spec 0226); it only tallies and labels them.

## Specification

- **S1. The subcommand.** `prototext is-canonical <paths>…`, a subcommand
  beside `decode`/`encode`/`list-schemas`/`score` (clap cannot name a
  subcommand with a leading `--`, so it is `is-canonical`, not
  `--is-canonical`). Globs and directories expand as `decode`'s do; with
  no paths it reads stdin, reported as `<stdin>`. `--descriptor-set` is
  the top-level option, as for the other subcommands.

- **S2. What counts as an anomaly (G1, option b).** Every anomaly
  prototext annotates in the decode counts — whether it is purely about
  the encoding or about disagreement with the type in force (spec 0226's
  vocabulary). The verdict is `anomalous` if any appear, `canonical` if
  none do. Each annotation maps to a plural, non-jargon label:

  | Annotation | Label |
  |---|---|
  | tag overhang (`tag_ohb`, end-tag) | `overhanging bytes in tags` |
  | length overhang (`len_ohb`) | `overhanging bytes in length prefixes` |
  | value overhang (`val_ohb`) | `overhanging bytes in values` |
  | packed-element overhang | `overhanging bytes in packed elements` |
  | out-of-range field number (`TAG_OOR`) | `out-of-range field numbers` |
  | invalid wire type (`INVALID_TAG_TYPE`) | `invalid wire types` |
  | `TRUNCATED_MESSAGE` | `truncated messages` |
  | `TRUNCATED_BYTES` | `truncated fields` |
  | non-canonical negative (`truncated_neg`, `neg`) | `non-canonical negative integers` |
  | non-canonical NaN | `non-canonical NaN values` |
  | `packing_mismatch` | `packing mismatches` |
  | `TYPE_MISMATCH` | `wire/schema type mismatches` |
  | `ENUM_UNKNOWN` | `unknown enum values` |
  | `INVALID_STRING` | `invalid UTF-8 strings` |
  | `repeated_singular` | `repeated singular fields` |

  Which labels can appear depends on the typing (S4): the top group
  (encoding anomalies) needs no schema; the rest appear only when a type
  is in force.

- **S3. Output (G1).** One block per file — the path, then the verdict:

  ```
  000050-request.pb: canonical
  000051-request.pb: anomalous
      overhanging bytes in values: 43
      truncated messages: 1
  000052-response.pb: anomalous
      invalid UTF-8 strings: 2
      unknown enum values: 1
  ```

  - `path: canonical` on one line when nothing is found.
  - `path: anomalous`, then one indented line per anomaly kind present,
    `label: count` — the count prepended with `: ` as `grep -c` does.
    Several of a kind, and several kinds, are both possible. Kinds are
    listed in a fixed order (the S2 table's order), so output is stable.
  - A single file prints the same block, no summary line.

- **S4. Schema (G3).** With no `--descriptor-set`/`--type`, the blob is
  read raw: wire-level canonicity, which is enough to catch the covert
  channel and needs no schema. With a descriptor set and/or an inferred
  or named type, canonicity is judged under that interpretation, so
  type-dependent anomalies (packing mismatch; a varint field whose bytes
  are canonical as one type and not as another) are reported as the type
  implies. The same resolution `decode` uses (explicit `--type`, else
  inference, else raw) applies.

- **S5. Exit status (G2).** 0 when every file is canonical; 1 when any
  file is anomalous; 2 for an operational error (a path that cannot be
  read, a bad descriptor set). So
  `prototext is-canonical capture/*.pb && echo "all clean"` is
  meaningful, and the per-file lines carry the detail.

- **S6. The demo: one capture (G4).** Section 2 is reshaped:
  - Part 1, "Eve is spying" (unchanged from spec 0395): Eve types shell
    commands live; their output returns to her. The audience sees the
    capability. No tap involved.
  - Part 2, "Hidden bits": Alice takes **one** capture — the tap runs
    while Bob plays a handful of steps, during which Eve's traffic is on
    the wire. Then:
    ```
    prototext is-canonical capture/*.pb
    ```
    Most files are `canonical`; one or two are `anomalous`, with
    `overhanging bytes in values: N`. The
    presenter reads the flagged file name and opens it in protolens:
    ```
    protolens --descriptor-set life.desc capture/NNNNNN-request.pb \
      --script beats/smuggle
    ```
    The `NNNNNN` in the preloaded command is a placeholder the presenter
    edits to the flagged file before running it (teleprompt lets a seed
    be edited before Enter). The deck no longer hardcodes a capture
    number for this step, because which capture carries the contraband is
    not under Alice's control (that is the point).
  - Spec 0393's `life-client --paused`, its fixed `000001`/`000002`
    numbering for section 2, and the second `life-tap` are dropped.
    `--paused` stays on `life-client` (it has other uses), but the deck's
    section 2 no longer needs it.

- **S7. The beat.** `beats/smuggle` is unchanged: it drives protolens on
  whatever file the command names.

## Alternatives considered

### A bash one-liner in the deck

The first sketch was `for c in capture/*.pb; do … prototext … ; done`
with `echo`/`if` around a silent exit status. Printing the status from
`is-canonical` itself (S3) makes the deck a single command and reads
far better on stage.

### Silent, exit-status only

An exit status alone needs the caller to loop and label. A printed
per-file line is useful on its own (the demo) and still carries the exit
status for scripts (S5).

### Re-encode canonically and compare bytes

prototext's round-trip deliberately *preserves* non-canonical bytes
(spec, lib.rs: "lossless round-trip"), so a re-encode does not
canonicalize and a byte compare would always match. The annotations are
the signal, not a re-encode.

## Test plan

1. `is-canonical` on a canonical blob: prints `path: canonical`, exits
   0.
2. On a blob with overhang bytes (a smuggled capture, or a crafted
   fixture): verdict `anomalous`, with `overhanging bytes in values: N`,
   exits 1.
3. On a truncated blob (the section-3 log, or a cut fixture): `anomalous`
   with `truncated messages: N` (or `truncated fields: N`), exits 1.
4. Multiple paths / a glob: one block each; exit 0 iff all canonical.
5. Type dependence (S4): a blob `canonical` read raw but `anomalous`
   (`packing mismatches: N`) under a type, and vice versa, reports per
   the type in force.
6. Label coverage: each S2 annotation, from a protocraft fixture that
   carries it, produces its label with the right count, in table order.
7. An unreadable path exits 2, distinct from an anomalous verdict.
8. Deck: `bash -n`; `prototext is-canonical capture/*.pb` lists the
   files; the protolens line is a placeholder-bearing seed.

## Measured outcome

Measured 2026-10-05 on the development machine.

- `is-canonical` is a subcommand (`prototext/src/lib.rs`), dispatched to
  `run_is_canonical` (`run.rs`), which renders each file with annotations
  on and counts the `#@` keywords (`is_canonical.rs`). The keyword→label
  map and the counting are unit-tested (4 tests, including that
  `val_ohb: N` counts as `val_ohb`, not a bare `N`, and that kinds print
  in table order).
- Exit codes verified by hand: a canonical blob exits 0; an overhang or
  truncated blob exits 1 with the right label; a glob is 0 iff all
  canonical; a missing path prints `error:` and exits 2.
- End to end on a real capture (schema-free): of twelve files, the one
  response that smuggled `whoami` is `anomalous` with `overhanging bytes
  in values: 28`; the rest are `canonical`. The presenter reads that
  filename and opens it in protolens.
- The deck's section is rewritten to the single capture: one `life-tap`,
  `prototext is-canonical capture/*.pb`, then protolens on the flagged
  file via an editable `NNNNNN` placeholder. `--paused` and the fixed
  numbering are gone from it.
- `cargo fmt --check` and clippy are clean on prototext. The four
  `prototext/tests/e2e.rs` failures seen locally are the stale-local-WKT
  issue (version 6 vs 7), unrelated to this change; the Nix sandbox
  regenerates the graph and they pass there.
- Not done: a dry run of the deck in the demo shell (needs a terminal).
