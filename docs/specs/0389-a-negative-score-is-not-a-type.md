<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0389 — a negative score is not a type

Status: implemented
Implemented in: 2026-10-04
App: protolens, prototext
Refs: docs/specs/0168-protolens-resolve-root-type-before-decode.md (the
      startup root-type inference this spec puts a floor under);
      docs/specs/0310-a-cut-file-is-not-a-wrong-file.md (a truncated file
      scores what it has, which is why a cut log can still score);
      docs/specs/0090-cli-review.md (shared `PROTOTEXT_*` env vars across
      the tools);
      docs/specs/0388-the-demo-runs-from-grehack2026.md (section 3 of the
      GreHack demo, where this shows)

## Background

When no `--type` is given, both tools infer the root type by scoring the
blob against every message in the schema DB. They then take the
top-scoring candidate, unless the second ties it:

- protolens: `pick_winner` (`protolens/src/decode.rs`).
- prototext: `infer_type` (`prototext/src/run.rs`), which returns
  `InferOutcome::Ambiguous` on a tie and `Unique` otherwise.

Neither looks at the score itself. A score is matches minus weighted
penalties (`prototext-graph/src/score/walk.rs`): −1 per packing issue,
−5 truncated, −10 unknown, −15 out of range, −20 non-canonical, −30
mismatch. A negative score means the type contradicts the bytes more
than it explains them, yet it wins whenever nothing ties it.

Measured on 2026-10-04 with `prototext list-schemas` against the
client-derived `life.desc` of the GreHack demo:

| Blob | Best candidate | Score |
|---|---|---|
| `capture/000001-response.pb` | `grehack.life.v1.StepResponse` | 3087 |
| `capture/000002-request.pb` (carries the covert channel) | `grehack.life.v1.StepRequest` | 2814 |
| `eve/server.log` (type not in the DB) | `grehack.life.v1.Row` | −55 |

protolens opens the log as a `Row`. That's wrong, and it spoils the
demo's point that the log's type is unknown. The right outcome is no
type at all, as on a tie.

## Goals

- **G1.** An inferred root type is used only if its score is at least a
  threshold. The default threshold is 0.
- **G2.** The threshold can be set per run, to any integer, positive or
  negative, or turned off.
- **G3.** protolens and prototext apply the same rule, so they agree
  about the same blob.
- **G4.** When the best candidate is rejected for its score, the user is
  told which candidate it was, its score, and the threshold.

## Non-goals

- **N1.** Heat cues are unchanged. They score each part of the blob
  separately, and section 3 of the demo relies on them recognizing
  `Request` and `Response` inside a blob whose root matches nothing.
- **N2.** No change to how scores are computed, nor to `list-schemas`
  and `score`, which report every score as it is.
- **N3.** No threshold relative to the blob's size (for example
  penalties divided by matches). Scores grow with the number of
  fields, so any threshold other than 0 means different things for
  small and large blobs. 0 does not have that problem, and an absolute
  number is easier to explain. Reconsider if a fixed number proves not
  to be enough.
- **N4.** The override pane is unchanged: it still lists every candidate,
  ranked, including those below the threshold, so a rejected type can
  still be chosen by hand.

## Specification

- **S1. The rule.** The top candidate is the inferred type only if no
  other candidate ties it and its score is at least the threshold.
  Otherwise there is no inferred type: protolens opens the blob with no
  type, as it does on a tie today, and prototext reports it as it does
  an ambiguous result.

- **S2. The option.** Both tools take `--min-score <N>`:
  - `N` is any `i64`. A leading minus is accepted
    (`--min-score -100`); in clap this needs `allow_negative_numbers`
    or `allow_hyphen_values` on the argument.
  - `--min-score any` turns the floor off, which is today's behavior.
  - The default is `0`.
  - The env var `PROTOTEXT_MIN_SCORE` sets it for every tool, like
    `PROTOTEXT_DESCRIPTOR_SET`. The command line wins over the env var.

- **S3. Where it applies.**
  - protolens: `pick_winner` takes the threshold and returns `None` below
    it. Only the startup inference (`RootType::Infer`) uses it;
    `--type` and `--raw` ignore it.
  - prototext: `infer_type` gains a third outcome,
    `InferOutcome::BelowThreshold { best, threshold }`. Every path that
    handles `Ambiguous` handles this one the same way: report it, and
    under `--strict` exit 1.

- **S4. What the user sees.**
  - protolens's startup line names the rejected candidate:
    `protolens: best candidate grehack.life.v1.Row scored -55, below
    --min-score 0: rendering with no type`.
  - prototext's report says the same, in the format of its ambiguous
    report.

## Alternatives considered

### Keep the tie rule and add `--raw` to the demo

The demo could open the log with `--raw`. That hides the problem rather
than fixing it: anyone else who opens a file whose type is not in their
DB still gets a confident wrong type. It also skips the inference the
audience is meant to watch fail.

### A fixed floor with no option

Simpler, but a slightly negative score can still be the right type, for
example on a badly damaged blob. An option costs little.

### Apply the floor to heat cues too

That would hide exactly the per-part recognition section 3 relies on
(N1).

## Test plan

1. `pick_winner_rejects_a_score_below_the_threshold`: candidates
   `[("a.Row", -55), ("a.Other", -80)]` give `None` at threshold 0, and
   `Some("a.Row")` at `-100` and with `any`.
2. `pick_winner_keeps_a_tie_ambiguous`: a top-score tie is still `None`,
   whatever the threshold.
3. `pick_winner_accepts_the_threshold_itself`: a score equal to the
   threshold wins.
4. prototext `infer_type` returns `BelowThreshold` for the same
   candidates, and `decode --strict` exits 1 on it.
5. CLI: `--min-score -100`, `--min-score=-100`, `--min-score any` and
   `PROTOTEXT_MIN_SCORE` all parse; `--min-score abc` is rejected.
6. End to end on the demo's files: with the default threshold, protolens
   opens `eve/server.log` with no type, and still types
   `capture/000001-response.pb` and `capture/000002-request.pb`.

## Measured outcome

Measured 2026-10-04 on the development machine.

- The threshold type, `MinScore`, lives in `prototext-graph`
  (`score/min_score.rs`), which both tools depend on. protolens's
  `pick_winner` and prototext's `infer_type` both use it. A second
  helper, `rejected_for_score`, gives protolens the candidate its
  startup line names.
- prototext reports a rejected file under its usual "type inference
  issues" heading, with a `below_min_score: <N>` line, and does not
  decode it, exactly as for an ambiguous file. `--strict` makes it exit 1.
- On the GreHack demo files, against `life.desc`:
  - `eve/server.log` (its best candidate, `Row`, scored −155 by then: the
    log had grown since the Background measurement) opens with no type.
    protolens prints `best candidate grehack.life.v1.Row scored -155,
    below --min-score 0: rendering with no type`.
  - With `--min-score -200` or `any`, the old behavior returns.
  - `capture/000002-request.pb` is still typed `StepRequest` (2814).
- Test plan items 1–5 are unit tests (`pick_winner_*`,
  `a_winner_below_the_floor_is_not_used`,
  `min_score_parses_negative_numbers_and_any`, and three `MinScore`
  tests). The `PROTOTEXT_MIN_SCORE` env var was checked by hand rather
  than in a unit test, since setting an env var in a test races with
  other tests. Item 6 was checked by hand, as above.
- The Nix sandbox test run (`nix-build -A rust-tests`) passes in full:
  all 34 test binaries, protolens's 1280 tests included. Run locally,
  four of prototext's e2e tests fail with "unsupported scoring-graph
  version 6". That is not this change: the local build output still
  embeds a WKT graph generated on 2026-09-25/26, before the format moved
  to version 7 (2026-09-29, spec 0371), and cargo never reran the build
  script. The sandbox regenerates it, and there they pass.
- Clippy and `cargo fmt --check` are clean on the three crates.
