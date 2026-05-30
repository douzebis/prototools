<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0090 — prototext CLI review and polish

**Status:** draft
**Implemented in:** —
**App:** prototext

---

## Background

The current CLI was designed incrementally across specs 0003, 0056, 0061, and
0088.  Now that the full subcommand surface is stable — `decode`, `encode`,
`list-schemas`, `instantiate-schema`, `score` — it is worth reviewing the
result as a whole from a user's perspective.

This spec records findings from that review and proposes concrete changes.

---

## Findings

### F1 — `--output-root` is duplicated between global and `decode`

`--output-root` / `-O` appears both at global level and inside the `decode`
subcommand.  There are two separate `output_root` fields: one in `Cli` and one
in `Command::Decode`.  This is confusing for users (where do I put `-O`?) and
creates inconsistency: `encode` uses the global `-O` while `decode` has its own.

Symptom in help output:

```
prototext --output-root DIR decode ...      # uses Cli::output_root
prototext decode --output-root DIR ...      # uses Decode::output_root
prototext encode --output-root DIR ...      # uses Cli::output_root (no subcommand copy)
```

The encode / decode asymmetry is particularly confusing.

### F2 — `--raw` is a long flag with no short form and a niche use case

`decode --raw` is schemaless decode (field numbers and wire types only).
This is already the default when no `--descriptor-set` is given and no
`--type` is specified — the only difference is that `--raw` forces it even
when a descriptor is available, and it enables annotations unconditionally.

Its relationship to the normal schemaless path is unclear from the help text.
A new user given only `prototext decode --help` cannot easily tell whether
`--raw` is needed for basic use.

### F3 — `--annotations` / `-a` is opt-in; the inverse is the default

The default for `decode` is *no annotations*.  But annotations are required
for a lossless round-trip.  This creates a footgun: a user who decodes,
edits, and re-encodes silently loses wire-type fidelity unless they remembered
`-a`.

The help text says "Required for lossless round-trip encode" but this is easy
to miss.  Annotations should be on by default; `--no-annotations` opts out for
protoc-compatible clean output.

### F4 — `--detailed-score` is opaque and hard to discover

Both `decode` and `list-schemas` have `--detailed-score`.  The flag is
correct, but its meaning ("add individual score dimensions to the output") is
opaque without reading the docs.  The help text mentions `matched, unknown,
mismatches, non_canonical` — a vocabulary that is only meaningful to users who
already understand the scoring model.  This flag, along with `--relax-ranges`
(see F5), belongs in an "advanced options" section of the help and man page.

### F5 — `--no-strict-ranges` is a double negative

The flag name requires parsing "no strict ranges" as "relax the range
strictness".  A verb-form name reads more naturally.

Proposed rename: `--relax-ranges`.

### F6 — `--no-expand-any` naming vs `--relax-ranges`

If F5 is renamed to `--relax-ranges`, the two flags use different conventions:
`--no-X` to disable a default-on feature vs. a verb form to relax a default-on
check.  This is minor.  `--no-expand-any` follows the idiomatic `--no-X`
pattern used by many CLIs (e.g. git's `--no-pager`) and is clear at a glance.
No change proposed.

### F7 — `instantiate-schema` is niche and superseded

`prototext instantiate-schema` generates pseudo-random `#@` prototext
instances.  It exists primarily to create test fixtures.  The separate
`reproto-instantiate-schema` command covers the same need better (it outputs
binary `.pb` files directly, which is what fixture pipelines consume).

The subcommand is real and not hallucinated, but it is rarely useful in normal
`prototext` workflows.  It should be removed from `prototext`.

### F8 — `--descriptor-set` / `--descriptor` alias and naming confusion

The current situation:
- Primary flag: `--descriptor-set`
- Hidden alias: `--descriptor` (deprecated)
- Env var: `PROTOTEXT_DEFAULT_DESCRIPTOR`
- Value name shown in help: `DESCRIPTOR_FILE`

Two problems:

1. `--descriptor-set` is the right primary name — it points to a
   `FileDescriptorSet` — but `--descriptor` has leaked into docs, scripts, and
   other tools in this repo.  All uses of `--descriptor` (as a flag) across
   the codebase should be replaced with `--descriptor-set`.

2. The env var `PROTOTEXT_DEFAULT_DESCRIPTOR` and the value name
   `DESCRIPTOR_FILE` are inconsistent with the flag name.  They should be
   renamed:
   - Env var: `PROTOTEXT_DESCRIPTOR_SET`
   - Value name: `DESCRIPTOR_SET_FILE`

### F9 — `score` subcommand has `--assume-binary` but `list-schemas` does not

`decode` and `score` both have `--assume-binary`.  `list-schemas` does not,
meaning it always attempts auto-detection of `#@` prototext input.  Since
`list-schemas` is typically used with raw binary files, this is fine in
practice, but the inconsistency is surprising.  Add `--assume-binary` to
`list-schemas` for completeness.

Note: `score` is a real subcommand (confirmed).  It scores one or more inputs
against a known type and reports the match breakdown.

### F10 — `--strict` is global but only affects `decode`

`--strict` (treat inference warnings as errors) is defined at the top level
but is only meaningful for `decode` auto-inference.  It is silently ignored
for `encode`, `list-schemas`, and `score`.

The idiomatic choice is to move it to the `decode` subcommand.  Options that
are only meaningful for one subcommand belong with that subcommand, not at
global level.  The argument for keeping it global (symmetry with `--quiet`)
does not hold: `--quiet` applies to all subcommands (it suppresses all
warnings on stderr); `--strict` applies to exactly one.

Moving it to `decode` also makes the auto-inference semantics clearer: it is
visually co-located with `--type` and the inference-related options.

### F11 — `--help` output and man page are thin

The top-level `--help` shows only one-line descriptions for each flag.  The
`--descriptor-set` help text is the most complete, but most other flags have
terse one-liners that do not explain the interaction between options (e.g. when
annotations are needed, when a DB-backed descriptor is required, what
"auto-inference" means).

The man page is auto-generated from the same clap metadata and inherits the
same thinness.

A richer help structure would help new users considerably.  Specifically:

- The top-level help should include a short **Examples** section.
- Subcommand help should group options into **basic** and **advanced** buckets
  (clap supports `next_help_heading`).
- The man page long descriptions (doc comments on each argument) should be
  expanded.

---

## Goals

1. **Remove `output_root` from `Command::Decode`** (F1): `--output-root` is a
   global option only; both `decode` and `encode` use `Cli::output_root`.
2. **Flip the `--annotations` default** (F3): annotations on by default; add
   `--no-annotations` to suppress them.
3. **Rename `--no-strict-ranges` → `--relax-ranges`** (F5): across `decode`,
   `list-schemas`, and `score`.
4. **Add `--assume-binary` to `list-schemas`** (F9).
5. **Remove `instantiate-schema` subcommand** (F7).
6. **Audit and replace all `--descriptor` flag usages** with `--descriptor-set`
   across the codebase (F8-1).
7. **Rename env var and value name** (F8-2): `PROTOTEXT_DEFAULT_DESCRIPTOR` →
   `PROTOTEXT_DESCRIPTOR_SET`; value name `DESCRIPTOR_FILE` →
   `DESCRIPTOR_SET_FILE`.
8. **Move `--strict` to `decode`** (F10).
9. **Improve `--help` and man page** (F11): add examples section to top-level
   help; group decode options into basic / advanced headings; expand long
   descriptions.

## Non-goals

- Removing `--raw` (F2): it has legitimate uses for debugging wire formats
  without a descriptor present.  No change.
- Changing `--no-expand-any` name (F6): keep as-is.
- Adding a short alias for `instantiate-schema` (F7 superseded by removal).

---

## Specification

### §1 — Remove `output_root` from `Command::Decode`

The `output_root` field inside the `Decode` variant is removed.  The global
`Cli::output_root` is used for all subcommands.

Before (current):

```
prototext decode --output-root DIR ...   ← used Decode::output_root
prototext encode --output-root DIR ...   ← used Cli::output_root
```

After:

```
prototext --output-root DIR decode ...   ← consistent for both
prototext --output-root DIR encode ...
```

The `conflicts_with_all = ["in_place"]` constraint that was on
`Decode::output_root` is removed; clap's existing global-level constraint is
sufficient since `--in-place` is already decode-only.

### §2 — Flip `--annotations` default

Current: annotations off by default; `-a` / `--annotations` opts in.

New: annotations on by default; `--no-annotations` opts out.

The short form `-a` is removed.  Users wanting protoc-compatible clean output
pass `--no-annotations`.

The `annotations: bool` field in `Command::Decode` becomes
`no_annotations: bool`, and the call site inverts the value (`annotations =
!no_annotations`).

Help text:

```
      --no-annotations   Suppress inline wire-type/field-number comments.
                         Output will not round-trip losslessly
```

### §3 — Rename `--no-strict-ranges` → `--relax-ranges`

In `decode`, `list-schemas`, and `score`:

```
      --relax-ranges   Downgrade out-of-range bool/enum vetoes to
                       non-canonical penalties.  32-bit overflow always
                       vetoes regardless.
```

A hidden alias `--no-strict-ranges` is kept for one release cycle.

Rust field name: `no_strict_ranges` → `relax_ranges` throughout.
`ScoringOpts::strict_ranges: bool` becomes `relax_ranges: bool` (inverted
semantics); call sites updated accordingly.

`--relax-ranges` belongs in the **advanced options** heading (see §9).

### §4 — Add `--assume-binary` to `list-schemas`

Identical behaviour to the existing flag in `decode` and `score`.

```
      --assume-binary   Treat PATH arguments as raw binary protobuf; skip
                        #@ prototext auto-detection on the input files
```

### §5 — Remove `instantiate-schema` subcommand

The `InstantiateSchema` variant is removed from `Command` in `lib.rs`.  The
supporting `run_instantiate_schema` handler in `run.rs` is removed.  The
`prototext_core::instantiate` module import in `run.rs` is removed.

Users who need pseudo-random protobuf instances should use
`reproto-instantiate-schema`, which outputs binary `.pb` files and is
better suited for fixture pipelines.

### §6 — Replace `--descriptor` with `--descriptor-set` across the codebase

Every occurrence of the `--descriptor` flag in scripts, docs, tests, and demo
files is replaced with `--descriptor-set`.  The hidden `alias = "descriptor"`
in the clap definition is kept for backward compat.

Files to audit: `demo/`, `docs/`, test fixtures, CI scripts.

### §7 — Rename env var and value name

In `Cli`:

```rust
#[arg(
    long = "descriptor-set",
    alias = "descriptor",           // hidden backward-compat alias
    value_name = "DESCRIPTOR_SET_FILE",
    env = "PROTOTEXT_DESCRIPTOR_SET",
    ...
)]
```

The old env var name `PROTOTEXT_DEFAULT_DESCRIPTOR` is supported as a silent
fallback for one release cycle: if `PROTOTEXT_DESCRIPTOR_SET` is unset but
`PROTOTEXT_DEFAULT_DESCRIPTOR` is set, use its value and, unless `--quiet` is
set, emit a deprecation warning to stderr.

### §8 — Move `--strict` to `decode`

`--strict` is removed from `Cli` and added to `Command::Decode`.

Updated help text for `decode`:

```
      --strict   Treat type-inference warnings (ambiguous type) as errors:
                 exit 1 instead of exit 2.  Only applicable when
                 auto-inferring type (no --type given and DB-backed
                 descriptor present)
```

### §9 — Improve `--help` and man page

**Top-level help**: add a short `Examples:` section after the commands list.
Clap supports this via `after_help` on the `Cli` struct.

```
Examples:
  # Decode to stdout (schemaless)
  prototext decode foo.pb

  # Decode with schema; annotations included by default
  prototext --descriptor-set my.desc decode --type com.example.Foo foo.pb

  # Suppress annotations (protoc-compatible output)
  prototext --descriptor-set my.desc decode --type com.example.Foo \
      --no-annotations foo.pb

  # Identify the schema of an unknown binary
  prototext --descriptor-set my.desc list-schemas foo.pb

  # Encode prototext back to binary
  prototext encode foo.txtpb -o foo.pb
```

**Option grouping in `decode`**: use `next_help_heading` to split options into
two groups:

```
Options:
  -t, --type <NAME>      Decode as this message type
      --raw              Decode without schema (field numbers and wire types)
      --no-annotations   Suppress inline comments (default: annotations on)
      --assume-binary    Skip #@ auto-detection; treat input as raw binary
  -i, --in-place         Rewrite input file(s) in place
  -h, --help             Print help

Advanced options:
      --detailed-score   Include score dimensions in ambiguous-type warning
      --relax-ranges     Downgrade bool/enum range vetoes to non-canonical
      --no-expand-any    Suppress google.protobuf.Any expansion
      --strict           Treat inference ambiguity as error (exit 1)
```

**Man page long descriptions**: expand the doc comments on `--descriptor-set`,
`--type`, `--annotations`/`--no-annotations`, `--raw`, and the auto-inference
behaviour in `decode` to include enough context that the man page is useful
without cross-referencing the README.

---

## Testing

- `TC-90-01`: `prototext decode FILE` emits annotations by default; output
  contains `#@` comments.
- `TC-90-02`: `prototext decode --no-annotations FILE` suppresses `#@` comments.
- `TC-90-03`: `prototext --output-root OUT decode FILE` writes to `OUT/FILE`.
- `TC-90-04`: `prototext decode --output-root DIR` is rejected (flag no longer
  exists on subcommand).
- `TC-90-05`: `prototext decode --relax-ranges` accepted;
  `--no-strict-ranges` still accepted (hidden alias).
- `TC-90-06`: `prototext list-schemas --assume-binary FILE` accepted.
- `TC-90-07`: `prototext instantiate-schema` is rejected (subcommand removed).
- `TC-90-08`: `PROTOTEXT_DESCRIPTOR_SET=my.desc prototext decode FILE` uses
  `my.desc`; `PROTOTEXT_DEFAULT_DESCRIPTOR` still accepted with deprecation
  warning.
- `TC-90-09`: `prototext --descriptor-set FILE decode --strict` accepted;
  `prototext --strict decode FILE` is rejected (flag moved to subcommand).

---

## Open questions

- None.
