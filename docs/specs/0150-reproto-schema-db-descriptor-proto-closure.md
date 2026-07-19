<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0150 — reproto: schema-db dependency closure drops suppressed `descriptor.proto`

Status: implemented
App: reproto
Implemented in: 2026-07-19

## Background

Building `googleapis.desc` via `nix-build` (`nix/python.nix`'s
`googleapisDb`, which runs `reproto --schema-db-out=... "$googleapis.pb"`
without `--emit-descriptor`) and then loading it in `protolens`/
`prototext` fails:

```
error: descriptor '.../googleapis.desc': invalid descriptor: imported
file 'google/protobuf/descriptor.proto' has not been added
```

`prost_reflect::DescriptorPool::decode` (the Rust consumer of `.desc`
files) requires a `FileDescriptorSet` to be transitively complete:
every file named in another included file's `dependency` list must
itself be present in the set.

Root cause, confirmed with a minimal reproduction (a fixture importing
`google/protobuf/descriptor.proto` to define a custom `MessageOptions`
extension, applied by a second file, compiled and run through
`reproto --schema-db-out` without `--emit-descriptor`): reproto's
"pull in WKT dependencies" mechanism (`_phase6_summoning`'s "sub-pass
3: DB dependency closure", `phases.py` ~1332–1365) and `_phase7_output`
(~1368–1381) disagree about whether `descriptor.proto` counts as
"already going to be included in the schema DB":

- `descriptor.proto`'s `is_summoned` flag genuinely becomes `True`
  whenever the corpus uses custom options (`MessageOptions`/
  `FieldOptions`/etc. extensions reference types declared in it) — this
  is correct and expected.
- Sub-pass 3 seeds its `seen`/`work` sets from every node with
  `is_summoned == True`. Since `descriptor.proto` is already `True`,
  sub-pass 3 treats it as "already handled" from the start and never
  walks it into `ctx.schema_db_extra_nodes`.
- But `_phase7_output`'s own `summoned` list — the thing that actually
  renders FDPs and appends them to `ctx.schema_db_fdps` — explicitly
  *excludes* `descriptor.proto` whenever `ctx.write_variant_descriptor`
  is `False` (i.e. `--emit-descriptor` was not passed):
  ```python
  and not (re_fdp.name == ctx.variant_descriptor_proto
           and not ctx.write_variant_descriptor)
  ```
  This exclusion exists to suppress writing `descriptor.proto` as
  `.proto` text (and `.pb`) into `--proto-out` by default — a
  deliberate, unrelated policy (nobody wants a copy of
  `descriptor.proto` cluttering their output tree by default).

The two views of "summoned" disagree, and `descriptor.proto` falls
through both inclusion mechanisms: sub-pass 3 thinks phase 7 will
render it (so it skips it), phase 7 explicitly refuses to render it
(so it doesn't). The result is a `.desc` file that is missing
`descriptor.proto` whenever it's needed only as a custom-option
dependency, silently violating the transitive-completeness invariant
`--schema-db-out` is supposed to guarantee (spec 0056/0068/0080).

This is a **schema-DB-only** bug: `--proto-out` and `--emit-binary`
output are unaffected and their existing suppression-by-default
behavior for `descriptor.proto` is correct and must be preserved.

## Goals

- **G1.** `--schema-db-out`/`--build-schema-db` always produces a
  transitively-complete `FileDescriptorSet`: every file named in the
  `dependency` list of any file included in the set must itself be
  included in the set — regardless of whether that file is
  `google/protobuf/descriptor.proto` (or any other WKT/fallback file)
  and regardless of whether `--emit-descriptor` was passed.
- **G2.** Fix the root cause by removing `descriptor.proto`'s special
  case from the *membership* question ("is this file part of the
  schema at all") entirely, so it is rendered, dependency-walked, and
  binary-accumulated exactly like every other WKT — with **no**
  changes needed to `_phase6_summoning`'s sub-pass 3. `--emit-descriptor`
  is re-scoped to be purely a disk-output-suppression switch, applied
  only at the point `_phase7_output` actually writes bytes to
  `--proto-out`, not at the point membership/rendering is decided.

## Non-goals

- N1: No change to `--proto-out`'s default suppression of
  `descriptor.proto` as `.proto` text — it remains suppressed unless
  `--emit-descriptor` is passed.
- N2: No change to `--emit-binary`'s default suppression of
  `descriptor.pb` in `--proto-out` — same suppression, same flag.
- N3: No change whatsoever to `_phase6_summoning`'s sub-pass 3 (the
  WKT dependency-closure mechanism) — once `descriptor.proto` is no
  longer excluded from `_phase7_output`'s `summoned` list, sub-pass 3's
  existing, untouched logic is already correct for it, exactly as it
  already is for every other WKT.
- N4: No change to which files count as `is_summoned` in the first
  place (reachability/summoning semantics, spec 0056 etc.) — only to
  which already-summoned files' bytes get written to `--proto-out`.

## Specification

### `reproto/src/reproto/phases.py`

`_phase7_output`'s `summoned` list drops the `descriptor.proto`
exclusion entirely, reverting to plain `is_present()`/`is_summoned` —
identical treatment to every other WKT:

```python
summoned = [
    re_fdp for re_fdp in ctx.nodes.values()
    if isinstance(re_fdp, ReFileDescriptorProto)
    and re_fdp.is_present()
    and re_fdp.is_summoned
]
```

Inside the render loop, a local flag captures the one remaining,
disk-output-only special case, computed once per `re_fdp`, and gates
every disk-visible side effect uniformly — the debug log line, the
parent-directory `mkdir`, and the two actual writes:

```python
for re_fdp in summoned:
    suppress_disk_output = (
        re_fdp.name == ctx.variant_descriptor_proto
        and not ctx.write_variant_descriptor
    )
    canonical_name = canonize_dependency(ctx, re_fdp.name)
    res_path = out_repo / Path(canonical_name)
    if ctx.debug and not suppress_disk_output:
        cli_info(f"  Writing: {res_path}")

    # Make sure all parent directories exist
    if not ctx.dry_run and not suppress_disk_output:
        res_path.parent.mkdir(parents=True, exist_ok=True)
    ...
```

Gating `mkdir` this way means it now only runs once we already know
this file's bytes are actually going to be written — no more empty
`google/protobuf/` directory in the corner case where `descriptor.proto`
would have been the only WKT living there. Gating the debug log line
the same way avoids a "Writing: .../descriptor.proto" message printing
when no such write happens.

The two actual disk-write statements gain the same guard:

```python
if ctx.binary and not ctx.dry_run and not suppress_disk_output and slot is not None and slot.out is not None:
    ...  # write .pb (unchanged otherwise)

# Accumulate for --build-schema-db — unconditional, same as today.
if ctx.build_schema_db and slot is not None and slot.out is not None:
    ctx.schema_db_fdps.append(slot.out)

if not ctx.dry_run and not suppress_disk_output:
    ...  # write .proto text (unchanged otherwise)
```

The binary-accumulation statement is **unchanged** — it was never
itself gated by the old exclusion; it only ever *appeared* broken
because `descriptor.proto` never reached this point in the loop at
all. Now that `descriptor.proto` is an ordinary member of `summoned`
whenever `is_summoned`, it gets rendered and accumulated into
`ctx.schema_db_fdps` through the exact same path as every other
summoned WKT — no dependency-closure "pull-in" via sub-pass 3 is even
needed for it anymore in the common case (sub-pass 3 remains in place,
unmodified, for the separate, pre-existing case of a WKT that is a
dependency but never itself `is_summoned`).

### Precedent

`_phase_build_schema_db`'s own `summoned_files` list (~line 1522,
used for scoring-graph YAML collection) already uses the plain
`is_summoned` flag with no `descriptor.proto` exception — this fix
makes `_phase7_output` consistent with that pre-existing precedent,
rather than introducing a new one.

## Test plan

- Regression test (new, `reproto/src/reproto/tests/test_schema_db.py`
  or alongside existing schema-db tests if a suitable file exists):
  compile `editions_roundtrip.proto` + `editions_custom_option_dep.proto`
  (existing fixtures, already exercising an imported custom
  `MessageOptions` extension) to a `FileDescriptorSet`, run
  `reproto --schema-db-out=... --use-variant descriptor` **without**
  `--emit-descriptor`, then:
  - assert the run succeeds (no crash, no missing-dependency error),
  - assert `google/protobuf/descriptor.proto` **is** one of the files
    in the resulting `.desc` `FileDescriptorSet` (via
    `FileDescriptorSet().MergeFromString(...)`),
  - assert `google/protobuf/descriptor.proto` is placed *before* any
    file that depends on it (Kahn's-algorithm ordering, unchanged by
    this fix — just confirm it still holds).
  - assert `--proto-out` still does **not** contain a
    `google/protobuf/descriptor.proto` file (N1 regression).
- Regression: existing `--emit-descriptor` tests continue to pass
  unchanged — when the flag *is* passed, `suppress_disk_output` is
  always `False` for `descriptor.proto`, so all three write sites
  behave exactly as before this fix.
- Regression: existing `--build-schema-db` tests for ordinary
  never-`is_summoned` WKT dependencies (sub-pass 3's pre-existing,
  untouched path) continue to pass unchanged.
- Regression: existing `--debug` output tests (if any) continue to
  pass; no new test needed purely for the log-line fix, but reviewers
  should note the debug line for a suppressed `descriptor.proto` no
  longer appears.
