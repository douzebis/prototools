<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0148 — reproto: load seed FDPs from every `-I` root, shadow duplicates by name

Status: implemented
Implemented in: 2026-07-19
App: reproto

## Background

`reproto -I path/to/a -I path/to/b .` only loads `FileDescriptorProto`s found
under `path/to/a`; everything under `path/to/b` is silently skipped.

Root cause is in `_load_files()` (`load.py`). `load_from_path()` is called
once per seed argument with the full `-I` root list (`phases.py`,
`_phase1_load_files`, seed-loading branch). Inside `_load_files()`, the
per-root loop resolves `root / rel_path`; when it is a directory, the
function walks it and immediately `return`s — before ever inspecting the
next root:

```python
for root in roots:
    res_path = root / rel_path
    if res_path.is_dir():
        for f in res_path.rglob('*'):
            if f.suffix in ALL_EXTENSIONS:
                loaded_files.append(QualFile(...))
        return loaded_files          # <-- bails after the first matching root
    else:
        ...                          # single-file branch: correctly tries
                                      #  every root in turn (see below)
```

The single-file branch just below is **not** affected: for a literal file
argument (or an import lookup by name during dependency discovery) it
already tries each root in order and stops at the first one that has the
file — matching `protoc -I` stacking semantics. That branch needs no change.

Investigation also surfaced that the rest of the pipeline already treats
`FileDescriptorProto.name` (not the filesystem path) as the identity for a
loaded file, and already has an implicit "first registration wins" rule
built into it:

- `QualFile.name` is always populated from the *parsed* `FileDescriptorProto.name`
  field (`split_fdps.py`), never from the filesystem `rel_path`. A single
  `.pbset`/`.protoset` file can expand into several `QualFile`s with distinct
  names via `split_fdps()`.
- `ReFile.__new__` (`topology.py`) already dedups by `.name`: if a `ReFile`
  for a given name already exists (fully initialised or not), the same
  instance is returned and `__init__` no-ops on it
  (`if not self.is_ref(): return`). A second `QualFile` sharing an
  already-registered name is today silently discarded with **no message**,
  once/if it even reaches this point.

So the fix is really two parts: (1) make the directory-scan branch actually
reach every root, and (2) make the resulting name collision — which the
rest of the system already resolves "first wins" — visible via an explicit
warning, instead of relying on the incidental silent no-op in `ReFile`.

## Goals

- **G1 (scan every `-I` root for directory-shaped seed args).** In
  `_load_files()`'s directory branch, `continue` instead of `return`, so
  every root under which `rel_path` resolves to a directory is walked and
  its files merged into `loaded_files`. After the loop, return
  `loaded_files` if non-empty; only fall through to the existing `w1`
  "not found" warning if it's empty. The single-file branch (`else:`) is
  unchanged.

- **G2 (dedup by parsed `FileDescriptorProto.name`, not filesystem path).**
  In `load_from_path()`, after all raw files have been parsed into
  `QualFile`s (i.e. after every `parse_qfile()` call, so `.name` is known),
  scan the resulting list and keep only the *first* `QualFile` seen for each
  distinct `.name`. "First" means: root order as given on `-I` (outermost
  loop), then filesystem walk order within a root for ties (e.g. two
  differently-named files under the same root that happen to declare the
  same `FileDescriptorProto.name` — a pre-existing, unrelated edge case that
  falls out of the same rule for free).

- **G3 (W7 warning per shadowed FDP).** For every `QualFile` dropped by G2,
  emit one immediate (not squashed — see N4) **W7** warning, naming the
  shadowed file first (the subject of the message) and the file that
  shadows it second, e.g.:
  ```
  Warning: path/to/b/foo.pb: definition of file:foo.proto shadowed by path/to/a/foo.pb
  ```
  W7 joins the existing W1–W6 taxonomy (spec 0041) as "duplicate FDP name
  across `-I` roots — load-time shadowing." Unlike W2 (an expected,
  reproto-controlled substitution, documented as "not a warning"), this is
  closer in spirit to W3 (duplicate-file ambiguity): overlapping `-I` roots
  providing the same declared name are usually not intentional, so it's
  worth surfacing as an actual `Warning:`, not an `Info:` notice.

- **G4 (same-root duplicates go through the same rule).** No special-casing
  needed: G2's dedup pass operates on the flat list of all parsed
  `QualFile`s regardless of which root or which raw file they came from, so
  a within-root collision (two files in the same `-I` dir yielding the same
  `.name`, e.g. via two different `.pbset`s) is naturally caught too.

## Non-goals

- N1: No shell-glob (`*`, `?`) support added to `DESCRIPTOR_FILES`
  arguments. Confirmed during investigation: no such expansion exists today
  (directory args are recursively scanned; file args are resolved
  literally, with `.proto` extension-probing as the only substitution). Out
  of scope here.
- N2: No change to the single-file resolution branch of `_load_files()`
  (used both for literal file seed args and for every import lookup during
  dependency discovery). It already correctly tries every root in order and
  stops at the first match — protoc-compatible behaviour, unaffected by
  this spec. In particular, no "shadow" message is emitted when a same-named
  file exists in a later root but is never reached because an earlier root
  already satisfied a single-file/import lookup — detecting that would
  require probing every remaining root for every import purely for
  diagnostics, which is not currently considered worth the I/O cost.
- N3: No interaction with the existing symbol-conflict pruning mechanism
  (spec 0041 §W3 / `_prune_if_duplicate` in `phases.py`). That is a later,
  content-based check at pool-build time (two files with *different* names
  that happen to define overlapping symbols) and is unrelated to this
  spec's load-time, name-based dedup of the *same* declared FDP name across
  `-I` roots.
- N4: W7 (G3) is **not** squashed/counted like W1/W4/W5 (spec 0041) — it's
  expected to be rare and each occurrence names a distinct, actionable `-I`
  configuration ambiguity, so every occurrence is printed immediately
  regardless of `--detailed-warnings`, following the precedent of W3
  (`w3()` — "always printed immediately").

## Specification

### `reproto/src/reproto/load.py`

`_load_files()` — directory branch no longer returns early:

```python
for root in roots:
    res_path = root / rel_path

    if res_path.is_dir():
        for f in res_path.rglob('*'):
            if f.suffix in ALL_EXTENSIONS:
                loaded_files.append(QualFile(
                    root,
                    f.relative_to(root),
                    f.read_text() if f.suffix in TEXT_EXTENSIONS
                    else f.read_bytes(),
                ))
        continue

    else:
        ...  # unchanged

if loaded_files:
    return loaded_files
from .lib.warnings import get_collector
get_collector().w1(str(rel_path))
return []
```

`load_from_path()` gains a post-parse dedup pass:

```python
def load_from_path(
    ctx: Context,
    roots: list[Path],
    file_or_dir_path: Path
) -> list[QualFile]:
    loaded_files = _load_files(ctx, roots, file_or_dir_path)
    qual_files: list[QualFile] = []
    for file in loaded_files:
        qual_files.extend(parse_qfile(ctx, file))

    from .lib.warnings import get_collector
    collector = get_collector()
    seen: dict[str, QualFile] = {}
    deduped: list[QualFile] = []
    for qf in qual_files:
        first = seen.get(qf.name)
        if first is None:
            seen[qf.name] = qf
            deduped.append(qf)
        else:
            collector.w7(
                qf.name,
                str(qf.root / qf.rel_path),
                str(first.root / first.rel_path),
            )
    return deduped
```

### `reproto/src/reproto/lib/warnings.py`

New `WarningCollector.w7()` method, printed immediately (mirrors `w3()`):

```python
def w7(self, fdp_name: str, shadowed_path: str, kept_path: str) -> None:
    """Duplicate FDP name across -I roots (G3) — always printed immediately."""
    cli_warning(
        f"Warning: {shadowed_path}: definition of file:{fdp_name} "
        f"shadowed by {kept_path}"
    )
```

## Test plan

- New test: two `-I` roots, each containing a distinct-named `.textpb`
  FDP under `.` — both load (regression test for the reported bug).
- New test: two `-I` roots, each containing a file that parses to the
  *same* `FileDescriptorProto.name` — only the first root's content is
  loaded (assert on FDP content, e.g. a distinguishing field/comment), and
  the shadow message fires exactly once, naming both paths.
- New test: same-root duplicate (two files under one `-I` root yielding
  the same `.name`, e.g. two `.pbset`s) also triggers exactly one shadow
  message (G4).
- Regression: existing single-`-I`-root tests continue to pass unchanged.
- Regression: existing single-file seed-arg / import-lookup tests confirm
  the `else` branch of `_load_files()` is untouched (first-root-wins,
  no shadow message emitted for a same-named file present in a later,
  never-reached root).
