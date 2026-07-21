<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0155 — reproto: allow `-O` under the `--schema-db-out` stub as `proto/`; protolens: default `--proto-root` from it

Status: implemented
Implemented in: 2026-07-21
App: reproto, protolens

## Background

`reproto --schema-db-out FILE.desc` writes three artifacts derived from
`FILE`'s stub (`FILE` with the `.desc` suffix stripped):

- `FILE` itself (a `FileDescriptorSet`),
- `<stub>/hopcroft.rkyv` (compiled scoring graph),
- `<stub>/index.rkyv` (lazy-loading FDS index).

`-O`/`--proto-out` is an independent, unrelated output directory for
reconstructed `.proto` sources. Nothing today prevents `-O` from
pointing anywhere, including inside `<stub>/`, which risks the two
outputs' files colliding or making the stub directory's contents
unpredictable (today it must contain exactly `hopcroft.rkyv` and
`index.rkyv`).

Separately, `protolens`'s `-I`/`--proto-root` (spec 0144) has no
default: if neither `$PROTOTEXT_PROTO_ROOT` nor `-I`/`--proto-root` is
given, `v` (jump-to-definition) always reports "no proto root
configured". When a `.desc` file was produced by
`reproto --schema-db-out FILE.desc -O <stub>/proto/`, the matching
`.proto` sources are always discoverable at a fixed, predictable
location relative to `FILE` — `protolens FILE ...` should find them
without requiring `--proto-root` to be spelled out every time.

## Goals

- **G1.** `reproto`: when both `--schema-db-out FILE` and `-O DIR` are
  given, `DIR` may only be located inside `FILE`'s stub directory
  (`FILE` with `.desc` stripped) if `DIR` is exactly that stub
  directory's immediate child named `proto` (i.e. `<stub>/proto/`).
  Any other location inside the stub directory (the stub directory
  itself, a differently-named immediate child, or anything nested
  deeper) is a hard `UsageError`. A `DIR` entirely outside the stub
  directory is unaffected — allowed exactly as today.
- **G2.** `protolens`: when neither `$PROTOTEXT_PROTO_ROOT` nor
  `-I`/`--proto-root` is given, default `proto_root` to
  `<stub>/proto/`, where `<stub>` is `--descriptor-set`'s path with
  its extension stripped (the same stub convention `reproto` and
  protolens's own `hopcroft.rkyv` sibling-graph lookup already use —
  `decode.rs:88-89`, `main.rs:181`). If that directory does not exist,
  `proto_root` silently stays `None` (identical to today's unset
  behavior) — no error, no warning.

## Non-goals

- N1: No change to `-O`'s behavior when `--schema-db-out` is absent —
  the new validation only triggers when both options are given.
- N2: No change to the runtime `:proto-root <dir>` TUI command (spec
  0144 G4) — it keeps validating and setting `proto_root` exactly as
  it does today; G2 only changes what `proto_root` defaults to at
  startup before any `:proto-root` command runs.
- N3: No content/existence validation of the discovered `<stub>/proto/`
  directory beyond "is it a directory" — e.g. protolens does not check
  it actually contains the specific `.proto` file `v` will need; that
  remains `open_definition`'s existing "proto source not found"
  runtime check (spec 0144 G4).

## Specification

### `reproto/src/reproto/cli.py`

Immediately after the existing `.desc`-suffix check:

```python
if build_schema_db is not None and not str(build_schema_db).endswith('.desc'):
    raise click.UsageError('--schema-db-out PATH must end in .desc')
```

add, guarded on both options being present:

```python
if build_schema_db is not None and proto_out is not None:
    stub_dir = build_schema_db.with_suffix('').resolve()
    resolved_out = proto_out.resolve()
    try:
        rel = resolved_out.relative_to(stub_dir)
    except ValueError:
        rel = None  # proto_out is not inside stub_dir at all — fine
    if rel is not None and rel != Path('proto'):
        raise click.UsageError(
            f"-O/--proto-out ({proto_out}) is inside the --schema-db-out "
            f"stub directory ({stub_dir}); only an immediate 'proto' "
            "child directory is allowed there — it otherwise holds "
            "hopcroft.rkyv/index.rkyv."
        )
```

`rel == Path('.')` (i.e. `-O` given as the stub directory itself) also
fails the `rel != Path('proto')` check, so that case is rejected too,
per G1.

Help text: `--schema-db-out`'s help string gains a short note about
this constraint; `-O`/`--proto-out`'s help string gains a
cross-reference.

### `protolens/src/main.rs`

A small, independently unit-testable function:

```rust
/// Default `proto_root` from `<descriptor_set-stub>/proto/` when the
/// caller didn't set one explicitly (spec 0155 G2) — `None` (no
/// fallback applied) whenever `cli_proto_root` is already `Some`, or
/// whenever the candidate directory doesn't exist.
fn resolve_proto_root(cli_proto_root: Option<PathBuf>, descriptor_set: &Path) -> Option<PathBuf> {
    cli_proto_root.or_else(|| {
        let candidate = descriptor_set.with_extension("").join("proto");
        candidate.is_dir().then_some(candidate)
    })
}
```

Called in `main()` right after `descriptor_set` is resolved, replacing
the current `cli.proto_root.clone()` passed to `App::new`:

```rust
let proto_root = resolve_proto_root(cli.proto_root.clone(), descriptor_set);
// ...
let mut app = tui::App::new(..., proto_root);
```

`Cli.proto_root`'s doc comment gains a note describing the fallback.

## Test plan

- `reproto/src/reproto/tests/test_schema_db_proto_subdir.py` (new),
  invoking `python -m reproto.cli` as a subprocess with a nonexistent
  dummy `DESCRIPTOR_FILES` argument (the validation runs before any
  file is loaded, so no `protoc`-compiled fixture is needed):
  - `-O <stub>/proto` — succeeds (past this validation; may fail later
    for unrelated reasons with a dummy input, which the test tolerates
    by asserting the specific UsageError text is absent).
  - `-O <stub>` (the stub itself) — `UsageError`.
  - `-O <stub>/desc` — `UsageError`.
  - `-O <stub>/nested/proto` — `UsageError`.
  - `-O <anything-outside-stub>` — succeeds past this validation.
  - `--schema-db-out` absent, `-O` anywhere — succeeds past this
    validation (N1).
- `protolens/src/main.rs`: `#[cfg(test)] mod tests` for
  `resolve_proto_root`:
  - `cli_proto_root = Some(x)` — returned unchanged regardless of
    `<stub>/proto/`'s existence.
  - `cli_proto_root = None`, `<stub>/proto/` exists as a directory —
    returns `Some(<stub>/proto/)`.
  - `cli_proto_root = None`, `<stub>/proto/` does not exist — returns
    `None`.
  - `cli_proto_root = None`, `<stub>/proto` exists but is a file, not
    a directory — returns `None`.
