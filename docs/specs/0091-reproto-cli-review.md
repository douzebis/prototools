<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0091 — reproto CLI review and polish

**Status:** draft
**Implemented in:** —
**App:** reproto, reproto-instantiate-schema

---

## Background

`reproto` is a flat (no-subcommand) Click CLI that has grown organically across
many specs.  It is more polished than the old `prototext` CLI in several
respects — option groupings are already present in the help output, and most
flags are clearly named.  However, a review from a fresh-user perspective
reveals a handful of rough edges, and cross-tool consistency with the changes
proposed in spec 0090 raises additional items.

---

## Findings

### F1 — Three options bury their output-path argument

`--build-schema-db`, `--emit-scoring-html`, and `--output-root` all write to a
path supplied by the user, but none of their names make it obvious that the
argument is a *destination*.

**`--build-schema-db FILE`**: the verb `build` suggests an action, not a path
parameter.  A user who types `reproto --build-schema-db` without a path gets a
cryptic Click error.

**`--emit-scoring-html FILE`**: `--emit-binary` and `--emit-scoring-yaml` are
boolean flags that take no argument, so their verb form is unambiguous.
`--emit-scoring-html FILE` is different: the FILE argument is required but the
name does not communicate that.

**`--output-root DIR`**: `output` is verb-ambiguous (could be read as "output
[the] root").  The name is already established and understood, but the `-out`
suffix pattern is strictly clearer.

Proposed renames, all using the `-out` suffix convention that makes destination
unambiguous and the path nature explicit:

- `--build-schema-db FILE` → `--schema-db-out FILE`
- `--emit-scoring-html FILE` → `--scoring-html-out FILE`
- `--output-root DIR` → `--proto-out DIR`

All three old names are kept as hidden deprecated aliases that emit a
deprecation warning on use.

Note: `--proto-out` aligns with the protoc plugin convention (`--java_out`,
`--python_out`) and makes it explicit that the output is specifically `.proto`
files — a meaning that `--output-root` does not convey.  The rename is
reproto-specific; `prototext` outputs prototext/`.txtpb` files so
`--output-root` remains the right name there.

### F2 — Positional argument name `PB_FILES` is confusing

The positional arguments are called `PB_FILES` in the usage line, but they
accept much more than `.pb` files:

- Binary `FileDescriptorSet` (any extension)
- Binary `FileDescriptorProto` (any extension)
- `#@` prototext-format `FileDescriptorSet` or `FileDescriptorProto`
- Directories (processed recursively)
- Any file extension; `.pb` and `.desc` are conventional but not required

Additionally, `PB_FILES` clashes visually with `--pb-path`, suggesting that
the positional paths are resolved relative to `--pb-path`.  This is in fact
correct — positional paths that are relative are resolved against the roots
given in `--pb-path` — but the name `PB_FILES` does not hint at this
relationship.

Proposed rename of the positional metavar: `DESCRIPTOR_FILES` (plural, since
`nargs=-1`).  The `--help` and man page should include a short explanation of
the accepted formats and directory handling.

`--pb-path` is also renamed to `--desc-root` (see §4).

### F3 — `--pb-path` help text is incomplete, and the name is stale

`--pb-path` is the resolution root for positional `DESCRIPTOR_FILES` arguments
(in addition to being a search path used internally when loading descriptors).
The current help text — "Search path for .pb files (like protoc -I)" — does
not mention the resolution role for positional arguments.

The name `--pb-path` was originally chosen for consistency with protoc's
`--proto-path`, but that rationale is no longer compelling: the tool is called
`reproto` (not `protoc`), the positional arguments are now called
`DESCRIPTOR_FILES`, and the option is just as much about `.desc` files as
`.pb` files.

Proposed rename: `--desc-root` (short form `-I` retained).  Hidden alias
`--pb-path` kept for backward compat.

The new help text:

> "Root directory for resolving relative DESCRIPTOR_FILES paths and for
> locating imports (repeatable; like protoc -I)."

### F4 — `--proto-out` is optional in schema-DB mode but the help says nothing

When `--schema-db-out` is given (or `--dry-run`, or `--scoring-html-out`),
`--proto-out` is not required — no `.proto` files are generated.  The help
for `--proto-out` says "Output directory for generated proto files (created
if absent)" with no hint that it can be omitted in these modes.

A user who forgets `-O` in proto-generation mode gets the error:

```
Missing option '-O' / '--proto-out'.
```

This is correct but abrupt.  The error should enumerate all the ways to
satisfy the requirement:

```
Missing option '-O' / '--proto-out'.
Required when generating .proto output.  Alternatives:
  - Add -O DIR to write .proto files to DIR
  - Add --schema-db-out FILE to write a schema DB only
  - Add --scoring-html-out FILE to write HTML graphs only
  - Add --dry-run to run without writing any files
```

### F5 — `--scoring-html-out` group and `--debug` belong in Advanced, not Diagnostics

`--scoring-html-out FILE` writes HTML scoring-graph visualisations.  This is
a niche feature — primarily used for the demo and educational purposes, rarely
used in production.  It is currently listed under `Diagnostics` alongside
`--quiet` and `--debug`.

`--debug` is similarly niche: it is rarely used in normal operation and has
no effect on output correctness.

Both should be moved to an `Advanced` section of the help, alongside the
modifiers `--with-leaf-nodes` and `--hide`.  This keeps the `Diagnostics`
group focused on the flags most relevant for day-to-day troubleshooting
(`--detailed-warnings`, `--quiet`, `--debug-fqdn`).

### F6 — `--seed` and `--prune` prefix syntax is undiscoverable, and bare names could be inferred

`--seed` and `--prune` require one of several known prefixes to disambiguate
the kind of target: `file:`, `desc:`, `enum:`, `serv:`, `meth:`, `fdsc:`.
A user who forgets the prefix gets a confusing error or silent misbehaviour.

Proposed auto-resolution for non-wildcard values when no prefix is given:

1. Try `file:<value>` first.
2. If no match, try all other known prefixes (`desc:`, `enum:`, `serv:`,
   `meth:`, `fdsc:`); collect all that match.
3. If exactly one prefix (from steps 1 and 2 combined) matches, use it
   silently.
4. If more than one matches, exit with an error naming the ambiguity and
   requiring an explicit prefix.
5. If none matches, pass through as-is (let the downstream code produce
   the original error).

For values containing a wildcard (`*`, `**`, `?`) and no explicit prefix —
prepend `file:` unconditionally.  The rationale is that wildcards expand to
multiple results, so attempting to auto-resolve across all prefixes would
invariably hit the ambiguity case in step 4 whenever both `file:` and any
other prefix match.  Treating wildcard patterns as `file:` is the only
semantically unambiguous choice.

The same logic applies to `--prune`.

This makes the common case (`--seed my.Msg`) work without the prefix,
while preserving exact semantics for explicit prefixes and preventing silent
wrong resolution.

### F7 — `--force-proto2-for-editions` embeds stale implementation notes

The help string for `--force-proto2-for-editions` contains:

> `--build-schema-db forces this unconditionally (prost-reflect does not yet
> support editions, upstream PR #1347).`

This is implementation detail that will become stale once the upstream issue
is resolved, and singles out an internal library in user-facing help text.

Remove the parenthetical.  The help becomes:

> `--schema-db-out forces this unconditionally.`

The upstream reference is moved to an inline code comment.

### F8 — `--quiet` semantics

`reproto --quiet` currently suppresses progress messages only.  Warnings are
always printed regardless of `--quiet`.  This is narrower than the common CLI
convention where `-q` suppresses all non-error output including warnings.

The behaviour should be changed to match the idiomatic convention: `--quiet`
suppresses both progress messages and warnings.  Only errors are always
printed.

### F9 — `reproto-instantiate-schema` uses the old env var name

`reproto-instantiate-schema` falls back to `PROTOTEXT_DEFAULT_DESCRIPTOR`.
Per spec 0090 §7, this is renamed to `PROTOTEXT_DESCRIPTOR_SET`.

Also, the help currently shows both `--descriptor-set` and `--descriptor` as
co-equal primary names.  Per the convention established in spec 0090,
`--descriptor-set` is the primary name; `--descriptor` becomes a hidden alias.

### F10 — No `--help` examples section

Like `prototext` (spec 0090, F11), `reproto` has no examples in its help
output.  Given the complexity of the flag surface and the non-obvious interplay
between `--seed`, `--prune`, `--schema-db-out`, and `--proto-out`, examples are
particularly valuable.

---

## Goals

1. **Rename `--build-schema-db` → `--schema-db-out`** (F1): deprecated alias
   `--build-schema-db` kept with deprecation warning.
2. **Rename `--emit-scoring-html` → `--scoring-html-out`** (F1): deprecated alias
   `--emit-scoring-html` kept with deprecation warning.
3. **Rename `--output-root` → `--proto-out`** (F1): deprecated alias
   `--output-root` kept with deprecation warning.
4. **Rename positional metavar** from `PB_FILES` to `DESCRIPTOR_FILES` (F2):
   update `--help` and man page with format and directory notes.
5. **Rename `--pb-path` → `--desc-root`** (F3): hidden alias `--pb-path`
   kept; improve help text.
6. **Improve missing-`-O` error message** (F4): enumerate all alternatives.
7. **Move `--scoring-html-out`, `--with-leaf-nodes`, `--hide`, `--debug`
   to Advanced** (F5).
8. **Implement prefix auto-resolution for `--seed` and `--prune`** (F6): bare
   non-wildcard values try `file:` first, then all other known prefixes,
   accepting only unambiguous single-prefix matches.
9. **Remove stale implementation note from `--force-proto2-for-editions`**
   (F7).
10. **Extend `--quiet` to suppress warnings** (F8).
11. **Update `reproto-instantiate-schema`** (F9): `PROTOTEXT_DESCRIPTOR_SET`
    env var (deprecation fallback for old name); `--descriptor` hidden alias.
12. **Add examples to `--help`** (F10).

## Non-goals

- Renaming `--seed` / `-s` to avoid nominal conflict with
  `reproto-instantiate-schema --seed`: the two tools are sufficiently distinct
  that the shared name is not a practical problem.
- Changing the `desc:` / `file:` prefix syntax: it is still required for
  explicit disambiguation and wildcard patterns; auto-resolution (Goal 8) is
  additive.

---

## Specification

### §1 — Rename `--build-schema-db` → `--schema-db-out`

```python
@click.option(
    '--schema-db-out',
    '--build-schema-db',   # hidden deprecated alias
    'build_schema_db',
    required=False,
    default=None,
    type=click.Path(dir_okay=False, writable=True, path_type=Path),
    help=(
        'Write the schema DB to FILE (must end in .desc). '
        'Writes FILE (FileDescriptorSet of all loaded FDPs), '
        'FILE-stem/hopcroft.rkyv (compiled scoring graph), and '
        'FILE-stem/index.rkyv (lazy-loading FDS index).'
    ),
)
```

`--build-schema-db` is hidden (`hidden=True` on the alias entry).  When a
user passes `--build-schema-db`, print a deprecation warning to stderr:

```
warning: --build-schema-db is deprecated; use --schema-db-out
```

All references to `--build-schema-db` in help strings for other options (e.g.
`--force-proto2-for-editions`) are updated to `--schema-db-out`.

### §2 — Rename `--emit-scoring-html` → `--scoring-html-out`

```python
@click.option(
    '--scoring-html-out',
    '--emit-scoring-html',   # hidden deprecated alias
    required=False,
    type=click.Path(file_okay=True, dir_okay=False, writable=True, path_type=Path),
    help='Write scoring-graph HTML visualisations to FILE; requires --schema-db-out',
)
```

`--emit-scoring-html` is hidden with a deprecation warning (same pattern as §1).
The existing `--emit-pyvis` alias remains hidden and deprecated as before.

### §3 — Rename `--output-root` → `--proto-out`

```python
@click.option(
    '-O', '--proto-out',
    '--output-root',   # hidden deprecated alias
    'proto_out',
    required=False,
    default=None,
    type=click.Path(file_okay=False, dir_okay=True, path_type=Path),
    help=(
        'Output directory for generated .proto files (created if absent). '
        'Not required when using --schema-db-out, --scoring-html-out, or --dry-run.'
    ),
)
```

`--output-root` is hidden with a deprecation warning:

```
warning: --output-root is deprecated; use --proto-out
```

### §4 — Rename positional metavar to `DESCRIPTOR_FILES`

```python
@click.argument(
    'pb_files',
    nargs=-1,
    metavar='DESCRIPTOR_FILES',
    type=click.Path(path_type=Path),
)
```

Usage line:

```
Usage: reproto [OPTIONS] DESCRIPTOR_FILES...
```

The `--help` output (via `epilog` or the command docstring) and the man page
include a short note:

> `DESCRIPTOR_FILES` accepts binary `FileDescriptorSet`, binary
> `FileDescriptorProto`, `#@` prototext-format descriptors, or directories
> (processed recursively).  Any file extension is accepted; `.pb` and `.desc`
> are conventional.  Relative paths are resolved against `--desc-root` roots.

### §5 — Rename `--pb-path` → `--desc-root`

```python
@click.option(
    '-I', '--desc-root',
    '--pb-path',   # hidden backward-compat alias
    'pb_path',
    multiple=True,
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    help=(
        'Root directory for resolving relative DESCRIPTOR_FILES paths '
        'and for locating imports (repeatable; like protoc -I).'
    ),
)
```

`--pb-path` is hidden (`hidden=True` on the alias entry).

### §6 — Improve missing-`-O` error message

In `cli.py`, replace:

```python
raise click.UsageError('Missing option \'-O\' / \'--output-root\'.')
```

with:

```python
raise click.UsageError(
    "Missing option '-O' / '--proto-out'.\n"
    "Required when generating .proto output.  Alternatives:\n"
    "  - Add -O DIR                   to write .proto files to DIR\n"
    "  - Add --schema-db-out FILE     to write a schema DB only\n"
    "  - Add --scoring-html-out FILE  to write HTML graphs only\n"
    "  - Add --dry-run                to run without writing any files"
)
```

### §7 — Move `--scoring-html-out` group and `--debug` to Advanced

In the `OPTION_GROUPS` dict:

```python
'--scoring-html-out': 'Advanced',
'--with-leaf-nodes':  'Advanced',
'--hide':             'Advanced',
'--debug':            'Advanced',
```

The `Diagnostics` group then contains: `--detailed-warnings`, `--quiet`,
`--debug-fqdn`.

### §8 — Prefix auto-resolution for `--seed` and `--prune`

Add a helper `_resolve_seed_or_prune(value: str, ctx) -> str` that:

1. If `value` already starts with a known prefix followed by `:` — pass
   through unchanged.
2. If `value` contains a wildcard (`*`, `**`, `?`) and has no prefix —
   prepend `file:` unconditionally.  (Wildcards expand to multiple results;
   trying all prefixes would invariably produce an ambiguity error.)
3. Otherwise (bare non-wildcard, no prefix):
   a. Try matching as `file:<value>`.
   b. Try matching as each of the other known prefixes (`desc:`, `enum:`,
      `serv:`, `meth:`, `fdsc:`).
   c. Collect all prefixes that produce a match.
   d. If exactly one matches, use it silently.
   e. If more than one matches, raise `click.UsageError` naming the ambiguity
      and requiring an explicit prefix.
   f. If none matches, pass through as-is (let the downstream code produce
      the original error).

This helper is called from the `seeds` and `stumps` normalisation in `main()`.

### §9 — Remove stale implementation note from `--force-proto2-for-editions`

Current help (excerpt):

> `--build-schema-db forces this unconditionally (prost-reflect does not yet
> support editions, upstream PR #1347).`

New:

> `--schema-db-out forces this unconditionally.`

Add to the source code above the option declaration:

```python
# Note: --schema-db-out forces --force-proto2-for-editions unconditionally
# because prost-reflect does not yet support editions syntax in compiled graphs.
# See upstream issue #1347.
```

### §10 — Extend `--quiet` to suppress warnings

Change `reproto --quiet` to suppress both progress messages and warnings.
Only errors (printed via `cli_error`) continue to appear regardless of
`--quiet`.

In `phases.py` and wherever `cli_warning()` is called, gate the call on
`not ctx.quiet`.  The `CLIWarningHandler` in `cli.py` is updated to check the
quiet flag, or alternatively `cli_warning()` calls are wrapped at their call
sites.

Update the `--quiet` help text:

```python
help='Suppress progress messages and warnings.  Errors are always printed.'
```

### §11 — Update `reproto-instantiate-schema`

In `instantiate_cli.py`:

- Change the option to show `--descriptor-set FILE` as the primary name;
  make `--descriptor` a hidden alias.
- Env var lookup:
  ```python
  env_val = (
      os.environ.get('PROTOTEXT_DESCRIPTOR_SET')
      or _deprecated_env('PROTOTEXT_DEFAULT_DESCRIPTOR', quiet)
  )
  ```
  where `_deprecated_env(name, quiet)` returns the value and, if not quiet,
  prints a deprecation warning to stderr.
- Help text: `[env: PROTOTEXT_DESCRIPTOR_SET]`.

### §12 — Add examples to `--help`

Add an `epilog` to the `@click.command` decorator:

```
Examples:

  # Decompile a descriptor to .proto source
  reproto -O out/ schema.desc

  # Build a scoring DB from a descriptor slice
  reproto --schema-db-out slice.desc \\
      --seed desc:.com.example.MyMessage schema.desc

  # Decompile all types reachable from a seed, pruning a noisy package
  reproto -O out/ \\
      --seed desc:.com.example.Root \\
      --prune file:google/protobuf/struct.proto \\
      schema.desc

  # Score and visualise the graph (advanced)
  reproto --schema-db-out out.desc \\
      --scoring-html-out out.html \\
      schema.desc
```

---

## Consistency with spec 0090

| Topic | prototext (0090) | reproto (this spec) |
|---|---|---|
| Descriptor input | `--descriptor-set FILE` flag | positional `DESCRIPTOR_FILES` |
| Env var | `PROTOTEXT_DESCRIPTOR_SET` | same (consumed by `reproto-instantiate-schema`) |
| `-I` short form | `--input-root DIR` | `--desc-root DIR` — different semantics, same short form |
| `-O` short form | `--output-root DIR` | `--proto-out DIR` — reproto-specific name |
| `-q` / `--quiet` | suppress warnings | suppress progress + warnings (aligned) |
| Examples in help | `after_help` block | `epilog` block |

---

## Open questions

- None.
