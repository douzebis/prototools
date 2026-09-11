<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0369 — the FDP plugin is applied at every parse, starting before phase 1

Status: implemented
Implemented in: 2026-09-11
App: reproto
Refs: docs/specs/0051-fallback-object-identity.md (why topo-sort
      object identity is load-bearing — the same ranking machinery this
      spec protects);
      docs/specs/0087-strip-unresolvable-field-types.md (the silent
      field deletion that a late-added dependency triggers);
      docs/specs/0148-reproto-multi-root-fdp-loading.md (the W7 dedup
      that runs after parsing, hence after the plugin);
      docs/specs/0149-reproto-filter-config-file.md (seed-by-path:
      `path_seeds` is keyed on the pre-plugin `rel_path`);
      docs/specs/0243-a-blob-is-a-root-and-the-defaults-fill-the-rest.md
      (blob members: a member's `rel_path` is read from the pre-plugin
      `fdp.name`)

## Background

`--phase2-plugin` lets a caller mutate a `FileDescriptorProto` before
reproto ingests it.  It is invoked at `phases.py:918` (text branch) and
`phases.py:934` (binary branch), inside the rank loop of phase 2.

That is too late for any patch that touches `fdp.dependency`, because
phase 1 has already consumed the *unpatched* dependency list twice:

- `topology.py:112-123` builds `ReFile.targets` from `fdp.dependency`
  while ingesting each `QualFile`;
- `phases.py:503-520` is a fixpoint loop that, for every `ReFile` still
  in the `is_ref()` state, calls `load_from_path` to fetch the file off
  the `-I` path.  A file becomes a ref *only* because some already-
  ingested FDP named it as a dependency.

So the dependency list decides both the rank ordering
(`phases.py:881-889` derives ranks from `targets`) and which
supplementary files are read from disk at all.

A dependency added in phase 2 therefore lands in one of three tiers,
ordered here by how far the patch gets before something intercepts it.
Severity runs the other way: tier 1 is the worst, because it is the
only one that destroys data without saying so.

1. **The named file was loaded anyway.** The import survives
   `_strip_unresolvable_dependencies` (`phases.py:636-642`), but the
   target's rank may be ≥ the patched file's, so its symbols are not in
   `pool_db` yet.  `_strip_unresolvable_field_types` then silently
   deletes the fields that referenced them, emitting only a W4.
2. **The named file exists only as a bare ref.** `topo_dep.is_ref()`
   is true, so the import is stripped and recorded in
   `stripped_dependencies`.
3. **The named file was never discovered.** `topo.files.get(dep)`
   returns `None` and the guard falls through without stripping
   anything.  The import survives into the rendered `.proto` pointing
   at a file reproto never loaded.

Tier 3 is unreachable from any post-phase-1 hook position: the only
code that could act on it is the discovery loop, which has finished.

There is a second, independent problem.  The plugin patches the `fdp`
object, but `QualFile.contents` — the raw fragment — is what phase 2
re-parses (`phases.py:905-932`).  Each parse produces a fresh,
unpatched FDP.  A hook that fires once therefore patches exactly one of
the several FDP objects that a single input file gives rise to.

## Goals

- **G1.** The plugin sees every `FileDescriptorProto` reproto
  materialises from an input file, at the moment it materialises, and
  before anything reads it.
- **G2.** The first application precedes topology construction, so
  `ReFile.targets`, the import-discovery loop, and the rank ordering
  are all computed from the patched dependency list.
- **G3.** The plugin contract is stated explicitly, including the fact
  that it will be called more than once per input file.
- **G4.** Existing plugins keep working, through a deprecated flag, and
  gain the fix without being rewritten.

## Non-goals

- **N1.** No FDS-level hook.  `split_fdps()` dissolves every
  `FileDescriptorSet` into per-file fragments before any FDP exists
  (`split_fdps.py:287-288` for binary, `375-377` for text), and
  `QualFile.desc` is typed `FileDescriptorProto` (`load.py:126`).  The
  plugin cannot see a file's siblings, and giving it that view would
  require carrying the set through the loader, which nothing else
  needs.
- **N2.** No new-file injection.  A plugin cannot synthesise a
  `.proto`; there is no container to append to.  The supported
  equivalent is to add a dependency *name* and let the discovery loop
  find it on the `-I` path.
- **N3.** The plugin is not required to be idempotent (see S5).
- **N4.** This does not fix the loss of unresolvable extensions on the
  text-input path (see C3).
- **N5.** No rollback.  If a patch makes the graph unsatisfiable, the
  existing W1/W4/circular-dependency diagnostics report it; reproto
  does not undo the patch.
- **N6.** The deprecated `--phase2-plugin` path gets no tests.  It
  shares one implementation with `--fdp-plugin` and differs only in
  which callable is invoked and with how many arguments; testing the
  new flag covers the machinery.  Writing tests for a path whose
  semantics are declared unspecified (S3) would pin down behavior this
  spec deliberately leaves open, and would then have to be deleted
  along with the flag.

## Specification

### S1 — The `contents` / `desc` invariant

For every `QualFile`:

- `contents` is the **raw** fragment exactly as read from the input,
  never rewritten by the plugin;
- `desc` is the **patched** FDP.

Everything else follows from this.  Every consumer that re-parses
`contents` gets a pristine FDP, so the patch has to be applied afresh
at each parse.  Idempotence does not enter into it: no call ever sees
an already-patched FDP.

### S2 — Apply at every FDP materialisation site

A single helper is called immediately after each FDP is parsed and
before any other code reads it:

```python
def apply_fdp_plugin(ctx: Context, fdp: FileDescriptorProto) -> None:
    """Apply the caller's plugin to fdp, in place."""
```

With no plugin configured it returns immediately.  The null check
belongs in the helper rather than at the call sites: guarding four
sites is four chances to omit one, and an unconditional call is what
makes the list below auditable.

**Resolution.**  The plugin source is `exec()`'d once, in
`_make_context` (`phases.py:437-450`) — the single point where a
`Context` is built, for the CLI and the library entry alike — and the
resulting callable is stored on the `Context`.  The `exec()` currently
at `phases.py:866-869` is deleted.  Resolving eagerly also turns a
misspelled entry point into a startup error naming the file, in place
of today's bare `KeyError: 'phase2_plugin'` raised from inside phase 2,
after the loading progress bar has run.  Resolution must not be cached
in a module global: the test suite runs reproto repeatedly in one
process, and a global would carry one run's plugin into the next.

`fdp_plugin_fn` is declared in `Context.__init__` with a `None`
default, among the other non-`Options` attributes
(`context.py:150-236`); `_make_context` overwrites it.  The default is
not decorative.  `Context` is also built bare in the test suite
(`test_load.py:21`, `test_editions_rendering.py:54`,
`test_anomalies.py:582`), bypassing `_make_context` entirely, and
`test_load.py` drives `load_from_path` → `parse_qfile` — S2 site 1.
Resolving only in `_make_context` would leave those Contexts without
the attribute and fail them with `AttributeError` on the first parse.

`_make_context` also serves library callers — anyone who builds
`Options` directly and calls `reproto()`.  For them this moves the
failure too: a `CodeType` with no valid entry point now raises at
`Context` construction rather than at first use.  That is a behavior
change for that entry point, and a deliberate one; there is no reading
of a plugin file that is valid in phase 2 and invalid at startup.

**Failure.**  The helper wraps the call and re-raises whatever the
plugin throws as `PluginError`.  This is load-bearing, not defensive —
see the exception clause in S4.

`PluginError` and `apply_fdp_plugin` both live in `context.py`.  They
cannot live in `phases.py`, which imports `load.py` at top level
(`phases.py:40`); `load.py` can only reach back by deferring the
import inside the function (`load.py:93` does this for `fqdn_match`),
and `parse_qfile` is not the place to pay for that.  `context.py` sits
below both callers — each reaches it as `from reproto import Context`
— already declares the `Options` plugin field, and already has `from
__future__ import annotations`, so the `FileDescriptorProto`
annotation stays under `TYPE_CHECKING`.

Call sites — these are exhaustive; parsing an input fragment anywhere
else without calling the helper reintroduces the bug:

1. `load.py:316-326`, `parse_qfile()` — both the binary and the text
   branch, after `qf.desc` is assigned.  This is the application that
   satisfies G2: it runs before the `QualFile` is handed to `ReFile`,
   hence before `targets` is built, for the seed files
   (`phases.py:487`) *and* for every file the discovery loop pulls in
   (`phases.py:513`).  Because the loop iterates until `topo.new_files`
   is empty, dependencies added to a supplementary file are discovered
   in turn; the loop converges on the patched graph.  (The
   pre-loaded-`QualFile` entry point has no such loop — C6.)
2. `phases.py:544-549`, `load_embedded_proto_fallback()` — after
   `qual_file.contents` has been set from the *unpatched*
   `fdp.SerializeToString()`, so S1 holds for embedded WKT fallbacks
   too.
3. `phases.py:911` and `phases.py:932`, the phase-2 re-parse — the
   existing call sites, unchanged in position (immediately before
   `patch_go_package`).

### S3 — New API; the old one is deprecated, not removed

This spec changes the plugin API twice over: the hook is no longer a
phase-2 hook (S2), so a name asserting otherwise misleads; and the
plugin may not read `ctx` (S5), so the parameter carrying it is dead
weight.

| | option | entry point |
|---|---|---|
| new | `--fdp-plugin` | `fdp_plugin(fdp)` |
| deprecated | `--phase2-plugin` | `phase2_plugin(ctx, fdp)` |

- **Both forms remain supported.**  The deprecated option follows the
  house pattern for aliases (`cli.py:314-321`, `cli.py:700-715`):
  `hidden=True`, a distinct click parameter name, and a
  `warning: --phase2-plugin is deprecated; use --fdp-plugin` on stderr,
  suppressed under `--quiet`.
- **The two are mutually exclusive.**  Supplying both is a
  `click.UsageError`, not a silent preference.  The existing aliases at
  `cli.py:706-715` resolve a conflict by preferring the canonical
  option, which is right for a path but wrong here: the two flags name
  two different files containing two different functions, and guessing
  which the caller meant would run the wrong code.
- **The deprecated form gets the new call schedule.**  A plugin loaded
  through `--phase2-plugin` is invoked at every site in S2, not only in
  phase 2, and receives `ctx` as its first argument purely for
  signature compatibility.  This is the point of keeping the flag: an
  existing plugin gets the ordering fix without being rewritten.
- **Its behavior is unspecified for a non-conforming plugin.**  If a
  plugin reached through the deprecated flag reads or mutates `ctx`, or
  is otherwise non-deterministic (S5), reproto makes no guarantee about
  the result.  It is not detected and not diagnosed.  Such a plugin was
  already producing one patch per file under the old schedule and will
  now produce several, with `ctx` in a different state each time.
  Conforming plugins — those that only mutate `fdp` — are unaffected
  beyond gaining the fix.
- **Removal** is deferred to a later spec.  The flag stays hidden in
  the meantime so it does not present itself to new callers.

Touch points: `cli.py:199` (help grouping), `cli.py:606-614` (the
option, plus the new one), `cli.py:690`, `cli.py:785-789`,
`cli.py:996-1009` (the `PluginError` handler, S4), `context.py:108`,
`completions.sh:26` (an entry for each flag).

`Options` carries the compiled source and which shape it is; the
`Context` additionally carries the callable resolved from it:

```python
# Options fields, reaching Context through from_options' **vars
fdp_plugin: CodeType | None = None
fdp_plugin_legacy: bool = False    # set by --phase2-plugin
# Context attribute, resolved in _make_context (S2)
fdp_plugin_fn: Callable[..., None] | None
```

`apply_fdp_plugin` calls `fdp_plugin_fn`, passing `ctx` as the first
argument when `fdp_plugin_legacy` is set.  Keeping the `Options` field a
`CodeType` leaves `cli.py`'s compile step (`cli.py:785-789`) as it is.

### S4 — Contract

A plugin file is `exec()`'d once per run, at `Context` construction
(S2), and must define:

```python
def fdp_plugin(fdp: FileDescriptorProto) -> None: ...
```

- It mutates `fdp` in place and returns `None`.
- It receives no `Context`.  The patch is a function of `fdp` alone
  (S5).  The deprecated entry point still takes one (S3), and reading
  or mutating it there is unspecified rather than forbidden — that one
  clause is the whole of the difference.  Every other clause in this
  contract binds both entry points equally.
- It is handed exactly one FDP per call, never an FDS (N1).
- It is called for reproto's own embedded files as well as for caller
  input — the WKT fallbacks and `descriptor.proto`.  This is not new: a
  fallback's `QualFile` is an ordinary, non-ref, non-pruned entry in
  `topo.files` (`phases.py:547-550` and `565`), so today's phase-2 hook
  already fires for it; S2 site 2 only adds the load-time application.
  An unconditional patch will therefore modify
  `google/protobuf/any.proto`.  Condition on `fdp.name` if that is not
  wanted.
- It may add, remove, or rewrite entries in `fdp.dependency`.  Added
  names are resolved by the ordinary discovery loop, i.e. against the
  `-I` roots.
- It must not change `fdp.name` (C1).
- An exception aborts the run.  A patch script that throws has not
  expressed a patch, and continuing with a half-mutated FDP would
  produce output nobody can reason about.

  This holds only because the helper re-raises as `PluginError` (S2).
  Three of the four call sites sit inside a handler that would
  otherwise absorb the throw: `except (ImportError, FileNotFoundError,
  DecodeError, IndexError, AttributeError)` at `phases.py:555`,
  `except message.DecodeError` at `phases.py:949`, and `except
  TypeError` at `phases.py:944`.  None of those guards exists for the
  plugin's benefit — they guard the embedded-fallback load, an
  unparseable input, and `pool_db.Add` respectively.  Unwrapped, a
  plugin raising `AttributeError`, `IndexError`, `TypeError` or
  `DecodeError` — the four most likely results of naive descriptor
  manipulation — is swallowed and reported as a corrupt *input file*,
  so the diagnostic blames the user's data for a fault in the user's
  plugin.  `reproto()` wraps its phases in `try: … finally:` with no
  `except` (`reproto.py:236`), so `PluginError` reaches the CLI intact.

  A library caller sees `PluginError` itself.  A CLI caller does not:
  it joins the three `DescriptorProto*Error` types already caught
  around the `reproto()` call (`cli.py:996-1009`) and is re-raised as a
  `click.ClickException` naming the plugin file and the underlying
  exception.  That yields one line on stderr and exit status 1, which
  is the house treatment for a reproto-level abort — a traceback here
  would read as a reproto crash rather than a fault in the caller's
  plugin, which is the same confusion the wrapping exists to prevent.
- The plugin is arbitrary Python executed with reproto's privileges.
  Only run plugins you would run as a script.

### S5 — Multiple invocations, and determinism

**The plugin is called once per parse, not once per file.**  The usual
count is two — once in `parse_qfile`, once at the phase-2 re-parse —
but it varies either way:

- **Once**, for a file that never reaches phase 2.  Refs, and files
  matching a pruning pattern, `continue` before the re-parse
  (`phases.py:896-903`).
- **More than twice**, when one proto name yields several candidates.
  A directory-shaped or blob-shaped seed is scanned under every `-I`
  root (`load.py:197`, spec 0148 G1), so one `rel_path` can produce two
  `QualFile`s and two parses.  The W7 dedup at `load.py:278-291` runs
  *after* `parse_qfile`, so the plugin has already been applied to the
  copy that is then dropped.  (A *file*-shaped seed returns at the
  first root that resolves — `load.py:208` and `216` — and is parsed
  once.)
- Files dropped later by `_prune_if_duplicate` have still been through
  the plugin.

Three consequences for plugin authors:

- **Determinism is required.**  The same input FDP must yield the same
  patch on every call.
- **A plugin must not query `ctx`.**  Not `ctx.pool_db`,
  `ctx.pool_db_fdps`, `ctx.nodes`, and not the settings either.  The
  patch is a function of `fdp` alone.

  The narrow justification is that reproto's own state is empty at the
  `parse_qfile` call and populated at the phase-2 call, so a plugin
  reading it emits two different patches for one file and the run
  becomes incoherent.  The rule is nonetheless stated without exception,
  including for fields that happen to be immutable after startup.  A
  rule of the form "you may read `ctx`, but only the parts that do not
  change" requires every plugin author, and every future reader of this
  spec, to re-derive which parts those are — and the answer drifts as
  `Context` grows.  A plugin needing a caller-supplied setting takes it
  from its own source, or the caller passes it another way.

  In the new API the rule is structural rather than advisory: `ctx` is
  dropped from the signature (S4), so there is nothing to query and
  nothing for a future reader to litigate.  reproto's internal helper
  keeps its `ctx` — it needs it to reach the compiled plugin — but the
  caller's function does not receive it.  The deprecated entry point
  still takes the parameter, which is exactly why its behavior is
  unspecified when a plugin uses it (S3).
- **Side effects outside `fdp` must tolerate N calls.**  Counters,
  logs, and file writes will fire more times than there are input
  files, including for FDPs that are subsequently discarded.

Idempotence is *not* required, because each call receives a freshly
parsed, unpatched FDP (S1).  It is also not sufficient: a plugin
carrying its own module-level state across calls can be perfectly
idempotent and still emit different patches for the same file.

## Caveats

### C1 — Renaming a file is not supported

`fdp.name` is consumed before the plugin can run, in places the patch
does not reach:

- blob members take their `rel_path` from the pre-plugin `fdp.name`
  (`load.py:60-67`), and `-s`/`-p` path patterns and the W7 dedup key
  off that path and off `qf.name` from `split_fdps`;
- phase 3 resolves the rendered FDP with
  `ctx.pool_db.FindFileByName(file.qfile.desc.name)`
  (`phases.py:986-988`).  Under S1 `desc` is patched, so this lookup
  agrees with `pool_db` — but the `QualFile`'s `rel_path` and dedup key
  still carry the old name.

A rename therefore leaves the file filed under one name and declared
under another.  Do not do it.

### C2 — A plugin cannot summon a well-known type

Embedded WKT fallbacks are not part of the import-discovery mechanism.
They are a separate, second pass inside phase 1, driven by a list the
plugin has no way to influence.

The plugin has no say in *which* fallbacks load, then — but it is still
called on the ones that do, and may patch their contents (S4).  The two
are easily confused.

Two things happen, in this order, to a WKT name the plugin adds to
`fdp.dependency`:

1. The **discovery loop** (`phases.py:503-520`) turns the name into a
   ref `ReFile` and calls `load_from_path` for it.  Embedded fallbacks
   do not live on the `-I` path, so unless the user happens to have the
   file there, this misses.
2. The **fallback loop** (`phases.py:563-584`) then walks
   `ctx.fallback_protos` and, for each entry, loads the embedded copy
   and force-assigns it onto the `ReFile` the discovery loop already
   created (`phases.py:582-584`).  That object is deliberately reused
   rather than replaced: the ref is held in the importing file's
   `targets`, and swapping in a new instance would collapse the rank
   separation between importer and import (`phases.py:566-575`, spec
   0051).

So the outcome depends entirely on whether the user passed the matching
`--use-variant`/`-d`:

- **Requested** (e.g. `-d any`, or `-d all`): the name is in
  `ctx.fallback_protos`, W1 was pre-suppressed for it at
  `phases.py:468`, step 2 upgrades the ref to a real file, and the
  plugin's import resolves and renders.
- **Not requested**: nothing upgrades the ref.  `load_from_path`
  already emitted a W1, and in phase 2
  `_strip_unresolvable_dependencies` sees `topo_dep.is_ref()` and
  strips the import — tier 2 of the Background.  The patch silently
  does not take.

`ctx.fallback_protos` is built at `cli.py:805-828` from the `-d` flags,
before `Context` is constructed, and nothing downstream appends to it.
A plugin that introduces a dependency on a well-known type therefore
carries a requirement on its caller's command line, which the plugin
can neither enforce nor detect — it must not read `ctx` at all (S5).
Document the required `-d` alongside the plugin.

A related trap that is *not* plugin-specific but bites in the same
place: the fallback list is order-sensitive, because a fallback may
import another fallback — `type.proto` imports `any.proto` and
`source_context.proto`.  The hardcoded append order at `cli.py:806-828`
puts leaves first so the topo-sort sees them in the right order
(`phases.py:586-589`).  But `-d type` alone still leaves `type.proto`'s
own imports as refs, and they are stripped exactly as in the
"not requested" case above.  `-d all` avoids it.

### C3 — Text and binary inputs do not carry the same extensions

On the text path, `text_format.Parse(..., allow_unknown_extension=True)`
*discards* an extension it cannot resolve (`text_format.py:947-948`
sets `field = None`, then `1025-1027` skips the field contents).
Resolution goes through the message's own pool via
`Extensions._FindExtensionByName` (`text_format.py:944`), which is
populated by imported `_pb2` modules — not by the `descriptor_pool=`
argument.  Binary `ParseFromString` retains unresolvable extensions as
unknown fields.

So a plugin that inspects custom options sees them for `.pb` input and
may not see them for `.textpb` input.  That is pre-existing and is a
function of `_pb2` coverage, not of this change.

### C4 — The two parses are otherwise equivalent

`phases.py:916` passes `descriptor_pool=ctx.pool` and `parse_qfile`
does not.  That argument serves `Any` expansion only
(`text_format.py:717`), not extension resolution (C3), so the FDP the
plugin receives at load time and at phase 2 is the same — the sole
exception being a text input embedding an `Any` whose type is
resolvable in `ctx.pool`.  This equivalence is what makes re-application
safe.

### C5 — A patch can create a cycle

An added import can close a dependency cycle, in which case the rank
loop terminates with files still unranked and they are pruned with
`Circular dependency detected` (`phases.py:959-962`).  The plugin is
responsible for not doing this; reproto only reports it.

### C6 — The pre-loaded-`QualFile` entry point has no discovery loop

`reproto()` accepts `seed_paths` as either `list[Path]` or
`list[QualFile]` (`reproto.py:206`).  In the `QualFile` branch
(`phases.py:473-480`) the caller supplies the files and there is no
import discovery at all — the loop at `phases.py:503-520` belongs to
the `Path` branch.  The plugin still runs, provided the caller built
those `QualFile`s through `load_from_path`, but a dependency it adds
resolves only if the caller happened to supply that file too.
Otherwise the name stays a ref and is stripped in phase 2.  This is a
property of that entry point, not something S2 changes.

## Alternatives considered

### Leave the hook in phase 2

Fixes nothing in tiers 2 and 3 of the Background, and tier 3 is
structurally unreachable from there.

### Hoist to a single pass over the seed files, before phase 1

Misses the files the discovery loop pulls in at `phases.py:513` — which
is most of the corpus for any `-I`-driven run — and is undone by the
phase-2 re-parse from raw `contents`.

### Patch `contents` at load time, so one application suffices

Would require re-serialising the fragment.  For text inputs that means
a `text_format` round trip, losing formatting and (per C3) any
extension the parse could not resolve; and `contents` would no longer
be the bytes that were read, which several diagnostics assume.
Re-applying a cheap deterministic function is the smaller price.

### Require idempotence instead of determinism

Neither necessary nor sufficient — see S5.

### Remove `--phase2-plugin` outright

Rejected by G4.  The argument for removal was that a flag named for a
phase it no longer runs in is worse than a failure; the argument
against is that the rename is cosmetic while the ordering fix is not,
and forcing a rewrite to obtain a bug fix is a poor trade for the
caller.  `hidden=True` plus a stderr warning keeps the old name out of
sight of new callers without stranding existing ones.

### Give the deprecated flag its old phase-2-only schedule

Would make `--phase2-plugin` mean what its name says, and would make
the deprecated path's behavior fully specified.  Rejected: it means
maintaining two call schedules, and it withholds the fix from exactly
the callers who already have a plugin and are therefore most likely to
be hitting the bug.

## Test plan

Deliberately narrow.  Two behaviors are covered, both through
`--fdp-plugin`: plugin-added imports, which is what this spec exists to
fix; and the exception policy, because `PluginError` is invisible in
the happy path and an edit to any of the three swallowing handlers
(S4) would undo it without breaking anything else.  Nothing here covers
the deprecated flag (N6) or FDS splitting — those are either unchanged
by this spec or assertions about code paths these tests already
traverse.

1. `plugin_added_import_is_discovered` — a plugin appends an import
   naming a file that is present on `-I` but referenced by nothing else
   in the input.  That file is loaded, ranked before its importer, and
   rendered.  This is the tier-3 regression and fails on today's code:
   the file is never read from disk at all.
2. `plugin_added_import_keeps_its_fields` — a plugin adds an import
   *and* a field whose type is defined in the imported file.  The field
   survives into the output, with no W4 from
   `_strip_unresolvable_field_types`.  Guards tier 1, which is the
   failure mode that loses data without saying so.
3. `plugin_added_import_appears_once` — the rendered `.proto` contains
   the added import exactly once, despite the plugin running at every
   parse.  Establishes the S1 invariant; would fail if the plugin were
   handed an already-patched FDP.
4. `plugin_added_import_unresolvable_is_stripped` — an import naming a
   file absent from `-I` draws a W1 from `load_from_path`, is stripped
   by `_strip_unresolvable_dependencies`, is recorded in
   `stripped_dependencies`, and the run completes.  The negative case:
   today it survives into the output pointing at nothing.

The exception cases each raise from a plugin that is otherwise a no-op,
and each asserts the same two things: the run aborts — exit status 1
with the plugin file named on stderr, and no traceback (S4) — and no
output tree is written.  The last three are named for the handler
they must not be absorbed by; all three pass trivially with a bare
`raise` and only fail once the wrapping in S2 is removed, which is the
point.

5. `plugin_exception_aborts_the_run` — the plugin raises `RuntimeError`,
   which no handler on the path catches.  The baseline: establishes that
   `PluginError` reaches the CLI at all.
6. `plugin_decode_error_is_not_a_corrupt_input` — the plugin raises
   `message.DecodeError` on a text input.  Unwrapped, `phases.py:949`
   catches it, warns `Skipping unparseable file`, and sets
   `n.is_pruned` — the file disappears from the output and the
   diagnostic blames the input.  This is the worst of the three.
7. `plugin_type_error_is_not_a_pool_conflict` — the plugin raises
   `TypeError` on a binary input.  Unwrapped, `phases.py:944` catches it
   and warns `Could not add descriptor ... to pool`, and the file is
   absent from `pool_db`.
8. `plugin_exception_on_a_fallback_aborts` — with `-d all`, the plugin
   raises `AttributeError` when `fdp.name` is an embedded fallback.
   Unwrapped, `phases.py:555` catches it and returns `None`; the
   fallback is never registered, its ref survives into phase 2 and is
   stripped, and the only trace is a message emitted under `--debug`
   alone.  Silent by default, hence worth a test of its own.
9. `reuse lint` passes.
