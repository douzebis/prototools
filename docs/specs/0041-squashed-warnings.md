<!--
SPDX-FileCopyrightText: 2026 THALES CLOUD SECURISE SAS

SPDX-License-Identifier: MIT
-->

# 0041 — reproto: warning clarity and squashed mode

**Status:** implemented
**Implemented in:** 2026-05-08 (initial); 2026-05-09 (§6, §7, §8)
**App:** reproto

---

## Background

When running reproto against a large corpus (e.g. a google3 checkout with
`--use-variant all`), thousands of warnings are emitted to stderr.  A sample
run produced 10,309 lines for a corpus where only 24 distinct source files
were missing from the `-I` path.  The explosion comes from per-field
repetition: a single missing type can fire once for every field that carries
an option referencing it.

This spec addresses two orthogonal but related concerns:

1. **Warning clarity** — some messages are unclear or carry Python
   implementation noise; fixing them benefits all modes.
2. **Squashed mode** — by default, repeated warnings are collapsed to one line
   per root cause; `--detailed-warnings` restores the full per-occurrence
   stream.

---

## Warning taxonomy

Five distinct warning classes have been identified.  W4 and W5 are kept
distinct because they surface different actionable information: W4 names a
type FQDN (useful for searching the codebase), W5 names a file path (directly
tells the user what to add to `-I`).

### W1 — Missing source file

Emitted during the "Discovering and loading imported files" phase for each
`.proto` that could not be found on the `-I` search path.

Currently fires **two lines per file** — always together, never separately.
The first comes from `load.py` (returns an empty list); the second from
`phases.py` (observes the empty result):

```
File 'third_party/envoy/.../address.proto' is missing, skipping
Skipping unreadable file: third_party/envoy/.../address.proto
```

24 distinct missing files → 48 lines in the sample run.

### W2 — Embedded fallback used

Informational notice emitted when reproto substitutes a built-in copy of a
well-known proto (e.g. `google/protobuf/timestamp.proto`):

```
Using embedded fallback: google/protobuf/timestamp.proto
```

7 lines in the sample run.  Not a warning — an informational status line.

### W3 — Duplicate file / symbol conflict

When two `.proto` files in the corpus define the same fully-qualified symbol,
Python's `descriptor_database` fires one `RuntimeWarning` per conflicting
symbol.  The subsequent `pool_db.Add()` call raises a `TypeError`, which
reproto catches.

#### Two-pool architecture

`ctx.pool_db` is a pure-Python `DescriptorDatabase` — a keyed store of
`FileDescriptorProto` objects, indexed by file name and symbol name.
`ctx.pool` is the C-extension `DescriptorPool`, constructed as
`DescriptorPool(pool_db)`.  This makes `pool_db` the *backing store*: when
`ctx.pool` is asked for a file or symbol it has not yet built into a live
`FileDescriptor`, it fetches the raw `FileDescriptorProto` from `pool_db`
and builds it on demand.  `pool_db.Add()` therefore serves two purposes:

1. **Backing store for lazy pool resolution** — `ctx.pool.FindFileByName()`
   falls back to `pool_db` on a cache miss, triggering deferred descriptor
   construction.
2. **Raw FDP retrieval in phase 3** — `ctx.pool_db.FindFileByName(desc.name)`
   (line 623) retrieves the original `FileDescriptorProto` for building the
   FQDN graph, bypassing the C pool entirely.

#### How the duplicate symbol problem actually works for binary files

The flow for a conflicting pair of `.pb` files is:

1. File A is processed first.  `pool_db.Add(fdp_A)` registers all of A's
   symbols in `pool_db._file_desc_protos_by_symbol`.  No error.
2. File B is processed.  `pool_db.Add(fdp_B)` iterates B's symbols; for each
   one already present it emits a `RuntimeWarning` (via `_AddSymbol`) and
   then **overwrites** the entry — pointing it at B's FDP.  No exception is
   raised from `pool_db.Add()`; the `try/except TypeError` in reproto's binary
   path is **never triggered** by this.  Both files are now in `pool_db`.
3. During rendering, `ctx.pool.FindFileByName('A')` succeeds (A's FDP is in
   `pool_db`; the C pool builds A's `FileDescriptor` and caches it, claiming
   the symbols as belonging to A).
4. `ctx.pool.FindFileByName('B')` is called for rendering B.  The C pool
   tries to build B's `FileDescriptor` from B's FDP (retrieved from
   `pool_db`), but the symbols `pkg.MyMessage` etc. are already registered in
   the C pool's internal symbol table as belonging to A.  The C extension
   raises `TypeError: Couldn't build proto file into descriptor pool:
   duplicate symbol '...'`.  This is the exception caught by the
   `try/except (... TypeError ...)` in `re_file.py` (anomaly A3) and the
   fallback in `phases.py:862`.

So the `RuntimeWarning` storm from `pool_db.Add()` and the `TypeError` during
rendering are **two separate events** from two separate phases — not cause and
effect of the same call.  The `try/except TypeError` in the binary loading
loop (lines 554, 567) is defensive code for a *different* class of TypeError
(e.g. from `phase2_plugin` or `patch_go_package`) and is **not** what catches
the duplicate-symbol failure.

#### `pool_db` symbol-index internals and pre-check cost

`DescriptorDatabase.Add()` indexes symbols by iterating `message_type`,
`enum_type`, `extension`, and `service` fields of the `FileDescriptorProto`,
recursing into nested types via `_ExtractSymbols`.  The `RuntimeWarning`
fires inside `_AddSymbol` for each already-present symbol, then the entry is
overwritten.

A pre-check for `--keep-duplicates` would perform the same iteration and
query `pool_db.FindFileContainingSymbol()` for each symbol *before* calling
`pool_db.Add()`.  The cost is O(S) dict lookups where S is the number of
symbols — the same work `Add()` already does.  Roughly a 2× constant factor
on the symbol-scan phase per file.

In practice this is negligible: typical `.proto` files have tens to low
hundreds of symbols, and the total symbol count is bounded by the corpus size
which reproto already fully iterates in phase 2.  There is no algorithmic
complexity increase; the overhead is unmeasurable against I/O and protobuf
parsing costs.

#### Upstream detection option

A `--keep-duplicates` mode can eliminate both the `RuntimeWarning` storm and
the deferred rendering `TypeError`.

The key insight is that `qf.desc` — already populated by `parse_qfile` in
phase 1 for both binary and text-format files — contains the pool-free
`FileDescriptorProto` with `package`, `message_type`, `enum_type`,
`extension`, and `service` fully populated (these are standard fields, not
extensions, so they parse correctly without a pool).  Symbol extraction
requires no additional parsing.

Before calling `pool_db.Add()` for a file, reproto iterates all symbols the
file defines and queries `pool_db.FindFileContainingSymbol()` for each.  That
method returns the `FileDescriptorProto` of the already-registered file
(giving its `.name` directly), or raises `KeyError` if not present.  All
conflicts are collected — not just the first — to produce a complete picture:

```python
conflicts: dict[str, str] = {}  # symbol → conflicting file name
for sym in extract_symbols(fdp):
    try:
        existing = pool_db.FindFileContainingSymbol(sym)
        conflicts[sym] = existing.name
    except KeyError:
        pass
```

If `conflicts` is non-empty, the file is marked `is_pruned = True` and
`pool_db.Add()` is skipped — preventing both the `RuntimeWarning` storm and
the C-pool `TypeError` at render time.  For text-format files, the phase 2
re-parse with the pool is also skipped, preventing `ctx.pool` corruption.

The warning groups conflicts by the file they originate from:

```
Warning: file:src/proto/grpc/channelz/channelz.proto pruned —
    duplicate symbols with file:third_party/grpc_proto/grpc/channelz/v1/channelz.proto
    (42 symbols)
```

If symbols conflict with more than one file (unusual but possible):

```
Warning: file:foo.proto pruned — duplicate symbols with:
    file:bar.proto (12 symbols)
    file:baz.proto (3 symbols)
```

The file that loaded first (topo-sort order) wins.  Well-known type fallbacks
are loaded first as leaf files, so they always win over any user file
redefining them — correctly.

In the sample run: 42 `RuntimeWarning` lines for a single file pair
(`channelz`), totalling 47 lines across 4 conflicting files.

```
RuntimeWarning: Conflict register for file "src/proto/grpc/channelz/channelz.proto":
    grpc.channelz.v1.Channel is already defined in
    "third_party/grpc_proto/grpc/channelz/v1/channelz.proto"
...  (one line per conflicting symbol)
'src/proto/grpc/channelz/channelz.proto': failed to render file options:
    TypeError: Couldn't build proto file into descriptor pool:
    duplicate symbol 'grpc.channelz.v1.Channel'
```

The `RuntimeWarning` lines come from the protobuf library; they can be
intercepted via a custom `warnings.showwarning` hook to participate in
squashing even when `--keep-duplicates` is not active.

### W4 — Option rendering failure: unresolvable type

When a field or file carries a custom option whose type cannot be resolved
(because the defining `.proto` was not loaded), reproto currently fires at
three levels, from two separate call sites:

- **File options** (anomaly A3, emitted from `re_file.py`) — one per affected
  file
- **Field options** (anomaly C5, emitted from `re_field.py`) — one per
  affected field in that file
- **File summary** (`phases.py:862`) — one per affected file, if the rendering
  exception propagates past the anomaly handler

85 distinct unresolvable type names in the sample run.  The top offender
(`.net_model_unm.proto.DrainType`) fired **2,147 times**, all traceable to
a single missing dependency.  Total: ~9,800 lines.

The `TypeError: Couldn't build proto file into descriptor pool:` prefix is a
Python implementation detail leaking into user-facing output.  Field-level
messages do not identify which `.proto` file the field belongs to.

Note on FQDN format: in reproto's internal FQDN scheme, type descriptors are
written as `desc:.some.package.TypeName` (prefix `desc:`).  The unresolvable
name appearing in W4 messages (e.g. `.net_model_unm.proto.DrainType`) is the
raw protobuf type reference, not a reproto FQDN — it has no `desc:` prefix.
The squashed warning format should present it as-is, since that is what the
user would search for.

### W5 — Option rendering failure: missing file dependency

Same call sites as W4 (A3 in `re_file.py`, C5 in `re_field.py`), but the
underlying error names the missing file rather than a missing symbol:

```
field 'name': failed to render options: TypeError: Couldn't build proto file
    into descriptor pool: Depends on file
    'third_party/protoc_gen_validate/validate/validate.proto',
    but it has not been loaded
```

11 distinct missing files; the top offender fired 341 times.  Total: ~684
lines.

W4 and W5 originate at the same code locations but carry different actionable
information:

- W4 names a **type reference** (e.g. `.net_model_unm.proto.DrainType`) —
  useful for grepping the codebase to find where the type is defined.
- W5 names a **file path** (e.g. `third_party/.../validate.proto`) — directly
  tells the user what to add to `-I`.

They are kept as separate warning kinds in both detailed and squashed output.
In reproto FQDN terms, a missing file would be `file:third_party/.../validate.proto`;
the squashed warning should use that form for consistency with `--seed` / `--prune`.

---

## Goals

1. Improve warning message clarity for all five classes in all modes.
2. Make squashed mode the default: each distinct root cause is shown once,
   with an occurrence count.
3. Provide `--detailed-warnings` to restore the original per-occurrence stream.
4. In squashed mode, flush a summary hint at the end when warnings were
   suppressed.
5. By default, prune duplicate-symbol files upfront (before pool population);
   provide `--keep-duplicates` to revert to the legacy behaviour.

---

## Non-goals

- Suppressing warnings entirely (a separate `--quiet` concern).
- Resolving missing dependencies automatically.
- Changing the set of conditions that produce warnings.

---

## Specification

### 1. Warning message clarity (applied in all modes)

**W1:** The two-line pair collapses to one line.  The `load.py` warning is
kept; the `phases.py` `"Skipping unreadable file: ..."` line is removed
(it is redundant — `load.py` already fired for the same file).

W1 and W5 are merged into a single counter (see §8).

**W2:** Keep as-is.  These are useful status lines, not warnings.

**W3:** The per-symbol `RuntimeWarning` lines from `descriptor_database` are
intercepted via a `warnings.showwarning` hook and fed into reproto's warning
collector (see §4), rather than being printed directly.  This removes the
`/nix/store/.../descriptor_database.py:152: RuntimeWarning:` prefix, which
gives the user a path into reproto's internal call site and is not actionable.

Reproto's own `"Could not add descriptor from '...' to pool: ..."` line is
replaced with a single line per conflicting file pair:

```
Warning: file:src/proto/grpc/channelz/channelz.proto conflicts with
    file:third_party/grpc_proto/grpc/channelz/v1/channelz.proto (file skipped)
```

**W4/W5:** Strip the `TypeError: Couldn't build proto file into descriptor
pool:` prefix.  Add the containing `.proto` file to field-level messages.
W4 and W5 keep distinct formats to preserve their different actionable content:

```
# W4 — before
field 'device_name': failed to render options: TypeError: Couldn't build proto
    file into descriptor pool: couldn't resolve name '.net_model_unm.proto.DrainType'

# W4 — after
Warning: 'net/model/foo.proto' field 'device_name': unresolvable type '.net_model_unm.proto.DrainType'

# W5 — before
field 'name': failed to render options: TypeError: Couldn't build proto file
    into descriptor pool: Depends on file 'third_party/.../validate.proto',
    but it has not been loaded

# W5 — after
Warning: 'net/model/foo.proto' field 'name': missing file dependency
    'third_party/protoc_gen_validate/validate/validate.proto'
```

### 2. Default mode (squashed)

Warnings are buffered during the run and flushed at the end, grouped by root
cause.  Each distinct root cause appears exactly once, with an occurrence
count.  If an error or unhandled exception occurs, the buffer is flushed
before exiting so warnings are not lost.

#### Flush order

Categories are printed in decreasing order of actionability — the most
directly fixable problems appear first:

1. **W5** — missing file dependencies (merged with W1, see §8): the user
   can immediately add the named file to `-I`.
2. **W4** — unresolvable types: requires grepping the codebase to identify
   which file to add; one step less direct than W5.
3. **W6** — option rendering failures ("Couldn't find Extension/message"):
   a rendering-level degradation, typically a consequence of a missing file
   already reported by W5; least actionable on its own.

**W2** is displayed as emitted (not buffered; no repetition).

**W3** is printed immediately as emitted, in both squashed and detailed modes
(one occurrence per pruned file; no buffering needed).

#### Format

Each squashed line always includes an occurrence count, even for N=1, so
that the flush block is visually distinct from immediate emissions:

**W5 squashed:**
```
Warning: missing dependency file:third_party/protoc_gen_validate/validate/validate.proto (341 occurrences)
Warning: missing dependency file:third_party/envoy/.../base.proto (164 occurrences)
```

**W4 squashed:**
```
Warning: unresolvable type .net_model_unm.proto.DrainType (2147 occurrences)
Warning: unresolvable type .net_model_unm.proto.Size (613 occurrences)
```

**W6 squashed:**
```
Warning: 'security/loas/.../thinmint_cert_extensions.proto' field 'message_set_extension': "Couldn't find Extension 43796541" (1 occurrence)
```

After the squashed block, if any warnings had more than one occurrence, append:

```
Run with --detailed-warnings to see all warning occurrences.
```

### 3. Detailed mode (`--detailed-warnings`)

Each warning is printed immediately as it is emitted, in the format described
in §1.  No buffering, no summary.  Behaviour is identical to today's output,
but with the cleaner message format.

### 4. Duplicate pruning (default) and `--keep-duplicates`

By default, reproto checks each file for symbol conflicts before calling
`pool_db.Add()`.  The check reads directly from `qf.desc` — the pool-free
`FileDescriptorProto` already populated in phase 1 for both binary and
text-format files — so no additional parsing is required.

All conflicts are collected by iterating every symbol the file defines and
calling `pool_db.FindFileContainingSymbol()` for each.  The result is a map
from symbol to the name of the already-registered file.  If any conflicts are
found, the file is marked `is_pruned = True`, `pool_db.Add()` is skipped, and
for text-format files the phase 2 re-parse with `ctx.pool` is also skipped.
This prevents both the per-symbol `RuntimeWarning` storm and the deferred
C-pool `TypeError` at render time.

W3 warnings are printed immediately as they occur (during pool-building, before
rendering), in both squashed and detailed modes — there is no per-field
explosion, so buffering adds no value:

```
Warning: file:src/proto/grpc/channelz/channelz.proto pruned —
    duplicate symbols with file:third_party/grpc_proto/grpc/channelz/v1/channelz.proto
    (42 symbols)
```

If symbols conflict with more than one file (unusual but possible in a large
corpus):

```
Warning: file:foo.proto pruned — duplicate symbols with:
    file:bar.proto (12 symbols)
    file:baz.proto (3 symbols)
```

The file that loaded first (topo-sort order) wins.  Well-known type fallbacks
are loaded first as leaf files and therefore always win over any user file
redefining them.

`--keep-duplicates` disables duplicate pruning entirely, reverting to the
legacy behaviour: both conflicting files are added to `pool_db`, producing
the per-symbol `RuntimeWarning` storm and the deferred C-pool `TypeError` at
render time.  This flag exists primarily for debugging or to observe legacy
behaviour.

### 5. Implementation notes

- Introduce a `WarningCollector` class.  In squashed mode it buffers warnings
  keyed by `(category, root_cause)`; in detailed mode it prints immediately.
- Register it at startup; expose a `ctx.warn(category, root_cause, detail)`
  call site used throughout rendering code.  The two existing anomaly call
  sites (A3 in `re_file.py`, C5 in `re_field.py`) and the file-summary site
  (`phases.py:862`) are updated to route through `WarningCollector`.
- Intercept `descriptor_database` `RuntimeWarning` lines via
  `warnings.showwarning` so they participate in squashing.
- Flush the buffer: (a) at normal end-of-run, after "Writing reconstructed
  .proto files."; (b) in `except`/`finally` blocks on abnormal exit.

### 6. Log output improvements (follow-up)

A second corpus run (`--proto-variant ... --use-variant all`) revealed four
remaining output quality issues.

#### 6.1 C5 field-option warnings not routed through `WarningCollector`

The "Couldn't find Extension/message" lines emitted during field-option
rendering (anomaly C5, `re_field.py`) currently bypass `WarningCollector`
and are printed raw to stderr as they occur.  In the sample run this
produces ~60 unsorted lines interleaved mid-phase-7, e.g.:

```
'security/loas/l2/internal/certs/thinmint_cert_extensions.proto' field 'message_set_extension': failed to render options: "Couldn't find Extension 43796541"
'security/loas/l2/internal/certs/thinmint_cert_extensions.proto' field 'message_set_extension': failed to render options: "Couldn't find Extension 43673850"
...  (12 more lines for the same file)
```

**Fix:** Route C5 through `WarningCollector` using a new `w6()` method (to
keep it distinct from W4/W5 which originate from the option-type resolution
path).  The squash key is `(proto_file, error_description)`.  In squashed
mode, all C5 lines are deferred and printed sorted at flush time, one line
per distinct `(file, error)` pair with an occurrence count.  In
`--detailed-warnings` mode, each fires immediately as before.

Squashed format:

```
Warning: 'security/loas/l2/internal/certs/thinmint_cert_extensions.proto' field 'message_set_extension': Couldn't find Extension 43796541
```

Since each `(file, field, extension-id)` combination is already unique, the
occurrence count for C5 will typically be 1 — it is included for consistency
but not printed when it equals 1 (matching W1/W4/W5 behavior).

#### 6.2 W5 warnings for importers of pruned files

In the sample run, `file:privacy/rollouts/proto/request_context_enforceable_mode_config.proto`
generates **850 W5 occurrences** solely because it was pruned by
duplicate-symbol detection.  Its importers render it as an orphan import
and each one fires W5 when the file is not found in `pool_db`.

This is noise generated by reproto's own pruning, not by a genuine user
error.  Files that were pruned (whether by `--prune` or duplicate-symbol
detection) should be silently skipped when generating W5: if reproto itself
decided to exclude the file, its absence from `pool_db` is expected and
should not be reported.

**Fix:** Before emitting W5, check whether the missing dependency's FQDN
(`file:<name>`) corresponds to a pruned node.  If so, suppress the W5
entirely.  Both squashed and detailed modes respect this suppression — the
warning is never generated, not merely hidden in the summary.

#### 6.3 `Skipping descriptor.proto` indentation

The line:

```
  Skipping net/proto2/proto/descriptor.proto (use --emit-descriptor to include)
```

is indented with two leading spaces, making it look visually subordinate
to the preceding "Writing reconstructed .proto files." phase header.  This
is inconsistent with all other `cli_info` lines which carry no indentation.

**Fix:** Remove the two leading spaces from the format string in `phases.py`.

#### 6.4 Squashed output should be sorted

In the current implementation, W3 warnings are printed in topo-sort order
(the order files are processed in phase 2) and W1/W4/W5 are sorted
alphabetically at flush time.  C5 (§6.1 above) should also be sorted at
flush time.

Additionally, the W1 single-occurrence format currently prints:

```
Warning: missing file 'third_party/foo.proto' (not found on -I path; skipped)
```

while the multi-occurrence format prints `(N occurrences)`.  For
consistency, single-occurrence lines should also carry `(1 occurrence)` —
or, equivalently, the occurrence count should always be appended.  This
makes it unambiguous that the line is from the squashed summary rather than
an immediate emission.

**Update:** Always append `(N occurrence[s])` in the squashed block,
even for N=1.  This applies to W1, W4, W5, and the new W6.

### 7. Squashed flush order

Corpus analysis showed that the original flush order (W1 → W6 → W4 → W5)
interleaved "easy to fix" and "hard to fix" warnings arbitrarily.

**Fix:** Reorder the flush block by decreasing actionability: W5 → W4 → W6
(W1 is merged into W5 per §8; see §2 for rationale).  The
`--detailed-warnings` stream is unaffected.

### 8. W1/W5 merge

A second corpus run revealed that the same file path often appeared in
both the W1 block and the W5 block:

```
Warning: missing dependency file:third_party/envoy/.../accesslog.proto (12 occurrences)
Warning: missing file 'third_party/envoy/.../accesslog.proto' (1 occurrence)
```

These are not the same occurrences — W1 counts the single loading-phase
miss; W5 counts rendering-phase pool failures — but they name the same
root cause and require the same fix (add the file to `-I`).  Showing both
is redundant and forces the user to correlate two entries mentally.

**Fix:** `w1()` feeds the same counter as `w5()`.  A missing file
accumulates one count when first looked up during loading (the W1 event)
and additional counts for each rendering reference that fails (W5 events).
The single flushed line is:

```
Warning: missing dependency file:third_party/envoy/.../accesslog.proto (13 occurrences)
```

Where 13 = 1 (loading) + 12 (rendering).  For files that are missing but
never referenced during rendering, the count is 1 — identical to what W1
alone would have shown.

In `--detailed-warnings` mode, W1 prints immediately (as before) using the
loading-phase message format, and W5 prints immediately at render time —
the two are kept distinct in detailed mode since they occur at different
phases and the user sees them in chronological order anyway.

---

## Test coverage

- Unit test: feed a set of pre-built warning events into `WarningCollector`
  in squashed mode and assert the flushed output matches expected lines
  including occurrence counts.
- Unit test: same events in detailed mode — assert each fires immediately in
  order.
- Integration test: run reproto against the existing fixture set in squashed
  mode; assert stderr line count is below a threshold and no root-cause appears
  twice.
- Integration test: with `--keep-duplicates`, confirm that conflicting files
  produce exactly one warning per pair and that no W4-like `duplicate symbol`
  rendering failures follow.
- Regression test (§6.2): confirm that a pruned file's importers produce zero
  W5 warnings.  The existing `test_pruned_dependency.py::test_duplicate_prune_no_crash`
  can be extended to assert that no "missing dependency" line appears in stderr
  for the pruned file.
- Existing tests must continue to pass (squashed mode is default; message
  format changes are covered by updating fixture expectations where needed).
