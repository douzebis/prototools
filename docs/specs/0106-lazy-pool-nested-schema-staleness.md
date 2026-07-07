<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0106 — Stop retaining pool clones across `LazyPool` dynamic completions

**Status:** implemented
**Implemented in:** 2026-07-07
**App:** prototext-core, prototext, prototext-pyo3

---

## Background

### There is one pool type, not several

`prost_reflect::DescriptorPool` is already exactly the "single mutable pool"
this problem needs: `add_file_descriptor_proto(&mut self, ...)` mutates it
incrementally, `get_message_by_name`/`get_enum_by_name` query whatever is
currently loaded. `LazyPool` (`prototext/src/lazy_pool.rs`) is not a
different kind of pool — it's a plain `pub pool: DescriptorPool` field plus
an mmap + `index.rkyv` telling it which `FileDescriptorProto` bytes to feed
in on demand. There was never a missing pool primitive to build.

Two loading mechanisms feed that one pool, and they differ in what they
know about:

- **Static loading** (`ensure_loaded`, spec 0068/0069): walks `dep_graph`,
  built ahead of time from each file's `.proto` `dependency:` imports. This
  is already minimal and correct by design — it loads exactly the root
  type's transitive import closure, nothing more, nothing wastefully large.
  This spec does not touch it.
- **Dynamic completion** (`ANY_LOADER`, spec 0099): `google.protobuf.Any`'s
  `type_url` and `MessageSet`'s `type_id` are runtime data, not `.proto`
  `dependency:` edges — structurally invisible to the static graph. Some
  form of on-demand, mid-render loading is unavoidable for these, and
  `ANY_LOADER` already provides it correctly: it re-derives its result
  fresh from `desc_ctx.pool()` on every call, never caching a value across
  calls.

Both mechanisms mutate the *same* pool object. The bug and the risk
described below both come from other code taking **clones** of that pool
(or of values obtained through it) and **retaining them for the render's
whole lifetime**, rather than from any deficiency in the pool itself or in
either loading mechanism.

### Why a retained clone is worse than "just stale"

`prototext-core`'s `ParsedSchema` wraps an owned `DescriptorPool` value
(`schema_from_pool(desc_ctx.pool().clone(), lookup)` clones it once at the
start of a decode). `render_text/mod.rs` additionally builds
`all_schemas: HashMap<String, Arc<MessageDescriptor>>` once, up front, via
`pool.all_messages().collect()`, and retains it for the entire render.

A naive mental model says: `DescriptorPool` is `Arc`-backed, so `.clone()`
is a cheap ref-count bump and every clone stays in sync automatically. That
is *not* what happens. `add_file_descriptor_proto` uses `Arc::make_mut`
(copy-on-write): if the pool's Arc has more than one strong reference at
the moment of mutation, the call does not mutate in place — it forks,
copying everything loaded so far into a fresh Arc, and applies the new file
only to that fresh copy. Every other outstanding clone (`ParsedSchema.pool`,
every `Arc<MessageDescriptor>` sitting in `all_schemas`, in fact every
`MessageDescriptor` value anyone is holding, since each one carries its own
internal pool-Arc clone) is left pointing at the **old**, now permanently
frozen data — not just out of date until refreshed, but structurally
disconnected from all future growth. `message_set_field.rs` already
documents this exact failure mode (§5.2 comment, lines 230-234) and works
around it for its own resolution step by using `ANY_LOADER`'s freshly
re-derived result instead of `msg_desc.get_extension()`.

Because `all_schemas` is retained for the *entire* render, it keeps the
pool's Arc refcount above 1 continuously. Every subsequent dynamic
completion (`Any`/`MessageSet`) after the first one therefore forks again —
each fork copying the *entire* pool state accumulated up to that point.
With N dynamic completions in one message, this is N copies of a
monotonically growing structure, not a fixed cost. This is the concrete
form of the risk: not merely correctness, but unbounded, compounding memory
churn scaling with how many distinct `Any`/`MessageSet` types a message
references.

### Where the staleness shows up today

`render_any_expansion` (`helpers/any_field.rs`) already has a fallback for
this: `all_schemas.get(fqdn)`, then `ANY_LOADER` on miss. That fallback is
wired into exactly one call site — the first `Any` boundary.

Two other places consult `all_schemas` with **no fallback**:

- `helpers/len_field.rs:251-253` — the generic nested-message path, hit for
  *every* ordinary (non-`Any`, non-`MessageSet`) message-typed field:

  ```rust
  let nested_schema: Option<&MessageDescriptor> = all_schemas
      .and_then(|m| m.get(nested_msg_desc.full_name()))
      .map(|v| &**v);
  ```

  `nested_msg_desc` here comes from `fs.kind()` — already a correctly
  resolved, live `MessageDescriptor`, obtained without touching
  `all_schemas` at all. On a miss, the code discards that resolved
  descriptor and sets `nested_schema = None`.

- `helpers/message_set_field.rs:299` — same shape: `inner_msg_desc` is
  already correctly resolved, but fields nested inside it are rendered by
  threading the same `all_schemas` one level deeper.

`render_any_expansion` itself only fixes the *first* level: it recurses
with `render_message(value_bytes, 0, None, Some(&*resolved_desc),
all_schemas, out)` — the same `all_schemas`, unchanged. Any ordinary
nested-message field inside that JIT-loaded type hits the `len_field.rs`
miss on the very next level down.

### Why a query against `fs.kind()`'s result is always sufficient (no new load needed)

Ordinary (non-`Any`) message-typed fields declare their target type via a
static `type_name`. `protoc` refuses to compile a field referencing a type
outside its own file or a `dependency:`-imported file, so the declaring
file of any such field's type is *always* already loaded by the time
`fs.kind()` can return it (`ensure_loaded` loads a file's full dependency
closure before returning). A message's own field list, once its FDP is
added to the pool, never changes regardless of which Arc generation it was
read through. So `nested_msg_desc` from `fs.kind()` is always complete for
its own fields — no lookup, no new load, ever required at this call site.

### Confirmed reproduction

Verified with a real customer descriptor set (`.desc` + `index.rkyv`
sidecar, `LazyPool` path) via temporary debug instrumentation at
`len_field.rs:251-253`:

```
DEBUG stale-snapshot: nested_msg_desc.full_name()=xuniverse.NotarizationPayloadWrapper
NOT in all_schemas (live field count: 1, all_schemas map size: 55)
```

Sequence: an `Any` field (`notarization`) triggers `ANY_LOADER`, which loads
`notarization.proto` — a file declaring both `Notarization` and its sibling
`NotarizationPayloadWrapper`. `Notarization` renders correctly (first-level
`Any` fallback). Its `wrapped_payload` field (an ordinary nested-message
field, not `Any`) resolves the type name correctly via `fs.kind()`, but
`len_field.rs`'s `all_schemas` lookup misses — `nested_schema` becomes
`None`, and every field inside `NotarizationPayloadWrapper`, including its
real `payload: Any` field, falls back to raw/heuristic decoding.

---

## Goals

1. A nested message type resolved via `fs.kind()` must never render as
   "unknown" solely because it is absent from some snapshot, as long as it
   is genuinely present in the live pool.
2. Fix must apply uniformly, at every recursion depth — not just the first
   `Any`/`MessageSet` boundary.
3. No render-duration structure may keep the canonical pool's Arc refcount
   above 1 for longer than the current call stack requires, so that dynamic
   completions mutate in place instead of repeatedly forking.
4. No change to `prototext-core`'s decoupling from `LazyPool`: `prototext`
   depends on `prototext-core`, so `prototext-core` cannot depend on
   `LazyPool` (which lives in `prototext`) without a dependency cycle. The
   existing `ANY_LOADER` thread-local remains the only channel back to the
   canonical pool.
5. No behavior change for the eager pool path.
6. Stop constructing `ParsedSchema` (and cloning `desc_ctx.pool()` into it)
   in `run.rs`'s decode/render call sites, once verified safe to do so —
   see S4.

## Non-goals

- Changing the static loading strategy (`ensure_loaded`/`dep_graph`) —
  already minimal and correct.
- Changing `ANY_LOADER`'s JIT-loading trigger logic (spec 0099) — the fix
  is about not retaining resolved values, not about how loading is
  triggered.
- Extending JIT-loading to *enum*-typed fields (out of scope; no report of
  this being an issue).
- Adding a bounded, render-scoped memoization cache for repeated identical
  `Any`/`MessageSet` type resolutions — not proposed here; revisit only if
  profiling shows it's needed (see Non-goals discussion under S2).
- Removing `ParsedSchema`/`schema_from_pool`/`parse_schema` from
  `prototext-core`'s public API. They remain available for library
  consumers that only have a plain `DescriptorPool` (no `LazyPool`). S4
  only changes what `run.rs`'s decode/render call sites construct — it
  does not touch `prototext-core/src/schema.rs`.
- Changing `prototext_core::decoder::ingest_pb`/`parse_message`/`packed.rs`
  — a separate recursive decoder (used by exactly one test, plus
  internally by `len_field.rs`'s own structural LEN-field probe via
  `ParsedSchema::empty()`). It takes `full_schema: &ParsedSchema` but
  dereferences it exactly once (`root_descriptor()`, in `ingest_pb`) —
  architecturally the same shape S4 narrows for `decode_and_render` — and
  never does `Any`/`MessageSet` dynamic loading, so it isn't part of the
  bug this spec fixes. Left untouched; not narrowed to `MessageDescriptor`
  alongside `decode_and_render` because nothing requires it.

---

## Specification

### S1 — `len_field.rs`: use the already-resolved descriptor, no lookup

```rust
let nested_schema: Option<&MessageDescriptor> = Some(&nested_msg_desc);
```

Replaces the `all_schemas.get(...)` lookup entirely — not just as a
fallback. `nested_msg_desc` is already live and correct (§ "Why a query
against `fs.kind()`'s result is always sufficient" above); re-deriving it
by name through a second structure was never necessary. This is a strict
simplification, not a slower/faster tradeoff: there is no lookup to time.

### S2 — Drop `all_schemas` / `build_descriptor_map` entirely

`render_any_expansion` and `render_message_set_expansion` already fall back
to `ANY_LOADER` on a miss, and — per spec 0099 §Goal 3 — `ANY_LOADER`'s
implementation works on *both* paths: on lazy pools it JIT-loads via
`LazyPool::get_message`, on eager pools it queries the already-complete
pool directly via `pool.get_message_by_name`. With S1 removing the only
call site that had no fallback, `all_schemas` no longer serves any purpose
other than a micro-optimization (skip the thread-local/closure indirection
when a type happens to already be in the initial static closure). Given
that `Any`/`MessageSet` fields are a small fraction of total fields in a
typical message, that micro-optimization is not worth retaining a
render-duration structure that keeps the pool's Arc pinned above refcount 1
and causes repeated forking (see Background).

Concretely:

- `render_text/mod.rs` no longer calls `build_descriptor_map` /
  `pool.all_messages()`. `build_descriptor_map` is deleted.
- The `all_schemas: Option<&HashMap<String, Arc<MessageDescriptor>>>`
  parameter is removed from `render_message`, `render_len_field`,
  `render_any_expansion`, and `render_message_set_expansion`.
- `render_any_expansion`'s resolution step becomes an unconditional
  `ANY_LOADER` call (no map to check first):

  ```rust
  let resolved_desc: Option<Arc<MessageDescriptor>> =
      ANY_LOADER.with(|l| l.borrow_mut().as_mut().and_then(|f| f(fqdn)));
  ```

- `render_message_set_expansion`'s existing `ANY_LOADER`-first,
  `get_extension`-fallback logic (lines 236-252) is unchanged — it never
  depended on `all_schemas` in the first place.
- Call sites that used `all_schemas.is_some()` purely as a "was a schema
  pool configured at all" signal (`len_field.rs:45`, `mod.rs:362/428/579`,
  distinguishing schema-aware rendering from `--raw`/no-descriptor mode)
  switch to a plain `schema_present: bool` captured once in
  `decode_and_render` from `schema.is_some()` (the `Option<&ParsedSchema>`
  parameter already passed in) and threaded down alongside `schema:
  Option<&MessageDescriptor>` — a direct, information-preserving
  replacement, since `all_schemas.is_some()` was already always exactly
  `schema.is_some()` (`all_descriptors = schema.map(build_descriptor_map)`).

**`prototext-pyo3` needs its own `ANY_LOADER`.** `prototext-pyo3` never
calls `set_any_loader` — it has no `DescriptorContext`/`LazyPool`
equivalent. Its pool (built once, eagerly, via `parse_schema`/
`DescriptorPool::decode`) is always complete, so today `all_schemas` alone
silently does 100% of the work for `Any` resolution in the Python bindings
— the `ANY_LOADER` branch in `render_any_expansion` is dead code for this
consumer. Once `all_schemas` is removed, that fallback disappears too, and
`Any` expansion in `prototext-pyo3` would regress to raw bytes for every
`Any` field, even though the type is present. To prevent this regression,
`prototext-pyo3` must install its own loader around both call sites
(`SchemaHandle::render_as_text`, `format_as_text`):

```rust
set_any_loader(Box::new({
    let schema = Arc::clone(&self.inner); // or the SchemaHandle in scope
    move |fqdn: &str| schema.get_descriptor(fqdn).map(std::sync::Arc::new)
}));
// ... decode_and_render(...) ...
clear_any_loader();
```

`ParsedSchema::get_descriptor` already exists for exactly this purpose
(`schema.rs:38`). No new `prototext-core` API is needed — only
`prototext-pyo3` gains code.

### S3 — `ParsedSchema.pool`: unavoidable one-time clone, no longer retained for lookups

`ParsedSchema` still owns a `DescriptorPool` value — it must, per S "no
`prototext-core` → `LazyPool` dependency" and because `ParsedSchema` is a
general-purpose wrapper used by other subcommands beyond decode/render.
`schema_from_pool(desc_ctx.pool().clone(), lookup)` still clones once, and
that clone is still used once, at the very start of `decode_and_render`, to
resolve `root_desc` via `schema.root_descriptor()`.

With S2 in place, that is now the *only* use of `ParsedSchema.pool` during
rendering — it is never consulted again afterward. This narrows the
retained-clone problem from "N entries, each individually pinning the pool,
for the whole render" (`all_schemas`) down to "one clone, used once, whose
containing `Option<&ParsedSchema>` parameter happens to remain in scope for
the rest of the call." That lingering scope can cause **at most one** fork,
on the first dynamic completion encountered — bounded and small (it copies
only the small static-closure state present at that point), not repeated.

S4 below removes this remaining clone.

### S4 — `run.rs`: stop constructing `ParsedSchema` for decode/render

**Call-site audit.** Every place in `run.rs` that consumes a schema for
decode/render was checked:

| Call site | Behavior |
|---|---|
| `decode --type` (stdin/single-file, line ~762) | one explicit `schema_from_pool(desc_ctx.pool().clone(), lookup)` for the one named type |
| `run_batch` (explicit `--type`, batch mode) | reuses that *same* single `ParsedSchema` for every file in the batch |
| auto-infer, stdin (line ~800) | `infer_type(&data, graph, scoring_opts)` scores wire bytes against `desc_ctx.graph` (the Hopcroft structure) — entirely separate from `DescriptorPool`; only *after* a unique winner is chosen does it call `schema_from_pool` once, for that one winning type |
| auto-infer, single-file (line ~843) | same pattern as above |
| `run_batch_infer` (auto-infer, batch, line ~1260) | same pattern, once per file, each iteration independent |

`encode`, `score`, and `list-schemas` never call `schema_from_pool` at all —
they don't use `ParsedSchema`/`DescriptorPool` in any form; `score` and
`list-schemas` work directly off `desc_ctx.graph`. There is no
`instantiate-schema` subcommand in the current `Command` enum (stale
reference in spec 0069 §S5's strategy table — no longer applicable).

So every decode/render call site resolves exactly one type, always after
any inference step has already completed. Narrowing the interface to "one
resolved type" loses no generality anywhere it's used, and auto-infer in
particular is unaffected: scoring never touches the pool, so this change
has no effect on inference behavior, only on how the winning type's
descriptor is threaded into the renderer afterward.

**Change.** `run.rs`'s five call sites above resolve the root
`MessageDescriptor` directly from `desc_ctx.pool()` (after
`lazy.get_message(lookup)`, already done unconditionally on the lazy path)
instead of constructing a `ParsedSchema`:

```rust
let root_desc = desc_ctx.pool().get_message_by_name(lookup);
```

`prototext-core`'s public signatures change accordingly:

- `decode_and_render(buf, schema: Option<&ParsedSchema>, ...)` →
  `decode_and_render(buf, root_desc: Option<&MessageDescriptor>, ...)`.
  Today this function's only use of `schema` (once S2 removes
  `build_descriptor_map`) is `schema.and_then(|s| s.root_descriptor())` —
  the new parameter is exactly that value, supplied by the caller instead
  of derived internally.
- `render_as_text` (`lib.rs`) and `process` (`run.rs`) update their
  `schema: Option<&ParsedSchema>` parameters to `Option<&MessageDescriptor>`
  to match.

`ParsedSchema`/`schema_from_pool`/`parse_schema` are unchanged in
`prototext-core/src/schema.rs` and remain public (see Non-goals) — `run.rs`
simply stops calling them for decode/render.

**This is a breaking change to `prototext-core`'s public API.**
`render_as_text` and `serialize::render_text::decode_and_render` are both
public and reachable from outside the workspace (`prototext-pyo3` already
imports `decode_and_render` directly via that path). Any external crate
calling either with `Option<&ParsedSchema>` stops compiling until updated
to `schema.root_descriptor().as_ref()`. `prototext-core` is `0.2.1` and
carries publish-ready metadata (`repository`, `description`, `keywords`),
so an unknown external consumer is possible even though none is known from
inside this workspace. Per Cargo/SemVer, breaking changes are permitted
pre-1.0 but must be signalled with a **minor** version bump so that
`^0.2`-pinned consumers don't pick it up silently: `0.2.1` → `0.3.0`.

**Error path — lookup failure.** `schema_from_pool`'s not-found error lists
every message in the pool (`pool.all_messages()...join(", ")`). At scale
(a descriptor set with, say, 100,000 messages) that dumps all 100,000 names
into one error string — already true today, but S4 moves the
error-construction responsibility into `run.rs`, which is the right moment
to fix it rather than reproduce it as-is. `run.rs`'s 5 call sites replace
the full dump with a single closest match by edit distance:

```rust
let root_desc = desc_ctx.pool().get_message_by_name(lookup);
if root_desc.is_none() {
    let closest = desc_ctx.pool().all_messages()
        .min_by_key(|m| strsim::levenshtein(m.full_name(), lookup));
    return Err(match closest {
        Some(m) => format!("type '{lookup}' not found (did you mean '{}'?)", m.full_name()),
        None => format!("type '{lookup}' not found"),
    });
}
```

`strsim` is already in `Cargo.lock` transitively (via `clap`); this
promotes it to a direct dependency of `prototext`. This changes the
not-found message's wording/content for `decode`/`run_batch`/
`run_batch_infer` only — `schema_from_pool`/`parse_schema`'s own
"available: ..." message in `schema.rs` is untouched (still used by
`prototext-pyo3`'s `register_schema` and any other direct library
consumer), so there is a wording inconsistency between the two error
sources going forward. Not resolved here — flagged as acceptable since
`schema.rs`'s message is a schema-registration-time error (rare, one-shot),
not a per-decode error.

**What this does and does not fix.** `ParsedSchema::root_descriptor()`
returns an owned `MessageDescriptor`, constructed via
`self.pool.get_message_by_name(...)` — it holds its own internal reference
into the same pool Arc as `self.pool`. So retaining a `ParsedSchema` across
a render actually keeps *two* outstanding references to that Arc: the
`pool: DescriptorPool` field itself, and the `MessageDescriptor` returned by
`root_descriptor()`. S4 removes the first (the `ParsedSchema`/`pool` field
was, after S1+S2, never read again anyway). It does **not** remove the
second: a render still needs a live root-type `MessageDescriptor` for its
whole duration (to know the top-level message's fields), and holding *any*
`MessageDescriptor` pins the pool's Arc refcount above 1 for as long as it's
held, regardless of whether it came from `ParsedSchema` or straight from
`desc_ctx.pool()`. So the "at most one bounded fork" from S3's analysis is
inherent to needing a live root descriptor at all — S4 removes one
redundant, otherwise-unused clone, not the fork itself. See "Pool identity
under the fix" below.

---

## Pool identity under the fix

Two pool "things" exist before and after this fix; their roles change as
follows.

**Pool A — `LazyPool.pool` / `desc_ctx.pool()`** (canonical, lives in
`prototext`/`run.rs`). Unchanged in nature: still the single object that
`ensure_loaded` (static) and `ANY_LOADER` (dynamic) mutate via
`add_file_descriptor_proto`. What changes is that, with S2/S4 in place,
nothing outside `run.rs` retains a long-lived *pool* clone anymore (only
the single root-type `MessageDescriptor`, see Pool B below), so its Arc
refcount stays at (or very close to) 2 — `desc_ctx.pool()` itself plus that
one descriptor — for the render's duration, instead of climbing with every
retained `all_schemas` entry.
Static and dynamic loads alike mutate it in place rather than forking.
This is the pool that actually grows over the render's lifetime.

**Pool B — `ParsedSchema.pool`** (`prototext-core`-side wrapper, required
by the crate-dependency boundary — `prototext-core` cannot depend on
`LazyPool`). Still exists in `prototext-core/src/schema.rs`, unchanged, and
still available to other library consumers. With S4, `run.rs`'s
decode/render call sites simply stop constructing one: no `ParsedSchema`,
no `desc_ctx.pool().clone()`, for this path. Pool B is no longer part of
the decode/render picture at all.

What remains, in Pool B's place, is a single `MessageDescriptor` — the
resolved root type — obtained directly from Pool A via
`desc_ctx.pool().get_message_by_name(lookup)` and held for the render's
duration (S4). This is not a new kind of cost: every other resolved
descriptor already flowing through the renderer (`fs.kind()`, `ANY_LOADER`
results) is the same `MessageDescriptor` type, holding the same kind of
internal Arc reference into Pool A. Holding this one root-type descriptor
for the whole render can still cause **at most one** bounded fork of Pool A
on the first dynamic completion encountered — the same bound described
under §S3 before S4, not a new or larger risk. What S4 removes is the
*redundant second* reference (the standalone `pool: DescriptorPool` clone
`ParsedSchema` used to hold, never read again after S1+S2) — a pure
simplification, not an additional fork-avoidance win.

---

## Files changed

- `prototext-core/src/serialize/render_text/mod.rs` — S2: remove
  `build_descriptor_map`, `all_schemas` construction and threading; add
  `schema_present: bool`.
- `prototext-core/src/serialize/render_text/helpers/len_field.rs` — S1, S2:
  drop `all_schemas` lookup and parameter; use `schema_present`.
- `prototext-core/src/serialize/render_text/helpers/any_field.rs` — S2:
  drop `all_schemas` parameter and fast-path check; unconditional
  `ANY_LOADER` call.
- `prototext-core/src/serialize/render_text/helpers/message_set_field.rs` —
  S2: drop `all_schemas` parameter (resolution logic unchanged).
- `prototext-core/src/serialize/render_text/mod.rs` — S4: `decode_and_render`
  signature `Option<&ParsedSchema>` → `Option<&MessageDescriptor>`.
- `prototext-core/src/lib.rs` — S4: `render_as_text` signature updated to
  match.
- `prototext/src/run.rs` — S4: the five decode/render call sites (S4
  table) resolve `MessageDescriptor` directly from `desc_ctx.pool()`
  instead of constructing `ParsedSchema`; `process()` signature updated to
  match; not-found error switches to closest-match-by-edit-distance.
- `prototext/Cargo.toml` — S4: add `strsim` as a direct dependency
  (already present transitively via `clap`).
- `prototext-pyo3/src/lib.rs` — S2: install `set_any_loader`/
  `clear_any_loader` around `SchemaHandle::render_as_text` and
  `format_as_text`, backed by `ParsedSchema::get_descriptor`, to preserve
  `Any` expansion once `all_schemas` is removed.
- `prototext-core/Cargo.toml` — S4: version bump `0.2.1` → `0.3.0`
  (breaking public API change, see S4).
- `prototext/tests/roundtrip.rs` — S4: ~50 `render_as_text(&wire,
  Some(&schema), ...)` call sites updated to
  `render_as_text(&wire, schema.root_descriptor().as_ref(), ...)`.
  **Not purely mechanical, contrary to this entry's original wording**: 3
  of those call sites (`any_field_expands_type_url_and_value`,
  `any_field_roundtrip`, `any_field_golden_annotated_output`) actually
  assert real `Any` expansion, and started failing after the mechanical
  rewrite — direct library callers, like `prototext-pyo3`, lose the
  `all_schemas` fast path too, so they must now install `ANY_LOADER`
  themselves (a new `with_any_loader` test helper does this, mirroring the
  `prototext-pyo3` fix). Also adds TC-1's regression fixture
  (`any_field_jit_loaded_type_nested_field_renders_symbolically`,
  `container_only_schema`, `payload_with_sibling_file_bytes`,
  `any_jit_nested_wire_bytes`) using an `ANY_LOADER` that grows a cloned
  pool on demand, mirroring `LazyPool::ensure_loaded`.
- `prototext/tests/e2e.rs` — TC-7: new
  `decode_type_typo_suggests_closest_match` test asserting the CLI's
  closest-match error message for a near-but-not-exact `--type`.
- `prototext-pyo3/tests/test_codec.py` — TC-8: new
  `test_format_as_text_expands_any_field` test (none existed before);
  regression guard for the `prototext-pyo3` `ANY_LOADER` fix above.
- `docs/specs/0106-lazy-pool-nested-schema-staleness.md` — this file.

---

## Test plan

- TC-1: **Implemented, with a lighter-weight fixture than originally
  specified.** Rather than a real `index.rkyv`/`LazyPool` fixture, the added
  test (`any_field_jit_loaded_type_nested_field_renders_symbolically` in
  `roundtrip.rs`) installs an `ANY_LOADER` closure that grows a cloned
  `DescriptorPool` on demand — functionally identical to
  `LazyPool::ensure_loaded` loading a whole file (a JIT-loaded `Any` payload
  type plus a sibling type reachable only via an ordinary nested-message
  field of that type) the first time it's requested, without needing the
  rkyv index file format. This exercises the exact bug mechanism (a stale
  snapshot taken before the JIT load misses the sibling) and fails without
  the S1 fix. A true `LazyPool`/`index.rkyv`-backed end-to-end fixture was
  judged disproportionate: S1's fix (`Some(&nested_msg_desc)` used
  directly, no lookup at all) makes the bug class structurally impossible
  regardless of which pool implementation triggered the JIT load.
- TC-2: Not added as a separate test — already covered by the pre-existing
  eager-pool `Any`-expansion tests (TC-4), which exercise the same
  `render_len_field`/`render_any_expansion` code paths S1/S2 touch.
- TC-3: Not added as a separate test — already covered by the pre-existing
  `message_set_group_annotation_syntax`/`message_set_resolved_expansion_renders_canonical_names`
  tests in `roundtrip.rs`, unchanged by this spec (`message_set_field.rs`'s
  resolution logic never depended on `all_schemas`).
- TC-4: Confirmed — all pre-existing `Any`-expansion tests in
  `roundtrip.rs` pass after the S1/S2/S4 changes (3 of them needed the
  `with_any_loader` fix described in Files changed above to keep passing).
- TC-5: Not implemented — no peak-RSS/Arc-strong-count sanity probe was
  added. S2's removal of `all_schemas` is a straightforward reachability
  argument (§ "Why a query against `fs.kind()`'s result is always
  sufficient"), not something the existing test infra has tooling for.
- TC-6: Confirmed — `prototext`'s full existing test suite (`roundtrip.rs`,
  `e2e.rs`, `protocraft.rs`) passes unchanged after S4's `run.rs` narrowing.
- TC-7: Implemented — `decode_type_typo_suggests_closest_match` in
  `e2e.rs` asserts the CLI's `decode --type SwissArmyKnif` (missing the
  trailing `e`) error contains `"did you mean 'SwissArmyKnife'?"`.
- TC-8: Implemented — no `Any`-expansion test existed in
  `prototext-pyo3/tests/test_codec.py` before this spec, so
  `test_format_as_text_expands_any_field` was added. Verified against the
  compiled `.so` directly with `pytest` (10/10 pass, including this one).
