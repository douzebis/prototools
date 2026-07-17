<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0135 — protolens: raw tag+payload re-wrap for overrides, primitive-type overrides

Status: implemented
Implemented in: 2026-07-17
Refs: docs/specs/0114-protolens-tui.md (wrap-and-redecode splice trick,
      `register_wrapper`/`wrap_blob` origin), docs/specs/0118-protolens-
      override-generalization.md (`register_wrapper` generalized to
      arbitrary field numbers), docs/specs/0119-protolens-override-
      fidelity-and-workflow.md (display-name override, `field_name_for`),
      docs/specs/0120-protolens-any-messageset-auto-expand.md
      (`protolens_internal` namespace origin, `MessageSetItem`),
      docs/specs/0122-protolens-override-header-patching.md (current
      header-patching mechanism — largely superseded here), docs/specs/
      0134-protolens-override-kind-mutation-rework.md (unrelated
      `OverrideKind`/origin-rotation axis, untouched by this spec)
App: protolens

## Background

`splice_override` (`tui/override_apply.rs`) is how the override pane and
`:type-as`/`:type-as-raw` reinterpret a node's bytes under a different
message schema. Today it:

1. Strips the node's own tag (and, for `WT_LEN`, its length prefix; for
   a group, its trailing `END_GROUP` tag) via
   `extract::message_payload_range`, leaving just the payload interior.
2. Re-wraps that interior payload with a **freshly synthesized**
   `WT_LEN` tag (`decode::wrap_blob`), regardless of what the node's
   true original wire type was.
3. Decodes the wrapped bytes against a synthetic one-field message
   descriptor (`decode::register_wrapper`, `protolens_internal.
   Wrapper_<field_number>_<field_name>_<target_fqdn>`), whose sole
   field is hardcoded `Type::Message`.
4. Since step 2 discarded the node's real wire framing (message vs.
   deprecated proto2 group), the synthetic wrapper's own rendered
   header cannot be reused wholesale — doing so silently loses `#@
   group` framing on override, corrupting a later re-encode (this was
   the exact bug spec 0122 fixed). Spec 0122's fix instead **patches**
   the node's own pre-existing header annotation in place: locate the
   type-declaration/wire-type-placeholder token inside `old_span.
   natural_annotation` and substitute it, leaving every other token
   (leading `group`, anomaly modifiers) untouched. This is roughly 70
   lines of token-splicing logic (`splice_override`'s `patched_
   annotation` block) — correct, but described in spec 0122 itself as
   more fragile than resynthesizing from typed structured facts (a
   direction spec 0122 considered and rejected as *even more* invasive
   at the time).

Two issues motivate revisiting this:

- **Primitive fields can't be overridden at all.** `can_override`
  (`tui/override_select.rs`) gates on `span.is_message ||
  span.wire_type == WT_LEN` — plain `VARINT`/`I32`/`I64` scalar fields
  are structurally excluded, because there is no way today to give the
  synthetic wrapper's sole field anything but `Type::Message`.
- **The header-patching mechanism is inherently fragile** — it exists
  purely to compensate for step 2 discarding the node's real wire
  framing. Any future annotation-grammar change risks silently
  breaking `patched_annotation`'s token-position assumptions.

### The key fact this spec is built on

`NodeSpan::raw_range` is **already** the node's complete original
tag+payload byte range — not just the payload. This is directly
verified by `extract::message_payload_range` (`extract.rs`): for a
group, it reconstructs the trailing `END_GROUP` tag position from
`range.end` in order to strip it — which only makes sense if
`raw_range` already spans the real `START_GROUP` tag through the real
`END_GROUP` tag, inclusive. In other words: **`self.blob[old_span.
raw_range.clone()]` is already a fully self-framed, valid encoding of
a single field occurrence, with its true original wire type intact**
(message `WT_LEN`, group `WT_START_GROUP`/`WT_END_GROUP`, or a scalar
`WT_VARINT`/`WT_I32`/`WT_I64` tag+value).

This means step 1 (strip the tag) and step 2 (re-synthesize a fake
`WT_LEN` tag) are both unnecessary: decoding `self.blob[old_span.
raw_range.clone()]` directly, against a synthetic descriptor whose
sole field has `field_number = old_span.field_number` and the correct
declared type, reproduces the node's real wire framing in the
rendered header **for free** — no patching needed, because `TextSink`
renders it correctly the first time.

**Packed-repeated fields** need one refinement, not an exception. A
packed-repeated scalar element (`old_span.packed_record_start.
is_some()`) has no tag of its own — every element's bytes sit inside
one shared, real, `WT_LEN`-framed record, whose single tag is at
`packed_record_start`. Overriding "one element in isolation" isn't a
wire-level operation the format supports; overriding is instead
defined at the level of the whole packed record's `WT_LEN` blob
(discussed and confirmed, 2026-07-17) — which *is* a normal,
real-tag-bearing `WT_LEN` field, so the general mechanism above
applies to it directly once its true extent is reconstructed:
re-parse the tag+length-varint at `packed_record_start` to get the
record's real `raw_range`, and gather every sibling element node that
shares that same `packed_record_start` to get the record's full
rendered `text_range` (first element's line start through last
element's line end) — both are needed since `splice_override` today
replaces a node's whole `text_range`, not just `raw_range`'s
corresponding bytes. Once reconstructed, this is decoded exactly like
any other `WT_LEN` field — string/bytes/message are all valid
override targets for it, `group` is not (a packed record is never
`WT_START_GROUP`-framed). This means there are, in the end, **no**
special-cased synthetic-tag code paths left anywhere in
`splice_override` — every override, packed or not, decodes real
tag-framed bytes.

**Reconstructing the record's extent is a data problem; collapsing it
in the tree is a separate, structural one.** Every packed element is
today a distinct top-level `TreeNode` — a true *sibling* of every
other element (same parent, linked via `next_sibling`/`prev_sibling`/
`doc_next`/`doc_prev`), not a descendant of one another. `splice_
override` today only ever replaces one node's own *descendants*
(`collect_descendants`, pointer-based, spec 0114 §5) — sibling
linkage and the parent's `first_child`/`last_child` are never touched,
because a single node's position among its own siblings never
changes when only its interior is replaced. Collapsing N sibling
element-nodes into one merged node (per the whole-record semantics
above) is therefore a **sibling merge**, not a subtree replacement —
new territory for `splice_override`, addressed in G1 below.

**A second, independent subtlety**, found while reading
`prototext-core`'s actual rendering dispatch (`render_group_field`/
`render_len_field`, `serialize/render_text/helpers/len_field.rs`):
which wire-type byte is observed (`WT_LEN` vs `WT_START_GROUP`)
decides *which renderer runs*, but resolving that renderer's *nested
schema* is gated on a second, independent check against the field's
**declared** `Type`:
- `render_group_field` only resolves `nested_msg_desc` when
  `field_schema.is_group()` is true (`Type::Group`) — a `Type::
  Message`-declared field here yields `None`.
- `render_len_field`'s message-resolution branch explicitly treats a
  `Type::Group`-declared field as a wire-type mismatch (falls through
  to the generic string/bytes/mismatch path) — only `Type::Message`
  resolves.

So a synthetic descriptor's declared `Type` must mirror the source
node's real wire framing (`old_span.wire_type == WT_START_GROUP` →
`Type::Group`; `WT_LEN` → `Type::Message`) — hardcoding `Type::
Message` always (today's `register_wrapper`) would, under G1's
real-tag reuse, silently lose schema resolution for the *interior* of
any group-framed override, even though the outer framing is by then
correct. This was missed in this spec's first draft and only
surfaced by reading the dispatch code directly.

## Goals

### G1 — decode the node's real tag+payload directly, drop header patching

- `splice_override`: for an ordinary (non-packed) node, slice directly:
  `let field_bytes = self.blob[old_span.raw_range.clone()].to_vec();`
  — decoded as-is, no synthetic tag prepended.
- For a packed-repeated element (`old_span.packed_record_start.
  is_some()`), first reconstruct the whole record's real `raw_range`
  (re-parse tag+length at `packed_record_start`) and real `text_range`
  (span of every sibling node sharing that `packed_record_start`), per
  Background above, then proceed identically to the ordinary case —
  no synthetic tag construction anywhere.
- **Sibling merge** (packed case only, per Background's "structural"
  subtlety): let `siblings` be every tree index sharing the clicked
  node's `packed_record_start`, in document order (found by walking
  the parent's child list, since packed elements are always
  contiguous children of the same parent).
  - The receiving node — the one whose `TreeNode` slot is mutated in
    place, exactly as `idx` is in the ordinary case — is always
    `siblings[0]`, regardless of which specific element the user
    invoked the override on. `idx` is reassigned to `siblings[0]`
    before any of the ordinary-case logic below runs; `old_span`'s
    `raw_range`/`text_range` are overwritten with the reconstructed
    whole-record values from the previous bullet.
  - `siblings[1..]` (and, generically, each one's own descendants —
    always empty in practice today, since packed elements are leaf
    scalars, but collected the same way as `old_descendants` for
    correctness if that ever changes) are **orphaned**: unioned into
    the same set that today only holds `idx`'s own descendants, so
    they're scrubbed from `folded` and excluded from the post-splice
    `line_to_node`/`footer_line_to_node` rebuild (both already walk
    the live `doc_next` chain, so an orphan unlinked from that chain
    is naturally excluded).
  - The seam node `after` (used for `doc_next`/`doc_prev` splicing and
    the forward `text_range` delta-shift) is computed from `siblings.
    last()`'s own `doc_next` — not `siblings[0]`'s — since the whole
    run, not just the first element, is being replaced.
  - Pointer repair beyond the ordinary case: `siblings[0].
    next_sibling` (currently pointing at `siblings[1]`, about to be
    orphaned) is repointed to `siblings.last().next_sibling` — the
    sibling that follows the *whole* packed run, if any — and that
    neighbor's `prev_sibling` is updated symmetrically. If the run
    reached the parent's own last child (`parent.last_child ==
    Some(*siblings.last())`), `parent.last_child` is repointed to
    `siblings[0]` too. `siblings[0]`'s own `prev_sibling` and the
    parent's `first_child` need no change — the run's *leading* edge
    is unaffected by absorbing the elements after it.
  - Net effect: whichever element the user actually clicked, the
    result is identical — one merged node at the packed field's
    original position, replacing all of its elements' rendered lines.
- The synthetic field's declared `Type` is `Type::Group` only when the
  (possibly just-reconstructed) node's `wire_type == WT_START_GROUP`
  (Background, "second subtlety"); otherwise it is simply whatever the
  chosen target already means — `Type::Message` for a message FQDN,
  `Type::String`/`Type::Bytes` for those keywords (G3), the matching
  primitive `Type` for a primitive keyword (G3). `wire_type` only ever
  forces a *departure* from the target's natural type in the group
  case; it never overrides the target's own type otherwise.
- The render cache (`self.render_cache`) is keyed by `(interior_range,
  target)` — not `raw_range`, and no longer `field_name` (G2 makes the
  cached render field-name-invariant; only the post-hoc placeholder
  substitution varies with it). `interior_range` is still computed via
  `extract::message_payload_range(&self.blob, &raw_range, None)` — the
  same "interior" quantity the cache already keys on today — just
  applied to the resolved `raw_range` (post packed-reconstruction, if
  applicable) rather than the pre-G1 stripped-and-rewrapped one; called
  with `packed_record_start: None` regardless, since by this point the
  packed case has already been normalized to an ordinary tagged
  `WT_LEN` record. `interior_range` and the bytes actually decoded
  (`raw_range`, tag included) are deliberately two different
  quantities now — the cache key no longer needs to equal the decode
  input, and `interior_range` remains just as collision-free a key as
  `raw_range`, since the tag/length-prefix width is a fixed function
  of `raw_range.start`.
- Local-tree-to-global-blob coordinate translation simplifies to match
  (`wrap_blob`/`wrapper_width` are gone from this call site — decoding
  no longer prepends anything): a freshly decoded local span's byte
  offset, 0-relative to the decoded `raw_range` bytes, maps into the
  document's real coordinates via plain `local_offset + raw_range.
  start` — no `wrapper_width` subtraction term, since there is nothing
  synthetic to subtract. `wrap_blob`/this `wrapper_width` computation
  survive only in `decode()`'s own top-level document-wrap call
  (Non-goals).
- `NodeSpan::natural_annotation`-based header patching
  (`patched_annotation`'s ~70-line token-splicing block, spec 0122 §2)
  is deleted. `new_lines[0]` — the synthetic descriptor's own rendered
  header line — is used as-is (after the field-name substitution of
  G2), since it is now built directly from the real wire framing.
- `NodeSpan::wire_type`/`natural_annotation` preservation-from-
  `old_span` on `new_self_span` (needed today only because `wrap_blob`
  discarded the real framing) is deleted with no remaining special
  case — the freshly decoded span's own `wire_type`/annotation are
  always correct now, since they were derived from the real tag in
  every case, packed or not.
- This fully supersedes spec 0122's patching mechanism.
  `NodeSpan::natural_annotation` (`prototext-core`) itself is
  `pub`/general-purpose and used elsewhere in `prototext-core`
  (unrelated to this override-specific patching) — left untouched;
  only its *use* in `splice_override` is removed.

### G2 — fixed placeholder field name, deterministic hashed type name

- `register_wrapper`: the synthetic field's `name` becomes the fixed
  literal `"_"` instead of the caller-supplied `field_name`.
- Today, renaming a field's display override name (spec 0119 §G4's
  `name`) causes a **new** synthetic descriptor to be registered every
  time, because `field_name` is baked into the cache key — real churn
  in the descriptor pool, not just a cosmetic wart. Fixing the name to
  `_` eliminates this.
- `splice_override`'s post-render step: since G1 means the header line
  is otherwise already correct, the only remaining patch is a plain
  substring replacement of the literal placeholder token `_` (the
  synthetic field's rendered name, immediately after indentation) with
  `field_name_for(idx)`'s result — a single `str::replacen` on the
  header token, not annotation surgery.
- **Synthetic message name**: a descriptor's full identity is now
  exactly `(field_number, Type, type_name)` — nothing else about it
  varies (name is always `_`, label is always `Optional`, syntax is
  always proto2). Build the short name deterministically from those
  three: `protolens_internal.x<32 lowercase hex chars>`, where the hex
  digits are the first 16 bytes (128 bits) of `SHA-256(format!(
  "{field_number}:{type_str}:{type_name}"))`, and:
  - `type_str` is `field_type.as_str_name()` — the prost-generated
    `Type` enum's own canonical name accessor (`"TYPE_MESSAGE"`,
    `"TYPE_GROUP"`, `"TYPE_INT32"`, ...). Deliberately *not* `{:?}`
    (`Debug`) formatting — `Debug` output isn't an API contract meant
    for stable/semantic use, whereas `as_str_name()` is the
    purpose-built, intentional accessor for exactly this.
  - `type_name` is `.{fqdn}` for a message/group target (mirrors
    `FieldDescriptorProto::type_name`'s own leading-dot convention),
    or the empty string for a primitive target (G3) — `type_name` is
    only meaningful for message/group/enum kinds in the first place.
    Nothing about this naming scheme is message/group-specific: an
    enum target's `type_str` would be `field_type.as_str_name()` →
    `"TYPE_ENUM"`, and its `type_name` would be `.{enum_fqdn}`, the
    same shape as a message target's. The scheme is enum-ready by
    construction, even though this spec never constructs that case
    (G3/Non-goals).
  - `sha2` is added as a direct `protolens` dependency — already
    present in the workspace `Cargo.lock` transitively, so this adds
    no new dependency-tree weight.
  - Leading `x`, not `_`: verified against `sha256`-hex naming
    concerns raised in discussion — official `.proto` identifier
    grammar (`ident = letter { letter | decimalDigit | "_" }`)
    requires the *first* character to be a letter; `_`/digits are
    only legal as continuation characters, not as the first one. (A
    leading-underscore name, e.g. protoc's own synthetic proto3-
    optional oneof name `_x` — verified directly against `protoc
    32.1` — is accepted by protoc's own descriptor builder for
    compiler-*generated* names, but that shows the builder tolerates
    it, not that it is grammar-legal; since the goal here is a
    grammar-legal name, not merely a builder-accepted one, `_` alone
    doesn't qualify.) `x` is a valid letter; `x<hex>` reads naturally
    as a hex-literal-style name and cannot collide with any
    plausible real message name (conventionally capitalized).
  - The full name is looked up (`pool.get_message_by_name`) before
    registering, same idempotent pattern as today — no new cache
    structure. Collision risk between two genuinely different
    `(field_number, type_str, type_name)` triples is the standard
    128-bit SHA-256-prefix collision probability — considered
    negligible; hashing happens at most once per distinct triple per
    session (subsequent calls hit the pool lookup), so using a full
    cryptographic hash instead of a faster non-cryptographic one costs
    nothing measurable.

### G3 — generalize the synthetic descriptor to primitive wire types

- `register_wrapper` (or a sibling function reused by the same
  call site) gains the ability to build a synthetic field whose
  `FieldDescriptorProto::type` is a wire-compatible **primitive**
  (`Type::Int32`/`Sint32`/`Uint32`/`Int64`/`Sint64`/`Uint64`/
  `Fixed32`/`Sfixed32`/`Float`/`Fixed64`/`Sfixed64`/`Double`/`Bool`/
  `String`/`Bytes`), not only `Type::Message`/`Type::Group`. Which
  primitives are valid for a given node depends on its `wire_type`:
  `WT_VARINT` → int32/int64/uint32/uint64/sint32/sint64/bool/enum
  (`enum` listed here for completeness/harness-readiness only — this
  spec does not wire up an enum target path anywhere, see G2's note
  and Non-goals; the compatibility rule itself is what a future spec
  will need, so it's recorded now rather than rediscovered later);
  `WT_I32` → fixed32/sfixed32/float; `WT_I64` →
  fixed64/sfixed64/double; `WT_LEN` → string/bytes/message (unchanged;
  never group — see Background); `WT_START_GROUP` → **no primitives at
  all** — group framing (`START_GROUP`/`END_GROUP` tags, no length
  prefix) can never be validly reinterpreted as a primitive scalar
  (a `Type::String`/`Int32`/etc. field expects `WT_LEN`/`WT_VARINT`/
  etc. framing and would just wire-type-mismatch on it); only a
  message/group FQDN target is valid for a group-framed node, exactly
  as today. Stated explicitly here (not left as a silent omission from
  the table) since `can_override` admits group-framed nodes via
  `is_message`, independent of this wire-type list — G4's primitive-
  keyword rejection must cover this case too.
- `can_override` (`override_select.rs`) is widened: any node with a
  decodable tag (`is_message || wire_type` being one of `WT_LEN`,
  `WT_VARINT`, `WT_I32`, `WT_I64`) is now a valid override target —
  plain scalar fields are no longer categorically excluded. For a
  packed element, this is evaluated against the record's own
  (reconstructed) wire type, always `WT_LEN` (G1) — never the
  element's individual wire type.
- No enum support is added in this spec (see Non-goals) — the same
  synthetic-field machinery generalizes to `Type::Enum` naturally in a
  future spec, but is not built here.

### G4 — `:type-as` accepts a primitive type keyword

- `run_type_as`/`type_as` (`tui/command_line.rs`): today `<FQDN>` is
  resolved exclusively via `pool.get_message_by_name`, which only
  finds message types. Extend argument resolution: if the argument
  matches one of the primitive keywords listed in G3 (`int32`,
  `sint32`, `uint32`, `int64`, `sint64`, `uint64`, `fixed32`,
  `sfixed32`, `float`, `fixed64`, `sfixed64`, `double`, `bool`,
  `string`, `bytes`), build the synthetic field with that primitive
  type (G3) instead of doing a message-FQDN pool lookup; otherwise,
  fall back to today's FQDN lookup unchanged.
- Reject (with a message-line error, mirroring today's "type '{fqdn}'
  not found" failure) a primitive keyword that is not wire-compatible
  with the target node's `wire_type` (G3's compatibility table) —
  e.g. `:type-as float` on a `WT_VARINT` node fails cleanly rather
  than producing garbage.
- Tab-completion (`complete_type_as_fqdn`) additionally offers the
  wire-compatible primitive keywords for the cursor node's current
  `wire_type`, alongside today's message-FQDN candidates.
- This is the end-to-end fix for Issue #1 ("not possible to override a
  primitive type"), reachable via the existing `:type-as` command-line
  path. The override pane's own candidate list/scoring UI is
  deliberately **not** extended to offer primitive targets in this
  spec (see Non-goals) — `all_type_fqdns`/`inferred_candidates`/
  `SortMode`/`CandidateCache` (`override_pane.rs`) remain
  message-FQDN-only.

## Non-goals

- No change to the override pane's candidate list/scoring UI
  (`override_pane.rs`'s `all_type_fqdns`, `inferred_candidates`,
  `SortMode`, `CandidateCache`) to browse/select primitive or enum
  targets — deferred to a follow-up spec (discussed and explicitly
  deferred, 2026-07-17). `OverrideEntry.r#type` gains no new
  representation for "primitive kind" in this spec; G4's primitive
  `:type-as` path resolves the type keyword directly at apply time,
  without needing a new `r#type` shape.
- No enum-type override support (`Type::Enum`) is *wired up* in this
  spec — no `:type-as <enum-name>` keyword resolution, no
  override-pane candidate list, no `can_override` path specific to
  enums. The synthetic-descriptor *harness* itself (`register_
  wrapper`/`synthetic_wrapper_name`'s `field_type: Type, type_name:
  Option<String>` signature, G2) is, however, already fully generic
  over `Type::Enum` plus an enum FQDN's `type_name` — a future spec
  adding enum support needs only the resolution/UI plumbing (mirroring
  G3/G4's primitive-keyword work), not any change to the harness
  itself.
- No new reserved namespace (e.g. `.protolens.xxx`) — synthetic
  descriptors continue to live under the existing, already-shipped
  `protolens_internal` package (used today for `Wrapper_*` and
  `MessageSetItem`), which already satisfies the collision-avoidance
  goal without introducing a second convention.
- No change to how a packed-repeated field is *displayed* (still one
  line per element) — only how *overriding* it is interpreted (the
  whole record's lines are replaced together, G1), same as any other
  field's override replacing its whole `text_range`.
- No change to `OverrideKind`/origin rotation (spec 0117/0134) — an
  unrelated axis (which nodes an override's origin resolves to), not
  touched by this spec.
- No change to `wrap_blob`'s use in `decode()` for the top-level
  document wrap (spec 0114 §1.1) — that call site has no real
  surrounding tag to reuse (the document root has no field number),
  so it still needs to synthesize one. This remains the *only*
  surviving call to `wrap_blob` in the codebase once G1 lands.

## Specification

### `Cargo.toml` (`protolens`)

- Add `sha2` as a direct dependency (already resolved in the
  workspace `Cargo.lock` transitively).

### `decode.rs`

- `register_wrapper`: field `name` hardcoded to `"_"`. Signature
  generalized to take the synthetic field's shape directly rather than
  a `&MessageDescriptor`, e.g. `field_type: prost_types::
  field_descriptor_proto::Type`, `type_name: Option<String>` (message/
  group FQDN, `.`-prefixed) — `type_name.is_some()` cases additionally
  need the target's parent file added as a `dependency` (as today).
  Builds the full name per G2's hashing scheme instead of the current
  `Wrapper_<suffix>` concatenation.
- New small helper for the hash/name computation itself (e.g. `fn
  synthetic_wrapper_name(field_number: u64, field_type: Type,
  type_name: &str) -> String`), used by `register_wrapper`.
- `wrap_blob` is unchanged in signature/behavior — still used only by
  the top-level `decode()` document-wrap call (Non-goals).

### `tui/override_apply.rs`

- `splice_override`: decode input becomes the direct `raw_range` slice
  (G1) for the ordinary case; add the packed-record reconstruction +
  sibling-merge step for the packed case, then continue through the
  same unified path. `wrap_blob`/`wrapper_width` are deleted from this
  function entirely.
- `message_payload_range` is *not* deleted — it moves from computing
  the decode input (its old role) to computing the render-cache key's
  `interior_range` (its new, sole remaining role here), called on the
  resolved `raw_range` with `packed_record_start: None` always (G1).
  `cache_key` becomes `(interior_range, target)` — `field_name` is
  dropped.
- `byte_offset` (used to translate the freshly decoded local tree's
  spans into global blob coordinates) drops its `wrapper_width` term:
  `let byte_offset = raw_range.start as isize;` — decoding no longer
  prepends a synthetic tag, so the local tree is already 0-relative to
  `raw_range.start`.
- Determine the synthetic field's `Type::Group`/`Type::Message`/
  primitive `Type` from the (possibly reconstructed) node's `wire_type`
  and the chosen target before calling `register_wrapper` (G1, "second
  subtlety").
- Delete the `patched_annotation` block (~70 lines) and its use in
  building `patched_first_line`; replace with a single placeholder
  substring replacement (G2).
- Delete the `new_self_span.wire_type`/`natural_annotation`
  preservation-from-`old_span` special-casing entirely — no case needs
  it any more (G1).
- New small helpers for the packed case (G1's "sibling merge"):
  - `fn packed_record_siblings(&self, idx: usize) -> Vec<usize>` —
    every tree index sharing `self.tree[idx].span.packed_record_start`
    with `idx`, in document order, found by walking `idx`'s parent's
    child list (`first_child`/`next_sibling`) and filtering on a
    matching `packed_record_start`.
  - `fn packed_record_extent(&self, siblings: &[usize]) ->
    (Range<usize>, Range<usize>)` — `(raw_range, text_range)`: the
    former by re-parsing the tag+length-varint at the shared
    `packed_record_start`; the latter as `siblings[0]`'s `text_range.
    start` through `siblings.last()`'s `text_range.end`.
  - Both used only when `old_span.packed_record_start.is_some()`, at
    the top of `splice_override`, before any other logic runs: `idx`
    is reassigned to `siblings[0]`, `old_span`'s `raw_range`/
    `text_range` are overwritten from `packed_record_extent`, and
    `siblings[1..]` (plus their own descendants, collected the same
    way as `old_descendants`) are added to the orphaned set. The seam
    (`after`) is derived from `siblings.last()`'s `doc_next` instead
    of `idx`'s own. After the new subtree is spliced in, `siblings[0].
    next_sibling`/`prev_sibling` of its new next-neighbor, and
    (conditionally) `parent.last_child`, are repointed past the
    absorbed run — see G1 for the exact rule.

### `tui/override_select.rs`

- `can_override`: widen the gate per G3; for a packed element,
  evaluate against the reconstructed record's `WT_LEN`, not the
  element's own `wire_type`.

### `tui/command_line.rs`

- `run_type_as`/`type_as`: primitive-keyword resolution + wire-type
  compatibility check, per G4.
- `complete_type_as_fqdn`: primitive-keyword completion candidates,
  per G4.

## Test plan

1. G1: overriding a group-wire-typed field still round-trips
   losslessly (spec 0122's original motivating bug) — with header
   patching removed entirely, not just fixed.
2. G1: overriding a message-wire-typed (`WT_LEN`) field produces an
   identical rendered header to today's (already-correct) case.
3. G1: overriding a group-wire-typed field's *interior* correctly
   resolves the nested schema (Background's "second subtlety") — not
   just the header framing.
4. G1: overriding via any element of a multi-element packed-repeated
   field replaces *every* element's rendered line with the new
   target's rendering (string/bytes/message), not just the clicked
   element's own line.
5. G1: `:type-as group` (or any group target) on a packed-repeated
   field is rejected — a packed record is never `WT_START_GROUP`.
6. G1 (sibling merge): the result is identical regardless of *which*
   element of the packed run the override was invoked on (first,
   middle, or last) — one merged node at the run's original position.
7. G1 (sibling merge): a packed field that is neither its parent's
   first nor last field still collapses correctly — the preceding
   sibling's `next_sibling`, the merged node's own `next_sibling`, and
   the following sibling's `prev_sibling` all end up consistent (no
   dangling/duplicated pointers), and both that preceding and
   following sibling remain independently navigable/foldable
   afterwards.
8. G1 (sibling merge): a packed field that *is* its parent's last
   field collapses correctly, with `parent.last_child` repointed to
   the merged node.
9. G2: renaming a field's display override name twice in a row does
   not grow the descriptor pool by more than one new descriptor total
   (registered once, reused thereafter).
10. G2: two different `(field_number, target)` overrides never collide
    on the same synthetic name; the same `(field_number, target)`
    requested twice (e.g. two nodes overridden to the same target)
    reuses one descriptor.
11. G2: the rendered header shows the current display name (default:
    parent schema field name / field number; overridden: the custom
    name), in both the "just applied" and "renamed after the fact"
    cases.
12. G3: `can_override` now accepts `WT_VARINT`/`WT_I32`/`WT_I64` nodes
    in addition to `is_message`/`WT_LEN`.
13. G4: `:type-as sint32` on a `WT_VARINT` node succeeds and renders a
    zigzag-decoded value; `:type-as float` on the same node fails with
    a clear message-line error (wire-type mismatch).
14. G4: `:type-as-raw` (target `None`) is unaffected — still falls
    back to schema-less rendering, unchanged by this spec.
15. G4: `:type-as int32` (or any primitive keyword) on a group-framed
    (`WT_START_GROUP`) node is rejected — only a message/group FQDN
    target is valid for it; tab-completion offers no primitive
    keywords for such a node either.
16. Existing spec 0114/0118/0119/0120/0122/0134 override tests
    (message-target overrides, `field_name_for`, Any/MessageSet
    auto-expansion, header round-tripping) still pass unchanged where
    not directly superseded by G1/G2 above.
17. `reuse lint` passes.
