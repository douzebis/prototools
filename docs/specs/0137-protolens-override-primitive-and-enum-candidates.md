<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0137 — protolens: primitive/enum candidates in the override selection pane

Status: implemented
Implemented in: 2026-07-17
Refs: docs/specs/0114-protolens-range-type-override.md (override pane
      §2/§3, pinned `<raw / no type>` row, now retired — see G4),
      docs/specs/0117-protolens-override-collection.md
      (`OverrideEntry`), docs/specs/0135-protolens-override-raw-tag-
      rewrap.md (primitive-type overrides, `natural_type` exclusion of
      `Enum`), docs/specs/0136-protolens-status-line-type-display.md
      (leading-dot collision-avoidance convention, reused verbatim
      here)
App: protolens

## Background

The override selection pane's "alphabetic" (lexicographic) candidate
list (`override_pane::all_type_fqdns`) currently lists only
message/group FQDNs (`pool.all_messages()`). Primitive types can only
be reached via the `:type-as <keyword>` command line (spec 0135), not
from the pane's own candidate list, and enum types cannot be selected
as an override target at all — `splice_override`'s target-resolution
match tries a message lookup, then a primitive-keyword lookup, and
errors if neither matches (no enum arm exists). This is purely a gap
in override target-*resolution*, not in rendering: `decode_and_
render_indexed`/`prototext-core`'s enum-symbol formatting already
renders schema-declared enum fields correctly today, whenever a
field's own declared `Kind` is `Enum` and no override is involved.
What's missing is the override-splicing wiring that lets a user
*explicitly pick* an enum FQDN and have `splice_override` build a
synthetic wrapper field of `Type::Enum` for it — the same mechanism
that already exists for message and primitive targets, just missing
the third arm.

The user wants the pane's alphabetic mode to expose *every* selectable
type — primitives, a special always-available `Empty` (raw) entry, and
enums — alongside messages/groups, sorted and grouped, with distinct
styling per kind.

## Goals

- G1: the override pane's alphabetic-mode candidate list additionally
  includes the 15 primitive-type keywords (spec 0135 §G4's list),
  sorted lexicographically, appearing before the non-primitive
  (message/group/enum) entries. `Empty` is prepended before that
  sorted block, in a fixed (not re-sorted) first position — displayed
  bare as `Empty`, whose uppercase `E` would sort before every
  lowercase primitive keyword anyway did it participate in the sort
  (it doesn't need to: see G4/Specification for why its *stored*
  string differs from its *displayed* one).
- G2: the non-primitive part of the alphabetic-mode list additionally
  includes enum FQDNs (`pool.all_enums()`), mixed with message/group
  FQDNs in one combined, lexicographically-sorted list — retrieved
  once from the descriptor set at startup, same lifetime/caching
  convention `all_type_fqdns` already has (§6: "needs no per-range
  caching").
- G3: **enum override application is real, working functionality, not
  just a list entry** — selecting an enum FQDN and confirming
  (`Enter`, or `:type-as <enum-fqdn>`) must actually splice a working
  override: `splice_override` gains a third resolution arm
  (`pool.get_enum_by_name`), and `register_wrapper` (or a parallel
  enum-specific helper) is generalized to build a synthetic wrapper
  field of `Type::Enum` with the right `type_name`/dependency — using
  the exact same rendering path (`decode_and_render_indexed`,
  `prototext-core`'s existing enum-symbol formatting) that already
  renders schema-declared enum fields today.
- G4: the pane's pinned row 0 (today's hardcoded `<raw / no type>`,
  present unconditionally in both sort modes) is **fully retired, not
  replaced 1:1**: `Empty` is *not* a substitute pinned row. Instead,
  `override_candidates` becomes every mode's sole source of rows —
  direct 0-based indexing, no special-cased offset row anywhere:
  - Alphabetic mode: `Empty` is a genuine element of
    `override_candidates`, always prepended first (G1), so it lands at
    row 0 there, styled per G8, without any pane-mechanics special
    case (only its stored-vs-displayed string differs — Specification).
  - Inferred mode: `Empty`/primitives are never added (G7, unchanged)
    — row 0 there is simply whatever `inferred_candidates` itself
    ranks first (a message/group, exactly as today's row *1* used to
    show). **There is no raw/`Empty` option reachable from the pane in
    inferred mode at all** — reaching raw there requires either
    switching to alphabetic mode or `:type-as Empty` (G5) from the
    command line.
  Selecting `Empty` (alphabetic mode) and confirming renders
  **exactly** like today's pinned row (`splice_override`'s existing
  `target: None` raw path) — the bare scalar/hex view, not a decoded
  — even if empty — message. Displayed bare as `Empty` (no leading dot
  — G6).
- G5: `Empty` is also reachable via `:type-as Empty` (bare token,
  command-line) — a second, independent route to the same reserved
  sentinel string `"protolens_internal.Empty"` (a namespace already
  reserved for synthetic types, per `register_wrapper`'s
  `protolens_internal.x<hex>` and `register_message_set_item`'s
  `protolens_internal.Item` — no real collision risk with any user
  schema), recognized directly in `splice_override`'s resolution match
  and translated straight to `(None, None)` — **no descriptor is ever
  registered for it**. With the pinned row fully retired (G4), the
  pane's own `Empty` selection now reads `override_candidates[0]`
  directly, like any other row, so it stores the *same*
  `OverrideEntry.r#type` value as `:type-as Empty` —
  `Some("protolens_internal.Empty")` — rather than a separate `None`
  path; `:type-as-raw` remains the one command-line route that stores
  plain `None` instead (spec 0114 §5, unaffected by this spec).
- G6: leading-dot collision-avoidance for FQDN display in the pane's
  list reuses spec 0136's exact rule: a message/group/enum FQDN is
  prefixed with `.` only when its bare form would otherwise collide
  with a primitive keyword (the 15 real keywords, or `Empty`) —
  otherwise no dot. (Today's list shows bare FQDNs unconditionally,
  since it never mixed in primitive-like names before now.)
- G7: `Empty` and the 15 primitive keywords are proposed **only** in
  alphabetic mode, never in inferred mode — inferred mode's
  `score_all` only ever ranks message/group candidates (Background),
  so this falls out naturally with no special-casing: none of them are
  added to `inferred_candidates`'s own list, only to the alphabetic
  one (G4: no exception for `Empty` — it is absent from the pane
  entirely in inferred mode).
- G8: candidate-row styling (rows 1.. in alphabetic mode; inferred-
  mode rows 1.. are always messages/groups, so they render the same
  as before — no visible change there; row 0 is covered separately,
  also below):
  - `Empty` (row 0, every sort mode) → `theme::style_for(SyntaxRole::
    Comment, theme)` — same reuse precedent as `manage_entry_style`'s
    `auto` color.
  - A primitive keyword → `theme::style_for(SyntaxRole::
    PunctuationBracketExtension, theme)` — a warm red/coral RGB
    ("Alexa" `#D16969` dark, "Dried Burgundy" `#811F3F` light), with a
    genuinely red ANSI-16 fallback (`Color::LightRed` dark,
    `Color::Red` light) — corrects the originally-drafted
    `StringLiteral`, whose ANSI-16 fallback was green, not red.
  - A message/group FQDN → unstyled (`Style::default()`, matching
    today's unstyled rendering).
  - An enum FQDN → `theme::style_for(SyntaxRole::Attribute, theme)`.
  - The existing highlighted-row `Modifier::REVERSED` overlay applies
    on top of whichever of the above, exactly as today — including row
    0, which today has no color at all (a new, additive style there).

## Non-goals

- No change to inferred-mode's own candidate computation
  (`inferred_candidates`/`score_all`) — G7.
- No change to `OverrideEntry.r#type`'s `Option<String>` shape (spec
  0117) — both the pane's `Empty` selection and `:type-as Empty` store
  `Some("protolens_internal.Empty")` (G5); `:type-as-raw` remains the
  separate route that stores plain `None`. All fit the existing type
  without any schema/persistence-format change.
- No wire-compatibility filtering of the primitive-keyword block in
  the pane — unfiltered, all 15 keywords always shown, differing from
  `:type-as`'s own tab-completion (which already filters — spec 0135
  §G4, unchanged by this spec). An incompatible selection is not
  rejected by `splice_override` either — it decodes the field's raw
  bytes against the mismatched synthetic wrapper exactly as
  `TextSink` already handles any other malformed/mismatched decode,
  expected to surface as an existing "invalid"-style annotation
  (spec 0133), not a hard error or pane-level rejection — to be
  confirmed during implementation testing (Test plan item 11), not a
  new mechanism to build.
- No change to `natural_type`'s own behavior (still excludes `Enum` —
  spec 0135's Non-goals, spec 0136's Non-goals) — that function
  remains specific to the auto/fallback splicing path; this spec's
  enum support is entirely about *explicit* user selection (pane or
  `:type-as`), a different code path (`splice_override`'s target
  resolution).

## Specification

### New/extended primitive-keyword list (`decode.rs`)

Add `pub(crate) const ALL_PRIMITIVE_KEYWORDS: &[&str]`, the same 15
keywords `primitive_type_for_keyword` already recognizes, alphabetically
pre-sorted, documented as needing to stay in sync with that function's
match arms (the same duplication precedent `primitive_keywords_for_wire_type`
already accepts).

### `Empty` resolution (`override_apply.rs`'s `splice_override`)

Add a resolution arm checked before the message/primitive lookups:

```
Some(name) if name == "protolens_internal.Empty" => (None, None),
```

### Enum resolution (`override_apply.rs`'s `splice_override`)

Add a third arm after the existing message/primitive checks:

```
else if let Some(enum_desc) = self.ctx.pool().get_enum_by_name(name) {
    (None, Some(Type::Enum))  // needs enum_desc's type_name/dependency
                                // threaded into register_wrapper — see G3
}
```

`register_wrapper`'s signature is generalized (exact shape TBD at
implementation time) so its `type_name`/`dependency` derivation works
for an `EnumDescriptor` as well as a `MessageDescriptor`.

### Combined alphabetic-mode list (`override_pane.rs`)

`all_type_fqdns` is extended to `pool.all_messages().chain(pool.all_enums())`,
still `sort_unstable`'d as one combined list — used, as today, by both
the override pane's lexicographic mode and `:type-as` tab-completion
(G2's "retrieved once," consistent with the existing session-global
caching).

### Pane candidate assembly (`override_select.rs`'s
`recompute_override_candidates`, `SortMode::Lexicographic` arm)

Prepends `["protolens_internal.Empty", ...ALL_PRIMITIVE_KEYWORDS]` (in
that fixed order — the sentinel string first, per G1) before the
existing `all_type_fqdns`-derived rows — still a plain
`Vec<(String, None)>` (no score column for any of these rows, same as
today's message/group alphabetic rows). The stored string is the
sentinel, not the bare `"Empty"` display label (see "Row styling"
below) — this avoids an ambiguous duplicate entry if a real,
packageless message happens to be named `Empty` (G6's collision case:
that real message would independently appear, later in the sorted
non-primitive block, displayed as `.Empty` per the dot-prefix rule).
`SortMode::Inferred`'s own arm is untouched (G7).

### Retiring the pinned row (`override_select.rs` / `render.rs`)

The separate, always-present "row 0" concept is removed entirely —
`override_candidates[row]` becomes the direct, sole source for every
row, in both sort modes (no more `row - 1` offset, no more
hardcoded pinned entry):

- `move_override_highlight`'s clamp changes from `0..=
  override_candidates.len()` (the old `len() + 1` positions, to
  account for the separate pinned row) to `0..override_candidates.
  len()` (plain, direct indexing) — in both modes.
- `preview_override_highlight` drops its `override_highlight == 0 =>
  tentative = None` special case entirely; it resolves
  `override_candidates[override_highlight]` unconditionally (in
  alphabetic mode, index `0` naturally holds `("Empty".to_string(),
  None)`, resolving to the raw preview exactly as before, but via the
  ordinary candidate path, not a pane-side special case).
- `jump_to_override_match` drops its "skip row 0" exclusion; it
  searches `override_candidates` directly, with no offset.
- The initial-highlight default on opening the pane (currently
  `usize::from(!override_candidates.is_empty())`, which skips past the
  old pinned row 0 when real candidates exist) becomes plain `0`
  (first candidate, if any) in both modes — in alphabetic mode this is
  always `Empty`; in inferred mode it's `inferred_candidates`'s
  top-ranked message, exactly as row *1* used to show. An empty
  `override_candidates` (possible only in inferred mode, when nothing
  scores) leaves no valid highlight, matching existing empty-list
  handling elsewhere in this module.

### Row styling + dot-prefixing (`render.rs`'s `render_override_pane`)

No more row-0 special case: every row is `override_candidates[row]`.
Classify the stored string (`"protolens_internal.Empty"` exact match,
else `ALL_PRIMITIVE_KEYWORDS` membership, else `pool.get_enum_by_name`,
else assumed message/group) to pick G8's style and G6's dot-prefix.
The sentinel is the one row whose *displayed* text differs from its
stored string: rendered bare as `"Empty"`, not
`"protolens_internal.Empty"` — analogous to, but simpler than, G6's
dot-prefix rewrite (a fixed substitution, not a conditional one).
`jump_to_override_match`'s substring search still matches it under a
`/Empty` query unaffected, since `"protolens_internal.Empty"`
lowercased still contains `"empty"`.

## Test plan

1. Override pane on any override-eligible node, alphabetic mode: index
   `0` shows `Empty` (`Comment`-styled); indices `1..16` show the 15
   primitive keywords alphabetically (`PunctuationBracketExtension`-
   styled); the rest show messages/enums mixed alphabetically
   (message/group unstyled, enum `Attribute`-styled).
2. Selecting a primitive keyword and confirming applies it exactly as
   `:type-as <keyword>` already does today (spec 0135) — no behavior
   change to primitive application itself, only to how it's reached.
3. Selecting `Empty` (alphabetic mode, index `0`) and confirming
   renders identically to today's pinned `<raw / no type>` row on the
   same node — bare scalar/hex raw view.
4. `:type-as Empty` (command line) applies the same raw rendering as
   the pane's `Empty` selection.
5. Selecting an enum FQDN and confirming renders the field using the
   enum's symbolic value names (same formatting schema-declared enum
   fields already get) — a new, previously-impossible capability.
6. `:type-as <enum-fqdn>` (command line, tab-completable) applies the
   same enum override.
7. Row coloring in the pane matches G8 for each of the four kinds;
   highlighted-row reverse-video still applies on top.
8. A message/group/enum FQDN whose bare name collides with a primitive
   keyword or `Empty` displays with a leading dot in the pane list
   (mirroring spec 0136's status-line rule); non-colliding names show
   no dot, exactly as today.
9. Inferred mode's candidate list is visually unchanged (still
   message/group-only, still shows scores, no primitive rows and no
   `Empty` row ever appear there) — opening the pane on inferred mode
   highlights the top-ranked message/group directly, with no raw
   option reachable at all short of switching to alphabetic mode or
   using `:type-as Empty`.
10. `j`/`k`/`Home`/`End`/search-jump all operate on `override_candidates`
    directly with no pinned-row special case, in both sort modes —
    clamped to `0..=override_candidates.len() - 1`, wrapping and
    matching every row including `Empty` and the primitives.
11. Selecting a primitive incompatible with the cursor node's current
    wire type: `splice_override` does not reject it; the field
    re-decodes against the mismatched synthetic wrapper and surfaces
    `prototext-core`'s existing invalid/mismatch annotation, same as
    any other malformed decode — no hard error, no pane-level
    rejection.
12. `cargo fmt --check`, `reuse lint`, full test suite pass.
