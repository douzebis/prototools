<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0143 — protolens: robustly locate the synthetic field-name placeholder

Status: implemented
Implemented in: 2026-07-18
Refs: docs/specs/0135-protolens-override-raw-tag-rewrap.md (`register_
      wrapper`'s `"_"` placeholder, G2's post-render substring-
      replacement design), docs/specs/0114-protolens-range-type-
      override.md (§1.1, the root wrapper's own placeholder patch in
      `decode()`), 2026-07-18 feedback (`TYPEtype_idMISMATCH` corrupted
      annotation, reported live during spec 0142's status-line fix)
App: protolens

## Background

`register_wrapper` (`decode.rs`) builds a synthetic one-field message
descriptor to wrap a node's raw bytes when `splice_override` (or the
top-level `decode()`, for the document root) applies a type override.
The synthetic field's own name is always the fixed placeholder literal
`"_"` — never the real display name — so the same cached descriptor
can be reused regardless of which node/field name a given call site
is patching in (spec 0135 G2's own doc comment: "so it's no longer
part of the descriptor's identity").

After rendering, both call sites patch the real field name back into
the rendered header line with a naive substring replacement:

```rust
new_lines[0] = new_lines[0].replacen('_', &field_name, 1);   // override_apply.rs
lines[0] = lines[0].replacen('_', "1", 1);                    // decode.rs
```

`replacen('_', ..., 1)` replaces the **first underscore character
anywhere in the line** — not specifically the placeholder token. This
happens to work whenever the placeholder is genuinely the first `_` on
the line, but nothing about the code establishes that; it worked "by
chance" for every override applied so far only because none of them
had rendered a `TYPE_MISMATCH` annotation before the placeholder was
supposed to appear.

### How the bug actually manifests

`prototext-core`'s two header-prefix writers, `wfl_prefix_n` (a plain
`name: value` line) and `wob_prefix_n` (a `name {` nested-message
header line), share one documented contract: they write the schema
field's own name **only when the render resolved to a known,
non-mismatched field**; on any wire-type mismatch (declared schema
kind incompatible with the value's actual on-wire framing — varint
vs. a non-varint-compatible kind, `LEN` vs. a non-`Bytes` kind, etc.)
they write the **numeric field key** instead, and the annotation
carries a `TYPE_MISMATCH` flag with no field declaration at all. So on
a mismatched render, the placeholder `"_"` is never written anywhere
on the line — but `TYPE_MISMATCH` itself contains an underscore.
`replacen('_', ..., 1)` finds *that* underscore instead and splices
the real field name into the middle of the literal `TYPE_MISMATCH`
token, e.g.:

```
2: 525005305  #@ varint; TYPE_MISMATCH
```

becomes

```
2: 525005305  #@ varint; TYPEtype_idMISMATCH
```

(reported live: overriding a varint-wire field to an incompatible
primitive type such as `double`/`string` reliably reproduces this.)

This is a correctness bug, not just a display glitch: once corrupted,
`TYPE_MISMATCH` is no longer a recognizable annotation token at all —
`prototext`'s own annotation parser (`encode_annotation.rs`) would
silently fail to recognize it as the `TYPE_MISMATCH` flag it's
supposed to be on any subsequent re-encode of the extracted text.

`decode.rs`'s own call site (`decode()`'s root-wrapper patch) happens
to never hit this, because it always registers the wrapper with
`Type::Message` — and `wob_prefix_n`'s `is_wire_or_mismatch` argument
is unconditionally `false` whenever the schema is known (`begin_nested`
passes `!is_known`, and the synthetic wrapper's field schema is always
`Some`), so a `Message`-typed placeholder is always written
unconditionally, mismatch or not. But this call site relies on that
same naive `replacen` mechanism too, exercising it correctly purely by
happening to only ever be called in the one shape that can't mismatch
— exactly the "works by chance" pattern this spec eliminates, applied
uniformly rather than left as an untested assumption.

## Goals

- G1: a single shared, robust placeholder-patch helper that locates
  the placeholder by its exact structural position — anchored
  immediately after the line's leading indentation — rather than by
  searching the line's contents for a bare `_` character anywhere.
  Precisely mirrors `wfl_prefix_n`/`wob_prefix_n`'s own documented
  contract: the placeholder, when present at all, is always the very
  first token on the line, immediately followed by either `": "`
  (scalar/value line) or `" {"` (nested-message header line).
- G2: when the anchored check does not find the placeholder in that
  exact position (i.e. the render fell into a wire-type-mismatch or
  unknown-field fallback and never wrote it), the line is returned
  **unchanged** — no replacement of any kind, correct or otherwise.
  This is the actual bug fix: previously the code always attempted a
  replacement and, absent a real placeholder, corrupted whatever
  underscore it found instead.
- G3: both existing call sites (`override_apply.rs`'s `splice_override`
  and `decode.rs`'s `decode()`) switch to the shared helper, so the
  fix and its invariant apply uniformly rather than being re-derived
  (or silently left unfixed) at each call site individually.

## Non-goals

- N1: no change to `register_wrapper`'s placeholder-name design itself
  (still the fixed literal `"_"`, still excluded from the descriptor's
  cache-key identity) — this spec only hardens how the placeholder is
  *located* in the rendered text afterward.
- N2: no change to `prototext-core`'s own annotation-writing code
  (`wfl_prefix_n`/`wob_prefix_n`/`begin_nested`/etc.) — their existing
  behavior is exactly what this spec's detection logic is designed to
  match precisely; nothing about them is wrong.
- N3: no attempt to make `TYPE_MISMATCH`-style renders show a field
  name at all — a mismatched field legitimately has no field
  declaration to show a name on (there is no "slot" to patch); the
  fix is to leave such lines alone, not to invent a display for them.

## Specification

### `decode.rs`

New function, placed directly after `register_wrapper` (the function
whose placeholder convention it exists to consume):

```rust
/// Patch `register_wrapper`'s synthetic placeholder field name (the
/// fixed literal `"_"`, spec 0135 G2) into `line`, if — and only if —
/// the render actually wrote that placeholder there.
/// `wfl_prefix_n`/`wob_prefix_n` (prototext-core) write the schema
/// field's own name only when the render resolved to a known,
/// non-mismatched field; on any wire-type mismatch they write the
/// numeric field key instead, and no placeholder is emitted anywhere
/// on the line. Detected precisely by anchoring on the exact two
/// prefix shapes both writers document — `"_: "` (scalar/value line)
/// or `"_ {"` (nested-message header line) — immediately after the
/// line's leading indentation, rather than searching the line for a
/// bare `_` character: the naive `.replacen('_', ..)` approach
/// previously matched the `_` inside an unrelated `TYPE_MISMATCH`
/// annotation on a mismatched line, corrupting it (2026-07-18
/// feedback). Returns `None` (caller keeps the original line
/// untouched) when no placeholder was actually written.
pub(crate) fn patch_synthetic_field_name(line: &str, field_name: &str) -> Option<String> {
    let indent_len = line.len() - line.trim_start().len();
    let (indent, rest) = line.split_at(indent_len);
    let after = rest.strip_prefix('_')?;
    if after.starts_with(": ") || after.starts_with(" {") {
        Some(format!("{indent}{field_name}{after}"))
    } else {
        None
    }
}
```

`decode()`'s root-wrapper patch becomes:

```rust
if wrapper_desc.is_some() {
    if let Some(patched) = patch_synthetic_field_name(&lines[0], "1") {
        lines[0] = patched;
        style_hints[0] =
            colorize::hints_by_line(&lines[..1], &colorize::colorize(&lines[0])).remove(0);
    }
}
```

### `override_apply.rs`

`splice_override`'s placeholder patch becomes:

```rust
if matches!(field_type, Some(ft) if ft != Type::Group) {
    if let Some(patched) = decode::patch_synthetic_field_name(&new_lines[0], &field_name) {
        new_lines[0] = patched;
        new_line_styles[0] =
            colorize::hints_by_line(&new_lines[..1], &colorize::colorize(&new_lines[0]))
                .remove(0);
    }
}
```

## Test plan

1. `patch_synthetic_field_name` unit tests (`decode.rs`):
   - `"_: 5"` with `field_name = "id"` → `Some("id: 5")`.
   - `"_ {"` with `field_name = "inner"` → `Some("inner {")`.
   - Indentation is preserved: `"    _: 5"` → `Some("    id: 5")`.
   - A wire-type-mismatch line with no placeholder, e.g.
     `"2: 525005305  #@ varint; TYPE_MISMATCH"` → `None`, line
     untouched — the exact regression case.
   - A line with no leading `_` at all (e.g. a plain numeric-keyed
     unknown field) → `None`.
2. `splice_override` regression test (`protolens/src/tui/tests/
   override_apply.rs`): override a field whose actual wire framing is
   incompatible with the target primitive type (e.g. a varint-framed
   field overridden to `double` or `string`) and assert the resulting
   line contains an intact, unmangled `TYPE_MISMATCH` token — not a
   corrupted variant with the field name spliced into it.
3. Existing message-override tests (already covered elsewhere, e.g.
   `splice_override_on_an_incompatible_scalar_does_not_panic`,
   `message_set_group_items_auto_expand_through_render_overrides`)
   continue to pass, confirming the placeholder is still correctly
   replaced on the successful (non-mismatched) path.
4. `cargo fmt --check`, `cargo clippy --all-targets`, full test suite
   pass.
