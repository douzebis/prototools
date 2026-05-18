<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0071 — Suppress `#@ prototext:` header when annotations are off

**Status:** implemented
**Implemented in:** 2026-05-18
**App:** prototext

---

## Purpose

`prototext decode` currently always emits a `#@ prototext: protoc` header line,
regardless of whether `-a` / `--annotations` is set.  Without annotations the
header is useless: `prototext encode` requires per-field wire-type annotations
to reconstruct the binary, so unannotated output cannot be round-tripped
regardless of whether the header is present.  The header clutters otherwise
clean human-readable output and misleads readers into thinking encode is
possible.

---

## Goals

1. When `annotations = false`, `decode_and_render` omits the
   `#@ prototext: protoc\n` header line entirely.
2. When `annotations = true`, behaviour is unchanged.
3. `prototext encode` already rejects input without the header (exit 1) —
   no change needed there.

---

## Non-goals

- Changing the encode path.
- Changing any other annotation behaviour.

---

## Specification

In `prototext-core/src/serialize/render_text/mod.rs`, the `decode_and_render`
function unconditionally writes the header before the field lines.  Gate it on
the `annotations` parameter:

```rust
if annotations {
    out.extend_from_slice(b"#@ prototext: protoc\n");
}
```

No other production code needs to change: `is_prototext_text()` (used by the
encode path to detect already-rendered input) is unaffected, and all other
callers of `decode_and_render` already pass `annotations` correctly.

---

## Impact

- **`prototext-core/src/serialize/render_text/mod.rs`**: one-line change (gate
  header on `annotations`).
- **`prototext/tests/roundtrip.rs`**: despite its name, this file contains a
  broad range of render/decode unit tests, many of which use
  `include_annotations: false`.  Only those that assert on the header line
  itself need updating; tests asserting on field content are unaffected.
- **`docs/tutorial.md`**: the note in Section 6 ("Without `-a` …") can be
  simplified now that the header absence is consistent with encode not working.
- No impact on reproto, protoscan, or the encode path.

---

## Files changed

- `prototext-core/src/serialize/render_text/mod.rs`
- `prototext/tests/roundtrip.rs`
- `docs/tutorial.md`
- `docs/specs/0071-suppress-header-without-annotations.md` — this file
