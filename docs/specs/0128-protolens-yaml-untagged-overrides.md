<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0128 — protolens: drop the redundant `kind` tag from the overrides YAML format

Status: implemented
Implemented in: 2026-07-15
Refs: docs/specs/0117-protolens-override-collection.md (`YamlEntry`, `to_yaml`/
      `from_yaml`, `#[serde(tag = "kind", ...)]`),
      protolens/todo.md (2026-07-15 feedback, item 8 — decisions this spec
      formalizes)
App: protolens

## Background

`YamlEntry` (override_pane.rs) is `#[serde(tag = "kind", rename_all =
"kebab-case")]` over three structurally disjoint variants: `Path` has
only `path`; `PathField` has `path`+`field`; `FqdnField` has
`fqdn`+`field` (no `path` key at all). Since the variants never share a
field set, `kind` carries no information serde couldn't already infer
from which fields are present — confirmed from the struct definitions,
not just plausible. `protolens` has no backward-compatibility
requirement yet (explicitly not a goal at this stage of the project), so
this is a straightforward, low-risk format simplification.

## Goals

- Switch `YamlEntry` from `#[serde(tag = "kind", rename_all =
  "kebab-case")]` to `#[serde(untagged)]` — each variant is now
  distinguished purely by which fields are present in the YAML mapping.
- Newly-written files (`to_yaml`) no longer emit a `kind:` line at all.
- Old files that still have a `kind: path`/etc. line no longer load —
  `untagged` needs `#[serde(deny_unknown_fields)]` on each variant to
  disambiguate correctly (see Specification: without it, a `PathField`
  mapping with a stray `field` key would silently match `Path` first
  instead of falling through, since `Path`'s fields are all present/
  optional), and that same `deny_unknown_fields` also rejects the now-
  unrecognized `kind` key. Confirmed acceptable — the project doesn't
  aim at backward compatibility yet.
- Malformed-YAML load failures get a clearer wrapper message instead of
  surfacing serde's raw `untagged`-enum error text (which is
  notoriously unhelpful — "data did not match any variant", no
  field-level detail): `from_yaml`'s parse-failure path wraps the
  original `serde_norway::Error` as `"malformed overrides file (expected
  a list of path/field/fqdn override entries): {inner}"`, keeping the
  original message available as `{inner}` for anyone who needs the
  detail.

## Non-goals

- No change to any other `YamlEntry` field (`path`/`field`/`fqdn`/
  `r#type`/`active`/`name`, or the new `auto` field from spec 0125) —
  purely the tagging mechanism.
- No migration tooling for old saved files (still have `kind:` keys) —
  they simply need to be re-saved via `:save-overrides` once, same as
  any other pre-this-spec file; not a concern given no backward-
  compatibility commitment exists yet.
- No change to the CLI-level wrapping (`main.rs`'s `"error:
  --load-overrides '<path>': {e}"`) — the existing
  `extract_load_overrides_malformed_yaml_is_a_hard_error` test only
  asserts the stderr contains `--load-overrides`, which this spec's
  message change doesn't affect.

## Specification

### `override_pane.rs`

- `YamlEntry`: replace `#[serde(tag = "kind", rename_all =
  "kebab-case")]` with `#[serde(untagged)]`, and change each of its
  three variants from an inline struct-variant to a newtype variant
  wrapping its own named struct (`YamlPathEntry`/`YamlPathFieldEntry`/
  `YamlFqdnFieldEntry`), each carrying `#[serde(deny_unknown_fields)]` —
  required because `deny_unknown_fields` isn't a valid enum-variant
  attribute directly, only a container (struct/enum) one, and it's
  required for correct disambiguation (see Background). A newtype
  variant over an `untagged` enum is transparent on the wire, so the
  YAML shape is unaffected. Variant declaration order still matters
  (`Path` before `PathField` before `FqdnField`) even with
  `deny_unknown_fields`, for the same "try `Path` first" reasoning.
- `from_yaml`: on `serde_norway::from_str` failure, wrap the error as
  `format!("malformed overrides file (expected a list of path/field/
  fqdn override entries): {e}")`. Changed `from_yaml`'s signature from
  `Result<_, serde_norway::Error>` to `Result<_, String>` accordingly;
  its one caller (`tui.rs`'s `load_overrides`) already converted the
  error to `String` via `.map_err(|e| e.to_string())`, so this is a
  simplification there, not a new conversion.

## Test plan

1. `to_yaml` output for a collection with all three origin kinds no
   longer contains any `kind:` line.
2. `from_yaml` of a freshly-`to_yaml`'d file (no `kind` key) round-trips
   correctly for all three kinds.
3. `from_yaml` of an old-format file (still has `kind: path`/`kind:
   path-field`/`kind: fqdn-field` lines) now fails with the new wrapped
   error message (regression coverage for the intentional break — the
   two existing hand-authored-fixture tests that used `kind:` were
   updated to drop it).
4. `from_yaml` of genuinely malformed YAML produces the new wrapped
   message text (asserting the message contains "malformed overrides
   file", not asserting on serde's inner text verbatim).
5. `extract_load_overrides_malformed_yaml_is_a_hard_error` (existing
   test) still passes unchanged.
6. `reuse lint` passes.
