<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0117 — protolens override collection

Status: implemented
Implemented in: 2026-07-13
Refs: docs/specs/0109-protolens-interactive-schema-inference.md,
      docs/specs/0114-protolens-range-type-override.md
App: protolens

## Background

Spec 0114 gave `protolens` a single active type override: selecting a
candidate type in the override selection pane (`t`) replaces whatever
override was previously active and re-renders the affected range. Its
Non-goals section explicitly deferred the fuller model:

> A set of overrides (multiple simultaneous, independently
> activate/deactivate/delete-able overrides) — spec 0109's fuller model;
> this slice supports exactly one active override, replaced wholesale
> each time a new one is applied. Explicitly deferred to a follow-up
> spec, per the discussion that produced this one.

Spec 0109 Goal 3 originally sketched two override scopes — "exact
position" and "field-number pool" (keyed by `(container_fqdn,
field_number)`) — but neither was implemented as a persistent,
independently-manageable collection.

This spec fulfills that deferral: `protolens` gains a genuine
**collection** of overrides, spanning three kinds/scopes, with a
management UI (navigate, toggle, delete) and YAML save/restore.

## Goals

- A persistent collection of overrides, each of one of three kinds
  (by decreasing priority):
  1. **`path`**: `path -> none | some(type)`.
  2. **`path-field`**: `(path, field number) -> none | some(type)`.
  3. **`fqdn-field`**: `(FQDN, field number) -> none | some(type)`.
- On startup, a single `path` override is seeded for the root (`/`)
  whenever a type was explicitly requested (`--type`) or inferred. If
  neither is available, no root override is seeded at all — the
  collection starts empty, and the root simply renders raw until the
  user adds an override.
- Overrides are sorted by kind (`path`, `path-field`, `fqdn-field`),
  then by origin (`path`'s own path string; `path-field`'s
  `path:field`; `fqdn-field`'s `fqdn:field`), then by type in
  lexicographic order (`none`/no-type sorts first, matching 0114 §3.1's
  pinned `<raw / no type>` entry precedent).
- At any time, an override may be active or inactive. At most one
  active override exists per origin (an origin being the `(kind,
  path)` / `(kind, path, field)` / `(kind, fqdn, field)` key, i.e.
  everything except the candidate type). Activating an override
  deactivates any other override sharing its origin.
- Override selection pane (`t`) gains a `z` key: rotates the pane's
  target kind among `path` / `path-field` / `fqdn-field`. `Enter`
  then creates (or reactivates, if it already exists — see below)
  an override of the currently-selected kind, and activates it:
  - `path`: unchanged from 0114 §5 — origin is the cursor node's
    own `positional_path`.
  - `path-field`: origin is `(parent's positional_path, cursor
    node's field_number)`. Errors (command/message-pane error, no
    override created) if the cursor node is the wrapper root (no
    parent).
  - `fqdn-field`: origin is `(parent's type_fqdn, cursor node's
    field_number)`. Errors if the cursor node is the wrapper root,
    or if the parent's `type_fqdn` is `None` (unresolved type).
  - If an override with the resulting origin and selected candidate
    type already exists in the collection, it is not duplicated —
    it is simply activated (deactivating whatever else shared its
    origin, per the invariant above).
- New override management pane, opened with `o`, in the same
  right-hand split slot as the override selection pane (0114 §2):
  - Opening `o` closes `t` if open, and vice versa — the two panes
    are mutually exclusive, sharing one UI slot.
  - Same minimum-terminal-width gate as `t` (0114 §2). Unlike `t`,
    `o` has no cursor-node-kind requirement — it lists the whole
    collection regardless of what's under the cursor, so it is
    always available (width permitting).
  - Lists all overrides in the sort order above. Navigation keys
    mirror the override selection pane (0114 §3.2/§4): up/down/
    PageUp/PageDown/Home/End, `/` forward search, `?` backward
    search, `n` repeat (empty pattern reuses the last active
    pattern, matching 0114 §4's conventions).
  - `a`: toggles the cursor-targeted override between active and
    inactive. Activating deactivates any other override with the
    same origin (the collection-wide invariant).
  - `Delete` / `Backspace`: removes the cursor-targeted override
    from the collection.
- Save/restore, from the management pane:
  - `s` pre-fills the command line with `:save-overrides <default
    path>`, following the same UX precedent as the `x` key's
    `extract <default path>` pre-fill (`tui.rs`
    `default_extract_path`). Default filename extension is
    `.yaml`.
  - `r` pre-fills `:restore-overrides ` (no default path).
  - Both commands register in the shared `:`-command dispatcher
    (0114 §7), getting prefix-abbreviation matching for free
    (`:save-o`, `:restore-o`, etc., as long as unambiguous).
  - Both commands' path argument gets Tab / Tab-Tab completion from
    a new filesystem-path completion widget (see §4).
  - `:save-overrides <path>` writes the entire collection (active
    and inactive entries) to `<path>` in the YAML format defined in
    §4, overwriting unconditionally if the file exists (matching
    `extract.rs`'s existing `std::fs::write` precedent — no
    overwrite confirmation elsewhere in `protolens`).
  - `:restore-overrides <path>` reads `<path>`, replaces the
    in-memory collection wholesale. If the file's recorded blob or
    descriptor-set hash doesn't match the currently-loaded blob/
    descriptor-set, a warning is shown in the command/message pane,
    but the restore proceeds anyway (best-effort). Entries whose
    origin doesn't resolve against the current tree/pool (bad path,
    unknown FQDN) are silently dropped — no per-entry warning.

## Non-goals

- Wiring the override *collection* into rendering/decoding, for any
  kind. 0114 §5's existing `path`-kind splice-render (`Enter`
  triggers `apply_override`, a one-shot mutation of the target
  node's `type_fqdn` plus a line splice) is unchanged and keeps
  firing exactly as it does today — this spec merely adds collection
  bookkeeping alongside that existing call, on `Enter` only. Nothing
  in the management pane (`a`, `Delete`, `:restore-overrides`) feeds
  back into `apply_override` or `type_fqdn` — toggling an entry's
  `active` flag, deleting an entry, or restoring a collection changes
  only what's tracked in `OverrideCollection`; the rendered tree is
  untouched until the user re-applies something via `Enter` in the
  selection pane, same as they can today. How the collection (all
  three kinds, and management-pane actions) should eventually drive
  rendering is left entirely to a future spec.
- Undo/redo of collection edits.
- Wildcard, regex, or range-based origins beyond the three exact-key
  kinds defined above.
- Retrofitting the new filesystem-path completion widget onto
  `:extract`'s existing path argument (0114 Non-goals already
  excludes this; unchanged here).
- Any change to how `path`/`fqdn` strings are computed — both remain
  independent of rendering state and of the override collection's
  own contents (raw wire field-positions and dot-separated type
  names respectively), so staleness across override changes is not
  a concern this spec needs to address.

## Specification

### §1 Data model

```rust
enum OverrideKind {
    Path,
    PathField,
    FqdnField,
}

enum OverrideOrigin {
    Path { path: String },                      // e.g. "/1/2"
    PathField { path: String, field: u64 },      // e.g. "/1", 2
    FqdnField { fqdn: String, field: u64 },       // e.g. "pkg.Msg", 2
}

struct OverrideEntry {
    origin: OverrideOrigin,
    r#type: Option<String>,  // None = raw/no type
    active: bool,
}

struct OverrideCollection {
    entries: Vec<OverrideEntry>,
}
```

`path` fields use the canonical `positional_path` form (no trailing
slash), matching spec 0113 D25's internal representation — the
trailing slash seen in the user-facing origin display (e.g. `/1/`)
is a display-only decoration for message/group nodes, applied the
same way 0114 §3 already decorates its own listings.

On startup, `OverrideCollection` is seeded with one entry —
`OverrideOrigin::Path { path: "/" }`, `active: true`, `r#type` set to
the explicitly-requested (`--type`) or inferred root type — only when
such a type was actually resolved. If neither `--type` nor inference
resolved a root type, no entry is seeded at all and the collection
starts empty; the root then renders raw (falling back to
`natural_type`'s "no active override" behavior, same as any other
untyped node) until the user adds a real override.

Sort order (used for both the management pane's listing and the YAML
file's entry order): `OverrideKind` (`Path` < `PathField` <
`FqdnField`), then origin (path/fqdn string, then field number where
applicable), then `r#type` lexicographically with `None` sorting
first.

### §2 Selection pane kind-cycling and creation

The override selection pane (0114 §3) gains a kind indicator (e.g. in
its title/status line) and the `z` key, which rotates the pane's
target kind `Path -> PathField -> FqdnField -> Path -> ...`. The
candidate list itself (0114 §3.2/§6) is unaffected by this — it still
lists candidate types for the cursor node exactly as today.

`Enter`'s behavior is extended per-kind as described in Goals above.
On success, the created/reactivated override is inserted into (or
updated within) the collection — a distinct data structure from any
existing 0114 state (in particular, unrelated to
`active_override_range`, which is purely a candidate-cache lookup
key for the pane's `SortMode::Inferred` scoring, spec 0114 §6, not a
record of what's currently applied). For the `Path` kind only, this
insertion happens alongside 0114 §5's existing one-shot
`apply_override` call, which still fires exactly as before
(overwriting the target node's `type_fqdn` and splicing freshly
rendered lines, imperatively, at the moment `Enter` is pressed — 0114
has no persistent "applied override" registry of its own to unify
with). For `PathField`/`FqdnField`, only the collection is updated;
no rendering occurs (per Non-goals).

Error cases (`PathField`/`FqdnField` on the wrapper root, or
`FqdnField` when the parent has no resolved `type_fqdn`) are reported
in the command/message pane and create no override.

### §3 Management pane

Opened with `o` (closes `t` if open); same minimum-width gate as `t`
(0114 §2), no cursor-node-kind precondition.

Layout: same right-hand split slot as the override selection pane.
Each row shows kind, origin, type (or `<raw / no type>`, per 0114
§3.1's precedent), and an active/inactive indicator: a leading `*`
for the active entry per origin (mirroring git's `*` marker for the
current branch), blank otherwise.

Navigation: up/down/PageUp/PageDown/Home/End move the cursor. `/`
opens forward search, `?` opens backward search, `n` repeats the last
search (same conventions as 0114 §4).

`a`: toggle the cursor-targeted entry's `active` flag. If toggling to
active, every other entry sharing the same origin is deactivated.
This affects only the collection's bookkeeping — it has no rendering
effect for any kind, including `Path` (per Non-goals: there is no
mechanism, yet, by which management-pane actions feed back into
`apply_override`/`type_fqdn`; that live-sync wiring is deferred to
the future rendering-integration spec).

`Delete` / `Backspace`: remove the cursor-targeted entry from the
collection. Same scope note as `a` — no rendering effect.

### §4 Save / restore

`s` (from the management pane) pre-fills the command line with
`:save-overrides <default path>`, where `<default path>` is derived
the same way `default_extract_path()` derives its default (same
directory/stem as the target blob, `.yaml` extension). `r` pre-fills
`:restore-overrides ` with no default.

Both `:save-overrides <path>` and `:restore-overrides <path>` accept
a filesystem path argument with Tab / Tab-Tab completion from a new
completion widget: given the partial path typed so far, it lists
matching entries in the corresponding directory (via
`std::fs::read_dir`), completing the longest common prefix on Tab,
and cycling among matches on repeated Tab-Tab — the same interaction
model as spec 0114 D26's in-memory FQDN completer, but backed by real
directory reads per path segment instead of a static candidate list.

#### YAML format

```yaml
version: 1
target:
  blob_sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b85"
  descriptor_set_sha256: "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
overrides:
  - kind: path
    path: "/"
    type: pkg.RootMessage
    active: true
  - kind: path
    path: "/1"
    type: null
  - kind: path-field
    path: "/1"
    field: 2
    type: pkg.SubMessage
  - kind: fqdn-field
    fqdn: pkg.RootMessage
    field: 3
    type: pkg.OtherMessage
    active: true
```

- `target.blob_sha256` / `target.descriptor_set_sha256`: SHA-256
  hashes of the *canonicalized binary* bytes — the blob after
  `render_as_bytes` conversion (`main.rs`, transparently handles
  `#@ prototext`-format input) and the descriptor set after
  `DescriptorContext::load`'s equivalent normalization — not the raw
  on-disk file bytes. This makes the hash invariant to reformatting
  a `#@ prototext`-format source file without changing its semantics,
  and invariant to the file moving (paths are not stored at all). On
  restore, both are recomputed the same way from the
  currently-loaded blob/descriptor-set and compared; a mismatch on
  either produces a warning in the command/message pane but does not
  block the restore.
- `overrides`: entries in the §1 sort order, for diff-stable saves.
  Each entry's `kind` selects which of `path` / `path`+`field` /
  `fqdn`+`field` fields are present. `type: null` represents
  raw/no-type. `active` is present and `true` only for active
  entries — inactive is the default and the key is omitted
  entirely for inactive entries.
- On restore, entries whose origin doesn't resolve against the
  current tree/descriptor pool are silently dropped (no per-entry
  warning — only the two top-level hash-mismatch warnings surface).
- Restore replaces the collection wholesale with exactly what the
  file contains. If the file lacks a `path` entry for `/`, the
  restored collection simply has no root override — the startup
  auto-seeding (§1) applies only at process startup, never as a
  post-restore fixup.

### §5 Key bindings (additions)

| Key                  | Context                    | Action                                     |
|-----------------------|-----------------------------|---------------------------------------------|
| `o`                   | main pane                   | open override management pane (closes `t`)  |
| `z`                   | override selection pane     | rotate target kind (path/path-field/fqdn-field) |
| `a`                   | override management pane    | toggle cursor entry active/inactive          |
| `Delete` / `Backspace`| override management pane    | remove cursor entry from collection          |
| `s`                   | override management pane    | pre-fill `:save-overrides <default path>`    |
| `r`                   | override management pane    | pre-fill `:restore-overrides `               |
| `/`, `?`, `n`         | override management pane    | search forward/backward/repeat (0114 §4)     |
| `Tab`, `Tab Tab`      | `:save-overrides`/`:restore-overrides` argument | filesystem path completion / cycle |

Existing 0114 override selection pane bindings (navigation, `/?n`
search, sort-mode toggle, `Enter` to apply) are unchanged.

## Open Issues

None.

## Files changed (anticipated)

| File                              | Change                                                             |
|------------------------------------|----------------------------------------------------------------------|
| `protolens/src/override_pane.rs`   | `OverrideKind`/`OverrideOrigin`/`OverrideEntry`/`OverrideCollection`, sorting, YAML (de)serialization, hashing |
| `protolens/src/tui.rs`             | management pane state/rendering, `z`/`a`/`Delete`/`s`/`r`/`o` key handling, pane mutual exclusion, `:save-overrides`/`:restore-overrides` commands, filesystem-path completion widget |
| `protolens/Cargo.toml`             | add `serde`, `serde_norway`, `sha2` dependencies (`serde`/`sha2` already present transitively in `Cargo.lock`; `serde_norway` — a maintained hard-fork of the archived `serde_yaml`, fixing YAML 1.1's implicit-typing "Norway problem" — is new) |
