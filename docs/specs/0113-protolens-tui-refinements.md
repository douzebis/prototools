<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0113 — `protolens` TUI refinements (living record)

**Status:** living / in progress
**Refs:** `docs/specs/0111-protolens-v1-decode-navigate-extract.md`,
`docs/specs/0114-protolens-range-type-override.md`
**App:** protolens

---

## Background

Spec 0111 defines `protolens` v1's committed scope (decode/navigate/extract)
and its Annex B/C key-binding and layout *proposal*. As v1 gets exercised
interactively, small UX/behavioral decisions accumulate faster than they'd
naturally fit as edits to 0111's Annexes without losing the thread of *why*
each one was made. This spec is a **living record** of those decisions: each
entry below is a concrete point raised during interactive testing, the
decision made, and (where relevant) the implementation note. It is expected
to keep growing as testing continues — new entries are appended, not
squeezed retroactively into 0111.

This spec does not restate or supersede 0111's committed Goals/Specification;
it only refines *how* v1 behaves within that scope, or corrects points where
implementation revealed 0111's assumptions were wrong.

### How this spec is organized

- **Index** (below): every entry as a GFM task-list checkbox (`[x]`
  implemented, `[ ]` deferred or open), grouped by category for quick
  scanning. Each line links to its full entry in "Decisions."
- **Decisions**: full entries, in stable `D<n>` order (`n` is assigned once,
  at creation, and never reused/renumbered — safe to reference `D7` from a
  commit message or another doc). Each entry carries an explicit
  `**Status:**` line: `Implemented`, `Deferred` (future phase, not
  actionable yet), or `Open` (decision not yet made — implementation
  pending discussion).
- New feedback: append a new `D<n>` under the right category in the index,
  then a full entry in `D<n>` order at the end of "Decisions." Don't
  renumber or reorder existing entries.

---

## Index

### Data model & tree construction
- [x] [D1](#d1--nodespan-emission-order-is-post-order-not-pre-order) — `NodeSpan` emission order is post-order, not pre-order

### Layout & rendering
- [x] [D2](#d2--all-panes-bordered-shared-border-between-adjacent-panes) — All panes bordered, shared border between adjacent panes
- [x] [D3](#d3--fold-marker-indentation) — Fold marker indentation
- [x] [D6](#d6--folded-line-display-closing-brace-before-trailing-content) — Folded-line display: closing brace before trailing content
- [x] [D12](#d12--d6s---splice-verified-against-real-annotated-output) — D6's `... }` splice verified against real annotated output
- [x] [D13](#d13--raw-range-status-line-display-inclusive-bound) — Raw-range status-line display: inclusive bound
- [ ] [D25](#d25--positional-path-notation-alongside-the-byte-range) — Positional-path notation, alongside the byte range

### Navigation & keybindings
- [x] [D7](#d7--groups-are-foldable-same-as-messages-no-special-casing-needed) — Groups are foldable, same as messages
- [x] [D8](#d8--folding-then-unfolding-a-node-must-not-mutate-descendants-fold-state) — Folding then unfolding a node must not mutate descendants' fold state
- [x] [D15](#d15--page-updown-fold-allunfold-all-siblings) — Page Up/Down; fold-all/unfold-all siblings
- [x] [D16](#d16--at-the-root-h-and-h-fold-the-whole-root-level) — At the root, `h`/`H` fold the whole root level
- [x] [D17](#d17--shift-left-as-an-alias-for-h) — `Shift-Left` as an alias for `H`
- [x] [D18](#d18--lright-made-symmetric-with-hleft-aria-tree-view-pattern) — `l`/`Right` made symmetric with `h`/`Left` (ARIA tree-view pattern)
- [x] [D19](#d19--homeend-and-ggg-jump-to-firstlast-visible-node) — `Home`/`End` and `gg`/`G` jump-to-first/last-visible-node
- [ ] [D20](#d20--future-user-configurable-keybindings-file) — Future: user-configurable keybindings file
- [ ] [D24](#d24--horizontal-panning-of-the-main-pane) — Horizontal panning of the main pane

### Mouse & input
- [x] [D4](#d4--mouse-support-wheel--click) — Mouse support (wheel + click)
- [x] [D14](#d14--mouse-driven-text-selection-for-copy) — Mouse-driven text selection for copy

### CLI flags & options
- [x] [D5](#d5--configurable-indent-step) — Configurable indent step
- [x] [D10](#d10---no-annotations-cli-flag) — `--no-annotations` CLI flag

### Extraction invariants
- [x] [D11](#d11--foldunfold-state-must-be-transparent-to-extraction) — Fold/unfold state must be transparent to extraction (constraint on not-yet-written `extract.rs`)
- [x] [D21](#d21--extract-command-line-x-and-extract) — Extract command line: `x` and `:extract`
- [x] [D23](#d23--extract-default-path-proposal) — Extract default-path proposal

### Command line
- [ ] [D26](#d26--tab-completion-with-cycling-for-the-command-line) — Tab-completion with cycling for the command line

### Help & onboarding
- [x] [D22](#d22--help-overlay-and-startup-splash-screen) — Help overlay and startup splash screen

### Persistence (future)
- [ ] [D9](#d9--foldedunfolded-node-list-belongs-in-the-saved-project-config-future) — Folded/unfolded node list belongs in the saved project config

---

## Decisions

### D1 — `NodeSpan` emission order is post-order, not pre-order

**Status:** Implemented

0111's "Tree construction (ingestion)" section assumed
`IndexingTextSink` hands back `Vec<NodeSpan>` in pre-order/document order.
Reading `IndexingTextSink::begin_nested`/`end_nested`
(`prototext-core/src/serialize/render_text/sink.rs`) shows a container's own
`NodeSpan` is only pushed in `end_nested` — i.e. *after* all of its
descendants have already pushed theirs. The vec is **post-order**: children
before their own parent. Leaves (`scalar_field`) are pushed immediately on
visitation.

- `protolens/src/decode.rs`'s `build_tree()` was rewritten for post-order
  input: for each incoming node `i` at `level`, pop every stack entry with a
  strictly greater level as one of `i`'s children (already fully built,
  post-order guarantees this); the (now topmost) remaining entry, if at the
  same level, is `i`'s immediate previous sibling.
- `TreeNode` gained an explicit `doc_next`/`doc_prev` document-order chain
  (sorted once by `raw_range.start`), since post-order array-index
  arithmetic no longer gives document order "for free" the way 0111
  originally assumed. `j`/`k`/mouse-wheel movement and `App::new()`'s
  initial cursor placement (`doc_prev.is_none()`) now use this chain
  instead of raw index arithmetic.
- 0111's own §1 pseudo-code / prose describing `TreeNode` construction is
  now stale on this point; not edited in place (per this spec's
  living-record approach) — this entry is the correction of record.

### D2 — All panes bordered; shared border between adjacent panes

**Status:** Implemented

Initial layout only bordered the main pane. Decision: all four regions
(header, main, status, command/message) get a border, but adjacent panes
share their separating line rather than drawing two adjacent border rows.

- Header uses `Block::bordered()` (all four sides).
- Main/status/command panes use
  `Block::default().borders(Borders::LEFT | Borders::RIGHT | Borders::BOTTOM)`
  (no `TOP`) — each pane's content starts exactly where the previous pane's
  bottom border row ended.
- Layout constraints: `[Length(3), Min(0), Length(2), Length(2)]` for
  header/main/status/command respectively.

### D3 — Fold marker indentation

**Status:** Implemented

Initial rendering prepended a fixed-width 2-column gutter (`▸`/`▾` or
blank) flush-left on every line, ahead of the rendered text's own
indentation. Decision: the marker should visually align with the node's
nesting depth instead of always sitting at column 0.

- `render_line_content()` splices the marker into the *last character of
  the line's own existing leading whitespace* rather than prepending a
  separate gutter column. A level-0 node (no leading whitespace) falls back
  to `"{marker} {content}"`.
- `marker_column()` (free function) computes the same column for mouse
  hit-testing (`indent_len.saturating_sub(1)`).

### D4 — Mouse support (wheel + click)

**Status:** Implemented

Decision: add mouse as a partial alternate input, per 0111 Annex A's choice
of `crossterm` (which already carries mouse events independently of
`ratatui`, which is stateless/immediate-mode and has no built-in focus
concept — "focus," where it matters, is ordinary app-level state, not
something `ratatui` manages itself).

- `run()` enables mouse capture (`EnableMouseCapture`/`DisableMouseCapture`
  around the terminal session).
- Wheel scroll dispatches to the same `move_down()`/`move_up()` helpers used
  by `j`/`k` (movement logic factored out of the key handler for reuse).
- Left-click hit-tests against a cached `main_area: Rect` (updated each
  `render()` call): resolves the clicked row to a tree node via
  `visible_rows`/`line_to_node`, moves the cursor there (recording a
  jumplist entry if the node changed, per 0111 Annex B's "explicit go-to"
  jumplist rule), and if the click column equals `marker_column(...)` on a
  foldable node, toggles its fold via `toggle_fold()` (also factored out of
  the keyboard fold bindings for reuse).
- v1 has no split panes yet, so there's no real focus ambiguity to resolve
  today; this factoring (app state vs. rendering) is expected to extend
  cleanly once Phase 3/5 panes (0111) land.
- **Trade-off surfaced by D14**: enabling `EnableMouseCapture` also disables
  the terminal emulator's own click-drag text selection (all mouse events
  are forwarded to the app instead) — see D14.

### D5 — Configurable indent step

**Status:** Implemented

`DecodeRenderOpts::indent_size` (from `prototext-core`) defaults to `1`,
too small for comfortable nesting in the TUI. Decision: add a `--indent`
CLI flag, default `2`.

- `Cli::indent: usize`, `#[arg(long = "indent", default_value_t = 2)]`
  (`protolens/src/main.rs`).
- `decode::decode()` takes an `indent_size: usize` parameter, threaded into
  `DecodeRenderOpts`.

### D6 — Folded-line display: closing brace before trailing content

**Status:** Implemented

A folded container line originally rendered as e.g. `message { #@ foo`
(with no visible closing brace at all). Decision: show
`message { ... } #@ foo` instead — the fold summary (`... }`) inserted
immediately after the node's own opening `{`, before any trailing
content/annotation, so the elision is visually self-contained rather than
implying the line simply never closes.

- `render_line_content()`: when the node is folded, finds the *last* `{` in
  the marker-spliced line (`.rfind('{')`) and inserts `" ... }"` right
  after it; falls back to appending at the end if no `{` is found (robust
  to any future trailing-annotation text).

### D7 — Groups are foldable, same as messages (no special-casing needed)

**Status:** Implemented

Question raised: can proto2 GROUP fields be folded/unfolded like messages,
or does their different wire encoding complicate this? Checked
`render_group_field` (`prototext-core/src/serialize/render_text/helpers/
len_field.rs`): it calls `sink.begin_nested(..., NestedKind::Group, ...)`/
`sink.end_nested(...)` exactly like a regular nested message field
(`NestedKind::Message`) — the only difference is the `NestedKind` tag and
that a group has no length prefix (`raw_start`'s frame isn't reset).
`NodeSpan` itself carries no `NestedKind`/kind distinction, and
`protolens`'s `TreeNode`/`has_children()` (`first_child.is_some()`) is
purely structural — it doesn't care what produced the nesting. **Decision:
no implementation change needed** — groups already fold/unfold correctly
today, for free, because they already produce a first-class
`begin_nested`/`end_nested` subtree in the index like any other container.

### D8 — Folding then unfolding a node must not mutate descendants' fold state

**Status:** Implemented

Requirement (already true of the current implementation — recorded here so
it doesn't regress): fold state is tracked per-node (`App::folded:
HashSet<usize>`), one independent bit per node. Folding a node only hides
its descendants' *rows* (via `rebuild_visible_rows`'s
`text_range`-derived hidden-range computation); it never touches
`folded`'s membership for any node other than the one toggled. So folding a
container, then unfolding it again, always restores its subtree exactly as
it was — any descendant that was independently folded stays folded, any
that was expanded stays expanded. `toggle_fold()` (D4) only ever inserts/
removes the single toggled index from `folded`, confirming this holds
going forward as well.

### D9 — Folded/unfolded node list belongs in the saved project config (future)

**Status:** Deferred (0111 Phase 7)

Noted for later, once 0111 Phase 7's project-file format
("Project file and batch mode" in 0111's "Beyond v1") is designed: the
current fold set (`App::folded: HashSet<usize>`, or a range-keyed
equivalent stable across re-decodes) should be part of the saved project
YAML, alongside the overriding collection, so reopening a project restores
the same view, not just the same interpretation. Not actionable yet — v1
has no project file at all (0111 Non-goals) — recorded here so it isn't
lost by the time Phase 7 starts.

### D10 — `--no-annotations` CLI flag

**Status:** Implemented

`prototext`'s own `decode` subcommand already ships `--no-annotations`
(annotations *on* by default — `prototext/src/lib.rs`). `protolens`
previously hard-coded `annotations: false` in `decode.rs`, diverging from
that convention and from the fact that annotations (wire type, field decl,
modifiers) are important context when eyeballing unknown/mismatched wire
data to guess its real type — exactly `protolens`'s use case. Decision:
match `prototext`'s convention — annotations on by default, `--no-annotations`
to suppress them.

- `Cli::no_annotations: bool`, `#[arg(long = "no-annotations")]`
  (`protolens/src/main.rs`).
- `decode::decode()` takes an `annotations: bool` parameter (`main.rs`
  passes `!cli.no_annotations`), threaded into `DecodeRenderOpts`.

### D11 — Fold/unfold state must be transparent to extraction

**Status:** Implemented (as a constraint — `extract.rs` itself not yet built)

Design invariant, flagged ahead of `extract.rs`'s implementation (not yet
built): fold/unfold is purely cosmetic UI state (`App::folded:
HashSet<usize>`) and must have **zero effect** on `extract`'s output.
Extraction always operates on the underlying `NodeSpan::raw_range` (or
`text_range` for the `#@ prototext` format, per 0111 Open Issue 2) against
the original blob/rendered text — never against the currently-folded
on-screen view. Reaffirms 0111's existing "fold state is pure UI state, not
part of the index/undo model" principle (0111 §2), called out here
specifically as a constraint `extract.rs` must honor when implemented.

### D12 — D6's `... }` splice verified against real annotated output

**Status:** Implemented (verified, no change needed)

Question raised once annotations went on by default (D10): does D6's
`render_line_content` fold-brace splice (`s.rfind('{')` + insert
`" ... }"` right after it) still land correctly now that the header line
also carries a trailing `#@ ...` annotation? Checked both statically and
by round-tripping `decode()` against a real self-describing descriptor set
(`prototext-core/fixtures/descriptor.pb`, decoded as
`google.protobuf.FileDescriptorSet` with `annotations: true`): every
container's own header line (`wob_prefix_n`/`begin_virtual_nested`/the
`NestedKind::Group` branch, all in `prototext-core/src/serialize/
render_text/{sink.rs,helpers/output.rs}`) writes its `{` exactly once,
with any `#@ ...` annotation text appended strictly *after* it, on the same
line, before the newline — and no annotation token (`field_decl`,
`TYPE_MISMATCH`, `tag_ohb: N`, `[packed=true]`, etc.) ever itself contains
a `{` character. So `rfind('{')` reliably finds the node's own opening
brace regardless of annotation content, e.g.:

```
"    field {  #@ repeated FieldDescriptorProto = 2"       (unfolded)
"   ▸field { ... }  #@ repeated FieldDescriptorProto = 2"  (folded)
```

**Decision: no code change needed** — D6's implementation already composes
correctly with annotations on. Recorded here since it was flagged as a
concern worth double-checking, not because a bug was found.

### D13 — Raw-range status-line display: inclusive bound

**Status:** Implemented

The status line showed `bytes[121..232]` using `raw_range`'s own
half-open-range values as-is — misleading, since it reads like an
inclusive range (`[start..end]`) while actually meaning `[start..end)`.
Decision: display an inclusive bound instead — `bytes[121..231]` — judged
easier to read at a glance than spelling out `[121..232)`.

- `render()`'s status-line `format!`: `node.raw_range.end` →
  `node.raw_range.end.saturating_sub(1)` (display-only; `NodeSpan` itself,
  and everything derived from it, e.g. future `extract.rs`, keeps using the
  half-open `raw_range` unchanged).

### D14 — Mouse-driven text selection for copy

**Status:** Implemented (documentation-only — no code change)

D4's `EnableMouseCapture` forwards *all* mouse events to `protolens`,
which means the terminal emulator's own click-drag text selection no
longer engages by default — a real regression for "just copy this line to
paste elsewhere," which worked for free before D4. Three options were
considered, not mutually exclusive:

1. **Already works today, zero code**: nearly every terminal emulator
   (xterm, GNOME Terminal/VTE, Kitty, Alacritty, iTerm2, Windows Terminal,
   WezTerm) supports holding **Shift while dragging** to bypass an app's
   mouse-capture request and fall back to the terminal's own native
   selection — a terminal-level convention, not something `protolens`
   implements or can break.
2. **App-level "visual selection" mode** (vim-style): a key (e.g. `v`)
   enters a line/range-selection mode; existing cursor movement
   (`j`/`k`/click) extends the selection; a key (e.g. `y`) yanks it.
   Copies via an OSC 52 escape sequence (`\x1b]52;c;<base64>\x07`) written
   directly to the terminal — no GUI clipboard binding needed on the Rust
   side (so no new platform-specific dependency, works over SSH), though
   some terminals/multiplexers require enabling it (e.g. `tmux set -g
   set-clipboard on`). Keyboard-driven, so it works even without a mouse.
3. **Mouse-driven drag-select**: `MouseEventKind::Down(Left)` sets a
   selection anchor, `Drag(Left)` extends it, `Up(Left)` finalizes and
   copies (same OSC 52 mechanism as option 2) — closer to "the mouse
   selection users expect," but more event-handling surface (multi-line
   selection rendering/highlighting, anchor bookkeeping) than option 2.

**Decision: option 1, zero code.** Shift+drag already restores native
terminal selection with no `protolens` changes. Options 2/3 remain
available to revisit later if Shift+drag proves insufficient in practice
(e.g. over some remote/multiplexer setup where it's unavailable), but
aren't needed now. Worth documenting in a future `?` help overlay (0111
Annex C) rather than assuming it's discoverable.

### D15 — Page Up/Down; fold-all/unfold-all siblings

**Status:** Implemented

Two related gaps: no page-wise scrolling, and no single keystroke to
fold/unfold every sibling of the cursor node at once (previously only
one-at-a-time via `z`/`Space`/click).

- `KeyCode::PageDown`/`PageUp`: repeats `move_down()`/`move_up()`
  `self.main_area.height` times (`move_page_down()`/`move_page_up()`) —
  reuses D4's existing single-step movement rather than a separate
  scroll-offset jump, so it inherits the same hidden-node-skipping
  (`next_visible`/`prev_visible`) behavior for free.
- `H`: fold every sibling of the cursor node that has children
  (`fold_all_siblings()`).
- `Shift-Right`: unfold every sibling of the cursor node
  (`unfold_all_siblings()`). Bound as `KeyCode::Right` guarded by
  `key.modifiers.contains(KeyModifiers::SHIFT)`, checked *before* the
  existing unguarded `l`/`Right` child-move arm in the `match` (guard
  ordering matters: an unguarded `Right` arm placed first would shadow
  it).
- Both new fold commands share a `sibling_range(idx)` helper: walk to the
  first sibling via `prev_sibling`, then collect forward via
  `next_sibling`. This works uniformly at any level, including root-level
  nodes, which are linked to each other via `next_sibling`/`prev_sibling`
  despite having no `parent` (`build_tree`'s stack-based algorithm sets
  sibling links independently of parent assignment) — see D16.

### D16 — At the root, `h`/`H` fold the whole root level

**Status:** Implemented

Previously, `h`/`Left` at a root-level node (no `parent` to move to)
printed "already at root" and did nothing. Decision: since D15's
`sibling_range`/`fold_all_siblings` already work at the root (root-level
nodes are sibling-linked to each other), reuse that instead of a no-op —
`h`/`Left`'s "no parent" fallback now calls `fold_all_siblings()`, the same
action `H` performs everywhere. No special-casing needed: root-level fold
is just `H`'s general "fold all siblings at this level" applied to the
level that happens to have no parent.

### D17 — `Shift-Left` as an alias for `H`

**Status:** Implemented

`H` (D15, fold-all-siblings) had no arrow-key alias, unlike `Shift-Right`
(unfold-all-siblings). Decision: add `Shift-Left` as an alias, mirroring
`Shift-Right`'s guard/placement — `KeyCode::Left` guarded by
`key.modifiers.contains(KeyModifiers::SHIFT)`, checked before the
unguarded `h`/`Left` parent-move/fold arm.

### D18 — `l`/`Right` made symmetric with `h`/`Left` (ARIA tree-view pattern)

**Status:** Implemented

Reported inconsistency: `l`/`Right` on a closed foldable node unfolded it
*and* jumped straight to its first child in one press, but a second press
then tried to descend into that child's own children instead of advancing
to the second child — surprising, since the two presses did visibly
different kinds of things. Researched the
[W3C WAI-ARIA Tree View Pattern](https://www.w3.org/WAI/ARIA/apg/patterns/treeview/),
the closest thing to a standard keyboard-interaction spec for tree
widgets: it explicitly decouples *open* from *move-to-child* — Right Arrow
on a closed node opens it with focus staying put; only a Right Arrow on an
already-open node moves focus to the first child. `h`/`Left` already had
this two-step shape (close-if-open first; move-to-parent only if already
closed/leaf) — `l`/`Right` didn't.

- `l`/`Right`'s handler now checks `folded.contains(&cursor)` first: if
  the cursor is on a closed foldable node, it only opens it
  (`toggle_fold`), cursor unchanged; only when the node has no children,
  or is already open, does it move to `first_child` (recording a
  jumplist entry, as before).
- This makes `l`/`l` and `h`/`h` symmetric: first press affects fold
  state only, second press moves the cursor — matching the ARIA standard
  and eliminating the reported inconsistency.

### D19 — `Home`/`End` and `gg`/`G` jump-to-first/last-visible-node

**Status:** Implemented

Gap flagged during review: no way to jump directly to the first/last node
without repeated `j`/`k`/PageDown — a conventional gap versus `less`,
file managers, and vim's own `gg`/`G`. Decision: add both a direct-key and
a vim-chord binding for the same two actions, since both are widely
idiomatic and neither conflicts with existing bindings.

- `Home` / `gg` (two `g` presses in a row — `App::pending_g`, cleared by
  any other key) → `move_home()`: jump to the document-order first node
  (`App::first_node`, computed once in `App::new()`, same node the cursor
  starts on).
- `End` / `G` → `move_end()`: jump to the document's absolute last node
  (`last_node()`, following `doc_next` to the end), or its nearest
  visible predecessor (`prev_visible`) if that last node is itself
  folded away — respects fold state, like PageUp/PageDown (D15) already
  do.
- Both record a jumplist entry (`record_jump`) when they actually move
  the cursor, consistent with the "explicit go-to" jumplist rule (0111
  Annex B) already applied to sibling-skip (`J`/`K`), parent/child move,
  and mouse click.
- Not proposed/added: vim's Ctrl-D/Ctrl-U (half-page) or Ctrl-F/Ctrl-B
  (full-page) — PageUp/PageDown (D15) already cover that ground; aliasing
  the same action under more keys wasn't resolving any reported gap.

### D20 — Future: user-configurable keybindings file

**Status:** Deferred (no action until a real layout collision is reported)

Raised during review (user has a French-Macintosh keyboard layout):
should keybindings be configurable per keyboard layout? Researched two
angles:

- **Physical-layout independence at the terminal-protocol level**: the
  Kitty keyboard protocol's "base-layout-key" (`report_alternates`)
  enhancement lets a terminal report the *physical* key identity
  independent of the active OS layout. Not usable today: `crossterm`
  (0111 Annex A's terminal dependency) doesn't yet implement this part of
  the protocol (open upstream issue,
  crossterm-rs/crossterm#968).
- **AZERTY-safety of the current binding set**: `h`/`j`/`k`/`l`/`z`/`x`/
  `q`/`H`/`J`/`K`/`g`/`G` all sit at the same physical/character position
  on AZERTY as QWERTY — the "vim hjkl problem" doesn't actually apply to
  these letters. AZERTY friction is concentrated elsewhere (top-left
  letter swap, `M` relocation, digit row defaults) — none of which
  `protolens` currently binds. **No known collision exists today.**
- **Practical fallback used by mature tools**: Helix (TOML,
  `~/.config/helix/config.toml`) and lazygit (YAML, `config.yml`) both
  solve layout/preference portability by shipping sane defaults *and*
  making every binding user-remappable via a config file, rather than
  trying to be layout-aware themselves.

**Decision:** don't build a keybindings config file speculatively — no
actual collision has been reported, and the AZERTY letters we use are
unaffected. If a real collision surfaces later, the Helix/lazygit
config-file-remapping model is the recommended path (not a bespoke
scheme). Recorded here so it isn't re-researched from scratch if/when it
becomes actionable.

### D21 — Extract command line: `x` and `:extract`

**Status:** Implemented

0111 Goal 4 (extract) had no `extract.rs` and no working `x` binding
(stub message only). Decision, resolving 0111 §2's "exact binding TBD":
support both forms 0111 sketched, rather than picking one — `x` as a
shortcut, `:extract` as the general form, vim-style (0111 Annex C already
frames the command/message line as vim-style, hosting `:extract <path>`-
style ex-commands).

- `App::command_buffer: Option<String>` — `Some(buffer)` while a command
  line is being edited, `None` in normal navigation mode;
  `handle_key`/`handle_mouse` fully defer to `handle_command_key` while
  it's `Some`, so command-line text doesn't leak into normal-mode
  bindings.
- `:` opens an empty command line; `x` is a shortcut that pre-fills it
  with `extract <default path>` (see D23) — both land in the same
  `command_buffer`/`handle_command_key`/`run_command` machinery.
- `Enter` executes (`run_command` → `run_extract`), `Esc` cancels,
  `Backspace` on an empty buffer also cancels (matches vim's own command
  line), any other character is appended.
- `extract.rs` (new file): `extract_binary()` (raw byte sub-slice of
  `raw_range`), `dedent()` (Python-`textwrap.dedent()`-style common-
  leading-whitespace strip, resolving 0111 Open Issue 2's "extracted
  `#@ prototext` snippet must be self-contained" requirement), and
  `extract()` (writes one or the other to a file). Covered by
  `#[cfg(test)]` unit tests per 0111 §4's "pure-logic unit tests" bullet.
- `run_extract` parses `extract [--binary|--text] <path>` — no quoting/
  escaping grammar, `path` is just the remaining whitespace-joined
  tokens; default format is text (see D23's sibling default-format
  decision, made together with this entry).
- No file-navigator popup: mimics vim's own `:w <path>` — a typed path on
  the command line, no built-in file browser (that's a plugin concern in
  vim, e.g. netrw/fzf, not core `:w` behavior) — consistent with keeping
  v1's command line minimal.

### D22 — Help overlay and startup splash screen

**Status:** Implemented

0111 Annex C already anticipated a `?` help overlay ("cheap enough to
ship in v1 itself") but it was never built; separately, a first-time user
has no in-app hint that `?` exists at all. Decision: build both.

- `HELP_TEXT: &[&str]` — a static, hand-phrased key-binding reference
  (grouped: Movement, Fold/unfold, Navigation history, Extract, Other),
  kept as flat text rather than generated from `handle_key`'s match arms
  so it can be organized for readability independent of match-arm order.
- `?` toggles `App::help_open`; while open, `handle_key` defers to
  `handle_help_key`: `j`/`k`/`Down`/`Up` scroll one line,
  `PageDown`/`PageUp` scroll by 10, `q`/`Esc`/`?` closes. `help_scroll` is
  clamped against the popup's actual rendered height in `render_help`
  (content length vs. `inner.height`), not against a fixed constant.
- `App::splash: bool`, `true` from `App::new()`; the very first keypress
  (any key, consumed without its normal effect) clears it — a "press any
  key to continue" screen, the common convention for this kind of
  one-shot onboarding hint. Shows the same header line as the main
  header pane plus "Press ? for help." / "Press any key to continue.".
- Both render as a centered modal via a new `centered_rect()` free
  function (the standard ratatui popup-centering recipe: nested
  `Percentage`-based vertical then horizontal `Layout` split) plus
  `Clear` (ratatui's "erase what's behind a popup" widget) before drawing
  the modal's own `Block`/`Paragraph` — drawn *after* the normal 4-region
  layout in `render()`, so the full UI is always laid out underneath.

### D23 — Extract default-path proposal

**Status:** Implemented

Typing a full path by hand for every extract is friction, especially
since the two most useful identifying facts about a node (its byte range,
its type) are already on screen (status line). Decision: `x` pre-fills
the command line with a proposed default path instead of leaving it
blank — the user can accept it (just press `Enter`) or overwrite/edit it
before confirming.

- Format: `<blob_stem>.<raw_start>-<raw_end>.<short_type>.pb` — e.g.
  extracting a `DescriptorProto` at byte range `[212..8841]` out of
  `descriptor.pb` proposes `descriptor.212-8841.DescriptorProto.pb`.
  `<blob_stem>` is the original blob's filename without extension
  (`blob_path.file_stem()`); `<short_type>` is the type FQDN's last
  `.`-segment (falls back to `"node"` if the node has no resolved type,
  e.g. an unknown/malformed field). The byte range ties the filename back
  to the status line's `bytes[..]` display and keeps repeated extracts
  from the same session collision-free; the short type name adds
  readability without the noise of a fully-qualified name in every
  filename.
- Always a `.pb` extension, regardless of format (`--binary` or the
  default `--text`): both are "a protobuf-shaped payload" in the sense
  that matters for this naming scheme (round-trippable via `prototext
  decode`/`prototext encode`), so the extension shouldn't encode which
  representation was chosen — that's what `--binary`/`--text` on the
  command itself already records, redundantly encoding it in the
  filename would just be one more thing that can drift out of sync if
  the file is renamed.
- Default format (independent question, decided together with this
  entry): `#@ prototext` text, not raw binary — carries more of the
  payload's inferred structure than opaque bytes, and is always
  reconstructible back to binary via `prototext encode`, whereas the
  reverse (bytes → structure) is exactly the hypothesis-testing problem
  `protolens` exists to help with. `--binary` opts into raw bytes when
  that's specifically what's needed (e.g. feeding a sub-blob to another
  tool's own `--type` guess, 0111 Goal 4's original framing).
- Implemented as `App::default_extract_path()`, called once when `x` is
  pressed (not recomputed as the user edits the pre-filled buffer).

### D24 — Horizontal panning of the main pane

**Status:** Open — key bindings agreed; pan step size and clamping/gutter
interaction still TBD at implementation time.

Gap: long field values (and, once spec 0114 lands, an override's re-spliced
subtree at extra indentation depth) can already exceed the main pane's
rendered width; there is no horizontal scroll offset today — a line just
renders as-is from column 0, clipped by the pane's `Rect` width.

- Bindings: `Ctrl-Left`/`Ctrl-Right` pan the view left/right. Bare
  `Left`/`Right` (parent/child move) and `Shift-Left`/`Shift-Right`
  (fold-all/unfold-all siblings, D15/D17) are both already taken; `Ctrl`+
  arrow follows the same modifier-escalation convention already used for
  `Ctrl-O`/`Ctrl-I` (jumplist) layered over plain `o`/`i` (now also
  `t` for spec 0114's override pane).
- Considered `<`/`>` as an unclaimed fallback if `Ctrl`+arrow doesn't reach
  the app in some terminal/multiplexer configuration — not adopted for v1;
  `Shift`+arrow already relies on similar terminal support and works fine
  in practice, so no reason to expect `Ctrl`+arrow to be worse.
- Not yet decided: exact pan step (e.g. a fixed column count vs. a fraction
  of the pane's visible width), clamping bounds (`0` on the left; on the
  right, likely the longest *currently visible* line's length minus the
  pane width, recomputed as the cursor/scroll position changes), and
  whether the fold-marker gutter (D3) stays pinned to column 0 while only
  the rendered text pans, or scrolls along with it.

### D25 — Positional-path notation, alongside the byte range

**Status:** Open — notation agreed; exact status-line layout and whether
very deep paths need truncation still TBD at implementation time.

Spec 0109's own User Interface section sketched a status-line "path"
(`.1.2`) without ever defining it precisely. Raised again as an
alternative/complementary way to identify the cursor node's range,
distinct from D13's `bytes[start..end]`: a byte range needs no schema
knowledge to *display*, but two different nodes can't be told apart from
it alone if you don't already know the tree shape; a **positional path**
identifies a node by its exact location in the tree instead, and does so
unambiguously with no schema knowledge required either.

- **Definition**: `/n_1/n_2/.../n_k`, a **slash-separated path**, where each
  `n_i` is the **1-based ordinal position of that level's node among its own
  parent's direct children, in document order** — *not* the field number.
  Field number was considered and rejected: a repeated field occurrence
  shares its field number with every other occurrence at the same level, so
  field number alone wouldn't be unambiguous; sibling position always is.
  This also means the path is computable purely structurally, from the same
  sibling-chain (`first_child`/`next_sibling`) `build_tree` (D1) already
  maintains — no field-number/tag inspection, no descriptor lookup needed.
- **Empty-path (root) notation**: the root/whole-document path is a lone
  `/`, with no segments after it — matching the familiar Unix filesystem-
  root convention. Every other path is "the root's `/`, plus one more `/n`
  segment per level" — uniform, no special-cased root format. Revises
  0109's own leading-dot sketch (`.1.2`): a dot-based path would sit
  directly adjacent to the status line's `.`-separated FQDN (e.g.
  `google.protobuf.DescriptorProto`), risking visual collision between the
  path's own `.` separators and the FQDN's; `/` avoids this entirely.
- **1-based**, matching the status line's own existing `Lx/total` (D13's
  neighbor) 1-based convention, for consistency within the same status
  line.
- **Display**: alongside `bytes[..]` (D13), not instead of it — e.g.
  `L5/3062  bytes[212..8841]  path /1/2  google.protobuf.DescriptorProto`.
  Exact column layout/ordering not yet decided.
- Noted in passing (not adopted, no action taken): this positional path
  would also be a valid, schema-independent key for identifying an
  override's target range (spec 0114) — 0114 sticks with the byte range as
  its cache/override key for now (already sufficient, no reason to
  complicate), but the path notation may be worth revisiting once spec
  0109's deferred "set of overrides" work needs a stable node identity
  that survives a re-render (a byte range can shift after an ancestor's
  own override changes its rendered length, if that ever becomes possible;
  a positional path, defined purely on the *original* wire structure,
  would not).

### D26 — Tab-completion with cycling for the command line

**Status:** Open — mechanism agreed; exact on-screen presentation of the
cycling state (e.g. a status-line hint, or just the buffer text changing)
still TBD at implementation time.

Motivated by spec 0114's `:type-as`/`:type-as-raw` command names (typing
either the command name or a full FQDN by hand is tedious), but designed
as general command-line infra, not ad hoc to that one feature — it also
benefits `:extract` (D21), and any future command added later.

Two independent things can be completed, at whichever position the cursor
sits in the command buffer: **(a)** the command name itself (the first
token), and **(b)** currently, only `:type-as`'s FQDN argument (the second
token, once the command name is resolved) — other commands' arguments
(e.g. `:extract`'s `<path>`) are left plain-typed, matching D21's existing
"no file browser, just like vim's own `:w <path>`" precedent; file-path
completion is not addressed by this entry.

- **Behavior**, modeled on vim's own `wildmenu`/`wildmode=longest,full`
  (a natural fit, since the command line already deliberately mimics vim —
  D21): the first `Tab` completes the current token to the longest common
  prefix of all matching candidates. If that prefix is still ambiguous
  (more than one candidate remains), each subsequent `Tab` — as long as no
  other key has been pressed in between — cycles forward through the full
  candidate list one at a time, replacing just that token, wrapping around
  after the last candidate. `Shift-Tab` cycles backward through the same
  list. Typing any other character, `Enter`, `Esc`, or `Backspace` ends the
  cycling state and returns to plain editing.
- **Templated, not ad hoc**: a single generic primitive, e.g.
  `fn complete_prefix<'a>(prefix: &str, candidates: impl Iterator<Item =
  &'a str>) -> Vec<&'a str>`, backs three call sites:
  1. `run_command`'s dispatcher itself — unambiguous-prefix execution at
     `Enter` time, with exact match always winning over prefix ambiguity
     (spec 0114 §7): typing a command's full name resolves to itself even
     when it's also a prefix of a longer command name (e.g. `:type-as` vs.
     `:type-as-raw`) — matching vim's own `:command` abbreviation
     convention and `argparse`'s prefix-matching, not a bespoke rule.
  2. Command-name Tab-completion, driven off the same single
     source-of-truth command-name registry already used by (1) — adding a
     command to that registry is the only step needed for it to get both
     prefix-dispatch and Tab-completion, automatically.
  3. `:type-as`'s FQDN-argument Tab-completion (spec 0114) — candidates are
     the same session-global, lexicographically-sorted FQDN list spec
     0114 §3.2/§6 already computes once and caches, reused here rather than
     recomputed. Structurally the same shape as the existing
     `protolens/src/complete.rs::complete_type_names` (a
     `clap_complete::ArgValueCompleter` used for the CLI's own `-t`/`--type`
     *shell* completion, outside the TUI) — not literally shared code
     (different completion frameworks: `clap_complete` vs. this TUI's own
     command-line editor), but the same matching semantics; worth keeping
     the two in sync if either changes.
- **No conflict with the override pane's own `Tab`** (spec 0114 §2):
  command-line editing (`App::command_buffer: Some(...)`, D21) and the
  override pane are mutually exclusive input modes — command-line mode
  already fully shadows every normal-mode key binding (D21), so its `Tab`
  binding and the override pane's focus-toggle `Tab` binding never compete
  for the same keypress.

---

## Open

- **D9** — folded/unfolded node list in saved project config: deferred to
  0111 Phase 7, not actionable until the project-file format exists.
- **D20** — user-configurable keybindings file: deferred until a real
  keyboard-layout collision is reported (see D20).
- **D24** — horizontal panning: key bindings settled, implementation
  details (pan step, clamping, gutter behavior) still open.
- **D25** — positional-path notation: notation settled, status-line layout
  still open.
- **D26** — Tab-completion with cycling: mechanism settled, on-screen
  presentation of the cycling state still open.

New entries get appended to the Index (grouped by category) and to
Decisions (in `D<n>` order) as further TUI feedback arrives.
