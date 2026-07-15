<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# protolens — working todo / status

Not a spec — a running status board for in-flight feedback items, tracking
which spec/doc each one lives in, its decision status, and open questions
that block implementation. Update in place as items move
open -> decided -> implemented; delete an item once it's folded into a
spec as `Implemented` (don't let this file drift out of sync with the
specs it points at).

## Spec 0113 (`docs/specs/0113-protolens-tui-refinements.md`) — small UI items

D27/D28/D29/D30/D31/D32/D33/D34 implemented (2026-07-14) — see spec 0113
§D27/§D28/§D29/§D30/§D31/§D32/§D33/§D34 (folded out of this list per this
file's own convention).

## Spec 0119 (`docs/specs/0119-protolens-override-fidelity-and-workflow.md`)
— override fidelity + manage-pane workflow

`Status: implemented (2026-07-14)`. Four interrelated items sharing
`splice_override`'s synthetic-wrapper mechanics. G1/G2/G3/G4 implemented
(2026-07-14) — see spec 0119 §G1/§G2/§G3/§G4 (folded out of this list per
this file's own convention).

## Spec 0114 §1.3 (`docs/specs/0114-protolens-range-type-override.md`)
— widen override eligibility to length-delimited scalars

Implemented (2026-07-14) — see spec 0114 §1.3 (folded out of this list per
this file's own convention). The packed-repeated-element exclusion this
item's open design question worried about turned out to need no new
`NodeSpan`/design work at all: a packed element's own `wire_type` is
always the element's primitive kind, never `WT_LEN`, so the simple
`is_message || wire_type == WT_LEN` predicate already excludes it for
free.

## Spec 0120 (`docs/specs/0120-protolens-any-messageset-as-auto-overrides.md`)
— Any/MessageSet expansion as automatic overrides

Implemented (2026-07-14) — see spec 0120 (folded out of this list per this
file's own convention).

## 2026-07-15 feedback — 9 items

Discussed/decided (review comments, resolved via inline `=>` replies),
split across specs 0124-0129. All 9 items implemented (2026-07-15) — see
spec 0124 §G1/§G2/§G3, spec 0125, spec 0126 §G1/§G2, spec 0127, spec
0128, spec 0129 (folded out of this list per this file's own
convention).

## 2026-07-15 feedback, round 2 — 4 items

### Item 2 — manage-pane color scheme (auto = field-name style, manual = comment style)

> In the override management pane, I'm not happy with cyan, also there
> is not enough difference between cyan and bold cyan. I propose the
> following update: For auto-derived overrides: use the same style as
> for `field name` in the main pane. For manual overrides: use the same
> style as for `comments` in the main pane.

[[Re "why Blue/Red, what do you mean" — my first draft tried to mirror
`Attribute`'s per-theme RGB hue into ANSI-16 (dark-rgb `#9CDCFE` is
light-blue-ish -> ANSI-16 `Blue`; light-rgb `#E50000` literally is red
-> ANSI-16 `Red`), which produced a confusing, theme-dependent color
name for the same role. Dropped in favor of the simpler scheme below —
one fixed color name per role, same in both themes.

Revised, corrected per your notes (auto <-> manual swapped back from
the first draft, `ITALIC` dropped, manual simplified to plain `Blue`).
One further correction caught while drafting the spec: `SyntaxRole`
itself is documented as strictly one variant per `queries/
highlights.scm` capture name, with `RECOGNIZED_NAMES`/
`from_highlight_index` as parallel, index-matched arrays driven by
tree-sitter's own highlight config — these two manage-pane colors have
no corresponding syntax capture, so adding them as `SyntaxRole`
variants would misuse/break that invariant. Instead: a small, separate
`theme::manage_entry_style(auto: bool, theme: ThemeKind) -> Style`
function, sitting next to `style_for` but independent of `SyntaxRole`,
with its own 4-way dispatch, colors reused from existing `SyntaxRole`
palette entries rather than invented:

- auto: `Comment`'s values verbatim, minus `ITALIC` — dark-rgb `#6A9955`
  / light-rgb `#008000` / dark-ansi16 `DarkGray` (no modifier) /
  light-ansi16 `DarkGray` (no modifier). Muted/de-emphasized, fitting
  "auto-derived, secondary" — and gives auto entries a real, non-default
  ANSI-16 color (unlike `Attribute`, whose own ANSI-16 fallback is
  `Style::default()`, i.e. no color at all — the caveat that started
  this whole redesign).
- manual: `Boolean`'s RGB values (the palette's genuine "blue" entry,
  not `Type`'s teal/cyan) paired with plain ANSI-16 `Blue` for both
  themes — dark-rgb `#569CD6` / light-rgb `#0000FF` / dark-ansi16 `Blue`
  (no modifier) / light-ansi16 `Blue` (no modifier, same name in both
  themes this time — the earlier Blue/Red split is gone).

`render_manage_pane`'s `ManageRow::Entry` branch switches from
`theme::style_for(SyntaxRole::Type, ...)` +/- `Modifier::BOLD` to
`theme::manage_entry_style(auto, self.theme)` directly — no `BOLD`
toggle needed, the two colors are distinct on their own (muted
gray-green vs. blue) at every palette depth, addressing the original
"cyan vs. bold cyan" complaint more directly than a bold toggle ever
could.]]

### Item 3 — copy/paste from the main pane: SSH clipboard, copy-current-line, keybinding

> Regarding copy paste lines from the main pane:
> - What is protolens[' behavior when it] execut[es] in an SSH session
>   in the terminal? Will the copy be able to find the system
>   clipboard? (I see X11-related error messages in the
>   command/message pane when I try to select a range of lines)
> - When no range is selected, I would like Copy to copy the one line
>   on which the cursor is in the main pane
> - What is the key for Copy?

[[Answers to the follow-up questions, then a revised, consolidated
design:

- "Even with a mouse selection, don't I still need a key to actually
  copy?" — Under spec 0129 as implemented today, no: `Up(MouseButton::
  Left)` already triggers `copy_selection_to_clipboard` automatically
  on release, no separate key needed. But the question is a fair push
  toward a cleaner mental model — decoupling "select" (mouse-drag, or
  just the cursor's position) from "copy" (one explicit key), applying
  uniformly regardless of how the selection was made. See revised
  design below.
- Vernacular meaning of "yank": vim's own term for "copy" — `y` copies
  text into a register (vim's clipboard-like buffer), later inserted
  with `p` ("put"/paste). Not to be confused with `d` (delete/cut).
- Why `y` over `Ctrl-C`: not a dismissal, just not compared — `y` was
  picked purely for consistency with protolens' existing vim-derived
  bindings (J/K). Trade-off check: `Ctrl-C` is confirmed unbound
  anywhere else in tui.rs today (grepped, no collision), is the
  near-universal modern "copy" shortcut (more discoverable to non-vim
  users), and, since protolens runs the terminal in raw mode, arrives
  as a normal key event rather than `SIGINT` — safe to bind. Revised
  recommendation below switches to `Ctrl-C`.
- Full-keyboard range selection: not given up on by me in this round —
  it was your own explicit call in spec 0129's original discussion
  (Non-goals: "No vim-style visual-line mode — explicitly rejected ...
  in favor of mouse-only selection"). Revisiting it now would be a real
  scope increase beyond this item's original ask ("copy the cursor's
  line when nothing is selected") — proposed as a separate future
  item below rather than folded into this one.

Revised, consolidated design (replaces the `y`-based proposal):
- Single key, `Ctrl-C`, performs Copy uniformly: copies the active
  drag-selection if one exists (`select_anchor`/`select_end` both
  `Some`), else falls back to the cursor's current line — same
  `selected_text()`/`copy_selection_to_clipboard()` machinery (spec
  0129), just triggered explicitly instead of automatically.
- Drop spec 0129 G2's auto-copy-on-`Up`: mouse release only finalizes/
  persists the highlighted selection (G1/G3 unchanged), it no longer
  copies by itself — `Ctrl-C` becomes the one, uniform trigger for the
  actual clipboard write, directly addressing the first question above.
- SSH/X11: confirmed root cause — `arboard` needs a reachable X11/
  Wayland display, absent over plain SSH without forwarding. OSC 52
  fallback confirmed viable: Alacritty does support OSC 52
  (configurable `osc52` permission level in `alacritty.toml` —
  allow/deny/clipboard-only), so both `arboard` (local/X-forwarded/
  Wayland) and the OSC 52 fallback (plain SSH, no forwarding) have a
  real path to work there, alongside the other terminals named earlier
  (iTerm2/kitty/foot/WezTerm/tmux-passthrough).

=> OK with this revised design (`Ctrl-C` as the one copy key, dropping
auto-copy-on-mouse-release, OSC 52 fallback)? And should full-keyboard
range selection become a new, separate todo.md item, or stay out of
scope for now? => Yes: Stay out of scope for now
=> Yes — nothing above changes drag tracking itself. `select_end`
already updates continuously on every `Drag` event regardless of
direction, and the render highlight/copy range always uses
`min(anchor, end)..=max(anchor, end)` (spec 0129 G1/G2), independent of
which one is numerically larger — dragging up (end row above start
row) and dragging down both already work, in correct top-to-bottom
document order either way (spec 0129's own test plan item 3 covers
exactly this: "dragging upward ... still copies the correct range in
top-to-bottom document order (not reversed)"). Unaffected by swapping
the copy trigger from auto-on-release to `Ctrl-C`. ]]

### Item 4 — override-selection-pane live preview + smarter default target

> In the override selection pane, I would like the currently targeted
> type to show on the main pane. Meaning: the main pane should
> tentatively render using the currently targeted type.
> - Hitting ESC to abort should revert to the previous rendering
> - On hitting `t` to enter override selection pane, protolens should
>   target as current type the one corresponding to (in decreasing
>   order of priority): (1) the current override type for the field in
>   the main pane, (2) if this field is not available, the type
>   corresponding to the top result of autoinference for the
>   corresponding range, (3) if autoinference is not available or does
>   not return results, <raw / no type>

[[Splitting this into two independent pieces:

Default-target priority: priorities (2)/(3) are ALREADY implemented —
`recompute_override_candidates` already sets `override_highlight =
usize::from(!override_candidates.is_empty())` (row 0 = `<raw / no
type>` when there are no candidates, row 1 = top-inferred otherwise).
Only priority (1) is missing. `resolve_active_override_entry(idx)`
(tui.rs:1583+) already resolves the currently-active override entry for
a node (checking `Path`, then `PathField`, then `FqdnField` origin, in
that exact priority order) — exactly what's needed. Fix: in
`toggle_override`, before calling `recompute_override_candidates`, call
`resolve_active_override_entry(cursor)`; if `Some(entry)`, look up
`entry.r#type` in `override_candidates` (row 0 if `None`) and use that
as `override_highlight` instead of the computed default. Small,
low-risk change, one call site.

Live preview: the bigger piece. The real "apply" path (`Enter` in
`handle_override_key`) is expensive and stateful — it commits to
`self.overrides` via `activate()`, then runs `render_overrides`, a
*recursive whole-tree* walk (handles nested Any/MessageSet
auto-expansion). Running that on every highlight-move keystroke
(arrow-key autorepeat can fire many events/sec) would be wasteful and
risky (it would mutate the persistent override collection before
you've confirmed anything).

`render_overrides` itself, per-node, bottoms out in a cheaper
primitive: `splice_override(idx, target)` — re-decodes/re-renders
*one* node's payload under a given type (with a render-cache keyed on
`(payload_range, target, field_name)` for repeat-highlight cheapness),
splices the new lines into `self.tree`/`self.lines`, and updates
`self.tree[idx].rendered_as` to record what's now shown — all without
touching `self.overrides` or recursing into children. This is exactly
the right building block for preview: call
`self.splice_override(override_target, tentative_type)` directly on
every override-pane highlight move, entirely bypassing
`OverrideCollection`/`render_overrides`; on `Enter`, no change needed
(the existing `activate()` + `render_overrides()` path is keyed on
`rendered_as` and will just see "already matches, no-op" for the node
the preview already spliced); on `Esc`, revert by re-computing the
same "effective type" `render_overrides` itself would compute for
this node — not just `resolve_active_override_entry`, which alone
misses two things `render_overrides` already accounts for: (i) the
stale-auto-entry check (`auto_entry_in_scope`), which can override an
active-but-stale auto entry back to `None`, and (ii) the fallback to
`natural_type(idx)` (the node's plain schema type), not just `None`,
when nothing is active at all. Correction from an earlier draft of
this note, which described the Esc-revert target too simply — the
actual fix is to factor `render_overrides`'s existing target-
computation block into a small shared helper and call it from both
places, rather than duplicating (or under-approximating) it.

Two things worth flagging before writing a spec: (a) preview only
touches the override target node itself, not nested children — if the
tentatively-previewed type itself contains an Any/MessageSet field,
that nested field's auto-expansion won't show live during preview, only
once `Enter` actually confirms (this matches how the override pane
already only ever showed a flat candidate list for one target node, so
it isn't a new limitation, but worth confirming acceptable); (b) every
highlight move becomes a `splice_override` call, doing real work
(decode + colorize) on a cache miss — no worse than what already
happens once per `Enter` today, just now potentially N times while
browsing candidates; flagging in case you'd rather it debounce/only
fire once movement pauses, rather than on every single keystroke.

=> Confirm the splice_override-based preview approach, and confirm (a)
above (no live nested-preview) is acceptable for a first cut.
=> In the future, we might want a complete preview (beyond just calling splice_override). Then indeed the cost of redrawing might be problematic. In that case I fancy the idea of decoupling rendering from navigation. Meaning: navigating to a new type would trigger a re-rendering, but while this re-rendering happens, the user can continue to navigate freely in the override selection pane. Whenever the user moves to a new type, the in-progress re-rendering is aborted and a new one starts. What do you think of the idea? Is it idiomatic from a generic TUI point of view? In the occurrence, how complex would it be to implement?

[[Yes, idiomatic — this "cancel-in-flight, latest-wins" pattern is the
standard answer to slow live-preview in TUIs/GUIs generally (fzf's own
preview pane, telescope.nvim's picker preview, VS Code's debounced/
cancelled hover-peek, incremental-search highlighting in most editors)
and to slow live-search/autocomplete in general.

Two distinct implementations worth telling apart, different
complexity:

1. Debounce + discard-stale-result (no threads): track a monotonic
   request counter; on each highlight move, bump it and only actually
   *start* the (still synchronous, blocking) render after a short idle
   gap since the last navigation event (e.g. via crossterm's poll
   timeout, which the event loop likely already uses); if the target
   changes again before that gap elapses, the pending request is simply
   replaced, never started. Low complexity — no threads, no shared
   state beyond the counter, small, local change to the override-pane
   key handler. Covers most of the practical benefit (no wasted work
   while arrow-key autorepeat is firing) since protolens' render work
   is pure in-memory decode+colorize (no network/disk I/O in the loop),
   typically fast enough that "don't start until the user pauses" is
   as good as "abort mid-flight."

2. True background-thread cancellation (render actually running
   *while* the user keeps navigating): needs a dedicated worker
   thread/channel, a generation id threaded through to compare against
   on completion (or, for *true* mid-computation abort rather than
   just discarding a late result, cancellation checkpoints sprinkled
   through the recursive render routine itself — Rust threads aren't
   preemptible, so "abort" without checkpoints really just means "run
   to completion, then discard if stale," which is actually option 1's
   outcome, just with the render running concurrently with input
   handling instead of after a pause). Meaningfully higher complexity:
   cross-thread state handoff back into `App` (currently a plain
   synchronous, single-threaded event loop, `&mut self` throughout),
   plus the recursive render routine would need restructuring for
   checkpointed interruption if true early-abort (not just
   discard-on-completion) is the actual goal.

Recommendation: don't build either now — this is future-scoped
("if/when the complete-preview case proves too slow") explicitly, and
even then option 1 (debounce, no threads) is probably sufficient given
protolens' render work has no I/O in the loop; reach for option 2 only
if profiling later shows option 1 isn't enough. Matches this project's
general "minimum complexity for the problem actually in front of us"
convention.
=> Agreed ]]
