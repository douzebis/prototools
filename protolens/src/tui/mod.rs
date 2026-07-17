// SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

//! Minimal v1 navigate + extract slice: single scrollable pane, cursor/fold
//! state, document-order / sibling-skip / parent / child movement, a
//! jumplist, mouse wheel/click, and a vim-style `:extract`/`x` command line
//! — spec 0111 §2/§4, Annex B, Annex C. No override picker yet.

use std::collections::{HashMap, HashSet};
use std::io;
use std::ops::Range;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use crossterm::event::{
    self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEvent, KeyModifiers,
    KeyboardEnhancementFlags, MouseButton, MouseEvent, MouseEventKind, PopKeyboardEnhancementFlags,
    PushKeyboardEnhancementFlags,
};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, supports_keyboard_enhancement, EnterAlternateScreen,
    LeaveAlternateScreen,
};
use ratatui::backend::{Backend, CrosstermBackend};
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Clear, Paragraph};
use ratatui::{Frame, Terminal};

use prototext_core::serialize::render_text::{decode_and_render_indexed, DecodeRenderOpts};

use crate::colorize::{self, SyntaxRole};
use crate::decode::{self, Decoded, DescriptorContext, TreeNode};
use crate::extract::{self, ExtractFormat};
use crate::override_pane::{self, OverrideKind, OverrideOrigin, SortMode};
use crate::render_cache::RenderCache;
use crate::theme::{self, ThemeKind};

/// Fixed horizontal-pan step, in columns (spec 0113 D24) — a generous but
/// simple constant rather than a fraction of the pane's width, so panning
/// speed doesn't change as the pane is resized.
const PAN_STEP: usize = 8;

/// Minimum terminal width (columns) below which `t` refuses to open the
/// override pane (spec 0114 §2) — matches 0111 Annex C's own Phase-5
/// threshold; rendering an unusably narrow split is worse than refusing.
const MIN_OVERRIDE_WIDTH: u16 = 100;

/// Maximum gap between two same-line `Down(MouseButton::Left)` events for
/// the second to count as a double-click (feedback, 2026-07-15) —
/// crossterm reports `Down` identically for single and double clicks, so
/// the app disambiguates them itself by comparing consecutive `Down`
/// timestamps/positions (`App::last_click`).
const DOUBLE_CLICK_THRESHOLD: Duration = Duration::from_millis(500);

/// Whether a click identified by `key` (a main-pane line index, or a
/// manage-pane entry index), arriving now, is the second half of a
/// double-click against `last`'s previously recorded click — same `key`,
/// within `DOUBLE_CLICK_THRESHOLD` — updating `last` to this click either
/// way. Generic form of the main pane's own same-line-within-threshold
/// check (`last_click`/`pending_double_click`, spec-0129-era), reused by
/// the manage pane's radio-marker double-click (2026-07-17 feedback): an
/// alternative to Shift-click, which most terminal emulators intercept
/// for native text selection before it ever reaches the app.
fn is_double_click<T: PartialEq>(last: &mut Option<(Instant, T)>, key: T) -> bool {
    let now = Instant::now();
    let is_double = matches!(
        last,
        Some((t, prev)) if *prev == key && now.duration_since(*t) < DOUBLE_CLICK_THRESHOLD
    );
    *last = Some((now, key));
    is_double
}

/// How long a passive status message stays visible in the shared bottom
/// command/message bar before `track_message_timeout` auto-dismisses it
/// — doesn't apply while that bar is actively serving as a text-entry
/// prompt or a pending `q` quit confirmation (see that function's doc
/// comment).
const MESSAGE_TIMEOUT: Duration = Duration::from_secs(4);

/// Byte budget for `App::candidate_cache` (spec 0114 §6) — tuned generously
/// for a short-lived interactive session: at a rough ~50-70 bytes per
/// cached `(fqdn, score)` entry, this comfortably holds capped previews for
/// hundreds of distinct previously-viewed ranges. Exact cap left as an
/// implementation-time tuning choice (spec Open Issue #1).
const CANDIDATE_CACHE_MAX_BYTES: usize = 1 << 20;

/// Byte budget for `App::render_cache` (spec 0116 §8) — same order of
/// magnitude as `CANDIDATE_CACHE_MAX_BYTES`, its direct structural
/// precedent, for the same short-lived-interactive-session reasoning.
const RENDER_CACHE_MAX_BYTES: usize = 1 << 20;

/// Single source-of-truth command-name registry (spec 0113 D26) — backs
/// both `resolve_command`'s exact-match-wins prefix dispatch and the
/// command line's Tab-completion (`App::start_tab_completion`). Adding a
/// command here is the only step needed for it to get both, automatically.
const COMMANDS: &[&str] = &[
    "extract",
    "type-as",
    "type-as-raw",
    "save-overrides",
    "restore-overrides",
];

/// Filter `candidates` to those starting with `prefix` (spec 0113 D26) — a
/// small generic primitive, not ad hoc to any one caller.
fn complete_prefix<'a>(prefix: &str, candidates: impl Iterator<Item = &'a str>) -> Vec<&'a str> {
    candidates.filter(|c| c.starts_with(prefix)).collect()
}

/// Longest common leading substring of `items` (byte-safe: only cuts at
/// `char` boundaries). Empty if `items` is empty.
fn longest_common_prefix(items: &[&str]) -> String {
    let Some((&first, rest)) = items.split_first() else {
        return String::new();
    };
    let mut end = first.len();
    for item in rest {
        let mut new_end = 0;
        for (a, b) in first.chars().zip(item.chars()) {
            if a != b {
                break;
            }
            new_end += a.len_utf8();
        }
        end = end.min(new_end);
    }
    first[..end].to_string()
}

/// Shared wrap-around search order behind the override- and manage-pane
/// `/`/`?`/`n` commands (`jump_to_override_match`, `jump_to_manage_match`):
/// checks each of the `n` 0-based indices, starting at `start` and moving
/// in `dir`, wrapping around exactly once; returns the first index for
/// which `matches` returns true, or `None` if none did.
fn search_wrap(
    n: usize,
    start: usize,
    dir: SearchDir,
    mut matches: impl FnMut(usize) -> bool,
) -> Option<usize> {
    for d in 0..n {
        let i = match dir {
            SearchDir::Forward => (start + d) % n,
            SearchDir::Backward => (start + n - d) % n,
        };
        if matches(i) {
            return Some(i);
        }
    }
    None
}

/// Shared clamp arithmetic behind the override- and manage-pane highlight
/// movement (`move_override_highlight`, `move_manage_highlight`): moves
/// `current` by `delta`, staying within `0..=max`.
fn clamp_highlight(current: usize, delta: isize, max: usize) -> usize {
    (current as isize + delta).clamp(0, max as isize) as usize
}

/// Shared scroll-to-keep-target-visible arithmetic behind the main,
/// override, and manage panes' own render passes: nudges `*scroll` by the
/// minimum amount needed to keep `target` within the `height`-row visible
/// window. No-op when `height` is `0`.
fn clamp_scroll_to_visible(scroll: &mut usize, target: usize, height: usize) {
    if height == 0 {
        return;
    }
    if target < *scroll {
        *scroll = target;
    } else if target >= *scroll + height {
        *scroll = target + 1 - height;
    }
}

/// Shared pan-by-one-step arithmetic behind Shift+wheel/native
/// ScrollLeft/ScrollRight handling in `handle_mouse` — moves `*offset` by
/// `PAN_STEP`, saturating at `0`.
fn pan_by_step(offset: &mut usize, left: bool) {
    *offset = if left {
        offset.saturating_sub(PAN_STEP)
    } else {
        offset.saturating_add(PAN_STEP)
    };
}

/// Border/title style for a focus-tracked pane (main/override/manage):
/// `theme::focus_style`'s bold accent color when focused,
/// `theme::unfocused_pane_style`'s plain accent otherwise — the visual
/// language protolens uses throughout for "this pane currently holds
/// keyboard focus," shared by `render`'s main-pane block,
/// `render_override_pane`, and `render_manage_pane`. Every bordered
/// pane always uses `BorderType::Rounded` — no built-in `BorderType`
/// combines rounded corners with any other line weight (2026-07-17),
/// so focus is conveyed by color/weight of style alone, not by
/// swapping border glyph sets.
fn pane_focus_style(focused: bool, theme: ThemeKind) -> Style {
    if focused {
        theme::focus_style(theme)
    } else {
        theme::unfocused_pane_style()
    }
}

/// Resolve a typed command `name` against `COMMANDS`, with **exact match
/// always winning over prefix ambiguity** (spec 0114 §7) — matching vim's
/// own `:command` abbreviation convention and `argparse`'s prefix-matching:
/// a command's full name always resolves to itself even when it's also a
/// prefix of another, longer command name.
fn resolve_command(name: &str) -> Result<&'static str, String> {
    if let Some(&exact) = COMMANDS.iter().find(|&&c| c == name) {
        return Ok(exact);
    }
    match complete_prefix(name, COMMANDS.iter().copied()).as_slice() {
        [] => Err(format!("unknown command: {name}")),
        [only] => Ok(*only),
        many => Err(format!("ambiguous command '{name}': {}", many.join(", "))),
    }
}

/// Active Tab-completion cycle state (spec 0113 D26) — `Some` only while
/// consecutive `Tab`/`Shift-Tab` presses are cycling through a candidate
/// list for the same token; any other key clears it (`handle_command_key`).
struct CompletionState {
    /// Char index into `command_buffer` where the completed token begins.
    token_start: usize,
    /// Text originally following the token (preserved verbatim across
    /// cycling, so repeated `Tab` presses don't drift the rest of the
    /// buffer — today always empty, since only the first token, typed at
    /// the buffer's end, is completed).
    suffix: String,
    candidates: Vec<String>,
    /// `None`: showing the longest-common-prefix, no specific candidate
    /// selected yet. `Some(i)`: cycling, currently showing `candidates[i]`.
    index: Option<usize>,
}

/// Search direction for the override pane's in-pane candidate search (spec
/// 0114 §4), vim-style `/` (forward) / `?` (backward).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SearchDir {
    Forward,
    Backward,
}

/// One row of the override management pane's grouped-by-origin listing:
/// an origin's own (unindented, non-selectable) header row, or one of its
/// candidate types (an index into `overrides.entries()`, indented under
/// the header — spec 0117 §3 amendment: origin kind is dropped from the
/// display since it's implicit from the origin's own format, and each
/// origin's types are grouped under a dedicated header line instead of
/// repeating the origin on every row).
enum ManageRow {
    Header(String),
    Entry(usize),
}

/// What the shared `command_buffer`/`command_cursor` text-entry state
/// currently represents (spec 0114 §4, extended to the main pane, override
/// pane, and management pane): a `:`/`x`-triggered ex-command, or a `/`/`?`
/// search pattern. They differ only in how `Enter` is interpreted and
/// whether Tab-completion applies — `Search`'s direction doubles as the
/// direction the pattern was originally requested in. Which pane's search
/// a confirmed `Search` pattern actually runs against is determined at
/// `Enter`-time from `self.override_focus`/`self.manage_focus`, not
/// carried in this enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CommandLineKind {
    Command,
    Search(SearchDir),
}

/// Static key-binding reference shown by the `F1` help overlay (spec 0111
/// Annex C, spec 0113 D22) — kept as one flat text block rather than
/// generated from the `handle_key` match arms, so it can be phrased for
/// readability independent of the code's own binding order.
const HELP_TEXT: &[&str] = &[
    "protolens — key bindings",
    "",
    "Movement",
    "  j / Down         next node (document order)",
    "  k / Up           previous node",
    "  J / Shift-Down   next sibling",
    "  K / Shift-Up     previous sibling",
    "  h / Left         close node, or move to parent",
    "  l / Right        open node, or move to first child",
    "  Home / gg        jump to first node",
    "  End / G          jump to last visible node",
    "  PageDown         scroll down one page",
    "  PageUp           scroll up one page",
    "  Ctrl-Left        pan main pane left",
    "  Ctrl-Right       pan main pane right",
    "  Shift+wheel / native horizontal scroll",
    "                   pan whichever pane (main, override, manage, or",
    "                   the command bar) the mouse is hovering",
    "  drag (main pane) select whole lines; release copies them to the",
    "                   OS clipboard; Esc clears the selection",
    "",
    "Fold / unfold",
    "  z / Space        toggle fold on the node under the cursor",
    "  H / Shift-Left   fold all siblings at this level",
    "  Shift-Right      unfold all siblings at this level",
    "",
    "Display",
    "  a                toggle main-pane #@ annotation display",
    "",
    "Navigation history",
    "  Ctrl-O           jump back",
    "  Ctrl-I           jump forward",
    "",
    "Extract",
    "  x                open the extract command line (prefilled",
    "                   \"extract \")",
    "  :extract [--binary|--text] <path>",
    "                   extract the cursor node to <path> — default",
    "                   format is #@ prototext text",
    "",
    "Command line",
    "  Tab              complete the command name (longest common prefix,",
    "                   then cycle through matches)",
    "  Shift-Tab        cycle backward through matches",
    "",
    "Search (main pane, requires main-pane focus)",
    "  /                search forward for a pattern (matches against the",
    "                   current, possibly-overridden rendering)",
    "  ?                search backward",
    "  n                repeat the last search, same direction",
    "  (confirming / or ? with no typed pattern reuses the last one)",
    "",
    "Override pane",
    "  t                open/close the override pane for the message/",
    "                   group node under the cursor",
    "  Tab              move focus between the main pane and the",
    "                   override pane (while it is open)",
    "  a                toggle candidate sort: inferred score (default)",
    "                   or alphanumeric",
    "  /  ?  n          search / search backward / repeat (pane focused)",
    "  j/k, PageUp/Down, Home/End   move the highlighted candidate",
    "                   (pane focused)",
    "  Enter            apply the highlighted type (pane focused) and",
    "                   close the pane; also records the override in the",
    "                   collection (see \"Override management\" below)",
    "  Esc              cancel and close the override pane",
    "  :type-as <FQDN>  apply <FQDN> as the cursor node's type override,",
    "                   bypassing the pane",
    "  :type-as-raw     mark the cursor node's range as explicitly raw/",
    "                   unschema'd, bypassing the pane",
    "",
    "Override management",
    "  o                open/close the override management pane (closes",
    "                   the override pane, if open)",
    "  Enter            close the management pane",
    "  Tab              move focus between the main pane and the",
    "                   management pane (while it is open)",
    "  j/k, PageUp/Down, Home/End   move the highlighted entry",
    "  Shift-Up / Shift-Down        move the highlighted entry and",
    "                   activate the destination (deactivating any",
    "                   other entry sharing its origin)",
    "  Left/Right       move the main-pane cursor to the prev/next field",
    "                   affected by the highlighted entry (wraps around)",
    "  /  ?  n          search / search backward / repeat",
    "  a / Space        toggle the highlighted entry active/inactive",
    "  A / Shift-Space  same, but also cascades the new state to every",
    "                   entry whose origin sits at-or-under it (a",
    "                   descendant path, or a path-field/fqdn-field at",
    "                   the same path); when several entries would",
    "                   activate under one origin, only the first",
    "                   (sorted) one does — Shift-Space needs terminal",
    "                   support (Kitty keyboard protocol); also",
    "                   available as Shift-click or double-click on an",
    "                   entry's marker",
    "  z / Z            rotate the highlighted entry's origin kind",
    "                   forward/backward: path, path-field, fqdn-field;",
    "                   auto-resolves from the fields the entry affects,",
    "                   falling back to the main-pane cursor/message line",
    "                   when ambiguous; repeating z/Z with the cursor",
    "                   unchanged advances to the next kind instead of",
    "                   getting stuck",
    "  d / Delete / Backspace  remove the highlighted entry from the",
    "                   collection (an auto-derived entry still in scope",
    "                   is deactivated instead, since deleting it would",
    "                   just recreate it)",
    "  D                duplicate the highlighted entry (the copy starts",
    "                   inactive and is always manual, even if the",
    "                   original was auto-derived)",
    "  entry rows: auto-derived entries are plain, manual entries bold",
    "  s                pre-fill \":save-overrides <default path>\"",
    "  r                pre-fill \":restore-overrides \"",
    "  :save-overrides <path>",
    "                   write the whole override collection to <path>",
    "                   as YAML",
    "  :restore-overrides <path>",
    "                   replace the override collection wholesale with",
    "                   <path>'s contents (entries that no longer",
    "                   resolve are silently dropped; a target-hash",
    "                   mismatch warns but does not block)",
    "  Tab              complete a filesystem path (save-overrides/",
    "                   restore-overrides argument)",
    "  (management-pane actions never change the current rendering —",
    "  only Enter in the override pane does)",
    "",
    "Other",
    "  F1               toggle this help",
    "  q                quit (press again to confirm)",
    "  Ctrl-Z           suspend (fg to resume) — Unix only",
    "",
    "j/k or PageUp/PageDown scroll this help; q, Esc, or F1 closes it.",
];

/// Owns all cursor/fold/scroll/jumplist state — kept separate from
/// `render()`'s drawing calls (spec 0111 §4, ratatui testability pattern).
pub struct App {
    /// Wrapped blob actually decoded (spec 0114 §1.1) — needed for binary
    /// extraction (`ExtractFormat::Binary` slices `NodeSpan::raw_range`
    /// from this, since every `raw_range` is relative to *this* blob, not
    /// the caller's original one).
    blob: Vec<u8>,
    /// Width in bytes of the wrapper's own tag+length prefix (spec 0114
    /// §1.1) — subtracted from any displayed `raw_range` coordinate to
    /// recover the caller's original (pre-wrap) numbering.
    wrapper_offset: usize,
    /// Original blob's own path — basis for `default_extract_path()`'s
    /// proposed `:extract`/`x` default path.
    blob_path: PathBuf,
    /// Whether the main pane currently shows each line's trailing `#@ ...`
    /// annotation (spec 0133) — a pure *display* attribute, toggled by the
    /// `a` key, decoupled from the underlying `lines`/`line_styles`, which
    /// always carry full annotations regardless of this flag.
    annotations: bool,
    /// Indentation step (spaces per nesting level) this session was decoded
    /// with — reused by `apply_override` (spec 0114 §5) so a splice
    /// re-render matches the rest of the document's own indentation.
    indent_size: usize,
    lines: Vec<String>,
    /// Syntax-highlighting spans (spec 0116 §7), index-parallel to `lines`
    /// — each entry holds that line's `(column range, role)` pairs.
    /// Spliced in lockstep with `lines` by `apply_override`, so no
    /// separate offset-shifting bookkeeping is needed.
    line_styles: Vec<Vec<(Range<usize>, SyntaxRole)>>,
    /// Resolved color theme (spec 0116 §9) — fixed for the session, never
    /// `ThemeKind::System` (resolved once in `main.rs` before `App::new`).
    theme: ThemeKind,
    tree: Vec<TreeNode>,
    /// Line index (in `lines`) -> node index, for nodes whose text starts
    /// on that line. Used for the fold-indicator gutter.
    line_to_node: HashMap<usize, usize>,
    /// Line index -> node index, for message/group nodes' own closing
    /// (`}`) line (`text_range.end - 1`) — the counterpart to
    /// `line_to_node`'s opening-line mapping, both maintained in lockstep
    /// at the same two sites (`App::new`, `splice_override`'s rebuild).
    /// Used by spec 0113 D33's bold override hint, which needs to
    /// recognize a node's own closing line as directly "its own" (not a
    /// descendant's), the same way `line_to_node` already recognizes its
    /// own opening line.
    footer_line_to_node: HashMap<usize, usize>,
    cursor: usize,
    /// Incremented every time `self.cursor` changes (via `set_cursor`),
    /// regardless of whether the new value differs from any prior one —
    /// a real "did the cursor move since X" signal (spec-0117-adjacent
    /// `z`/`Z` rework, 2026-07-16 feedback), since comparing `self.
    /// cursor`'s current value against a stashed old value alone misses
    /// a round trip (e.g. Down then Up) that leaves the position
    /// numerically unchanged but is still a real move.
    cursor_moves: u64,
    /// Mouse-driven whole-line selection in the main pane (spec 0129
    /// §G1) — `line_idx` of the row a drag started on; `None` when no
    /// selection is active. Never affects `self.cursor`, which only ever
    /// moves via the initial `Down` click (`handle_click`, unchanged).
    select_anchor: Option<usize>,
    /// `line_idx` of the row the drag is currently over (or ended on);
    /// `None`/`None` together with `select_anchor` means no selection.
    /// Equal to `select_anchor` for a plain click with no drag.
    select_end: Option<usize>,
    /// Timestamp + `line_idx` of the most recent main-pane left-click
    /// `Down` event (feedback, 2026-07-15) — compared against on the next
    /// `Down` to recognize a double-click (same line, within
    /// `DOUBLE_CLICK_THRESHOLD`). `None` before the first click.
    last_click: Option<(Instant, usize)>,
    /// Whether the click currently in progress (`Down` already handled,
    /// matching `Up` not yet seen) was recognized as the second click of
    /// a double-click — consulted by the `Up` handler to decide whether a
    /// plain (non-dragged) click should deselect (`false`, the default)
    /// or keep the single-line selection `Down` just set (`true`).
    pending_double_click: bool,
    folded: HashSet<usize>,
    /// Rows currently visible (line indices in `lines`, folded-away lines
    /// excluded) — rebuilt only on fold-state changes, not every frame.
    visible_rows: Vec<usize>,
    scroll_offset: usize,
    /// Horizontal scroll offset (in characters) for the main pane (spec
    /// 0113 D24) — the whole rendered line (fold-marker gutter included)
    /// pans together, the simplest of the layout options the spec left
    /// open.
    pan_offset: usize,
    /// Horizontal scroll offset (in characters) for the override
    /// selection pane's rows (spec 0127 §G1) — reset to `0` whenever the
    /// pane (re)opens or its candidate list is recomputed, mirroring how
    /// `override_scroll` (vertical) is already reset at those points.
    override_pan_offset: usize,
    /// Horizontal scroll offset (in characters) for the override
    /// management pane's rows (spec 0127 §G1) — reset to `0` whenever the
    /// pane (re)opens or its entry list changes in a way that already
    /// resets `manage_scroll` (vertical).
    manage_pan_offset: usize,
    /// Horizontal scroll offset (in characters) for the bottom command/
    /// message bar (spec 0127 §G1) — while a command/search/rename buffer
    /// is being typed, `render` auto-adjusts this to keep the cursor
    /// visible (mirroring the main pane's cursor-follow vertical scroll);
    /// otherwise it only changes via Shift+wheel/native horizontal-scroll
    /// pan on the hovered command bar.
    command_pan_offset: usize,
    /// `Some(node_idx)` while the override pane is open, holding the
    /// message/group node whose byte range it targets (spec 0114 §1/§2);
    /// `None` when closed.
    override_target: Option<usize>,
    /// `true` when the override pane has focus (spec 0114 §3's `Tab`
    /// toggle); meaningless while `override_target` is `None`.
    override_focus: bool,
    /// Type-lookup/scoring context (spec 0114 §3) — owned by `App` after
    /// `decode()` returns it, so the override pane can resolve/score
    /// candidate types for the rest of the session.
    ctx: DescriptorContext,
    /// Session-global, alphabetically-sorted list of every message/group
    /// type FQDN known to `ctx.pool()` (spec 0114 §3.2/§6) — independent
    /// of range, computed once in `App::new`, reused by every
    /// lexicographic sort and by `:type-as`'s FQDN Tab-completion (spec
    /// 0114 §7).
    all_type_fqdns: Vec<String>,
    /// Sort mode for the override pane's ranked candidates (spec 0114
    /// §3.2) — persists across successive `t` invocations for the session
    /// (§8's key-bindings table).
    override_sort: SortMode,
    /// Ranked candidates (excluding the pinned `<raw / no type>` entry —
    /// §3.1) for whichever range `override_target` currently names, in
    /// the currently active `override_sort` order — FQDN plus its
    /// inferred score (`None` in lexicographic mode, which computes no
    /// score).
    override_candidates: Vec<(String, Option<i64>)>,
    /// Highlighted row within the override pane: `0` is the pinned
    /// `<raw / no type>` entry; `1..=override_candidates.len()` is
    /// `override_candidates[row - 1]`.
    override_highlight: usize,
    /// Scroll offset (in rows, the pinned raw entry included) for the
    /// override pane's candidate list.
    override_scroll: usize,
    /// Last confirmed in-pane search (direction, pattern) — `n` repeats it
    /// in the same direction.
    last_override_search: Option<(SearchDir, String)>,
    /// Full terminal width (columns) as of the last `render()` call —
    /// basis for the override pane's minimum-width refusal (spec 0114
    /// §2), since `main_area`'s own width shrinks once the pane is open.
    term_width: u16,
    /// Override pane's candidate-list visible row count as of the last
    /// `render_override_pane()` call — basis for `PageUp`/`PageDown`
    /// scrolling by a full page, mirroring `main_area` (used the same way
    /// for the main pane's own `PageUp`/`PageDown`).
    override_list_height: usize,
    /// Byte-bounded MRU cache of capped inferred-candidate previews for
    /// ranges other than the one currently active (spec 0114 §6).
    candidate_cache: override_pane::CandidateCache,
    /// Byte-bounded MRU cache of `(range, type) -> (lines, spans, style
    /// hints)` renders (spec 0116 §8) — consulted/populated by
    /// `apply_override`, keyed by the same `payload_range`/type pair
    /// `candidate_cache` already keys on.
    render_cache: RenderCache,
    /// The tag/length-stripped target range whose complete-or-capped
    /// inferred-candidate list `override_inferred_raw` currently holds —
    /// `None` when no override pane is open, or the graph-less/
    /// lexicographic-only case. Distinct from `override_target` (a tree
    /// node index): this is the byte range that list was computed for.
    active_override_range: Option<Range<usize>>,
    /// Raw `(fqdn, score)` list for `active_override_range`, source of
    /// truth `override_candidates` is derived from in `SortMode::Inferred`
    /// — either the complete ranked list, or (right after a
    /// `candidate_cache` hit) a capped preview, per
    /// `override_candidates_complete`.
    override_inferred_raw: Vec<(String, i64)>,
    /// Whether `override_inferred_raw` is the complete ranked list for
    /// `active_override_range`, or just a capped preview pulled from
    /// `candidate_cache` — an incomplete preview is upgraded to the
    /// complete list (a fresh `score_all` call) the moment the user tries
    /// to scroll past it (spec 0114 §6).
    override_candidates_complete: bool,
    /// Persistent collection of overrides (spec 0117 §1) — distinct from,
    /// and unrelated to, the one-shot `apply_override` splice-render
    /// mechanism above; see spec 0117's Non-goals.
    overrides: override_pane::OverrideCollection,
    /// `true` while the override management pane (spec 0117 §3, `o`) is
    /// open. Mutually exclusive with `override_target.is_some()`.
    manage_open: bool,
    /// `true` when the management pane has focus (mirroring
    /// `override_focus`); meaningless while `manage_open` is `false`.
    /// A main-pane mouse click while the pane stays open shifts this
    /// back to `false` without closing it (2026-07-14 feedback).
    manage_focus: bool,
    /// Highlighted row (index into `overrides.entries()`) in the
    /// management pane.
    manage_highlight: usize,
    /// Scroll offset (in rows) for the management pane's listing.
    manage_scroll: usize,
    /// Timestamp + entry index of the most recent left-click `Down` that
    /// landed on an entry's radio marker (2026-07-17 feedback) — compared
    /// against on the next such click to recognize a double-click (same
    /// entry, within `DOUBLE_CLICK_THRESHOLD`), the mouse-only
    /// alternative to Shift-click for `toggle_active_cascading` (most
    /// terminal emulators intercept Shift-click for native text
    /// selection before it ever reaches the app). `None` before the
    /// first marker click.
    last_manage_click: Option<(Instant, usize)>,
    /// Last confirmed management-pane in-pane search — `n` repeats it.
    last_manage_search: Option<(SearchDir, String)>,
    /// `Some` while `f` in the management pane is editing the highlighted
    /// entry's display-name override (spec 0119 G4) — pre-filled with its
    /// current `name` (empty if `None`), mutually exclusive with an
    /// in-progress `command_buffer` search.
    manage_rename: Option<String>,
    /// `Some((origin, kind, cursor_moves))` while a `z`/`Z` attempt in
    /// the management pane is unresolved (spec 0134 G2/G3): `origin` is
    /// the highlighted entry's origin at the time of that attempt,
    /// `kind` is the `OverrideKind` it evaluated, and `cursor_moves` is
    /// `self.cursor_moves`'s value at that time. A same-direction `z`/
    /// `Z` press with `self.cursor_moves` still equal to the stashed
    /// value (i.e. the cursor genuinely hasn't moved since — not just
    /// "ended up at the same position," which a Down-then-Up round trip
    /// would falsely satisfy) advances past `kind`; otherwise it retries
    /// `kind`. Cleared on every successful rotation and whenever
    /// `manage_highlight` moves to a different entry.
    manage_pending_kind: Option<(OverrideOrigin, OverrideKind, u64)>,
    /// Management pane's visible row count as of the last
    /// `render_manage_pane()` call — basis for `PageUp`/`PageDown`.
    manage_list_height: usize,
    back_stack: Vec<usize>,
    fwd_stack: Vec<usize>,
    /// Document-order first node — `Home`/`gg` target.
    first_node: usize,
    /// Set by a first `g` press, consumed (and cleared) by a second `g`
    /// press within the very next keystroke (`gg` chord, vim-style); any
    /// other key clears it.
    pending_g: bool,
    /// `Some(buffer)` while a `:`/`x`-triggered command line, or a `/`/`?`
    /// main-pane search prompt (spec 0114 §4, extended from the override
    /// pane — see `CommandLineKind`), is being edited; `None` in normal
    /// navigation mode.
    command_buffer: Option<String>,
    /// What `command_buffer` currently represents; meaningless while
    /// `command_buffer` is `None`.
    command_kind: CommandLineKind,
    /// Cursor position within `command_buffer`, as a **char** index (not
    /// byte index) — `0..=command_buffer.chars().count()`. Moved by
    /// `Left`/`Right`/`Home`/`End`; edits (`Backspace`/`Delete`/typing)
    /// happen relative to it rather than always at the buffer's end.
    command_cursor: usize,
    /// Last confirmed main-pane in-pane search (direction, pattern) — `n`
    /// repeats it in the same direction; an empty `/`/`?` confirmation
    /// reuses the pattern (spec 0114 §4, mirroring `last_override_search`).
    last_search: Option<(SearchDir, String)>,
    /// Active Tab-completion cycle state (spec 0113 D26); `None` when not
    /// currently cycling.
    completion: Option<CompletionState>,
    /// `true` on startup until the first keypress dismisses it — a splash
    /// screen telling the user how to reach help (spec 0113 D22).
    splash: bool,
    /// `true` while the `F1` help overlay is open.
    help_open: bool,
    /// Scroll offset (in `HELP_TEXT` lines) while the help overlay is open.
    help_scroll: usize,
    /// Help overlay's inner (bordered-away) `Rect` as of the last
    /// `render_help()` call (feedback, 2026-07-15) — used to hit-test
    /// mouse wheel/Shift-wheel events against the overlay instead of
    /// letting them fall through to whichever pane it happens to be
    /// drawn on top of. Only meaningful while `help_open`.
    help_area: Rect,
    header: String,
    /// Main pane's inner (bordered-away) `Rect` as of the last `render()`
    /// call — used to hit-test mouse clicks against display rows/columns.
    main_area: Rect,
    /// Override selection pane's / override management pane's inner
    /// `Rect` as of the last render (spec 0113 D30) — used to hit-test
    /// mouse clicks the same way `main_area` does. A single field
    /// suffices since the two panes are mutually exclusive
    /// (`override_target.is_some()` XOR `manage_open`).
    side_area: Rect,
    /// Bottom command/message bar's inner (bordered-away) `Rect` as of
    /// the last `render()` call, `None` when the bar isn't shown at all
    /// (spec 0127 §G2) — used to hit-test mouse hover for Shift+wheel/
    /// native horizontal pan the same way `main_area`/`side_area` do.
    cmd_area: Option<Rect>,
    pub message: String,
    /// Mirrors `self.message` as of the last `track_message_timeout()`
    /// call — used to detect a freshly-set message (`self.message` has
    /// no dedicated setter; it's assigned directly all over this file),
    /// so `message_deadline` gets (re)armed exactly once per message,
    /// not on every frame.
    last_message_seen: String,
    /// Wall-clock time at which the current `self.message` should be
    /// auto-dismissed, `None` while `self.message` is empty. Consulted
    /// (and cleared) only by `track_message_timeout`, which never fires
    /// while a text-entry prompt (`command_buffer`/`manage_rename`) or a
    /// pending `q` quit confirmation is actively awaiting a keypress.
    message_deadline: Option<Instant>,
    pub should_quit: bool,
    /// `true` right after a first `q` press asks for confirmation; a
    /// second `q` press (any mode) actually quits, any other key cancels.
    /// Checked centrally at the top of `handle_key`, ahead of every other
    /// dispatch, so it applies uniformly regardless of focus.
    quit_confirm: bool,
    /// `true` right after `Ctrl-Z` (spec 0113 D31, Unix only), checked by
    /// `run_loop` after each `handle_key` call — mirrors `should_quit`'s
    /// own "flag set here, acted on there" split, since actually
    /// suspending the process needs the `Terminal` handle that only
    /// `run_loop` owns.
    pub should_suspend: bool,
}

impl App {
    pub fn new(
        decoded: Decoded,
        blob_label: &str,
        blob_path: PathBuf,
        indent_size: usize,
        ctx: DescriptorContext,
        theme: ThemeKind,
    ) -> Self {
        let all_type_fqdns = override_pane::all_type_fqdns(ctx.pool());
        let mut line_to_node = HashMap::new();
        let mut footer_line_to_node = HashMap::new();
        for (idx, node) in decoded.tree.iter().enumerate() {
            line_to_node.insert(node.span.text_range.start, idx);
            if node.first_child.is_some() {
                footer_line_to_node.insert(node.span.text_range.end - 1, idx);
            }
        }
        let header = format!("protolens — {blob_label} — {}", decoded.root_type);
        // Document-order first node (doc_prev == None) — not array index 0,
        // which is post-order (see decode::TreeNode's doc comment).
        let cursor = decoded
            .tree
            .iter()
            .position(|n| n.doc_prev.is_none())
            .unwrap_or(0);
        // Spec 0117 §1: seed the root `path` override with whatever type
        // was explicitly requested or inferred; if neither is available,
        // seed nothing at all — an untyped root has no override worth
        // recording, and the collection is legitimately empty until the
        // user adds one. `decode::decode` uses the "<raw / no type>"
        // sentinel for the "neither" case rather than an `Option`.
        let root_override_type = if decoded.root_type == "<raw / no type>" {
            None
        } else {
            Some(decoded.root_type.clone())
        };
        let mut overrides = override_pane::OverrideCollection::new();
        if root_override_type.is_some() {
            overrides.seed_root(root_override_type.clone());
        }
        let mut app = App {
            blob: decoded.blob,
            wrapper_offset: decoded.wrapper_offset,
            blob_path,
            // Always on (spec 0133): a pure main-pane display attribute
            // from here on, toggled at runtime by the `a` key.
            annotations: true,
            indent_size,
            lines: decoded.lines,
            line_styles: decoded.style_hints,
            theme,
            tree: decoded.tree,
            line_to_node,
            footer_line_to_node,
            cursor,
            cursor_moves: 0,
            select_anchor: None,
            select_end: None,
            last_click: None,
            pending_double_click: false,
            folded: HashSet::new(),
            visible_rows: Vec::new(),
            scroll_offset: 0,
            pan_offset: 0,
            override_pan_offset: 0,
            manage_pan_offset: 0,
            command_pan_offset: 0,
            override_target: None,
            override_focus: false,
            ctx,
            all_type_fqdns,
            override_sort: SortMode::Inferred,
            override_candidates: Vec::new(),
            override_highlight: 0,
            override_scroll: 0,
            last_override_search: None,
            term_width: 0,
            override_list_height: 0,
            candidate_cache: override_pane::CandidateCache::new(CANDIDATE_CACHE_MAX_BYTES),
            render_cache: RenderCache::new(RENDER_CACHE_MAX_BYTES),
            active_override_range: None,
            override_inferred_raw: Vec::new(),
            override_candidates_complete: false,
            overrides,
            manage_open: false,
            manage_focus: false,
            manage_highlight: 0,
            manage_scroll: 0,
            last_manage_click: None,
            last_manage_search: None,
            manage_rename: None,
            manage_pending_kind: None,
            manage_list_height: 0,
            back_stack: Vec::new(),
            fwd_stack: Vec::new(),
            first_node: cursor,
            pending_g: false,
            command_buffer: None,
            command_kind: CommandLineKind::Command,
            command_cursor: 0,
            last_search: None,
            completion: None,
            splash: true,
            help_open: false,
            help_scroll: 0,
            help_area: Rect::default(),
            header,
            main_area: Rect::default(),
            side_area: Rect::default(),
            cmd_area: None,
            message: String::new(),
            last_message_seen: String::new(),
            message_deadline: None,
            should_quit: false,
            quit_confirm: false,
            should_suspend: false,
        };
        // Spec 0118 §2.1: the wrapper root is already rendered under
        // `root_override_type` by `decode()` itself, matching the
        // `seed_root` entry above (when one was seeded) — mark it as
        // such so the first `render_overrides` pass doesn't treat it as
        // a mismatch and needlessly re-splice the entire tree (which
        // would invalidate every already-computed node index: `cursor`,
        // `folded`, etc.). When no entry was seeded (untyped root), the
        // outer `Option` must be `None` — matching what
        // `resolve_active_override` will itself compute ("no active
        // entry") — not `Some(None)` ("an active entry explicitly says
        // raw"), else the first pass would wrongly conclude nothing
        // needs resettling should the user later seed a real entry.
        if let Some(node) = app.tree.get_mut(cursor) {
            // The root's own field name is always "1" (its field number
            // in the virtual encompassing message — mirrors
            // `field_name_for`'s no-parent case), and can't yet carry a
            // §G4 name override at this point (the collection was just
            // seeded, nothing has been renamed).
            node.rendered_as = Some((root_override_type.clone().map(Some), "1".to_string()));
        }
        // Spec 0120: Any/MessageSet auto-expansion is computed by
        // `render_overrides` itself (`auto_expand_type`), not by
        // `decode()`'s own initial paint — run one pass now so the
        // initial view already shows any/MessageSet content expanded,
        // matching the pre-spec-0120 behavior where `decode()` expanded
        // it directly via prototext-core. Guarded like the block above:
        // an empty tree has no node at `cursor` to render.
        if !app.tree.is_empty() {
            app.render_overrides(cursor);
        }
        app.rebuild_visible_rows();
        app
    }
}

/// Standard ratatui popup-centering recipe: an `area`-relative `Rect`
/// `percent_x`% wide and `percent_y`% tall, centered within `area`.
fn centered_rect(percent_x: u16, percent_y: u16, area: Rect) -> Rect {
    let vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(area);
    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(vertical[1])[1]
}

/// Fills the gaps between `hints` (sorted, non-overlapping byte ranges
/// into `content`) with `None`-tagged segments, so the result covers all
/// of `content` — the input `App::spans_with_insertions` needs to build a
/// complete `Vec<Span>` for a line (spec 0116 §7).
fn segment_line(
    content: &str,
    hints: &[(Range<usize>, SyntaxRole)],
) -> Vec<(Range<usize>, Option<SyntaxRole>)> {
    let mut segments = Vec::new();
    let mut pos = 0;
    for (range, role) in hints {
        if range.start > pos {
            segments.push((pos..range.start, None));
        }
        segments.push((range.clone(), Some(*role)));
        pos = range.end;
    }
    if pos < content.len() {
        segments.push((pos..content.len(), None));
    }
    segments
}

/// Drop the leading `offset` characters of the rendered line (spec 0113
/// D24's horizontal pan, composed with spec 0116 §7's syntax
/// highlighting) — skips `offset` characters across the whole span
/// sequence, trimming (not dropping the style of) whichever span the
/// skip boundary lands inside. The remainder is left for
/// `ratatui::Paragraph` to clip to the pane's width as usual, same as an
/// un-panned line.
fn pan_spans(spans: Vec<Span<'static>>, offset: usize) -> Vec<Span<'static>> {
    if offset == 0 {
        return spans;
    }
    let mut remaining = offset;
    let mut result = Vec::new();
    for span in spans {
        let char_count = span.content.chars().count();
        if remaining >= char_count {
            remaining -= char_count;
            continue;
        }
        let trimmed: String = span.content.chars().skip(remaining).collect();
        remaining = 0;
        result.push(Span::styled(trimmed, span.style));
    }
    result
}

/// Spec 0129 §G2/0131 §G2: write `text` to the real OS clipboard (plain
/// text only, no ANSI/colors). If `arboard` fails (e.g. no X11/Wayland
/// clipboard provider available, the common case over plain SSH),
/// additionally emits an OSC 52 escape sequence to stdout, best-effort —
/// a terminal-level (not X-server) fallback that many terminal
/// emulators honor transparently over SSH. The original `arboard`
/// error is still returned either way, so a caller distinguishing
/// "confirmed via arboard" from "best-effort via OSC 52" still can.
fn copy_to_clipboard(text: &str) -> Result<(), arboard::Error> {
    let result = arboard::Clipboard::new().and_then(|mut clipboard| clipboard.set_text(text));
    if result.is_err() {
        emit_osc52_copy(text);
    }
    result
}

/// Spec 0131 §G2: emit `ESC ]52;c;{base64(text)}\x07` to stdout — the
/// OSC 52 clipboard-set sequence. No error is surfaced from this: there
/// is no terminal handshake/ack for OSC 52, so whether it was actually
/// honored can never be confirmed either way.
fn emit_osc52_copy(text: &str) {
    use base64::Engine;
    use std::io::Write;
    let encoded = base64::engine::general_purpose::STANDARD.encode(text.as_bytes());
    let _ = write!(std::io::stdout(), "\x1b]52;c;{encoded}\x07");
    let _ = std::io::stdout().flush();
}

/// Column where a fold marker is inserted by `App::render_line_content` —
/// right after the line's own leading indentation (column 0 for an
/// unindented, root-level line).
fn marker_column(line: &str) -> u16 {
    let indent_len = line.len() - line.trim_start().len();
    indent_len as u16
}

/// Drain any input events already queued in the terminal's input buffer
/// before disabling raw mode (feedback, 2026-07-16).
///
/// `EnableMouseCapture` always turns on any-motion reporting (crossterm
/// gives no way to opt out short of hand-rolling the escape sequences — see
/// the comment on `handle_mouse`'s `Moved` guard), so a mouse move happening
/// in the split second between the app's last `event::read()` and raw mode
/// being disabled here would otherwise sit unread in the pty's input queue.
/// Once cooked-mode echo comes back on, the tty driver echoes those queued
/// bytes straight to the screen as raw escape-sequence garbage (e.g.
/// `^[[<35;60;17M`) that the shell then needs an Enter/Ctrl-C to clear.
/// Reading them here, while raw mode (no echo) is still active, discards
/// them silently instead.
fn drain_pending_input() {
    let deadline = Instant::now() + Duration::from_millis(60);
    while Instant::now() < deadline {
        match event::poll(Duration::from_millis(15)) {
            Ok(true) => {
                let _ = event::read();
            }
            _ => break,
        }
    }
}

/// Set by `push_keyboard_enhancement` once it has actually pushed Kitty
/// keyboard-protocol enhancement flags, so `pop_keyboard_enhancement`
/// knows whether the matching pop is needed — `restore_terminal`/
/// `suspend` are free functions with no `App` to carry this as ordinary
/// state, and popping when nothing was pushed would either do nothing
/// (unsupported terminals just ignore the unknown escape sequence) or,
/// worse, pop a flag set some other way. Single-threaded (one terminal,
/// one event loop), so `Ordering::Relaxed` is enough.
static KITTY_KEYBOARD_ENHANCED: AtomicBool = AtomicBool::new(false);

/// Push `DISAMBIGUATE_ESCAPE_CODES` (Kitty keyboard protocol) if the
/// terminal supports it (2026-07-17 feedback) — without it, legacy
/// terminal escape sequences carry no modifier parameter for printable
/// keys, so Shift-Space is reported identically to plain Space (unlike
/// arrow/function keys, which already carry one, e.g. `ESC [1;2A` for
/// Shift-Up). `supports_keyboard_enhancement` queries the terminal and
/// blocks briefly waiting for its response — fine here since it only
/// ever runs before the main event loop starts (`run`) or during a
/// suspend/resume cycle (`suspend`), never concurrently with
/// `event::read`/`poll`. Terminals that don't support it are left
/// exactly as before (no-op): `handle_manage_key`'s guarded
/// `Char(' ') if SHIFT` arm simply never fires there, same as today.
fn push_keyboard_enhancement() -> io::Result<()> {
    if supports_keyboard_enhancement().unwrap_or(false) {
        execute!(
            io::stdout(),
            PushKeyboardEnhancementFlags(KeyboardEnhancementFlags::DISAMBIGUATE_ESCAPE_CODES)
        )?;
        KITTY_KEYBOARD_ENHANCED.store(true, Ordering::Relaxed);
    }
    Ok(())
}

/// Undo `push_keyboard_enhancement`, if it actually pushed anything.
fn pop_keyboard_enhancement() {
    if KITTY_KEYBOARD_ENHANCED.swap(false, Ordering::Relaxed) {
        let _ = execute!(io::stdout(), PopKeyboardEnhancementFlags);
    }
}

/// Restore the terminal to its normal (cooked, main-screen, no mouse
/// capture) state — shared by `run`'s own cleanup and the panic hook below,
/// so a panic mid-session doesn't leave the user's terminal unusable.
fn restore_terminal() {
    drain_pending_input();
    pop_keyboard_enhancement();
    let _ = disable_raw_mode();
    let _ = execute!(io::stdout(), LeaveAlternateScreen, DisableMouseCapture);
}

/// `Ctrl-Z` suspend (spec 0113 D31): leave the terminal in the same clean
/// state a normal exit would (mirroring `restore_terminal`/the panic
/// hook), raise `SIGTSTP` on this process, and — once `fg` sends
/// `SIGCONT` and execution resumes right here — re-enter the alternate
/// screen/mouse-capture/raw-mode trio and force a full redraw, since the
/// terminal's actual contents are unknown after a suspend/resume cycle
/// (another program may have used the same terminal in between).
#[cfg(unix)]
fn suspend<B: Backend>(terminal: &mut Terminal<B>) -> io::Result<()>
where
    io::Error: From<B::Error>,
{
    restore_terminal();
    // `Terminal::draw()` hides the hardware cursor unless the render
    // callback calls `Frame::set_cursor_position()` — which protolens never
    // does — so the last `draw()` call before this suspend left it hidden.
    // Without this, the shell prompt gets no visible cursor after `fg`
    // (feedback, 2026-07-16).
    terminal.show_cursor()?;
    // SAFETY: raising a signal on our own process is always sound.
    unsafe {
        libc::raise(libc::SIGTSTP);
    }
    enable_raw_mode()?;
    push_keyboard_enhancement()?;
    execute!(io::stdout(), EnterAlternateScreen, EnableMouseCapture)?;
    terminal.clear()?;
    Ok(())
}

/// Run the interactive TUI loop against a real terminal.
pub fn run(app: &mut App) -> io::Result<()> {
    enable_raw_mode()?;
    push_keyboard_enhancement()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // A panic mid-session (e.g. an indexing bug) would otherwise unwind
    // straight out of this function, skipping the cleanup below and
    // leaving the terminal stuck in raw/alt-screen/mouse-capture mode.
    // Restore it first, then hand off to the default panic printer.
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        restore_terminal();
        default_hook(info);
    }));

    let result = run_loop(&mut terminal, app);

    let _ = std::panic::take_hook();
    restore_terminal();
    terminal.show_cursor()?;

    result
}

fn run_loop<B: Backend>(terminal: &mut Terminal<B>, app: &mut App) -> io::Result<()>
where
    io::Error: From<B::Error>,
{
    loop {
        terminal.draw(|frame| app.render(frame))?;
        // While a status message is pending auto-dismissal
        // (`message_deadline`, `track_message_timeout`), poll with a
        // timeout instead of blocking indefinitely on `event::read()`,
        // so the next `render()` (which actually clears an expired
        // message) runs even with no further keypress. No behavior
        // change — same indefinite block as before — while no message
        // is pending, which is most of the time in ordinary navigation.
        let event = match app.message_deadline {
            Some(deadline) => {
                let timeout = deadline.saturating_duration_since(Instant::now());
                if event::poll(timeout)? {
                    Some(event::read()?)
                } else {
                    None
                }
            }
            None => Some(event::read()?),
        };
        match event {
            Some(Event::Key(key)) => app.handle_key(key),
            Some(Event::Mouse(mouse)) => app.handle_mouse(mouse),
            _ => {}
        }
        if app.should_quit {
            return Ok(());
        }
        #[cfg(unix)]
        if app.should_suspend {
            app.should_suspend = false;
            suspend(terminal)?;
        }
    }
}

mod command_line;
mod key_dispatch;
mod manage_pane;
mod mouse;
mod navigation;
mod override_apply;
mod override_select;
mod render;

#[cfg(test)]
mod tests;
