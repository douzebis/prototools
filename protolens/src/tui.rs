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
use std::time::{Duration, Instant};

use crossterm::event::{
    self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEvent, KeyModifiers,
    MouseButton, MouseEvent, MouseEventKind,
};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::{Backend, CrosstermBackend};
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Clear, Paragraph};
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
    "  Left/Right       move the main-pane cursor to the prev/next field",
    "                   affected by the highlighted entry (wraps around)",
    "  /  ?  n          search / search backward / repeat",
    "  a                toggle the highlighted entry active/inactive",
    "  z / Z            rotate the highlighted entry's origin kind",
    "                   forward/backward: path, path-field, fqdn-field;",
    "                   auto-resolves from the fields the entry affects,",
    "                   falling back to the main-pane cursor/message line",
    "                   when ambiguous; repeating z/Z with the cursor",
    "                   unchanged advances to the next kind instead of",
    "                   getting stuck",
    "  d                duplicate the highlighted entry (the copy starts",
    "                   inactive)",
    "  Delete/Backspace remove the highlighted entry from the collection",
    "                   (an auto-derived entry still in scope is",
    "                   deactivated instead, since deleting it would",
    "                   just recreate it)",
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
    /// Last confirmed management-pane in-pane search — `n` repeats it.
    last_manage_search: Option<(SearchDir, String)>,
    /// `Some` while `f` in the management pane is editing the highlighted
    /// entry's display-name override (spec 0119 G4) — pre-filled with its
    /// current `name` (empty if `None`), mutually exclusive with an
    /// in-progress `command_buffer` search.
    manage_rename: Option<String>,
    /// `Some((origin, kind, cursor))` while a `z`/`Z` attempt in the
    /// management pane is unresolved (spec 0134 G2/G3): `origin` is the
    /// highlighted entry's origin at the time of that attempt, `kind` is
    /// the `OverrideKind` it evaluated, and `cursor` is `self.cursor`'s
    /// value at that time. A same-direction `z`/`Z` press with an
    /// unchanged cursor advances past `kind`; with a changed cursor, it
    /// retries `kind`. Cleared on every successful rotation and whenever
    /// `manage_highlight` moves to a different entry.
    manage_pending_kind: Option<(OverrideOrigin, OverrideKind, usize)>,
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
        // was explicitly requested or inferred; `None` (raw) if neither —
        // `decode::decode` uses the "<raw / no type>" sentinel for that
        // case rather than an `Option`.
        let root_override_type = if decoded.root_type == "<raw / no type>" {
            None
        } else {
            Some(decoded.root_type.clone())
        };
        let mut overrides = override_pane::OverrideCollection::new();
        overrides.seed_root(root_override_type.clone());
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
        // `seed_root` entry above — mark it as such so the first
        // `render_overrides` pass doesn't treat it as a mismatch and
        // needlessly re-splice the entire tree (which would invalidate
        // every already-computed node index: `cursor`, `folded`, etc.).
        if let Some(node) = app.tree.get_mut(cursor) {
            // The root's own field name is always "1" (its field number
            // in the virtual encompassing message — mirrors
            // `field_name_for`'s no-parent case), and can't yet carry a
            // §G4 name override at this point (the collection was just
            // seeded, nothing has been renamed).
            node.rendered_as = Some((Some(root_override_type), "1".to_string()));
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

    fn has_children(&self, idx: usize) -> bool {
        self.tree[idx].first_child.is_some()
    }

    /// Recompute `visible_rows` from current fold state: a folded node
    /// hides its body (`text_range.start + 1 .. text_range.end`), keeping
    /// its own opening line visible with a fold indicator.
    fn rebuild_visible_rows(&mut self) {
        let total = self.lines.len();
        let mut hidden = vec![false; total];
        for &idx in &self.folded {
            let r = &self.tree[idx].span.text_range;
            let end = r.end.min(total);
            for h in hidden.iter_mut().take(end).skip(r.start + 1) {
                *h = true;
            }
        }
        self.visible_rows = (0..total).filter(|&l| !hidden[l]).collect();
    }

    /// True if any ancestor of `idx` is currently folded (so `idx` itself
    /// is not reachable by cursor movement).
    fn is_hidden(&self, idx: usize) -> bool {
        let mut p = self.tree[idx].parent;
        while let Some(pi) = p {
            if self.folded.contains(&pi) {
                return true;
            }
            p = self.tree[pi].parent;
        }
        false
    }

    /// Unfold every ancestor of `idx`, so it becomes visible.
    fn unfold_ancestors(&mut self, idx: usize) {
        let mut p = self.tree[idx].parent;
        let mut changed = false;
        while let Some(pi) = p {
            if self.folded.remove(&pi) {
                changed = true;
            }
            p = self.tree[pi].parent;
        }
        if changed {
            self.rebuild_visible_rows();
        }
    }

    /// Next node in document order (`raw_range.start`), skipping any
    /// hidden (folded-away) node — not the same as `from + 1`: the
    /// underlying arena is post-order, not document order (see
    /// `decode::TreeNode`'s doc comment).
    fn next_visible(&self, from: usize) -> Option<usize> {
        let mut cur = self.tree[from].doc_next;
        while let Some(i) = cur {
            if !self.is_hidden(i) {
                return Some(i);
            }
            cur = self.tree[i].doc_next;
        }
        None
    }

    fn prev_visible(&self, from: usize) -> Option<usize> {
        let mut cur = self.tree[from].doc_prev;
        while let Some(i) = cur {
            if !self.is_hidden(i) {
                return Some(i);
            }
            cur = self.tree[i].doc_prev;
        }
        None
    }

    fn move_down(&mut self) {
        if let Some(next) = self.next_visible(self.cursor) {
            self.cursor = next;
        }
    }

    fn move_up(&mut self) {
        if let Some(prev) = self.prev_visible(self.cursor) {
            self.cursor = prev;
        }
    }

    /// Sibling-skip move (`J` / Shift-Down, spec 0126 G2): moves to the
    /// cursor's next sibling, or leaves it in place with a message if
    /// there isn't one.
    fn next_sibling_move(&mut self) {
        if let Some(next) = self.tree[self.cursor].next_sibling {
            self.record_jump(self.cursor);
            self.cursor = next;
        } else {
            self.message = "no next sibling".to_string();
        }
    }

    /// Sibling-skip move (`K` / Shift-Up, spec 0126 G2): moves to the
    /// cursor's previous sibling, or leaves it in place with a message if
    /// there isn't one.
    fn prev_sibling_move(&mut self) {
        if let Some(prev) = self.tree[self.cursor].prev_sibling {
            self.record_jump(self.cursor);
            self.cursor = prev;
        } else {
            self.message = "no previous sibling".to_string();
        }
    }

    fn move_page_down(&mut self) {
        let page = (self.main_area.height as usize).max(1);
        for _ in 0..page {
            self.move_down();
        }
    }

    fn move_page_up(&mut self) {
        let page = (self.main_area.height as usize).max(1);
        for _ in 0..page {
            self.move_up();
        }
    }

    /// Longest rendered line (in characters, gutter included) among the
    /// currently visible window — the basis for `pan_right`'s clamping
    /// bound (spec 0113 D24: "recomputed as the cursor/scroll position
    /// changes").
    fn max_visible_line_len(&self) -> usize {
        let pane_height = self.main_area.height as usize;
        let start = self.scroll_offset.min(self.visible_rows.len());
        let end = (self.scroll_offset + pane_height).min(self.visible_rows.len());
        self.visible_rows[start..end]
            .iter()
            .map(|&li| self.render_line_content(li).chars().count())
            .max()
            .unwrap_or(0)
    }

    fn pan_left(&mut self) {
        self.pan_offset = self.pan_offset.saturating_sub(PAN_STEP);
    }

    fn pan_right(&mut self) {
        let width = self.main_area.width as usize;
        let max_offset = self.max_visible_line_len().saturating_sub(width);
        self.pan_offset = (self.pan_offset + PAN_STEP).min(max_offset);
    }

    /// Absolute last node in document order (regardless of visibility).
    fn last_node(&self) -> usize {
        let mut cur = self.first_node;
        while let Some(n) = self.tree[cur].doc_next {
            cur = n;
        }
        cur
    }

    /// Jump to the document-order first node (`Home`/`gg`).
    fn move_home(&mut self) {
        if self.cursor != self.first_node {
            self.record_jump(self.cursor);
            self.cursor = self.first_node;
        }
    }

    /// Jump to the last currently-visible node (`End`/`G`) — the document's
    /// absolute last node, or its nearest visible predecessor if that node
    /// is itself folded away.
    fn move_end(&mut self) {
        let last = self.last_node();
        let target = if self.is_hidden(last) {
            self.prev_visible(last).unwrap_or(last)
        } else {
            last
        };
        if self.cursor != target {
            self.record_jump(self.cursor);
            self.cursor = target;
        }
    }

    fn toggle_fold(&mut self, idx: usize) {
        if !self.folded.remove(&idx) {
            self.folded.insert(idx);
        }
        self.rebuild_visible_rows();
    }

    /// All siblings of `idx` (including `idx` itself), in document order —
    /// walks to the first sibling via `prev_sibling`, then follows
    /// `next_sibling`. Works uniformly at any level, including root-level
    /// nodes (which share sibling links despite having no `parent`).
    fn sibling_range(&self, idx: usize) -> Vec<usize> {
        let mut first = idx;
        while let Some(p) = self.tree[first].prev_sibling {
            first = p;
        }
        let mut v = Vec::new();
        let mut cur = Some(first);
        while let Some(i) = cur {
            v.push(i);
            cur = self.tree[i].next_sibling;
        }
        v
    }

    fn fold_all_siblings(&mut self) {
        let siblings = self.sibling_range(self.cursor);
        let mut changed = false;
        for i in siblings {
            if self.has_children(i) && self.folded.insert(i) {
                changed = true;
            }
        }
        if changed {
            self.rebuild_visible_rows();
        }
    }

    fn unfold_all_siblings(&mut self) {
        let siblings = self.sibling_range(self.cursor);
        let mut changed = false;
        for i in siblings {
            if self.folded.remove(&i) {
                changed = true;
            }
        }
        if changed {
            self.rebuild_visible_rows();
        }
    }

    /// 1-based ordinal position of `idx` among its own parent's direct
    /// children (or among root-level siblings, if `idx` has no parent —
    /// root-level nodes are sibling-linked despite having no `parent`, see
    /// D16), in document order (spec 0113 D25).
    fn sibling_position(&self, idx: usize) -> usize {
        let mut pos = 1;
        let mut cur = idx;
        while let Some(prev) = self.tree[cur].prev_sibling {
            pos += 1;
            cur = prev;
        }
        pos
    }

    /// Slash-separated positional path from the root to `idx` (spec 0113
    /// D25) — e.g. `/1/2/3`, each segment a `sibling_position`. No schema
    /// knowledge required, purely structural.
    ///
    /// The underlying tree's actual root is the virtual encompassing
    /// wrapper (spec 0114 §1.1); every real node's true internal path
    /// therefore has a leading `/1` leg (descent into the wrapper's sole
    /// field) that isn't part of the caller-visible protobuf. Drop it here
    /// so displayed paths match exactly what they were before the wrapper
    /// existed; the wrapper's own node (internal path `/1`) displays as
    /// bare `/`.
    fn positional_path(&self, idx: usize) -> String {
        let mut segments = Vec::new();
        let mut cur = Some(idx);
        while let Some(i) = cur {
            segments.push(self.sibling_position(i));
            cur = self.tree[i].parent;
        }
        segments.reverse();
        segments.remove(0);
        let mut path = String::from("/");
        for (i, seg) in segments.iter().enumerate() {
            if i > 0 {
                path.push('/');
            }
            path.push_str(&seg.to_string());
        }
        path
    }

    /// Node `idx`'s displayed byte range, half-open `[start, end)`, in the
    /// caller's original (pre-wrap) blob's numbering (spec 0114 §1.1):
    /// every node — message/group *and* scalar alike — is shown
    /// payload-only, tag (and, for length-delimited fields, the length
    /// prefix — strings, bytes, and packed-repeated scalars are all
    /// wire-type LEN, same as messages/groups) stripped via
    /// `extract::message_payload_range`, which strips generically by wire
    /// type rather than by node kind. Every coordinate also has
    /// `wrapper_offset` subtracted to undo the virtual encompassing
    /// wrapper's own tag+length prefix. The wrapper's own node displays
    /// as `[0, n)`.
    fn display_range(&self, idx: usize) -> Range<usize> {
        let span = &self.tree[idx].span;
        let raw =
            extract::message_payload_range(&self.blob, &span.raw_range, span.packed_record_start);
        (raw.start - self.wrapper_offset)..(raw.end - self.wrapper_offset)
    }

    /// Whether `idx` is eligible as an override target (`t`, `type-as`,
    /// `type-as-raw`): a message/group node already (`NodeSpan::
    /// is_message`, spec 0114 §1.2 — *not* `type_fqdn.is_some()`, which is
    /// ambiguous between a scalar and a schema-unresolved message/group),
    /// or a plain scalar carrying a length-delimited payload (`wire_type
    /// == WT_LEN` — string, bytes, or an unresolved LEN-wire field) that
    /// *could* be reinterpreted as an embedded message. Any/MessageSet
    /// auto-expansion (spec 0120) already reinterprets exactly this kind
    /// of scalar unconditionally; a manual override that turns out to
    /// target genuinely non-message bytes simply fails to parse and
    /// `splice_override` reports it — the user is trusted to judge
    /// whether the result is meaningful (2026-07-14 feedback: `t` used
    /// to unconditionally refuse every string/bytes field).
    fn can_override(&self, idx: usize) -> bool {
        let span = &self.tree[idx].span;
        span.is_message || span.wire_type == prototext_core::helpers::WT_LEN
    }

    /// `t`: toggle the override pane for the node under the cursor (spec
    /// 0114 §1/§2). Closes it (cancelling) if already open, regardless of
    /// which pane currently has focus. Otherwise opens it — moving focus
    /// there — if the cursor sits on an eligible node (`can_override`)
    /// and the terminal is wide enough; an ineligible target or an
    /// over-narrow terminal instead leaves a status-line message.
    fn toggle_override(&mut self) {
        if self.override_target.is_some() {
            self.close_override();
            return;
        }
        if !self.can_override(self.cursor) {
            self.message =
                "cannot override: not a message/group or length-delimited field".to_string();
            return;
        }
        if self.term_width < MIN_OVERRIDE_WIDTH {
            self.message = format!(
                "terminal too narrow for override pane (need >= {MIN_OVERRIDE_WIDTH} columns)"
            );
            return;
        }
        // Mutually exclusive with the management pane (spec 0117 §3):
        // they share one right-hand UI slot.
        if self.manage_open {
            self.close_manage_pane();
        }
        // Spec 0132 §G1: priority (1) of the default-highlight order —
        // an already-active override for this node takes precedence
        // over `recompute_override_candidates`'s own priority (2)/(3)
        // default (top-inferred candidate, else `<raw / no type>`).
        // Resolved before `recompute_override_candidates` overwrites
        // `override_candidates`, per the cursor's node.
        let active_type = self
            .resolve_active_override_entry(self.cursor)
            .map(|e| e.r#type.clone());
        self.override_target = Some(self.cursor);
        self.override_focus = true;
        self.override_scroll = 0;
        self.override_pan_offset = 0;
        self.recompute_override_candidates();
        if let Some(fqdn_or_raw) = active_type {
            let highlight = match &fqdn_or_raw {
                None => Some(0),
                Some(fqdn) => self
                    .override_candidates
                    .iter()
                    .position(|(f, _)| f == fqdn)
                    .map(|row| row + 1),
            };
            if let Some(highlight) = highlight {
                self.override_highlight = highlight;
            }
        }
        // Spec 0132 §G2: live-preview the initial highlighted row from
        // the very first frame the pane is shown, not just after the
        // first navigation keystroke.
        self.preview_override_highlight();
    }

    /// `o`: toggle the override management pane (spec 0117 §3). Closes
    /// it (cancelling) if already open. Otherwise opens it — no
    /// cursor-node-kind precondition, unlike `t` — closing the override
    /// selection pane first if it's open (mutual exclusion, one shared
    /// right-hand UI slot).
    fn toggle_manage_pane(&mut self) {
        if self.manage_open {
            self.close_manage_pane();
            return;
        }
        if self.term_width < MIN_OVERRIDE_WIDTH {
            self.message = format!(
                "terminal too narrow for override management pane (need >= \
                 {MIN_OVERRIDE_WIDTH} columns)"
            );
            return;
        }
        if self.override_target.is_some() {
            self.close_override();
        }
        self.manage_open = true;
        self.manage_focus = true;
        self.manage_highlight = 0;
        self.manage_scroll = 0;
        self.manage_pan_offset = 0;
        self.manage_pending_kind = None;
    }

    /// Close the override management pane (spec 0117 §3).
    fn close_manage_pane(&mut self) {
        self.manage_open = false;
        self.manage_focus = false;
    }

    /// Move the management pane's highlighted row by `delta`, clamped to
    /// `0..overrides.entries().len()` (spec 0117 §3's `j`/`k`).
    fn move_manage_highlight(&mut self, delta: isize) {
        let len = self.overrides.entries().len();
        if len == 0 {
            self.manage_highlight = 0;
            self.manage_pending_kind = None;
            return;
        }
        let current = self.manage_highlight as isize;
        self.manage_highlight = (current + delta).clamp(0, len as isize - 1) as usize;
        self.manage_pending_kind = None;
    }

    /// The management pane's grouped-by-origin display rows (spec 0117
    /// §3 amendment): one `Header` row per distinct origin (in the
    /// collection's own sort order — origins never interleave, since
    /// `OverrideCollection::sort` already groups by origin), followed by
    /// one `Entry` row per type recorded under it.
    fn manage_display_rows(&self) -> Vec<ManageRow> {
        let mut rows = Vec::new();
        let mut prev_origin: Option<&OverrideOrigin> = None;
        for (idx, entry) in self.overrides.entries().iter().enumerate() {
            if prev_origin != Some(&entry.origin) {
                rows.push(ManageRow::Header(entry.origin.label()));
                prev_origin = Some(&entry.origin);
            }
            rows.push(ManageRow::Entry(idx));
        }
        rows
    }

    /// One management-pane type row's display text: indented, active
    /// marker (`*`) leading, type label (spec 0117 §3 amendment), plus
    /// the display-name override when set (spec 0119 §G4).
    fn manage_type_line(&self, idx: usize) -> String {
        let e = &self.overrides.entries()[idx];
        let marker = if e.active { '*' } else { ' ' };
        let type_label = e.r#type.as_deref().unwrap_or("<raw / no type>");
        match &e.name {
            Some(name) => format!("  {marker} {type_label}  as \"{name}\""),
            None => format!("  {marker} {type_label}"),
        }
    }

    /// Search corpus for management-pane entry `idx` (spec 0117 §3's
    /// `/`/`?`/`n`) — origin label plus type label, so searching for
    /// either the origin or the type finds it, independent of how the
    /// grouped display happens to lay them out across rows.
    fn manage_search_text(&self, idx: usize) -> String {
        let e = &self.overrides.entries()[idx];
        let type_label = e.r#type.as_deref().unwrap_or("<raw / no type>");
        format!("{} {type_label}", e.origin.label())
    }

    /// Find the next management-pane entry (spec 0117 §3's `/`/`?`/`n`)
    /// whose search text (`manage_search_text`) contains `pattern`
    /// (case-insensitive), searching in `dir` from just past the current
    /// highlight, wrapping around. Moves the highlight there on success;
    /// otherwise leaves it unchanged and sets a status-line message.
    fn jump_to_manage_match(&mut self, dir: SearchDir, pattern: &str) {
        let n = self.overrides.entries().len();
        if pattern.is_empty() || n == 0 {
            return;
        }
        let needle = pattern.to_lowercase();
        let start = self.manage_highlight % n;
        let order: Vec<usize> = match dir {
            SearchDir::Forward => (1..=n).map(|d| (start + d) % n).collect(),
            SearchDir::Backward => (1..=n).map(|d| (start + n - d) % n).collect(),
        };
        for i in order {
            if self.manage_search_text(i).to_lowercase().contains(&needle) {
                self.manage_highlight = i;
                self.manage_pending_kind = None;
                return;
            }
        }
        self.message = format!("pattern not found: {pattern}");
    }

    /// Close the override pane (cancelling — spec 0114 §2), regardless of
    /// which pane currently has focus. Demotes `override_inferred_raw` (if
    /// any) into `candidate_cache`, capped to however many rows the pane
    /// was actually showing — spec 0114 §6's "other entries keep only the
    /// first N lines."
    ///
    /// Spec 0132 §G3: first settles `override_target`'s main-pane
    /// rendering back to its actual effective type — reverting whatever
    /// the live preview last spliced in. Uses the full recursive
    /// `render_overrides` (not the single-node `resettle_node`): the live
    /// preview's own `splice_override` call rebuilds `idx`'s entire
    /// subtree from scratch, with no overrides applied to any of the
    /// fresh descendants (§G2's "no live nested Any/MessageSet preview"
    /// non-goal) — a `resettle_node`-only revert would fix `idx` itself
    /// but leave every previously-auto-expanded Any/MessageSet descendant
    /// un-re-expanded. `render_overrides`'s recursion re-seeds/reapplies
    /// every descendant's own override exactly as it does on any other
    /// pass. A no-op when nothing was ever previewed (the `Enter`-confirm
    /// call site already ran `render_overrides` itself, which leaves
    /// `rendered_as` matching everywhere, so this becomes the cheap
    /// "already current" path throughout the subtree).
    fn close_override(&mut self) {
        if let Some(idx) = self.override_target {
            self.render_overrides(idx);
        }
        if let Some(range) = self.active_override_range.take() {
            let n = self.override_list_height.max(1);
            let capped: Vec<_> = self.override_inferred_raw.iter().take(n).cloned().collect();
            self.candidate_cache.insert(range, capped);
        }
        self.override_inferred_raw.clear();
        self.override_candidates_complete = false;
        self.override_target = None;
        self.override_focus = false;
    }

    /// Recompute `override_candidates` for the current `override_target`
    /// under the currently active `override_sort` (spec 0114 §3.2), and
    /// reset the highlight to the first ranked candidate — not the pinned
    /// raw entry (§3.1's "not the default on open"). Called both when the
    /// pane first opens and whenever `i` toggles the sort mode.
    ///
    /// `SortMode::Inferred` consults `candidate_cache`/`active_override_range`
    /// (spec 0114 §6) before calling `score_all`: toggling back to
    /// `Inferred` within the same open-pane session reuses
    /// `override_inferred_raw` as-is (no recomputation at all); opening on
    /// a previously-viewed range reuses its cached capped preview; only a
    /// genuinely new range pays for a fresh `score_all` call.
    fn recompute_override_candidates(&mut self) {
        let Some(idx) = self.override_target else {
            return;
        };
        self.override_candidates = match self.override_sort {
            SortMode::Lexicographic => self
                .all_type_fqdns
                .iter()
                .map(|f| (f.clone(), None))
                .collect(),
            SortMode::Inferred => match &self.ctx.graph {
                Some(graph) => {
                    let node = &self.tree[idx].span;
                    let range = extract::message_payload_range(
                        &self.blob,
                        &node.raw_range,
                        node.packed_record_start,
                    );
                    if self.active_override_range.as_ref() != Some(&range) {
                        if let Some(cached) = self.candidate_cache.get(&range) {
                            self.override_inferred_raw = cached;
                            self.override_candidates_complete = false;
                        } else {
                            let range_bytes = &self.blob[range.clone()];
                            self.override_inferred_raw =
                                override_pane::inferred_candidates(range_bytes, graph);
                            self.override_candidates_complete = true;
                        }
                        self.active_override_range = Some(range);
                    }
                    self.override_inferred_raw
                        .iter()
                        .map(|(f, s)| (f.clone(), Some(*s)))
                        .collect()
                }
                None => {
                    self.message = "no scoring graph available for inferred order; press 'a' \
                                     for alphanumeric"
                        .to_string();
                    Vec::new()
                }
            },
        };
        self.override_highlight = usize::from(!self.override_candidates.is_empty());
        self.override_scroll = 0;
        self.override_pan_offset = 0;
    }

    /// Recompute the complete ranked list for `active_override_range`
    /// (dropping a capped `candidate_cache` preview), and refresh
    /// `override_candidates` from it. No-op if already complete. Called
    /// when the user tries to scroll past a capped preview's last row
    /// (spec 0114 §6).
    fn upgrade_active_override_to_complete(&mut self) {
        if self.override_candidates_complete {
            return;
        }
        let (Some(idx), Some(graph)) = (self.override_target, &self.ctx.graph) else {
            return;
        };
        let node = &self.tree[idx].span;
        let range =
            extract::message_payload_range(&self.blob, &node.raw_range, node.packed_record_start);
        let range_bytes = &self.blob[range.clone()];
        self.override_inferred_raw = override_pane::inferred_candidates(range_bytes, graph);
        self.override_candidates_complete = true;
        self.active_override_range = Some(range);
        self.override_candidates = self
            .override_inferred_raw
            .iter()
            .map(|(f, s)| (f.clone(), Some(*s)))
            .collect();
    }

    /// Move the override pane's highlighted row by `delta` (spec 0114
    /// §3.2's `j`/`k`), clamped to `0..=override_candidates.len()` (row
    /// `0` is the pinned raw entry). Upgrades a capped preview to the
    /// complete list first (spec 0114 §6) if the requested move would go
    /// past what's currently loaded.
    fn move_override_highlight(&mut self, delta: isize) {
        if delta > 0
            && !self.override_candidates_complete
            && self.override_sort == SortMode::Inferred
            && self.override_highlight as isize + delta > self.override_candidates.len() as isize
        {
            self.upgrade_active_override_to_complete();
        }
        let max = self.override_candidates.len();
        let current = self.override_highlight as isize;
        self.override_highlight = (current + delta).clamp(0, max as isize) as usize;
        // Spec 0132 §G2: live-preview the newly-highlighted candidate.
        self.preview_override_highlight();
    }

    /// Spec 0132 §G2: live-previews the currently-highlighted override
    /// candidate by splicing it directly into the main pane — cheap,
    /// single-node `splice_override` call that deliberately does not
    /// touch `self.overrides`, so a later `Enter`-confirm (which does
    /// touch it) is entirely unaffected by whatever was last previewed.
    /// No-op if the override pane isn't open. Row 0 is the pinned
    /// `<raw / no type>` entry (§3.1); rows 1.. are
    /// `override_candidates[row - 1]`.
    ///
    /// `idx`'s own `rendered_as` *is* deliberately invalidated
    /// (`None`'d out) on every successful preview splice — unlike a real
    /// `render_overrides`/`resettle_node` splice, which records the
    /// splice's own target into `rendered_as` so a later pass can no-op
    /// when nothing changed. A preview splice's target is provisional,
    /// not `idx`'s real effective type, so `rendered_as` must not claim
    /// otherwise: leaving it stale (matching whatever it held before the
    /// pane opened) would make a later revert's `resettle_node` — which
    /// compares against `rendered_as` to decide whether to re-splice at
    /// all — wrongly conclude nothing needs re-splicing whenever the
    /// previewed row happens to coincide with what was already recorded
    /// (e.g. the common case of previewing the raw/no-type row on a node
    /// whose real effective type is itself schema-inferred, not an
    /// explicit override), permanently leaving the preview's content on
    /// screen instead of actually reverting (2026-07-15 feedback: `Esc`
    /// silently failed to restore nested Any/MessageSet auto-expansion,
    /// root-caused to exactly this).
    fn preview_override_highlight(&mut self) {
        let Some(idx) = self.override_target else {
            return;
        };
        let tentative = if self.override_highlight == 0 {
            None
        } else {
            self.override_candidates
                .get(self.override_highlight - 1)
                .map(|(fqdn, _)| fqdn.clone())
        };
        match self.splice_override(idx, tentative) {
            Ok(()) => self.tree[idx].rendered_as = None,
            Err(e) => self.message = format!("cannot preview override: {e}"),
        }
    }

    /// Find the next `override_candidates` entry (1-based row, the pinned
    /// raw entry excluded from matching — §4) whose FQDN contains
    /// `pattern` (case-insensitive), searching in `dir` from just past the
    /// currently highlighted row, wrapping around. Moves the highlight
    /// there on success; otherwise leaves it unchanged and sets a
    /// status-line message.
    fn jump_to_override_match(&mut self, dir: SearchDir, pattern: &str) {
        if pattern.is_empty() || self.override_candidates.is_empty() {
            return;
        }
        let needle = pattern.to_lowercase();
        let n = self.override_candidates.len();
        // Candidate indices (0-based into `override_candidates`), starting
        // just past the current highlight (row 0 = raw, row i+1 =
        // candidate i) and wrapping around, in search direction. `row` is
        // clamped into `0..=n` first since the raw entry (row 0) has no
        // corresponding candidate index.
        let row = self.override_highlight.min(n);
        let order: Vec<usize> = match dir {
            SearchDir::Forward => {
                let start = row % n;
                (0..n).map(|d| (start + d) % n).collect()
            }
            SearchDir::Backward => {
                let cur = row.saturating_sub(1);
                let start = (cur + n - 1) % n;
                (0..n).map(|d| (start + n - d) % n).collect()
            }
        };
        for i in order {
            if self.override_candidates[i]
                .0
                .to_lowercase()
                .contains(&needle)
            {
                self.override_highlight = i + 1;
                return;
            }
        }
        self.message = format!("pattern not found: {pattern}");
    }

    /// Find the next node (walking the whole document-order chain via
    /// `doc_next`/`doc_prev` — not just currently visible/unfolded nodes,
    /// so a folded-away match is still found and then revealed) whose own
    /// opening line (`self.lines[node.span.text_range.start]`) contains
    /// `pattern` (case-insensitive), searching in `dir` from just past the
    /// cursor and wrapping around at the ends of the chain via
    /// `first_node`/`last_node()` (spec 0114 §4, extended to the main
    /// pane). Always matches against `self.lines`' *current* rendered
    /// text, so a range whose type has been overridden (spec 0114 §5)
    /// searches the post-override rendering, not the original one — no
    /// special-casing needed, since overrides mutate `self.lines` in
    /// place rather than being tracked separately. On a match, moves the
    /// cursor there (recording a jumplist entry) and unfolds its
    /// ancestors so it's visible; otherwise leaves the cursor unchanged
    /// and sets a status-line message.
    fn jump_to_match(&mut self, dir: SearchDir, pattern: &str) {
        if pattern.is_empty() || self.tree.is_empty() {
            return;
        }
        let needle = pattern.to_lowercase();
        let mut cur = self.cursor;
        loop {
            cur = match dir {
                SearchDir::Forward => self.tree[cur].doc_next.unwrap_or(self.first_node),
                SearchDir::Backward => self.tree[cur].doc_prev.unwrap_or(self.last_node()),
            };
            let line_idx = self.tree[cur].span.text_range.start;
            if self.lines[line_idx].to_lowercase().contains(&needle) {
                if cur != self.cursor {
                    self.record_jump(self.cursor);
                    self.cursor = cur;
                    self.unfold_ancestors(cur);
                }
                return;
            }
            if cur == self.cursor {
                break;
            }
        }
        self.message = format!("pattern not found: {pattern}");
    }

    /// Recursively collect every current descendant of `idx` (any depth),
    /// via `first_child`/`next_sibling` pointer traversal — never array
    /// position (spec 0114 §5's splice design: post-order array
    /// contiguity does not survive a *second* override of the same node,
    /// since the first override's new nodes are appended at the array's
    /// end, breaking it). Used to find which array entries become orphans
    /// once `idx`'s subtree is replaced, so they can be scrubbed from
    /// `self.folded`.
    fn collect_descendants(&self, idx: usize, out: &mut Vec<usize>) {
        let mut child = self.tree[idx].first_child;
        while let Some(c) = child {
            out.push(c);
            self.collect_descendants(c, out);
            child = self.tree[c].next_sibling;
        }
    }

    /// Looks up `idx`'s own field on its parent's schema (spec 0119
    /// §G1/§G2's shared lookup): requires both that `idx`'s parent has a
    /// resolved `type_fqdn` and that its schema declares `idx`'s
    /// `field_number`. Returns `None` when either fails (no parent,
    /// unresolved parent type, or the field isn't declared) — the same
    /// failure mode `natural_type`/`field_name_for` both fall back from.
    fn parent_field(&self, idx: usize) -> Option<prost_reflect::FieldDescriptor> {
        let parent = self.tree[idx].parent?;
        let fqdn = self.tree[parent].span.type_fqdn.as_ref()?;
        let field_number = self.tree[idx].span.field_number;
        self.ctx
            .pool()
            .get_message_by_name(fqdn)?
            .get_field(field_number as u32)
    }

    /// The type `idx` would naturally have from its parent's schema, used
    /// as the fallback when no active override applies (spec 0119 §G1) —
    /// `None` only when genuinely no type information is available (no
    /// parent schema, field not declared, or a non-message field kind).
    fn natural_type(&self, idx: usize) -> Option<String> {
        match self.parent_field(idx)?.kind() {
            prost_reflect::Kind::Message(desc) => Some(desc.full_name().to_string()),
            _ => None,
        }
    }

    /// `true` when `idx`'s resolved type is `google.protobuf.Any` — spec
    /// 0120 §G1's detection rule, a plain FQDN match (per review).
    fn is_any_typed(&self, idx: usize) -> bool {
        self.tree[idx].span.type_fqdn.as_deref() == Some("google.protobuf.Any")
    }

    /// `true` when `idx`'s resolved type is a MessageSet — spec 0120 §G2's
    /// detection rule: `message_set_wire_format = true` in the resolved
    /// `MessageDescriptor`'s own options, and zero declared fields. Mirrors
    /// `prototext-core`'s own (private, unreachable from this crate)
    /// `is_message_set` heuristic — an independent replica, not a shared
    /// helper, since protolens already has direct `prost_reflect`/
    /// `ctx.pool()` access and needs no new plumbing (spec 0120's
    /// assessment).
    fn is_message_set_typed(&self, idx: usize) -> bool {
        let Some(fqdn) = self.tree[idx].span.type_fqdn.as_ref() else {
            return false;
        };
        let Some(desc) = self.ctx.pool().get_message_by_name(fqdn) else {
            return false;
        };
        let msf = desc
            .descriptor_proto()
            .options
            .as_ref()
            .and_then(|o| o.message_set_wire_format)
            .unwrap_or(false);
        msf && desc.fields().count() == 0
    }

    /// The sibling of `idx` (another child of `idx`'s own parent) whose
    /// `field_number` is `field_number`, if any — used by
    /// `auto_expand_type` to locate Any's `type_url` next to `value`, and
    /// MessageSet's `type_id` next to `message`.
    fn find_sibling(&self, idx: usize, field_number: u64) -> Option<usize> {
        let parent = self.tree[idx].parent?;
        let mut c = self.tree[parent].first_child;
        while let Some(ci) = c {
            if self.tree[ci].span.field_number == field_number {
                return Some(ci);
            }
            c = self.tree[ci].next_sibling;
        }
        None
    }

    /// Reads `idx`'s own raw payload (tag/length stripped, per
    /// `extract::message_payload_range`) as a UTF-8 string — used to read
    /// Any's `type_url` value directly off the wire, independent of how
    /// (or whether) it's currently rendered.
    fn read_string_field(&self, idx: usize) -> Option<String> {
        let span = &self.tree[idx].span;
        let payload =
            extract::message_payload_range(&self.blob, &span.raw_range, span.packed_record_start);
        String::from_utf8(self.blob[payload].to_vec()).ok()
    }

    /// Reads `idx`'s own raw payload as a varint — used to read
    /// MessageSet's `type_id` value directly off the wire.
    fn read_varint_field(&self, idx: usize) -> Option<u64> {
        let span = &self.tree[idx].span;
        let payload =
            extract::message_payload_range(&self.blob, &span.raw_range, span.packed_record_start);
        prototext_core::helpers::parse_varint(&self.blob, payload.start).varint
    }

    /// `true` when `idx` is structurally *eligible* for Any/MessageSet
    /// auto-expansion (spec 0120) — regardless of whether the actual
    /// target type turns out to be resolvable. Used by `render_overrides`
    /// to widen its child-recursion gate (normally `span.is_message`
    /// only) just enough to give these two specific field shapes a
    /// chance to be visited and auto-overridden, without reopening the
    /// spec 0119 bug where every plain scalar LEN-wire field got
    /// incorrectly demoted to raw by being recursed into at all.
    fn is_auto_expand_candidate(&self, idx: usize) -> bool {
        let Some(parent) = self.tree[idx].parent else {
            return false;
        };
        let field_number = self.tree[idx].span.field_number;
        if field_number == 2 && self.is_any_typed(parent) {
            return true;
        }
        // MessageSet tier 1 (the "Item" group wrapper itself) needs no
        // entry here: it's already `is_message == true` naturally (a
        // real decoded group), so `render_overrides`'s own `is_message`
        // half of its recursion gate already reaches it.
        if field_number == 3
            && self.tree[parent].span.type_fqdn.as_deref() == Some(decode::MESSAGE_SET_ITEM_FQDN)
        {
            if let Some(grandparent) = self.tree[parent].parent {
                return self.is_message_set_typed(grandparent);
            }
        }
        false
    }

    /// The Any/MessageSet auto-derived type for `idx`, if `idx` is one of
    /// the two eligible field shapes (spec 0120 §G1/§G2) and the type it
    /// points at is resolvable in `ctx.pool()` — `None` otherwise (either
    /// not an eligible shape, or an unresolvable `type_url`/`type_id`,
    /// both of which fall back to plain raw rendering like any other
    /// unresolvable type). Consulted as a fallback tier between an
    /// explicit active override and `natural_type` in `render_overrides`.
    fn auto_expand_type(&mut self, idx: usize) -> Option<String> {
        let parent = self.tree[idx].parent?;
        let field_number = self.tree[idx].span.field_number;

        // Any's `value` (field 2): FQDN read from the sibling `type_url`
        // (field 1), stripped of any leading `.../` host/prefix segment
        // (mirrors `any_field.rs`'s own `rfind('/')` resolution).
        if field_number == 2 && self.is_any_typed(parent) {
            let type_url_idx = self.find_sibling(idx, 1)?;
            let type_url = self.read_string_field(type_url_idx)?;
            let fqdn = match type_url.rfind('/') {
                Some(slash) => &type_url[slash + 1..],
                None => type_url.as_str(),
            };
            return self
                .ctx
                .pool()
                .get_message_by_name(fqdn)
                .map(|d| d.full_name().to_string());
        }

        // MessageSet tier 1: the "Item" group wrapper (field 1,
        // `WT_START_GROUP`) auto-derives to the synthetic, globally
        // shared `protolens_internal.MessageSetItem` shape (`type_id` +
        // `message`) — registered once per pool and reused across every
        // MessageSet occurrence in the document.
        if field_number == 1
            && self.tree[idx].span.wire_type == prototext_core::helpers::WT_START_GROUP
            && self.is_message_set_typed(parent)
        {
            return decode::register_message_set_item(self.ctx.pool_mut())
                .ok()
                .map(|d| d.full_name().to_string());
        }

        // MessageSet tier 2: "message" (field 3) of an Item already
        // retyped (tier 1) to `MessageSetItem` — extension type resolved
        // from the sibling `type_id` (field 2), keyed against the
        // MessageSet container's (idx's grandparent) own extensions.
        if field_number == 3
            && self.tree[parent].span.type_fqdn.as_deref() == Some(decode::MESSAGE_SET_ITEM_FQDN)
        {
            let grandparent = self.tree[parent].parent?;
            if self.is_message_set_typed(grandparent) {
                let type_id_idx = self.find_sibling(idx, 2)?;
                let type_id = self.read_varint_field(type_id_idx)?;
                let grandparent_fqdn = self.tree[grandparent].span.type_fqdn.clone()?;
                let extendee = self.ctx.pool().get_message_by_name(&grandparent_fqdn)?;
                let ext = extendee.get_extension(type_id as u32)?;
                if let prost_reflect::Kind::Message(inner) = ext.kind() {
                    return Some(inner.full_name().to_string());
                }
            }
        }

        None
    }

    /// The display name to use for `idx`'s synthetic wrapper field in
    /// `splice_override` (spec 0119 §G2, extended by §G4): the resolved
    /// active override entry's own `name` override when set (§G4 takes
    /// priority); otherwise `idx`'s real field name when resolvable from
    /// the parent's schema; otherwise `idx`'s field number as a string
    /// (protobuf field names can never be all-digits, so this can't
    /// collide with a real name) — the document root is not special-
    /// cased: it's always field number 1 of the virtual encompassing
    /// message, so it falls through to this same field-number case.
    fn field_name_for(&self, idx: usize) -> String {
        if let Some(name) = self
            .resolve_active_override_entry(idx)
            .and_then(|e| e.name.clone())
        {
            return name;
        }
        if let Some(field) = self.parent_field(idx) {
            field.name().to_string()
        } else {
            self.tree[idx].span.field_number.to_string()
        }
    }

    /// Resolves `idx`'s applicable override entry, per the priority
    /// `Path > PathField > FqdnField` (spec 0117), or `None` when no
    /// active entry applies at all — spec 0118 §2. Only `active` entries
    /// are considered (at most one active entry per origin, per spec
    /// 0117's invariant). Shared by `resolve_active_override` (the
    /// entry's `r#type`) and `field_name_for` (spec 0119 §G4's `name`).
    fn resolve_active_override_entry(&self, idx: usize) -> Option<&override_pane::OverrideEntry> {
        let path = self.positional_path(idx);
        for e in self.overrides.entries() {
            if e.active {
                if let OverrideOrigin::Path { path: p } = &e.origin {
                    if *p == path {
                        return Some(e);
                    }
                }
            }
        }
        let parent = self.tree[idx].parent?;
        let field = self.tree[idx].span.field_number;
        let parent_path = self.positional_path(parent);
        for e in self.overrides.entries() {
            if e.active {
                if let OverrideOrigin::PathField { path: p, field: f } = &e.origin {
                    if *p == parent_path && *f == field {
                        return Some(e);
                    }
                }
            }
        }
        if let Some(fqdn) = &self.tree[parent].span.type_fqdn {
            for e in self.overrides.entries() {
                if e.active {
                    if let OverrideOrigin::FqdnField {
                        fqdn: f,
                        field: fld,
                    } = &e.origin
                    {
                        if f == fqdn && *fld == field {
                            return Some(e);
                        }
                    }
                }
            }
        }
        None
    }

    /// Resolves to the type (or `None` = raw) that should currently be
    /// used to render `idx`'s payload, or the outer `None` when no active
    /// override applies at all — spec 0118 §2.
    fn resolve_active_override(&self, idx: usize) -> Option<Option<String>> {
        self.resolve_active_override_entry(idx)
            .map(|e| e.r#type.clone())
    }

    /// Spec 0120's stale-auto-entry demotion (factored out of
    /// `render_overrides` by spec 0132 §G3, so it can also be reused by
    /// the override-pane live preview/revert): the override (if any)
    /// that should currently be considered "active" for `idx`, demoting
    /// a stale `auto` entry — one whose ancestor context has since
    /// changed, `auto_entry_in_scope` returning `false` — back to
    /// "nothing active", same as `resolve_active_override` otherwise.
    /// Outer `None` = no override active; inner `Option<String>` = the
    /// override's type (`None` = raw/no-type override).
    fn effective_override_target(&mut self, idx: usize) -> Option<Option<String>> {
        let stale_auto_entry = self
            .resolve_active_override_entry(idx)
            .filter(|e| e.auto)
            .cloned();
        match stale_auto_entry {
            Some(entry) if !self.auto_entry_in_scope(&entry) => None,
            _ => self.resolve_active_override(idx),
        }
    }

    /// Spec 0132 §G3: settles `idx`'s main-pane rendering to its current
    /// "effective" override target (`effective_override_target`'s
    /// explicit type if one is active, else `natural_type(idx)` when
    /// nothing is active at all) — splicing only if it doesn't already
    /// match `self.tree[idx].rendered_as` (the same no-op-when-already-
    /// current guard `render_overrides` always used, verbatim). Factored
    /// out of `render_overrides` itself (which calls this for `idx`
    /// before recursing into children) so the override-pane's live-
    /// preview revert (on close/cancel) can reuse the exact same
    /// "effective type" computation — including the stale-auto-entry
    /// demotion and natural-type fallback a plain
    /// `resolve_active_override_entry`-only revert would get wrong.
    fn resettle_node(&mut self, idx: usize) {
        let target = self.effective_override_target(idx);
        let field_name = self.field_name_for(idx);
        let current = Some((target.clone(), field_name));
        if current != self.tree[idx].rendered_as {
            let effective = match &target {
                Some(explicit) => explicit.clone(),
                None => self.natural_type(idx),
            };
            match self.splice_override(idx, effective) {
                Ok(()) => self.tree[idx].rendered_as = current,
                Err(e) => self.message = format!("cannot apply override: {e}"),
            }
        }
    }

    /// Whether `entry` (assumed `auto == true`) would still be re-derived
    /// with the same `r#type` if `render_overrides` visited its node
    /// again right now — i.e. it is still "in scope" (spec 0125 §G2).
    /// Factored out of `render_overrides`'s own staleness/demotion check
    /// (spec 0120) so `handle_manage_key`'s `Delete` handling can reuse
    /// the same predicate instead of duplicating it. Lives on `App`
    /// (not `OverrideCollection`) because it needs `auto_expand_type`,
    /// which resolves against the live tree/descriptor pool, not just
    /// the override collection itself. Auto-seeded entries only ever
    /// have a `Path` origin (`render_overrides` always calls
    /// `activate_auto` with `OverrideOrigin::Path`), so a single
    /// `resolve_path` lookup suffices.
    fn auto_entry_in_scope(&mut self, entry: &override_pane::OverrideEntry) -> bool {
        let OverrideOrigin::Path { path } = &entry.origin else {
            return false;
        };
        let Some(idx) = self.resolve_path(path) else {
            return false;
        };
        self.auto_expand_type(idx) == entry.r#type
    }

    /// Recursive override-driven rendering pass (spec 0118 §3): resolves
    /// `idx`'s applicable override and splices a fresh render whenever the
    /// resolved target no longer matches what's currently displayed
    /// (`TreeNode::rendered_as`, spec 0118 §2.1) — comparing against
    /// provenance, not just "is there an override right now?", is what
    /// correctly detects a demotion (an override that used to apply no
    /// longer does), not just fresh promotions/retypes.
    ///
    /// Any/MessageSet auto-expansion (spec 0120) is seeded as a real,
    /// persisted `OverrideEntry` (`OverrideOrigin::Path`) the first time
    /// `idx` is visited with *no entry at all yet existing* for its path —
    /// checked via `self.overrides.entries()`, not via
    /// `resolve_active_override`: the latter can't distinguish "never
    /// seeded" from "user explicitly deactivated the seeded entry", and
    /// naively re-seeding (calling `activate` again) on every subsequent
    /// pass would both silently resurrect a deactivation the user just
    /// made in the manage pane, and — since `activate` unconditionally
    /// resorts the entries list — reshuffle `manage_highlight`'s raw index
    /// out from under the very keypress that triggered this pass. Once
    /// truly first-seeded, `auto_expand_type(idx)` computes the derived
    /// type, `self.overrides.activate` records it, and — because this
    /// happens *before* `target`/`current` are computed below — the very
    /// same pass's `resolve_active_override` already sees it, so no
    /// separate fallback tier is needed in the splice logic itself. This
    /// makes the derived type a real, visible, user-editable/removable
    /// entry in the override management pane (rather than a silent
    /// dynamic fallback), and means every subsequent pass resolves it via
    /// the ordinary entries scan instead of re-deriving it from the wire
    /// each time. When no active override applies at all after seeding
    /// (`target == None`, e.g. the type wasn't resolvable, or the user
    /// deactivated it), the effective splice target falls back to
    /// `natural_type(idx)` — `idx`'s inherited type from its parent's
    /// schema. That fallback never fires when an active entry explicitly
    /// says raw (`target == Some(None)`), which still renders raw, since
    /// that's an explicit user choice. The *outer* `Option` of `target` is
    /// still what gets stored into `rendered_as`, preserving the
    /// provenance distinction for the next pass — paired with
    /// `field_name_for(idx)` (spec 0119 §G4): either half changing (a
    /// retype, or a name-only rename of the governing entry) is enough to
    /// trigger a re-splice, since both feed directly into the rendered
    /// text.
    ///
    /// Named `render_overrides` (not `render`) to avoid colliding with the
    /// unrelated `render(&mut self, frame: &mut Frame)` ratatui draw
    /// method below.
    fn render_overrides(&mut self, idx: usize) {
        let origin = OverrideOrigin::Path {
            path: self.positional_path(idx),
        };
        let already_seeded = self.overrides.entries().iter().any(|e| e.origin == origin);
        if !already_seeded {
            if let Some(t) = self.auto_expand_type(idx) {
                // MessageSet tier 1's synthetic wrapper field has no
                // schema-declared name to fall back on (`field_name_for`
                // would otherwise show the bare field number "1"), so
                // seed it with the display name `prototext-core`'s native
                // MessageSet rendering uses for it ("Item") — spec 0120
                // §G2's follow-up cosmetic fix.
                let is_message_set_item = self.tree[idx].span.field_number == 1
                    && self.tree[idx].span.wire_type == prototext_core::helpers::WT_START_GROUP
                    && self.tree[idx]
                        .parent
                        .is_some_and(|p| self.is_message_set_typed(p));
                self.overrides.activate_auto(origin.clone(), Some(t));
                if is_message_set_item {
                    if let Some(entry_idx) = self
                        .overrides
                        .entries()
                        .iter()
                        .position(|e| e.origin == origin)
                    {
                        self.overrides.rename(entry_idx, Some("Item".to_string()));
                    }
                }
            }
        }
        // Demotion (spec 0120 follow-up): an *auto*-seeded entry's
        // derivation depended on its ancestor's context at the time it
        // was seeded (e.g. tier 2's extension-type lookup needs its
        // parent to still resolve as `MessageSetItem`). If that ancestor
        // context has since changed — most commonly because the user
        // deactivated (or retyped) the ancestor's own auto-derived entry
        // — re-deriving now not only can, but must, disagree with the
        // stale persisted type. Detected without touching `active` (so
        // it transparently resumes once the ancestor context is
        // restored): only entries the user has never manually
        // (re-)activated are eligible, since `activate` always pins
        // `auto` back to `false`.
        self.resettle_node(idx);
        let mut child = self.tree[idx].first_child;
        while let Some(c) = child {
            // Recurse into every node actually rendered as message/group
            // (`NodeSpan::is_message`) — the set of nodes that can carry
            // nested overridable children at all (spec 0119) — plus the
            // two specific plain-scalar shapes eligible for Any/
            // MessageSet auto-expansion (spec 0120's
            // `is_auto_expand_candidate`): those aren't `is_message` yet
            // (they're still bytes/varint until auto-overridden), but
            // must still be visited once so `auto_expand_type` above gets
            // a chance to promote them. Recursing into every plain
            // scalar LEN-wire field unconditionally would reopen the
            // spec 0119 bug this same gate was introduced to fix
            // (`natural_type` demoting an ordinary string/bytes field to
            // a raw record dump) — `is_auto_expand_candidate` is
            // deliberately narrow, matching only these two shapes.
            if self.tree[c].span.is_message || self.is_auto_expand_candidate(c) {
                self.render_overrides(c);
            }
            child = self.tree[c].next_sibling;
        }
    }

    /// Unified splice mechanic (spec 0118 §4): regenerates the *whole*
    /// rendering of `idx` — header, interior, and footer alike — under
    /// `target` (`None` = revert to raw, `Some(fqdn)` = retype/promote).
    /// No existing rendering of `idx` is ever reused verbatim: generalizes
    /// `register_wrapper`/`wrap_blob` (spec 0114 §1.1, previously
    /// hardcoded to field number `1` for the document root) to `idx`'s own
    /// real field number, wrapping its payload with a real tag+length and
    /// decoding it as if it were the sole field of a synthetic one-field
    /// message — exactly the trick the root's own initial paint already
    /// used, generalized to every node. This is what fixes task #34 (a
    /// stale `#@` type annotation surviving a retype) as a byproduct, for
    /// every node.
    ///
    /// `idx` keeps its own tree-array identity (so `cursor`/`folded`/
    /// back-jump state referencing it stays valid) — only its `span`
    /// (`raw_range` excepted: the underlying bytes haven't moved) and its
    /// children (old ones orphaned via `collect_descendants`, new ones
    /// appended and stitched in) are replaced.
    fn splice_override(&mut self, idx: usize, target: Option<String>) -> Result<(), String> {
        let target_desc = match &target {
            Some(fqdn) => Some(
                self.ctx
                    .pool()
                    .get_message_by_name(fqdn)
                    .ok_or_else(|| format!("type '{fqdn}' not found in descriptor set"))?,
            ),
            None => None,
        };

        let old_span = self.tree[idx].span.clone();
        let field_number = old_span.field_number;
        let field_name = self.field_name_for(idx);
        let payload_range = extract::message_payload_range(
            &self.blob,
            &old_span.raw_range,
            old_span.packed_record_start,
        );
        let payload_bytes = self.blob[payload_range.clone()].to_vec();
        let wrapped = decode::wrap_blob(field_number, &payload_bytes);
        let wrapper_width = wrapped.len() - payload_bytes.len();

        // Render-cache lookup (spec 0116 §8/0118 §5) — same
        // `payload_range`/type key `candidate_cache` already keys
        // previews on; a hit skips both `decode_and_render_indexed` and
        // the colorize pass.
        let cache_key = (payload_range.clone(), target.clone(), field_name.clone());
        let (mut new_lines, new_spans, new_style_hints) = match self.render_cache.get(&cache_key) {
            Some(cached) => cached,
            None => {
                let wrapper_desc = match &target_desc {
                    Some(desc) => Some(
                        decode::register_wrapper(
                            self.ctx.pool_mut(),
                            field_number,
                            &field_name,
                            desc,
                        )
                        .map_err(|e| e.to_string())?,
                    ),
                    None => None,
                };
                let opts = DecodeRenderOpts {
                    // Always on (spec 0133): annotations are a pure
                    // main-pane display concern, not a decode-time input.
                    annotations: true,
                    indent_size: self.indent_size,
                    initial_level: old_span.level,
                    emit_header: false,
                    // Any/MessageSet expansion is handled by protolens
                    // itself, as automatic overrides (spec 0120), not by
                    // prototext-core's own virtual-node expansion.
                    expand_any: false,
                    expand_message_set: false,
                    ..Default::default()
                };
                let (new_text, new_spans) =
                    decode_and_render_indexed(&wrapped, wrapper_desc.as_ref(), opts);
                let new_text = String::from_utf8(new_text)
                    .map_err(|e| format!("rendered text is not valid UTF-8: {e}"))?;
                let new_lines: Vec<String> = new_text.lines().map(str::to_string).collect();
                let new_style_hints = colorize::colorize(&new_text);
                let value = (new_lines, new_spans, new_style_hints);
                self.render_cache.insert(cache_key, value.clone());
                value
            }
        };

        // Build this node's own header line (spec 0122 §2): patch
        // `old_span`'s own natural annotation with the freshly-resolved
        // type-declaration token, rather than reusing the synthetic
        // wrapper's own header line wholesale (which lost group framing
        // on override — the original bug).
        let brace_prefix = format!("{field_name} {{");
        // Unconditionally computed (spec 0133: annotations are always on
        // at the decode/splice level now) — stored below into the new
        // self-span's own `natural_annotation` too (not just used to
        // build `new_lines[0]`), so a *later* splice on this same node
        // patches from the correct base text instead of the synthetic
        // wrapper's own unpatched rendering.
        let patched_annotation: String = {
            // A message-kind synthetic wrapper field should always carry a
            // natural annotation (`sink.rs`'s `begin_nested` always writes
            // one when annotations are on) — but forcing an incompatible
            // override target onto genuinely non-message bytes (e.g. `t`
            // on a plain string) can defeat that assumption. Rather than
            // panic and lose the user's cursor position/work, fall back to
            // the same "unresolved type" placeholder `wrap_blob`'s own
            // unknown-field cascade already uses elsewhere — the override
            // still applies, and the mismatch surfaces as ordinary
            // `TYPE_MISMATCH`/`INVALID_*` annotations in the interior
            // instead (feedback, 2026-07-16).
            let new_ann_owned = new_spans
                .last()
                .and_then(|s| s.natural_annotation.clone())
                .unwrap_or_else(|| "#@ message".to_string());
            // Step 3: under `wrap_blob`'s hardcoded `WT_LEN` framing this
            // is always token 0 of the synthetic root's own annotation.
            let new_token = new_ann_owned
                .strip_prefix("#@ ")
                .unwrap_or(&new_ann_owned)
                .split("; ")
                .next()
                .unwrap_or("");
            match &old_span.natural_annotation {
                Some(base_ann) => {
                    // Steps 5-6: locate the type-decl/wire-type-
                    // placeholder token slot within the base text and
                    // replace only it — every other token (leading
                    // `group`, any anomaly modifier) is copied through
                    // verbatim, unexamined.
                    let base_content = base_ann.strip_prefix("#@ ").unwrap_or(base_ann);
                    let mut tokens: Vec<&str> = base_content.split("; ").collect();
                    if tokens.first() == Some(&"group") {
                        let has_slot = tokens
                            .get(1)
                            .is_some_and(|t| *t == "TYPE_MISMATCH" || t.contains('='));
                        // `"message"` is `wrap_blob`'s synthetic
                        // Message-kind "unknown schema" placeholder — it
                        // has no equivalent in Group-kind's own native
                        // convention, which simply omits the decl/
                        // mismatch slot entirely when unresolved. Treat
                        // it as "no token" here rather than leaking it
                        // into the group's header (spec 0122).
                        if new_token == "message" {
                            if has_slot {
                                tokens.remove(1);
                            }
                        } else if has_slot {
                            tokens[1] = new_token;
                        } else {
                            tokens.insert(1, new_token);
                        }
                    } else {
                        tokens[0] = new_token;
                    }
                    tokens.join("; ")
                }
                // Step 4 fallback: `old_span` was itself a scalar-origin
                // node (`natural_annotation` is unconditionally `None`
                // for scalars) — no base text to patch, and none needed:
                // by G4 a scalar's `wire_type` never becomes
                // `WT_START_GROUP`, so no `group;` prefix is ever
                // required here.
                None => new_token.to_string(),
            }
        };
        // The synthetic wrapper's own header line (still in `new_lines[0]`
        // at this point) was rendered by `decode_and_render_indexed` with
        // `initial_level: old_span.level`, so its leading whitespace is
        // already this node's correct indentation — preserve it, since
        // `brace_prefix` itself carries none (it's built from bare
        // `field_name`/`"{"`, spec 0122 §2).
        let indent_width = new_lines[0].len() - new_lines[0].trim_start().len();
        let indent = &new_lines[0][..indent_width];
        let patched_first_line = format!("{indent}{brace_prefix}  #@ {patched_annotation}");

        // `new_style_hints`'s byte offsets are relative to the CACHED
        // render's own (unpatched) header line, not `patched_first_line`
        // — bucket by line using `new_lines` while it still carries that
        // cached header, or a header-length delta would silently shift
        // every subsequent line's colors (2026-07-15 regression: colors
        // drifted right after the first `#@ group;` header whenever the
        // patched header's length differed from the cached one). Only
        // line 0's own bucket is stale afterwards, since nothing in
        // `queries/highlights.scm` spans a rendered newline (`colorize`
        // doc comment) — recolor it in isolation once the header is
        // swapped in for display.
        let mut new_line_styles = colorize::hints_by_line(&new_lines, &new_style_hints);
        new_lines[0] = patched_first_line;
        new_line_styles[0] =
            colorize::hints_by_line(&new_lines[..1], &colorize::colorize(&new_lines[0])).remove(0);

        let delta = new_lines.len() as isize
            - (old_span.text_range.end - old_span.text_range.start) as isize;

        // Collect old descendants (pointer-based, before any pointer is
        // overwritten below) and scrub them from `folded` — otherwise
        // `rebuild_visible_rows` could read their now-meaningless stale
        // `text_range` and hide unrelated post-splice content. `idx`
        // itself is deliberately left in `folded` untouched (spec 0118
        // §7 — fold state on `idx` survives its own retype).
        let mut old_descendants = Vec::new();
        self.collect_descendants(idx, &mut old_descendants);
        for d in &old_descendants {
            self.folded.remove(d);
        }
        let old_descendants: HashSet<usize> = old_descendants.into_iter().collect();

        // The live node immediately following the *whole* old subtree in
        // document order — the seam the new subtree must be spliced back
        // into.
        let mut after = self.tree[idx].doc_next;
        while let Some(a) = after {
            if old_descendants.contains(&a) {
                after = self.tree[a].doc_next;
            } else {
                break;
            }
        }

        // Replace `idx`'s *whole* line range (header, interior, and
        // footer alike) — not just its interior, unlike the old
        // `apply_override`.
        self.lines.splice(
            old_span.text_range.start..old_span.text_range.end,
            new_lines,
        );
        self.line_styles.splice(
            old_span.text_range.start..old_span.text_range.end,
            new_line_styles,
        );

        // Translate the freshly built local tree (wrapped-buffer-relative
        // coordinates) into this document's global coordinates and append
        // it at the array's end. `build_tree` always emits a container's
        // own span last (post-order) — the local tree's final entry is
        // always idx's *new* self (the wrapped field, whatever shape it
        // turned out to be); everything else is its descendants.
        let base = self.tree.len();
        let byte_offset = payload_range.start as isize - wrapper_width as isize;
        let local_len = new_spans.len();
        let local_root_idx = local_len - 1;
        let local_tree = decode::build_tree(new_spans);
        for node in local_tree {
            let mut span = node.span;
            span.raw_range = (span.raw_range.start as isize + byte_offset) as usize
                ..(span.raw_range.end as isize + byte_offset) as usize;
            span.text_range = (span.text_range.start + old_span.text_range.start)
                ..(span.text_range.end + old_span.text_range.start);
            let translate = |o: Option<usize>| o.map(|i| i + base);
            // `idx`'s new self is *not* pushed as a separate live entry
            // (its own span/children are folded into `self.tree[idx]`
            // below) — root-level local nodes (parent `None`) and its
            // direct children (local parent == the local root) both
            // become `idx`'s children, so both map their parent to `idx`.
            let parent = if node.parent.is_none() || node.parent == Some(local_root_idx) {
                Some(idx)
            } else {
                node.parent.map(|p| p + base)
            };
            self.tree.push(TreeNode {
                span,
                parent,
                first_child: translate(node.first_child),
                last_child: translate(node.last_child),
                next_sibling: translate(node.next_sibling),
                prev_sibling: translate(node.prev_sibling),
                doc_next: translate(node.doc_next),
                doc_prev: translate(node.doc_prev),
                rendered_as: None,
            });
        }

        // The pushed copy of the local root (at `new_self_idx`) is left
        // orphaned, never referenced again — its span/children are copied
        // into the live `idx` entry instead, same "abandon in place"
        // pattern already used for old descendants.
        let new_self_idx = base + local_root_idx;
        let mut new_self_span = self.tree[new_self_idx].span.clone();
        new_self_span.raw_range = old_span.raw_range.clone();
        // `wrap_blob` always wraps `idx`'s payload as a fresh `WT_LEN`
        // tag (spec 0120 follow-up) regardless of `idx`'s true original
        // wire type in the document — so the freshly-decoded wrapper
        // span's own `wire_type` is generic wrapping metadata, not a
        // faithful re-derivation of what's actually at `raw_range` in
        // `self.blob`. Preserved here alongside `raw_range` (both
        // describe the *real* underlying bytes, unaffected by how this
        // splice chose to reinterpret them) so a later pass can still
        // tell, e.g., that `idx` is really a `WT_START_GROUP` node even
        // after one or more splices — `extract::message_payload_range`
        // sidesteps this by re-parsing the tag from `blob` directly
        // rather than trusting `span.wire_type`, but `auto_expand_type`'s
        // structural candidacy checks read `span.wire_type` straight
        // from the tree and would otherwise wrongly see every
        // previously-spliced node as `WT_LEN` from its second splice
        // onward.
        new_self_span.wire_type = old_span.wire_type;
        // The synthetic wrap-rendered span's own `natural_annotation`
        // (always `Message`-kind, per `wrap_blob`'s hardcoded `WT_LEN`
        // framing — same caveat as `wire_type` above) is not what a
        // *later* splice on this node should patch from; the header text
        // actually patched onto `new_lines[0]` above is (spec 0122 §2) —
        // stored back here so it becomes `old_span.natural_annotation`
        // next time.
        new_self_span.natural_annotation = Some(format!("#@ {patched_annotation}"));
        self.tree[idx].span = new_self_span;
        self.tree[idx].first_child = self.tree[new_self_idx].first_child;
        self.tree[idx].last_child = self.tree[new_self_idx].last_child;

        if local_len > 1 {
            let first_new = self.tree[new_self_idx].doc_next;
            let last_new = (base..base + local_len)
                .find(|&i| self.tree[i].doc_next.is_none())
                .expect("local tree with descendants has a document-order last node");
            self.tree[idx].doc_next = first_new;
            if let Some(fnw) = first_new {
                self.tree[fnw].doc_prev = Some(idx);
            }
            self.tree[last_new].doc_next = after;
            if let Some(a) = after {
                self.tree[a].doc_prev = Some(last_new);
            }
        } else {
            self.tree[idx].doc_next = after;
            if let Some(a) = after {
                self.tree[a].doc_prev = Some(idx);
            }
        }

        // Forward doc-chain shift: every node from `after` onward has its
        // own text_range shifted by `delta`.
        let mut cur = after;
        while let Some(c) = cur {
            let r = &mut self.tree[c].span.text_range;
            r.start = (r.start as isize + delta) as usize;
            r.end = (r.end as isize + delta) as usize;
            cur = self.tree[c].doc_next;
        }
        // Ancestor closing-brace-line shift: each ancestor's own opening
        // line is unaffected, only its closing line moves.
        let mut p = self.tree[idx].parent;
        while let Some(pi) = p {
            self.tree[pi].span.text_range.end =
                (self.tree[pi].span.text_range.end as isize + delta) as usize;
            p = self.tree[pi].parent;
        }

        // Full rebuild — walking the doc chain (not array order) so
        // orphaned entries are naturally excluded.
        self.line_to_node.clear();
        self.footer_line_to_node.clear();
        let mut cur = Some(self.first_node);
        while let Some(c) = cur {
            self.line_to_node
                .insert(self.tree[c].span.text_range.start, c);
            if self.tree[c].first_child.is_some() {
                self.footer_line_to_node
                    .insert(self.tree[c].span.text_range.end - 1, c);
            }
            cur = self.tree[c].doc_next;
        }
        self.rebuild_visible_rows();

        Ok(())
    }

    /// Origin for a brand-new override, targeting node `idx` — always
    /// created as kind `Path` (spec 0134 G1). Delegates to
    /// `origin_for_kind`.
    fn override_origin_for_kind(&self, idx: usize) -> Result<OverrideOrigin, String> {
        self.origin_for_kind(idx, OverrideKind::Path)
    }

    /// Origin for an arbitrary `kind`, targeting node `idx` (spec 0117
    /// §2's derivation rules, generalized in spec 0124 G2 so the
    /// manage-pane `z` key can rederive an origin under a rotated kind).
    /// `PathField`/`FqdnField` error out when `idx` is the wrapper root
    /// (no parent) or, for `FqdnField`, when the parent's `type_fqdn` is
    /// unresolved.
    fn origin_for_kind(&self, idx: usize, kind: OverrideKind) -> Result<OverrideOrigin, String> {
        match kind {
            OverrideKind::Path => Ok(OverrideOrigin::Path {
                path: self.positional_path(idx),
            }),
            OverrideKind::PathField => {
                let parent = self.tree[idx]
                    .parent
                    .ok_or_else(|| "cursor is the wrapper root (no parent)".to_string())?;
                Ok(OverrideOrigin::PathField {
                    path: self.positional_path(parent),
                    field: self.tree[idx].span.field_number,
                })
            }
            OverrideKind::FqdnField => {
                let parent = self.tree[idx]
                    .parent
                    .ok_or_else(|| "cursor is the wrapper root (no parent)".to_string())?;
                let fqdn = self.tree[parent]
                    .span
                    .type_fqdn
                    .clone()
                    .ok_or_else(|| "parent's type is unresolved".to_string())?;
                Ok(OverrideOrigin::FqdnField {
                    fqdn,
                    field: self.tree[idx].span.field_number,
                })
            }
        }
    }

    /// Third `OverrideKind` — the one that is neither `a` nor `b` (spec
    /// 0134 G2 step 5's `other_kind`; there are only 3 kinds total).
    fn third_kind(a: OverrideKind, b: OverrideKind) -> OverrideKind {
        [
            OverrideKind::Path,
            OverrideKind::PathField,
            OverrideKind::FqdnField,
        ]
        .into_iter()
        .find(|k| *k != a && *k != b)
        .expect("3 kinds total, 2 excluded, 1 remains")
    }

    /// Origins derivable under `kind` from every node in `affected`, in
    /// document order, deduplicated by `OverrideOrigin` equality (spec
    /// 0134 G2 step 4).
    fn manage_kind_candidates(
        &self,
        affected: &[usize],
        kind: OverrideKind,
    ) -> Vec<OverrideOrigin> {
        let mut result: Vec<OverrideOrigin> = Vec::new();
        for &node in affected {
            if let Ok(origin) = self.origin_for_kind(node, kind) {
                if !result.contains(&origin) {
                    result.push(origin);
                }
            }
        }
        result
    }

    /// Document-order list of main-pane node indices whose origin
    /// matches `origin` exactly (spec 0124 G1, also reused by G2's `z`
    /// membership test). `Path` has at most one match, via
    /// `resolve_path`; `PathField` scans the one parent's children;
    /// `FqdnField` has no shortcut — a message type of a given FQDN can
    /// recur anywhere in the tree, so this is a full document-order walk.
    fn manage_affected_nodes(&self, origin: &OverrideOrigin) -> Vec<usize> {
        match origin {
            OverrideOrigin::Path { path } => self.resolve_path(path).into_iter().collect(),
            OverrideOrigin::PathField { path, field } => {
                let Some(parent) = self.resolve_path(path) else {
                    return Vec::new();
                };
                let mut result = Vec::new();
                let mut child = self.tree[parent].first_child;
                while let Some(c) = child {
                    if self.tree[c].span.field_number == *field {
                        result.push(c);
                    }
                    child = self.tree[c].next_sibling;
                }
                result
            }
            OverrideOrigin::FqdnField { fqdn, field } => {
                let mut result = Vec::new();
                let mut cur = Some(self.first_node);
                while let Some(c) = cur {
                    let parent_fqdn = self.tree[c]
                        .parent
                        .and_then(|p| self.tree[p].span.type_fqdn.as_deref());
                    if self.tree[c].span.field_number == *field
                        && parent_fqdn == Some(fqdn.as_str())
                    {
                        result.push(c);
                    }
                    cur = self.tree[c].doc_next;
                }
                result
            }
        }
    }

    /// Handle a keypress while the override pane has focus (spec 0114
    /// §2/§3/§4).
    fn handle_override_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Tab => self.override_focus = false,
            KeyCode::Esc | KeyCode::Char('t') | KeyCode::Char('q') => self.close_override(),
            KeyCode::Char('j') | KeyCode::Down => self.move_override_highlight(1),
            KeyCode::Char('k') | KeyCode::Up => self.move_override_highlight(-1),
            KeyCode::PageDown => {
                self.move_override_highlight(self.override_list_height.max(1) as isize)
            }
            KeyCode::PageUp => {
                self.move_override_highlight(-(self.override_list_height.max(1) as isize))
            }
            KeyCode::Home => {
                self.override_highlight = 0;
                self.preview_override_highlight();
            }
            KeyCode::End => {
                if !self.override_candidates_complete && self.override_sort == SortMode::Inferred {
                    self.upgrade_active_override_to_complete();
                }
                self.override_highlight = self.override_candidates.len();
                self.preview_override_highlight();
            }
            KeyCode::Char('a') => {
                self.override_sort = match self.override_sort {
                    SortMode::Lexicographic => SortMode::Inferred,
                    SortMode::Inferred => SortMode::Lexicographic,
                };
                self.recompute_override_candidates();
            }
            // In-pane search (spec 0114 §4, spec-0133-adjacent rework):
            // reuses the shared bottom command/message bar as the search
            // prompt, same mechanism as the main pane's own `/`/`?`
            // (`handle_command_key`'s `Enter` arm dispatches to
            // `jump_to_override_match` while `override_focus` is set).
            KeyCode::Char('/') => {
                self.command_kind = CommandLineKind::Search(SearchDir::Forward);
                self.command_buffer = Some(String::new());
                self.command_cursor = 0;
            }
            KeyCode::Char('?') => {
                self.command_kind = CommandLineKind::Search(SearchDir::Backward);
                self.command_buffer = Some(String::new());
                self.command_cursor = 0;
            }
            KeyCode::Char('n') => {
                if let Some((dir, pattern)) = self.last_override_search.clone() {
                    self.jump_to_override_match(dir, &pattern);
                }
            }
            KeyCode::Enter => {
                let Some(idx) = self.override_target else {
                    return;
                };
                // Row 0 is the pinned `<raw / no type>` entry (§3.1);
                // rows 1.. are `override_candidates[row - 1]`.
                let new_fqdn = if self.override_highlight == 0 {
                    None
                } else {
                    match self
                        .override_candidates
                        .get(self.override_highlight - 1)
                        .map(|(fqdn, _)| fqdn.clone())
                    {
                        Some(fqdn) => Some(fqdn),
                        None => {
                            self.message =
                                "cannot apply override: no candidate selected".to_string();
                            return;
                        }
                    }
                };
                // Spec 0117 §2: per-kind origin — errors (wrapper root,
                // unresolved parent FQDN) abort before either the
                // collection or 0114's splice-render is touched.
                let origin = match self.override_origin_for_kind(idx) {
                    Ok(origin) => origin,
                    Err(e) => {
                        self.message = format!("cannot create override: {e}");
                        return;
                    }
                };
                // Spec 0118 §6: any kind's activation triggers the
                // recursive render pass — `path`/`path-field`/`fqdn-field`
                // alike, not just `path` (unlike the old one-shot
                // `apply_override`, which only ever fired for `path`).
                self.overrides.activate(origin.clone(), new_fqdn.clone());
                self.render_overrides(self.first_node);
                // Spec 0119 G3: land in the management pane, highlighting
                // the entry just created/reactivated, instead of just
                // closing the pane. `activate` guarantees at most one
                // entry per origin is active, so this origin/type pair
                // unambiguously identifies it.
                let target_highlight = self
                    .overrides
                    .entries()
                    .iter()
                    .position(|e| e.origin == origin && e.r#type == new_fqdn);
                self.close_override();
                self.manage_open = true;
                self.manage_focus = true;
                self.manage_highlight = target_highlight.unwrap_or(0);
                self.manage_scroll = 0;
                self.manage_pan_offset = 0;
            }
            _ => {}
        }
    }

    /// Handle a keypress while the override management pane is open (spec
    /// 0117 §3) — always focused while open, no separate focus check
    /// (unlike `handle_override_key`).
    fn handle_manage_key(&mut self, key: KeyEvent) {
        if let Some(buffer) = &mut self.manage_rename {
            match key.code {
                KeyCode::Esc => self.manage_rename = None,
                KeyCode::Enter => {
                    let buffer = self.manage_rename.take().expect("checked above");
                    let name = if buffer.is_empty() {
                        None
                    } else {
                        Some(buffer)
                    };
                    let was_active = self.overrides.entries()[self.manage_highlight].active;
                    self.overrides.rename(self.manage_highlight, name);
                    if was_active {
                        self.render_overrides(self.first_node);
                    }
                }
                KeyCode::Backspace => {
                    buffer.pop();
                }
                KeyCode::Char(c) => buffer.push(c),
                _ => {}
            }
            return;
        }
        match key.code {
            KeyCode::Tab => self.manage_focus = false,
            KeyCode::Esc | KeyCode::Char('o') | KeyCode::Char('q') | KeyCode::Enter => {
                self.close_manage_pane()
            }
            KeyCode::Char('j') | KeyCode::Down => self.move_manage_highlight(1),
            KeyCode::Char('k') | KeyCode::Up => self.move_manage_highlight(-1),
            KeyCode::PageDown => {
                self.move_manage_highlight(self.manage_list_height.max(1) as isize)
            }
            KeyCode::PageUp => {
                self.move_manage_highlight(-(self.manage_list_height.max(1) as isize))
            }
            KeyCode::Home => {
                self.manage_highlight = 0;
                self.manage_pending_kind = None;
            }
            KeyCode::End => {
                self.manage_highlight = self.overrides.entries().len().saturating_sub(1);
                self.manage_pending_kind = None;
            }
            // Spec 0124 G1: circulate the main-pane cursor among the
            // fields the highlighted entry's origin currently matches,
            // without touching focus. No-op on zero matches; if the
            // cursor isn't currently one of the matches, jumps to the
            // first (Right) or last (Left) match.
            KeyCode::Left | KeyCode::Right => {
                if let Some(entry) = self.overrides.entries().get(self.manage_highlight) {
                    let origin = entry.origin.clone();
                    let affected = self.manage_affected_nodes(&origin);
                    if !affected.is_empty() {
                        let next = match affected.iter().position(|&i| i == self.cursor) {
                            Some(pos) if key.code == KeyCode::Right => {
                                affected[(pos + 1) % affected.len()]
                            }
                            Some(pos) => affected[(pos + affected.len() - 1) % affected.len()],
                            None if key.code == KeyCode::Right => affected[0],
                            None => affected[affected.len() - 1],
                        };
                        self.record_jump(self.cursor);
                        self.cursor = next;
                    }
                }
            }
            // In-pane search (spec 0117 §3, spec-0133-adjacent rework):
            // reuses the shared bottom command/message bar as the search
            // prompt, mirroring the override pane's own `/`/`?`
            // (`handle_command_key`'s `Enter` arm dispatches to
            // `jump_to_manage_match` while `manage_open && manage_focus`).
            KeyCode::Char('/') => {
                self.command_kind = CommandLineKind::Search(SearchDir::Forward);
                self.command_buffer = Some(String::new());
                self.command_cursor = 0;
            }
            KeyCode::Char('?') => {
                self.command_kind = CommandLineKind::Search(SearchDir::Backward);
                self.command_buffer = Some(String::new());
                self.command_cursor = 0;
            }
            KeyCode::Char('n') => {
                if let Some((dir, pattern)) = self.last_manage_search.clone() {
                    self.jump_to_manage_match(dir, &pattern);
                }
            }
            // Spec 0119 §G4: edit the highlighted entry's display-name
            // override, pre-filled with its current value (empty when
            // unset).
            KeyCode::Char('f') => {
                if !self.overrides.entries().is_empty() {
                    let current = self.overrides.entries()[self.manage_highlight]
                        .name
                        .clone()
                        .unwrap_or_default();
                    self.manage_rename = Some(current);
                }
            }
            // Spec 0118 §6: toggling active status changes the active set
            // (possibly for a sibling too), so it always triggers a
            // recursive render pass.
            KeyCode::Char('a') | KeyCode::Char(' ') => {
                if !self.overrides.entries().is_empty() {
                    self.overrides.toggle_active(self.manage_highlight);
                    self.render_overrides(self.first_node);
                }
            }
            // Spec 0134 G2/G3: forgiving multi-candidate resolution —
            // works out the mutated origin from every node the entry
            // currently affects, only falling back to the main-pane
            // cursor/message line when genuinely ambiguous, and never
            // gets stuck repeating an unresolvable rotation (advances one
            // more step down the 3-kind barrel on a same-key retry with
            // an unchanged cursor). `Z` rotates in reverse.
            KeyCode::Char('z') | KeyCode::Char('Z') => {
                if let Some(entry) = self.overrides.entries().get(self.manage_highlight) {
                    let origin = entry.origin.clone();
                    let r#type = entry.r#type.clone();
                    let was_active = entry.active;
                    let entry_kind = origin.kind();
                    let reverse = key.code == KeyCode::Char('Z');
                    let affected = self.manage_affected_nodes(&origin);

                    let attempt_kind = match &self.manage_pending_kind {
                        Some((pending_origin, kind, last_cursor)) if *pending_origin == origin => {
                            if self.cursor == *last_cursor {
                                if reverse {
                                    kind.prev()
                                } else {
                                    kind.next()
                                }
                            } else {
                                *kind
                            }
                        }
                        _ => {
                            if reverse {
                                entry_kind.prev()
                            } else {
                                entry_kind.next()
                            }
                        }
                    };

                    let candidates = self.manage_kind_candidates(&affected, attempt_kind);

                    if candidates.is_empty() {
                        let other_kind = Self::third_kind(entry_kind, attempt_kind);
                        let other_candidates = self.manage_kind_candidates(&affected, other_kind);
                        if other_candidates.is_empty() {
                            self.message = "z: no override target".to_string();
                            self.manage_pending_kind = None;
                        } else {
                            self.message = format!(
                                "z: no override target, try again for {} origin",
                                other_kind.label()
                            );
                            self.manage_pending_kind = Some((origin, attempt_kind, self.cursor));
                        }
                    } else {
                        let cursor_origin = if affected.contains(&self.cursor) {
                            self.origin_for_kind(self.cursor, attempt_kind).ok()
                        } else {
                            None
                        };
                        let resolved = cursor_origin
                            .or_else(|| (candidates.len() == 1).then(|| candidates[0].clone()));

                        match resolved {
                            Some(new_origin) => {
                                self.manage_highlight = self
                                    .overrides
                                    .rotate_origin(self.manage_highlight, new_origin.clone());
                                if was_active {
                                    self.render_overrides(self.first_node);
                                    // `render_overrides` can auto-seed
                                    // brand-new entries elsewhere in the
                                    // tree (Any/MessageSet auto-expansion),
                                    // which re-sorts the whole collection
                                    // and can invalidate the index
                                    // `rotate_origin` just returned above
                                    // — relocate the rotated entry by
                                    // identity instead of trusting the
                                    // pre-render index (feedback,
                                    // 2026-07-16).
                                    if let Some(idx) =
                                        self.overrides.entries().iter().rposition(|e| {
                                            e.origin == new_origin && e.r#type == r#type
                                        })
                                    {
                                        self.manage_highlight = idx;
                                    }
                                }
                                self.manage_pending_kind = None;
                            }
                            None => {
                                self.message = "z: pick an override target (<-/->)".to_string();
                                self.manage_pending_kind =
                                    Some((origin, attempt_kind, self.cursor));
                            }
                        }
                    }
                }
            }
            // Spec 0124 G3: duplicate the highlighted entry as a new,
            // always-inactive copy.
            KeyCode::Char('d') => {
                if !self.overrides.entries().is_empty() {
                    self.manage_highlight = self.overrides.duplicate(self.manage_highlight);
                    self.manage_pending_kind = None;
                    self.render_overrides(self.first_node);
                }
            }
            // Spec 0125 §G2: an in-scope `auto` entry is deactivated
            // instead of removed — deleting it would just make
            // `render_overrides`'s next pass re-seed an identical entry.
            KeyCode::Delete | KeyCode::Backspace => {
                if let Some(entry) = self.overrides.entries().get(self.manage_highlight).cloned() {
                    if entry.auto && self.auto_entry_in_scope(&entry) {
                        if entry.active {
                            self.overrides.toggle_active(self.manage_highlight);
                            self.render_overrides(self.first_node);
                        }
                        self.message = "auto-derived override deactivated (still in scope \
                            — delete would just recreate it; use 'a' or wait for it to go \
                            out of scope)"
                            .to_string();
                    } else {
                        // Spec 0118 §6: only re-render when the removed
                        // entry was active — removing an inactive entry
                        // cannot change any node's resolved override.
                        let was_active = entry.active;
                        self.overrides.remove(self.manage_highlight);
                        let len = self.overrides.entries().len();
                        if self.manage_highlight >= len {
                            self.manage_highlight = len.saturating_sub(1);
                        }
                        self.manage_pending_kind = None;
                        if was_active {
                            self.render_overrides(self.first_node);
                        }
                    }
                }
            }
            KeyCode::Char('s') => {
                let buf = format!("save-overrides {}", self.default_save_overrides_path());
                self.command_kind = CommandLineKind::Command;
                self.command_cursor = buf.chars().count();
                self.command_buffer = Some(buf);
            }
            KeyCode::Char('r') => {
                let buf = "restore-overrides ".to_string();
                self.command_kind = CommandLineKind::Command;
                self.command_cursor = buf.chars().count();
                self.command_buffer = Some(buf);
            }
            _ => {}
        }
    }

    fn record_jump(&mut self, from: usize) {
        self.back_stack.push(from);
        self.fwd_stack.clear();
    }

    /// Propose a default `:extract`/`x` path, in the same directory as the
    /// original blob: `<blob_stem>.<raw_start>-<raw_end>.<short_type>.pb`.
    /// The byte range ties the filename back to the status line's
    /// `bytes[..]` display (and keeps repeated extracts from the same blob
    /// collision-free); the short type name (the FQDN's last `.`-segment)
    /// adds readability. Always `.pb`, regardless of format (0113 D23) —
    /// binary and `#@ prototext` are both "a protobuf-shaped payload"; the
    /// extension shouldn't leak which one was chosen.
    fn default_extract_path(&self) -> String {
        let stem = self
            .blob_path
            .file_stem()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| "extract".to_string());
        let node = &self.tree[self.cursor].span;
        let short_type = node
            .type_fqdn
            .as_deref()
            .and_then(|f| f.rsplit('.').next())
            .unwrap_or("node");
        let range = self.display_range(self.cursor);
        let filename = format!("{stem}.{}-{}.{short_type}.pb", range.start, range.end);
        match self.blob_path.parent() {
            Some(dir) if !dir.as_os_str().is_empty() => {
                dir.join(filename).to_string_lossy().into_owned()
            }
            _ => filename,
        }
    }

    /// First `q` press: arm `quit_confirm` and prompt; meaningless once
    /// already armed (the top-of-`handle_key` check in that case handles
    /// the second press directly, before dispatch ever reaches here).
    fn request_quit(&mut self) {
        self.quit_confirm = true;
        self.message = "quit? press q again to confirm, any other key cancels".to_string();
    }

    /// Handle one key event, mutating cursor/fold/scroll/jumplist state.
    /// No `ratatui` rendering happens here — see spec 0111 §4.
    pub fn handle_key(&mut self, key: KeyEvent) {
        // Dismiss the splash screen transparently: the key that dismisses
        // it is also processed as a real command, same as if there had
        // been no splash screen at all (spec 0113 D22 amendment).
        self.splash = false;

        // `Ctrl-Z` suspends the process (spec 0113 D31, Unix only) —
        // checked centrally here, ahead of every other dispatch, so it
        // applies uniformly regardless of focus/mode, same as
        // `quit_confirm` below. Left unbound on non-Unix platforms
        // (no `SIGTSTP` equivalent). Doesn't touch `quit_confirm`, so a
        // pending quit confirmation survives a suspend/resume cycle.
        #[cfg(unix)]
        if key.code == KeyCode::Char('z') && key.modifiers.contains(KeyModifiers::CONTROL) {
            self.should_suspend = true;
            return;
        }

        // A prior `q` press is awaiting confirmation (see `request_quit`):
        // resolve it here, ahead of every other dispatch, so it applies
        // uniformly regardless of which mode/pane has focus. A second `q`
        // quits; any other key cancels without otherwise acting on it.
        if self.quit_confirm {
            self.quit_confirm = false;
            if key.code == KeyCode::Char('q') {
                self.should_quit = true;
            } else {
                self.message.clear();
            }
            return;
        }

        // `F1` opens the help overlay regardless of current focus (spec
        // 0126 G1) — checked centrally here, same tier as `Ctrl-Z`/
        // `quit_confirm` above, ahead of every focus-specific dispatch.
        // Closing it again is still handled by `handle_help_key`'s own
        // `F1` arm below (`self.help_open` branch), which fires first
        // once help is open, so this only ever needs to *open* it.
        if !self.help_open && key.code == KeyCode::F(1) {
            self.help_open = true;
            self.help_scroll = 0;
            return;
        }

        if self.help_open {
            self.handle_help_key(key);
            return;
        }
        if self.command_buffer.is_some() {
            self.handle_command_key(key);
            return;
        }
        if self.override_focus {
            self.handle_override_key(key);
            return;
        }
        if self.manage_open && self.manage_focus {
            self.handle_manage_key(key);
            return;
        }
        self.message.clear();

        // An empty tree (e.g. reopening an extracted `google.protobuf.Empty`,
        // or any all-default submessage — decoding zero bytes legitimately
        // yields zero fields, see spec 0113) has no cursor node to index
        // into: only allow the keys that don't touch `self.tree`.
        if self.tree.is_empty() {
            match key.code {
                KeyCode::Char('q') => self.request_quit(),
                KeyCode::Char(':') => {
                    self.command_kind = CommandLineKind::Command;
                    self.command_buffer = Some(String::new());
                    self.command_cursor = 0;
                }
                _ => {}
            }
            return;
        }

        // `gg` chord (vim-style jump-to-first): a first `g` press arms
        // `pending_g`; a second `g` press immediately after fires
        // `move_home()`. Any other key clears the pending state.
        if key.code == KeyCode::Char('g') {
            if self.pending_g {
                self.pending_g = false;
                self.move_home();
            } else {
                self.pending_g = true;
            }
            return;
        }
        self.pending_g = false;

        match key.code {
            KeyCode::Char('q') => self.request_quit(),

            // Sibling-skip move (spec 0126 G2: Shift-Down/Shift-Up alias
            // `J`/`K` — checked before the plain Down/Up arms below, same
            // "modifier-guard first" convention as Ctrl/Shift-Left/Right
            // above).
            KeyCode::Down if key.modifiers.contains(KeyModifiers::SHIFT) => {
                self.next_sibling_move()
            }
            KeyCode::Up if key.modifiers.contains(KeyModifiers::SHIFT) => self.prev_sibling_move(),
            KeyCode::Char('J') => self.next_sibling_move(),
            KeyCode::Char('K') => self.prev_sibling_move(),

            // Document-order move.
            KeyCode::Char('j') | KeyCode::Down => self.move_down(),
            KeyCode::Char('k') | KeyCode::Up => self.move_up(),

            // Jump to first/last visible node.
            KeyCode::Home => self.move_home(),
            KeyCode::End | KeyCode::Char('G') => self.move_end(),

            // Page move.
            KeyCode::PageDown => self.move_page_down(),
            KeyCode::PageUp => self.move_page_up(),

            // Horizontal pan (spec 0113 D24). Checked before the
            // Shift-guarded and plain Left/Right arms below, since `Ctrl`
            // and `Shift` are independent modifier checks.
            KeyCode::Left if key.modifiers.contains(KeyModifiers::CONTROL) => self.pan_left(),
            KeyCode::Right if key.modifiers.contains(KeyModifiers::CONTROL) => self.pan_right(),

            // Fold all siblings of the cursor node (alias for `H`).
            KeyCode::Left if key.modifiers.contains(KeyModifiers::SHIFT) => {
                self.fold_all_siblings()
            }

            // Parent move / fold (nvim-tree-style: fold an expanded
            // foldable node first; a second press then moves to parent).
            // At the root (no parent to move to), fold all root-level
            // siblings instead — same effect as `H`.
            KeyCode::Char('h') | KeyCode::Left => {
                if self.has_children(self.cursor) && !self.folded.contains(&self.cursor) {
                    self.toggle_fold(self.cursor);
                } else if let Some(parent) = self.tree[self.cursor].parent {
                    self.record_jump(self.cursor);
                    self.cursor = parent;
                } else {
                    self.fold_all_siblings();
                }
            }

            // Fold all siblings of the cursor node (its level under the
            // same parent, or all root-level nodes if the cursor is at the
            // root — sibling links are unconditional, see sibling_range).
            KeyCode::Char('H') => self.fold_all_siblings(),

            // Unfold all siblings of the cursor node.
            KeyCode::Right if key.modifiers.contains(KeyModifiers::SHIFT) => {
                self.unfold_all_siblings()
            }

            // Unfold / child move (ARIA tree-view pattern, symmetric with
            // `h`/`Left`: open a closed foldable node first, cursor stays;
            // a second press then moves to the first child).
            KeyCode::Char('l') | KeyCode::Right => {
                if self.has_children(self.cursor) && self.folded.contains(&self.cursor) {
                    self.toggle_fold(self.cursor);
                } else if let Some(child) = self.tree[self.cursor].first_child {
                    self.record_jump(self.cursor);
                    self.cursor = child;
                } else {
                    self.message = "no children".to_string();
                }
            }

            // Fold/unfold toggle.
            KeyCode::Char('z') | KeyCode::Char(' ') => {
                if self.has_children(self.cursor) {
                    self.toggle_fold(self.cursor);
                } else {
                    self.message = "not foldable".to_string();
                }
            }

            // Toggle main-pane annotation display (spec 0133 G3) — a
            // pure display attribute, distinct from the override pane's
            // own `a` (candidate sort toggle) and the manage pane's own
            // `a` (entry active toggle), both gated behind their own
            // focus checks and unreachable here.
            KeyCode::Char('a') => self.annotations = !self.annotations,

            // Navigation history.
            KeyCode::Char('o') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                if let Some(pos) = self.back_stack.pop() {
                    self.fwd_stack.push(self.cursor);
                    self.cursor = pos;
                    self.unfold_ancestors(pos);
                } else {
                    self.message = "jumplist: at oldest position".to_string();
                }
            }
            KeyCode::Char('i') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                if let Some(pos) = self.fwd_stack.pop() {
                    self.back_stack.push(self.cursor);
                    self.cursor = pos;
                    self.unfold_ancestors(pos);
                } else {
                    self.message = "jumplist: at newest position".to_string();
                }
            }

            // Extract command line (vim-style): `:` opens an empty
            // ex-command line; `x` is a shortcut that pre-fills it with
            // "extract " plus a proposed default path (0113 D21).
            KeyCode::Char(':') => {
                self.command_kind = CommandLineKind::Command;
                self.command_buffer = Some(String::new());
                self.command_cursor = 0;
            }
            KeyCode::Char('x') => {
                let buf = format!("extract {}", self.default_extract_path());
                self.command_kind = CommandLineKind::Command;
                self.command_cursor = buf.chars().count();
                self.command_buffer = Some(buf);
            }

            // In-pane search (spec 0114 §4, extended to the main pane):
            // reuses the command-line row as the search prompt. Only
            // reachable with main-pane focus — `override_focus` is checked
            // earlier in `handle_key`, and the override pane has its own
            // `/`/`?`/`n` in `handle_override_key`.
            KeyCode::Char('/') => {
                self.command_kind = CommandLineKind::Search(SearchDir::Forward);
                self.command_buffer = Some(String::new());
                self.command_cursor = 0;
            }
            KeyCode::Char('?') => {
                self.command_kind = CommandLineKind::Search(SearchDir::Backward);
                self.command_buffer = Some(String::new());
                self.command_cursor = 0;
            }
            KeyCode::Char('n') => {
                if let Some((dir, pattern)) = self.last_search.clone() {
                    self.jump_to_match(dir, &pattern);
                }
            }

            // Override pane (spec 0114 §1/§2): `t` opens/closes it; `Tab`
            // moves focus into it while it's open; `Esc` closes it
            // (focus is main pane here, since `override_focus` is
            // checked earlier in `handle_key`) — same "works regardless
            // of focus" treatment as `t`.
            KeyCode::Char('t') => self.toggle_override(),
            KeyCode::Esc if self.override_target.is_some() => self.close_override(),
            // Spec 0129 §G3: `Esc` clears an active main-pane line
            // selection, alongside whatever else it already clears above.
            KeyCode::Esc => {
                self.select_anchor = None;
                self.select_end = None;
            }

            // Spec 0131 §G1: `Ctrl-C` is the single, explicit copy key —
            // copies the active drag-selection if one exists, else the
            // cursor's own current line. Mouse release no longer copies
            // by itself (see the no-op `Up(MouseButton::Left)` arm in
            // `handle_mouse`).
            KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                self.copy_current_selection_or_line()
            }
            KeyCode::Tab if self.override_target.is_some() => self.override_focus = true,

            // Override management pane (spec 0117 §3): `o` opens/closes
            // it, mirroring `t`. `Tab` moves focus back into it while
            // it's open, mirroring the override selection pane (a
            // main-pane mouse click can also shift focus here without
            // closing the pane — `handle_mouse`, 2026-07-14 feedback).
            KeyCode::Char('o') => self.toggle_manage_pane(),
            KeyCode::Tab if self.manage_open => self.manage_focus = true,

            _ => {}
        }
    }

    /// Scroll/close the `F1` help overlay.
    fn handle_help_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Char('q') | KeyCode::Esc | KeyCode::F(1) => self.help_open = false,
            KeyCode::Char('j') | KeyCode::Down => {
                self.help_scroll = self.help_scroll.saturating_add(1)
            }
            KeyCode::Char('k') | KeyCode::Up => {
                self.help_scroll = self.help_scroll.saturating_sub(1)
            }
            KeyCode::PageDown => self.help_scroll = self.help_scroll.saturating_add(10),
            KeyCode::PageUp => self.help_scroll = self.help_scroll.saturating_sub(10),
            _ => {}
        }
    }

    /// Edit the in-progress command-line buffer at `command_cursor`
    /// (a proper single-line text-input model — `Left`/`Right`/`Home`/`End`
    /// move it, `Backspace`/`Delete`/typing act relative to it), or
    /// execute/cancel the buffer. `Backspace` on an empty buffer cancels,
    /// matching vim's own command line.
    fn handle_command_key(&mut self, key: KeyEvent) {
        // Any key other than Tab/Shift-Tab ends an in-progress completion
        // cycle (spec 0113 D26) — a fresh Tab press afterward starts a new
        // one from scratch, against whatever the buffer/cursor now are.
        if !matches!(key.code, KeyCode::Tab | KeyCode::BackTab) {
            self.completion = None;
        }
        match key.code {
            KeyCode::Tab if self.command_kind == CommandLineKind::Command => {
                self.handle_tab_key(true)
            }
            KeyCode::BackTab if self.command_kind == CommandLineKind::Command => {
                self.handle_tab_key(false)
            }
            KeyCode::Enter => {
                let buf = self.command_buffer.take().unwrap_or_default();
                self.command_cursor = 0;
                match self.command_kind {
                    CommandLineKind::Command => self.run_command(&buf),
                    // Vim convention: `/`/`?` confirmed with an empty
                    // pattern re-uses the last active pattern, searching
                    // in the newly chosen direction (which may differ
                    // from the direction that pattern was originally
                    // searched in — unlike `n`, which always repeats in
                    // the same direction as last time). Which pane's
                    // search actually runs is determined by whichever
                    // pane has focus right now — `override_focus`/
                    // `manage_focus` are untouched by typing into
                    // `command_buffer` (spec 0114 §4/0117 §3, extended by
                    // this rework to share the main pane's own bar).
                    CommandLineKind::Search(dir) if self.override_focus => {
                        let pattern = if buf.is_empty() {
                            self.last_override_search
                                .as_ref()
                                .map(|(_, p)| p.clone())
                                .unwrap_or(buf)
                        } else {
                            buf
                        };
                        self.last_override_search = Some((dir, pattern.clone()));
                        self.jump_to_override_match(dir, &pattern);
                    }
                    CommandLineKind::Search(dir) if self.manage_open && self.manage_focus => {
                        let pattern = if buf.is_empty() {
                            self.last_manage_search
                                .as_ref()
                                .map(|(_, p)| p.clone())
                                .unwrap_or(buf)
                        } else {
                            buf
                        };
                        self.last_manage_search = Some((dir, pattern.clone()));
                        self.jump_to_manage_match(dir, &pattern);
                    }
                    CommandLineKind::Search(dir) => {
                        let pattern = if buf.is_empty() {
                            self.last_search
                                .as_ref()
                                .map(|(_, p)| p.clone())
                                .unwrap_or(buf)
                        } else {
                            buf
                        };
                        self.last_search = Some((dir, pattern.clone()));
                        self.jump_to_match(dir, &pattern);
                    }
                }
            }
            KeyCode::Esc => {
                self.command_buffer = None;
                self.command_cursor = 0;
                self.message.clear();
            }
            KeyCode::Left => self.command_cursor = self.command_cursor.saturating_sub(1),
            KeyCode::Right => {
                let len = self.command_buffer_char_len();
                self.command_cursor = (self.command_cursor + 1).min(len);
            }
            KeyCode::Home => self.command_cursor = 0,
            KeyCode::End => self.command_cursor = self.command_buffer_char_len(),
            KeyCode::Backspace => {
                let empty = match &self.command_buffer {
                    Some(buf) => buf.is_empty(),
                    None => true,
                };
                if empty {
                    self.command_buffer = None;
                    self.command_cursor = 0;
                } else if self.command_cursor > 0 {
                    self.command_cursor -= 1;
                    self.remove_char_at(self.command_cursor);
                }
            }
            KeyCode::Delete => {
                if self.command_cursor < self.command_buffer_char_len() {
                    self.remove_char_at(self.command_cursor);
                }
            }
            KeyCode::Char(c) => {
                let byte_idx = self.char_byte_index(self.command_cursor);
                if let Some(buf) = self.command_buffer.as_mut() {
                    buf.insert(byte_idx, c);
                }
                self.command_cursor += 1;
            }
            _ => {}
        }
    }

    /// `Tab` (`forward`)/`Shift-Tab` (`!forward`) in the command line (spec
    /// 0113 D26): continue an already-cycling completion, or start a new
    /// one against the current token.
    fn handle_tab_key(&mut self, forward: bool) {
        if let Some(state) = &self.completion {
            if state.candidates.len() > 1 {
                let n = state.candidates.len();
                let new_index = match state.index {
                    Some(i) if forward => (i + 1) % n,
                    Some(i) => (i + n - 1) % n,
                    None if forward => 0,
                    None => n - 1,
                };
                let candidate = state.candidates[new_index].clone();
                let token_start = state.token_start;
                let suffix = state.suffix.clone();
                self.replace_token(token_start, &suffix, &candidate);
                if let Some(state) = &mut self.completion {
                    state.index = Some(new_index);
                }
                return;
            }
        }
        self.start_tab_completion();
    }

    /// Complete the token the cursor currently sits in: the first token
    /// (the command name, before any space) always; the second token, once
    /// exactly one space precedes the cursor, only when the first token
    /// has already unambiguously resolved to `type-as` (spec 0114 §7) — an
    /// FQDN argument, completed against `all_type_fqdns`. Anywhere else
    /// (past `type-as`'s single argument, or a second token following any
    /// other command) is a silent no-op.
    fn start_tab_completion(&mut self) {
        let buf = self.command_buffer.clone().unwrap_or_default();
        let cursor_byte = self.char_byte_index(self.command_cursor);
        let prefix = &buf[..cursor_byte];
        match prefix.split_once(' ') {
            None => self.complete_command_name(prefix),
            Some((cmd, arg_prefix))
                if !arg_prefix.contains(' ') && resolve_command(cmd) == Ok("type-as") =>
            {
                self.complete_type_as_fqdn(cmd, arg_prefix);
            }
            Some((cmd, arg_prefix))
                if matches!(
                    resolve_command(cmd),
                    Ok("save-overrides") | Ok("restore-overrides")
                ) =>
            {
                self.complete_fs_path(cmd, arg_prefix);
            }
            Some(_) => {}
        }
    }

    /// First-token (command-name) completion — see `start_tab_completion`.
    fn complete_command_name(&mut self, prefix: &str) {
        let mut matches = complete_prefix(prefix, COMMANDS.iter().copied());
        if matches.is_empty() {
            self.message = format!("no command matches '{prefix}'");
            return;
        }
        matches.sort_unstable();
        let cursor_byte = self.char_byte_index(self.command_cursor);
        let buf = self.command_buffer.clone().unwrap_or_default();
        let suffix = buf[cursor_byte..].to_string();
        if matches.len() == 1 {
            self.replace_token(0, &suffix, matches[0]);
            return;
        }
        let lcp = longest_common_prefix(&matches);
        if lcp.chars().count() > prefix.chars().count() {
            self.replace_token(0, &suffix, &lcp);
        }
        self.completion = Some(CompletionState {
            token_start: 0,
            suffix,
            candidates: matches.into_iter().map(String::from).collect(),
            index: None,
        });
    }

    /// `:type-as <FQDN>`'s argument completion (spec 0114 §7) — candidates
    /// are `all_type_fqdns` (the same session-global, lexicographically-
    /// sorted list §3.2/§6 already compute and cache), reused here rather
    /// than recomputed.
    fn complete_type_as_fqdn(&mut self, cmd: &str, arg_prefix: &str) {
        // Collected into owned `String`s upfront (rather than borrowing
        // `self.all_type_fqdns` for `matches`'s lifetime) so the
        // subsequent `self.replace_token`/`self.completion = ...` calls
        // below aren't blocked by a live immutable borrow of `self`.
        let matches: Vec<String> =
            complete_prefix(arg_prefix, self.all_type_fqdns.iter().map(String::as_str))
                .into_iter()
                .map(String::from)
                .collect();
        if matches.is_empty() {
            self.message = format!("no type matches '{arg_prefix}'");
            return;
        }
        // `all_type_fqdns` is already sorted; `complete_prefix` preserves
        // that order via its filter, no re-sort needed.
        let token_start = cmd.chars().count() + 1;
        let cursor_byte = self.char_byte_index(self.command_cursor);
        let buf = self.command_buffer.clone().unwrap_or_default();
        let suffix = buf[cursor_byte..].to_string();
        if matches.len() == 1 {
            self.replace_token(token_start, &suffix, &matches[0]);
            return;
        }
        let refs: Vec<&str> = matches.iter().map(String::as_str).collect();
        let lcp = longest_common_prefix(&refs);
        if lcp.chars().count() > arg_prefix.chars().count() {
            self.replace_token(token_start, &suffix, &lcp);
        }
        self.completion = Some(CompletionState {
            token_start,
            suffix,
            candidates: matches,
            index: None,
        });
    }

    /// `:save-overrides`/`:restore-overrides`'s argument completion (spec
    /// 0117 §4) — candidates are `std::fs::read_dir`'s entries for the
    /// argument's directory portion (everything up to and including its
    /// last `/`, or the current directory if there is none), filtered by
    /// its final path segment; directory entries get a trailing `/`
    /// appended, so a further Tab press descends into them. No
    /// `!arg_prefix.contains(' ')` guard, unlike `complete_type_as_fqdn` —
    /// a path argument is everything after the command name's single
    /// space, embedded spaces included.
    fn complete_fs_path(&mut self, cmd: &str, arg_prefix: &str) {
        let (dir_part, file_prefix) = match arg_prefix.rfind('/') {
            Some(i) => (&arg_prefix[..=i], &arg_prefix[i + 1..]),
            None => ("", arg_prefix),
        };
        let read_dir_path = if dir_part.is_empty() {
            Path::new(".")
        } else {
            Path::new(dir_part)
        };
        let entries = match std::fs::read_dir(read_dir_path) {
            Ok(rd) => rd,
            Err(e) => {
                self.message = format!("cannot list '{}': {e}", read_dir_path.display());
                return;
            }
        };
        let mut matches: Vec<String> = Vec::new();
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if !name.starts_with(file_prefix) {
                continue;
            }
            let is_dir = entry.file_type().map(|t| t.is_dir()).unwrap_or(false);
            let mut candidate = format!("{dir_part}{name}");
            if is_dir {
                candidate.push('/');
            }
            matches.push(candidate);
        }
        if matches.is_empty() {
            self.message = format!("no path matches '{arg_prefix}'");
            return;
        }
        matches.sort_unstable();
        let token_start = cmd.chars().count() + 1;
        let cursor_byte = self.char_byte_index(self.command_cursor);
        let buf = self.command_buffer.clone().unwrap_or_default();
        let suffix = buf[cursor_byte..].to_string();
        if matches.len() == 1 {
            self.replace_token(token_start, &suffix, &matches[0]);
            return;
        }
        let refs: Vec<&str> = matches.iter().map(String::as_str).collect();
        let lcp = longest_common_prefix(&refs);
        if lcp.chars().count() > arg_prefix.chars().count() {
            self.replace_token(token_start, &suffix, &lcp);
        }
        self.completion = Some(CompletionState {
            token_start,
            suffix,
            candidates: matches,
            index: None,
        });
    }

    /// Replace `command_buffer[token_start..command_cursor]` with
    /// `replacement`, re-appending `suffix` (the text that originally
    /// followed the token) verbatim, and move the cursor to just past the
    /// replacement.
    fn replace_token(&mut self, token_start: usize, suffix: &str, replacement: &str) {
        let start_byte = self.char_byte_index(token_start);
        let mut new_buf = String::with_capacity(start_byte + replacement.len() + suffix.len());
        if let Some(buf) = &self.command_buffer {
            new_buf.push_str(&buf[..start_byte]);
        }
        new_buf.push_str(replacement);
        new_buf.push_str(suffix);
        self.command_cursor = token_start + replacement.chars().count();
        self.command_buffer = Some(new_buf);
    }

    fn command_buffer_char_len(&self) -> usize {
        self.command_buffer
            .as_deref()
            .map(|b| b.chars().count())
            .unwrap_or(0)
    }

    /// Byte offset in `command_buffer` of the `char_idx`-th character (or
    /// the buffer's end, if `char_idx` is at/past its length).
    fn char_byte_index(&self, char_idx: usize) -> usize {
        let buf = self.command_buffer.as_deref().unwrap_or("");
        buf.char_indices()
            .nth(char_idx)
            .map(|(i, _)| i)
            .unwrap_or(buf.len())
    }

    /// Remove the character at char index `char_idx` from `command_buffer`.
    fn remove_char_at(&mut self, char_idx: usize) {
        let byte_idx = self.char_byte_index(char_idx);
        if let Some(buf) = self.command_buffer.as_mut() {
            if byte_idx < buf.len() {
                buf.remove(byte_idx);
            }
        }
    }

    fn run_command(&mut self, cmd: &str) {
        let mut tokens = cmd.split_whitespace();
        let Some(name) = tokens.next() else {
            return;
        };
        match resolve_command(name) {
            Ok("extract") => self.run_extract(tokens.collect()),
            Ok("type-as") => self.run_type_as(tokens.collect()),
            Ok("type-as-raw") => self.run_type_as_raw(),
            Ok("save-overrides") => self.run_save_overrides(tokens.collect()),
            Ok("restore-overrides") => self.run_restore_overrides(tokens.collect()),
            Ok(other) => unreachable!("resolve_command returned unregistered command: {other}"),
            Err(e) => self.message = e,
        }
    }

    /// `type-as <FQDN>` — apply `FQDN` as the cursor node's type override,
    /// bypassing the override pane entirely (spec 0114 Goal 4/§5/§7). Same
    /// validation/application as picking a ranked candidate from the pane.
    fn run_type_as(&mut self, args: Vec<&str>) {
        if args.is_empty() {
            self.message = "type-as: missing type FQDN".to_string();
            return;
        }
        let fqdn = args.join(" ");
        self.message = match self.type_as(Some(&fqdn)) {
            Ok(()) => format!("overridden as {fqdn}"),
            Err(e) => e,
        };
    }

    /// `type-as-raw` — mark the cursor node's range as explicitly raw/
    /// unschema'd (spec 0114 §3.1/§5/§7), bypassing the override pane.
    fn run_type_as_raw(&mut self) {
        self.message = match self.type_as(None) {
            Ok(()) => "overridden as raw".to_string(),
            Err(e) => e,
        };
    }

    /// Shared application logic for `type-as`/`type-as-raw` (spec 0114 §5
    /// step 1, spec 0118 §6): validates the cursor is on an eligible node
    /// (`can_override`, §1) — same refusal `t` gives — then activates a
    /// `Path`-kind override for the cursor node's positional path and
    /// runs the recursive `render_overrides` pass (§4/§6), without ever
    /// opening the override pane. Unlike the old `apply_override`-based
    /// one-shot splice, this persists the override in the collection.
    fn type_as(&mut self, new_fqdn: Option<&str>) -> Result<(), String> {
        if !self.can_override(self.cursor) {
            return Err(
                "cannot override: not a message/group or length-delimited field".to_string(),
            );
        }
        let origin = OverrideOrigin::Path {
            path: self.positional_path(self.cursor),
        };
        self.overrides.activate(origin, new_fqdn.map(String::from));
        self.render_overrides(self.first_node);
        Ok(())
    }

    /// `extract [--binary|--text] <path>` — default format is `#@ prototext`
    /// text (0113 D21); the underlying render always carries full
    /// annotations now (spec 0133), so there's no longer a binary-default
    /// fallback case.
    fn run_extract(&mut self, args: Vec<&str>) {
        let mut format = ExtractFormat::Text;
        let mut path_parts = Vec::new();
        for a in args {
            match a {
                "--binary" => format = ExtractFormat::Binary,
                "--text" => format = ExtractFormat::Text,
                other => path_parts.push(other),
            }
        }
        if path_parts.is_empty() {
            self.message = "extract: missing path".to_string();
            return;
        }
        let path = path_parts.join(" ");
        let node = &self.tree[self.cursor];
        match extract::extract(Path::new(&path), format, &self.blob, &self.lines, node) {
            Ok(()) => self.message = format!("extracted to {path}"),
            Err(e) => self.message = format!("extract error: {e}"),
        }
    }

    /// `idx`'s extracted rendering, in the requested format — the
    /// byte-vector counterpart to `run_extract`'s file-writing TUI
    /// command, for a caller with no `Path` to write to (spec 0123's
    /// batch mode, writing to stdout or an explicit `-o`/`--output`).
    pub(crate) fn extract_bytes(&self, idx: usize, format: ExtractFormat) -> Vec<u8> {
        extract::extract_bytes(format, &self.blob, &self.lines, &self.tree[idx])
    }

    /// Propose a default `:save-overrides` path — same directory/stem as
    /// the target blob, `.yaml` extension (spec 0117 §4, mirroring
    /// `default_extract_path`).
    fn default_save_overrides_path(&self) -> String {
        let stem = self
            .blob_path
            .file_stem()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| "overrides".to_string());
        let filename = format!("{stem}.yaml");
        match self.blob_path.parent() {
            Some(dir) if !dir.as_os_str().is_empty() => {
                dir.join(filename).to_string_lossy().into_owned()
            }
            _ => filename,
        }
    }

    /// SHA-256 hex digests of the currently-loaded blob/descriptor set,
    /// canonicalized-binary bytes (spec 0117 §4's `blob_sha256`/
    /// `descriptor_set_sha256`) — the caller's original (pre-wrap) blob,
    /// and the descriptor set's own canonicalized bytes (`ctx.raw_bytes`).
    fn target_hashes(&self) -> (String, String) {
        let blob_sha256 = override_pane::sha256_hex(&self.blob[self.wrapper_offset..]);
        let descriptor_set_sha256 = override_pane::sha256_hex(&self.ctx.raw_bytes);
        (blob_sha256, descriptor_set_sha256)
    }

    /// `idx`'s `pos`-th child (1-based, document order) — the sibling-chain
    /// counterpart to `sibling_position`.
    fn nth_child(&self, idx: usize, pos: usize) -> Option<usize> {
        let mut cur = self.tree[idx].first_child;
        for _ in 1..pos {
            cur = cur.and_then(|c| self.tree[c].next_sibling);
        }
        cur
    }

    /// Inverse of `positional_path`: resolves a canonical `/1/2/3`-style
    /// path (or bare `/` for the wrapper root) back to a tree index.
    /// `None` if any segment doesn't parse as a 1-based position, or
    /// doesn't resolve against the current tree (spec 0117 §4 restore-time
    /// validation). `pub(crate)`: also reused by `main.rs`'s batch `extract`
    /// subcommand (spec 0123) to resolve its `path` argument.
    pub(crate) fn resolve_path(&self, path: &str) -> Option<usize> {
        let root = self.tree.iter().position(|n| n.parent.is_none())?;
        if path == "/" {
            return Some(root);
        }
        let mut cur = root;
        for seg in path.trim_start_matches('/').split('/') {
            let pos: usize = seg.parse().ok()?;
            cur = self.nth_child(cur, pos)?;
        }
        Some(cur)
    }

    /// Whether `origin` resolves against the currently-loaded tree/
    /// descriptor pool (spec 0117 §4 restore-time validation): `Path`
    /// needs the path to resolve to a node; `PathField` additionally
    /// needs that node to have at least one child with the given field
    /// number; `FqdnField` needs the FQDN to resolve in the descriptor
    /// pool and that message to declare the given field number.
    fn origin_resolves(&self, origin: &OverrideOrigin) -> bool {
        match origin {
            OverrideOrigin::Path { path } => self.resolve_path(path).is_some(),
            OverrideOrigin::PathField { path, field } => match self.resolve_path(path) {
                Some(idx) => {
                    let mut child = self.tree[idx].first_child;
                    while let Some(c) = child {
                        if self.tree[c].span.field_number == *field {
                            return true;
                        }
                        child = self.tree[c].next_sibling;
                    }
                    false
                }
                None => false,
            },
            OverrideOrigin::FqdnField { fqdn, field } => self
                .ctx
                .pool()
                .get_message_by_name(fqdn)
                .and_then(|m| m.get_field(*field as u32))
                .is_some(),
        }
    }

    /// `save-overrides <path>` (spec 0117 §4): writes the entire
    /// collection, plus the current target's hashes, to `<path>` as YAML.
    fn run_save_overrides(&mut self, args: Vec<&str>) {
        if args.is_empty() {
            self.message = "save-overrides: missing path".to_string();
            return;
        }
        let path = args.join(" ");
        let (blob_sha256, descriptor_set_sha256) = self.target_hashes();
        let yaml = self.overrides.to_yaml(blob_sha256, descriptor_set_sha256);
        match std::fs::write(&path, yaml) {
            Ok(()) => self.message = format!("saved overrides to {path}"),
            Err(e) => self.message = format!("save-overrides error: {e}"),
        }
    }

    /// Shared core of `restore-overrides`/batch `--load-overrides` (spec
    /// 0117 §4, spec 0123 G4): loads and parses the YAML override
    /// collection at `path`, silently drops any entry that doesn't
    /// resolve against the current tree/descriptor pool, then replaces
    /// `self.overrides` wholesale and re-renders (spec 0118 §6:
    /// replacing the whole collection can change the resolved override
    /// for any node). Returns the list of non-blocking hash-mismatch
    /// warnings (empty if none) on success — a hash mismatch alone is
    /// never a failure — or `Err(diagnostic)` if the file couldn't be
    /// read or parsed as valid YAML in the first place, which the two
    /// callers (`run_restore_overrides`, batch mode) treat differently:
    /// the TUI just displays it and keeps running; batch mode (spec 0123
    /// G4) treats it as a hard error.
    pub(crate) fn load_overrides(&mut self, path: &str) -> Result<Vec<&'static str>, String> {
        let text = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
        let (mut collection, target) = override_pane::OverrideCollection::from_yaml(&text)?;
        collection.retain_resolvable(|origin| self.origin_resolves(origin));
        let (blob_sha256, descriptor_set_sha256) = self.target_hashes();
        let mut warnings = Vec::new();
        if target.blob_sha256 != blob_sha256 {
            warnings.push("blob hash mismatch");
        }
        if target.descriptor_set_sha256 != descriptor_set_sha256 {
            warnings.push("descriptor-set hash mismatch");
        }
        // The document root's own type is external input (CLI `--type`,
        // auto-inference, or an interactive retype) — unlike every other
        // node, it's never re-derivable from the schema once lost, since
        // `natural_type` infers a node's type by walking up to its
        // *parent's* resolved field descriptor, and root has no parent.
        // It must therefore survive a wholesale collection replace as a
        // persistent baseline entry, same as `App::new`'s own initial
        // `seed_root` call — otherwise root (and, transitively, every
        // schema-typed descendant whose own `natural_type` walks back up
        // through it) silently reverts to raw rendering, even though the
        // loaded file's own explicit overrides are all individually
        // intact. Preserve the currently-resolved root type unless the
        // loaded file defines its own active root entry.
        let root_origin = OverrideOrigin::Path {
            path: "/".to_string(),
        };
        let has_root_entry = collection
            .entries()
            .iter()
            .any(|e| e.active && e.origin == root_origin);
        let current_root_type = self.resolve_active_override(self.first_node).flatten();
        self.overrides = collection;
        if !has_root_entry {
            self.overrides.seed_root(current_root_type);
        }
        self.render_overrides(self.first_node);
        self.manage_highlight = 0;
        self.manage_scroll = 0;
        self.manage_pan_offset = 0;
        self.manage_pending_kind = None;
        Ok(warnings)
    }

    /// `restore-overrides <path>` (spec 0117 §4): replaces the collection
    /// wholesale with `<path>`'s contents — see `load_overrides`.
    fn run_restore_overrides(&mut self, args: Vec<&str>) {
        if args.is_empty() {
            self.message = "restore-overrides: missing path".to_string();
            return;
        }
        let path = args.join(" ");
        self.message = match self.load_overrides(&path) {
            Ok(warnings) if warnings.is_empty() => format!("restored overrides from {path}"),
            Ok(warnings) => format!(
                "restored overrides from {path} (warning: {})",
                warnings.join(", ")
            ),
            Err(e) => format!("restore-overrides error: {e}"),
        };
    }

    /// Handle one mouse event: wheel scroll moves the cursor like `j`/`k`;
    /// a left click on a foldable node's marker column toggles its fold,
    /// a click elsewhere on a node's line moves the cursor there.
    pub fn handle_mouse(&mut self, event: MouseEvent) {
        // A bare `Moved` event (no button held, no wheel) is pointer-
        // tracking noise, not user input — `EnableMouseCapture` turns on
        // any-motion reporting, so the terminal sends one of these on
        // essentially every pixel the mouse crosses, with no click at
        // all. Nothing in this function does anything with `Moved`
        // itself; without this guard, the side effects below (splash
        // dismissal in particular) fired on the very first stray cursor
        // twitch after startup, well before the user ever saw the splash
        // screen, or read as an unintended cause behind status messages
        // vanishing while the mouse merely hovered over the terminal.
        if event.kind == MouseEventKind::Moved {
            return;
        }

        // Dismiss the splash screen transparently, same as `handle_key`
        // (spec 0113 D22/D28): the mouse event that dismisses it is also
        // processed as a real event, not swallowed.
        self.splash = false;

        self.message.clear();

        // Feedback (2026-07-15): while the `F1` help overlay is open,
        // mouse wheel/Shift-wheel hovering over it scrolls its own text
        // instead of leaking through to whichever pane happens to be
        // drawn underneath — `over_main`/`over_side` below have no idea
        // the overlay exists, so this must be checked first. Shift-wheel
        // is reported as a plain `ScrollUp`/`ScrollDown` with the `SHIFT`
        // modifier set (matched here regardless), not as a distinct
        // event kind — help has no horizontal content to pan, so there's
        // no separate Shift behavior to give it. Native
        // `ScrollLeft`/`ScrollRight` (a real horizontal wheel/trackpad
        // gesture) is likewise swallowed here rather than panning the
        // pane behind the overlay.
        if self.help_open && Self::rect_contains(self.help_area, event.column, event.row) {
            match event.kind {
                MouseEventKind::ScrollDown => self.help_scroll = self.help_scroll.saturating_add(1),
                MouseEventKind::ScrollUp => self.help_scroll = self.help_scroll.saturating_sub(1),
                _ => {}
            }
            return;
        }

        let side_open = self.manage_open || self.override_target.is_some();
        let over_side = side_open && Self::rect_contains(self.side_area, event.column, event.row);
        let over_main = Self::rect_contains(self.main_area, event.column, event.row);
        let over_cmd = self
            .cmd_area
            .is_some_and(|area| Self::rect_contains(area, event.column, event.row));

        // Spec 0127 §G2: Shift+wheel and native ScrollLeft/ScrollRight pan
        // whichever pane is under the pointer, instead of the vertical
        // scroll the plain wheel dispatches to below — checked first so
        // it takes priority over the vertical-scroll branch.
        let shift = event.modifiers.contains(KeyModifiers::SHIFT);
        let (pan_left, pan_right) = match event.kind {
            MouseEventKind::ScrollLeft => (true, false),
            MouseEventKind::ScrollRight => (false, true),
            MouseEventKind::ScrollUp if shift => (true, false),
            MouseEventKind::ScrollDown if shift => (false, true),
            _ => (false, false),
        };
        if pan_left || pan_right {
            if over_side {
                let offset = if self.manage_open {
                    &mut self.manage_pan_offset
                } else {
                    &mut self.override_pan_offset
                };
                *offset = if pan_left {
                    offset.saturating_sub(PAN_STEP)
                } else {
                    offset.saturating_add(PAN_STEP)
                };
            } else if over_main {
                if pan_left {
                    self.pan_left();
                } else {
                    self.pan_right();
                }
            } else if over_cmd {
                self.command_pan_offset = if pan_left {
                    self.command_pan_offset.saturating_sub(PAN_STEP)
                } else {
                    self.command_pan_offset.saturating_add(PAN_STEP)
                };
            }
            return;
        }

        // Wheel scroll routes to whichever pane the mouse is currently
        // hovering, independent of keyboard focus (2026-07-14 feedback,
        // item 4) — unlike `handle_key`, which always follows focus,
        // since a mouse event already carries its own screen position
        // (`event.column`/`event.row`), making hover-based routing both
        // natural and unambiguous.
        if matches!(
            event.kind,
            MouseEventKind::ScrollUp | MouseEventKind::ScrollDown
        ) {
            if over_side {
                if self.manage_open {
                    self.handle_manage_mouse(event);
                } else {
                    self.handle_override_mouse(event);
                }
            } else if over_main {
                match event.kind {
                    MouseEventKind::ScrollDown => self.move_down(),
                    MouseEventKind::ScrollUp => self.move_up(),
                    _ => unreachable!(),
                }
            }
            return;
        }

        if let MouseEventKind::Down(MouseButton::Left) = event.kind {
            if over_main {
                // A click in the main pane always shifts keyboard focus
                // back to it without closing the side pane (2026-07-14
                // feedback, item 3) — `handle_key` follows `override_focus`/
                // `manage_focus`, so clearing them here is what makes the
                // shift stick for subsequent keystrokes too.
                self.override_focus = false;
                self.manage_focus = false;
                self.handle_click(event.column, event.row);
                let line_idx = self.main_pane_line_idx(event.column, event.row);

                // Double-click detection (feedback, 2026-07-15): crossterm
                // reports `Down` identically for single and double
                // clicks, so recognizing the second click of a pair means
                // comparing this `Down` against the previous one's own
                // timestamp/line ourselves. The `Up` handler below is
                // what actually acts on `pending_double_click`.
                let now = Instant::now();
                self.pending_double_click = matches!(
                    (self.last_click, line_idx),
                    (Some((t, prev_line)), Some(cur_line))
                        if prev_line == cur_line && now.duration_since(t) < DOUBLE_CLICK_THRESHOLD
                );
                self.last_click = line_idx.map(|l| (now, l));

                // Spec 0129 §G1: a click also (re-)seeds the drag
                // selection's anchor/end, replacing any previous one, so
                // a following `Drag` still works. Whether a *non-dragged*
                // click keeps or discards this single-line selection is
                // decided by the `Up` handler below (feedback, 2026-07-15:
                // a plain click now deselects; only a double-click keeps
                // it selected).
                self.select_anchor = line_idx;
                self.select_end = line_idx;
            } else if over_side {
                // Symmetric with the main-pane case above: clicking the
                // side pane (re-)claims keyboard focus for it too.
                if self.manage_open {
                    self.manage_focus = true;
                    self.handle_manage_click(event.column, event.row);
                } else {
                    self.override_focus = true;
                    self.handle_override_click(event.column, event.row);
                }
            }
            return;
        }

        if over_main {
            match event.kind {
                // Spec 0129 §G1: dragging extends the selection's end to
                // the row under the pointer; clamped to the pane's
                // currently-visible rows (no auto-scroll past the top/
                // bottom edge in this first cut — an out-of-bounds drag
                // position simply leaves `select_end` where it was).
                MouseEventKind::Drag(MouseButton::Left) => {
                    if let Some(line_idx) = self.main_pane_line_idx(event.column, event.row) {
                        self.select_end = Some(line_idx);
                    }
                }
                // Spec 0131 §G1: mouse release intentionally no longer
                // copies by itself — selection state was already
                // finalized by the preceding `Down`/`Drag` handling
                // (§G1/§G3 of spec 0129, unchanged); `Ctrl-C` is now the
                // sole trigger for the actual clipboard write.
                //
                // Feedback (2026-07-15): single vs. double click vs. drag
                // disambiguation. A drag (`select_anchor != select_end`)
                // always keeps its selection, unchanged. Otherwise: a
                // plain single click deselects everything; a double-click
                // (recognized by the `Down` handler above, same line,
                // within `DOUBLE_CLICK_THRESHOLD`) instead keeps the
                // single-line selection `Down` just set.
                MouseEventKind::Up(MouseButton::Left) => {
                    if self.select_anchor == self.select_end && !self.pending_double_click {
                        self.select_anchor = None;
                        self.select_end = None;
                    }
                }
                _ => {}
            }
        }
    }

    /// Spec 0129 §G2: the currently-selected main-pane lines' full
    /// (untruncated) text, one `render_line_content` per line in
    /// `min(select_anchor, select_end)..=max(...)`, joined with `\n`,
    /// alongside the line count — `None` if there is no active
    /// selection. Split out from `copy_selection_to_clipboard` so the
    /// text-building logic is testable independent of real OS clipboard
    /// access (unavailable e.g. in headless/CI environments).
    fn selected_text(&self) -> Option<(usize, String)> {
        let (Some(anchor), Some(end)) = (self.select_anchor, self.select_end) else {
            return None;
        };
        let (start, stop) = (anchor.min(end), anchor.max(end));
        let text = (start..=stop)
            .map(|i| self.render_line_content(i))
            .collect::<Vec<_>>()
            .join("\n");
        Some((stop - start + 1, text))
    }

    /// Spec 0129 §G2/0131 §G2: copy the currently-selected main-pane
    /// lines to the OS clipboard. No-op if there is no active selection.
    /// `copy_to_clipboard` always attempts an OSC 52 fallback when
    /// `arboard` fails (no reliable ack from the terminal either way),
    /// so a failure here still reports an (optimistic) success message
    /// rather than "clipboard unavailable" — spec 0131 §G2's "safest
    /// default."
    fn copy_selection_to_clipboard(&mut self) {
        let Some((count, text)) = self.selected_text() else {
            return;
        };
        self.message = match copy_to_clipboard(&text) {
            Ok(()) => format!("{count} line(s) copied to clipboard"),
            Err(_) => format!("{count} line(s) copied to clipboard (OSC 52 fallback)"),
        };
    }

    /// Spec 0131 §G1: `Ctrl-C` — copies the active drag-selection if one
    /// exists (unchanged `selected_text`/`copy_selection_to_clipboard`
    /// logic), else falls back to the cursor's own current line, treated
    /// as a length-1 selection so the existing range-based copy logic
    /// applies unchanged.
    fn copy_current_selection_or_line(&mut self) {
        if self.select_anchor.is_none() {
            let line_idx = self.visible_rows[self.cursor_display_row()];
            self.select_anchor = Some(line_idx);
            self.select_end = Some(line_idx);
        }
        self.copy_selection_to_clipboard();
    }

    /// Whether `(col, row)` falls inside `area` (used for mouse hit-
    /// testing against `main_area`/`side_area`).
    fn rect_contains(area: Rect, col: u16, row: u16) -> bool {
        col >= area.x && col < area.x + area.width && row >= area.y && row < area.y + area.height
    }

    /// Mouse handling for the override selection pane (spec 0113 D30):
    /// wheel scroll moves the highlight by one row (same effect as `j`/
    /// `k`, which is what the render function's own auto-scroll-into-view
    /// logic keys off of), click moves the highlight to the row under the
    /// cursor.
    fn handle_override_mouse(&mut self, event: MouseEvent) {
        match event.kind {
            MouseEventKind::ScrollDown => self.move_override_highlight(1),
            MouseEventKind::ScrollUp => self.move_override_highlight(-1),
            MouseEventKind::Down(MouseButton::Left) => {
                self.handle_override_click(event.column, event.row)
            }
            _ => {}
        }
    }

    fn handle_override_click(&mut self, col: u16, row: u16) {
        let area = self.side_area;
        if col < area.x || col >= area.x + area.width || row < area.y || row >= area.y + area.height
        {
            return;
        }
        let rel_row = (row - area.y) as usize;
        if rel_row >= self.override_list_height {
            return;
        }
        let absolute_row = self.override_scroll + rel_row;
        let total_rows = self.override_candidates.len() + 1;
        if absolute_row < total_rows {
            self.override_highlight = absolute_row;
        }
    }

    /// Mouse handling for the override management pane (spec 0113 D30):
    /// wheel scroll moves the highlight by one entry, click moves the
    /// highlight to the entry under the cursor (header rows under the
    /// click are ignored, same as clicking whitespace).
    fn handle_manage_mouse(&mut self, event: MouseEvent) {
        match event.kind {
            MouseEventKind::ScrollDown => self.move_manage_highlight(1),
            MouseEventKind::ScrollUp => self.move_manage_highlight(-1),
            MouseEventKind::Down(MouseButton::Left) => {
                self.handle_manage_click(event.column, event.row)
            }
            _ => {}
        }
    }

    fn handle_manage_click(&mut self, col: u16, row: u16) {
        let area = self.side_area;
        if col < area.x || col >= area.x + area.width || row < area.y || row >= area.y + area.height
        {
            return;
        }
        let rel_row = (row - area.y) as usize;
        if rel_row >= self.manage_list_height {
            return;
        }
        let absolute_row = self.manage_scroll + rel_row;
        let rows = self.manage_display_rows();
        if let Some(ManageRow::Entry(idx)) = rows.get(absolute_row) {
            self.manage_highlight = *idx;
            self.manage_pending_kind = None;
        }
    }

    /// `line_idx` of the main-pane row under `(col, row)`, or `None` if
    /// the position is outside `main_area` or past the last visible row
    /// (spec 0129 §G1) — shared by `handle_click` and the drag-select
    /// tracking in `handle_mouse`.
    fn main_pane_line_idx(&self, col: u16, row: u16) -> Option<usize> {
        let area = self.main_area;
        if col < area.x || col >= area.x + area.width || row < area.y || row >= area.y + area.height
        {
            return None;
        }
        let rel_row = (row - area.y) as usize;
        self.visible_rows.get(self.scroll_offset + rel_row).copied()
    }

    fn handle_click(&mut self, col: u16, row: u16) {
        let Some(line_idx) = self.main_pane_line_idx(col, row) else {
            return;
        };
        let Some(&idx) = self.line_to_node.get(&line_idx) else {
            return;
        };

        if idx != self.cursor {
            self.record_jump(self.cursor);
            self.cursor = idx;
        }

        if self.has_children(idx) {
            let area = self.main_area;
            let rel_col = col - area.x;
            if rel_col == marker_column(&self.lines[line_idx]) {
                self.toggle_fold(idx);
            }
        }
    }

    /// Index of `cursor`'s opening line within `visible_rows`.
    fn cursor_display_row(&self) -> usize {
        let target = self.tree[self.cursor].span.text_range.start;
        self.visible_rows
            .binary_search(&target)
            .unwrap_or_else(|i| i)
    }

    /// Byte offset within `self.lines[line_idx]` where that line's
    /// trailing `#@ ...` annotation starts, if it has one (spec 0133 G4)
    /// — reuses the tree-sitter `SyntaxRole::Comment` span already
    /// computed in `self.line_styles` (a comment always spans from `#` to
    /// end of line, and protolens's own rendered text never otherwise
    /// contains a bare `#` outside a quoted string, so at most one such
    /// span exists per line).
    fn annotation_start(&self, line_idx: usize) -> Option<usize> {
        self.line_styles
            .get(line_idx)?
            .iter()
            .find(|(_, role)| *role == SyntaxRole::Comment)
            .map(|(range, _)| range.start)
    }

    /// A foldable node's line, with its fold marker inserted right after
    /// the line's own leading indentation (kept intact — not shortened by
    /// one column to make room) and immediately before the first
    /// non-blank token, with no extra space either side — see
    /// `marker_column`. Lines with no associated foldable node are
    /// returned unchanged.
    ///
    /// When `self.annotations` is off, the line's trailing `#@ ...`
    /// annotation (and the whitespace that used to separate it from the
    /// value) is hidden — a purely cosmetic, display-time transform (spec
    /// 0133 G4); the underlying `self.lines` always carries the full
    /// annotation regardless.
    fn render_line_content(&self, line_idx: usize) -> String {
        let content = self.lines.get(line_idx).map(String::as_str).unwrap_or("");
        let content = if !self.annotations {
            match self.annotation_start(line_idx) {
                Some(pos) => content[..pos].trim_end(),
                None => content,
            }
        } else {
            content
        };
        let Some(&idx) = self.line_to_node.get(&line_idx) else {
            return content.to_string();
        };
        if !self.has_children(idx) {
            return content.to_string();
        }
        let folded = self.folded.contains(&idx);
        let marker = if folded { '▸' } else { '▾' };
        let indent_len = content.len() - content.trim_start().len();
        let mut s = format!(
            "{}{marker}{}",
            &content[..indent_len],
            &content[indent_len..]
        );
        if folded {
            match s.rfind('{') {
                Some(pos) => s.insert_str(pos + 1, " ... }"),
                None => s.push_str(" ... }"),
            }
        }
        s
    }

    /// Styled counterpart of `render_line_content` (spec 0116 §7/§9):
    /// applies `self.line_styles[line_idx]`'s syntax-highlighting spans
    /// via `theme::style_for`, then splices in the same fold-marker /
    /// `" ... }"` collapse-summary text `render_line_content` inserts —
    /// as unstyled spans, so highlighting and folding compose cleanly.
    ///
    /// Follows the same display-time annotation-hiding truncation as
    /// `render_line_content` (spec 0133 G4) — any `self.line_styles`
    /// hint extending past the truncated length is clipped/dropped
    /// before `segment_line` runs, since `segment_line` doesn't
    /// bounds-check hint ranges against `content`.
    fn render_line_spans(&self, line_idx: usize) -> Vec<Span<'static>> {
        let full_content = self.lines.get(line_idx).map(String::as_str).unwrap_or("");
        let full_hints = self
            .line_styles
            .get(line_idx)
            .map(Vec::as_slice)
            .unwrap_or(&[]);
        let (content, hints): (&str, Vec<(Range<usize>, SyntaxRole)>) =
            match (!self.annotations, self.annotation_start(line_idx)) {
                (true, Some(pos)) => {
                    let truncated = full_content[..pos].trim_end();
                    let clipped = full_hints
                        .iter()
                        .filter(|(r, _)| r.start < truncated.len())
                        .map(|(r, role)| (r.start..r.end.min(truncated.len()), *role))
                        .collect();
                    (truncated, clipped)
                }
                _ => (full_content, full_hints.to_vec()),
            };
        let segments = segment_line(content, &hints);

        let Some(&idx) = self.line_to_node.get(&line_idx) else {
            return self.spans_with_insertions(content, segments, Vec::new());
        };
        if !self.has_children(idx) {
            return self.spans_with_insertions(content, segments, Vec::new());
        }
        let folded = self.folded.contains(&idx);
        let marker = if folded { '▸' } else { '▾' };
        let indent_len = content.len() - content.trim_start().len();

        let mut insertions = vec![(indent_len, marker.to_string())];
        if folded {
            let insert_at = match content.rfind('{') {
                Some(pos) => pos + 1,
                None => content.len(),
            };
            insertions.push((insert_at, " ... }".to_string()));
        }
        self.spans_with_insertions(content, segments, insertions)
    }

    /// Turns `content`'s `segments` (byte ranges tagged with an optional
    /// `SyntaxRole`, covering all of `content`) into styled `Span`s,
    /// splicing in `insertions` — `(byte position in content, literal
    /// text)` pairs, each rendered as its own unstyled `Span` at that
    /// point (fold-marker/collapse-summary text is never part of the
    /// highlighted source, so it never carries a role).
    fn spans_with_insertions(
        &self,
        content: &str,
        segments: Vec<(Range<usize>, Option<SyntaxRole>)>,
        mut insertions: Vec<(usize, String)>,
    ) -> Vec<Span<'static>> {
        insertions.sort_by_key(|(pos, _)| *pos);
        let mut segments: std::collections::VecDeque<_> = segments.into();
        let mut result = Vec::new();
        for (ins_pos, ins_text) in insertions {
            while let Some((range, role)) = segments.pop_front() {
                if range.end <= ins_pos {
                    result.push(self.make_span(content[range].to_string(), role));
                } else if range.start < ins_pos {
                    result.push(self.make_span(content[range.start..ins_pos].to_string(), role));
                    segments.push_front((ins_pos..range.end, role));
                    break;
                } else {
                    segments.push_front((range, role));
                    break;
                }
            }
            result.push(Span::raw(ins_text));
        }
        for (range, role) in segments {
            result.push(self.make_span(content[range].to_string(), role));
        }
        result
    }

    fn make_span(&self, text: String, role: Option<SyntaxRole>) -> Span<'static> {
        match role {
            Some(role) => Span::styled(text, theme::style_for(role, self.theme)),
            None => Span::raw(text),
        }
    }

    /// Spec 0113 D33: `true` when `line_idx` is one of *its own* node's
    /// header/footer lines (`line_to_node`'s opening-line mapping, or
    /// `footer_line_to_node`'s closing-line mapping — never a
    /// descendant's own lines, which is what keeps this from cascading
    /// visual weight down a whole overridden subtree) and that node
    /// currently carries an active override, of whichever kind (a single
    /// boolean state — the three override kinds are not visually
    /// distinguished here, they're already visible in the management
    /// pane).
    fn line_has_active_override(&self, line_idx: usize) -> bool {
        let idx = self
            .line_to_node
            .get(&line_idx)
            .or_else(|| self.footer_line_to_node.get(&line_idx));
        match idx {
            Some(&idx) => self.resolve_active_override(idx).is_some(),
            None => false,
        }
    }

    /// Auto-dismiss `self.message` after `MESSAGE_TIMEOUT` of it staying
    /// unchanged — otherwise a passive status/error notice (e.g. "pattern
    /// not found") stays on screen indefinitely once set, even while the
    /// user is just navigating a side pane with nothing left to say about
    /// it. `self.message` has no dedicated setter (assigned directly all
    /// over this file), so a freshly-set message is detected here by
    /// comparing against `last_message_seen` rather than at each
    /// assignment site. Never dismissed while `command_buffer`/
    /// `manage_rename` is `Some` (the bottom bar renders those instead of
    /// `self.message` while either is active — see `render`'s `cmd_text`)
    /// or while `quit_confirm` is armed (both are actively awaiting a
    /// keypress, unlike a plain notice). Called once per `render()`.
    fn track_message_timeout(&mut self) {
        if self.message != self.last_message_seen {
            self.last_message_seen = self.message.clone();
            self.message_deadline = if self.message.is_empty() {
                None
            } else {
                Some(Instant::now() + MESSAGE_TIMEOUT)
            };
            return;
        }
        if self.command_buffer.is_some() || self.manage_rename.is_some() || self.quit_confirm {
            return;
        }
        if let Some(deadline) = self.message_deadline {
            if Instant::now() >= deadline {
                self.message.clear();
                self.last_message_seen.clear();
                self.message_deadline = None;
            }
        }
    }

    pub fn render(&mut self, frame: &mut Frame) {
        self.track_message_timeout();
        let area = frame.area();
        self.term_width = area.width;
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Min(0),    // main pane (header folded into its title)
                Constraint::Length(3), // command/message (left) + status (right)
            ])
            .split(area);

        // Ephemeral right-hand split (spec 0114 §2, extended by spec 0117
        // §3 to the management pane) when either the override selection
        // pane or the management pane is open — 50/50, giving the
        // candidate/entry list enough room to be legible. The two panes
        // are mutually exclusive (spec 0117 §3), so at most one of these
        // is ever true.
        let (main_outer, right_outer) = if self.override_target.is_some() || self.manage_open {
            let split = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
                .split(chunks[0]);
            (split[0], Some(split[1]))
        } else {
            (chunks[0], None)
        };

        // Bold border marks whichever pane currently holds keyboard
        // focus, mirroring the override/management panes' own
        // `override_focus`/`manage_focus`-driven border style — the main
        // pane has focus exactly when neither side pane does (2026-07-14
        // feedback: no prior visible sign of which pane focus was in).
        let main_focused = !self.override_focus && !self.manage_focus;
        let main_border_style = if main_focused {
            Style::default().add_modifier(Modifier::BOLD)
        } else {
            Style::default()
        };
        let main_block = Block::bordered()
            .title(format!(" {} ", self.header))
            .border_style(main_border_style);
        let inner = main_block.inner(main_outer);
        frame.render_widget(main_block, main_outer);
        self.main_area = inner;

        let pane_height = inner.height as usize;
        let cursor_row = if self.tree.is_empty() {
            0
        } else {
            self.cursor_display_row()
        };
        if pane_height > 0 && !self.tree.is_empty() {
            if cursor_row < self.scroll_offset {
                self.scroll_offset = cursor_row;
            } else if cursor_row >= self.scroll_offset + pane_height {
                self.scroll_offset = cursor_row + 1 - pane_height;
            }
        }
        let end = (self.scroll_offset + pane_height).min(self.visible_rows.len());
        let window = &self.visible_rows[self.scroll_offset.min(self.visible_rows.len())..end];

        // Spec 0129 §G1: the drag-selected `line_idx` range (if any) gets
        // the same `REVERSED` treatment as the single cursor row below —
        // the two can coexist harmlessly since `REVERSED` on an already-
        // `REVERSED` span is a no-op.
        let selection_range = match (self.select_anchor, self.select_end) {
            (Some(a), Some(b)) => Some(a.min(b)..=a.max(b)),
            _ => None,
        };

        let text_lines: Vec<Line> = window
            .iter()
            .enumerate()
            .map(|(row, &line_idx)| {
                let mut spans = pan_spans(self.render_line_spans(line_idx), self.pan_offset);
                if self.line_has_active_override(line_idx) {
                    for span in &mut spans {
                        span.style = span.style.add_modifier(Modifier::BOLD);
                    }
                }
                let selected = selection_range
                    .as_ref()
                    .is_some_and(|r| r.contains(&line_idx));
                if self.scroll_offset + row == cursor_row || selected {
                    for span in &mut spans {
                        span.style = span.style.add_modifier(Modifier::REVERSED);
                    }
                }
                Line::from(spans)
            })
            .collect();
        frame.render_widget(Paragraph::new(text_lines), inner);

        // Bottom row: command/message (left, 60%) and status (right, 40%) —
        // vim-style, command line/messages flush left where the cursor
        // naturally anchors while typing, ruler-style position info on the
        // right. The command/message pane is hidden (no split at all, the
        // status pane takes the full row) whenever there's nothing to show
        // there — which is most of the time in ordinary navigation, since
        // `self.message` is cleared on every normal-mode keypress before
        // its handler runs.
        // The management pane's rename buffer (spec 0119 §G4's `f` key)
        // shares this same bottom bar rather than being appended inside
        // the side pane's own line list (2026-07-14 interactive
        // feedback): unlike `:command`/`/`-search, that side-pane-local
        // spot never got a real terminal cursor, making it unclear where
        // typing lands — this bar already solves that for the main pane's
        // own command/search input, so reusing it fixes both at once.
        const RENAME_PREFIX: &str = "name: ";
        let cmd_text = match &self.command_buffer {
            Some(buf) => {
                let prefix = match self.command_kind {
                    CommandLineKind::Command => ':',
                    CommandLineKind::Search(SearchDir::Forward) => '/',
                    CommandLineKind::Search(SearchDir::Backward) => '?',
                };
                format!("{prefix}{buf}")
            }
            None => match &self.manage_rename {
                Some(buf) => format!("{RENAME_PREFIX}{buf}"),
                None => self.message.clone(),
            },
        };
        let status_outer = if cmd_text.is_empty() {
            self.cmd_area = None;
            chunks[1]
        } else {
            let bottom = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([Constraint::Percentage(60), Constraint::Percentage(40)])
                .split(chunks[1]);

            let cmd_block = Block::bordered();
            let cmd_inner = cmd_block.inner(bottom[0]);
            frame.render_widget(cmd_block, bottom[0]);
            self.cmd_area = Some(cmd_inner);

            // Spec 0127 §G1: cursor char position (including the leading
            // "prefix"/"name: " char(s)) within `cmd_text`, `None` while
            // just displaying a plain message (no active edit, so no
            // cursor to keep visible).
            let cursor_pos = if self.command_buffer.is_some() {
                Some(1 + self.command_cursor)
            } else {
                self.manage_rename
                    .as_ref()
                    .map(|buf| RENAME_PREFIX.chars().count() + buf.chars().count())
            };
            let width = cmd_inner.width as usize;
            if let Some(pos) = cursor_pos {
                // Auto-follow the cursor while typing (mirrors the main
                // pane's cursor-follow vertical scroll) — coexists with,
                // rather than replaces, manual Shift+wheel/native
                // horizontal-scroll pan on this same field.
                if pos < self.command_pan_offset {
                    self.command_pan_offset = pos;
                } else if width > 0 && pos >= self.command_pan_offset + width {
                    self.command_pan_offset = pos + 1 - width;
                }
            }
            let spans = pan_spans(vec![Span::raw(cmd_text)], self.command_pan_offset);
            frame.render_widget(Paragraph::new(Line::from(spans)), cmd_inner);
            if let Some(pos) = cursor_pos {
                let x = cmd_inner.x + (pos - self.command_pan_offset) as u16;
                frame.set_cursor_position((x, cmd_inner.y));
            }
            bottom[1]
        };

        let status = if self.tree.is_empty() {
            "(empty — decoded to zero fields)".to_string()
        } else {
            let path = self.positional_path(self.cursor);
            let range = self.display_range(self.cursor);
            let node = &self.tree[self.cursor].span;
            let type_label = match node.type_fqdn.as_deref() {
                Some(fqdn) => format!("type: {fqdn}"),
                None => String::new(),
            };
            format!(
                "L{}/{}  {}  bytes[{}..{})  {}",
                node.text_range.start + 1,
                self.lines.len(),
                path,
                range.start,
                range.end,
                type_label,
            )
        };
        let status_block = Block::bordered().title(" Status — F1 for help ");
        let status_inner = status_block.inner(status_outer);
        frame.render_widget(status_block, status_outer);
        frame.render_widget(Paragraph::new(status), status_inner);

        if let Some(right_area) = right_outer {
            if self.override_target.is_some() {
                self.render_override_pane(frame, right_area);
            } else if self.manage_open {
                self.render_manage_pane(frame, right_area);
            }
        }

        if self.splash {
            self.render_splash(frame, area);
        } else if self.help_open {
            self.render_help(frame, area);
        }
    }

    /// Ephemeral right-hand override pane (spec 0114 §2): title showing the
    /// target's byte range and sort mode, the pinned `<raw / no type>` row
    /// (§3.1) followed by the ranked/lexicographic candidate list (§3.2)
    /// with the highlighted row reverse-styled, scrolled to keep it
    /// visible. The `/`/`?` search buffer (§4) renders in the shared
    /// bottom command/message bar instead of a row here (spec-0133-
    /// adjacent rework). Apply-on-`Enter` (§5) lands in a later
    /// implementation step.
    fn render_override_pane(&mut self, frame: &mut Frame, area: Rect) {
        let Some(idx) = self.override_target else {
            return;
        };
        let range = self.display_range(idx);
        let sort_label = match self.override_sort {
            SortMode::Lexicographic => "a-z",
            SortMode::Inferred => "inferred",
        };
        let title = format!(
            " Override — range [{}..{}) — sort: {sort_label} ",
            range.start, range.end,
        );
        let border_style = if self.override_focus {
            Style::default().add_modifier(Modifier::BOLD)
        } else {
            Style::default()
        };
        let block = Block::bordered().title(title).border_style(border_style);
        let inner = block.inner(area);
        frame.render_widget(block, area);
        self.side_area = inner;

        let list_height = inner.height as usize;
        self.override_list_height = list_height;

        let total_rows = self.override_candidates.len() + 1;
        if list_height > 0 {
            if self.override_highlight < self.override_scroll {
                self.override_scroll = self.override_highlight;
            } else if self.override_highlight >= self.override_scroll + list_height {
                self.override_scroll = self.override_highlight + 1 - list_height;
            }
        }
        let end = (self.override_scroll + list_height).min(total_rows);
        let start = self.override_scroll.min(total_rows);

        let mut lines: Vec<Line> = Vec::new();
        for row in start..end {
            let text = if row == 0 {
                "<raw / no type>".to_string()
            } else {
                let (fqdn, score) = &self.override_candidates[row - 1];
                match score {
                    Some(s) => format!("{fqdn}  (score: {s})"),
                    None => fqdn.clone(),
                }
            };
            let style = if row == self.override_highlight {
                Style::default().add_modifier(Modifier::REVERSED)
            } else {
                Style::default()
            };
            // Spec 0127 §G1: pan the override pane's own rows
            // independently of the main pane's `pan_offset`.
            lines.push(Line::from(pan_spans(
                vec![Span::styled(text, style)],
                self.override_pan_offset,
            )));
        }
        frame.render_widget(Paragraph::new(lines), inner);
    }

    /// Override management pane (spec 0117 §3) — always focused while
    /// open (bold border unconditionally), lists the whole
    /// `OverrideCollection` in its canonical sort order.
    fn render_manage_pane(&mut self, frame: &mut Frame, area: Rect) {
        let title = format!(" Overrides ({} entries) ", self.overrides.entries().len());
        let border_style = if self.manage_focus {
            Style::default().add_modifier(Modifier::BOLD)
        } else {
            Style::default()
        };
        let block = Block::bordered().title(title).border_style(border_style);
        let inner = block.inner(area);
        frame.render_widget(block, area);
        self.side_area = inner;

        // Neither the rename buffer nor the `/`/`?` search buffer reserves
        // a row here — both render in the shared bottom command/message
        // bar instead (`render`, 2026-07-14 feedback / spec-0133-adjacent
        // rework), which also gives them a real cursor.
        let list_height = inner.height as usize;
        self.manage_list_height = list_height;

        let rows = self.manage_display_rows();
        let total_rows = rows.len();
        let highlighted_row = rows
            .iter()
            .position(|r| matches!(r, ManageRow::Entry(idx) if *idx == self.manage_highlight))
            .unwrap_or(0);
        if list_height > 0 {
            if highlighted_row < self.manage_scroll {
                self.manage_scroll = highlighted_row;
            } else if highlighted_row >= self.manage_scroll + list_height {
                self.manage_scroll = highlighted_row + 1 - list_height;
            }
        }
        let end = (self.manage_scroll + list_height).min(total_rows);
        let start = self.manage_scroll.min(total_rows);

        let mut lines: Vec<Line> = Vec::new();
        for row in &rows[start..end] {
            match row {
                // Spec 0127 §G1: pan the manage pane's own rows
                // independently of the main pane's `pan_offset`.
                ManageRow::Header(label) => lines.push(Line::from(pan_spans(
                    vec![Span::raw(label.clone())],
                    self.manage_pan_offset,
                ))),
                ManageRow::Entry(idx) => {
                    let text = self.manage_type_line(*idx);
                    // Spec 0130 §G1: auto-derived entries render in
                    // `Comment`'s muted color, manual entries in
                    // `Boolean`'s blue — dedicated, `SyntaxRole`-
                    // independent styling, visually distinct at every
                    // palette depth. The highlighted row's `REVERSED`
                    // modifier layers on top of either.
                    let auto = self.overrides.entries()[*idx].auto;
                    let mut style = theme::manage_entry_style(auto, self.theme);
                    if *idx == self.manage_highlight {
                        style = style.add_modifier(Modifier::REVERSED);
                    }
                    lines.push(Line::from(pan_spans(
                        vec![Span::styled(text, style)],
                        self.manage_pan_offset,
                    )));
                }
            }
        }
        frame.render_widget(Paragraph::new(lines), inner);
    }

    /// Centered modal listing `HELP_TEXT`, scrollable via `help_scroll`.
    fn render_help(&mut self, frame: &mut Frame, area: Rect) {
        let popup = centered_rect(70, 70, area);
        frame.render_widget(Clear, popup);
        let block = Block::bordered().title(" Help (j/k scroll, q/Esc/F1 close) ");
        let inner = block.inner(popup);
        frame.render_widget(block, popup);
        self.help_area = inner;

        let visible_height = (inner.height as usize).max(1);
        let max_scroll = HELP_TEXT.len().saturating_sub(visible_height);
        self.help_scroll = self.help_scroll.min(max_scroll);
        let end = (self.help_scroll + visible_height).min(HELP_TEXT.len());
        let lines: Vec<Line> = HELP_TEXT[self.help_scroll..end]
            .iter()
            .map(|&l| Line::from(l))
            .collect();
        frame.render_widget(Paragraph::new(lines), inner);
    }

    /// Startup splash — dismissed by any key — telling the user how to
    /// reach the `F1` help overlay (spec 0113 D22).
    fn render_splash(&self, frame: &mut Frame, area: Rect) {
        let popup = centered_rect(60, 30, area);
        frame.render_widget(Clear, popup);
        let block = Block::bordered().title(" protolens ");
        let inner = block.inner(popup);
        frame.render_widget(block, popup);
        let text = vec![
            Line::from(self.header.as_str()),
            Line::from(""),
            Line::from("Press F1 for help."),
            Line::from("Press any key to continue."),
        ];
        frame.render_widget(Paragraph::new(text).alignment(Alignment::Center), inner);
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

/// Restore the terminal to its normal (cooked, main-screen, no mouse
/// capture) state — shared by `run`'s own cleanup and the panic hook below,
/// so a panic mid-session doesn't leave the user's terminal unusable.
fn restore_terminal() {
    drain_pending_input();
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
    execute!(io::stdout(), EnterAlternateScreen, EnableMouseCapture)?;
    terminal.clear()?;
    Ok(())
}

/// Run the interactive TUI loop against a real terminal.
pub fn run(app: &mut App) -> io::Result<()> {
    enable_raw_mode()?;
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

#[cfg(test)]
mod tests {
    use prototext_core::helpers::{WT_LEN, WT_VARINT};
    use prototext_core::serialize::render_text::NodeSpan;
    use ratatui::backend::TestBackend;

    use super::*;

    /// Regression test: a legitimately-empty decode (e.g. reopening an
    /// extracted `google.protobuf.Empty`, or any all-default submessage —
    /// decoding zero bytes yields zero `TreeNode`s, not an error) must not
    /// panic on the first `render()` call or on keypresses, now that
    /// `main.rs` no longer refuses to open such a blob.
    #[test]
    fn empty_tree_renders_and_handles_keys_without_panicking() {
        let decoded = Decoded {
            lines: Vec::new(),
            tree: Vec::new(),
            root_type: "google.protobuf.Empty".to_string(),
            blob: Vec::new(),
            wrapper_offset: 0,
            style_hints: Vec::new(),
        };
        let mut app = App::new(
            decoded,
            "empty.pb",
            PathBuf::from("empty.pb"),
            2,
            DescriptorContext::empty_for_test(),
            ThemeKind::Dark,
        );

        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|frame| app.render(frame)).unwrap();

        // Dismiss the startup splash first (any key), then exercise a
        // handful of keys that are unguarded `self.tree[...]` indexing
        // sites for a non-empty tree.
        app.splash = false;
        for code in [
            KeyCode::Down,
            KeyCode::Up,
            KeyCode::Left,
            KeyCode::Right,
            KeyCode::Char('z'),
            KeyCode::Char('x'),
            KeyCode::End,
        ] {
            app.handle_key(KeyEvent::new(code, KeyModifiers::NONE));
        }
        terminal.draw(|frame| app.render(frame)).unwrap();

        app.handle_key(KeyEvent::new(KeyCode::Char('q'), KeyModifiers::NONE));
        assert!(!app.should_quit);
        app.handle_key(KeyEvent::new(KeyCode::Char('q'), KeyModifiers::NONE));
        assert!(app.should_quit);
    }

    #[test]
    fn q_confirmation_is_cancelled_by_any_other_key() {
        let decoded = Decoded {
            lines: Vec::new(),
            tree: Vec::new(),
            root_type: "google.protobuf.Empty".to_string(),
            blob: Vec::new(),
            wrapper_offset: 0,
            style_hints: Vec::new(),
        };
        let mut app = App::new(
            decoded,
            "empty.pb",
            PathBuf::from("empty.pb"),
            2,
            DescriptorContext::empty_for_test(),
            ThemeKind::Dark,
        );
        app.splash = false;

        app.handle_key(KeyEvent::new(KeyCode::Char('q'), KeyModifiers::NONE));
        assert!(!app.should_quit);
        assert!(app.quit_confirm);

        app.handle_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
        assert!(!app.should_quit);
        assert!(!app.quit_confirm);
        assert!(app.message.is_empty());

        // A fresh `q` press re-arms confirmation from scratch.
        app.handle_key(KeyEvent::new(KeyCode::Char('q'), KeyModifiers::NONE));
        assert!(app.quit_confirm);
        app.handle_key(KeyEvent::new(KeyCode::Char('q'), KeyModifiers::NONE));
        assert!(app.should_quit);
    }

    /// Spec 0113 D31: `Ctrl-Z` sets `should_suspend` (the actual
    /// `SIGTSTP`/terminal dance lives in `run_loop`/`suspend`, outside
    /// `App`'s own unit-testable surface) — checked centrally, so it
    /// fires uniformly regardless of a pending quit confirmation, and
    /// leaves that confirmation untouched.
    #[test]
    #[cfg(unix)]
    fn ctrl_z_sets_should_suspend_without_disturbing_quit_confirm() {
        let decoded = Decoded {
            lines: Vec::new(),
            tree: Vec::new(),
            root_type: "google.protobuf.Empty".to_string(),
            blob: Vec::new(),
            wrapper_offset: 0,
            style_hints: Vec::new(),
        };
        let mut app = App::new(
            decoded,
            "empty.pb",
            PathBuf::from("empty.pb"),
            2,
            DescriptorContext::empty_for_test(),
            ThemeKind::Dark,
        );
        app.splash = false;

        app.handle_key(KeyEvent::new(KeyCode::Char('q'), KeyModifiers::NONE));
        assert!(app.quit_confirm);

        app.handle_key(KeyEvent::new(KeyCode::Char('z'), KeyModifiers::CONTROL));
        assert!(app.should_suspend);
        assert!(!app.should_quit);
        assert!(
            app.quit_confirm,
            "Ctrl-Z must not disturb a pending quit confirmation"
        );
    }

    /// A passive status message auto-dismisses once `MESSAGE_TIMEOUT` has
    /// elapsed since it was set — detected by `track_message_timeout`
    /// (called from `render`) noticing an expired `message_deadline`.
    #[test]
    fn message_auto_dismisses_after_timeout() {
        let mut app = empty_app();
        app.splash = false;
        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).unwrap();

        app.message = "pattern not found: xyz".to_string();
        terminal.draw(|frame| app.render(frame)).unwrap();
        assert!(app.message_deadline.is_some());
        assert_eq!(app.message, "pattern not found: xyz");

        // Not yet expired: still showing on a later render.
        terminal.draw(|frame| app.render(frame)).unwrap();
        assert_eq!(app.message, "pattern not found: xyz");

        // Force expiry (real time never actually elapses in a unit test).
        app.message_deadline = Some(Instant::now() - Duration::from_millis(1));
        terminal.draw(|frame| app.render(frame)).unwrap();
        assert!(app.message.is_empty());
        assert!(app.message_deadline.is_none());
    }

    /// A message never auto-dismisses while the bottom bar is actively
    /// serving as a text-entry prompt (`command_buffer`) or a pending `q`
    /// quit confirmation — both are actively awaiting a keypress, unlike
    /// a plain notice.
    #[test]
    fn message_is_not_dismissed_while_a_prompt_or_quit_confirm_is_active() {
        let mut app = empty_app();
        app.splash = false;
        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).unwrap();

        app.message = "some notice".to_string();
        app.command_buffer = Some(String::new());
        terminal.draw(|frame| app.render(frame)).unwrap();
        app.message_deadline = Some(Instant::now() - Duration::from_millis(1));
        terminal.draw(|frame| app.render(frame)).unwrap();
        assert_eq!(
            app.message, "some notice",
            "prompt active: must not dismiss"
        );

        app.command_buffer = None;
        app.quit_confirm = true;
        app.message_deadline = Some(Instant::now() - Duration::from_millis(1));
        terminal.draw(|frame| app.render(frame)).unwrap();
        assert_eq!(
            app.message, "some notice",
            "quit_confirm active: must not dismiss"
        );
    }

    #[test]
    fn resolve_command_prefix_and_exact_match() {
        assert_eq!(resolve_command("extract"), Ok("extract"));
        assert_eq!(resolve_command("e"), Ok("extract"));
        assert!(resolve_command("zzz").is_err());
        // "type-as" is itself a prefix of "type-as-raw" — exact match
        // must still win (spec 0114 §7).
        assert_eq!(resolve_command("type-as"), Ok("type-as"));
        assert_eq!(resolve_command("type-as-raw"), Ok("type-as-raw"));
        assert!(resolve_command("type-a").is_err());
    }

    #[test]
    fn longest_common_prefix_examples() {
        assert_eq!(longest_common_prefix(&["extract", "extra"]), "extra");
        assert_eq!(longest_common_prefix(&["extract"]), "extract");
        assert_eq!(longest_common_prefix(&[]), "");
        assert_eq!(longest_common_prefix(&["abc", "xyz"]), "");
    }

    fn empty_app() -> App {
        let decoded = Decoded {
            lines: Vec::new(),
            tree: Vec::new(),
            root_type: "google.protobuf.Empty".to_string(),
            blob: Vec::new(),
            wrapper_offset: 0,
            style_hints: Vec::new(),
        };
        App::new(
            decoded,
            "empty.pb",
            PathBuf::from("empty.pb"),
            2,
            DescriptorContext::empty_for_test(),
            ThemeKind::Dark,
        )
    }

    /// Spec 0113 D26: `Tab` on a unique-matching command-name prefix
    /// completes it in full.
    #[test]
    fn tab_completes_the_unique_command_name() {
        let mut app = empty_app();
        app.splash = false;
        app.handle_key(KeyEvent::new(KeyCode::Char(':'), KeyModifiers::NONE));
        app.handle_key(KeyEvent::new(KeyCode::Char('e'), KeyModifiers::NONE));
        app.handle_key(KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE));
        assert_eq!(app.command_buffer.as_deref(), Some("extract"));
        assert_eq!(app.command_cursor, "extract".chars().count());
    }

    /// Spec 0113 D26: once a space precedes the cursor, `Tab` is a silent
    /// no-op for commands with no argument completion — `:extract` has
    /// none (spec 0114 §7 only adds argument completion for `:type-as`'s
    /// FQDN argument, exercised separately).
    #[test]
    fn tab_is_a_no_op_once_past_the_first_space() {
        let mut app = empty_app();
        app.splash = false;
        app.handle_key(KeyEvent::new(KeyCode::Char(':'), KeyModifiers::NONE));
        for c in "extract ".chars() {
            app.handle_key(KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE));
        }
        app.handle_key(KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE));
        assert_eq!(app.command_buffer.as_deref(), Some("extract "));
    }

    /// Spec 0113 D26: repeated `Tab` cycles forward through a multi-
    /// candidate list, wrapping around; `Shift-Tab` (`BackTab`) cycles
    /// backward. Exercised directly against `handle_tab_key`/a synthetic
    /// `CompletionState` (real multi-candidate cycling is also reachable
    /// end-to-end via `:type-as`/`:type-as-raw`, spec 0114 §7 — see
    /// `resolve_command_prefix_and_exact_match` and the `type_as_command_*`
    /// tests below).
    #[test]
    fn tab_cycles_forward_and_shift_tab_cycles_backward() {
        let mut app = empty_app();
        app.command_buffer = Some("xy".to_string());
        app.command_cursor = 2;
        app.completion = Some(CompletionState {
            token_start: 0,
            suffix: String::new(),
            candidates: vec![
                "xyalpha".to_string(),
                "xybeta".to_string(),
                "xygamma".to_string(),
            ],
            index: None,
        });
        app.handle_tab_key(true);
        assert_eq!(app.command_buffer.as_deref(), Some("xyalpha"));
        app.handle_tab_key(true);
        assert_eq!(app.command_buffer.as_deref(), Some("xybeta"));
        app.handle_tab_key(false);
        assert_eq!(app.command_buffer.as_deref(), Some("xyalpha"));
        // Wraps backward past the start.
        app.handle_tab_key(false);
        assert_eq!(app.command_buffer.as_deref(), Some("xygamma"));
    }

    /// A single-node tree whose root is a message/group node — the
    /// minimal fixture needed to exercise `t`'s override-target
    /// validation (spec 0114 §1).
    fn message_node_app() -> App {
        let lines: Vec<String> = vec!["message_type {".to_string(), "}".to_string()];
        let node = TreeNode {
            span: NodeSpan {
                field_number: 4,
                raw_range: 0..10,
                text_range: 0..2,
                level: 0,
                type_fqdn: Some("google.protobuf.DescriptorProto".to_string()),
                is_message: true,
                packed_record_start: None,
                wire_type: WT_LEN,
                natural_annotation: None,
            },
            parent: None,
            first_child: None,
            last_child: None,
            next_sibling: None,
            prev_sibling: None,
            doc_next: None,
            doc_prev: None,
            rendered_as: None,
        };
        let decoded = Decoded {
            lines,
            tree: vec![node],
            root_type: "google.protobuf.FileDescriptorProto".to_string(),
            // Tag `0x22` = field 4 << 3 | WT_LEN(2), length varint `0x08`
            // = 8, then 8 zero payload bytes — a real, `raw_range`-
            // consistent blob, needed since spec 0132's live preview now
            // splices this node's contents at pane-open time.
            blob: vec![0x22, 0x08, 0, 0, 0, 0, 0, 0, 0, 0],
            wrapper_offset: 0,
            style_hints: vec![Vec::new(); 2],
        };
        App::new(
            decoded,
            "test.pb",
            PathBuf::from("test.pb"),
            2,
            DescriptorContext::empty_for_test(),
            ThemeKind::Dark,
        )
    }

    /// `n` document-order-linked scalar sibling nodes at the root level
    /// (spec 0113 D16: root-level nodes are sibling-linked despite having
    /// no `parent`), one line of text each — the minimal fixture for
    /// exercising main-pane search (spec 0114 §4, extended from the
    /// override pane), which walks `doc_next`/`doc_prev`.
    fn sibling_leaves_app(texts: &[&str]) -> App {
        let lines: Vec<String> = texts.iter().map(|s| s.to_string()).collect();
        let n = lines.len();
        let tree: Vec<TreeNode> = (0..n)
            .map(|i| TreeNode {
                span: NodeSpan {
                    field_number: i as u64 + 1,
                    raw_range: (i * 10)..(i * 10 + 5),
                    text_range: i..i + 1,
                    level: 0,
                    type_fqdn: None,
                    is_message: false,
                    packed_record_start: None,
                    wire_type: WT_VARINT,
                    natural_annotation: None,
                },
                parent: None,
                first_child: None,
                last_child: None,
                next_sibling: (i + 1 < n).then_some(i + 1),
                prev_sibling: i.checked_sub(1),
                doc_next: (i + 1 < n).then_some(i + 1),
                doc_prev: i.checked_sub(1),
                rendered_as: None,
            })
            .collect();
        let decoded = Decoded {
            lines,
            tree,
            root_type: "google.protobuf.FileDescriptorProto".to_string(),
            blob: Vec::new(),
            wrapper_offset: 0,
            style_hints: Vec::new(),
        };
        App::new(
            decoded,
            "test.pb",
            PathBuf::from("test.pb"),
            2,
            DescriptorContext::empty_for_test(),
            ThemeKind::Dark,
        )
    }

    /// Spec 0114 §1/§2: `t` opens the override pane for a message-shaped
    /// cursor node and moves focus there; a second `t` (from either
    /// pane's focus) closes it again.
    #[test]
    fn t_opens_and_closes_the_override_pane_on_a_message_node() {
        let mut app = message_node_app();
        app.splash = false;
        app.term_width = 120;

        app.handle_key(KeyEvent::new(KeyCode::Char('t'), KeyModifiers::NONE));
        assert_eq!(app.override_target, Some(0));
        assert!(app.override_focus);

        // `t` from override-pane focus closes it too.
        app.handle_key(KeyEvent::new(KeyCode::Char('t'), KeyModifiers::NONE));
        assert_eq!(app.override_target, None);
        assert!(!app.override_focus);
    }

    /// `q` closes the override pane (not just blurs focus, unlike
    /// `Tab`).
    #[test]
    fn override_pane_q_closes_pane() {
        let mut app = message_node_app();
        app.splash = false;
        app.term_width = 120;

        app.handle_key(KeyEvent::new(KeyCode::Char('t'), KeyModifiers::NONE));
        assert_eq!(app.override_target, Some(0));
        assert!(app.override_focus);

        app.handle_key(KeyEvent::new(KeyCode::Char('q'), KeyModifiers::NONE));
        assert_eq!(app.override_target, None);
        assert!(!app.override_focus);
    }

    /// Spec 0134 G1: the override selection pane no longer has a `z`/`Z`
    /// kind-rotation key — pressing either is a no-op (no message, no
    /// panic, pane stays open); `Enter` always creates a `Path`-kind
    /// origin.
    #[test]
    fn override_pane_z_is_a_noop() {
        let mut app = message_node_app();
        app.splash = false;
        app.term_width = 120;

        app.handle_key(KeyEvent::new(KeyCode::Char('t'), KeyModifiers::NONE));
        assert!(app.override_focus);

        let message_before = app.message.clone();
        app.handle_key(KeyEvent::new(KeyCode::Char('z'), KeyModifiers::NONE));
        assert_eq!(app.message, message_before);
        assert!(app.override_focus, "pane must stay open");
        app.handle_key(KeyEvent::new(KeyCode::Char('Z'), KeyModifiers::NONE));
        assert_eq!(app.message, message_before);
        assert!(app.override_focus, "pane must stay open");

        app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        let entry = app
            .overrides
            .entries()
            .iter()
            .find(|e| e.active)
            .expect("Enter must create an active entry");
        assert!(matches!(entry.origin, OverrideOrigin::Path { .. }));
    }

    /// Spec 0114 §1.2: `t` also opens the pane on a message/group node
    /// whose type wasn't resolved by the schema (`type_fqdn: None`, as
    /// produced by the unknown-LEN-field probe cascade) — this is the bug
    /// reported during interactive testing of Task #17, where every node
    /// looked scalar-shaped to `type_fqdn.is_none()` under a schema
    /// declaring no fields for the target type.
    #[test]
    fn t_opens_the_override_pane_on_an_unresolved_message_node() {
        let lines: Vec<String> = vec!["1 {".to_string(), "}".to_string()];
        let node = TreeNode {
            span: NodeSpan {
                field_number: 1,
                raw_range: 0..2,
                text_range: 0..2,
                level: 0,
                type_fqdn: None,
                is_message: true,
                packed_record_start: None,
                wire_type: WT_LEN,
                natural_annotation: None,
            },
            parent: None,
            first_child: None,
            last_child: None,
            next_sibling: None,
            prev_sibling: None,
            doc_next: None,
            doc_prev: None,
            rendered_as: None,
        };
        let decoded = Decoded {
            lines,
            tree: vec![node],
            root_type: "google.protobuf.Empty".to_string(),
            // Tag `0x0A` = field 1 << 3 | WT_LEN(2), length varint `0x00`
            // = 0, zero payload bytes — a real, `raw_range`-consistent
            // blob, needed since spec 0132's live preview now splices
            // this node's contents at pane-open time.
            blob: vec![0x0A, 0x00],
            wrapper_offset: 0,
            style_hints: vec![Vec::new(); 2],
        };
        let mut app = App::new(
            decoded,
            "test.pb",
            PathBuf::from("test.pb"),
            2,
            DescriptorContext::empty_for_test(),
            ThemeKind::Dark,
        );
        app.splash = false;
        app.term_width = 120;

        app.handle_key(KeyEvent::new(KeyCode::Char('t'), KeyModifiers::NONE));
        assert_eq!(app.override_target, Some(0));
        assert!(app.override_focus);
    }

    /// Spec 0114 §1: `t` on a scalar/leaf node (no `type_fqdn`) is a
    /// no-op with a status-line message, no pane opens.
    #[test]
    fn t_is_a_no_op_on_a_scalar_node() {
        let lines: Vec<String> = vec!["value: 1".to_string()];
        let node = TreeNode {
            span: NodeSpan {
                field_number: 1,
                raw_range: 0..2,
                text_range: 0..1,
                level: 0,
                type_fqdn: None,
                is_message: false,
                packed_record_start: None,
                wire_type: WT_VARINT,
                natural_annotation: None,
            },
            parent: None,
            first_child: None,
            last_child: None,
            next_sibling: None,
            prev_sibling: None,
            doc_next: None,
            doc_prev: None,
            rendered_as: None,
        };
        let decoded = Decoded {
            lines,
            tree: vec![node],
            root_type: "test.Scalar".to_string(),
            blob: Vec::new(),
            wrapper_offset: 0,
            style_hints: Vec::new(),
        };
        let mut app = App::new(
            decoded,
            "test.pb",
            PathBuf::from("test.pb"),
            2,
            DescriptorContext::empty_for_test(),
            ThemeKind::Dark,
        );
        app.splash = false;
        app.term_width = 120;

        app.handle_key(KeyEvent::new(KeyCode::Char('t'), KeyModifiers::NONE));
        assert_eq!(app.override_target, None);
        assert!(app.message.contains("not a message/group"));
    }

    /// 2026-07-14 feedback: `t` must not refuse a plain string/bytes
    /// field just because it isn't schema-typed as a message — it's
    /// still `WT_LEN`-wire and may in practice carry an embedded
    /// submessage the schema doesn't know about, so the user should be
    /// free to attempt reinterpreting it.
    #[test]
    fn t_opens_the_override_pane_on_a_length_delimited_scalar_field() {
        let lines: Vec<String> = vec!["value: \"hi\"".to_string()];
        let node = TreeNode {
            span: NodeSpan {
                field_number: 1,
                raw_range: 0..4,
                text_range: 0..1,
                level: 0,
                type_fqdn: None,
                is_message: false,
                packed_record_start: None,
                wire_type: WT_LEN,
                natural_annotation: None,
            },
            parent: None,
            first_child: None,
            last_child: None,
            next_sibling: None,
            prev_sibling: None,
            doc_next: None,
            doc_prev: None,
            rendered_as: None,
        };
        let decoded = Decoded {
            lines,
            tree: vec![node],
            root_type: "test.Scalar".to_string(),
            blob: vec![0x0A, 0x02, b'h', b'i'],
            wrapper_offset: 0,
            // One entry per `lines` (spec 0132's live preview now
            // splices this node at pane-open time, which requires
            // `line_styles` to stay index-aligned with `lines`).
            style_hints: vec![Vec::new(); 1],
        };
        let mut app = App::new(
            decoded,
            "test.pb",
            PathBuf::from("test.pb"),
            2,
            DescriptorContext::empty_for_test(),
            ThemeKind::Dark,
        );
        app.splash = false;
        app.term_width = 120;

        app.handle_key(KeyEvent::new(KeyCode::Char('t'), KeyModifiers::NONE));
        assert_eq!(app.override_target, Some(0));
    }

    /// Spec 0114 §2: `t` refuses to open the pane below the minimum
    /// terminal width.
    #[test]
    fn t_refuses_below_the_minimum_terminal_width() {
        let mut app = message_node_app();
        app.splash = false;
        app.term_width = MIN_OVERRIDE_WIDTH - 1;

        app.handle_key(KeyEvent::new(KeyCode::Char('t'), KeyModifiers::NONE));
        assert_eq!(app.override_target, None);
        assert!(app.message.contains("too narrow"));
    }

    /// Spec 0114 §3.2: sort mode defaults to `Inferred` on open, and `a`
    /// toggles between the two modes.
    #[test]
    fn override_sort_defaults_to_inferred_and_a_toggles_it() {
        let mut app = message_node_app();
        app.splash = false;
        app.term_width = 120;
        app.handle_key(KeyEvent::new(KeyCode::Char('t'), KeyModifiers::NONE));
        assert_eq!(app.override_sort, SortMode::Inferred);

        app.handle_key(KeyEvent::new(KeyCode::Char('a'), KeyModifiers::NONE));
        assert_eq!(app.override_sort, SortMode::Lexicographic);

        app.handle_key(KeyEvent::new(KeyCode::Char('a'), KeyModifiers::NONE));
        assert_eq!(app.override_sort, SortMode::Inferred);
    }

    /// Spec 0133 G3/G4: the main-pane `a` key toggles display of each
    /// line's trailing `#@ ...` annotation, purely at render time — the
    /// underlying `self.lines`/`self.line_styles` are untouched, so
    /// toggling `a` twice restores byte-for-byte identical rendering.
    /// Distinct from the override pane's own `a` (candidate sort,
    /// exercised above) and the manage pane's own `a` (entry active
    /// toggle) — this fixture has neither pane open, so only the
    /// main-pane binding is reachable.
    #[test]
    fn a_toggles_the_main_pane_annotation_display() {
        let line = "  id: 5  #@ int32 = 1".to_string();
        let comment_start = line.find("#@").unwrap();
        let node = TreeNode {
            span: NodeSpan {
                field_number: 1,
                raw_range: 0..2,
                text_range: 0..1,
                level: 0,
                type_fqdn: None,
                is_message: false,
                packed_record_start: None,
                wire_type: WT_VARINT,
                natural_annotation: None,
            },
            parent: None,
            first_child: None,
            last_child: None,
            next_sibling: None,
            prev_sibling: None,
            doc_next: None,
            doc_prev: None,
            rendered_as: None,
        };
        let decoded = Decoded {
            lines: vec![line.clone()],
            tree: vec![node],
            root_type: "test.Msg".to_string(),
            blob: vec![0x08, 0x05],
            wrapper_offset: 0,
            style_hints: vec![vec![(comment_start..line.len(), SyntaxRole::Comment)]],
        };
        let mut app = App::new(
            decoded,
            "test.pb",
            PathBuf::from("test.pb"),
            2,
            DescriptorContext::empty_for_test(),
            ThemeKind::Dark,
        );
        app.splash = false;

        assert!(app.annotations);
        assert_eq!(app.render_line_content(0), line);

        app.handle_key(KeyEvent::new(KeyCode::Char('a'), KeyModifiers::NONE));
        assert!(!app.annotations);
        assert_eq!(app.render_line_content(0), "  id: 5");
        let spanned: String = app
            .render_line_spans(0)
            .iter()
            .map(|s| s.content.as_ref())
            .collect();
        assert_eq!(spanned, "  id: 5");

        app.handle_key(KeyEvent::new(KeyCode::Char('a'), KeyModifiers::NONE));
        assert!(app.annotations);
        assert_eq!(app.render_line_content(0), line);
    }

    /// The splash screen is transparent to keyboard input (spec 0113 D22
    /// amendment): the very first keypress both dismisses it and is
    /// processed as a real command, rather than being swallowed.
    #[test]
    fn splash_dismissing_keypress_is_also_processed_as_a_command() {
        let mut app = message_node_app();
        assert!(app.splash);
        app.term_width = 120;

        app.handle_key(KeyEvent::new(KeyCode::Char('t'), KeyModifiers::NONE));
        assert!(!app.splash);
        assert_eq!(app.override_target, Some(0));
    }

    /// Regression test (2026-07-15 feedback): `EnableMouseCapture` turns
    /// on any-motion tracking, so real terminals send a bare `Moved`
    /// event on essentially every pixel the cursor crosses, with no
    /// click at all — a pure `Moved` event must not dismiss the splash
    /// screen (nor clear a status message), unlike every other mouse
    /// event kind, which legitimately counts as user input (spec 0113
    /// D28).
    #[test]
    fn bare_mouse_move_does_not_dismiss_the_splash_screen() {
        let mut app = message_node_app();
        app.main_area = Rect::new(0, 0, 40, 20);
        assert!(app.splash);

        app.handle_mouse(MouseEvent {
            kind: MouseEventKind::Moved,
            column: 0,
            row: 0,
            modifiers: KeyModifiers::NONE,
        });
        assert!(app.splash, "a bare mouse move must not dismiss the splash");

        app.handle_mouse(MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: 0,
            row: 0,
            modifiers: KeyModifiers::NONE,
        });
        assert!(
            !app.splash,
            "an actual click must still dismiss the splash, same as before"
        );
    }

    /// `F1` opens the help overlay; `q`, `Esc`, or `F1` closes it — `?` is
    /// no longer bound to help, since it now belongs to in-pane search.
    #[test]
    fn f1_opens_and_closes_the_help_overlay() {
        let mut app = message_node_app();
        app.splash = false;

        app.handle_key(KeyEvent::new(KeyCode::F(1), KeyModifiers::NONE));
        assert!(app.help_open);

        app.handle_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
        assert!(!app.help_open);

        app.handle_key(KeyEvent::new(KeyCode::F(1), KeyModifiers::NONE));
        assert!(app.help_open);
        app.handle_key(KeyEvent::new(KeyCode::F(1), KeyModifiers::NONE));
        assert!(!app.help_open);
    }

    /// Feedback (2026-07-15): mouse wheel and Shift-wheel scroll the `F1`
    /// help overlay when the pointer hovers over it, instead of leaking
    /// through to the main pane drawn underneath.
    #[test]
    fn mouse_wheel_scrolls_the_help_overlay_when_hovered() {
        let mut app = message_node_app();
        app.splash = false;
        app.main_area = Rect::new(0, 0, 40, 20);
        app.help_open = true;
        app.help_area = Rect::new(5, 5, 30, 10);

        let cursor_before = app.cursor;
        app.handle_mouse(MouseEvent {
            kind: MouseEventKind::ScrollDown,
            column: 10,
            row: 6,
            modifiers: KeyModifiers::NONE,
        });
        assert_eq!(app.help_scroll, 1);
        assert_eq!(
            app.cursor, cursor_before,
            "must not also scroll the main pane underneath"
        );

        app.handle_mouse(MouseEvent {
            kind: MouseEventKind::ScrollDown,
            column: 10,
            row: 6,
            modifiers: KeyModifiers::SHIFT,
        });
        assert_eq!(app.help_scroll, 2, "Shift-wheel scrolls it too");

        app.handle_mouse(MouseEvent {
            kind: MouseEventKind::ScrollUp,
            column: 10,
            row: 6,
            modifiers: KeyModifiers::NONE,
        });
        assert_eq!(app.help_scroll, 1);

        // Hovering outside the overlay (but still over the main pane)
        // must not touch `help_scroll` — it falls through to the pane
        // underneath instead.
        app.handle_mouse(MouseEvent {
            kind: MouseEventKind::ScrollDown,
            column: 1,
            row: 1,
            modifiers: KeyModifiers::NONE,
        });
        assert_eq!(app.help_scroll, 1, "unhovered help overlay must not react");
    }

    /// Spec 0126 G1: `F1` opens the help overlay regardless of what
    /// currently has focus — `manage_focus`, `override_focus`, and an
    /// open `command_buffer` all used to swallow it before reaching the
    /// main match arm's own `F1` handling.
    #[test]
    fn f1_opens_help_regardless_of_focus() {
        let mut app = message_node_app();
        app.splash = false;

        app.manage_focus = true;
        app.handle_key(KeyEvent::new(KeyCode::F(1), KeyModifiers::NONE));
        assert!(app.help_open);
        app.help_open = false;

        app.override_focus = true;
        app.handle_key(KeyEvent::new(KeyCode::F(1), KeyModifiers::NONE));
        assert!(app.help_open);
        app.help_open = false;
        app.override_focus = false;

        app.command_buffer = Some(String::new());
        app.handle_key(KeyEvent::new(KeyCode::F(1), KeyModifiers::NONE));
        assert!(app.help_open);
    }

    /// Spec 0126 G2: Shift-Down/Shift-Up alias `J`/`K`'s sibling-skip
    /// move, no-op-with-message on a childless-of-siblings node either
    /// way.
    #[test]
    fn shift_down_up_alias_sibling_skip_move() {
        let mut app = message_node_app();
        app.splash = false;

        let start = app.cursor;
        app.handle_key(KeyEvent::new(KeyCode::Char('J'), KeyModifiers::NONE));
        let via_j = app.cursor;

        app.cursor = start;
        app.handle_key(KeyEvent::new(KeyCode::Down, KeyModifiers::SHIFT));
        assert_eq!(app.cursor, via_j, "Shift-Down must match J's result");

        app.cursor = via_j;
        app.handle_key(KeyEvent::new(KeyCode::Char('K'), KeyModifiers::NONE));
        let via_k = app.cursor;

        app.cursor = via_j;
        app.handle_key(KeyEvent::new(KeyCode::Up, KeyModifiers::SHIFT));
        assert_eq!(app.cursor, via_k, "Shift-Up must match K's result");
    }

    /// `Outer { repeated int32 vals = 1; }`, packed, 3 elements (`5, 6,
    /// 7`), document order — spec 0124's shared fixture: gives a
    /// `PathField`/`FqdnField` origin (parent path `/`, field `1`) 3
    /// matches, and a `Path` origin (e.g. `/2`) exactly 1 match. Uses a
    /// packed *scalar* repeated field (one `NodeSpan` per element, spec
    /// 0115) rather than a repeated message field, to keep the fixture's
    /// tree shape simple (no nested-message decode involved).
    fn repeated_scalar_fixture() -> (App, Vec<usize>) {
        use prost::Message as _;
        use prost_types::field_descriptor_proto::{Label, Type};
        use prost_types::{
            DescriptorProto, FieldDescriptorProto, FileDescriptorProto, FileDescriptorSet,
        };

        use crate::decode::{decode, DescriptorContext};

        let outer_desc = DescriptorProto {
            name: Some("Outer".to_string()),
            field: vec![FieldDescriptorProto {
                name: Some("vals".to_string()),
                number: Some(1),
                label: Some(Label::Repeated as i32),
                r#type: Some(Type::Int32 as i32),
                ..Default::default()
            }],
            ..Default::default()
        };
        let file = FileDescriptorProto {
            name: Some("test_repeated_scalar.proto".to_string()),
            package: Some("test".to_string()),
            message_type: vec![outer_desc],
            syntax: Some("proto3".to_string()),
            ..Default::default()
        };
        let fds = FileDescriptorSet { file: vec![file] };

        static COUNTER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let descriptor_path =
            std::env::temp_dir().join(format!("protolens-tui-repeated-scalar-descriptor-{n}.pb"));
        std::fs::write(&descriptor_path, fds.encode_to_vec()).unwrap();
        let mut ctx = DescriptorContext::load(&descriptor_path).unwrap();
        std::fs::remove_file(&descriptor_path).unwrap();

        // vals: field 1 (tag 0x0A, LEN/packed), length 3, payload
        // [0x05, 0x06, 0x07] (three one-byte varint elements).
        let blob = [0x0Au8, 0x03, 0x05, 0x06, 0x07];
        let decoded = decode(&blob, &mut ctx, Some("test.Outer"), 2).unwrap();
        let mut app = App::new(
            decoded,
            "test.pb",
            PathBuf::from("test.pb"),
            2,
            ctx,
            ThemeKind::Dark,
        );
        app.splash = false;
        app.term_width = 120;

        let mut items: Vec<usize> = app
            .tree
            .iter()
            .enumerate()
            .filter(|(_, n)| n.span.packed_record_start.is_some())
            .map(|(i, _)| i)
            .collect();
        items.sort_by_key(|&i| app.positional_path(i));
        assert_eq!(items.len(), 3, "fixture must contain 3 packed elements");
        (app, items)
    }

    /// Spec 0124 G1: Left/Right in the manage pane circulate the
    /// main-pane cursor among the fields the highlighted entry's origin
    /// matches, with wraparound, never touching focus; a zero-match
    /// origin is a no-op.
    #[test]
    fn manage_pane_left_right_circulate_affected_fields() {
        let (mut app, items) = repeated_scalar_fixture();
        app.manage_focus = true;
        app.manage_open = true;

        // `PathField` origin: parent `/`, field `1` -> all 3 elements.
        let origin = OverrideOrigin::PathField {
            path: "/".to_string(),
            field: 1,
        };
        app.overrides.activate(origin, None);
        app.manage_highlight = app.overrides.entries().len() - 1;

        app.cursor = items[0];
        app.handle_key(KeyEvent::new(KeyCode::Right, KeyModifiers::NONE));
        assert_eq!(app.cursor, items[1]);
        app.handle_key(KeyEvent::new(KeyCode::Right, KeyModifiers::NONE));
        assert_eq!(app.cursor, items[2]);
        app.handle_key(KeyEvent::new(KeyCode::Right, KeyModifiers::NONE));
        assert_eq!(app.cursor, items[0], "Right must wrap around");
        app.handle_key(KeyEvent::new(KeyCode::Left, KeyModifiers::NONE));
        assert_eq!(app.cursor, items[2], "Left must wrap around");
        assert!(app.manage_focus, "focus must not change");

        // Zero-match origin: no-op.
        app.overrides.activate(
            OverrideOrigin::PathField {
                path: "/".to_string(),
                field: 99,
            },
            None,
        );
        app.manage_highlight = app.overrides.entries().len() - 1;
        let before = app.cursor;
        app.handle_key(KeyEvent::new(KeyCode::Right, KeyModifiers::NONE));
        assert_eq!(app.cursor, before, "zero matches must be a no-op");
    }

    /// Spec 0134 G2: a single derivable candidate is used even when the
    /// main-pane cursor isn't on the node that produced it — rotating
    /// onto a colliding origin deactivates the other entry (existing
    /// `activate`-style invariant, reused unchanged).
    #[test]
    fn manage_pane_z_single_candidate_resolves_without_cursor_match() {
        let (mut app, items) = repeated_scalar_fixture();
        app.manage_focus = true;
        app.manage_open = true;

        let path_origin = OverrideOrigin::Path {
            path: app.positional_path(items[0]),
        };
        app.overrides.activate(path_origin.clone(), None);
        app.manage_highlight = app.overrides.entries().len() - 1;

        // Also seed a colliding PathField entry (parent `/`, field `1`),
        // active, so the rotation-collision path is exercised.
        let collide_origin = OverrideOrigin::PathField {
            path: "/".to_string(),
            field: 1,
        };
        app.overrides.activate(collide_origin.clone(), None);
        let collide_idx = app.overrides.entries().len() - 1;
        assert!(app.overrides.entries()[collide_idx].active);

        // `path_origin` only ever matches `items[0]` itself, so there is
        // exactly one candidate under `PathField` regardless of where
        // the cursor sits — put it elsewhere to confirm the single
        // candidate is used anyway.
        app.cursor = items[1];
        let entry_idx = app
            .overrides
            .entries()
            .iter()
            .position(|e| e.origin == path_origin)
            .expect("original Path entry must still exist");
        app.manage_highlight = entry_idx;
        app.handle_key(KeyEvent::new(KeyCode::Char('z'), KeyModifiers::NONE));

        // `handle_key` leaves `manage_highlight` on the rotated entry
        // (spec 0124 G2) — look it up by index, not by origin: two
        // entries now share `collide_origin` (the rotated one and the
        // pre-existing one it collided with), so origin alone is
        // ambiguous.
        let rotated = &app.overrides.entries()[app.manage_highlight];
        assert_eq!(rotated.origin, collide_origin);
        assert!(rotated.active, "rotated entry must stay active");
        assert!(!rotated.auto, "rotation always resets auto to false");
        let other = app
            .overrides
            .entries()
            .iter()
            .filter(|e| e.origin == collide_origin)
            .count();
        assert_eq!(other, 2, "duplicates now coexist under the same origin");
        assert_eq!(
            app.overrides
                .entries()
                .iter()
                .filter(|e| e.origin == collide_origin && e.active)
                .count(),
            1,
            "only one entry per origin stays active"
        );
        assert!(app.manage_pending_kind.is_none());
    }

    /// Spec 0134 G2/G3: 2+ distinct candidates with the cursor not on
    /// any of them prompts instead of resolving; a same-key retry with
    /// the cursor unchanged advances to the next kind in the barrel
    /// instead of repeating the identical ambiguous outcome.
    #[test]
    fn manage_pane_z_ambiguous_candidates_advance_on_repeated_press() {
        let (mut app, items) = repeated_scalar_fixture();
        app.manage_focus = true;
        app.manage_open = true;

        let fqdn_origin = app
            .origin_for_kind(items[0], OverrideKind::FqdnField)
            .expect("field's parent type is known");
        app.overrides.activate(fqdn_origin.clone(), None);
        app.manage_highlight = app.overrides.entries().len() - 1;

        let outside = app
            .tree
            .iter()
            .position(|n| n.parent.is_none())
            .expect("root node must exist");
        app.cursor = outside;

        // FqdnField -> Path: all 3 packed elements derive distinct Path
        // origins, and the cursor isn't on any of them -> ambiguous.
        app.handle_key(KeyEvent::new(KeyCode::Char('z'), KeyModifiers::NONE));
        assert_eq!(app.message, "z: pick an override target (<-/->)");
        assert_eq!(
            app.overrides.entries()[app.manage_highlight].origin,
            fqdn_origin,
            "entry unchanged while ambiguous"
        );
        assert!(app.manage_pending_kind.is_some());

        // Same key, cursor still unchanged -> advances Path -> PathField.
        // All 3 elements share the same parent/field, so PathField
        // dedups to a single candidate and resolves immediately even
        // though the cursor still isn't on any of them.
        app.handle_key(KeyEvent::new(KeyCode::Char('z'), KeyModifiers::NONE));
        let expected = OverrideOrigin::PathField {
            path: "/".to_string(),
            field: 1,
        };
        assert_eq!(
            app.overrides.entries()[app.manage_highlight].origin,
            expected
        );
        assert!(app.manage_pending_kind.is_none());
    }

    /// Spec 0134 G2/G3: moving the main-pane cursor between two `z`
    /// attempts retries the same stuck kind (instead of advancing past
    /// it) and resolves via the cursor-match branch.
    #[test]
    fn manage_pane_z_ambiguous_then_resolved_via_cursor_move() {
        let (mut app, items) = repeated_scalar_fixture();
        app.manage_focus = true;
        app.manage_open = true;

        let fqdn_origin = app
            .origin_for_kind(items[0], OverrideKind::FqdnField)
            .expect("field's parent type is known");
        app.overrides.activate(fqdn_origin.clone(), None);
        app.manage_highlight = app.overrides.entries().len() - 1;

        let outside = app
            .tree
            .iter()
            .position(|n| n.parent.is_none())
            .expect("root node must exist");
        app.cursor = outside;

        app.handle_key(KeyEvent::new(KeyCode::Char('z'), KeyModifiers::NONE));
        assert_eq!(app.message, "z: pick an override target (<-/->)");

        // Move the cursor onto one of the affected nodes, then retry —
        // must retry the same `Path` attempt (not advance to
        // `PathField`) and resolve via the cursor match.
        app.cursor = items[1];
        app.handle_key(KeyEvent::new(KeyCode::Char('z'), KeyModifiers::NONE));
        let expected = OverrideOrigin::Path {
            path: app.positional_path(items[1]),
        };
        assert_eq!(
            app.overrides.entries()[app.manage_highlight].origin,
            expected
        );
        assert!(app.manage_pending_kind.is_none());
    }

    /// Spec 0134 G2: when no kind (other than the entry's own) applies
    /// to any affected node — e.g. the wrapper root, which has no
    /// parent so `PathField`/`FqdnField` both error — `z` writes "no
    /// override target", leaves the entry unchanged, and clears the
    /// pending state; repeating `z` reproduces the identical outcome.
    #[test]
    fn manage_pane_z_no_target_aborts_when_no_kind_applies() {
        let (mut app, _items) = repeated_scalar_fixture();
        app.manage_focus = true;
        app.manage_open = true;

        let root_idx = app
            .tree
            .iter()
            .position(|n| n.parent.is_none())
            .expect("root node must exist");
        let root_origin = OverrideOrigin::Path {
            path: app.positional_path(root_idx),
        };
        app.overrides.activate(root_origin.clone(), None);
        app.manage_highlight = app.overrides.entries().len() - 1;
        app.cursor = root_idx;

        app.handle_key(KeyEvent::new(KeyCode::Char('z'), KeyModifiers::NONE));
        assert_eq!(app.message, "z: no override target");
        assert_eq!(
            app.overrides.entries()[app.manage_highlight].origin,
            root_origin
        );
        assert!(app.manage_pending_kind.is_none());

        app.handle_key(KeyEvent::new(KeyCode::Char('z'), KeyModifiers::NONE));
        assert_eq!(app.message, "z: no override target");
    }

    /// Rotating an *active* entry's origin kind runs `render_overrides`,
    /// which can auto-seed a brand-new entry elsewhere in the tree (Any/
    /// MessageSet auto-expansion) — re-sorting the whole collection out
    /// from under the index `rotate_origin` already returned.
    /// `manage_highlight` must still land on the just-rotated entry, not
    /// whichever row the reshuffle happens to leave at that stale index
    /// (feedback, 2026-07-16).
    #[test]
    fn manage_pane_z_rotation_survives_a_concurrent_auto_seed_reshuffle() {
        use prost::Message as _;
        use prost_types::field_descriptor_proto::{Label, Type};
        use prost_types::{
            DescriptorProto, FieldDescriptorProto, FileDescriptorProto, FileDescriptorSet,
        };

        use crate::decode::{decode, DescriptorContext};

        let any_msg = DescriptorProto {
            name: Some("Any".to_string()),
            field: vec![
                FieldDescriptorProto {
                    name: Some("type_url".to_string()),
                    number: Some(1),
                    label: Some(Label::Optional as i32),
                    r#type: Some(Type::String as i32),
                    ..Default::default()
                },
                FieldDescriptorProto {
                    name: Some("value".to_string()),
                    number: Some(2),
                    label: Some(Label::Optional as i32),
                    r#type: Some(Type::Bytes as i32),
                    ..Default::default()
                },
            ],
            ..Default::default()
        };
        let any_file = FileDescriptorProto {
            name: Some("google/protobuf/any.proto".to_string()),
            syntax: Some("proto3".to_string()),
            package: Some("google.protobuf".to_string()),
            message_type: vec![any_msg],
            ..Default::default()
        };
        let payload_msg = DescriptorProto {
            name: Some("Payload".to_string()),
            field: vec![FieldDescriptorProto {
                name: Some("label".to_string()),
                number: Some(1),
                label: Some(Label::Optional as i32),
                r#type: Some(Type::String as i32),
                ..Default::default()
            }],
            ..Default::default()
        };
        let container_msg = DescriptorProto {
            name: Some("Container".to_string()),
            field: vec![
                FieldDescriptorProto {
                    name: Some("val".to_string()),
                    number: Some(1),
                    label: Some(Label::Optional as i32),
                    r#type: Some(Type::Int32 as i32),
                    ..Default::default()
                },
                FieldDescriptorProto {
                    name: Some("payload".to_string()),
                    number: Some(2),
                    label: Some(Label::Optional as i32),
                    r#type: Some(Type::Message as i32),
                    type_name: Some(".google.protobuf.Any".to_string()),
                    ..Default::default()
                },
            ],
            ..Default::default()
        };
        let acme_file = FileDescriptorProto {
            name: Some("acme.proto".to_string()),
            syntax: Some("proto2".to_string()),
            package: Some("acme".to_string()),
            dependency: vec!["google/protobuf/any.proto".to_string()],
            message_type: vec![payload_msg, container_msg],
            ..Default::default()
        };
        let fds = FileDescriptorSet {
            file: vec![any_file, acme_file],
        };

        static COUNTER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let descriptor_path = std::env::temp_dir().join(format!(
            "protolens-tui-manage-z-reshuffle-descriptor-{n}.pb"
        ));
        std::fs::write(&descriptor_path, fds.encode_to_vec()).unwrap();
        let mut ctx = DescriptorContext::load(&descriptor_path).unwrap();
        std::fs::remove_file(&descriptor_path).unwrap();

        // Container {
        //   val: 42,
        //   payload: Any { type_url: "type.googleapis.com/acme.Payload",
        //                   value: Payload { label: "hi" } },
        // }
        let label = b"hi";
        let mut payload_bytes = vec![0x0au8, label.len() as u8];
        payload_bytes.extend_from_slice(label);
        let type_url = b"type.googleapis.com/acme.Payload";
        let mut any_bytes = vec![0x0au8, type_url.len() as u8];
        any_bytes.extend_from_slice(type_url);
        any_bytes.push(0x12);
        any_bytes.push(payload_bytes.len() as u8);
        any_bytes.extend_from_slice(&payload_bytes);
        let mut blob = vec![0x08u8, 0x2A]; // field 1, VARINT, value 42
        blob.push(0x12); // field 2, LEN
        blob.push(any_bytes.len() as u8);
        blob.extend_from_slice(&any_bytes);

        let decoded = decode(&blob, &mut ctx, Some("acme.Container"), 2).unwrap();
        let mut app = App::new(
            decoded,
            "test.pb",
            PathBuf::from("test.pb"),
            2,
            ctx,
            ThemeKind::Dark,
        );
        app.splash = false;
        app.term_width = 120;

        let val_idx = app
            .tree
            .iter()
            .position(|n| n.span.field_number == 1)
            .expect("must find the val node");

        // `App::new` already ran one `render_overrides` pass, which
        // auto-seeded the Any field's `value` — undo that seeding so it
        // starts out unexpanded again (no entry for it at all), letting
        // the `z`-triggered pass below re-seed it as a *fresh* entry and
        // reshuffle the collection out from under `manage_highlight`.
        let any_entry_idx = app
            .overrides
            .entries()
            .iter()
            .position(|e| e.auto)
            .expect("Any field must have been auto-seeded by App::new");
        app.overrides.remove(any_entry_idx);

        // Seed `val` as an explicit, active `Path` override — mirroring
        // what the override pane would do.
        let val_origin = override_pane::OverrideOrigin::Path {
            path: app.positional_path(val_idx),
        };
        app.overrides.activate(val_origin.clone(), None);
        app.manage_highlight = app
            .overrides
            .entries()
            .iter()
            .position(|e| e.origin == val_origin)
            .unwrap();
        app.manage_focus = true;
        app.manage_open = true;
        app.cursor = val_idx;
        assert_eq!(
            app.overrides.entries().len(),
            2,
            "root + val, Any field's auto-expansion not seeded yet: {:#?}",
            app.overrides.entries()
        );

        // Rotate: Path -> PathField. Since the rotated entry is active,
        // `handle_key` also runs `render_overrides`, which (for the
        // first time) walks into the still-unexpanded Any field and
        // auto-seeds a brand-new entry for it, reshuffling the whole
        // sorted collection.
        app.handle_key(KeyEvent::new(KeyCode::Char('z'), KeyModifiers::NONE));

        assert_eq!(
            app.overrides.entries().len(),
            3,
            "the Any field's auto-expansion must have been re-seeded by \
             the same render_overrides pass: {:#?}",
            app.overrides.entries()
        );
        let expected_origin = override_pane::OverrideOrigin::PathField {
            path: "/".to_string(),
            field: 1,
        };
        let highlighted = &app.overrides.entries()[app.manage_highlight];
        assert_eq!(
            highlighted.origin,
            expected_origin,
            "manage_highlight must still point at the just-rotated entry, \
             not the newly auto-seeded Any entry: {:#?}",
            app.overrides.entries()
        );
        assert!(highlighted.active, "rotated entry must stay active");
    }

    /// Spec 0124 G3: `d` duplicates the highlighted entry as a new,
    /// always-inactive copy; the original and the copy coexist.
    #[test]
    fn manage_pane_d_duplicates_highlighted_entry_as_inactive() {
        let (mut app, items) = repeated_scalar_fixture();
        app.manage_focus = true;
        app.manage_open = true;

        let origin = OverrideOrigin::Path {
            path: app.positional_path(items[0]),
        };
        app.overrides.activate(origin.clone(), None);
        let orig_idx = app.overrides.entries().len() - 1;
        app.manage_highlight = orig_idx;

        let before_len = app.overrides.entries().len();
        app.handle_key(KeyEvent::new(KeyCode::Char('d'), KeyModifiers::NONE));
        assert_eq!(app.overrides.entries().len(), before_len + 1);
        let new_idx = app.manage_highlight;
        assert!(!app.overrides.entries()[new_idx].active, "copy is inactive");
        assert_eq!(app.overrides.entries()[new_idx].origin, origin);

        // Activating the copy deactivates the original (existing
        // invariant, not new code).
        app.overrides.toggle_active(new_idx);
        let active_count = app
            .overrides
            .entries()
            .iter()
            .filter(|e| e.origin == origin && e.active)
            .count();
        assert_eq!(active_count, 1, "still at most one active entry per origin");
        assert!(app.overrides.entries()[new_idx].active);
    }

    /// `Enter` in the management pane closes it (returning focus to the
    /// main pane), same as `Esc`/`o`.
    #[test]
    fn manage_pane_enter_closes_pane() {
        let (mut app, _items) = repeated_scalar_fixture();
        app.manage_focus = true;
        app.manage_open = true;

        app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert!(!app.manage_open);
        assert!(!app.manage_focus);
    }

    /// `q` closes the management pane (not just blurs focus, unlike
    /// `Tab`).
    #[test]
    fn manage_pane_q_closes_pane() {
        let (mut app, _items) = repeated_scalar_fixture();
        app.manage_focus = true;
        app.manage_open = true;

        app.handle_key(KeyEvent::new(KeyCode::Char('q'), KeyModifiers::NONE));
        assert!(!app.manage_open);
        assert!(!app.manage_focus);
    }

    /// Spec 0130 §G1: manage-pane entry rows render `auto == true`
    /// entries in `manage_entry_style(true, ..)`'s color and
    /// `auto == false` entries in `manage_entry_style(false, ..)`'s
    /// distinct color (no `REVERSED` on either, since neither is
    /// highlighted here).
    #[test]
    fn manage_pane_entries_style_auto_vs_manual_distinctly() {
        let (mut app, items) = repeated_scalar_fixture();
        app.manage_focus = true;
        app.manage_open = true;

        app.overrides.activate(
            OverrideOrigin::Path {
                path: app.positional_path(items[0]),
            },
            None,
        );
        let manual_idx = app.overrides.entries().len() - 1;
        app.overrides.activate_auto(
            OverrideOrigin::Path {
                path: app.positional_path(items[1]),
            },
            Some("auto.Type".to_string()),
        );
        let auto_idx = app
            .overrides
            .entries()
            .iter()
            .position(|e| e.auto)
            .expect("auto entry must exist");
        assert_ne!(manual_idx, auto_idx);
        // Neither entry is highlighted, so `REVERSED` doesn't interfere
        // with the bold/plain assertion below.
        app.manage_highlight = app.overrides.entries().len();

        let area = Rect::new(0, 0, 120, 40);
        let mut terminal =
            Terminal::new(TestBackend::new(area.width, area.height)).expect("terminal");
        terminal
            .draw(|frame| app.render_manage_pane(frame, area))
            .expect("render must not panic");
        let buffer = terminal.backend().buffer().clone();
        let inner = Block::bordered().inner(area);

        let rows = app.manage_display_rows();
        let row_fg = |entry_idx: usize| {
            let row = rows
                .iter()
                .position(|r| matches!(r, ManageRow::Entry(i) if *i == entry_idx))
                .expect("row must exist");
            let y = inner.y + row as u16;
            (inner.x..inner.x + inner.width)
                .map(|x| &buffer[(x, y)])
                .find(|c| !c.symbol().trim().is_empty())
                .expect("row must render some text")
                .fg
        };
        assert_eq!(
            Some(row_fg(auto_idx)),
            theme::manage_entry_style(true, app.theme).fg,
            "auto entry row must use the auto color"
        );
        assert_eq!(
            Some(row_fg(manual_idx)),
            theme::manage_entry_style(false, app.theme).fg,
            "manual entry row must use the manual color"
        );
        assert_ne!(
            row_fg(auto_idx),
            row_fg(manual_idx),
            "auto and manual entries must be visually distinct"
        );
    }

    /// Spec 0125 §G2: `Delete` on an `auto` entry still "in scope"
    /// deactivates it instead of removing it, and shows the explanatory
    /// message; `Delete` on an `auto` entry that has gone out of scope
    /// (its ancestor's own override changed) actually removes it, same
    /// as a manual entry.
    #[test]
    fn manage_pane_delete_deactivates_in_scope_auto_but_removes_out_of_scope_auto() {
        let mut app = message_set_fixture();
        app.manage_focus = true;
        app.manage_open = true;

        let item_idx = app
            .tree
            .iter()
            .position(|n| n.span.type_fqdn.as_deref() == Some(decode::MESSAGE_SET_ITEM_FQDN))
            .expect("Item group must be spliced to the synthetic MessageSetItem type");
        let item_path = app.positional_path(item_idx);
        let item_entry_idx = app
            .overrides
            .entries()
            .iter()
            .position(|e| matches!(&e.origin, OverrideOrigin::Path { path } if *path == item_path))
            .expect("tier-1 entry must exist");
        assert!(app.overrides.entries()[item_entry_idx].auto);
        assert!(app.overrides.entries()[item_entry_idx].active);

        let message_idx = app
            .tree
            .iter()
            .position(|n| n.span.type_fqdn.as_deref() == Some("ms_test.ExtPayload"))
            .expect("message field must resolve to ExtPayload");
        let message_path = app.positional_path(message_idx);
        let message_entry_idx = app
            .overrides
            .entries()
            .iter()
            .position(
                |e| matches!(&e.origin, OverrideOrigin::Path { path } if *path == message_path),
            )
            .expect("tier-2 entry must exist");
        assert!(app.overrides.entries()[message_entry_idx].auto);

        // In-scope: `Delete` on the tier-1 entry deactivates, does not
        // remove.
        let before_len = app.overrides.entries().len();
        app.manage_highlight = item_entry_idx;
        app.handle_key(KeyEvent::new(KeyCode::Delete, KeyModifiers::NONE));
        assert_eq!(
            app.overrides.entries().len(),
            before_len,
            "in-scope auto entry must not be removed"
        );
        assert!(
            !app.overrides.entries()[item_entry_idx].active,
            "in-scope auto entry must be deactivated"
        );
        assert_eq!(
            app.message,
            "auto-derived override deactivated (still in scope — delete would \
             just recreate it; use 'a' or wait for it to go out of scope)"
        );

        // Deactivating tier-1 makes tier-2 no longer "in scope" (spec
        // 0120's demotion): `Delete` on the tier-2 entry now actually
        // removes it, same as a manual entry.
        assert!(!app.auto_entry_in_scope(&app.overrides.entries()[message_entry_idx].clone()));
        let before_len = app.overrides.entries().len();
        app.manage_highlight = message_entry_idx;
        app.handle_key(KeyEvent::new(KeyCode::Delete, KeyModifiers::NONE));
        assert_eq!(
            app.overrides.entries().len(),
            before_len - 1,
            "out-of-scope auto entry must be removed like a manual entry"
        );
    }

    /// Spec 0125 §G2: `Delete` on a manual (`auto == false`) entry is
    /// unchanged — removes it outright, no special message.
    #[test]
    fn manage_pane_delete_removes_manual_entry_unchanged() {
        let (mut app, items) = repeated_scalar_fixture();
        app.manage_focus = true;
        app.manage_open = true;

        app.overrides.activate(
            OverrideOrigin::Path {
                path: app.positional_path(items[0]),
            },
            None,
        );
        let idx = app.overrides.entries().len() - 1;
        assert!(!app.overrides.entries()[idx].auto);
        app.manage_highlight = idx;

        let before_len = app.overrides.entries().len();
        app.handle_key(KeyEvent::new(KeyCode::Delete, KeyModifiers::NONE));
        assert_eq!(app.overrides.entries().len(), before_len - 1);
        assert!(
            !app.message.contains("auto-derived"),
            "manual delete must not show the auto-entry message: {}",
            app.message
        );
    }

    /// Spec 0125 §G3: `:save-overrides` then `:restore-overrides`
    /// round-trips an `auto: true` entry's `auto` flag exactly, and a
    /// pre-existing YAML file with no `auto` key still loads fine
    /// (defaults to `false`).
    #[test]
    fn yaml_round_trips_auto_flag_and_defaults_false_when_absent() {
        let mut collection = override_pane::OverrideCollection::new();
        collection.activate_auto(
            OverrideOrigin::Path {
                path: "/".to_string(),
            },
            Some("pkg.Type".to_string()),
        );
        let yaml = collection.to_yaml("blobsha".to_string(), "descsha".to_string());
        assert!(
            yaml.contains("auto: true"),
            "auto: true must round-trip: {yaml}"
        );
        let (restored, _target) =
            override_pane::OverrideCollection::from_yaml(&yaml).expect("must parse");
        assert!(
            restored.entries()[0].auto,
            "restored entry must keep auto: true"
        );

        // Pre-existing file with no `auto` key at all.
        let legacy_yaml = "version: 1\n\
             target:\n  blob_sha256: blobsha\n  descriptor_set_sha256: descsha\n\
             overrides:\n  - path: /\n    type: pkg.Type\n    active: true\n";
        let (legacy, _target) =
            override_pane::OverrideCollection::from_yaml(legacy_yaml).expect("must parse legacy");
        assert!(
            !legacy.entries()[0].auto,
            "legacy file with no auto key must default to auto: false"
        );
    }

    /// Spec 0114 §3.2: `j`/`k` move the highlight, clamped to
    /// `0..=candidates.len()` — row `0` is the pinned raw entry.
    #[test]
    fn override_highlight_movement_clamps_at_both_ends() {
        let mut app = message_node_app();
        app.splash = false;
        app.term_width = 120;
        app.handle_key(KeyEvent::new(KeyCode::Char('t'), KeyModifiers::NONE));

        app.override_candidates = vec![("a.B".to_string(), None), ("a.C".to_string(), None)];
        app.override_highlight = 0;

        app.handle_key(KeyEvent::new(KeyCode::Char('k'), KeyModifiers::NONE));
        assert_eq!(app.override_highlight, 0);

        app.handle_key(KeyEvent::new(KeyCode::Char('j'), KeyModifiers::NONE));
        assert_eq!(app.override_highlight, 1);
        app.handle_key(KeyEvent::new(KeyCode::Char('j'), KeyModifiers::NONE));
        assert_eq!(app.override_highlight, 2);
        app.handle_key(KeyEvent::new(KeyCode::Char('j'), KeyModifiers::NONE));
        assert_eq!(app.override_highlight, 2);
    }

    /// Spec 0114 §4: `/` searches forward, `?` searches backward, `n`
    /// repeats the last search — wrapping around — and the pinned raw
    /// entry (row `0`) is never matched.
    #[test]
    fn override_search_forward_backward_and_repeat_with_n() {
        let mut app = message_node_app();
        app.splash = false;
        app.term_width = 120;
        app.handle_key(KeyEvent::new(KeyCode::Char('t'), KeyModifiers::NONE));

        app.override_candidates = vec![
            ("pkg.Alpha".to_string(), None),
            ("pkg.Beta".to_string(), None),
            ("pkg.Gamma".to_string(), None),
            ("pkg.Beta2".to_string(), None),
        ];
        app.override_highlight = 0;

        app.handle_key(KeyEvent::new(KeyCode::Char('/'), KeyModifiers::NONE));
        for c in "beta".chars() {
            app.handle_key(KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE));
        }
        app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert!(app.command_buffer.is_none());
        assert_eq!(app.override_highlight, 2); // pkg.Beta

        // `n` repeats forward, wrapping to the next match.
        app.handle_key(KeyEvent::new(KeyCode::Char('n'), KeyModifiers::NONE));
        assert_eq!(app.override_highlight, 4); // pkg.Beta2

        // Wraps back around to the first match.
        app.handle_key(KeyEvent::new(KeyCode::Char('n'), KeyModifiers::NONE));
        assert_eq!(app.override_highlight, 2); // pkg.Beta

        // `?` searches backward from the current highlight (pkg.Beta,
        // row 2) — skips itself, wraps to pkg.Beta2 (row 4).
        app.handle_key(KeyEvent::new(KeyCode::Char('?'), KeyModifiers::NONE));
        for c in "beta".chars() {
            app.handle_key(KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE));
        }
        app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert_eq!(app.override_highlight, 4); // pkg.Beta2

        // No match leaves the highlight unchanged and sets a message.
        app.handle_key(KeyEvent::new(KeyCode::Char('/'), KeyModifiers::NONE));
        for c in "nope".chars() {
            app.handle_key(KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE));
        }
        app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert_eq!(app.override_highlight, 4);
        assert!(app.message.contains("not found"));
    }

    /// Spec 0114 §4 (vim convention): confirming `/` or `?` with an empty
    /// pattern re-uses the last active search pattern, searching in
    /// whichever direction the key that opened this prompt requested —
    /// which may differ from the direction the pattern was originally
    /// searched in.
    #[test]
    fn override_search_with_no_argument_reuses_the_active_pattern() {
        let mut app = message_node_app();
        app.splash = false;
        app.term_width = 120;
        app.handle_key(KeyEvent::new(KeyCode::Char('t'), KeyModifiers::NONE));

        app.override_candidates = vec![
            ("pkg.Alpha".to_string(), None),
            ("pkg.Beta".to_string(), None),
            ("pkg.Gamma".to_string(), None),
            ("pkg.Beta2".to_string(), None),
        ];
        app.override_highlight = 0;

        app.handle_key(KeyEvent::new(KeyCode::Char('/'), KeyModifiers::NONE));
        for c in "beta".chars() {
            app.handle_key(KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE));
        }
        app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert_eq!(app.override_highlight, 2); // pkg.Beta

        // `/<Enter>` with no typed pattern re-uses "beta", searching
        // forward from the current highlight — wraps to pkg.Beta2.
        app.handle_key(KeyEvent::new(KeyCode::Char('/'), KeyModifiers::NONE));
        app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert_eq!(app.override_highlight, 4); // pkg.Beta2

        // `?<Enter>` with no typed pattern re-uses "beta" too, but now
        // searches backward from the current highlight.
        app.handle_key(KeyEvent::new(KeyCode::Char('?'), KeyModifiers::NONE));
        app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert_eq!(app.override_highlight, 2); // pkg.Beta
    }

    /// Spec 0114 §4: `Esc` cancels an in-progress search without moving the
    /// highlight, and `Backspace` on an empty buffer also cancels it.
    #[test]
    fn override_search_esc_and_empty_backspace_cancel() {
        let mut app = message_node_app();
        app.splash = false;
        app.term_width = 120;
        app.handle_key(KeyEvent::new(KeyCode::Char('t'), KeyModifiers::NONE));
        app.override_candidates = vec![("pkg.Alpha".to_string(), None)];
        app.override_highlight = 0;

        app.handle_key(KeyEvent::new(KeyCode::Char('/'), KeyModifiers::NONE));
        app.handle_key(KeyEvent::new(KeyCode::Char('x'), KeyModifiers::NONE));
        app.handle_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
        assert!(app.command_buffer.is_none());
        assert_eq!(app.override_highlight, 0);

        app.handle_key(KeyEvent::new(KeyCode::Char('/'), KeyModifiers::NONE));
        assert!(app.command_buffer.is_some());
        app.handle_key(KeyEvent::new(KeyCode::Backspace, KeyModifiers::NONE));
        assert!(app.command_buffer.is_none());
    }

    /// Spec 0117 §3, extended: `/`/`?` in the management pane share the
    /// same `command_buffer` as main-pane/override-pane search
    /// (spec-0133-adjacent rework), but `Enter` dispatches to
    /// `jump_to_manage_match`, moving `manage_highlight` rather than the
    /// main-pane cursor or the override pane's own highlight.
    #[test]
    fn manage_pane_search_forward_and_backward() {
        let (mut app, items) = repeated_scalar_fixture();
        app.manage_focus = true;
        app.manage_open = true;

        for (item, ty) in items.iter().zip(["pkg.Alpha", "pkg.Beta", "pkg.Gamma"]) {
            let origin = OverrideOrigin::Path {
                path: app.positional_path(*item),
            };
            app.overrides.activate(origin, Some(ty.to_string()));
        }
        app.manage_highlight = 0;

        app.handle_key(KeyEvent::new(KeyCode::Char('/'), KeyModifiers::NONE));
        assert!(app.command_buffer.is_some());
        for c in "gamma".chars() {
            app.handle_key(KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE));
        }
        app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert!(app.command_buffer.is_none());
        assert_eq!(
            app.overrides.entries()[app.manage_highlight]
                .r#type
                .as_deref(),
            Some("pkg.Gamma")
        );

        app.handle_key(KeyEvent::new(KeyCode::Char('?'), KeyModifiers::NONE));
        for c in "alpha".chars() {
            app.handle_key(KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE));
        }
        app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert_eq!(
            app.overrides.entries()[app.manage_highlight]
                .r#type
                .as_deref(),
            Some("pkg.Alpha")
        );
    }

    /// Spec 0114 §4, extended to the main pane: `/`/`?` open a search
    /// prompt on the shared command-line row, `n` repeats the last search
    /// in the same direction, and matches wrap around the document.
    #[test]
    fn main_pane_search_forward_backward_and_repeat_with_n() {
        let mut app = sibling_leaves_app(&["alpha: 1", "beta: 2", "gamma: 3", "beta2: 4"]);
        app.splash = false;
        app.term_width = 120;
        assert_eq!(app.cursor, 0); // alpha

        app.handle_key(KeyEvent::new(KeyCode::Char('/'), KeyModifiers::NONE));
        assert_eq!(app.command_buffer.as_deref(), Some(""));
        for c in "beta".chars() {
            app.handle_key(KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE));
        }
        app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert!(app.command_buffer.is_none());
        assert_eq!(app.cursor, 1); // beta

        // `n` repeats forward, wrapping to the next match.
        app.handle_key(KeyEvent::new(KeyCode::Char('n'), KeyModifiers::NONE));
        assert_eq!(app.cursor, 3); // beta2

        // Wraps back around to the first match.
        app.handle_key(KeyEvent::new(KeyCode::Char('n'), KeyModifiers::NONE));
        assert_eq!(app.cursor, 1); // beta

        // `?` searches backward from the cursor (beta) — skips itself,
        // wraps to beta2.
        app.handle_key(KeyEvent::new(KeyCode::Char('?'), KeyModifiers::NONE));
        for c in "beta".chars() {
            app.handle_key(KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE));
        }
        app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert_eq!(app.cursor, 3); // beta2

        // No match leaves the cursor unchanged and sets a message.
        app.handle_key(KeyEvent::new(KeyCode::Char('/'), KeyModifiers::NONE));
        for c in "nope".chars() {
            app.handle_key(KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE));
        }
        app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert_eq!(app.cursor, 3);
        assert!(app.message.contains("not found"));
    }

    /// Spec 0114 §4 (vim convention), extended to the main pane:
    /// confirming `/` or `?` with an empty pattern re-uses the last
    /// active search pattern, searching in the newly chosen direction.
    #[test]
    fn main_pane_search_with_no_argument_reuses_the_active_pattern() {
        let mut app = sibling_leaves_app(&["alpha: 1", "beta: 2", "gamma: 3", "beta2: 4"]);
        app.splash = false;
        app.term_width = 120;

        app.handle_key(KeyEvent::new(KeyCode::Char('/'), KeyModifiers::NONE));
        for c in "beta".chars() {
            app.handle_key(KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE));
        }
        app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert_eq!(app.cursor, 1); // beta

        // `/<Enter>` with no typed pattern re-uses "beta", forward.
        app.handle_key(KeyEvent::new(KeyCode::Char('/'), KeyModifiers::NONE));
        app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert_eq!(app.cursor, 3); // beta2

        // `?<Enter>` with no typed pattern re-uses "beta" too, backward.
        app.handle_key(KeyEvent::new(KeyCode::Char('?'), KeyModifiers::NONE));
        app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert_eq!(app.cursor, 1); // beta
    }

    /// Spec 0114 §4, extended to the main pane: `Esc` cancels an
    /// in-progress search without moving the cursor, and `Backspace` on an
    /// empty buffer also cancels it.
    #[test]
    fn main_pane_search_esc_and_empty_backspace_cancel() {
        let mut app = sibling_leaves_app(&["alpha: 1", "beta: 2"]);
        app.splash = false;
        app.term_width = 120;

        app.handle_key(KeyEvent::new(KeyCode::Char('/'), KeyModifiers::NONE));
        app.handle_key(KeyEvent::new(KeyCode::Char('x'), KeyModifiers::NONE));
        app.handle_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
        assert!(app.command_buffer.is_none());
        assert_eq!(app.cursor, 0);

        app.handle_key(KeyEvent::new(KeyCode::Char('/'), KeyModifiers::NONE));
        assert!(app.command_buffer.is_some());
        app.handle_key(KeyEvent::new(KeyCode::Backspace, KeyModifiers::NONE));
        assert!(app.command_buffer.is_none());
    }

    /// Spec 0114 §4's main-pane search directive: "search in main pane
    /// requires main pane to be in focus" — while the override pane has
    /// focus, `/`/`?`/`n` share the same `command_buffer` as main-pane
    /// search (spec-0133-adjacent rework), but `Enter` dispatches to the
    /// override pane's own `jump_to_override_match`, not the main pane's
    /// `jump_to_match` — the main-pane cursor never moves.
    #[test]
    fn main_pane_search_keys_are_inert_while_override_pane_has_focus() {
        let mut app = message_node_app();
        app.splash = false;
        app.term_width = 120;
        app.handle_key(KeyEvent::new(KeyCode::Char('t'), KeyModifiers::NONE));
        assert!(app.override_focus);
        let cursor_before = app.cursor;

        app.override_candidates = vec![("pkg.Alpha".to_string(), None)];
        app.override_highlight = 0;

        app.handle_key(KeyEvent::new(KeyCode::Char('/'), KeyModifiers::NONE));
        assert!(app.command_buffer.is_some());
        for c in "alpha".chars() {
            app.handle_key(KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE));
        }
        app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert!(app.command_buffer.is_none());
        assert_eq!(app.override_highlight, 1); // pkg.Alpha
        assert_eq!(app.cursor, cursor_before);
    }

    /// Spec 0114 §4's main-pane search directive: search matches against
    /// the *current* rendered text (`self.lines`), so a range whose type
    /// has been overridden is matched post-override, not against the
    /// original rendering — there is no separate "original text" cache to
    /// special-case.
    #[test]
    fn main_pane_search_matches_the_current_not_original_rendering() {
        let mut app = sibling_leaves_app(&["alpha: 1", "beta: 2"]);
        app.splash = false;
        app.term_width = 120;

        // Simulate an already-applied override splice (spec 0114 §5):
        // node 1's rendered line no longer contains "beta" at all.
        app.lines[1] = "pkg.Overridden { x: 1 }".to_string();

        app.handle_key(KeyEvent::new(KeyCode::Char('/'), KeyModifiers::NONE));
        for c in "beta".chars() {
            app.handle_key(KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE));
        }
        app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert_eq!(app.cursor, 0); // unchanged — "beta" no longer present
        assert!(app.message.contains("not found"));

        app.handle_key(KeyEvent::new(KeyCode::Char('/'), KeyModifiers::NONE));
        for c in "overridden".chars() {
            app.handle_key(KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE));
        }
        app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert_eq!(app.cursor, 1); // matches the overridden text
    }

    /// Spec 0114 §3: `Tab` toggles focus between the main pane and the
    /// open override pane; main-pane navigation keys are inert while the
    /// override pane has focus.
    #[test]
    fn tab_toggles_focus_between_main_and_override_panes() {
        let mut app = message_node_app();
        app.splash = false;
        app.term_width = 120;
        app.handle_key(KeyEvent::new(KeyCode::Char('t'), KeyModifiers::NONE));
        assert!(app.override_focus);

        app.handle_key(KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE));
        assert!(!app.override_focus);
        assert_eq!(app.override_target, Some(0)); // pane stays open

        app.handle_key(KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE));
        assert!(app.override_focus);
    }

    /// A mouse click landing in the main pane shifts keyboard focus back
    /// to it without closing the still-open side pane (2026-07-14
    /// feedback, item 3).
    #[test]
    fn mouse_click_in_main_pane_refocuses_without_closing_override_pane() {
        let (mut app, inner_idx, _) = type_as_fixture();
        app.cursor = inner_idx;
        app.handle_key(KeyEvent::new(KeyCode::Char('t'), KeyModifiers::NONE));
        assert!(app.override_target.is_some());
        assert!(app.override_focus);

        app.main_area = Rect::new(0, 0, 40, 20);
        app.side_area = Rect::new(60, 0, 40, 20);

        app.handle_mouse(MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: 5,
            row: 0,
            modifiers: KeyModifiers::NONE,
        });

        assert!(
            !app.override_focus,
            "click in main pane must shift focus back to it"
        );
        assert_eq!(
            app.override_target,
            Some(inner_idx),
            "the override pane must stay open"
        );
    }

    /// Wheel scroll routes to whichever pane the mouse is hovering, not
    /// whichever pane currently has keyboard focus (2026-07-14 feedback,
    /// item 4).
    #[test]
    fn mouse_wheel_routes_by_hover_position_not_keyboard_focus() {
        let (mut app, inner_idx, _) = type_as_fixture();
        app.cursor = inner_idx;
        app.handle_key(KeyEvent::new(KeyCode::Char('t'), KeyModifiers::NONE));
        assert!(app.override_focus, "keyboard focus starts in the side pane");

        app.main_area = Rect::new(0, 0, 40, 20);
        app.side_area = Rect::new(60, 0, 40, 20);
        app.override_candidates = vec![("a.B".to_string(), None), ("a.C".to_string(), None)];
        app.override_highlight = 0;

        let cursor_before = app.cursor;
        app.handle_mouse(MouseEvent {
            kind: MouseEventKind::ScrollDown,
            column: 5,
            row: 0,
            modifiers: KeyModifiers::NONE,
        });
        assert_ne!(
            app.cursor, cursor_before,
            "hovering the main pane must scroll it, even though the side \
             pane still has keyboard focus"
        );
        assert_eq!(
            app.override_highlight, 0,
            "the unhovered side pane must not react"
        );

        let cursor_after_main_scroll = app.cursor;
        app.handle_mouse(MouseEvent {
            kind: MouseEventKind::ScrollDown,
            column: 65,
            row: 0,
            modifiers: KeyModifiers::NONE,
        });
        assert_eq!(
            app.cursor, cursor_after_main_scroll,
            "hovering the side pane must not move the main-pane cursor"
        );
        assert_eq!(
            app.override_highlight, 1,
            "hovering the side pane must scroll it"
        );
    }

    /// Spec 0127 §G2: Shift+wheel pans whichever pane the mouse is
    /// hovering; plain wheel (no Shift) keeps scrolling vertically as
    /// before.
    #[test]
    fn shift_wheel_pans_the_hovered_main_pane_plain_wheel_still_scrolls() {
        let (mut app, _items) = repeated_scalar_fixture();
        app.main_area = Rect::new(0, 0, 5, 20);
        app.side_area = Rect::new(60, 0, 40, 20);

        let cursor_before = app.cursor;
        app.handle_mouse(MouseEvent {
            kind: MouseEventKind::ScrollDown,
            column: 2,
            row: 0,
            modifiers: KeyModifiers::SHIFT,
        });
        assert_eq!(
            app.cursor, cursor_before,
            "Shift+wheel must pan, not move the cursor"
        );
        assert_eq!(app.pan_offset, PAN_STEP, "Shift+ScrollDown must pan right");

        app.handle_mouse(MouseEvent {
            kind: MouseEventKind::ScrollUp,
            column: 2,
            row: 0,
            modifiers: KeyModifiers::SHIFT,
        });
        assert_eq!(app.pan_offset, 0, "Shift+ScrollUp must pan left");

        app.handle_mouse(MouseEvent {
            kind: MouseEventKind::ScrollDown,
            column: 2,
            row: 0,
            modifiers: KeyModifiers::NONE,
        });
        assert_ne!(
            app.cursor, cursor_before,
            "plain wheel (no Shift) must still scroll vertically"
        );
        assert_eq!(app.pan_offset, 0, "plain wheel must not pan");
    }

    /// Spec 0127 §G2: native `ScrollLeft`/`ScrollRight` pan the hovered
    /// pane without needing Shift.
    #[test]
    fn native_scroll_left_right_pans_without_shift() {
        let (mut app, _items) = repeated_scalar_fixture();
        app.main_area = Rect::new(0, 0, 5, 20);

        app.handle_mouse(MouseEvent {
            kind: MouseEventKind::ScrollRight,
            column: 2,
            row: 0,
            modifiers: KeyModifiers::NONE,
        });
        assert_eq!(app.pan_offset, PAN_STEP, "ScrollRight must pan right");

        app.handle_mouse(MouseEvent {
            kind: MouseEventKind::ScrollLeft,
            column: 2,
            row: 0,
            modifiers: KeyModifiers::NONE,
        });
        assert_eq!(app.pan_offset, 0, "ScrollLeft must pan left");
    }

    /// Spec 0127 §G1: the override pane and the manage pane each carry
    /// their own `pan_offset`, independent of the main pane's and of each
    /// other's.
    #[test]
    fn override_and_manage_panes_pan_independently_of_the_main_pane() {
        let (mut app, items) = repeated_scalar_fixture();
        app.main_area = Rect::new(0, 0, 40, 20);
        app.side_area = Rect::new(60, 0, 5, 20);

        app.manage_open = true;
        app.overrides.activate(
            OverrideOrigin::Path {
                path: app.positional_path(items[0]),
            },
            None,
        );
        app.handle_mouse(MouseEvent {
            kind: MouseEventKind::ScrollRight,
            column: 62,
            row: 0,
            modifiers: KeyModifiers::NONE,
        });
        assert_eq!(app.manage_pan_offset, PAN_STEP);
        assert_eq!(
            app.pan_offset, 0,
            "the main pane's pan_offset must be untouched"
        );

        app.manage_open = false;
        app.override_target = Some(items[0]);
        app.handle_mouse(MouseEvent {
            kind: MouseEventKind::ScrollRight,
            column: 62,
            row: 0,
            modifiers: KeyModifiers::NONE,
        });
        assert_eq!(app.override_pan_offset, PAN_STEP);
        assert_eq!(
            app.manage_pan_offset, PAN_STEP,
            "unrelated to the override pane's own offset"
        );
    }

    /// Spec 0127 §G1: a long `:command` buffer becomes pannable — typing
    /// past the visible width auto-follows the cursor instead of clipping
    /// it off-screen, and the same offset can also be panned manually via
    /// hover + Shift+wheel/native horizontal scroll.
    #[test]
    fn long_command_buffer_is_pannable_and_keeps_cursor_visible() {
        let (mut app, _items) = repeated_scalar_fixture();
        app.splash = false;
        app.command_buffer = Some("a".repeat(80));
        app.command_cursor = 80;

        let backend = TestBackend::new(60, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|frame| app.render(frame)).unwrap();

        let cmd_area = app
            .cmd_area
            .expect("command bar must be shown while typing");
        assert!(
            app.command_pan_offset > 0,
            "auto-follow must have panned to keep the cursor visible"
        );
        let cursor_x = cmd_area.x + (1 + app.command_cursor - app.command_pan_offset) as u16;
        assert!(
            cursor_x < cmd_area.x + cmd_area.width,
            "the cursor must stay within the visible command bar"
        );

        let offset_before = app.command_pan_offset;
        app.handle_mouse(MouseEvent {
            kind: MouseEventKind::ScrollLeft,
            column: cmd_area.x,
            row: cmd_area.y,
            modifiers: KeyModifiers::NONE,
        });
        assert!(
            app.command_pan_offset < offset_before,
            "hovering + ScrollLeft must pan the command bar left"
        );
    }

    /// Spec 0129 §G1/§G3: click-drag across N main-pane rows, release —
    /// selects the whole `[start, end]` range in document order, and
    /// `render` highlights every row in that range with `REVERSED`.
    #[test]
    fn drag_select_spans_multiple_main_pane_rows() {
        let mut app = sibling_leaves_app(&["alpha: 1", "beta: 2", "gamma: 3", "delta: 4"]);
        app.splash = false;
        app.main_area = Rect::new(0, 0, 40, 20);

        app.handle_mouse(MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: 0,
            row: 1,
            modifiers: KeyModifiers::NONE,
        });
        assert_eq!(app.select_anchor, Some(1));
        assert_eq!(app.select_end, Some(1));

        app.handle_mouse(MouseEvent {
            kind: MouseEventKind::Drag(MouseButton::Left),
            column: 0,
            row: 3,
            modifiers: KeyModifiers::NONE,
        });
        assert_eq!(app.select_anchor, Some(1));
        assert_eq!(app.select_end, Some(3));

        let (count, text) = app.selected_text().expect("selection must be active");
        assert_eq!(count, 3);
        assert_eq!(text, "beta: 2\ngamma: 3\ndelta: 4");

        app.handle_mouse(MouseEvent {
            kind: MouseEventKind::Up(MouseButton::Left),
            column: 0,
            row: 3,
            modifiers: KeyModifiers::NONE,
        });
        assert_eq!(
            app.select_anchor,
            Some(1),
            "selection persists after release"
        );
        assert_eq!(app.select_end, Some(3));
        // Spec 0131 §G1/test plan item 3: mouse release no longer copies
        // by itself.
        assert!(
            app.message.is_empty(),
            "unexpected message: {}",
            app.message
        );

        // Spec 0131 §G1/test plan item 1: `Ctrl-C` copies the persisted
        // drag-selection. No working clipboard provider exists in this
        // (headless) test environment — the OSC 52 fallback path is
        // exactly what's exercised here, not a panic.
        app.handle_key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL));
        assert!(
            app.message == "3 line(s) copied to clipboard"
                || app.message == "3 line(s) copied to clipboard (OSC 52 fallback)",
            "unexpected message: {}",
            app.message
        );
    }

    /// Feedback (2026-07-15): a plain click (`Down`+`Up`, no drag, not
    /// the second half of a double-click) must deselect any active
    /// selection rather than leave a length-1 selection behind — this
    /// replaces spec 0129 §G3's original "plain click always selects"
    /// behavior (superseded; see `double_click_selects_the_clicked_line`
    /// for the new, explicit way to select a single line by mouse).
    #[test]
    fn plain_click_with_no_drag_deselects() {
        let mut app = sibling_leaves_app(&["alpha: 1", "beta: 2", "gamma: 3"]);
        app.splash = false;
        app.main_area = Rect::new(0, 0, 40, 20);

        // Seed an existing drag-selection first, so this also proves a
        // later plain click clears a *pre-existing* selection, not just
        // "never selects in the first place".
        app.handle_mouse(MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: 0,
            row: 0,
            modifiers: KeyModifiers::NONE,
        });
        app.handle_mouse(MouseEvent {
            kind: MouseEventKind::Drag(MouseButton::Left),
            column: 0,
            row: 2,
            modifiers: KeyModifiers::NONE,
        });
        app.handle_mouse(MouseEvent {
            kind: MouseEventKind::Up(MouseButton::Left),
            column: 0,
            row: 2,
            modifiers: KeyModifiers::NONE,
        });
        assert_eq!(app.select_anchor, Some(0));
        assert_eq!(app.select_end, Some(2));

        // A plain click on a different line (no drag) must clear it.
        app.handle_mouse(MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: 0,
            row: 1,
            modifiers: KeyModifiers::NONE,
        });
        app.handle_mouse(MouseEvent {
            kind: MouseEventKind::Up(MouseButton::Left),
            column: 0,
            row: 1,
            modifiers: KeyModifiers::NONE,
        });
        assert_eq!(app.select_anchor, None, "plain click deselects");
        assert_eq!(app.select_end, None);
    }

    /// Feedback (2026-07-15): double-clicking a main-pane line (two
    /// `Down`+`Up` clicks on the same line, in quick succession)
    /// explicitly selects that line for copy. Crossterm reports `Down`
    /// identically for single and double clicks, so this exercises the
    /// app's own timestamp/position-based disambiguation
    /// (`App::last_click`/`pending_double_click`).
    #[test]
    fn double_click_selects_the_clicked_line_for_copy() {
        let mut app = sibling_leaves_app(&["alpha: 1", "beta: 2"]);
        app.splash = false;
        app.main_area = Rect::new(0, 0, 40, 20);

        for _ in 0..2 {
            app.handle_mouse(MouseEvent {
                kind: MouseEventKind::Down(MouseButton::Left),
                column: 0,
                row: 0,
                modifiers: KeyModifiers::NONE,
            });
            app.handle_mouse(MouseEvent {
                kind: MouseEventKind::Up(MouseButton::Left),
                column: 0,
                row: 0,
                modifiers: KeyModifiers::NONE,
            });
        }

        assert_eq!(app.select_anchor, Some(0), "double-click selects the line");
        assert_eq!(app.select_end, Some(0));
        assert!(
            app.message.is_empty(),
            "unexpected message: {}",
            app.message
        );

        let (count, text) = app.selected_text().expect("selection must be active");
        assert_eq!(count, 1);
        assert_eq!(text, "alpha: 1");

        app.handle_key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL));
        assert!(
            app.message == "1 line(s) copied to clipboard"
                || app.message == "1 line(s) copied to clipboard (OSC 52 fallback)",
            "unexpected message: {}",
            app.message
        );
    }

    /// Spec 0129 §G1/test plan item 3: dragging upward (end row above
    /// start row) still copies the correct range in top-to-bottom
    /// document order, not reversed.
    #[test]
    fn drag_select_upward_still_copies_top_to_bottom() {
        let mut app = sibling_leaves_app(&["alpha: 1", "beta: 2", "gamma: 3"]);
        app.splash = false;
        app.main_area = Rect::new(0, 0, 40, 20);

        app.handle_mouse(MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: 0,
            row: 2,
            modifiers: KeyModifiers::NONE,
        });
        app.handle_mouse(MouseEvent {
            kind: MouseEventKind::Drag(MouseButton::Left),
            column: 0,
            row: 0,
            modifiers: KeyModifiers::NONE,
        });
        assert_eq!(app.select_anchor, Some(2));
        assert_eq!(app.select_end, Some(0));

        let (count, text) = app.selected_text().expect("selection must be active");
        assert_eq!(count, 3, "top-to-bottom order, not reversed");
        assert_eq!(text, "alpha: 1\nbeta: 2\ngamma: 3");

        app.handle_mouse(MouseEvent {
            kind: MouseEventKind::Up(MouseButton::Left),
            column: 0,
            row: 0,
            modifiers: KeyModifiers::NONE,
        });
        assert!(
            app.message.is_empty(),
            "unexpected message: {}",
            app.message
        );

        app.handle_key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL));
        assert!(
            app.message == "3 line(s) copied to clipboard"
                || app.message == "3 line(s) copied to clipboard (OSC 52 fallback)",
            "unexpected message: {}",
            app.message
        );
    }

    /// Spec 0131 §G1/test plan item 2: `Ctrl-C` with no active selection
    /// copies exactly the cursor's current line.
    #[test]
    fn ctrl_c_with_no_selection_copies_cursor_line() {
        let mut app = sibling_leaves_app(&["alpha: 1", "beta: 2"]);
        app.splash = false;
        app.main_area = Rect::new(0, 0, 40, 20);

        assert_eq!(app.select_anchor, None, "no selection active yet");
        app.handle_key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL));
        assert_eq!(app.select_anchor, Some(0));
        assert_eq!(app.select_end, Some(0));
        assert!(
            app.message == "1 line(s) copied to clipboard"
                || app.message == "1 line(s) copied to clipboard (OSC 52 fallback)",
            "unexpected message: {}",
            app.message
        );
    }

    /// Spec 0131 §G2/test plan item 4: a clipboard-unavailable
    /// environment (no provider reachable, as in this headless test
    /// harness) produces the OSC 52 fallback message instead of
    /// panicking.
    #[test]
    fn clipboard_unavailable_shows_fallback_message_without_panicking() {
        let mut app = sibling_leaves_app(&["alpha: 1"]);
        app.splash = false;
        app.main_area = Rect::new(0, 0, 40, 20);

        app.handle_mouse(MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: 0,
            row: 0,
            modifiers: KeyModifiers::NONE,
        });
        app.handle_key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL));
        // This sandbox has no reachable clipboard provider, so the
        // failure branch is exactly what's exercised here.
        assert!(
            app.message == "1 line(s) copied to clipboard"
                || app.message == "1 line(s) copied to clipboard (OSC 52 fallback)",
            "unexpected message: {}",
            app.message
        );
    }

    /// Spec 0129 §G3: a fresh click starts a new selection, replacing
    /// the old one; `Esc` clears an existing selection's highlight too.
    #[test]
    fn fresh_click_replaces_selection_esc_clears_it() {
        let mut app = sibling_leaves_app(&["alpha: 1", "beta: 2", "gamma: 3"]);
        app.splash = false;
        app.main_area = Rect::new(0, 0, 40, 20);

        app.handle_mouse(MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: 0,
            row: 0,
            modifiers: KeyModifiers::NONE,
        });
        app.handle_mouse(MouseEvent {
            kind: MouseEventKind::Drag(MouseButton::Left),
            column: 0,
            row: 2,
            modifiers: KeyModifiers::NONE,
        });
        app.handle_mouse(MouseEvent {
            kind: MouseEventKind::Up(MouseButton::Left),
            column: 0,
            row: 2,
            modifiers: KeyModifiers::NONE,
        });
        assert_eq!(app.select_anchor, Some(0));
        assert_eq!(app.select_end, Some(2));

        app.handle_mouse(MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: 0,
            row: 1,
            modifiers: KeyModifiers::NONE,
        });
        assert_eq!(
            app.select_anchor,
            Some(1),
            "a fresh click replaces the old selection"
        );
        assert_eq!(app.select_end, Some(1));

        app.handle_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
        assert_eq!(app.select_anchor, None, "Esc clears the selection");
        assert_eq!(app.select_end, None);
    }

    /// `Esc` closes the override pane regardless of which pane currently
    /// has focus — same "works regardless of focus" treatment as `t`
    /// (spec 0114 §8's key-bindings table).
    #[test]
    fn esc_closes_the_override_pane_from_either_focus() {
        let mut app = message_node_app();
        app.splash = false;
        app.term_width = 120;

        app.handle_key(KeyEvent::new(KeyCode::Char('t'), KeyModifiers::NONE));
        app.handle_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
        assert_eq!(app.override_target, None);

        app.handle_key(KeyEvent::new(KeyCode::Char('t'), KeyModifiers::NONE));
        app.handle_key(KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE));
        assert!(!app.override_focus);
        app.handle_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
        assert_eq!(app.override_target, None);
    }

    /// Spec 0114 §1.1: the virtual encompassing wrapper protobuf makes
    /// "the node under the cursor" unambiguous even at the top level, and
    /// display coordinates (byte ranges, positional paths) are corrected
    /// back to exactly what they were pre-wrap. Mirrors the synthetic
    /// `Outer { inner: Inner { id: 5 } }` fixture in
    /// `extract::tests::extract_binary_message_round_trips_through_a_fresh_decode`.
    #[test]
    fn wrapper_offset_and_display_range_restore_pre_wrap_coordinates() {
        use prost::Message as _;
        use prost_types::field_descriptor_proto::{Label, Type};
        use prost_types::{
            DescriptorProto, FieldDescriptorProto, FileDescriptorProto, FileDescriptorSet,
        };

        use crate::decode::{decode, DescriptorContext};

        let inner_desc = DescriptorProto {
            name: Some("Inner".to_string()),
            field: vec![FieldDescriptorProto {
                name: Some("id".to_string()),
                number: Some(1),
                label: Some(Label::Optional as i32),
                r#type: Some(Type::Int32 as i32),
                ..Default::default()
            }],
            ..Default::default()
        };
        let outer_desc = DescriptorProto {
            name: Some("Outer".to_string()),
            field: vec![FieldDescriptorProto {
                name: Some("inner".to_string()),
                number: Some(1),
                label: Some(Label::Optional as i32),
                r#type: Some(Type::Message as i32),
                type_name: Some(".test.Inner".to_string()),
                ..Default::default()
            }],
            ..Default::default()
        };
        let file = FileDescriptorProto {
            name: Some("test_wrapper_offset.proto".to_string()),
            package: Some("test".to_string()),
            message_type: vec![outer_desc, inner_desc],
            syntax: Some("proto3".to_string()),
            ..Default::default()
        };
        let fds = FileDescriptorSet { file: vec![file] };

        let descriptor_path =
            std::env::temp_dir().join("protolens-tui-wrapper-offset-descriptor.pb");
        std::fs::write(&descriptor_path, fds.encode_to_vec()).unwrap();
        let mut ctx = DescriptorContext::load(&descriptor_path).unwrap();
        std::fs::remove_file(&descriptor_path).unwrap();

        // Inner: field 1 varint 5 -> tag 0x08, value 0x05.
        let inner_bytes = [0x08u8, 0x05];
        // Outer wraps it as field 1 (LEN): tag (1<<3)|2 = 0x0A, len 2.
        let blob = [0x0Au8, 0x02, inner_bytes[0], inner_bytes[1]];

        let decoded = decode(&blob, &mut ctx, Some("test.Outer"), 2).unwrap();
        // tag(1 byte) + length-varint(1 byte, blob.len() == 4 fits in 1 byte).
        assert_eq!(decoded.wrapper_offset, 2);
        assert_eq!(decoded.blob.len(), blob.len() + 2);

        let app = App::new(
            decoded,
            "test.pb",
            PathBuf::from("test.pb"),
            2,
            ctx,
            ThemeKind::Dark,
        );

        // The level-0 node is the wrapper's sole field, standing in for
        // the entire original message (spec 0114 §1.1) — it did not exist
        // pre-wrap.
        let outer_idx = app
            .tree
            .iter()
            .position(|n| n.span.type_fqdn.as_deref() == Some("test.Outer"))
            .expect("tree must contain the Outer stand-in node");
        // Its whole-message payload, offset-corrected, is exactly the
        // caller's original blob.
        assert_eq!(app.display_range(outer_idx), 0..blob.len());
        // The wrapper's own node displays as bare "/".
        assert_eq!(app.positional_path(outer_idx), "/");

        let inner_idx = app
            .tree
            .iter()
            .position(|n| n.span.type_fqdn.as_deref() == Some("test.Inner"))
            .expect("tree must contain the Inner submessage");
        // Byte offsets 2..4 of the *original* blob, not the wrapped one.
        assert_eq!(app.display_range(inner_idx), 2..blob.len());
        // Leading `/1` leg (descent into the wrapper's sole field) is
        // dropped — matches the path this node would have had pre-wrap.
        assert_eq!(app.positional_path(inner_idx), "/1");
    }

    /// `display_range` on a scalar node starts at the payload, same as a
    /// message/group node: the field's own tag (and, for length-delimited
    /// scalars, the length prefix) is stripped. A packed-repeated field is
    /// the length-delimited case, but `IndexingTextSink::scalar_field`
    /// pushes one `NodeSpan` *per element* (spec 0115), each already
    /// bare-payload (`packed_record_start: Some(...)`) — so `display_range`
    /// on one of those element nodes returns that element's own byte
    /// unstripped, not the whole record's tag+length-stripped payload.
    #[test]
    fn display_range_strips_tag_and_length_for_scalars_including_packed() {
        use prost::Message as _;
        use prost_types::field_descriptor_proto::{Label, Type};
        use prost_types::{
            DescriptorProto, FieldDescriptorProto, FileDescriptorProto, FileDescriptorSet,
        };

        use crate::decode::{decode, DescriptorContext};

        let msg_desc = DescriptorProto {
            name: Some("Msg".to_string()),
            field: vec![
                FieldDescriptorProto {
                    name: Some("id".to_string()),
                    number: Some(1),
                    label: Some(Label::Optional as i32),
                    r#type: Some(Type::Int32 as i32),
                    ..Default::default()
                },
                FieldDescriptorProto {
                    name: Some("vals".to_string()),
                    number: Some(2),
                    label: Some(Label::Repeated as i32),
                    r#type: Some(Type::Int32 as i32),
                    ..Default::default()
                },
            ],
            ..Default::default()
        };
        let file = FileDescriptorProto {
            name: Some("test_display_range_scalars.proto".to_string()),
            package: Some("test".to_string()),
            message_type: vec![msg_desc],
            syntax: Some("proto3".to_string()),
            ..Default::default()
        };
        let fds = FileDescriptorSet { file: vec![file] };

        let descriptor_path =
            std::env::temp_dir().join("protolens-tui-display-range-scalars-descriptor.pb");
        std::fs::write(&descriptor_path, fds.encode_to_vec()).unwrap();
        let mut ctx = DescriptorContext::load(&descriptor_path).unwrap();
        std::fs::remove_file(&descriptor_path).unwrap();

        // id: field 1 varint 5 -> tag 0x08, value 0x05.
        // vals: field 2 (LEN, packed) tag (2<<3)|2 = 0x12, len 3, payload
        // [0x01, 0x02, 0x03] (three varint elements 1, 2, 3).
        let blob = [0x08u8, 0x05, 0x12, 0x03, 0x01, 0x02, 0x03];

        let decoded = decode(&blob, &mut ctx, Some("test.Msg"), 2).unwrap();
        let app = App::new(
            decoded,
            "test.pb",
            PathBuf::from("test.pb"),
            2,
            ctx,
            ThemeKind::Dark,
        );

        let id_idx = app
            .tree
            .iter()
            .position(|n| n.span.field_number == 1)
            .expect("tree must contain the id field");
        assert!(!app.tree[id_idx].span.is_message);
        // Tag (1 byte) stripped: just the varint value byte.
        assert_eq!(app.display_range(id_idx), 1..2);

        let vals_indices: Vec<usize> = app
            .tree
            .iter()
            .enumerate()
            .filter(|(_, n)| n.span.field_number == 2)
            .map(|(i, _)| i)
            .collect();
        // One NodeSpan per packed element (spec 0115), not one for the
        // whole record.
        assert_eq!(vals_indices.len(), 3);
        for idx in &vals_indices {
            assert!(!app.tree[*idx].span.is_message);
            assert!(app.tree[*idx].span.packed_record_start.is_some());
        }
        // Each element's own byte, already bare-payload — no further
        // tag/length stripping applied.
        assert_eq!(app.display_range(vals_indices[0]), 4..5);
        assert_eq!(app.display_range(vals_indices[1]), 5..6);
        assert_eq!(app.display_range(vals_indices[2]), 6..7);
    }

    /// Spec 0118 §4: `splice_override` regenerates a whole node (not just
    /// its interior) into `self.lines`/`self.tree`, repeatable on the
    /// same node (the design's key risk: post-order array contiguity does
    /// not survive a *second* override of the same node, since the first
    /// override's new nodes are appended at the array's end —
    /// `splice_override` must never rely on it).
    #[test]
    fn apply_override_splices_tree_and_lines_repeatedly() {
        use prost::Message as _;
        use prost_types::field_descriptor_proto::{Label, Type};
        use prost_types::{
            DescriptorProto, FieldDescriptorProto, FileDescriptorProto, FileDescriptorSet,
        };

        use crate::decode::{decode, DescriptorContext};

        let leaf_desc = DescriptorProto {
            name: Some("Leaf".to_string()),
            field: vec![FieldDescriptorProto {
                name: Some("val".to_string()),
                number: Some(1),
                label: Some(Label::Optional as i32),
                r#type: Some(Type::Int32 as i32),
                ..Default::default()
            }],
            ..Default::default()
        };
        let node_desc = DescriptorProto {
            name: Some("Node".to_string()),
            field: vec![
                FieldDescriptorProto {
                    name: Some("a".to_string()),
                    number: Some(1),
                    label: Some(Label::Optional as i32),
                    r#type: Some(Type::Message as i32),
                    type_name: Some(".test.Leaf".to_string()),
                    ..Default::default()
                },
                FieldDescriptorProto {
                    name: Some("b".to_string()),
                    number: Some(2),
                    label: Some(Label::Optional as i32),
                    r#type: Some(Type::Int32 as i32),
                    ..Default::default()
                },
            ],
            ..Default::default()
        };
        let outer_desc = DescriptorProto {
            name: Some("Outer".to_string()),
            field: vec![FieldDescriptorProto {
                name: Some("inner".to_string()),
                number: Some(1),
                label: Some(Label::Optional as i32),
                r#type: Some(Type::Message as i32),
                type_name: Some(".test.Node".to_string()),
                ..Default::default()
            }],
            ..Default::default()
        };
        let file = FileDescriptorProto {
            name: Some("test_apply_override.proto".to_string()),
            package: Some("test".to_string()),
            message_type: vec![outer_desc, node_desc, leaf_desc],
            syntax: Some("proto3".to_string()),
            ..Default::default()
        };
        let fds = FileDescriptorSet { file: vec![file] };

        let descriptor_path =
            std::env::temp_dir().join("protolens-tui-apply-override-descriptor.pb");
        std::fs::write(&descriptor_path, fds.encode_to_vec()).unwrap();
        let mut ctx = DescriptorContext::load(&descriptor_path).unwrap();
        std::fs::remove_file(&descriptor_path).unwrap();

        // Node payload: a = Leaf { val: 9 } (message, field 1), b = 42
        // (varint, field 2).
        let leaf_bytes = [0x08u8, 0x09];
        let node_payload = [0x0Au8, 0x02, leaf_bytes[0], leaf_bytes[1], 0x10, 0x2A];
        // Outer wraps Node as field 1 (LEN).
        let mut blob = vec![0x0Au8, node_payload.len() as u8];
        blob.extend_from_slice(&node_payload);

        let decoded = decode(&blob, &mut ctx, Some("test.Outer"), 2).unwrap();
        let mut app = App::new(
            decoded,
            "test.pb",
            PathBuf::from("test.pb"),
            2,
            ctx,
            ThemeKind::Dark,
        );

        let node_idx = app
            .tree
            .iter()
            .position(|n| n.span.type_fqdn.as_deref() == Some("test.Node"))
            .expect("tree must contain the Node submessage");
        let node_level = app.tree[node_idx].span.level;

        // Fold the "a" child before overriding, to verify the stale-fold
        // scrubbing (`collect_descendants` cleanup).
        let a_idx_before = app.tree[node_idx]
            .first_child
            .expect("Node has at least one child");
        app.folded.insert(a_idx_before);

        let assert_children = |app: &App, tag: &str| {
            let mut children = Vec::new();
            let mut cur = app.tree[node_idx].first_child;
            while let Some(c) = cur {
                children.push(c);
                cur = app.tree[c].next_sibling;
            }
            assert_eq!(children.len(), 2, "{tag}: expected two children (a, b)");
            for &c in &children {
                assert_eq!(
                    app.tree[c].span.level,
                    node_level + 1,
                    "{tag}: child level must match pre-override nesting"
                );
            }
            assert_eq!(
                app.tree[children[0]].span.type_fqdn.as_deref(),
                Some("test.Leaf"),
                "{tag}: first child must resolve to test.Leaf"
            );
        };

        app.override_target = Some(node_idx);

        // 1) Re-typed as itself: idempotent structural round-trip.
        app.splice_override(node_idx, Some("test.Node".to_string()))
            .expect("re-typing as the same type must succeed");
        assert_children(&app, "re-typed as itself");
        assert_eq!(
            app.tree[node_idx].span.type_fqdn.as_deref(),
            Some("test.Node")
        );
        assert!(
            !app.folded.contains(&a_idx_before),
            "orphaned old child must be scrubbed from `folded`"
        );

        // 2) Raw override (no schema).
        app.splice_override(node_idx, None)
            .expect("raw override must succeed");
        assert_eq!(app.tree[node_idx].span.type_fqdn, None);

        // 3) Re-typed again, on top of two prior overrides — exercises
        // repeated overrides of the same node.
        app.splice_override(node_idx, Some("test.Node".to_string()))
            .expect("third override must still succeed");
        assert_children(&app, "re-typed a third time");

        // `line_to_node` must stay fully consistent with the doc chain:
        // every reachable node via `doc_next` from `first_node`, and
        // nothing else.
        let mut expected = HashMap::new();
        let mut cur = Some(app.first_node);
        let mut count = 0;
        while let Some(c) = cur {
            expected.insert(app.tree[c].span.text_range.start, c);
            count += 1;
            assert!(count <= app.tree.len(), "doc chain must not cycle");
            cur = app.tree[c].doc_next;
        }
        assert_eq!(app.line_to_node, expected);
    }

    /// Spec 0114 §5: `Enter` in the override pane applies the highlighted
    /// row (the pinned raw entry, or a ranked candidate) and closes the
    /// pane on success.
    #[test]
    fn enter_key_applies_override_and_closes_pane() {
        use prost::Message as _;
        use prost_types::field_descriptor_proto::{Label, Type};
        use prost_types::{
            DescriptorProto, FieldDescriptorProto, FileDescriptorProto, FileDescriptorSet,
        };

        use crate::decode::{decode, DescriptorContext};

        let inner_desc = DescriptorProto {
            name: Some("Inner".to_string()),
            field: vec![FieldDescriptorProto {
                name: Some("id".to_string()),
                number: Some(1),
                label: Some(Label::Optional as i32),
                r#type: Some(Type::Int32 as i32),
                ..Default::default()
            }],
            ..Default::default()
        };
        let outer_desc = DescriptorProto {
            name: Some("Outer".to_string()),
            field: vec![FieldDescriptorProto {
                name: Some("inner".to_string()),
                number: Some(1),
                label: Some(Label::Optional as i32),
                r#type: Some(Type::Message as i32),
                type_name: Some(".test.Inner".to_string()),
                ..Default::default()
            }],
            ..Default::default()
        };
        let file = FileDescriptorProto {
            name: Some("test_enter_override.proto".to_string()),
            package: Some("test".to_string()),
            message_type: vec![outer_desc, inner_desc],
            syntax: Some("proto3".to_string()),
            ..Default::default()
        };
        let fds = FileDescriptorSet { file: vec![file] };

        let descriptor_path =
            std::env::temp_dir().join("protolens-tui-enter-override-descriptor.pb");
        std::fs::write(&descriptor_path, fds.encode_to_vec()).unwrap();
        let mut ctx = DescriptorContext::load(&descriptor_path).unwrap();
        std::fs::remove_file(&descriptor_path).unwrap();

        // Outer { inner: Inner { id: 5 } }.
        let blob = [0x0Au8, 0x02, 0x08, 0x05];
        let decoded = decode(&blob, &mut ctx, Some("test.Outer"), 2).unwrap();
        let mut app = App::new(
            decoded,
            "test.pb",
            PathBuf::from("test.pb"),
            2,
            ctx,
            ThemeKind::Dark,
        );
        app.splash = false;
        app.term_width = 120;

        let inner_idx = app
            .tree
            .iter()
            .position(|n| n.span.type_fqdn.as_deref() == Some("test.Inner"))
            .expect("tree must contain the Inner submessage");
        app.cursor = inner_idx;

        // Row 0 (pinned raw entry): `Enter` clears the type and closes
        // the pane. `t`'s default Inferred sort mode leaves an unrelated
        // "no scoring graph" status message in this graph-less fixture —
        // clear it first so it can't be mistaken for an override error.
        app.handle_key(KeyEvent::new(KeyCode::Char('t'), KeyModifiers::NONE));
        assert!(app.override_target.is_some());
        app.message.clear();
        app.override_highlight = 0;
        app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert!(app.override_target.is_none(), "pane must close on success");
        assert_eq!(app.tree[inner_idx].span.type_fqdn, None);
        assert!(app.message.is_empty(), "no error expected: {}", app.message);
        // Spec 0119 G3: `Enter` lands in the management pane instead of
        // just closing outright.
        assert!(app.manage_open, "must open the management pane (G3)");
        app.handle_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
        assert!(!app.manage_open);

        // A ranked candidate row: re-open, switch to lexicographic sort
        // (no scoring graph in this fixture), and select the first
        // candidate.
        app.cursor = inner_idx;
        app.handle_key(KeyEvent::new(KeyCode::Char('t'), KeyModifiers::NONE));
        app.override_sort = SortMode::Lexicographic;
        app.recompute_override_candidates();
        assert!(!app.override_candidates.is_empty());
        app.override_highlight = 1;
        let chosen = app.override_candidates[0].0.clone();
        app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert!(app.override_target.is_none());
        assert_eq!(
            app.tree[inner_idx].span.type_fqdn.as_deref(),
            Some(chosen.as_str())
        );
    }

    /// Spec 0119 §G4: `f` in the management pane opens a rename buffer
    /// pre-filled from the highlighted entry's current name; `Enter`
    /// confirms, mutating the entry in place and — since the entry is
    /// active — triggering a re-render whose header line picks up the
    /// new name (the `(type, field_name)` re-splice gate).
    #[test]
    fn manage_pane_rename_updates_entry_and_rerenders_active_override() {
        let (mut app, inner_idx, _) = type_as_fixture();
        app.cursor = inner_idx;
        app.run_command("type-as test.Inner");
        assert_eq!(
            app.tree[inner_idx].span.type_fqdn.as_deref(),
            Some("test.Inner")
        );

        app.toggle_manage_pane();
        assert!(app.manage_open);
        let entry_idx = app
            .overrides
            .entries()
            .iter()
            .position(|e| e.active && e.r#type.as_deref() == Some("test.Inner"))
            .expect("type-as must have created an active entry for test.Inner");
        app.manage_highlight = entry_idx;

        app.handle_key(KeyEvent::new(KeyCode::Char('f'), KeyModifiers::NONE));
        assert!(app.manage_rename.is_some());
        for c in "custom_name".chars() {
            app.handle_key(KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE));
        }
        app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert!(app.manage_rename.is_none());
        assert_eq!(
            app.overrides.entries()[entry_idx].name.as_deref(),
            Some("custom_name")
        );

        let line_idx = app.tree[inner_idx].span.text_range.start;
        let header = &app.lines[line_idx];
        assert!(
            header.contains("custom_name"),
            "expected the renamed field name in the re-rendered header: {header}"
        );
    }

    /// Builds the same `Outer { inner: Inner { id: 5 } }` fixture as
    /// `enter_key_applies_override_and_closes_pane`, for the `:type-as`/
    /// `:type-as-raw` command tests (spec 0114 §7).
    fn type_as_fixture() -> (App, usize, usize) {
        use prost::Message as _;
        use prost_types::field_descriptor_proto::{Label, Type};
        use prost_types::{
            DescriptorProto, FieldDescriptorProto, FileDescriptorProto, FileDescriptorSet,
        };

        use crate::decode::{decode, DescriptorContext};

        let inner_desc = DescriptorProto {
            name: Some("Inner".to_string()),
            field: vec![FieldDescriptorProto {
                name: Some("id".to_string()),
                number: Some(1),
                label: Some(Label::Optional as i32),
                r#type: Some(Type::Int32 as i32),
                ..Default::default()
            }],
            ..Default::default()
        };
        let outer_desc = DescriptorProto {
            name: Some("Outer".to_string()),
            field: vec![FieldDescriptorProto {
                name: Some("inner".to_string()),
                number: Some(1),
                label: Some(Label::Optional as i32),
                r#type: Some(Type::Message as i32),
                type_name: Some(".test.Inner".to_string()),
                ..Default::default()
            }],
            ..Default::default()
        };
        let file = FileDescriptorProto {
            name: Some("test_type_as.proto".to_string()),
            package: Some("test".to_string()),
            message_type: vec![outer_desc, inner_desc],
            syntax: Some("proto3".to_string()),
            ..Default::default()
        };
        let fds = FileDescriptorSet { file: vec![file] };

        // Unique per call (this fixture is shared by several tests that
        // may run concurrently) to avoid one test's cleanup racing
        // another's read of the same path.
        static COUNTER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let descriptor_path =
            std::env::temp_dir().join(format!("protolens-tui-type-as-descriptor-{n}.pb"));
        std::fs::write(&descriptor_path, fds.encode_to_vec()).unwrap();
        let mut ctx = DescriptorContext::load(&descriptor_path).unwrap();
        std::fs::remove_file(&descriptor_path).unwrap();

        // Outer { inner: Inner { id: 5 } }.
        let blob = [0x0Au8, 0x02, 0x08, 0x05];
        let decoded = decode(&blob, &mut ctx, Some("test.Outer"), 2).unwrap();
        let mut app = App::new(
            decoded,
            "test.pb",
            PathBuf::from("test.pb"),
            2,
            ctx,
            ThemeKind::Dark,
        );
        app.splash = false;
        app.term_width = 120;

        let inner_idx = app
            .tree
            .iter()
            .position(|n| n.span.type_fqdn.as_deref() == Some("test.Inner"))
            .expect("tree must contain the Inner submessage");
        let id_idx = app.tree[inner_idx]
            .first_child
            .expect("Inner has at least one child");
        (app, inner_idx, id_idx)
    }

    /// Overriding a plain scalar (string) field into an incompatible
    /// message type must not panic — it should apply the override and
    /// surface the mismatch as ordinary `TYPE_MISMATCH`/`INVALID_*`
    /// annotations in the interior, exactly like any other malformed
    /// nested-message re-decode (feedback, 2026-07-16: `t` used to
    /// panic on `natural_annotation`'s `.expect()`).
    #[test]
    fn splice_override_on_an_incompatible_scalar_does_not_panic() {
        use crate::decode::{decode, DescriptorContext};
        use prost::Message as _;
        use prost_types::field_descriptor_proto::{Label, Type};
        use prost_types::{
            DescriptorProto, FieldDescriptorProto, FileDescriptorProto, FileDescriptorSet,
        };

        let str_msg = DescriptorProto {
            name: Some("StrHolder".to_string()),
            field: vec![FieldDescriptorProto {
                name: Some("s".to_string()),
                number: Some(1),
                label: Some(Label::Optional as i32),
                r#type: Some(Type::String as i32),
                ..Default::default()
            }],
            ..Default::default()
        };
        let target_msg = DescriptorProto {
            name: Some("Target".to_string()),
            field: vec![FieldDescriptorProto {
                name: Some("id".to_string()),
                number: Some(1),
                label: Some(Label::Optional as i32),
                r#type: Some(Type::Int32 as i32),
                ..Default::default()
            }],
            ..Default::default()
        };
        let file = FileDescriptorProto {
            name: Some("incompat.proto".to_string()),
            package: Some("incompat".to_string()),
            message_type: vec![str_msg, target_msg],
            syntax: Some("proto3".to_string()),
            ..Default::default()
        };
        let fds = FileDescriptorSet { file: vec![file] };
        static COUNTER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let descriptor_path =
            std::env::temp_dir().join(format!("protolens-tui-incompat-override-{n}.pb"));
        std::fs::write(&descriptor_path, fds.encode_to_vec()).unwrap();
        let mut ctx = DescriptorContext::load(&descriptor_path).unwrap();
        std::fs::remove_file(&descriptor_path).unwrap();

        // StrHolder { s: "hello" }
        let label = b"hello";
        let mut blob = vec![0x0Au8, label.len() as u8];
        blob.extend_from_slice(label);
        let decoded = decode(&blob, &mut ctx, Some("incompat.StrHolder"), 2).unwrap();
        let mut app = App::new(
            decoded,
            "test.pb",
            PathBuf::from("test.pb"),
            2,
            ctx,
            ThemeKind::Dark,
        );
        app.splash = false;
        app.term_width = 120;

        let s_idx = app
            .tree
            .iter()
            .position(|n| n.span.field_number == 1)
            .expect("must find field 1");
        assert!(
            app.can_override(s_idx),
            "a WT_LEN scalar must be overridable"
        );

        app.splice_override(s_idx, Some("incompat.Target".to_string()))
            .expect("override onto an incompatible type must still succeed");
        assert!(
            app.lines
                .iter()
                .any(|l| l.contains("INVALID") || l.contains("TYPE_MISMATCH")),
            "mismatch must surface as an inline annotation, not a panic: {:?}",
            app.lines
        );
    }

    /// `Outer2 { grp: MyGroup { id: 5 } }`, with `grp` declared as a
    /// genuine schema wire-group field (`Type::Group`) — unlike
    /// `message_set_fixture`'s auto-expanded MessageSet group items,
    /// this is directly schema-resolved from the start. Also registers
    /// a same-shaped sibling type `NewGroup` to override `grp` into
    /// (spec 0122 Test Plan item 2).
    fn group_type_fixture() -> (App, usize) {
        // START_GROUP(5), id=5, END_GROUP(5) — minimal tag encoding.
        group_type_fixture_with_blob(&[0x2Bu8, 0x08, 0x05, 0x2Cu8])
    }

    /// Same schema as `group_type_fixture`, but with `grp`'s `START_GROUP`
    /// tag encoded with one overhang byte (non-minimal varint: `0xAB, 0x00`
    /// instead of the minimal `0x2B`) — exercises the `tag_ohb: 1` anomaly
    /// modifier (spec 0122 Test Plan item 2, 3rd bullet).
    fn group_type_fixture_with_tag_ohb() -> (App, usize) {
        group_type_fixture_with_blob(&[0xABu8, 0x00, 0x08, 0x05, 0x2Cu8])
    }

    fn group_type_fixture_with_blob(blob: &[u8]) -> (App, usize) {
        use prost::Message as _;
        use prost_types::field_descriptor_proto::{Label, Type};
        use prost_types::{
            DescriptorProto, FieldDescriptorProto, FileDescriptorProto, FileDescriptorSet,
        };

        use crate::decode::{decode, DescriptorContext};

        let my_group_desc = DescriptorProto {
            name: Some("MyGroup".to_string()),
            field: vec![FieldDescriptorProto {
                name: Some("id".to_string()),
                number: Some(1),
                label: Some(Label::Optional as i32),
                r#type: Some(Type::Int32 as i32),
                ..Default::default()
            }],
            ..Default::default()
        };
        let new_group_desc = DescriptorProto {
            name: Some("NewGroup".to_string()),
            field: vec![FieldDescriptorProto {
                name: Some("value".to_string()),
                number: Some(1),
                label: Some(Label::Optional as i32),
                r#type: Some(Type::Int32 as i32),
                ..Default::default()
            }],
            ..Default::default()
        };
        let outer_desc = DescriptorProto {
            name: Some("Outer2".to_string()),
            field: vec![FieldDescriptorProto {
                name: Some("grp".to_string()),
                number: Some(5),
                label: Some(Label::Optional as i32),
                r#type: Some(Type::Group as i32),
                type_name: Some(".test.MyGroup".to_string()),
                ..Default::default()
            }],
            ..Default::default()
        };
        let file = FileDescriptorProto {
            name: Some("test_group_type.proto".to_string()),
            package: Some("test".to_string()),
            syntax: Some("proto2".to_string()),
            message_type: vec![outer_desc, my_group_desc, new_group_desc],
            ..Default::default()
        };
        let fds = FileDescriptorSet { file: vec![file] };

        // Unique per call (this fixture is shared by several tests that
        // may run concurrently) to avoid one test's cleanup racing
        // another's read of the same path.
        static COUNTER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let descriptor_path =
            std::env::temp_dir().join(format!("protolens-tui-group-type-descriptor-{n}.pb"));
        std::fs::write(&descriptor_path, fds.encode_to_vec()).unwrap();
        let mut ctx = DescriptorContext::load(&descriptor_path).unwrap();
        std::fs::remove_file(&descriptor_path).unwrap();

        let decoded = decode(blob, &mut ctx, Some("test.Outer2"), 2).unwrap();
        let mut app = App::new(
            decoded,
            "test.pb",
            PathBuf::from("test.pb"),
            2,
            ctx,
            ThemeKind::Dark,
        );
        app.splash = false;
        app.term_width = 120;

        let grp_idx = app
            .tree
            .iter()
            .position(|n| n.span.type_fqdn.as_deref() == Some("test.MyGroup"))
            .expect("tree must contain the MyGroup submessage");
        (app, grp_idx)
    }

    /// Overriding a group field to a resolvable type must keep the
    /// `group;` prefix in the header (spec 0122 Test Plan item 2, 1st
    /// bullet).
    #[test]
    fn splice_override_on_a_group_field_keeps_the_group_prefix() {
        let (mut app, grp_idx) = group_type_fixture();
        app.splice_override(grp_idx, Some("test.NewGroup".to_string()))
            .unwrap();
        let header = &app.lines[app.tree[grp_idx].span.text_range.start];
        assert!(
            header.contains("#@ group; NewGroup = 5"),
            "expected group; NewGroup = 5 in header, got: {header:?}"
        );
    }

    /// The header-line patch (spec 0122 §2) usually changes the header's
    /// byte length (e.g. bare `#@ group` growing into `#@ group; NewGroup
    /// = 5`) — `line_styles`' per-line color buckets must stay aligned
    /// with `self.lines`' actual text for every line *after* the header,
    /// not just the header itself (2026-07-15 regression: colors drifted
    /// starting right after the first patched `#@ group;` header,
    /// because `hints_by_line` was bucketing hints computed against the
    /// *cached* (unpatched) header length using the *patched* line
    /// array's lengths).
    #[test]
    fn splice_override_keeps_colors_aligned_after_a_header_length_change() {
        let (mut app, grp_idx) = group_type_fixture();
        app.splice_override(grp_idx, Some("test.NewGroup".to_string()))
            .unwrap();
        let value_idx = app.tree[grp_idx]
            .first_child
            .expect("NewGroup has at least one child");
        let line_idx = app.tree[value_idx].span.text_range.start;
        let line = &app.lines[line_idx];
        let value_pos = line
            .find('5')
            .expect("value line must contain the scalar 5");
        assert!(
            app.line_styles[line_idx]
                .iter()
                .any(|(range, role)| *role == SyntaxRole::Number && range.contains(&value_pos)),
            "expected a Number-colored span covering the '5' in {line:?}, got {:?}",
            app.line_styles[line_idx]
        );
    }

    /// A group field carrying a `tag_ohb` anomaly modifier keeps that
    /// modifier verbatim after being overridden to a different type (spec
    /// 0122 Test Plan item 2, 3rd bullet).
    #[test]
    fn splice_override_on_a_group_field_keeps_the_tag_ohb_modifier() {
        let (mut app, grp_idx) = group_type_fixture_with_tag_ohb();
        let header_before = app.lines[app.tree[grp_idx].span.text_range.start].clone();
        assert!(
            header_before.contains("tag_ohb: 1"),
            "fixture must exercise the anomaly modifier, got: {header_before:?}"
        );
        app.splice_override(grp_idx, Some("test.NewGroup".to_string()))
            .unwrap();
        let header = &app.lines[app.tree[grp_idx].span.text_range.start];
        assert!(
            header.contains("#@ group; NewGroup = 5; tag_ohb: 1"),
            "expected group; NewGroup = 5; tag_ohb: 1 in header, got: {header:?}"
        );
    }

    /// Overriding a `WT_LEN` (non-group) field to a resolvable type must
    /// NOT show a `group;` prefix (spec 0122 Test Plan item 2, 2nd
    /// bullet).
    #[test]
    fn splice_override_on_a_wt_len_field_has_no_group_prefix() {
        let (mut app, inner_idx, _) = type_as_fixture();
        app.splice_override(inner_idx, Some("test.Outer".to_string()))
            .unwrap();
        let header = &app.lines[app.tree[inner_idx].span.text_range.start];
        assert!(
            header.contains("#@ Outer = 1"),
            "expected Outer = 1 in header, got: {header:?}"
        );
        assert!(
            !header.contains("group;"),
            "WT_LEN field override must not show group;: {header:?}"
        );
    }

    /// A nested (non-root) field's header line must keep its leading
    /// indentation after `splice_override` — the spec 0122 header-patching
    /// rewrite of `new_lines[0]` must not drop the indentation the
    /// synthetic wrapper's own render already computed via
    /// `initial_level` (2026-07-15 regression: header lines of overridden
    /// nested nodes lost their indentation while sibling/interior lines
    /// stayed correctly indented).
    #[test]
    fn splice_override_preserves_the_header_line_indentation() {
        let (mut app, inner_idx, _) = type_as_fixture();
        let start = app.tree[inner_idx].span.text_range.start;
        let indent_before = app.lines[start].len() - app.lines[start].trim_start().len();
        app.splice_override(inner_idx, Some("test.Outer".to_string()))
            .unwrap();
        let header = &app.lines[app.tree[inner_idx].span.text_range.start];
        let indent_after = header.len() - header.trim_start().len();
        assert!(
            indent_after > 0,
            "fixture must exercise a nested (indented) field"
        );
        assert_eq!(
            indent_after, indent_before,
            "header line lost its indentation after splice_override: {header:?}"
        );
    }

    /// Reverting a group field's override (`target: None`) must restore
    /// bare `#@ group` — the synthetic wrapper's `"message"` placeholder
    /// must not leak into the header (spec 0122 Test Plan item 2, 4th
    /// bullet; user-approved fix, 2026-07-15).
    #[test]
    fn splice_override_reverting_a_group_field_restores_bare_group() {
        let (mut app, grp_idx) = group_type_fixture();
        app.splice_override(grp_idx, Some("test.NewGroup".to_string()))
            .unwrap();
        app.splice_override(grp_idx, None).unwrap();
        let header = &app.lines[app.tree[grp_idx].span.text_range.start];
        assert!(
            header.contains("#@ group"),
            "expected bare group in header, got: {header:?}"
        );
        assert!(
            !header.contains("message"),
            "reverted group header must not leak the synthetic \"message\" placeholder: {header:?}"
        );
    }

    /// The document root is field number 1 of the virtual encompassing
    /// message — a `splice_override`-driven re-render of the root (any
    /// retype, not just the initial `decode()` paint) must keep showing
    /// its field number in the header line, same as
    /// `decode_shows_the_root_field_number_in_the_header_line`
    /// (`decode.rs`) covers for the initial paint.
    #[test]
    fn splice_override_shows_the_root_field_number_in_the_header_line() {
        let (mut app, _, _) = type_as_fixture();
        app.splice_override(app.first_node, Some("test.Outer".to_string()))
            .unwrap();
        assert!(
            app.lines[0].starts_with("1 "),
            "root header line must show the root field number: {:?}",
            app.lines[0]
        );
    }

    /// Retyping the document root *raw* (no schema, `target: None`) must
    /// also keep showing its field number in the header line — the root
    /// is not special-cased regardless of `target`.
    #[test]
    fn splice_override_raw_root_shows_the_field_number_in_the_header_line() {
        let (mut app, _, _) = type_as_fixture();
        app.splice_override(app.first_node, None).unwrap();
        assert!(
            app.lines[0].starts_with("1 "),
            "raw root header line must show the field number: {:?}",
            app.lines[0]
        );
    }

    /// Reproduces interactive-testing feedback (2026-07-14, post-D34): a
    /// root node retyped raw (`None`) then retyped back to a real schema
    /// must still expand its `Any` descendants — a bare re-splice of the
    /// root shouldn't lose `Any` expansion the *initial* `render_overrides`
    /// pass (spec 0120) got right. Fixture mirrors `decode.rs`'s own
    /// `decode_leaves_any_fields_unexpanded_with_real_type_url_and_value_spans`.
    #[test]
    fn splice_override_reactivating_root_type_still_expands_any_fields() {
        use prost::Message as _;
        use prost_types::field_descriptor_proto::{Label, Type};
        use prost_types::{
            DescriptorProto, FieldDescriptorProto, FileDescriptorProto, FileDescriptorSet,
        };

        use crate::decode::{decode, DescriptorContext};

        let any_msg = DescriptorProto {
            name: Some("Any".to_string()),
            field: vec![
                FieldDescriptorProto {
                    name: Some("type_url".to_string()),
                    number: Some(1),
                    label: Some(Label::Optional as i32),
                    r#type: Some(Type::String as i32),
                    ..Default::default()
                },
                FieldDescriptorProto {
                    name: Some("value".to_string()),
                    number: Some(2),
                    label: Some(Label::Optional as i32),
                    r#type: Some(Type::Bytes as i32),
                    ..Default::default()
                },
            ],
            ..Default::default()
        };
        let any_file = FileDescriptorProto {
            name: Some("google/protobuf/any.proto".to_string()),
            syntax: Some("proto3".to_string()),
            package: Some("google.protobuf".to_string()),
            message_type: vec![any_msg],
            ..Default::default()
        };

        let payload_msg = DescriptorProto {
            name: Some("Payload".to_string()),
            field: vec![FieldDescriptorProto {
                name: Some("label".to_string()),
                number: Some(1),
                label: Some(Label::Optional as i32),
                r#type: Some(Type::String as i32),
                ..Default::default()
            }],
            ..Default::default()
        };
        let container_msg = DescriptorProto {
            name: Some("Container".to_string()),
            field: vec![FieldDescriptorProto {
                name: Some("payload".to_string()),
                number: Some(1),
                label: Some(Label::Optional as i32),
                r#type: Some(Type::Message as i32),
                type_name: Some(".google.protobuf.Any".to_string()),
                ..Default::default()
            }],
            ..Default::default()
        };
        let acme_file = FileDescriptorProto {
            name: Some("acme.proto".to_string()),
            syntax: Some("proto2".to_string()),
            package: Some("acme".to_string()),
            dependency: vec!["google/protobuf/any.proto".to_string()],
            message_type: vec![payload_msg, container_msg],
            ..Default::default()
        };
        let fds = FileDescriptorSet {
            file: vec![any_file, acme_file],
        };

        let descriptor_path =
            std::env::temp_dir().join("protolens-tui-splice-any-reactivate-descriptor.pb");
        std::fs::write(&descriptor_path, fds.encode_to_vec()).unwrap();
        let mut ctx = DescriptorContext::load(&descriptor_path).unwrap();
        std::fs::remove_file(&descriptor_path).unwrap();

        // Container { payload: Any { type_url:
        // "type.googleapis.com/acme.Payload", value: Payload { label:
        // "hello" } } }.
        let label = b"hello";
        let mut payload_bytes = vec![0x0au8, label.len() as u8];
        payload_bytes.extend_from_slice(label);
        let type_url = b"type.googleapis.com/acme.Payload";
        let mut any_bytes = vec![0x0au8, type_url.len() as u8];
        any_bytes.extend_from_slice(type_url);
        any_bytes.push(0x12);
        any_bytes.push(payload_bytes.len() as u8);
        any_bytes.extend_from_slice(&payload_bytes);
        let mut blob = vec![0x0au8, any_bytes.len() as u8];
        blob.extend_from_slice(&any_bytes);

        let decoded = decode(&blob, &mut ctx, Some("acme.Container"), 2).unwrap();
        let mut app = App::new(
            decoded,
            "test.pb",
            PathBuf::from("test.pb"),
            2,
            ctx,
            ThemeKind::Dark,
        );
        app.splash = false;
        app.term_width = 120;

        // 1) retype the root raw (no schema) — mirrors the interactive
        //    "override / with raw/no-type" step, driven through the same
        //    `overrides.activate` + `render_overrides` path the `Enter`
        //    key handler uses in the override pane (not a bare
        //    `splice_override` call, which bypasses the recursive pass
        //    entirely and would miss this bug).
        let root_origin = override_pane::OverrideOrigin::Path {
            path: "/".to_string(),
        };
        app.overrides.activate(root_origin.clone(), None);
        app.render_overrides(app.first_node);
        // 2) retype the root back to the real schema — mirrors
        //    reactivating `acme.Container` in the management pane.
        app.overrides
            .activate(root_origin, Some("acme.Container".to_string()));
        app.render_overrides(app.first_node);

        assert!(
            app.tree
                .iter()
                .any(|n| n.span.type_fqdn.as_deref() == Some("acme.Payload")),
            "Any field must still expand after retyping the root away and \
             back: {:#?}",
            app.lines
        );
        assert!(
            app.lines
                .iter()
                .any(|l| l.contains("label") && l.contains("hello")),
            "expanded Any payload's own field must appear in the \
             re-spliced text: {:?}",
            app.lines
        );
    }

    /// Builds the shared `Container { extensions: TestMessageSet { Item {
    /// type_id: 100, message: ExtPayload { label: "hi" } } } }` fixture
    /// used by both the auto-expansion test and the toggle/reactivate
    /// regression test below.
    fn message_set_fixture() -> App {
        use prost::Message as _;
        use prost_types::descriptor_proto::ExtensionRange;
        use prost_types::field_descriptor_proto::{Label, Type};
        use prost_types::{
            DescriptorProto, FieldDescriptorProto, FileDescriptorProto, FileDescriptorSet,
            MessageOptions,
        };

        use crate::decode::{decode, DescriptorContext};

        let message_set_msg = DescriptorProto {
            name: Some("TestMessageSet".to_string()),
            options: Some(MessageOptions {
                message_set_wire_format: Some(true),
                ..Default::default()
            }),
            extension_range: vec![ExtensionRange {
                start: Some(1),
                end: Some(536870912),
                ..Default::default()
            }],
            ..Default::default()
        };
        let ext_payload_msg = DescriptorProto {
            name: Some("ExtPayload".to_string()),
            field: vec![FieldDescriptorProto {
                name: Some("label".to_string()),
                number: Some(1),
                label: Some(Label::Optional as i32),
                r#type: Some(Type::String as i32),
                ..Default::default()
            }],
            ..Default::default()
        };
        let extension_field = FieldDescriptorProto {
            name: Some("ext_payload".to_string()),
            number: Some(100),
            label: Some(Label::Optional as i32),
            r#type: Some(Type::Message as i32),
            type_name: Some(".ms_test.ExtPayload".to_string()),
            extendee: Some(".ms_test.TestMessageSet".to_string()),
            ..Default::default()
        };
        let container_msg = DescriptorProto {
            name: Some("Container".to_string()),
            field: vec![FieldDescriptorProto {
                name: Some("extensions".to_string()),
                number: Some(2),
                label: Some(Label::Optional as i32),
                r#type: Some(Type::Message as i32),
                type_name: Some(".ms_test.TestMessageSet".to_string()),
                ..Default::default()
            }],
            ..Default::default()
        };
        let file = FileDescriptorProto {
            name: Some("ms_test.proto".to_string()),
            syntax: Some("proto2".to_string()),
            package: Some("ms_test".to_string()),
            message_type: vec![message_set_msg, ext_payload_msg, container_msg],
            extension: vec![extension_field],
            ..Default::default()
        };
        let fds = FileDescriptorSet { file: vec![file] };

        // Unique per call (this fixture is shared by several tests that
        // may run concurrently) to avoid one test's cleanup racing
        // another's read of the same path.
        static COUNTER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let descriptor_path = std::env::temp_dir().join(format!(
            "protolens-tui-message-set-expand-descriptor-{n}.pb"
        ));
        std::fs::write(&descriptor_path, fds.encode_to_vec()).unwrap();
        let mut ctx = DescriptorContext::load(&descriptor_path).unwrap();
        std::fs::remove_file(&descriptor_path).unwrap();

        // Container { extensions: TestMessageSet {
        //   Item { type_id: 100, message: ExtPayload { label: "hi" } }
        // } }.
        let ext_payload_bytes = [0x0au8, 0x02, b'h', b'i'];
        let mut item_bytes = vec![0x0bu8, 0x10, 100u8];
        item_bytes.push(0x1a);
        item_bytes.push(ext_payload_bytes.len() as u8);
        item_bytes.extend_from_slice(&ext_payload_bytes);
        item_bytes.push(0x0c); // END_GROUP
        let mut blob = vec![0x12u8, item_bytes.len() as u8];
        blob.extend_from_slice(&item_bytes);

        let decoded = decode(&blob, &mut ctx, Some("ms_test.Container"), 2).unwrap();
        let mut app = App::new(
            decoded,
            "test.pb",
            PathBuf::from("test.pb"),
            2,
            ctx,
            ThemeKind::Dark,
        );
        app.splash = false;
        app.term_width = 120;
        app
    }

    /// Regression test (spec 0120 §G2, post-bugfix): a MessageSet's
    /// group-wire "Item" entries (field 1, `WT_START_GROUP`) must be
    /// decomposed via the two-tier auto-expansion (tier 1: synthetic
    /// `protolens_internal.MessageSetItem`; tier 2: the specific
    /// extension type resolved from `type_id`) through `render_overrides`
    /// — not corrupted into a flat raw scalar, which is what happened
    /// before the fix (`render_overrides`'s `is_message` recursion gate
    /// unconditionally spliced the group node with no matching tier,
    /// poisoning the render via `extract::message_payload_range`'s
    /// documented "leaves the trailing END_GROUP tag" behavior for
    /// `WT_START_GROUP`). Also asserts both tiers land as real,
    /// persisted, active `OverrideEntry` rows (spec 0120 redesign: no
    /// longer a silent dynamic fallback).
    #[test]
    fn message_set_group_items_auto_expand_through_render_overrides() {
        let app = message_set_fixture();

        assert!(
            app.tree
                .iter()
                .any(|n| n.span.type_fqdn.as_deref() == Some("ms_test.ExtPayload")),
            "MessageSet Item's message must auto-expand to the resolved \
             extension type: {:#?}",
            app.lines
        );
        assert!(
            app.lines
                .iter()
                .any(|l| l.contains("label") && l.contains("hi")),
            "expanded MessageSet extension payload's own field must appear \
             in the spliced text: {:?}",
            app.lines
        );

        let item_idx = app
            .tree
            .iter()
            .position(|n| n.span.type_fqdn.as_deref() == Some(decode::MESSAGE_SET_ITEM_FQDN))
            .expect("Item group must be spliced to the synthetic MessageSetItem type");
        let item_path = app.positional_path(item_idx);
        assert!(
            app.overrides.entries().iter().any(|e| {
                e.active
                    && matches!(&e.origin, OverrideOrigin::Path { path } if *path == item_path)
                    && e.r#type.as_deref() == Some(decode::MESSAGE_SET_ITEM_FQDN)
            }),
            "tier-1 auto-expansion must be a real, persisted, active \
             override entry: {:#?}",
            app.overrides.entries()
        );
        assert!(
            app.overrides.entries().iter().any(|e| {
                matches!(&e.origin, OverrideOrigin::Path { path } if *path == item_path)
                    && e.name.as_deref() == Some("Item")
            }),
            "tier-1 auto-expansion must be seeded with the display name \
             \"Item\" (mirroring prototext-core's native MessageSet \
             rendering), not the bare field number: {:#?}",
            app.overrides.entries()
        );
        assert!(
            app.lines
                .iter()
                .any(|l| l.trim_start().starts_with("Item {")),
            "the Item wrapper must render under the name \"Item\", not \
             its field number: {:?}",
            app.lines
        );

        let message_idx = app
            .tree
            .iter()
            .position(|n| n.span.type_fqdn.as_deref() == Some("ms_test.ExtPayload"))
            .expect("message field must resolve to ExtPayload");
        let message_path = app.positional_path(message_idx);
        assert!(
            app.overrides.entries().iter().any(|e| {
                e.active
                    && matches!(&e.origin, OverrideOrigin::Path { path } if *path == message_path)
                    && e.r#type.as_deref() == Some("ms_test.ExtPayload")
            }),
            "tier-2 auto-expansion must be a real, persisted, active \
             override entry: {:#?}",
            app.overrides.entries()
        );
    }

    /// Regression test (spec 0132 §G3 feedback, 2026-07-15): opening the
    /// override pane on an ancestor of a MessageSet's `Item` group live-
    /// previews that ancestor's subtree via a bare `splice_override`
    /// call (§G2 non-goal: "no live nested Any/MessageSet preview"),
    /// which discards the tier-1/tier-2 auto-expansion of every
    /// descendant. Cancelling with `Esc` must fully restore it — not
    /// just re-settle the ancestor node itself back to its own correct
    /// type, but re-run the whole `render_overrides` recursion so
    /// `ExtPayload` gets re-expanded too.
    #[test]
    fn esc_closing_the_override_pane_restores_nested_message_set_auto_expansion() {
        let mut app = message_set_fixture();
        let extensions_idx = app
            .tree
            .iter()
            .position(|n| n.span.type_fqdn.as_deref() == Some("ms_test.TestMessageSet"))
            .expect("extensions field must resolve to TestMessageSet");
        app.cursor = extensions_idx;

        app.handle_key(KeyEvent::new(KeyCode::Char('t'), KeyModifiers::NONE));
        assert_eq!(app.override_target, Some(extensions_idx));
        // The live preview's own `splice_override` call rebuilds the
        // subtree from scratch with no per-descendant overrides applied
        // (§G2 non-goal) — the rendered text must no longer show the
        // nested expansion for the duration of the pane being open.
        // (`splice_override` never removes orphaned descendant entries
        // from the flat `tree` Vec, only unlinks them — so `app.tree`
        // itself is not a reliable signal here; `app.lines`, what's
        // actually displayed, is.)
        assert!(
            !app.lines.iter().any(|l| l.contains("label")),
            "live preview must not still show the nested auto-expansion: {:?}",
            app.lines
        );

        app.handle_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
        assert_eq!(app.override_target, None);
        assert!(
            app.tree
                .iter()
                .any(|n| n.span.type_fqdn.as_deref() == Some("ms_test.ExtPayload")),
            "Esc-cancel must restore the nested MessageSet auto-expansion: {:#?}",
            app.lines
        );
        assert!(
            app.lines
                .iter()
                .any(|l| l.contains("label") && l.contains("hi")),
            "expanded MessageSet extension payload's own field must be back \
             in the rendered text: {:?}",
            app.lines
        );
    }

    /// Regression test for a bug found while implementing spec 0123's
    /// test plan: `load_overrides` (`:restore-overrides`/batch
    /// `--load-overrides`) wholesale-replaces `self.overrides` (spec
    /// 0117 §4), which used to silently drop the document root's own
    /// `seed_root` entry whenever the loaded file didn't carry one
    /// itself (the normal case — nobody manually saves a `path: "/"`
    /// override). Root's type is external input (CLI `--type`/auto-
    /// inference) with no schema-derived fallback (`natural_type` has no
    /// parent field descriptor to consult for the root), so losing it
    /// reverted root to raw rendering — which cascaded: every ordinary,
    /// never-explicitly-overridden descendant's own `natural_type` walks
    /// up through its parent's *resolved* type to find its field's
    /// schema type, so the whole document (not just root) went raw, and
    /// spec 0120's tier-2 MessageSet auto-expansion candidacy gate
    /// (which needs its un-overridden grandparent to still resolve as
    /// MessageSet-typed) silently stopped firing even when its own
    /// override entry was present, correct, and active. Fixed by
    /// preserving the currently-resolved root type across the replace
    /// when the loaded file doesn't define its own.
    #[test]
    fn load_overrides_without_a_root_entry_preserves_the_current_root_type() {
        let mut app = message_set_fixture();
        let (blob_sha256, descriptor_set_sha256) = app.target_hashes();

        // Deliberately omits any `path: "/"` entry — exactly the shape a
        // real `:save-overrides` produces is *not* what's being tested
        // here (that's covered by `save_and_restore_overrides_round_trips
        // _and_drops_unresolvable_entries`); this reproduces a
        // hand-authored/edited file, or any file saved before root ever
        // carried a resolved type.
        let yaml = format!(
            "version: 1\n\
             target:\n\
             \x20 blob_sha256: \"{blob_sha256}\"\n\
             \x20 descriptor_set_sha256: \"{descriptor_set_sha256}\"\n\
             overrides:\n\
             \x20 - path: \"/1/1\"\n\
             \x20   type: protolens_internal.MessageSetItem\n\
             \x20   active: true\n\
             \x20   name: Item\n\
             \x20 - path: \"/1/1/2\"\n\
             \x20   type: ms_test.ExtPayload\n\
             \x20   active: true\n"
        );
        static COUNTER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path = std::env::temp_dir()
            .join(format!("protolens-tui-load-overrides-no-root-{n}.yaml"))
            .to_string_lossy()
            .into_owned();
        std::fs::write(&path, &yaml).unwrap();
        let warnings = app.load_overrides(&path).unwrap();
        std::fs::remove_file(&path).unwrap();

        assert!(warnings.is_empty(), "{warnings:?}");
        assert!(
            app.tree[app.first_node].span.type_fqdn.as_deref() == Some("ms_test.Container"),
            "root must keep its resolved type across a wholesale \
             override-collection replace, even though the loaded file \
             defines no root entry of its own: {:#?}",
            app.lines
        );
        assert!(
            app.lines
                .iter()
                .any(|l| l.contains("label") && l.contains("hi")),
            "tier-2 MessageSet auto-expansion must still take effect \
             after --load-overrides, not just tier-1: {:#?}",
            app.lines
        );
    }

    /// Round-trip regression test (spec 0122 Test Plan item 3 — the
    /// original reported bug's exact scenario): decode a MessageSet
    /// fixture, let `App::new`'s automatic Any/MessageSet overrides
    /// (spec 0120) apply, extract the root as `#@ prototext` text (spec
    /// 0123's batch-mode rendering), `encode_text_to_binary` it back to
    /// binary, and assert byte-for-byte equality with the original blob.
    /// Before spec 0122's fix, `splice_override`'s synthetic `WT_LEN`-only
    /// re-decode dropped the MessageSet `Item` group's `#@ group`
    /// annotation, so re-encoding lost the group's wire framing entirely.
    #[test]
    fn round_trip_extract_and_encode_preserves_message_set_group_framing() {
        let app = message_set_fixture();
        let root_idx = app.resolve_path("/").expect("tree must have a root");
        let text = app.extract_bytes(root_idx, ExtractFormat::Text);
        let reencoded = prototext_core::serialize::encode_text::encode_text_to_binary(&text);
        let original = &app.blob[app.wrapper_offset..];
        assert_eq!(
            reencoded, original,
            "round-trip through extract+encode must byte-for-byte match \
             the original blob"
        );
    }

    /// Regression test for the manage-pane toggle/reactivate bug reported
    /// against spec 0120's auto-expansion seeding: deactivating a
    /// MessageSet tier-1 (`MessageSetItem`) auto-derived override via
    /// `toggle_active` (the manage pane's `a`/Space key) must actually
    /// stick across a `render_overrides` pass — not be silently
    /// resurrected, which is what happened when the seeding condition in
    /// `render_overrides` only checked "no active override currently
    /// resolves" rather than "no entry exists yet for this origin at
    /// all". Also asserts that reactivating it re-splices the Item's
    /// payload back to the expanded `ExtPayload` form.
    #[test]
    fn toggling_message_set_auto_override_off_and_on_sticks() {
        let mut app = message_set_fixture();

        let item_idx = app
            .tree
            .iter()
            .position(|n| n.span.type_fqdn.as_deref() == Some(decode::MESSAGE_SET_ITEM_FQDN))
            .expect("Item group must be spliced to the synthetic MessageSetItem type");
        let item_path = app.positional_path(item_idx);
        let entry_idx = app
            .overrides
            .entries()
            .iter()
            .position(|e| matches!(&e.origin, OverrideOrigin::Path { path } if *path == item_path))
            .expect("tier-1 entry must exist");

        // Deactivate, then re-render: the entry must stay inactive (not
        // be re-seeded), and the Item node must revert to its natural
        // (un-overridden) type.
        app.overrides.toggle_active(entry_idx);
        app.render_overrides(app.first_node);
        assert!(
            !app.overrides.entries()[entry_idx].active,
            "deactivating the tier-1 override must stick across a render \
             pass, not self-heal back to active: {:#?}",
            app.overrides.entries()
        );
        assert_eq!(
            app.tree[item_idx].span.type_fqdn.as_deref(),
            None,
            "Item node must render raw/natural once its override is \
             deactivated: {:#?}",
            app.lines
        );

        // Reactivate: the same entry (same index — `toggle_active` never
        // resorts) must come back active, and the Item's payload must
        // re-expand to ExtPayload.
        app.overrides.toggle_active(entry_idx);
        app.render_overrides(app.first_node);
        assert!(
            app.overrides.entries()[entry_idx].active,
            "reactivating the tier-1 override must stick: {:#?}",
            app.overrides.entries()
        );
        assert_eq!(
            app.tree[item_idx].span.type_fqdn.as_deref(),
            Some(decode::MESSAGE_SET_ITEM_FQDN),
            "Item node must re-expand once its override is reactivated: \
             {:#?}",
            app.lines
        );
        assert!(
            app.tree
                .iter()
                .any(|n| n.span.type_fqdn.as_deref() == Some("ms_test.ExtPayload")),
            "tier-2 auto-expansion must also come back after reactivating \
             tier-1: {:#?}",
            app.lines
        );
    }

    /// Regression test (2026-07-14 interactive feedback): deactivating a
    /// MessageSet's tier-1 (`Item`) auto-derived override must also stop
    /// honoring its tier-2 (`message`) auto-derived override, even though
    /// the tier-2 entry itself is never touched — its derivation
    /// (looking up the extension type from `type_id`) is only valid
    /// while its parent still resolves as `MessageSetItem`, so it must
    /// demote alongside its ancestor rather than keep rendering the stale
    /// extension type. Previously, only deactivating an *outer* ancestor
    /// override (e.g. an enclosing `Any`) cleared it — deactivating the
    /// immediate tier-1 `Item` alone was not enough.
    #[test]
    fn deactivating_tier_1_demotes_the_still_active_tier_2_entry() {
        let mut app = message_set_fixture();

        let item_idx = app
            .tree
            .iter()
            .position(|n| n.span.type_fqdn.as_deref() == Some(decode::MESSAGE_SET_ITEM_FQDN))
            .expect("Item group must be spliced to the synthetic MessageSetItem type");
        let item_path = app.positional_path(item_idx);
        let item_entry_idx = app
            .overrides
            .entries()
            .iter()
            .position(|e| matches!(&e.origin, OverrideOrigin::Path { path } if *path == item_path))
            .expect("tier-1 entry must exist");
        let message_idx = app
            .tree
            .iter()
            .position(|n| n.span.type_fqdn.as_deref() == Some("ms_test.ExtPayload"))
            .expect("message field must resolve to ExtPayload");
        let message_path = app.positional_path(message_idx);
        let message_entry_idx = app
            .overrides
            .entries()
            .iter()
            .position(
                |e| matches!(&e.origin, OverrideOrigin::Path { path } if *path == message_path),
            )
            .expect("tier-2 entry must exist");

        // Deactivate tier-1 only — tier-2's own entry is left untouched.
        app.overrides.toggle_active(item_entry_idx);
        app.render_overrides(app.first_node);

        assert!(
            app.overrides.entries()[message_entry_idx].active,
            "tier-2's own entry must remain active (untouched by \
             deactivating tier-1) — demotion must not mutate `active`: \
             {:#?}",
            app.overrides.entries()
        );
        // `app.tree` retains splice-abandoned/orphaned entries (never
        // referenced again but never removed from the `Vec` either — see
        // `splice_override`'s "abandon in place" pattern), so checking
        // for absence must go through the *rendered* text (`app.lines`),
        // which only ever reflects the current, live splice — not
        // `app.tree.iter()`, which could still find the old, no-longer-
        // reachable `ExtPayload` node from before this deactivation.
        assert!(
            !app.lines.iter().any(|l| l.contains("ExtPayload")),
            "tier-2's stale extension-type annotation must disappear \
             once its governing tier-1 ancestor is deactivated: {:?}",
            app.lines
        );

        // Reactivating tier-1 must bring tier-2 back without touching
        // tier-2's own entry.
        app.overrides.toggle_active(item_entry_idx);
        app.render_overrides(app.first_node);
        assert!(
            app.tree
                .iter()
                .any(|n| n.span.type_fqdn.as_deref() == Some("ms_test.ExtPayload")),
            "tier-2 must resume once its tier-1 ancestor is reactivated: \
             {:?}",
            app.lines
        );
    }

    /// Spec 0113 D33: the bold override hint applies to a node's own
    /// header and (when it has children) footer line, but must not
    /// cascade to descendant lines.
    #[test]
    fn line_has_active_override_marks_header_and_footer_but_not_children() {
        let (mut app, inner_idx, id_idx) = type_as_fixture();
        app.cursor = inner_idx;
        app.run_command("type-as test.Inner");
        assert_eq!(
            app.tree[inner_idx].span.type_fqdn.as_deref(),
            Some("test.Inner")
        );

        let header_line = app.tree[inner_idx].span.text_range.start;
        let footer_line = app.tree[inner_idx].span.text_range.end - 1;
        assert!(app.line_has_active_override(header_line));
        assert!(app.line_has_active_override(footer_line));

        let id_line = app.tree[id_idx].span.text_range.start;
        assert!(!app.line_has_active_override(id_line));
    }

    /// Spec 0114 §7: `:type-as <FQDN>` applies the override directly to
    /// the cursor node, bypassing the override pane entirely — it must
    /// never open (`override_target` stays `None` throughout).
    #[test]
    fn type_as_command_applies_override_bypassing_pane() {
        let (mut app, inner_idx, _) = type_as_fixture();
        app.cursor = inner_idx;
        app.run_command("type-as test.Inner");
        assert!(
            app.override_target.is_none(),
            "the pane must never open for :type-as"
        );
        assert_eq!(
            app.tree[inner_idx].span.type_fqdn.as_deref(),
            Some("test.Inner")
        );
        assert!(app.message.contains("test.Inner"));
    }

    /// Spec 0114 §7: `:type-as-raw` marks the cursor node's range as
    /// explicitly raw, bypassing the pane.
    #[test]
    fn type_as_raw_command_marks_raw() {
        let (mut app, inner_idx, _) = type_as_fixture();
        app.cursor = inner_idx;
        app.run_command("type-as-raw");
        assert!(app.override_target.is_none());
        assert_eq!(app.tree[inner_idx].span.type_fqdn, None);
    }

    /// Spec 0114 §7/§5 step 1: `:type-as` on an ineligible node (neither
    /// message/group nor length-delimited scalar) is refused with the
    /// same message `t` gives.
    #[test]
    fn type_as_command_rejects_non_message_node() {
        let (mut app, _, id_idx) = type_as_fixture();
        app.cursor = id_idx;
        app.run_command("type-as test.Inner");
        assert!(
            app.message
                .contains("cannot override: not a message/group or length-delimited field"),
            "unexpected message: {}",
            app.message
        );
    }

    /// Spec 0114 §7: once the command-name token has unambiguously
    /// resolved to `type-as`, `Tab` completes its FQDN argument against
    /// `all_type_fqdns`.
    #[test]
    fn tab_completes_type_as_fqdn_argument() {
        let (mut app, _, _) = type_as_fixture();
        app.handle_key(KeyEvent::new(KeyCode::Char(':'), KeyModifiers::NONE));
        for c in "type-as test.In".chars() {
            app.handle_key(KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE));
        }
        app.handle_key(KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE));
        assert_eq!(app.command_buffer.as_deref(), Some("type-as test.Inner"));
    }

    /// Spec 0117 §4: `resolve_path` is the inverse of `positional_path`
    /// for every node reachable from the root, and `None` for a path that
    /// doesn't resolve against the current tree.
    #[test]
    fn resolve_path_is_the_inverse_of_positional_path() {
        let (app, inner_idx, id_idx) = type_as_fixture();
        let outer_idx = app
            .tree
            .iter()
            .position(|n| n.parent.is_none())
            .expect("tree must have a wrapper root");
        assert_eq!(
            app.resolve_path(&app.positional_path(outer_idx)),
            Some(outer_idx)
        );
        assert_eq!(
            app.resolve_path(&app.positional_path(inner_idx)),
            Some(inner_idx)
        );
        assert_eq!(app.resolve_path(&app.positional_path(id_idx)), Some(id_idx));
        assert_eq!(app.resolve_path("/99"), None);
    }

    /// Spec 0117 §4's restore-time validation: `origin_resolves` checks
    /// each of the three origin kinds against the current tree/descriptor
    /// pool.
    #[test]
    fn origin_resolves_checks_path_field_and_fqdn_field_origins() {
        let (app, inner_idx, _) = type_as_fixture();
        let inner_path = app.positional_path(inner_idx);

        assert!(app.origin_resolves(&OverrideOrigin::Path {
            path: inner_path.clone()
        }));
        assert!(!app.origin_resolves(&OverrideOrigin::Path {
            path: "/99".to_string()
        }));

        assert!(app.origin_resolves(&OverrideOrigin::PathField {
            path: inner_path.clone(),
            field: 1,
        }));
        assert!(!app.origin_resolves(&OverrideOrigin::PathField {
            path: inner_path,
            field: 99,
        }));

        assert!(app.origin_resolves(&OverrideOrigin::FqdnField {
            fqdn: "test.Inner".to_string(),
            field: 1,
        }));
        assert!(!app.origin_resolves(&OverrideOrigin::FqdnField {
            fqdn: "test.Inner".to_string(),
            field: 99,
        }));
        assert!(!app.origin_resolves(&OverrideOrigin::FqdnField {
            fqdn: "test.NoSuchType".to_string(),
            field: 1,
        }));
    }

    /// Spec 0117 §4: `default_save_overrides_path` mirrors
    /// `default_extract_path`'s directory/stem derivation, but always
    /// with a `.yaml` extension.
    #[test]
    fn default_save_overrides_path_uses_blob_stem_with_yaml_extension() {
        let (mut app, _, _) = type_as_fixture();
        app.blob_path = PathBuf::from("/tmp/some/target.pb");
        assert_eq!(app.default_save_overrides_path(), "/tmp/some/target.yaml");
    }

    /// Spec 0117 §4: `:save-overrides`/`:restore-overrides` round-trip the
    /// collection through YAML, and restore silently drops an entry whose
    /// origin no longer resolves against the current tree.
    #[test]
    fn save_and_restore_overrides_round_trips_and_drops_unresolvable_entries() {
        let (mut app, inner_idx, _) = type_as_fixture();
        app.overrides.activate(
            OverrideOrigin::PathField {
                path: app.positional_path(inner_idx),
                field: 1,
            },
            Some("test.Inner".to_string()),
        );
        // Doesn't resolve against this tree — must be dropped on restore.
        app.overrides.activate(
            OverrideOrigin::Path {
                path: "/99".to_string(),
            },
            None,
        );
        assert_eq!(app.overrides.entries().len(), 3); // root + the two above

        static COUNTER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path = std::env::temp_dir()
            .join(format!("protolens-tui-save-restore-{n}.yaml"))
            .to_string_lossy()
            .into_owned();

        app.run_save_overrides(vec![&path]);
        assert!(
            app.message.starts_with("saved overrides to"),
            "unexpected message: {}",
            app.message
        );

        app.overrides = override_pane::OverrideCollection::new();
        app.run_restore_overrides(vec![&path]);
        std::fs::remove_file(&path).unwrap();

        assert!(
            app.message.starts_with("restored overrides from"),
            "unexpected message: {}",
            app.message
        );
        assert!(
            !app.message.contains("warning"),
            "unexpected warning: {}",
            app.message
        );
        assert_eq!(app.overrides.entries().len(), 2); // "/99" silently dropped
        assert!(!app
            .overrides
            .entries()
            .iter()
            .any(|e| matches!(&e.origin, OverrideOrigin::Path { path } if path == "/99")));
    }

    /// Spec 0117 §4: a target-hash mismatch on restore warns in the
    /// message line but does not block the restore.
    #[test]
    fn restore_overrides_warns_on_hash_mismatch_without_blocking() {
        let (mut app, _, _) = type_as_fixture();
        let yaml = app
            .overrides
            .to_yaml("deadbeef".to_string(), "deadbeef".to_string());

        static COUNTER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path = std::env::temp_dir()
            .join(format!("protolens-tui-restore-hash-mismatch-{n}.yaml"))
            .to_string_lossy()
            .into_owned();
        std::fs::write(&path, &yaml).unwrap();

        app.run_restore_overrides(vec![&path]);
        std::fs::remove_file(&path).unwrap();

        assert!(app.message.contains("warning"), "{}", app.message);
        assert!(app.message.contains("blob hash mismatch"));
        assert!(app.message.contains("descriptor-set hash mismatch"));
        assert_eq!(app.overrides.entries().len(), 1); // restore still applied
    }

    /// Spec 0117 §4: `Tab` completes `:save-overrides`/`:restore-overrides`'s
    /// path argument against real directory entries, cycling on the
    /// longest common prefix — no `!arg_prefix.contains(' ')` restriction,
    /// unlike `:type-as`'s FQDN completer.
    #[test]
    fn tab_completes_filesystem_path_for_save_overrides_argument() {
        let (mut app, _, _) = type_as_fixture();
        let dir =
            std::env::temp_dir().join(format!("protolens-tui-fs-complete-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("alpha.yaml"), b"").unwrap();
        std::fs::write(dir.join("alphabet.yaml"), b"").unwrap();

        let prefix = format!("save-overrides {}/al", dir.to_string_lossy());
        app.handle_key(KeyEvent::new(KeyCode::Char(':'), KeyModifiers::NONE));
        for c in prefix.chars() {
            app.handle_key(KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE));
        }
        app.handle_key(KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE));
        let expected = format!("save-overrides {}/alpha", dir.to_string_lossy());
        assert_eq!(app.command_buffer.as_deref(), Some(expected.as_str()));

        std::fs::remove_dir_all(&dir).unwrap();
    }
}
