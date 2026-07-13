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

use crate::decode::{Decoded, TreeNode};
use crate::extract::{self, ExtractFormat};

/// Fixed horizontal-pan step, in columns (spec 0113 D24) — a generous but
/// simple constant rather than a fraction of the pane's width, so panning
/// speed doesn't change as the pane is resized.
const PAN_STEP: usize = 8;

/// Minimum terminal width (columns) below which `t` refuses to open the
/// override pane (spec 0114 §2) — matches 0111 Annex C's own Phase-5
/// threshold; rendering an unusably narrow split is worse than refusing.
const MIN_OVERRIDE_WIDTH: u16 = 100;

/// Single source-of-truth command-name registry (spec 0113 D26) — backs
/// both `resolve_command`'s exact-match-wins prefix dispatch and the
/// command line's Tab-completion (`App::start_tab_completion`). Adding a
/// command here is the only step needed for it to get both, automatically.
const COMMANDS: &[&str] = &["extract"];

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

/// Static key-binding reference shown by the `?` help overlay (spec 0111
/// Annex C, spec 0113 D22) — kept as one flat text block rather than
/// generated from the `handle_key` match arms, so it can be phrased for
/// readability independent of the code's own binding order.
const HELP_TEXT: &[&str] = &[
    "protolens — key bindings",
    "",
    "Movement",
    "  j / Down         next node (document order)",
    "  k / Up           previous node",
    "  J                next sibling",
    "  K                previous sibling",
    "  h / Left         close node, or move to parent",
    "  l / Right        open node, or move to first child",
    "  Home / gg        jump to first node",
    "  End / G          jump to last visible node",
    "  PageDown         scroll down one page",
    "  PageUp           scroll up one page",
    "  Ctrl-Left         pan main pane left",
    "  Ctrl-Right        pan main pane right",
    "",
    "Fold / unfold",
    "  z / Space        toggle fold on the node under the cursor",
    "  H / Shift-Left   fold all siblings at this level",
    "  Shift-Right      unfold all siblings at this level",
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
    "  Tab               complete the command name (longest common prefix,",
    "                    then cycle through matches)",
    "  Shift-Tab         cycle backward through matches",
    "",
    "Override pane",
    "  t                 open/close the override pane for the message/",
    "                    group node under the cursor",
    "  Tab               move focus between the main pane and the",
    "                    override pane (while it is open)",
    "  Esc               cancel and close the override pane",
    "",
    "Other",
    "  ?                toggle this help",
    "  q                quit",
    "",
    "j/k or PageUp/PageDown scroll this help; q, Esc, or ? closes it.",
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
    /// Whether this session was decoded with `#@ ...` annotations. Without
    /// them, a `#@ prototext` text extract cannot be round-tripped back to
    /// binary (`prototext encode` needs the annotations), so the default
    /// extract format must be binary in that case (0113 D23 amendment).
    annotations: bool,
    lines: Vec<String>,
    tree: Vec<TreeNode>,
    /// Line index (in `lines`) -> node index, for nodes whose text starts
    /// on that line. Used for the fold-indicator gutter.
    line_to_node: HashMap<usize, usize>,
    cursor: usize,
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
    /// `Some(node_idx)` while the override pane is open, holding the
    /// message/group node whose byte range it targets (spec 0114 §1/§2);
    /// `None` when closed.
    override_target: Option<usize>,
    /// `true` when the override pane has focus (spec 0114 §3's `Tab`
    /// toggle); meaningless while `override_target` is `None`.
    override_focus: bool,
    /// Full terminal width (columns) as of the last `render()` call —
    /// basis for the override pane's minimum-width refusal (spec 0114
    /// §2), since `main_area`'s own width shrinks once the pane is open.
    term_width: u16,
    back_stack: Vec<usize>,
    fwd_stack: Vec<usize>,
    /// Document-order first node — `Home`/`gg` target.
    first_node: usize,
    /// Set by a first `g` press, consumed (and cleared) by a second `g`
    /// press within the very next keystroke (`gg` chord, vim-style); any
    /// other key clears it.
    pending_g: bool,
    /// `Some(buffer)` while a `:`/`x`-triggered command line is being
    /// edited (vim-style ex-command line — see `handle_command_key`);
    /// `None` in normal navigation mode.
    command_buffer: Option<String>,
    /// Cursor position within `command_buffer`, as a **char** index (not
    /// byte index) — `0..=command_buffer.chars().count()`. Moved by
    /// `Left`/`Right`/`Home`/`End`; edits (`Backspace`/`Delete`/typing)
    /// happen relative to it rather than always at the buffer's end.
    command_cursor: usize,
    /// Active Tab-completion cycle state (spec 0113 D26); `None` when not
    /// currently cycling.
    completion: Option<CompletionState>,
    /// `true` on startup until the first keypress dismisses it — a splash
    /// screen telling the user how to reach help (spec 0113 D22).
    splash: bool,
    /// `true` while the `?` help overlay is open.
    help_open: bool,
    /// Scroll offset (in `HELP_TEXT` lines) while the help overlay is open.
    help_scroll: usize,
    header: String,
    /// Main pane's inner (bordered-away) `Rect` as of the last `render()`
    /// call — used to hit-test mouse clicks against display rows/columns.
    main_area: Rect,
    pub message: String,
    pub should_quit: bool,
}

impl App {
    pub fn new(decoded: Decoded, blob_label: &str, blob_path: PathBuf, annotations: bool) -> Self {
        let mut line_to_node = HashMap::new();
        for (idx, node) in decoded.tree.iter().enumerate() {
            line_to_node.insert(node.span.text_range.start, idx);
        }
        let header = format!("protolens — {blob_label} — {}", decoded.root_type);
        // Document-order first node (doc_prev == None) — not array index 0,
        // which is post-order (see decode::TreeNode's doc comment).
        let cursor = decoded
            .tree
            .iter()
            .position(|n| n.doc_prev.is_none())
            .unwrap_or(0);
        let mut app = App {
            blob: decoded.blob,
            wrapper_offset: decoded.wrapper_offset,
            blob_path,
            annotations,
            lines: decoded.lines,
            tree: decoded.tree,
            line_to_node,
            cursor,
            folded: HashSet::new(),
            visible_rows: Vec::new(),
            scroll_offset: 0,
            pan_offset: 0,
            override_target: None,
            override_focus: false,
            term_width: 0,
            back_stack: Vec::new(),
            fwd_stack: Vec::new(),
            first_node: cursor,
            pending_g: false,
            command_buffer: None,
            command_cursor: 0,
            completion: None,
            splash: true,
            help_open: false,
            help_scroll: 0,
            header,
            main_area: Rect::default(),
            message: String::new(),
            should_quit: false,
        };
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
    /// message/group nodes are shown payload-only (their own tag/length
    /// stripped via `extract::message_payload_range`), and every
    /// coordinate has `wrapper_offset` subtracted to undo the virtual
    /// encompassing wrapper's own tag+length prefix. The wrapper's own
    /// node displays as `[0, n)`.
    fn display_range(&self, idx: usize) -> Range<usize> {
        let span = &self.tree[idx].span;
        let raw = if span.is_message {
            extract::message_payload_range(&self.blob, &span.raw_range)
        } else {
            span.raw_range.clone()
        };
        (raw.start - self.wrapper_offset)..(raw.end - self.wrapper_offset)
    }

    /// `t`: toggle the override pane for the node under the cursor (spec
    /// 0114 §1/§2). Closes it (cancelling) if already open, regardless of
    /// which pane currently has focus. Otherwise opens it — moving focus
    /// there — if the cursor sits on a message/group node (`NodeSpan::
    /// is_message`, spec 0114 §1.2 — *not* `type_fqdn.is_some()`, which is
    /// ambiguous between a scalar and a schema-unresolved message/group)
    /// and the terminal is wide enough; a scalar/leaf target or an
    /// over-narrow terminal instead leaves a status-line message.
    fn toggle_override(&mut self) {
        if self.override_target.is_some() {
            self.override_target = None;
            self.override_focus = false;
            return;
        }
        if !self.tree[self.cursor].span.is_message {
            self.message = "cannot override: not a message/group field".to_string();
            return;
        }
        if self.term_width < MIN_OVERRIDE_WIDTH {
            self.message = format!(
                "terminal too narrow for override pane (need >= {MIN_OVERRIDE_WIDTH} columns)"
            );
            return;
        }
        self.override_target = Some(self.cursor);
        self.override_focus = true;
    }

    /// Handle a keypress while the override pane has focus (spec 0114
    /// §2) — a minimal skeleton for now: candidate-list movement/search
    /// (§3/§4) and apply-on-`Enter` (§5) land in later implementation
    /// steps.
    fn handle_override_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Tab => self.override_focus = false,
            KeyCode::Esc | KeyCode::Char('t') => {
                self.override_target = None;
                self.override_focus = false;
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

    /// Default `:extract`/`x` format: `#@ prototext` text when the session
    /// was decoded with annotations (it carries more structural
    /// information and round-trips back to binary via `prototext encode`),
    /// else raw binary — without annotations, a text extract cannot be
    /// converted back to binary at all (0113 D23 amendment).
    fn default_extract_format(&self) -> ExtractFormat {
        if self.annotations {
            ExtractFormat::Text
        } else {
            ExtractFormat::Binary
        }
    }

    /// Handle one key event, mutating cursor/fold/scroll/jumplist state.
    /// No `ratatui` rendering happens here — see spec 0111 §4.
    pub fn handle_key(&mut self, key: KeyEvent) {
        if self.splash {
            self.splash = false;
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
        self.message.clear();

        // An empty tree (e.g. reopening an extracted `google.protobuf.Empty`,
        // or any all-default submessage — decoding zero bytes legitimately
        // yields zero fields, see spec 0113) has no cursor node to index
        // into: only allow the keys that don't touch `self.tree`.
        if self.tree.is_empty() {
            match key.code {
                KeyCode::Char('q') => self.should_quit = true,
                KeyCode::Char(':') => {
                    self.command_buffer = Some(String::new());
                    self.command_cursor = 0;
                }
                KeyCode::Char('?') => {
                    self.help_open = true;
                    self.help_scroll = 0;
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
            KeyCode::Char('q') => self.should_quit = true,

            // Document-order move.
            KeyCode::Char('j') | KeyCode::Down => self.move_down(),
            KeyCode::Char('k') | KeyCode::Up => self.move_up(),

            // Jump to first/last visible node.
            KeyCode::Home => self.move_home(),
            KeyCode::End | KeyCode::Char('G') => self.move_end(),

            // Page move.
            KeyCode::PageDown => self.move_page_down(),
            KeyCode::PageUp => self.move_page_up(),

            // Sibling-skip move.
            KeyCode::Char('J') => {
                if let Some(next) = self.tree[self.cursor].next_sibling {
                    self.record_jump(self.cursor);
                    self.cursor = next;
                } else {
                    self.message = "no next sibling".to_string();
                }
            }
            KeyCode::Char('K') => {
                if let Some(prev) = self.tree[self.cursor].prev_sibling {
                    self.record_jump(self.cursor);
                    self.cursor = prev;
                } else {
                    self.message = "no previous sibling".to_string();
                }
            }

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
                self.command_buffer = Some(String::new());
                self.command_cursor = 0;
            }
            KeyCode::Char('x') => {
                let buf = format!("extract {}", self.default_extract_path());
                self.command_cursor = buf.chars().count();
                self.command_buffer = Some(buf);
            }

            // Override pane (spec 0114 §1/§2): `t` opens/closes it; `Tab`
            // moves focus into it while it's open (focus is main pane
            // here, since `override_focus` is checked earlier in
            // `handle_key`).
            KeyCode::Char('t') => self.toggle_override(),
            KeyCode::Tab if self.override_target.is_some() => self.override_focus = true,

            // Help overlay.
            KeyCode::Char('?') => {
                self.help_open = true;
                self.help_scroll = 0;
            }

            _ => {}
        }
    }

    /// Scroll/close the `?` help overlay.
    fn handle_help_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Char('?') | KeyCode::Char('q') | KeyCode::Esc => self.help_open = false,
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
            KeyCode::Tab => self.handle_tab_key(true),
            KeyCode::BackTab => self.handle_tab_key(false),
            KeyCode::Enter => {
                let cmd = self.command_buffer.take().unwrap_or_default();
                self.command_cursor = 0;
                self.run_command(&cmd);
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

    /// Complete the token the cursor currently sits in. Today only the
    /// first token (the command name, before any space) is completable —
    /// once a space precedes the cursor this is a silent no-op; spec 0114
    /// §7 extends this to `:type-as`'s FQDN argument as a second token
    /// kind, reusing this same machinery.
    fn start_tab_completion(&mut self) {
        let buf = self.command_buffer.clone().unwrap_or_default();
        let cursor_byte = self.char_byte_index(self.command_cursor);
        let prefix = &buf[..cursor_byte];
        if prefix.contains(' ') {
            return;
        }
        let mut matches = complete_prefix(prefix, COMMANDS.iter().copied());
        if matches.is_empty() {
            self.message = format!("no command matches '{prefix}'");
            return;
        }
        matches.sort_unstable();
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
            Ok(other) => unreachable!("resolve_command returned unregistered command: {other}"),
            Err(e) => self.message = e,
        }
    }

    /// `extract [--binary|--text] <path>` — default format is `#@ prototext`
    /// text when annotations are on (0113 D21), else binary (0113 D23
    /// amendment) — see `default_extract_format`.
    fn run_extract(&mut self, args: Vec<&str>) {
        let mut format = self.default_extract_format();
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

    /// Handle one mouse event: wheel scroll moves the cursor like `j`/`k`;
    /// a left click on a foldable node's marker column toggles its fold,
    /// a click elsewhere on a node's line moves the cursor there.
    pub fn handle_mouse(&mut self, event: MouseEvent) {
        self.message.clear();
        match event.kind {
            MouseEventKind::ScrollDown => self.move_down(),
            MouseEventKind::ScrollUp => self.move_up(),
            MouseEventKind::Down(MouseButton::Left) => self.handle_click(event.column, event.row),
            _ => {}
        }
    }

    fn handle_click(&mut self, col: u16, row: u16) {
        let area = self.main_area;
        if col < area.x || col >= area.x + area.width || row < area.y || row >= area.y + area.height
        {
            return;
        }
        let rel_row = (row - area.y) as usize;
        let Some(&line_idx) = self.visible_rows.get(self.scroll_offset + rel_row) else {
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

    /// A foldable node's line, with its fold marker spliced into the
    /// line's own leading indentation (aligned with the node's nesting
    /// depth, not flushed to column 0) — see `marker_column`. Lines with no
    /// associated foldable node are returned unchanged.
    fn render_line_content(&self, line_idx: usize) -> String {
        let content = self.lines.get(line_idx).map(String::as_str).unwrap_or("");
        let Some(&idx) = self.line_to_node.get(&line_idx) else {
            return content.to_string();
        };
        if !self.has_children(idx) {
            return content.to_string();
        }
        let folded = self.folded.contains(&idx);
        let marker = if folded { '▸' } else { '▾' };
        let indent_len = content.len() - content.trim_start().len();
        let mut s = if indent_len > 0 {
            let mut s = String::with_capacity(content.len());
            s.push_str(&content[..indent_len - 1]);
            s.push(marker);
            s.push_str(&content[indent_len..]);
            s
        } else {
            format!("{marker} {content}")
        };
        if folded {
            match s.rfind('{') {
                Some(pos) => s.insert_str(pos + 1, " ... }"),
                None => s.push_str(" ... }"),
            }
        }
        s
    }

    pub fn render(&mut self, frame: &mut Frame) {
        let area = frame.area();
        self.term_width = area.width;
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Min(0),    // main pane (header folded into its title)
                Constraint::Length(3), // command/message (left) + status (right)
            ])
            .split(area);

        // Ephemeral right-hand split (spec 0114 §2) when the override
        // pane is open — same `Percentage(65)`/`Percentage(35)` ratio as
        // 0111 Annex C's own Phase-5 mockup, transient rather than a
        // persistent toggle.
        let (main_outer, override_outer) = if self.override_target.is_some() {
            let split = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([Constraint::Percentage(65), Constraint::Percentage(35)])
                .split(chunks[0]);
            (split[0], Some(split[1]))
        } else {
            (chunks[0], None)
        };

        let main_block = Block::bordered().title(format!(" {} ", self.header));
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

        let text_lines: Vec<Line> = window
            .iter()
            .enumerate()
            .map(|(row, &line_idx)| {
                let line_str = pan_line(&self.render_line_content(line_idx), self.pan_offset);
                if self.scroll_offset + row == cursor_row {
                    Line::from(Span::styled(
                        line_str,
                        Style::default().add_modifier(Modifier::REVERSED),
                    ))
                } else {
                    Line::from(line_str)
                }
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
        let cmd_text = match &self.command_buffer {
            Some(buf) => format!(":{buf}"),
            None => self.message.clone(),
        };
        let status_outer = if cmd_text.is_empty() {
            chunks[1]
        } else {
            let bottom = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([Constraint::Percentage(60), Constraint::Percentage(40)])
                .split(chunks[1]);

            let cmd_block = Block::bordered();
            let cmd_inner = cmd_block.inner(bottom[0]);
            frame.render_widget(cmd_block, bottom[0]);
            frame.render_widget(Paragraph::new(cmd_text), cmd_inner);
            if self.command_buffer.is_some() {
                // Show a real terminal cursor at the edit position (":"
                // plus `command_cursor` chars into the buffer) — without
                // this the user can't tell where they're typing.
                let x = cmd_inner.x + 1 + self.command_cursor as u16;
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
            format!(
                "L{}/{}  bytes[{}..{})  path {}  {}",
                node.text_range.start + 1,
                self.lines.len(),
                range.start,
                range.end,
                path,
                node.type_fqdn.as_deref().unwrap_or(""),
            )
        };
        let status_block = Block::bordered();
        let status_inner = status_block.inner(status_outer);
        frame.render_widget(status_block, status_outer);
        frame.render_widget(Paragraph::new(status), status_inner);

        if let Some(override_area) = override_outer {
            self.render_override_pane(frame, override_area);
        }

        if self.splash {
            self.render_splash(frame, area);
        } else if self.help_open {
            self.render_help(frame, area);
        }
    }

    /// Ephemeral right-hand override pane (spec 0114 §2) — skeleton only:
    /// title showing the target's byte range and the pinned `<raw / no
    /// type>` row (§3.1). The ranked candidate list (§3.2), search (§4),
    /// and apply-on-`Enter` (§5) land in later implementation steps.
    fn render_override_pane(&self, frame: &mut Frame, area: Rect) {
        let Some(idx) = self.override_target else {
            return;
        };
        let range = self.display_range(idx);
        let title = format!(" Override — range [{}..{}) ", range.start, range.end);
        let border_style = if self.override_focus {
            Style::default().add_modifier(Modifier::BOLD)
        } else {
            Style::default()
        };
        let block = Block::bordered().title(title).border_style(border_style);
        let inner = block.inner(area);
        frame.render_widget(block, area);
        let lines = vec![
            Line::from("<raw / no type>"),
            Line::from(""),
            Line::from("(candidate list — coming soon)"),
        ];
        frame.render_widget(Paragraph::new(lines), inner);
    }

    /// Centered modal listing `HELP_TEXT`, scrollable via `help_scroll`.
    fn render_help(&mut self, frame: &mut Frame, area: Rect) {
        let popup = centered_rect(70, 70, area);
        frame.render_widget(Clear, popup);
        let block = Block::bordered().title(" Help (j/k scroll, q/Esc/? close) ");
        let inner = block.inner(popup);
        frame.render_widget(block, popup);

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
    /// reach the `?` help overlay (spec 0113 D22).
    fn render_splash(&self, frame: &mut Frame, area: Rect) {
        let popup = centered_rect(60, 30, area);
        frame.render_widget(Clear, popup);
        let block = Block::bordered().title(" protolens ");
        let inner = block.inner(popup);
        frame.render_widget(block, popup);
        let text = vec![
            Line::from(self.header.as_str()),
            Line::from(""),
            Line::from("Press ? for help."),
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

/// Drop the leading `offset` characters of `line` (spec 0113 D24) — the
/// remainder is left for `ratatui::Paragraph` to clip to the pane's width
/// as usual, same as an un-panned line.
fn pan_line(line: &str, offset: usize) -> String {
    if offset == 0 {
        return line.to_string();
    }
    line.chars().skip(offset).collect()
}

/// Column, within a line's own leading indentation, where a fold marker is
/// spliced in by `App::render_line_content` — the last indent column before
/// the token if any indentation exists, else column 0.
fn marker_column(line: &str) -> u16 {
    let indent_len = line.len() - line.trim_start().len();
    indent_len.saturating_sub(1) as u16
}

/// Restore the terminal to its normal (cooked, main-screen, no mouse
/// capture) state — shared by `run`'s own cleanup and the panic hook below,
/// so a panic mid-session doesn't leave the user's terminal unusable.
fn restore_terminal() {
    let _ = disable_raw_mode();
    let _ = execute!(io::stdout(), LeaveAlternateScreen, DisableMouseCapture);
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

fn run_loop<B: Backend>(terminal: &mut Terminal<B>, app: &mut App) -> io::Result<()> {
    loop {
        terminal.draw(|frame| app.render(frame))?;
        match event::read()? {
            Event::Key(key) => app.handle_key(key),
            Event::Mouse(mouse) => app.handle_mouse(mouse),
            _ => {}
        }
        if app.should_quit {
            return Ok(());
        }
    }
}

#[cfg(test)]
mod tests {
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
        };
        let mut app = App::new(decoded, "empty.pb", PathBuf::from("empty.pb"), true);

        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|frame| app.render(frame)).unwrap();

        // Dismiss the startup splash first (any key), then exercise a
        // handful of keys that are unguarded `self.tree[...]` indexing
        // sites for a non-empty tree.
        app.handle_key(KeyEvent::new(KeyCode::Char('?'), KeyModifiers::NONE));
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
        assert!(app.should_quit);
    }

    #[test]
    fn resolve_command_prefix_and_exact_match() {
        assert_eq!(resolve_command("extract"), Ok("extract"));
        assert_eq!(resolve_command("e"), Ok("extract"));
        assert!(resolve_command("zzz").is_err());
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
        };
        App::new(decoded, "empty.pb", PathBuf::from("empty.pb"), true)
    }

    /// Spec 0113 D26: `Tab` on a unique-matching command-name prefix
    /// completes it in full.
    #[test]
    fn tab_completes_the_unique_command_name() {
        let mut app = empty_app();
        app.handle_key(KeyEvent::new(KeyCode::Char('?'), KeyModifiers::NONE)); // dismiss splash
        app.handle_key(KeyEvent::new(KeyCode::Char(':'), KeyModifiers::NONE));
        app.handle_key(KeyEvent::new(KeyCode::Char('e'), KeyModifiers::NONE));
        app.handle_key(KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE));
        assert_eq!(app.command_buffer.as_deref(), Some("extract"));
        assert_eq!(app.command_cursor, "extract".chars().count());
    }

    /// Spec 0113 D26: once a space precedes the cursor, `Tab` is a silent
    /// no-op (only command-name completion exists until spec 0114's
    /// `:type-as` FQDN-argument completion lands).
    #[test]
    fn tab_is_a_no_op_once_past_the_first_space() {
        let mut app = empty_app();
        app.handle_key(KeyEvent::new(KeyCode::Char('?'), KeyModifiers::NONE));
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
    /// `CompletionState`, since `COMMANDS` itself has only one entry today
    /// (real multi-candidate cycling becomes reachable end-to-end once
    /// spec 0114 adds `:type-as`/`:type-as-raw`).
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
            },
            parent: None,
            first_child: None,
            last_child: None,
            next_sibling: None,
            prev_sibling: None,
            doc_next: None,
            doc_prev: None,
        };
        let decoded = Decoded {
            lines,
            tree: vec![node],
            root_type: "google.protobuf.FileDescriptorProto".to_string(),
            blob: Vec::new(),
            wrapper_offset: 0,
        };
        App::new(decoded, "test.pb", PathBuf::from("test.pb"), true)
    }

    /// Spec 0114 §1/§2: `t` opens the override pane for a message-shaped
    /// cursor node and moves focus there; a second `t` (from either
    /// pane's focus) closes it again.
    #[test]
    fn t_opens_and_closes_the_override_pane_on_a_message_node() {
        let mut app = message_node_app();
        app.handle_key(KeyEvent::new(KeyCode::Char('?'), KeyModifiers::NONE)); // dismiss splash
        app.term_width = 120;

        app.handle_key(KeyEvent::new(KeyCode::Char('t'), KeyModifiers::NONE));
        assert_eq!(app.override_target, Some(0));
        assert!(app.override_focus);

        // `t` from override-pane focus closes it too.
        app.handle_key(KeyEvent::new(KeyCode::Char('t'), KeyModifiers::NONE));
        assert_eq!(app.override_target, None);
        assert!(!app.override_focus);
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
            },
            parent: None,
            first_child: None,
            last_child: None,
            next_sibling: None,
            prev_sibling: None,
            doc_next: None,
            doc_prev: None,
        };
        let decoded = Decoded {
            lines,
            tree: vec![node],
            root_type: "google.protobuf.Empty".to_string(),
            blob: Vec::new(),
            wrapper_offset: 0,
        };
        let mut app = App::new(decoded, "test.pb", PathBuf::from("test.pb"), true);
        app.handle_key(KeyEvent::new(KeyCode::Char('?'), KeyModifiers::NONE));
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
            },
            parent: None,
            first_child: None,
            last_child: None,
            next_sibling: None,
            prev_sibling: None,
            doc_next: None,
            doc_prev: None,
        };
        let decoded = Decoded {
            lines,
            tree: vec![node],
            root_type: "test.Scalar".to_string(),
            blob: Vec::new(),
            wrapper_offset: 0,
        };
        let mut app = App::new(decoded, "test.pb", PathBuf::from("test.pb"), true);
        app.handle_key(KeyEvent::new(KeyCode::Char('?'), KeyModifiers::NONE));
        app.term_width = 120;

        app.handle_key(KeyEvent::new(KeyCode::Char('t'), KeyModifiers::NONE));
        assert_eq!(app.override_target, None);
        assert!(app.message.contains("not a message/group"));
    }

    /// Spec 0114 §2: `t` refuses to open the pane below the minimum
    /// terminal width.
    #[test]
    fn t_refuses_below_the_minimum_terminal_width() {
        let mut app = message_node_app();
        app.handle_key(KeyEvent::new(KeyCode::Char('?'), KeyModifiers::NONE));
        app.term_width = MIN_OVERRIDE_WIDTH - 1;

        app.handle_key(KeyEvent::new(KeyCode::Char('t'), KeyModifiers::NONE));
        assert_eq!(app.override_target, None);
        assert!(app.message.contains("too narrow"));
    }

    /// Spec 0114 §3: `Tab` toggles focus between the main pane and the
    /// open override pane; main-pane navigation keys are inert while the
    /// override pane has focus.
    #[test]
    fn tab_toggles_focus_between_main_and_override_panes() {
        let mut app = message_node_app();
        app.handle_key(KeyEvent::new(KeyCode::Char('?'), KeyModifiers::NONE));
        app.term_width = 120;
        app.handle_key(KeyEvent::new(KeyCode::Char('t'), KeyModifiers::NONE));
        assert!(app.override_focus);

        app.handle_key(KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE));
        assert!(!app.override_focus);
        assert_eq!(app.override_target, Some(0)); // pane stays open

        app.handle_key(KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE));
        assert!(app.override_focus);
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

        let decoded = decode(&blob, &mut ctx, Some("test.Outer"), 2, true).unwrap();
        // tag(1 byte) + length-varint(1 byte, blob.len() == 4 fits in 1 byte).
        assert_eq!(decoded.wrapper_offset, 2);
        assert_eq!(decoded.blob.len(), blob.len() + 2);

        let app = App::new(decoded, "test.pb", PathBuf::from("test.pb"), true);

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
}
