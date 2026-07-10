// SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

//! Minimal v1 navigate + extract slice: single scrollable pane, cursor/fold
//! state, document-order / sibling-skip / parent / child movement, a
//! jumplist, mouse wheel/click, and a vim-style `:extract`/`x` command line
//! — spec 0111 §2/§4, Annex B, Annex C. No override picker yet.

use std::collections::{HashMap, HashSet};
use std::io;
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
use ratatui::widgets::{Block, Borders, Clear, Paragraph};
use ratatui::{Frame, Terminal};

use crate::decode::{Decoded, TreeNode};
use crate::extract::{self, ExtractFormat};

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
    "Other",
    "  ?                toggle this help",
    "  q                quit",
    "",
    "j/k or PageUp/PageDown scroll this help; q, Esc, or ? closes it.",
];

/// Owns all cursor/fold/scroll/jumplist state — kept separate from
/// `render()`'s drawing calls (spec 0111 §4, ratatui testability pattern).
pub struct App {
    /// Original blob bytes — needed for binary extraction
    /// (`ExtractFormat::Binary` slices `NodeSpan::raw_range` from this).
    blob: Vec<u8>,
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
    pub fn new(
        decoded: Decoded,
        blob_label: &str,
        blob: Vec<u8>,
        blob_path: PathBuf,
        annotations: bool,
    ) -> Self {
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
            blob,
            blob_path,
            annotations,
            lines: decoded.lines,
            tree: decoded.tree,
            line_to_node,
            cursor,
            folded: HashSet::new(),
            visible_rows: Vec::new(),
            scroll_offset: 0,
            back_stack: Vec::new(),
            fwd_stack: Vec::new(),
            first_node: cursor,
            pending_g: false,
            command_buffer: None,
            command_cursor: 0,
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
        let filename = format!(
            "{stem}.{}-{}.{short_type}.pb",
            node.raw_range.start, node.raw_range.end
        );
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
        match key.code {
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
        match tokens.next() {
            Some("extract") => self.run_extract(tokens.collect()),
            Some(other) => self.message = format!("unknown command: {other}"),
            None => {}
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
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3), // header (bordered)
                Constraint::Min(0),    // main pane (reuses header's bottom border)
                Constraint::Length(2), // status line (reuses main's bottom border)
                Constraint::Length(2), // command/message line (reuses status's bottom border)
            ])
            .split(area);

        let no_top = Borders::LEFT | Borders::RIGHT | Borders::BOTTOM;

        let header_block = Block::bordered();
        let header_inner = header_block.inner(chunks[0]);
        frame.render_widget(header_block, chunks[0]);
        frame.render_widget(Paragraph::new(self.header.as_str()), header_inner);

        let main_block = Block::default().borders(no_top);
        let inner = main_block.inner(chunks[1]);
        frame.render_widget(main_block, chunks[1]);
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
                let line_str = self.render_line_content(line_idx);
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

        let status = if self.tree.is_empty() {
            "(empty — decoded to zero fields)".to_string()
        } else {
            let node = &self.tree[self.cursor].span;
            format!(
                "L{}/{}  bytes[{}..{}]  {}",
                node.text_range.start + 1,
                self.lines.len(),
                node.raw_range.start,
                node.raw_range.end.saturating_sub(1),
                node.type_fqdn.as_deref().unwrap_or(""),
            )
        };
        let status_block = Block::default().borders(no_top);
        let status_inner = status_block.inner(chunks[2]);
        frame.render_widget(status_block, chunks[2]);
        frame.render_widget(Paragraph::new(status), status_inner);

        let cmd_block = Block::default().borders(no_top);
        let cmd_inner = cmd_block.inner(chunks[3]);
        frame.render_widget(cmd_block, chunks[3]);
        let cmd_text = match &self.command_buffer {
            Some(buf) => format!(":{buf}"),
            None => self.message.clone(),
        };
        frame.render_widget(Paragraph::new(cmd_text), cmd_inner);
        if self.command_buffer.is_some() {
            // Show a real terminal cursor at the edit position (":" plus
            // `command_cursor` chars into the buffer) — without this the
            // user can't tell where they're typing.
            let x = cmd_inner.x + 1 + self.command_cursor as u16;
            frame.set_cursor_position((x, cmd_inner.y));
        }

        if self.splash {
            self.render_splash(frame, area);
        } else if self.help_open {
            self.render_help(frame, area);
        }
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
        };
        let mut app = App::new(
            decoded,
            "empty.pb",
            Vec::new(),
            PathBuf::from("empty.pb"),
            true,
        );

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
}
