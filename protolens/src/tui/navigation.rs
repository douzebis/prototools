// SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

use super::*;

impl App {
    /// Whether `idx` is a bracketed node — has its own distinct header
    /// *and* footer line, so it's foldable and carries a fold marker.
    /// Not the same as `self.tree[idx].first_child.is_some()` (spec
    /// 0142 fix, 2026-07-18 feedback): an empty-but-bracketed message
    /// (decoded with zero populated fields, still rendered as `Name {`
    /// then `}` on the next line) has no children yet is still a real,
    /// two-line bracketed node — foldable (folding it just hides its
    /// own footer line, same as any node with an empty body) and
    /// entitled to a fold marker/handle like any other message node.
    pub(super) fn has_children(&self, idx: usize) -> bool {
        let span = &self.tree[idx].span;
        span.text_range.end - 1 > span.text_range.start
    }

    /// Recompute `visible_rows` from current fold state: a folded node
    /// hides its body (`text_range.start + 1 .. text_range.end`), keeping
    /// its own opening line visible with a fold indicator.
    pub(super) fn rebuild_visible_rows(&mut self) {
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

    /// Unfold every ancestor of `idx`, so it becomes visible.
    pub(super) fn unfold_ancestors(&mut self, idx: usize) {
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

    /// Sets `self.cursor` and bumps `cursor_moves` — the sole mutation
    /// path for `self.cursor`, so every real cursor change (even a
    /// round trip that lands back on the same node, e.g. Down then Up)
    /// is observable via `cursor_moves`, unlike comparing `self.
    /// cursor`'s value alone against a stashed old value. Always resets
    /// `cursor_footer` to `false` (spec 0142) — every caller of this
    /// method targets a node's own header row.
    pub(super) fn set_cursor(&mut self, idx: usize) {
        self.cursor = idx;
        self.cursor_footer = false;
        self.cursor_moves += 1;
    }

    /// `self.cursor`'s own currently-displayed line: its footer line
    /// (`text_range.end - 1`) if `cursor_footer`, else its header line
    /// (`text_range.start`) — spec 0142.
    pub(super) fn cursor_line(&self) -> usize {
        let span = &self.tree[self.cursor].span;
        if self.cursor_footer {
            span.text_range.end - 1
        } else {
            span.text_range.start
        }
    }

    /// Resolve a visible line back to a `(node, is_footer)` cursor stop
    /// (spec 0142) — `line_to_node` (header) checked first,
    /// `footer_line_to_node` (footer) as fallback; the two never
    /// overlap for the same line (a footer line only exists for a node
    /// with a nonempty body, so its closing line always differs from
    /// its own header line).
    fn resolve_cursor_line(&self, line: usize) -> Option<(usize, bool)> {
        if let Some(&idx) = self.line_to_node.get(&line) {
            return Some((idx, false));
        }
        self.footer_line_to_node.get(&line).map(|&idx| (idx, true))
    }

    /// Moves the cursor to the next/previous visible *line* (spec
    /// 0142) — a node's own closing `}` line is now a distinct stop,
    /// right after its last visible descendant and right before its
    /// next sibling (or ancestor's own footer). Walks `visible_rows`
    /// directly rather than `doc_next`/`doc_prev` node links, since
    /// footer lines aren't nodes in their own right.
    pub(super) fn move_down(&mut self) {
        let cur = self.cursor_line();
        if let Ok(pos) = self.visible_rows.binary_search(&cur) {
            if let Some(&line) = self.visible_rows.get(pos + 1) {
                if let Some((idx, footer)) = self.resolve_cursor_line(line) {
                    self.cursor = idx;
                    self.cursor_footer = footer;
                    self.cursor_moves += 1;
                }
            }
        }
    }

    pub(super) fn move_up(&mut self) {
        let cur = self.cursor_line();
        if let Ok(pos) = self.visible_rows.binary_search(&cur) {
            if pos > 0 {
                if let Some((idx, footer)) = self.resolve_cursor_line(self.visible_rows[pos - 1]) {
                    self.cursor = idx;
                    self.cursor_footer = footer;
                    self.cursor_moves += 1;
                }
            }
        }
    }

    /// Sibling-skip move (`J` / Shift-Down, spec 0126 G2): moves to the
    /// cursor's next sibling, or leaves it in place with a message if
    /// there isn't one.
    pub(super) fn next_sibling_move(&mut self) {
        if let Some(next) = self.tree[self.cursor].next_sibling {
            self.record_jump(self.cursor);
            self.set_cursor(next);
        } else {
            self.message = "no next sibling".to_string();
        }
    }

    /// Sibling-skip move (`K` / Shift-Up, spec 0126 G2): moves to the
    /// cursor's previous sibling, or leaves it in place with a message if
    /// there isn't one.
    pub(super) fn prev_sibling_move(&mut self) {
        if let Some(prev) = self.tree[self.cursor].prev_sibling {
            self.record_jump(self.cursor);
            self.set_cursor(prev);
        } else {
            self.message = "no previous sibling".to_string();
        }
    }

    pub(super) fn move_page_down(&mut self) {
        let page = (self.main_area.height as usize).max(1);
        for _ in 0..page {
            self.move_down();
        }
    }

    pub(super) fn move_page_up(&mut self) {
        let page = (self.main_area.height as usize).max(1);
        for _ in 0..page {
            self.move_up();
        }
    }

    /// Longest rendered line (in characters, gutter included) among the
    /// currently visible window — the basis for `pan_right`'s clamping
    /// bound (spec 0113 D24: "recomputed as the cursor/scroll position
    /// changes").
    pub(super) fn max_visible_line_len(&self) -> usize {
        let pane_height = self.main_area.height as usize;
        let start = self.scroll_offset.min(self.visible_rows.len());
        let end = (self.scroll_offset + pane_height).min(self.visible_rows.len());
        self.visible_rows[start..end]
            .iter()
            .map(|&li| self.render_line_content(li).chars().count())
            .max()
            .unwrap_or(0)
    }

    pub(super) fn pan_left(&mut self) {
        self.pan_offset = self.pan_offset.saturating_sub(PAN_STEP);
    }

    pub(super) fn pan_right(&mut self) {
        // Column 0 of `main_area` is always the heat-cue gutter (spec
        // 0138 N1), reserved but never panned — only `width - 1` columns
        // actually show line text, so the clamp must leave room for that
        // extra column or panning stops one character short of the
        // line's true end.
        let width = (self.main_area.width as usize).saturating_sub(1);
        let max_offset = self.max_visible_line_len().saturating_sub(width);
        self.pan_offset = (self.pan_offset + PAN_STEP).min(max_offset);
    }

    /// Vertical pan (Ctrl-Up/Ctrl-Down, 2026-07-18 feedback item 2):
    /// scrolls the main pane's viewport without moving the cursor,
    /// bounded so the cursor's own row never leaves view.
    pub(super) fn pan_vertical_up(&mut self) {
        let height = self.main_area.height as usize;
        let cursor_row = self.cursor_display_row();
        pan_vertical_by_step(&mut self.scroll_offset, cursor_row, height, true);
    }

    pub(super) fn pan_vertical_down(&mut self) {
        let height = self.main_area.height as usize;
        let cursor_row = self.cursor_display_row();
        pan_vertical_by_step(&mut self.scroll_offset, cursor_row, height, false);
    }

    /// Absolute last node in document order (regardless of visibility).
    pub(super) fn last_node(&self) -> usize {
        let mut cur = self.first_node;
        while let Some(n) = self.tree[cur].doc_next {
            cur = n;
        }
        cur
    }

    /// Jump to the document-order first node (`Home`/`gg`).
    pub(super) fn move_home(&mut self) {
        if self.cursor != self.first_node {
            self.record_jump(self.cursor);
            self.set_cursor(self.first_node);
        }
    }

    /// Jump to the document's true last visible line (`End`/`G`, spec
    /// 0142) — `visible_rows`'s own last entry, which may be a node's
    /// footer line (e.g. the virtual encompassing wrapper's own final
    /// `}`), not just the last content node's header as before.
    pub(super) fn move_end(&mut self) {
        let Some(&last_line) = self.visible_rows.last() else {
            return;
        };
        let Some((idx, footer)) = self.resolve_cursor_line(last_line) else {
            return;
        };
        if self.cursor != idx || self.cursor_footer != footer {
            self.record_jump(self.cursor);
            self.cursor = idx;
            self.cursor_footer = footer;
            self.cursor_moves += 1;
        }
    }

    /// Folds/unfolds `idx`. Folding hides `idx`'s whole body, including
    /// its own footer line — if the cursor was resting there
    /// (`cursor_footer`) at the moment `idx` itself gets folded, snap
    /// it back to `idx`'s header (spec 0142 G6.2), since that line is
    /// no longer visible.
    pub(super) fn toggle_fold(&mut self, idx: usize) {
        if !self.folded.remove(&idx) {
            self.folded.insert(idx);
            if idx == self.cursor && self.cursor_footer {
                self.cursor_footer = false;
            }
        }
        self.rebuild_visible_rows();
    }

    /// All siblings of `idx` (including `idx` itself), in document order —
    /// walks to the first sibling via `prev_sibling`, then follows
    /// `next_sibling`. Works uniformly at any level, including root-level
    /// nodes (which share sibling links despite having no `parent`).
    pub(super) fn sibling_range(&self, idx: usize) -> Vec<usize> {
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

    pub(super) fn fold_all_siblings(&mut self) {
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

    pub(super) fn unfold_all_siblings(&mut self) {
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
    pub(super) fn sibling_position(&self, idx: usize) -> usize {
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
    pub(super) fn positional_path(&self, idx: usize) -> String {
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
    pub(super) fn display_range(&self, idx: usize) -> Range<usize> {
        let span = &self.tree[idx].span;
        let raw =
            extract::message_payload_range(&self.blob, &span.raw_range, span.packed_record_start);
        (raw.start - self.wrapper_offset)..(raw.end - self.wrapper_offset)
    }
}
