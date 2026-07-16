// SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

use super::*;

impl App {
    /// `o`: toggle the override management pane (spec 0117 §3). Closes
    /// it (cancelling) if already open. Otherwise opens it — no
    /// cursor-node-kind precondition, unlike `t` — closing the override
    /// selection pane first if it's open (mutual exclusion, one shared
    /// right-hand UI slot).
    pub(super) fn toggle_manage_pane(&mut self) {
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
    pub(super) fn close_manage_pane(&mut self) {
        self.manage_open = false;
        self.manage_focus = false;
    }

    /// Move the management pane's highlighted row by `delta`, clamped to
    /// `0..overrides.entries().len()` (spec 0117 §3's `j`/`k`).
    pub(super) fn move_manage_highlight(&mut self, delta: isize) {
        let len = self.overrides.entries().len();
        if len == 0 {
            self.manage_highlight = 0;
            self.manage_pending_kind = None;
            return;
        }
        self.manage_highlight = clamp_highlight(self.manage_highlight, delta, len - 1);
        self.manage_pending_kind = None;
    }

    /// The management pane's grouped-by-origin display rows (spec 0117
    /// §3 amendment): one `Header` row per distinct origin (in the
    /// collection's own sort order — origins never interleave, since
    /// `OverrideCollection::sort` already groups by origin), followed by
    /// one `Entry` row per type recorded under it.
    pub(super) fn manage_display_rows(&self) -> Vec<ManageRow> {
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
    pub(super) fn manage_type_line(&self, idx: usize) -> String {
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
    pub(super) fn manage_search_text(&self, idx: usize) -> String {
        let e = &self.overrides.entries()[idx];
        let type_label = e.r#type.as_deref().unwrap_or("<raw / no type>");
        format!("{} {type_label}", e.origin.label())
    }

    /// Find the next management-pane entry (spec 0117 §3's `/`/`?`/`n`)
    /// whose search text (`manage_search_text`) contains `pattern`
    /// (case-insensitive), searching in `dir` from just past the current
    /// highlight, wrapping around. Moves the highlight there on success;
    /// otherwise leaves it unchanged and sets a status-line message.
    pub(super) fn jump_to_manage_match(&mut self, dir: SearchDir, pattern: &str) {
        let n = self.overrides.entries().len();
        if pattern.is_empty() || n == 0 {
            return;
        }
        let needle = pattern.to_lowercase();
        // Convert to the 0-based `start` convention `search_wrap` expects
        // (index to check first, not "current + 1" or "current - 1").
        let start = match dir {
            SearchDir::Forward => (self.manage_highlight + 1) % n,
            SearchDir::Backward => (self.manage_highlight + n - 1) % n,
        };
        match search_wrap(n, start, dir, |i| {
            self.manage_search_text(i).to_lowercase().contains(&needle)
        }) {
            Some(i) => {
                self.manage_highlight = i;
                self.manage_pending_kind = None;
            }
            None => self.message = format!("pattern not found: {pattern}"),
        }
    }

    /// Origins derivable under `kind` from every node in `affected`, in
    /// document order, deduplicated by `OverrideOrigin` equality (spec
    /// 0134 G2 step 4).
    pub(super) fn manage_kind_candidates(
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
    pub(super) fn manage_affected_nodes(&self, origin: &OverrideOrigin) -> Vec<usize> {
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

    /// Handle a keypress while the override management pane is open (spec
    /// 0117 §3) — always focused while open, no separate focus check
    /// (unlike `handle_override_key`).
    pub(super) fn handle_manage_key(&mut self, key: KeyEvent) {
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
                        self.set_cursor(next);
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
                        Some((pending_origin, kind, last_cursor_moves))
                            if *pending_origin == origin =>
                        {
                            if self.cursor_moves == *last_cursor_moves {
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
                            self.message =
                                format!("z: no {} override target", attempt_kind.label());
                            self.manage_pending_kind = None;
                        } else {
                            self.message = format!(
                                "z: no {} override target, try again for {} override",
                                attempt_kind.label(),
                                other_kind.label()
                            );
                            self.manage_pending_kind =
                                Some((origin, attempt_kind, self.cursor_moves));
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
                                    Some((origin, attempt_kind, self.cursor_moves));
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

    /// Mouse handling for the override management pane (spec 0113 D30):
    /// wheel scroll moves the highlight by one entry, click moves the
    /// highlight to the entry under the cursor (header rows under the
    /// click are ignored, same as clicking whitespace).
    pub(super) fn handle_manage_mouse(&mut self, event: MouseEvent) {
        match event.kind {
            MouseEventKind::ScrollDown => self.move_manage_highlight(1),
            MouseEventKind::ScrollUp => self.move_manage_highlight(-1),
            MouseEventKind::Down(MouseButton::Left) => {
                self.handle_manage_click(event.column, event.row)
            }
            _ => {}
        }
    }

    pub(super) fn handle_manage_click(&mut self, col: u16, row: u16) {
        let area = self.side_area;
        if !Self::rect_contains(area, col, row) {
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

    /// Override management pane (spec 0117 §3) — always focused while
    /// open (bold border unconditionally), lists the whole
    /// `OverrideCollection` in its canonical sort order.
    pub(super) fn render_manage_pane(&mut self, frame: &mut Frame, area: Rect) {
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
        clamp_scroll_to_visible(&mut self.manage_scroll, highlighted_row, list_height);
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
}
