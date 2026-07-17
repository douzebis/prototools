// SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

use super::*;

impl App {
    /// Byte offset within `self.lines[line_idx]` where that line's
    /// trailing `#@ ...` annotation starts, if it has one (spec 0133 G4)
    /// — reuses the tree-sitter `SyntaxRole::Comment` span already
    /// computed in `self.line_styles` (a comment always spans from `#` to
    /// end of line, and protolens's own rendered text never otherwise
    /// contains a bare `#` outside a quoted string, so at most one such
    /// span exists per line).
    pub(super) fn annotation_start(&self, line_idx: usize) -> Option<usize> {
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
    pub(super) fn render_line_content(&self, line_idx: usize) -> String {
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
    pub(super) fn render_line_spans(&self, line_idx: usize) -> Vec<Span<'static>> {
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
    pub(super) fn spans_with_insertions(
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

    pub(super) fn make_span(&self, text: String, role: Option<SyntaxRole>) -> Span<'static> {
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
    pub(super) fn line_has_active_override(&self, line_idx: usize) -> bool {
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
    pub(super) fn track_message_timeout(&mut self) {
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

        // `pane_focus_style` marks whichever pane currently holds keyboard
        // focus, shared with the override/management panes' own
        // `render_override_pane`/`render_manage_pane` — the main pane has
        // focus exactly when neither side pane does (2026-07-14 feedback:
        // no prior visible sign of which pane focus was in).
        let main_focused = !self.override_focus && !self.manage_focus;
        let main_style = pane_focus_style(main_focused, self.theme);
        let main_block = Block::bordered()
            .title(Line::styled(format!(" {} ", self.header), main_style))
            .border_style(main_style)
            .border_type(BorderType::Rounded);
        let inner = main_block.inner(main_outer);
        frame.render_widget(main_block, main_outer);
        self.main_area = inner;

        let pane_height = inner.height as usize;
        let cursor_row = if self.tree.is_empty() {
            0
        } else {
            self.cursor_display_row()
        };
        if !self.tree.is_empty() {
            clamp_scroll_to_visible(&mut self.scroll_offset, cursor_row, pane_height);
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

            let cmd_block = Block::bordered().border_type(BorderType::Rounded);
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
                "L{}/{}  {}  range[{}..{})  {}",
                node.text_range.start + 1,
                self.lines.len(),
                path,
                range.start,
                range.end,
                type_label,
            )
        };
        let status_block = Block::bordered()
            .title(" Status — F1 for help ")
            .border_type(BorderType::Rounded);
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
    pub(super) fn render_override_pane(&mut self, frame: &mut Frame, area: Rect) {
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
        let style = pane_focus_style(self.override_focus, self.theme);
        let block = Block::bordered()
            .title(Line::styled(title, style))
            .border_style(style)
            .border_type(BorderType::Rounded);
        let inner = block.inner(area);
        frame.render_widget(block, area);
        self.side_area = inner;

        let list_height = inner.height as usize;
        self.override_list_height = list_height;

        let total_rows = self.override_candidates.len() + 1;
        clamp_scroll_to_visible(
            &mut self.override_scroll,
            self.override_highlight,
            list_height,
        );
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

    /// Centered modal listing `HELP_TEXT`, scrollable via `help_scroll`.
    pub(super) fn render_help(&mut self, frame: &mut Frame, area: Rect) {
        let popup = centered_rect(70, 70, area);
        frame.render_widget(Clear, popup);
        let block = Block::bordered()
            .title(" Help (j/k scroll, q/Esc/F1 close) ")
            .border_type(BorderType::Rounded);
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
    pub(super) fn render_splash(&self, frame: &mut Frame, area: Rect) {
        let popup = centered_rect(60, 30, area);
        frame.render_widget(Clear, popup);
        let block = Block::bordered()
            .title(" protolens ")
            .border_type(BorderType::Rounded);
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
