// SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

use super::*;

impl App {
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
    pub(super) fn can_override(&self, idx: usize) -> bool {
        let span = &self.tree[idx].span;
        span.is_message || span.wire_type == prototext_core::helpers::WT_LEN
    }

    /// `t`: toggle the override pane for the node under the cursor (spec
    /// 0114 §1/§2). Closes it (cancelling) if already open, regardless of
    /// which pane currently has focus. Otherwise opens it — moving focus
    /// there — if the cursor sits on an eligible node (`can_override`)
    /// and the terminal is wide enough; an ineligible target or an
    /// over-narrow terminal instead leaves a status-line message.
    pub(super) fn toggle_override(&mut self) {
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
    pub(super) fn close_override(&mut self) {
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
    pub(super) fn recompute_override_candidates(&mut self) {
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
    pub(super) fn upgrade_active_override_to_complete(&mut self) {
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
    pub(super) fn move_override_highlight(&mut self, delta: isize) {
        if delta > 0
            && !self.override_candidates_complete
            && self.override_sort == SortMode::Inferred
            && self.override_highlight as isize + delta > self.override_candidates.len() as isize
        {
            self.upgrade_active_override_to_complete();
        }
        self.override_highlight = clamp_highlight(
            self.override_highlight,
            delta,
            self.override_candidates.len(),
        );
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
    pub(super) fn preview_override_highlight(&mut self) {
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
    pub(super) fn jump_to_override_match(&mut self, dir: SearchDir, pattern: &str) {
        if pattern.is_empty() || self.override_candidates.is_empty() {
            return;
        }
        let needle = pattern.to_lowercase();
        let n = self.override_candidates.len();
        // Candidate index (0-based into `override_candidates`) to start
        // just past (row 0 = raw, row i+1 = candidate i) and wrapping
        // around, in search direction. `row` is clamped into `0..=n`
        // first since the raw entry (row 0) has no corresponding
        // candidate index.
        let row = self.override_highlight.min(n);
        let start = match dir {
            SearchDir::Forward => row % n,
            SearchDir::Backward => (row.saturating_sub(1) + n - 1) % n,
        };
        match search_wrap(n, start, dir, |i| {
            self.override_candidates[i]
                .0
                .to_lowercase()
                .contains(&needle)
        }) {
            Some(i) => self.override_highlight = i + 1,
            None => self.message = format!("pattern not found: {pattern}"),
        }
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
    pub(super) fn jump_to_match(&mut self, dir: SearchDir, pattern: &str) {
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
                    self.set_cursor(cur);
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
}
