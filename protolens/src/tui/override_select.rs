// SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

use super::*;

impl App {
    /// Whether `idx` is eligible as an override target (`t`, `type-as`,
    /// `type-as-raw`): a message/group node already (`NodeSpan::
    /// is_message`, spec 0114 §1.2 — *not* `type_fqdn.is_some()`, which is
    /// ambiguous between a scalar and a schema-unresolved message/group),
    /// or any scalar with a decodable tag — `wire_type` one of `WT_LEN`
    /// (string, bytes, or an unresolved LEN-wire field, reinterpretable
    /// as an embedded message), `WT_VARINT`, `WT_I32`, `WT_I64` (spec
    /// 0135 §G3: primitive-type overrides, no longer categorically
    /// excluded). For a packed-repeated element (`packed_record_start.
    /// is_some()`), eligibility is evaluated against the whole record's
    /// own reconstructed wire type, always `WT_LEN` (spec 0135 §G1) — not
    /// the individual element's own `wire_type`. Any/MessageSet
    /// auto-expansion (spec 0120) already reinterprets exactly this kind
    /// of scalar unconditionally; a manual override that turns out to
    /// target genuinely incompatible bytes simply fails to parse and
    /// `splice_override` reports it — the user is trusted to judge
    /// whether the result is meaningful (2026-07-14 feedback: `t` used
    /// to unconditionally refuse every string/bytes field).
    pub(super) fn can_override(&self, idx: usize) -> bool {
        use prototext_core::helpers::{WT_I32, WT_I64, WT_LEN, WT_VARINT};
        let span = &self.tree[idx].span;
        if span.packed_record_start.is_some() {
            return true;
        }
        span.is_message || matches!(span.wire_type, WT_LEN | WT_VARINT | WT_I32 | WT_I64)
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
        self.override_target = Some(self.cursor);
        self.override_focus = true;
        self.override_scroll = 0;
        self.override_pan_offset = 0;

        // Spec 0139: smart initial sort-mode/highlight. Step A: an
        // active override on the cursor node; else Step B: the first
        // inactive-but-applicable entry from the management list
        // (`first_entry_matching_origin_candidates` — by construction,
        // since Step A found no active match, any entry it returns here
        // is necessarily inactive); else Step B.5: for an enum-typed
        // field with no override at all, its own schema-declared enum
        // type (`natural_type`). Without this step such a field fell
        // through to `open_override_on_default`'s `Inferred`-mode
        // scoring, which is meaningless for an enum scalar (it scores
        // the bytes as a prospective *message*) and so landed on the
        // unrelated `None` sentinel row instead of the field's own
        // current type (2026-07-18 feedback).
        let candidate_type = self
            .resolve_active_override_entry(self.cursor)
            .map(|e| e.r#type.clone())
            .or_else(|| {
                self.first_entry_matching_origin_candidates(self.cursor)
                    .map(|i| self.overrides.entries()[i].r#type.clone())
            })
            .or_else(|| {
                let is_enum = matches!(
                    self.parent_field(self.cursor).map(|f| f.kind()),
                    Some(prost_reflect::Kind::Enum(_))
                );
                is_enum.then(|| self.natural_type(self.cursor))
            });

        match candidate_type {
            Some(fqdn_or_raw) => self.open_override_on_type(fqdn_or_raw),
            None => self.open_override_on_default(),
        }

        // Spec 0132 §G2: live-preview the initial highlighted row from
        // the very first frame the pane is shown, not just after the
        // first navigation keystroke.
        self.preview_override_highlight();
    }

    /// Spec 0139's mode-selection rule, shared by Steps A and B: open
    /// in `Inferred` mode with the highlight on `fqdn_or_raw`'s row if
    /// that type is present in the node's *complete* inferred candidate
    /// list (`upgrade_active_override_to_complete` avoids a false
    /// "not found" from a stale capped `candidate_cache` preview);
    /// otherwise open in `Lexicographic` mode, whose candidate set is
    /// the fixed universe of every selectable type and so is guaranteed
    /// to contain it.
    fn open_override_on_type(&mut self, fqdn_or_raw: Option<String>) {
        // Spec 0137 §G4: raw (`Option::None`) maps to the `None`
        // sentinel string.
        let key = fqdn_or_raw.unwrap_or_else(|| "protolens_internal.None".to_string());
        self.override_sort = SortMode::Inferred;
        self.recompute_override_candidates();
        self.upgrade_active_override_to_complete();
        if let Some(row) = self.override_candidates.iter().position(|(f, _)| *f == key) {
            self.override_highlight = row;
            return;
        }
        self.override_sort = SortMode::Lexicographic;
        self.recompute_override_candidates();
        if let Some(row) = self.override_candidates.iter().position(|(f, _)| *f == key) {
            self.override_highlight = row;
        }
    }

    /// Spec 0139 Steps C/D: neither an active nor an applicable-inactive
    /// override exists for the cursor node — default to `Inferred` mode
    /// (highlight on the top-scored row) when that list is non-empty;
    /// otherwise fall back to `Lexicographic` mode (highlight on the
    /// `None` sentinel row), silently — the "no scoring graph available"
    /// message `recompute_override_candidates` sets in the no-graph case
    /// would be redundant here, since this fallback already performs
    /// exactly what that message suggests.
    fn open_override_on_default(&mut self) {
        self.override_sort = SortMode::Inferred;
        self.recompute_override_candidates();
        if self.override_candidates.is_empty() {
            self.message.clear();
            self.override_sort = SortMode::Lexicographic;
            self.recompute_override_candidates();
        }
    }

    /// `Enter`/double-click on a main-pane node (item 3, spec 0139
    /// follow-up): a smart proxy for `t`/`o` — opens the management
    /// pane (`o`) if an override already applies to the cursor node,
    /// active or not (the same Step A/B check spec 0139's `t` itself
    /// uses to pick its initial highlight); otherwise opens the
    /// selection pane (`t`), which handles eligibility/width refusals
    /// on its own exactly as a direct keypress would.
    pub(super) fn open_smart_override_or_manage(&mut self) {
        let has_override = self.resolve_active_override_entry(self.cursor).is_some()
            || self
                .first_entry_matching_origin_candidates(self.cursor)
                .is_some();
        if has_override {
            self.toggle_manage_pane();
        } else {
            self.toggle_override();
        }
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
        // Item 11 (2026-07-17 feedback): a pane opened from the
        // management pane always returns there on close — the Enter-
        // confirm call site (`handle_override_key`) already sets these
        // same three fields itself right after calling this, so setting
        // them here too is harmless there; it's the cancelling call
        // sites (`Esc`/`t`/`q`) that actually need it.
        if self.override_opened_from_manage {
            self.override_opened_from_manage = false;
            self.manage_open = true;
            self.manage_focus = true;
        }
    }

    /// `Enter`/double-click on an entry in the override management pane
    /// (item 11, 2026-07-17 feedback): opens the selection pane on that
    /// entry's own origin, initially highlighted on its own current type
    /// (Step A/B's mode-selection rule, reused via `open_override_on_
    /// type`), to let the user pick an alternate type. Confirming lands
    /// back in the management pane (spec 0119 G3, unconditional); Esc/
    /// `t`/`q` also return there — without mutating the entry — via
    /// `override_opened_from_manage` (`close_override`).
    pub(super) fn open_override_from_manage(&mut self) {
        let Some(entry) = self.overrides.entries().get(self.manage_highlight) else {
            return;
        };
        let origin = entry.origin.clone();
        let current_type = entry.r#type.clone();
        let affected = self.manage_affected_nodes(&origin);
        let target = affected
            .iter()
            .find(|&&i| i == self.cursor)
            .or_else(|| affected.first());
        let Some(&target) = target else {
            return;
        };
        self.manage_open = false;
        self.override_target = Some(target);
        self.override_focus = true;
        self.override_scroll = 0;
        self.override_pan_offset = 0;
        self.override_opened_from_manage = true;
        self.open_override_on_type(current_type);
        self.preview_override_highlight();
    }

    /// Recompute `override_candidates` for the current `override_target`
    /// under the currently active `override_sort` (spec 0114 §3.2), and
    /// reset the highlight to the first candidate (index `0`) — in
    /// alphabetic mode this is always the `None` sentinel (spec 0137
    /// §G1/§G4), not necessarily what was previously highlighted;
    /// there is no separate pinned row to preserve any more. Called
    /// both when the pane first opens and whenever `i` toggles the sort
    /// mode.
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
            // Spec 0137 §G1/§G4: the `None` sentinel + the 15 primitive
            // keywords are prepended, in that fixed order, ahead of the
            // sorted message/group/enum FQDNs — alphabetic mode only
            // (§G7).
            SortMode::Lexicographic => std::iter::once("protolens_internal.None".to_string())
                .chain(decode::ALL_PRIMITIVE_KEYWORDS.iter().map(|s| s.to_string()))
                .chain(self.all_type_fqdns.iter().cloned())
                .map(|f| (f, None))
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
                    self.message = "no scoring graph available for inferred order; press 'i' \
                                     for alphanumeric"
                        .to_string();
                    Vec::new()
                }
            },
        };
        self.override_highlight = 0;
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
    /// §3.2's `j`/`k`), clamped to `0..=override_candidates.len() - 1`
    /// (spec 0137 §G4: `override_candidates` is indexed directly — no
    /// more pinned row 0). Upgrades a capped preview to the complete
    /// list first (spec 0114 §6) if the requested move would go past
    /// what's currently loaded.
    pub(super) fn move_override_highlight(&mut self, delta: isize) {
        let max_index = self.override_candidates.len().saturating_sub(1);
        if delta > 0
            && !self.override_candidates_complete
            && self.override_sort == SortMode::Inferred
            && self.override_highlight as isize + delta > max_index as isize
        {
            self.upgrade_active_override_to_complete();
        }
        let max_index = self.override_candidates.len().saturating_sub(1);
        self.override_highlight = clamp_highlight(self.override_highlight, delta, max_index);
        // Spec 0132 §G2: live-preview the newly-highlighted candidate.
        self.preview_override_highlight();
    }

    /// Spec 0132 §G2: live-previews the currently-highlighted override
    /// candidate by splicing it directly into the main pane — cheap,
    /// single-node `splice_override` call that deliberately does not
    /// touch `self.overrides`, so a later `Enter`-confirm (which does
    /// touch it) is entirely unaffected by whatever was last previewed.
    /// No-op if the override pane isn't open. `override_highlight`
    /// indexes `override_candidates` directly (spec 0137 §G4) — no more
    /// pinned row 0; raw (`Option::None`) is reached only via the
    /// `None` sentinel entry in alphabetic mode.
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
        let tentative = self
            .override_candidates
            .get(self.override_highlight)
            .map(|(fqdn, _)| fqdn.clone());
        match self.splice_override(idx, tentative) {
            Ok(()) => self.tree[idx].rendered_as = None,
            Err(e) => self.message = format!("cannot preview override: {e}"),
        }
    }

    /// Find the next `override_candidates` entry (0-based, direct index
    /// — spec 0137 §G4: no more pinned raw row excluded from matching)
    /// whose FQDN contains `pattern` (case-insensitive), searching in
    /// `dir` from just past the currently highlighted row, wrapping
    /// around. Moves the highlight there on success; otherwise leaves it
    /// unchanged and sets a status-line message.
    pub(super) fn jump_to_override_match(&mut self, dir: SearchDir, pattern: &str) {
        if pattern.is_empty() || self.override_candidates.is_empty() {
            return;
        }
        let needle = pattern.to_lowercase();
        let n = self.override_candidates.len();
        let start = match dir {
            SearchDir::Forward => (self.override_highlight + 1) % n,
            SearchDir::Backward => (self.override_highlight + n - 1) % n,
        };
        match search_wrap(n, start, dir, |i| {
            self.override_candidates[i]
                .0
                .to_lowercase()
                .contains(&needle)
        }) {
            Some(i) => {
                self.override_highlight = i;
                // Spec 0132 §G2: live-preview the newly-highlighted
                // candidate, same as arrow-key movement (2026-07-17
                // feedback: search-jump landed silently, without a
                // main-pane preview).
                self.preview_override_highlight();
            }
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
