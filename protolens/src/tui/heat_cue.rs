// SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

//! Main-pane inference-mismatch heat cue (spec 0138, item 12 of
//! 2026-07-17 feedback) — a per-node cue, shown only when auto-inference
//! finds a strictly better-scoring type for a node's byte range than the
//! node's current effective type.

use super::*;

/// Leading gutter glyph (spec 0138 N1) — a filled circle reads clearly at
/// a single terminal cell width in both light and dark themes, and is
/// distinct from the fold marker (`▸`/`▾`) and every other glyph this
/// crate already uses.
pub(super) const HEAT_GLYPH: char = '●';

/// A node's computed heat cue (spec 0138 G2-G4, G9-G12): either a
/// `Mismatch` (red — the original gate, `best` strictly exceeds
/// `current`) or a `Tie` (blue — `current` already equals `best`, but at
/// least one other candidate shares that same top score, so the current
/// typing, while optimal, isn't the *unique* optimum).
pub(super) struct HeatCue {
    /// Brightness level, 1..=12 (spec 0138 G5), bucketed from `best`
    /// (`Mismatch`) or from the shared top score (`Tie`) — same
    /// bucketing function either way.
    pub(super) level: u8,
    pub(super) kind: HeatCueKind,
}

pub(super) enum HeatCueKind {
    Mismatch { current: i64, best: i64 },
    Tie { tie_count: usize },
}

/// Spec 0138 G5's Fibonacci brightness bucketing: `[1, 2, 3, 5, 8, 13,
/// 21, 34, 55, 89, 144]` as 11 ascending boundaries, partitioning the
/// score axis into 12 levels.
pub(super) fn heat_level(best_score: i64) -> u8 {
    const BOUNDARIES: [i64; 11] = [1, 2, 3, 5, 8, 13, 21, 34, 55, 89, 144];
    for (i, &boundary) in BOUNDARIES.iter().enumerate() {
        if best_score <= boundary {
            return (i + 1) as u8;
        }
    }
    12
}

impl App {
    /// A node's currently effective type, as a lookup key into its
    /// heat-cache candidate list (spec 0138 G3). Message/group nodes read
    /// `span.type_fqdn` directly — already kept in sync with any active
    /// override by `resettle_node` on every render pass (see
    /// `status_type_label`'s own doc comment), so no separate override
    /// lookup is needed. Scalar nodes consult `resolve_active_override`
    /// first, falling back to the schema-declared type
    /// (`natural_type_display`) when no override is active — mirroring
    /// `status_type_label`'s own fallback chain. A primitive-keyword or
    /// otherwise-unranked result simply won't be found in the candidate
    /// list, naturally defaulting `current_score` to `0` (G3).
    fn current_type_key(&self, idx: usize) -> Option<String> {
        let span = &self.tree[idx].span;
        if span.is_message {
            return span.type_fqdn.clone();
        }
        match self.resolve_active_override(idx) {
            Some(inner) => inner,
            None => self.natural_type_display(idx),
        }
    }

    /// This line's heat cue, if any (spec 0138) — `None` both when the
    /// cue is hidden (`i`) or gated absent (G4/G8), and when `line_idx`
    /// isn't a node's own header line (`line_to_node`, mirroring
    /// `line_has_active_override`'s restriction to header/footer lines —
    /// only the header side applies here, since a cue is about the
    /// node's own type, not its closing brace).
    ///
    /// Lazily populates `self.heat_cache` (G1) on a miss, keyed by the
    /// node's tag/length-stripped payload range — independent of any
    /// active override on that node, so the same cached entry serves
    /// every subsequent lookup regardless of later override changes.
    pub(super) fn heat_cue_for(&mut self, line_idx: usize) -> Option<HeatCue> {
        if self.heat_cues_hidden {
            return None;
        }
        let idx = *self.line_to_node.get(&line_idx)?;
        if !self.can_override(idx) {
            return None;
        }
        let range = {
            let node = &self.tree[idx].span;
            extract::message_payload_range(&self.blob, &node.raw_range, node.packed_record_start)
        };
        let candidates = match self.heat_cache.get(&range) {
            Some(c) => c,
            None => {
                let graph = self.ctx.graph.as_ref()?;
                let range_bytes = &self.blob[range.clone()];
                let c = override_pane::inferred_candidates(range_bytes, graph);
                self.heat_cache.insert(range.clone(), c.clone());
                c
            }
        };
        let current_key = self.current_type_key(idx);
        heat_cue_from_candidates(&candidates, current_key.as_deref())
    }
}

/// Pure gate/level computation over an already-fetched candidate list
/// (spec 0138 G2-G4, G9) — split out from `heat_cue_for` so it's
/// directly unit-testable without a real scoring graph. `current_key` is
/// `None` both for a raw/unresolvable current type and for "not found in
/// `candidates`" — either way `current_score` defaults to `0` (G3).
pub(super) fn heat_cue_from_candidates(
    candidates: &[(String, i64)],
    current_key: Option<&str>,
) -> Option<HeatCue> {
    let best = candidates.first()?.1;
    let current_entry = candidates
        .iter()
        .find(|(fqdn, _)| Some(fqdn.as_str()) == current_key);
    let current = current_entry.map(|(_, score)| *score).unwrap_or(0);
    if best > current {
        return Some(HeatCue {
            level: heat_level(best),
            kind: HeatCueKind::Mismatch { current, best },
        });
    }
    // G4's original gate didn't trigger: the current typing already
    // scores at the top (`current == best`, since `current` can never
    // exceed `best`). G9: if other candidates tie it there, the current
    // typing isn't a *unique* optimum — flag that ambiguity with a
    // distinct ("Tie") cue instead of showing nothing. Requires
    // `current_entry` to be an actual match (not just a coincidental
    // `0 == best` default) — see G9's own doc in spec 0138.
    if current_entry.is_some() {
        let tie_count = candidates
            .iter()
            .filter(|(_, score)| *score == best)
            .count();
        if tie_count > 1 {
            return Some(HeatCue {
                level: heat_level(best),
                kind: HeatCueKind::Tie { tie_count },
            });
        }
    }
    None
}
