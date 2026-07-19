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

/// Small, fixed-size summary of a range's inference-candidate list
/// (spec 0151 G1) — everything `heat_cue_from_stats` actually needs,
/// derived once and cached in place of the full `Vec<(String, i64)>`
/// `inferred_candidates` returns.
#[derive(Clone, Copy)]
pub(super) struct RangeHeatStats {
    /// `None` when every candidate for this range is vetoed
    /// (equivalently, `-inf`) — a real, cacheable value, not an
    /// absent-entry sentinel (see spec 0151 Background).
    pub(super) best_score: Option<i64>,
    /// Cardinality of the set of candidates sharing `best_score`. A
    /// unique winner has `best_count == 1`, never `0`. Meaningless
    /// (left `0`) when `best_score` is `None`.
    pub(super) best_count: usize,
}

/// Bounded-MRU cache, generic over a small, fixed-size value (spec 0151
/// G1/G4) — the shared shape behind both `heat_range_cache` and
/// `heat_current_score_cache`. Distinct from `override_pane::
/// CandidateCache` (byte-budget-bounded, sized for large `Vec<(String,
/// i64)>` previews) — entry-count-bounded instead, since `V` here is
/// always a small fixed-size scalar with no need for a per-entry size
/// estimator. Deliberately minimal (`get`/`insert` only, `entries`/
/// `max_entries` never exposed) so a future background scoring thread
/// (spec 0151 N7) could wrap an instance in a `Mutex` transparently.
pub(super) struct BoundedMru<K: PartialEq + Clone, V: Clone> {
    entries: Vec<(K, V)>,
    max_entries: usize,
}

impl<K: PartialEq + Clone, V: Clone> BoundedMru<K, V> {
    pub(super) fn new(max_entries: usize) -> Self {
        Self {
            entries: Vec::new(),
            max_entries,
        }
    }

    /// Promotes to most-recently-used on a hit, mirroring
    /// `CandidateCache::get`.
    pub(super) fn get(&mut self, key: &K) -> Option<V> {
        let pos = self.entries.iter().position(|(k, _)| k == key)?;
        let (k, v) = self.entries.remove(pos);
        self.entries.push((k, v.clone()));
        Some(v)
    }

    /// Replaces an existing entry for `key` in place (re-promoting it),
    /// or appends a new one; evicts the least-recently-used entry while
    /// over `max_entries`, always keeping at least the one just
    /// inserted — mirrors `CandidateCache::insert`'s shape with an
    /// entry-count bound instead of a byte budget.
    pub(super) fn insert(&mut self, key: K, value: V) {
        self.entries.retain(|(k, _)| *k != key);
        self.entries.push((key, value));
        while self.entries.len() > self.max_entries.max(1) {
            self.entries.remove(0);
        }
    }
}

/// Entry-count cap for `heat_range_cache`/`heat_current_score_cache`
/// (spec 0151 G4) — generous headroom for any realistically browsed
/// document tree; both value types are small fixed-size scalars, so
/// even a fully populated cache costs well under 1MB.
pub(super) const HEAT_CACHE_MAX_ENTRIES: usize = 8192;

/// Derives `RangeHeatStats` from a full candidate list (spec 0151 G1) —
/// always returns a value (no `Option`/`?`): an empty `candidates` list
/// is itself informative (`best_score: None`) and must still be cached,
/// not treated as "nothing to insert" (see Background).
pub(super) fn derive_stats(candidates: &[(String, i64)]) -> RangeHeatStats {
    let Some(&(_, best)) = candidates.first() else {
        return RangeHeatStats {
            best_score: None,
            best_count: 0,
        };
    };
    let best_count = candidates.iter().filter(|(_, s)| *s == best).count();
    RangeHeatStats {
        best_score: Some(best),
        best_count,
    }
}

/// Looks up one candidate's score by FQDN — `None` when `key` isn't in
/// `candidates` at all (vetoed for this range).
pub(super) fn score_of(candidates: &[(String, i64)], key: &str) -> Option<i64> {
    candidates
        .iter()
        .find(|(fqdn, _)| fqdn == key)
        .map(|(_, score)| *score)
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
    /// first, falling back to the schema-declared type (`natural_type`)
    /// when no override is active — mirroring `status_type_label`'s own
    /// fallback chain. A primitive-keyword or otherwise-unranked result
    /// simply won't be found in the candidate list — `heat_cue_from_
    /// stats` treats that as `current_entry: None` (spec 0151 G5), not
    /// a coincidental `0`.
    fn current_type_key(&self, idx: usize) -> Option<String> {
        let span = &self.tree[idx].span;
        if span.is_message {
            return span.type_fqdn.clone();
        }
        match self.resolve_active_override(idx) {
            Some(inner) => inner,
            None => self.natural_type(idx),
        }
    }

    /// This line's heat cue, if any (spec 0138) — `None` both when the
    /// cue is hidden (`i`) or gated absent (G4/G8), and when `line_idx`
    /// isn't a node's own header line (`line_to_node`, mirroring
    /// `line_has_active_override`'s restriction to header/footer lines —
    /// only the header side applies here, since a cue is about the
    /// node's own type, not its closing brace).
    ///
    /// Lazily populates `self.heat_range_cache`/`self.
    /// heat_current_score_cache` (spec 0151 G1-G3) on a miss, keyed by
    /// the node's tag/length-stripped payload range's `start` offset —
    /// independent of any active override on that node for the
    /// range-level stats, while the current-type score is additionally
    /// keyed by the current type's FQDN so an override edit invalidates
    /// only that one entry (G3).
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
        let start = range.start;
        let current_key = self.current_type_key(idx);

        let stats = match self.heat_range_cache.get(&start) {
            Some(s) => s,
            None => {
                let graph = self.ctx.graph.as_ref()?;
                let range_bytes = &self.blob[range.clone()];
                let candidates = override_pane::inferred_candidates(range_bytes, graph);
                let stats = derive_stats(&candidates);
                self.heat_range_cache.insert(start, stats);
                if let Some(key) = current_key.as_ref() {
                    let score = score_of(&candidates, key);
                    self.heat_current_score_cache
                        .insert((start, key.clone()), score);
                }
                // G6: opportunistically prime the override pane's own
                // cache with this same, already-paid-for candidate list.
                let capped: Vec<_> = candidates
                    .into_iter()
                    .take(self.override_list_height.max(1))
                    .collect();
                self.candidate_cache.insert(range.clone(), capped);
                stats
            }
        };

        let current_entry: Option<i64> = match current_key.as_deref() {
            None => None,
            Some(key) => {
                let cache_key = (start, key.to_string());
                match self.heat_current_score_cache.get(&cache_key) {
                    Some(entry) => entry,
                    None => {
                        let graph = self.ctx.graph.as_ref()?;
                        let range_bytes = &self.blob[range.clone()];
                        let candidates = override_pane::inferred_candidates(range_bytes, graph);
                        let score = score_of(&candidates, key);
                        self.heat_current_score_cache.insert(cache_key, score);
                        // G6: same cross-population as the miss branch
                        // above — this call's candidate list is
                        // identical to what a fresh range-cache miss
                        // would have produced for this range
                        // (independent of current type), so it's just
                        // as worth caching for the override pane.
                        let capped: Vec<_> = candidates
                            .into_iter()
                            .take(self.override_list_height.max(1))
                            .collect();
                        self.candidate_cache.insert(range.clone(), capped);
                        score
                    }
                }
            }
        };

        heat_cue_from_stats(stats, current_entry)
    }
}

/// Pure gate/level computation over an already-derived stats summary
/// (spec 0151 G5, spec 0138 G2-G4/G9) — split out from `heat_cue_for` so
/// it's directly unit-testable without a real scoring graph.
/// `Option`-aware throughout: a `None` `current_entry` (vetoed current
/// type) is never conflated with a genuine `0` score, and a `None`
/// `stats.best_score` (every candidate vetoed) always yields no cue.
pub(super) fn heat_cue_from_stats(
    stats: RangeHeatStats,
    current_entry: Option<i64>,
) -> Option<HeatCue> {
    let best = stats.best_score?; // every candidate vetoed — no cue possible
    match current_entry {
        None => Some(HeatCue {
            level: heat_level(best),
            // Display value only; the gating decision above already
            // treated `None` as strictly worse than any `best`,
            // independent of what's shown here.
            kind: HeatCueKind::Mismatch { current: 0, best },
        }),
        Some(current) if current < best => Some(HeatCue {
            level: heat_level(best),
            kind: HeatCueKind::Mismatch { current, best },
        }),
        Some(current) if current == best && stats.best_count > 1 => Some(HeatCue {
            level: heat_level(best),
            kind: HeatCueKind::Tie {
                tie_count: stats.best_count,
            },
        }),
        _ => None,
    }
}
