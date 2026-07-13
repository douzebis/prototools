// SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

//! Override-pane candidate-list computation and sort modes (spec 0114 §3).
//! `override` itself is a reserved Rust keyword, unusable as a module name
//! (spec 0114 Background) — hence `override_pane`.

use std::ops::Range;

use prost_reflect::DescriptorPool;
use prototext_graph::build_scoring_graph::serial::ArchivedCompiledGraph;
use prototext_graph::score::{score_all, ScoringOpts};

/// Sort mode for the override pane's ranked candidate list (spec 0114
/// §3.2), toggled by `i` while the pane has focus. Applies only to the
/// ranked candidates below the pinned `<raw / no type>` entry (§3.1),
/// which is neither sorted nor affected by this choice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SortMode {
    /// All message/group types known to the loaded descriptor set,
    /// alphabetically by FQDN. Cheap — no `score_all` call.
    Lexicographic,
    /// Ranked by `score_all` against the target range, descending score
    /// (ties broken by FQDN) — the default.
    Inferred,
}

/// All message/group type FQDNs known to `pool`, alphabetically sorted
/// (spec 0114 §3.2's lexicographic mode). Independent of range — computed
/// once and reused for every override-pane invocation, every range, for
/// the whole session (§6: "needs no per-range caching").
pub fn all_type_fqdns(pool: &DescriptorPool) -> Vec<String> {
    let mut names: Vec<String> = pool
        .all_messages()
        .map(|m| m.full_name().to_string())
        .collect();
    names.sort_unstable();
    names
}

/// Ranked candidate FQDNs (with their score) for `range_bytes`, descending
/// inferred score, ties broken by FQDN (spec 0114 §3.2) — same scoring
/// engine and tie-break rule `decode.rs::determine_root_type` already uses
/// for the document's own root type, applied here per-range instead of
/// corpus-wide. The score is surfaced alongside each FQDN so the override
/// pane can display it next to the candidate.
///
/// Vetoed candidates (a structural wire-format mismatch against the
/// range's actual bytes — see `prototext-graph`'s veto rules) are
/// excluded entirely: a type the wire data already contradicts is not a
/// plausible override target, the same "non_vetoed" filtering
/// `determine_root_type` applies before ranking.
pub fn inferred_candidates(
    range_bytes: &[u8],
    graph: &ArchivedCompiledGraph,
) -> Vec<(String, i64)> {
    let opts = ScoringOpts::default();
    let mut results = score_all(range_bytes, graph, &opts);
    results.sort_by(|a, b| match (a.vetoed, b.vetoed) {
        (false, true) => std::cmp::Ordering::Less,
        (true, false) => std::cmp::Ordering::Greater,
        (true, true) => a.fqdn.cmp(&b.fqdn),
        (false, false) => b.score().cmp(&a.score()).then(a.fqdn.cmp(&b.fqdn)),
    });
    results
        .into_iter()
        .filter(|r| !r.vetoed)
        .map(|r| (r.fqdn.clone(), r.score()))
        .collect()
}

/// Approximate heap footprint of a cached candidate list, for
/// `CandidateCache`'s byte budget — a per-`String` fixed overhead plus its
/// bytes, plus the paired `i64` score. Deliberately approximate (not
/// `size_of_val`-exact): only used to bound total cache size, not for any
/// correctness-sensitive purpose.
fn candidates_bytes(candidates: &[(String, i64)]) -> usize {
    candidates
        .iter()
        .map(|(fqdn, _)| fqdn.len() + std::mem::size_of::<i64>())
        .sum()
}

/// Session-scoped, byte-bounded MRU cache of *capped* `inferred_candidates`
/// previews, keyed by tag/length-stripped target range (spec 0114 §6).
///
/// Deliberately never holds a range's *complete* ranked list — only a
/// preview capped to however many entries fit the pane at the time it was
/// cached (typically the pane's own visible height). The complete list for
/// whichever range is *currently* the open override pane's target is held
/// separately (`App::override_inferred_raw`), not by this cache; a
/// previously-active range's list is capped down before being handed to
/// `insert` when the pane closes or retargets. This lets a small byte
/// budget hold many more distinct ranges than a handful of complete lists
/// ever could — most of the time, a user only looks at the top of a
/// ranked list anyway.
/// One cached range's capped `(fqdn, score)` preview.
type CandidateEntry = (Range<usize>, Vec<(String, i64)>);

pub struct CandidateCache {
    /// Most-recently-used entry at the back; least-recently-used (next to
    /// evict) at the front.
    entries: Vec<CandidateEntry>,
    total_bytes: usize,
    max_bytes: usize,
}

impl CandidateCache {
    pub fn new(max_bytes: usize) -> Self {
        Self {
            entries: Vec::new(),
            total_bytes: 0,
            max_bytes,
        }
    }

    /// Look up `range`'s cached preview, promoting it to most-recently-used
    /// on a hit.
    pub fn get(&mut self, range: &Range<usize>) -> Option<Vec<(String, i64)>> {
        let pos = self.entries.iter().position(|(r, _)| r == range)?;
        let entry = self.entries.remove(pos);
        let result = entry.1.clone();
        self.entries.push(entry);
        Some(result)
    }

    /// Insert (or replace) `range`'s cached preview, evicting
    /// least-recently-used entries until back under the byte budget.
    pub fn insert(&mut self, range: Range<usize>, candidates: Vec<(String, i64)>) {
        if let Some(pos) = self.entries.iter().position(|(r, _)| *r == range) {
            let (_, old) = self.entries.remove(pos);
            self.total_bytes -= candidates_bytes(&old);
        }
        self.total_bytes += candidates_bytes(&candidates);
        self.entries.push((range, candidates));
        // Always keep at least the entry just inserted, even if it alone
        // exceeds the budget.
        while self.total_bytes > self.max_bytes && self.entries.len() > 1 {
            let (_, evicted) = self.entries.remove(0);
            self.total_bytes -= candidates_bytes(&evicted);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_type_fqdns_of_an_empty_pool_is_empty() {
        let pool = DescriptorPool::new();
        assert!(all_type_fqdns(&pool).is_empty());
    }

    #[test]
    fn candidate_cache_hit_promotes_to_most_recently_used() {
        let mut cache = CandidateCache::new(1_000_000);
        cache.insert(0..10, vec![("a.A".to_string(), 1)]);
        cache.insert(10..20, vec![("b.B".to_string(), 2)]);
        assert!(cache.get(&(0..10)).is_some());
        assert!(cache.get(&(10..20)).is_some());
        assert!(cache.get(&(20..30)).is_none());
    }

    #[test]
    fn candidate_cache_evicts_least_recently_used_past_byte_budget() {
        // Each entry costs len("a.A") + 8 = 11 bytes; budget of 20 fits
        // exactly one entry at a time.
        let mut cache = CandidateCache::new(20);
        cache.insert(0..10, vec![("a.A".to_string(), 1)]);
        cache.insert(10..20, vec![("b.B".to_string(), 2)]);
        assert!(
            cache.get(&(0..10)).is_none(),
            "oldest entry should be evicted"
        );
        assert!(cache.get(&(10..20)).is_some());
    }

    #[test]
    fn candidate_cache_keeps_oversized_entry_alone() {
        let mut cache = CandidateCache::new(1);
        cache.insert(0..10, vec![("a.A".to_string(), 1), ("b.B".to_string(), 2)]);
        assert!(cache.get(&(0..10)).is_some());
    }
}
