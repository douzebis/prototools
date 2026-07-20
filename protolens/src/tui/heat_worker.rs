// SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

//! Background scoring worker thread (spec 0152) — moves every
//! remaining synchronous `inferred_candidates` call (the heat-cue
//! miss path and the override pane's `t`-key freeze) off the render/
//! input thread onto one dedicated worker thread, sharing a small
//! piece of state with it under a single mutex. See spec 0152's
//! "The approach, in plain terms" for the overall design.

use std::ops::Range;
use std::sync::{mpsc, Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};

#[cfg(test)]
use std::sync::atomic::{AtomicUsize, Ordering};

use prototext_graph::build_scoring_graph::serial::ArchivedCompiledGraph;

use super::event::AppEvent;
use super::heat_cue::{self, BoundedMru};
use super::App;
use crate::override_pane;

/// Defensive memory cap for `HeatRequestQueue` (spec 0152 G3) — a
/// purely defensive bound: entries are merged by key, not duplicated,
/// so reaching it during ordinary interactive use would mean this many
/// *distinct* ranges are simultaneously unresolved, not expected in
/// practice.
const HEAT_REQUEST_QUEUE_MAX_ENTRIES: usize = 512;

/// One request for the worker thread (spec 0152 "plain terms"/G3):
/// which node's payload range, its currently-assigned type (if any),
/// and the `[start, end)` window of the ranked candidate list actually
/// wanted.
#[derive(Clone)]
pub(super) struct HeatRequest {
    pub(super) range: Range<usize>,
    pub(super) current_key: Option<String>,
    pub(super) start: usize,
    pub(super) end: usize,
}

/// Distinguishes a request directly triggered by a user action from
/// one raised by passive background/polling code (2026-07-20
/// feedback) — `HeatRequestQueue::push`'s only means of deciding
/// whether a push may jump the queue.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Priority {
    /// Directly follows a user event (opening/navigating the override
    /// pane, toggling sort mode, scrolling past the loaded window) —
    /// promoted to the front of the queue, same as every push before
    /// this distinction existed.
    UserEvent,
    /// Passive re-check or background polling (e.g. the main pane's
    /// per-frame heat-cue glyph re-verifying its own pending status,
    /// or the override pane re-checking an outstanding request after a
    /// worker-progress wakeup) — merged into an existing entry without
    /// moving it, or, if genuinely new, queued behind whatever's
    /// already there instead of preempting it. The goal (2026-07-20
    /// feedback): the most recent thing the user actually asked for
    /// stays at the front even while unrelated background traffic
    /// keeps touching the queue.
    Background,
}

struct HeatRequestQueueState {
    mru: BoundedMru<usize, HeatRequest>,
    stop: bool,
}

/// Merge-on-push, most-recently-touched-first request queue (spec
/// 0152 G3) — asking again for a range that's already queued merges
/// into the existing entry (union window, newest `current_key` wins)
/// and moves it to the front, rather than piling up a second entry.
pub(super) struct HeatRequestQueue {
    state: Mutex<HeatRequestQueueState>,
    condvar: Condvar,
}

impl HeatRequestQueue {
    fn new() -> Self {
        HeatRequestQueue {
            state: Mutex::new(HeatRequestQueueState {
                mru: BoundedMru::new(HEAT_REQUEST_QUEUE_MAX_ENTRIES),
                stop: false,
            }),
            condvar: Condvar::new(),
        }
    }

    /// `priority` (2026-07-20 feedback) governs where a push lands, not
    /// whether it merges: merging by `range.start` (union window,
    /// newest `current_key` wins) happens either way. `UserEvent`
    /// always promotes to the front, as every push did before this
    /// distinction existed. `Background` merges in place (no reorder)
    /// if the key is already queued, or appends behind whatever's
    /// already there if it's genuinely new — so passive polling can
    /// never preempt a request a user action already queued.
    fn push(&self, req: HeatRequest, priority: Priority) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let key = req.range.start;
        let existing = state.mru.peek(&key);
        let merged = match &existing {
            Some(existing) => HeatRequest {
                range: req.range.clone(),
                current_key: req.current_key.clone(),
                start: existing.start.min(req.start),
                end: existing.end.max(req.end),
            },
            None => req,
        };
        match (priority, existing.is_some()) {
            (Priority::UserEvent, _) => state.mru.insert(key, merged),
            (Priority::Background, true) => state.mru.update_in_place(&key, merged),
            (Priority::Background, false) => state.mru.insert_back(key, merged),
        }
        self.condvar.notify_one();
    }

    /// Blocks until a request is available or `stop` is set; pops the
    /// most-recently-touched entry. `None` once `stop` is set — checked
    /// *before* popping, so a `shutdown()` mid-backlog abandons whatever
    /// is still queued instead of draining it first (each entry can be
    /// an expensive `inferred_candidates` call; the one request already
    /// popped and mid-flight when `stop` was set still finishes
    /// normally — unavoidable, and bounded to one item).
    fn pop_blocking(&self) -> Option<(usize, HeatRequest)> {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        loop {
            if state.stop {
                return None;
            }
            if let Some(entry) = state.mru.pop_mru() {
                return Some(entry);
            }
            state = self.condvar.wait(state).unwrap_or_else(|e| e.into_inner());
        }
    }

    fn signal_stop(&self) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.stop = true;
        self.condvar.notify_all();
    }

    /// Test-only entry-count introspection (spec 0152 test plan).
    #[cfg(test)]
    fn len(&self) -> usize {
        let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.mru.len()
    }
}

/// One range's cached scoring results (spec 0152 G4) — the merge
/// target for spec 0151's separate `range_stats`/`candidates` caches:
/// both were always derived from the same `inferred_candidates` call,
/// so keeping them as one entry avoids a second lookup/insert for
/// what is, underneath, one piece of data.
#[derive(Clone)]
pub(super) struct RangeHeatEntry {
    pub(super) best_score: Option<i64>,
    pub(super) best_count: usize,
    /// Ranked candidates `[0, top_n.len())`.
    pub(super) top_n: Vec<(String, i64)>,
}

/// The most recently fully-scored range and its complete candidate
/// list — factored into a named type to keep clippy's
/// `type_complexity` lint happy.
type CompleteSlot = (Range<usize>, Vec<(String, i64)>);

/// The shared cache (spec 0152 G4) — both the render/input thread and
/// the worker thread read and write this same structure directly,
/// under `App::heat_caches`' single `Mutex`.
pub(super) struct HeatCaches {
    /// Keyed by a node's tag/length-stripped payload range's `start`
    /// offset.
    pub(super) by_range: BoundedMru<usize, RangeHeatEntry>,
    /// The current type's exact score — kept separate from `by_range`
    /// because it's keyed on an orthogonal axis (the currently-
    /// assigned type, which changes independently of a range's
    /// candidate list on every override edit) and because it may not
    /// be one of `top_n`'s entries at all.
    pub(super) current_score: BoundedMru<(usize, String), Option<i64>>,
    /// The most recently *fully* scored range's complete candidate
    /// list — a single slot, not a cache: only one override pane can
    /// be open at a time. Refreshed unconditionally by the worker
    /// every time it fully scores *any* range (G5).
    pub(super) complete: Option<CompleteSlot>,
}

impl HeatCaches {
    pub(super) fn new(max_entries: usize) -> Self {
        HeatCaches {
            by_range: BoundedMru::new(max_entries),
            current_score: BoundedMru::new(max_entries),
            complete: None,
        }
    }

    /// Pure, read-only lookup, no side effects, no access to the queue
    /// (spec 0152 G4): `Some` (a clone of) the answer for `[start,
    /// end)` if either `by_range`'s `top_n` already covers it, or
    /// `complete` holds this exact range; `None` otherwise.
    ///
    /// `complete` is always the true, unbounded, fully-scored
    /// candidate list for whichever range it matches (spec 0152 G5),
    /// so unlike `top_n` — a growable prefix that can genuinely still
    /// be incomplete — a `complete` hit is clamped to its own length
    /// rather than requiring `candidates.len() >= end`. Without this,
    /// a node whose real candidate-type count is smaller than the
    /// window bound (e.g. `override_list_height`, seeded from the
    /// raw terminal height) could never report a hit even after the
    /// worker finished scoring it, leaving callers to busy-loop.
    pub(super) fn window(
        &self,
        range_start: usize,
        start: usize,
        end: usize,
    ) -> Option<Vec<(String, i64)>> {
        if let Some(entry) = self.by_range.peek(&range_start) {
            if entry.top_n.len() >= end {
                return Some(entry.top_n[start..end].to_vec());
            }
        }
        if let Some((range, candidates)) = &self.complete {
            if range.start == range_start {
                let end = end.min(candidates.len());
                let start = start.min(end);
                return Some(candidates[start..end].to_vec());
            }
        }
        None
    }
}

impl App {
    /// The one thing rendering code calls (spec 0152 G6) — used by
    /// both `heat_cue_for` and the override pane. Checks whether the
    /// cache already answers `[start, end)` for `range` — and, when
    /// `current_key` is given, whether that type's exact score is
    /// cached too (both must hold; `current_key: None` — the override
    /// pane's case, G7 — only requires the window itself). On a hit,
    /// returns the data. On a miss, pushes a `HeatRequest` (merging
    /// with the queue's own semantics, G3) and returns `None` —
    /// "pending". `priority` (2026-07-20 feedback) is forwarded
    /// unchanged to `HeatRequestQueue::push` — see `Priority`'s own
    /// doc comment.
    pub(super) fn heat_lookup(
        &self,
        range: &Range<usize>,
        current_key: Option<&str>,
        start: usize,
        end: usize,
        priority: Priority,
    ) -> Option<Vec<(String, i64)>> {
        let ready = {
            let c = self.heat_caches.lock().unwrap_or_else(|e| e.into_inner());
            let window = c.window(range.start, start, end);
            let current_ready = current_key.is_none_or(|k| {
                c.current_score
                    .peek(&(range.start, k.to_string()))
                    .is_some()
            });
            window.filter(|_| current_ready)
        };
        if ready.is_some() {
            return ready;
        }
        if let Some(worker) = &self.heat_worker {
            worker.push(
                HeatRequest {
                    range: range.clone(),
                    current_key: current_key.map(str::to_string),
                    start,
                    end,
                },
                priority,
            );
        }
        None
    }
}

/// Worker loop body (spec 0152 G5): block until a request is
/// available, pop the most-recently-touched one, lock the cache
/// briefly to double-check it's still actually missing (cheap
/// insurance against a request satisfied by something else between
/// being queued and being popped — not the primary dedup mechanism,
/// G3's merge-on-push is), then, if still missing, run the one real
/// expensive call with no lock held, then re-lock briefly to write
/// everything just learned into the shared cache, then notify the
/// main thread before looping again.
/// Test-only call counter (spec 0152 test plan) — proves the "no
/// second `score_all` call" claim for a request the cache already
/// covers by the time the worker re-checks it.
#[cfg(test)]
pub(super) static TEST_INFERRED_CANDIDATES_CALLS: AtomicUsize = AtomicUsize::new(0);

pub(super) fn heat_worker_loop(
    queue: Arc<HeatRequestQueue>,
    caches: Arc<Mutex<HeatCaches>>,
    graph: &'static ArchivedCompiledGraph,
    blob: Arc<Vec<u8>>,
    progress: mpsc::Sender<AppEvent>,
) {
    while let Some((start, req)) = queue.pop_blocking() {
        let (covers_window, covers_current) = {
            let c = caches.lock().unwrap_or_else(|e| e.into_inner());
            let covers_window = c
                .by_range
                .peek(&start)
                .is_some_and(|e| e.top_n.len() >= req.end);
            let covers_current = req
                .current_key
                .as_deref()
                .is_none_or(|k| c.current_score.peek(&(start, k.to_string())).is_some());
            (covers_window, covers_current)
        };
        match (covers_window, covers_current) {
            (true, true) => {} // already done
            (true, false) => {
                // Spec 0154 G2: the window is already cached — only the
                // current type's exact score is missing. Fill just that,
                // via the cheap `score_one`-backed fast path, instead of
                // re-running a full `score_all` sweep over every root.
                let range_bytes = &blob[req.range.clone()];
                let key = req
                    .current_key
                    .as_deref()
                    .expect("covers_current false implies current_key is Some");
                let score = override_pane::inferred_score(range_bytes, key, graph);
                let mut c = caches.lock().unwrap_or_else(|e| e.into_inner());
                c.current_score.insert((start, key.to_string()), score);
            }
            (false, _) => {
                let range_bytes = &blob[req.range.clone()];
                #[cfg(test)]
                TEST_INFERRED_CANDIDATES_CALLS.fetch_add(1, Ordering::SeqCst);
                let candidates = override_pane::inferred_candidates(range_bytes, graph);
                let stats = heat_cue::derive_stats(&candidates);
                let current_score = req
                    .current_key
                    .as_deref()
                    .and_then(|k| heat_cue::score_of(&candidates, k));
                let mut c = caches.lock().unwrap_or_else(|e| e.into_inner());
                let top_n_len = c
                    .by_range
                    .get(&start)
                    .map_or(0, |e| e.top_n.len())
                    .max(req.end);
                c.by_range.insert(
                    start,
                    RangeHeatEntry {
                        best_score: stats.best_score,
                        best_count: stats.best_count,
                        top_n: candidates.iter().take(top_n_len.max(1)).cloned().collect(),
                    },
                );
                if let Some(key) = &req.current_key {
                    c.current_score.insert((start, key.clone()), current_score);
                }
                c.complete = Some((req.range.clone(), candidates)); // always refreshed
            }
        }
        let _ = progress.send(AppEvent::HeatWorkerProgress);
    }
}

/// Owns the worker thread's join handle and its request queue (spec
/// 0152 Specification). `Drop` covers the one shutdown path an
/// explicit `shutdown()` call can't reach — a panic unwinding through
/// `run_loop` before that call — see "Shutdown and safety" in spec
/// 0152.
pub(super) struct HeatWorkerHandle {
    queue: Arc<HeatRequestQueue>,
    join: Option<JoinHandle<()>>,
}

impl HeatWorkerHandle {
    pub(super) fn spawn(
        caches: Arc<Mutex<HeatCaches>>,
        graph: &'static ArchivedCompiledGraph,
        blob: Arc<Vec<u8>>,
        progress: mpsc::Sender<AppEvent>,
    ) -> Self {
        let queue = Arc::new(HeatRequestQueue::new());
        let worker_queue = Arc::clone(&queue);
        let join =
            thread::spawn(move || heat_worker_loop(worker_queue, caches, graph, blob, progress));
        HeatWorkerHandle {
            queue,
            join: Some(join),
        }
    }

    pub(super) fn push(&self, req: HeatRequest, priority: Priority) {
        self.queue.push(req, priority);
    }

    /// Signal stop, then block until the worker exits. Shared body
    /// with `Drop` below.
    fn shutdown_inner(&mut self) {
        self.queue.signal_stop();
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }

    pub(super) fn shutdown(mut self) {
        self.shutdown_inner();
    }

    /// Test-only queue-length introspection (spec 0152 test plan).
    #[cfg(test)]
    pub(super) fn queue_len(&self) -> usize {
        self.queue.len()
    }

    /// Test-only construction (spec 0152 test plan) — a live queue
    /// with no spawned thread, so App-level "exactly one request
    /// pushed" tests can inspect the queue deterministically instead
    /// of racing a real worker thread that drains it near-instantly.
    #[cfg(test)]
    pub(super) fn stub_for_test() -> Self {
        HeatWorkerHandle {
            queue: Arc::new(HeatRequestQueue::new()),
            join: None,
        }
    }
}

impl Drop for HeatWorkerHandle {
    fn drop(&mut self) {
        self.shutdown_inner();
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use prototext_graph::build_scoring_graph::build_from_strings;
    use prototext_graph::score::load::LoadedGraph;

    use super::*;

    fn req(range_start: usize, start: usize, end: usize) -> HeatRequest {
        HeatRequest {
            range: range_start..range_start + 1,
            current_key: None,
            start,
            end,
        }
    }

    // ── HeatRequestQueue (spec 0152 test plan) ──────────────────────

    /// Pushing the same `range.start` twice with different `[start,
    /// end)` windows yields one entry whose window is the union, not
    /// two entries (G3's merge-on-push behavior); the later push's
    /// `current_key` wins.
    #[test]
    fn push_merges_same_range_start_into_union_window() {
        let queue = HeatRequestQueue::new();
        queue.push(
            HeatRequest {
                range: 5..10,
                current_key: None,
                start: 0,
                end: 2,
            },
            Priority::UserEvent,
        );
        queue.push(
            HeatRequest {
                range: 5..10,
                current_key: Some("x".to_string()),
                start: 1,
                end: 5,
            },
            Priority::UserEvent,
        );
        assert_eq!(queue.len(), 1, "same range.start must merge into one entry");
        let (key, merged) = queue.pop_blocking().unwrap();
        assert_eq!(key, 5);
        assert_eq!(merged.start, 0);
        assert_eq!(merged.end, 5);
        assert_eq!(merged.current_key.as_deref(), Some("x"));
    }

    /// Pushing distinct ranges pops the most-recently-pushed one first
    /// (LIFO/MRU order across distinct keys); a later merging push for
    /// an already-queued key re-promotes it to the front.
    #[test]
    fn pop_returns_most_recently_pushed_or_merged_first() {
        let queue = HeatRequestQueue::new();
        queue.push(req(1, 0, 1), Priority::UserEvent);
        queue.push(req(2, 0, 1), Priority::UserEvent);
        queue.push(req(3, 0, 1), Priority::UserEvent);
        assert_eq!(queue.pop_blocking().unwrap().0, 3);
        assert_eq!(queue.pop_blocking().unwrap().0, 2);
        assert_eq!(queue.pop_blocking().unwrap().0, 1);

        queue.push(req(1, 0, 1), Priority::UserEvent);
        queue.push(req(2, 0, 1), Priority::UserEvent);
        // Re-touch key 1 via a merging push — moves it back to the front.
        queue.push(req(1, 0, 1), Priority::UserEvent);
        assert_eq!(queue.pop_blocking().unwrap().0, 1);
        assert_eq!(queue.pop_blocking().unwrap().0, 2);
    }

    /// 2026-07-20 feedback: a `Priority::Background` push for a
    /// brand-new key must not preempt a `Priority::UserEvent` request
    /// already queued — it's appended behind it instead of promoted to
    /// the front.
    #[test]
    fn background_push_of_a_new_key_does_not_preempt_a_queued_user_event() {
        let queue = HeatRequestQueue::new();
        queue.push(req(1, 0, 1), Priority::UserEvent);
        queue.push(req(2, 0, 1), Priority::Background);
        assert_eq!(
            queue.pop_blocking().unwrap().0,
            1,
            "the user-event request must still pop first"
        );
        assert_eq!(queue.pop_blocking().unwrap().0, 2);
    }

    /// A `Priority::Background` push that merges into an *already-
    /// queued* entry updates its window/`current_key` in place without
    /// moving it — a later `UserEvent` push for a different key stays
    /// ahead of it.
    #[test]
    fn background_push_merging_an_existing_entry_does_not_reorder_it() {
        let queue = HeatRequestQueue::new();
        queue.push(req(1, 0, 1), Priority::UserEvent);
        queue.push(req(2, 0, 1), Priority::UserEvent);
        // Re-touch key 1 in the background — merges its window but must
        // not re-promote it ahead of key 2.
        queue.push(req(1, 1, 3), Priority::Background);
        assert_eq!(
            queue.pop_blocking().unwrap().0,
            2,
            "key 2 must still pop first — the background push must not reorder key 1"
        );
        let (key, merged) = queue.pop_blocking().unwrap();
        assert_eq!(key, 1);
        assert_eq!(
            (merged.start, merged.end),
            (0, 3),
            "the background push's window must still be merged in"
        );
    }

    /// Pushing past `HEAT_REQUEST_QUEUE_MAX_ENTRIES` caps the queue
    /// length, dropping the least-recently-touched entry first.
    #[test]
    fn push_past_capacity_evicts_least_recently_touched() {
        let queue = HeatRequestQueue::new();
        for start in 0..HEAT_REQUEST_QUEUE_MAX_ENTRIES {
            queue.push(req(start, 0, 1), Priority::UserEvent);
        }
        assert_eq!(queue.len(), HEAT_REQUEST_QUEUE_MAX_ENTRIES);
        queue.push(
            req(HEAT_REQUEST_QUEUE_MAX_ENTRIES, 0, 1),
            Priority::UserEvent,
        );
        assert_eq!(
            queue.len(),
            HEAT_REQUEST_QUEUE_MAX_ENTRIES,
            "must stay capped"
        );
        let state = queue.state.lock().unwrap();
        assert!(
            state.mru.peek(&0).is_none(),
            "the least-recently-touched entry must be evicted"
        );
        assert!(state.mru.peek(&HEAT_REQUEST_QUEUE_MAX_ENTRIES).is_some());
    }

    /// `pop_blocking` on a spawned thread against an empty queue
    /// blocks until `signal_stop()` (called from this test thread)
    /// wakes it, at which point it returns `None` and the thread joins
    /// promptly.
    #[test]
    fn pop_blocking_returns_none_after_signal_stop() {
        let queue = Arc::new(HeatRequestQueue::new());
        let worker_queue = Arc::clone(&queue);
        let join = thread::spawn(move || worker_queue.pop_blocking());
        thread::sleep(Duration::from_millis(20)); // let the thread start blocking
        queue.signal_stop();
        let result = join.join().expect("worker thread must not panic");
        assert!(result.is_none());
    }

    // ── HeatCaches / worker round trip (spec 0152 test plan) ────────

    /// A minimal, real, in-memory scoring graph — one message with a
    /// single `uint64` field — built with zero file I/O via
    /// `build_from_strings` + `Box::leak` + `LoadedGraph::
    /// from_static_bytes` (as spec 0151's own notes anticipated).
    fn test_scoring_graph() -> LoadedGraph {
        let yaml = "\
entries:
- Msg
messages:
  Msg:
    fields:
    - number: 1
      type: uint64
"
        .to_string();
        let (bytes, _, _) =
            build_from_strings(&[yaml], false, false, |_, _| {}).expect("test graph must build");
        let bytes: &'static [u8] = Box::leak(bytes.into_boxed_slice());
        LoadedGraph::from_static_bytes(bytes).expect("test graph must load")
    }

    /// Real worker thread, real tiny in-memory graph, no file I/O:
    /// pushing a request populates `by_range` with the same answer a
    /// direct, synchronous `inferred_candidates`/`derive_stats` call
    /// produces, and refreshes `complete` unconditionally (G5). A
    /// second, cache-covered request for the same range is answered
    /// without a second `score_all` call (proven via the test-only
    /// call counter).
    #[test]
    fn heat_caches_worker_round_trip() {
        let graph = test_scoring_graph();
        let graph: &'static ArchivedCompiledGraph = graph.graph;
        // A valid encoding of field 1 (varint) = 5: tag 0x08, value 0x05.
        let range_bytes = vec![0x08, 0x05];
        let blob = Arc::new(range_bytes.clone());
        let caches = Arc::new(Mutex::new(HeatCaches::new(8)));
        let (tx, rx) = mpsc::channel::<AppEvent>();
        let worker = HeatWorkerHandle::spawn(Arc::clone(&caches), graph, Arc::clone(&blob), tx);

        worker.push(
            HeatRequest {
                range: 0..2,
                current_key: None,
                start: 0,
                end: 1,
            },
            Priority::UserEvent,
        );

        // Bounded poll, not `recv` — this isn't exercising the
        // event-driven wiring, just the worker/cache contract.
        let mut entry = None;
        for _ in 0..200 {
            if let Some(e) = caches.lock().unwrap().by_range.peek(&0) {
                entry = Some(e);
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }
        let entry = entry.expect("worker must populate by_range within the bounded poll");
        // Drain the progress event the first request's completion sent.
        rx.recv_timeout(Duration::from_secs(2))
            .expect("progress must fire for the first request");

        let expected_candidates = override_pane::inferred_candidates(&range_bytes, graph);
        let expected_stats = heat_cue::derive_stats(&expected_candidates);
        assert_eq!(entry.best_score, expected_stats.best_score);
        assert_eq!(entry.best_count, expected_stats.best_count);
        let want_top_n: Vec<_> = expected_candidates.iter().take(1).cloned().collect();
        assert_eq!(entry.top_n, want_top_n);

        let complete = caches.lock().unwrap().complete.clone();
        assert_eq!(complete, Some((0..2, expected_candidates.clone())));

        let calls_before = TEST_INFERRED_CANDIDATES_CALLS.load(Ordering::SeqCst);
        worker.push(
            HeatRequest {
                range: 0..2,
                current_key: None,
                start: 0,
                end: 1,
            },
            Priority::UserEvent,
        );
        rx.recv_timeout(Duration::from_secs(2))
            .expect("progress must fire for the second request");
        let calls_after = TEST_INFERRED_CANDIDATES_CALLS.load(Ordering::SeqCst);
        assert_eq!(
            calls_after, calls_before,
            "a cache-covered request must not re-score"
        );

        worker.shutdown();
    }

    /// W-01 (spec 0154 test plan): once a range's window is already
    /// cached, a request for that same range whose `current_key` isn't
    /// cached yet is served by the cheap `score_one`-backed fast path —
    /// no additional `inferred_candidates` sweep (the existing
    /// `TEST_INFERRED_CANDIDATES_CALLS` counter stays flat), and
    /// `by_range`/`complete` are left untouched, only `current_score`
    /// gains the new entry. (W-02 — the full-sweep path itself — is
    /// covered by `heat_caches_worker_round_trip` above.)
    #[test]
    fn worker_uses_cheap_fast_path_when_only_current_is_missing() {
        let graph = test_scoring_graph();
        let graph: &'static ArchivedCompiledGraph = graph.graph;
        let range_bytes = vec![0x08, 0x05];
        let blob = Arc::new(range_bytes.clone());
        let caches = Arc::new(Mutex::new(HeatCaches::new(8)));
        let (tx, rx) = mpsc::channel::<AppEvent>();
        let worker = HeatWorkerHandle::spawn(Arc::clone(&caches), graph, Arc::clone(&blob), tx);

        // Prime the window via a full sweep first.
        worker.push(
            HeatRequest {
                range: 0..2,
                current_key: None,
                start: 0,
                end: 1,
            },
            Priority::UserEvent,
        );
        rx.recv_timeout(Duration::from_secs(2))
            .expect("progress must fire for the priming request");
        let (by_range_before, complete_before) = {
            let c = caches.lock().unwrap();
            let entry = c.by_range.peek(&0).expect("window must be primed");
            (
                (entry.best_score, entry.best_count, entry.top_n.clone()),
                c.complete.clone(),
            )
        };
        let calls_before = TEST_INFERRED_CANDIDATES_CALLS.load(Ordering::SeqCst);

        // Ask again for the same window, now with a current_key that
        // isn't cached yet.
        worker.push(
            HeatRequest {
                range: 0..2,
                current_key: Some("Msg".to_string()),
                start: 0,
                end: 1,
            },
            Priority::UserEvent,
        );
        rx.recv_timeout(Duration::from_secs(2))
            .expect("progress must fire for the cheap-path request");

        let calls_after = TEST_INFERRED_CANDIDATES_CALLS.load(Ordering::SeqCst);
        assert_eq!(
            calls_after, calls_before,
            "the cheap fast path must not re-run a full score_all sweep"
        );
        let c = caches.lock().unwrap();
        assert!(
            c.current_score.peek(&(0, "Msg".to_string())).is_some(),
            "current_score must be filled by the fast path"
        );
        let entry = c.by_range.peek(&0).unwrap();
        assert_eq!(
            (entry.best_score, entry.best_count, entry.top_n.clone()),
            by_range_before,
            "by_range must be untouched by the cheap path"
        );
        assert_eq!(
            c.complete, complete_before,
            "complete must be untouched by the cheap path"
        );
        drop(c);
        worker.shutdown();
    }
}
