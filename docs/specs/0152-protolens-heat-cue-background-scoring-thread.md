<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0152 — protolens: heat-cue background scoring thread

Status: implemented
App: protolens
Implemented in: 2026-07-19
Refs: docs/specs/0151-protolens-heat-cue-cache-and-startup-progress.md
      ("step 1" — the caching redesign this spec builds on, and N7,
      whose sketch this spec supersedes with a fully worked-out
      design), `protolens/src/tui/heat_cue.rs` (`heat_cue_for`,
      `derive_stats`, `score_of` — reused, not redefined),
      `protolens/src/tui/override_select.rs`
      (`recompute_override_candidates`, `upgrade_active_override_to_
      complete` — the second freeze point this spec also fixes),
      `protolens/src/override_pane.rs` (`inferred_candidates`),
      `prototext-graph/src/score/load.rs` (`LoadedGraph`),
      `prototext-graph/src/build_scoring_graph/mod.rs`
      (`build_from_strings` — this spec's test plan uses it to build a
      real in-memory graph without file I/O)

## Background

Spec 0151 ("step 1") fixed the *recurring* per-render cost of
heat-cue computation (a cached range is never rescored) and gave the
*initial* viewport's one-time scoring cost visible progress (G8's
warm-up pass). What it deliberately left synchronous (its own N7,
deferred as "step 2") is every other first visit to a range during
the interactive session — scrolling into new territory, or editing an
override — each of which still calls `inferred_candidates` (a full
`score_all` walk) directly on the render/input thread, blocking all
input until it returns (measured ≈1.35s for one representative range
against a large real-world corpus; see spec 0151's Background).

A second, independent freeze point has the identical shape: pressing
`t` to open the override pane on a node whose range has never been
scored calls `inferred_candidates` synchronously too
(`recompute_override_candidates`'s `SortMode::Inferred` miss branch),
and scrolling an already-open pane's list past a *capped* preview's
last row (`upgrade_active_override_to_complete`) does the same to
fetch the complete ranked list. Both are the same underlying bug as
the heat-cue one: an implicit or explicit request for
`inferred_candidates` results that happens to miss every cache blocks
the whole UI for as long as `score_all` takes.

This spec moves every one of these remaining synchronous calls off
the render/input thread, onto one dedicated worker thread, sharing
one small piece of state between the two threads under a single
mutex — and, since a synchronous freeze is only half the problem
(the other half being "how does the UI *notice* an answer landed
without wasting CPU polling for it"), it also replaces the render
loop's own input handling with a small event-driven design so the
main thread can *sleep* until something worth reacting to happens,
rather than waking up on a fixed schedule "just in case."

## The approach, in plain terms

There are exactly two pieces of state shared between the main
thread and the worker thread, both cheap to reason about because
every read/write of them is a handful of `Vec` operations with no
I/O, held only as long as it takes to do those operations:

1. **A shared cache** (`Arc<Mutex<HeatCaches>>`). **Both threads read
   and write this same structure directly.** There is no separate
   "response" message and no channel carrying scoring results: the
   worker's answer *is* it writing into this shared cache, and the
   main thread's answer *is* it re-reading the same cache once it's
   been told (see point 3 below) that something may have changed.
2. **A request queue** (`Arc<HeatRequestQueue>`) — not a plain stack
   this time, but a small `Mutex`+`Condvar`-guarded structure keyed
   by range, so that asking again for a range that's already queued
   *merges into* the existing entry and moves it to the front,
   rather than piling up a second entry. A request is:
   ```rust
   struct HeatRequest {
       range: Range<usize>,          // which node's payload range
       current_key: Option<String>,  // its currently-assigned type, if any
       start: usize,                 // [start, end) — the window of the
       end: usize,                   // ranked candidate list actually wanted
   }
   ```
   `[0, 8)` is what a heat cue asks for; `[0, page_size)` is the
   override pane's first page; `[page_size, 2*page_size)` is what
   paging to the second page asks for. There's no separate "give me
   everything" flag: asking for a big enough `end` *is* asking for
   (most of) everything, and — see G5 — the worker always fully
   scores a range as a side effect of answering *any* window, so
   `end` only ever affects what's cached, never how much work the
   worker actually does underneath.

   Rendering code never touches the cache or the queue directly — it
   calls one function, `App::heat_lookup(range, current_key, start,
   end) -> Option<Vec<(String, i64)>>` (G6), used by both `heat_cue_
   for` and the override pane. Internally, `heat_lookup` checks
   whether the cache *already* covers `[start, end)` for this range —
   and, when `current_key` is given, whether that type's exact score
   is cached too — via `HeatCaches::window`, a pure, read-only lookup
   with no side effects and no access to the queue. On a hit,
   `heat_lookup` returns the data immediately, no request involved.
   On a miss, it pushes a request onto the worker's queue itself and
   returns `None` ('pending') — rendering code never has to remember
   to push separately. This matters concretely for `t`: heat cues are
   computed proactively as the user scrolls, so by the time `t` is
   pressed on a visible node, that node's preview is very often
   *already* cached — `heat_lookup` returns it on the spot, no request
   ever queued.

The worker thread loops: block until a request is available, pop the
most-recently-touched one, lock the cache **briefly** to double-check
it's still actually missing (cheap insurance against a request that
was satisfied by something else between being queued and being
popped), then, if still missing, release the lock and run the one
real expensive call (`inferred_candidates`, no lock held), then
re-lock **briefly** to write everything it just learned into the
shared cache, then **send a small "I made progress" notification**
(point 3) before looping again.

3. **How the main thread finds out.** This is the part that changes
   most from earlier drafts of this spec: instead of the render loop
   waking up on a fixed timer to go check whether anything landed, a
   dedicated *input-reader* thread and the worker thread both feed
   one shared channel of a small `AppEvent` enum (terminal input, or
   "the worker made progress"), and the main thread's loop simply
   blocks on that one channel — real sleep, not a poll loop — waking
   only for a keypress, a mouse event, an existing deadline (message/
   splash auto-dismiss, unchanged from spec 0147), or a worker
   progress notification. See G8.

## Goals

### Threading model

- **G1. One dedicated worker thread**, spawned once per session inside
  `tui::run()`, after G8/spec-0151's warm-up pass completes and
  before `run_loop` starts — see N2 for why the warm-up pass itself
  stays synchronous and untouched. Spawned only when
  `app.ctx.graph.is_some()` (mirroring the warm-up pass's own gate):
  with no scoring graph, `app.heat_worker` stays `None` for the whole
  session, and every fork below that checks `heat_worker.is_some()`
  falls through to the existing synchronous logic — a graph-less
  session behaves exactly as today, zero threads spawned.
- **G2. The worker's only *external* dependency is immutable, `'static`
  data**, established once at spawn time:
  - `graph: &'static ArchivedCompiledGraph` — copied out of
    `app.ctx.graph` (`LoadedGraph::graph` is already typed
    `&'static ArchivedCompiledGraph`; see G9 for the safety
    obligation this creates).
  - `blob: Arc<Vec<u8>>` — **one** `Arc::new(app.blob.clone())` at
    spawn time (a single, one-time O(blob-size) clone for the whole
    session, not a per-request clone). `app.blob` is never reassigned
    after `App::new` (confirmed: no other assignment to `self.blob`
    exists anywhere in `tui/`), so this `Arc` and `app.blob` stay
    byte-identical for the worker's entire lifetime; the worker slices
    its own `Arc<Vec<u8>>` by each request's `Range<usize>`.

  Beyond these two `'static`/session-long values, the worker's *only*
  other shared state is the cache and the queue — it never touches
  any other `App` field, and it never touches terminal I/O.
- **G3. Request queue — merge-on-push, most-recently-touched-first.**
  Rather than a plain `Vec`-backed LIFO stack, the queue reuses the
  same `BoundedMru<K, V>` shape spec 0151 introduced for the caches
  (see spec 0151 G1/G4) — because "push, deduping and promoting an
  existing entry with the same key to the front" is *exactly*
  `BoundedMru::insert`'s existing behavior:
  ```rust
  struct HeatRequestQueueState {
      mru: heat_cue::BoundedMru<usize, HeatRequest>, // keyed by range.start
      stop: bool,
  }
  struct HeatRequestQueue {
      state: Mutex<HeatRequestQueueState>,
      condvar: Condvar,
  }
  ```
  - `push(req)`: locks, looks up `req.range.start` — if an entry
    already exists (still queued, not yet popped), **merges** it with
    `req` (`start = min(existing.start, req.start)`, `end =
    max(existing.end, req.end)`, `current_key = req.current_key` — the
    newest observed current type wins, since it's the one that matters
    going forward), then `insert`s the merged value (which, per
    `BoundedMru::insert`'s existing semantics, both updates the entry
    *and* moves it to the most-recently-used end). No entry, no merge —
    just `insert`s `req` as-is. Either way, `condvar.notify_one()`.
  - `BoundedMru` gains one small new method for this spec,
    `pop_mru(&mut self) -> Option<(K, V)>` — removes and returns the
    most-recently-used (last) entry, the queue's counterpart to the
    existing `get`/`insert`. (`peek`, spec 0151's non-promoting read,
    is reused as-is by G5 below — no new addition needed there.)
  - `pop_blocking`: locks, blocks on the condvar while `mru` is empty
    and `stop` is unset, then `pop_mru()`s the front; returns `None`
    once `stop` is set and `mru` is empty — the worker's sole exit
    condition.
  - Bounded (`HEAT_REQUEST_QUEUE_MAX_ENTRIES = 512`, spec 0151's
    `BoundedMru::insert` eviction, unchanged): a purely defensive
    memory cap. Because entries are merged by key rather than
    duplicated, reaching this bound during ordinary interactive use
    (scrolling, editing) would mean 512 *distinct* ranges are
    simultaneously unresolved — not expected in practice, but if it
    happens, eviction just means the least-recently-touched of those
    ranges is re-asked-for on its next observed miss, same as spec
    0151's cache eviction story.

  This directly replaces the earlier "no dedup, `AtomicUsize`
  outstanding counter" design: because both sides of a request
  (the range it's for) are already checked for cache-sufficiency
  *before* ever reaching the queue (G6/G7), and the queue itself now
  merges same-range requests instead of stacking duplicates, there's
  no separate outstanding-count bookkeeping needed for anything —
  wakeups are event-driven (G8), not counter-driven.
- **G4. The shared cache.**
  ```rust
  struct RangeHeatEntry {
      best_score: Option<i64>,
      best_count: usize,
      /// Ranked candidates `[0, top_n.len())` — the merge target for
      /// spec 0151's separate `range_stats` and `candidates` caches:
      /// both were always derived from the same `inferred_candidates`
      /// call, so keeping them as one entry avoids a second lookup/
      /// insert for what is, underneath, one piece of data.
      top_n: Vec<(String, i64)>,
  }
  struct HeatCaches {
      by_range: heat_cue::BoundedMru<usize, RangeHeatEntry>, // keyed by range.start
      /// The current type's exact score — kept separate from
      /// `by_range` because it's keyed on an *orthogonal* axis
      /// (the currently-assigned type, which changes independently
      /// of a range's candidate list on every override edit) and
      /// because it may not be one of `top_n`'s entries at all (a
      /// mismatched current type can rank arbitrarily low).
      current_score: heat_cue::BoundedMru<(usize, String), Option<i64>>,
      /// The most recently *fully* scored range's complete candidate
      /// list — a single slot, not a cache: only one override pane
      /// can be open at a time, so only one complete list is ever
      /// "interesting". Refreshed unconditionally by the worker every
      /// time it fully scores *any* range (G5) — not just when the
      /// override pane asked for one — since the full list is already
      /// sitting in hand at that point at no extra cost. Consumed by
      /// whichever poll first observes it matching the pane's current
      /// target range (G7).
      complete: Option<(Range<usize>, Vec<(String, i64)>)>,
  }
  ```
  `App` holds exactly one `heat_caches: Arc<Mutex<HeatCaches>>` field,
  replacing spec 0151's three separate fields
  (`heat_range_cache`/`heat_current_score_cache`/`candidate_cache`).
  Bundling these three pieces under one lock (rather than one lock
  per field) is a deliberate simplicity choice — see spec 0151's own
  precedent for this reasoning (negligible, I/O-free critical
  sections).

  `HeatCaches` also exposes one read-only method, `window(&self,
  range_start: usize, start: usize, end: usize) -> Option<Vec<(String,
  i64)>>` — `Some` (a clone of) the answer for `[start, end)` if
  either `by_range`'s `top_n` already covers it, or `complete` holds
  this exact range and covers it; `None` otherwise. It's purely a
  "what do we already know" read: no side effects, and no access to
  the queue (it can't push anything). It's called, with the lock
  already held, from inside `App::heat_lookup` (G6) — the one place
  that *also* decides whether to push a request on a miss.

  **Poisoning:** every `.lock()` call, on both threads, uses
  `.unwrap_or_else(|poisoned| poisoned.into_inner())` rather than a
  bare `.unwrap()` — recovering the guard even if a previous holder
  panicked mid-critical-section, rather than propagating a "poisoned
  lock" panic to every future caller (which would turn one worker
  panic into a crashed *interactive session*, defeating N6's
  graceful-degradation goal).
- **G5. Worker loop body:**
  ```rust
  fn heat_worker_loop(
      queue: Arc<HeatRequestQueue>,
      caches: Arc<Mutex<HeatCaches>>,
      graph: &'static ArchivedCompiledGraph,
      blob: Arc<Vec<u8>>,
      progress: mpsc::Sender<AppEvent>,
  ) {
      while let Some((start, req)) = queue.pop_blocking() {
          let already_done = {
              let c = caches.lock().unwrap_or_else(|e| e.into_inner());
              let covers_window = c.by_range.peek(&start)
                  .is_some_and(|e| e.top_n.len() >= req.end);
              let covers_current = req.current_key.as_deref().is_none_or(|k| {
                  c.current_score.peek(&(start, k.to_string())).is_some()
              });
              covers_window && covers_current
          };
          if !already_done {
              let range_bytes = &blob[req.range.clone()];
              let candidates = override_pane::inferred_candidates(range_bytes, graph);
              let stats = heat_cue::derive_stats(&candidates);
              let current_score = req.current_key.as_deref()
                  .and_then(|k| heat_cue::score_of(&candidates, k));
              let mut c = caches.lock().unwrap_or_else(|e| e.into_inner());
              let top_n_len = c.by_range.get(&start)
                  .map_or(0, |e| e.top_n.len())
                  .max(req.end);
              c.by_range.insert(start, RangeHeatEntry {
                  best_score: stats.best_score,
                  best_count: stats.best_count,
                  top_n: candidates.iter().take(top_n_len.max(1)).cloned().collect(),
              });
              if let Some(key) = &req.current_key {
                  c.current_score.insert((start, key.clone()), current_score);
              }
              c.complete = Some((req.range.clone(), candidates)); // always refreshed
          }
          let _ = progress.send(AppEvent::HeatWorkerProgress);
      }
  }
  ```
  One `inferred_candidates` call produces everything: `stats` and
  `current_score` derived from it by reference, `top_n` a cloned
  prefix (kept at least as long as it already was, so a later,
  narrower request never *shrinks* a previously wider preview), and
  the original full `Vec` moved (not cloned again) into `complete`
  unconditionally. The "already done?" check is a cheap defensive
  double-check, not this design's primary dedup mechanism (G3's
  merge-on-push is) — it only matters for the rare case where the
  same range's answer arrived via a *different* request between this
  one being queued and being popped.

  The progress notification is sent whether or not real work was
  done (an instant skip still means "something in the cache may now
  be worth re-checking" — cheap and harmless if the main thread finds
  nothing new).
- **G6. `App::heat_lookup` — the one orchestration entry point —
  and `heat_cue_for`'s cache-miss fork** (`tui/heat_cue.rs`). Both
  this fork and G7's override-pane integration go through the same
  function, rather than each manually interleaving a cache check and
  a queue push:
  ```rust
  impl App {
      /// The one thing rendering code calls. Checks whether the
      /// cache already answers `[start, end)` for `range` — and,
      /// when `current_key` is given, whether that type's exact
      /// score is cached too (both must hold; `current_key: None` —
      /// the override pane's case, G7 — only requires the window
      /// itself). On a hit, returns the data. On a miss, pushes a
      /// `HeatRequest` (merging with the queue's own semantics, G3)
      /// and returns `None` — "pending".
      fn heat_lookup(
          &self,
          range: &Range<usize>,
          current_key: Option<&str>,
          start: usize,
          end: usize,
      ) -> Option<Vec<(String, i64)>> {
          let ready = {
              let c = self.heat_caches.lock().unwrap_or_else(|e| e.into_inner());
              let window = c.window(range.start, start, end);
              let current_ready = current_key.is_none_or(|k| {
                  c.current_score.peek(&(range.start, k.to_string())).is_some()
              });
              window.filter(|_| current_ready)
          };
          if ready.is_some() {
              return ready;
          }
          if let Some(worker) = &self.heat_worker {
              worker.push(HeatRequest {
                  range: range.clone(),
                  current_key: current_key.map(str::to_string),
                  start,
                  end,
              });
          }
          None
      }
  }
  ```
  Each node's heat-cue status is tracked with a small per-node state,
  parallel to `self.tree` (`heat_states: Vec<HeatState>`,
  `App::new`-initialized to `Pending` for every node, resized/reset
  alongside `self.tree` if it's ever rebuilt):
  ```rust
  pub(super) enum HeatState {
      Pending,                     // ask again (recheck cache) this tick
      Resolved(Option<HeatCue>),   // known — read directly, touch nothing else
  }
  ```
  (`HeatCue`/`HeatCueKind` gain `#[derive(Clone, Copy)]` — both
  already hold only `i64`/`usize` fields — so `Resolved` can be read
  by copying out, not moving.) `heat_cue_for(line_idx)`:
  1. `line_to_node` miss, hidden cues, or `!can_override` → `None`,
     exactly as spec 0151 (no `HeatState` involvement at all — these
     aren't "pending", they're "not applicable").
  2. `HeatState::Resolved(cue)` → return `cue` directly. **No cache
     lock, no re-derivation** — this is the whole point of tracking
     resolution per node instead of re-polling the shared cache for
     every visible line on every redraw.
  3. `HeatState::Pending` → `self.heat_lookup(&range, current_key.
     as_deref(), 0, HEAT_CUE_PREVIEW)` (a small fixed preview width,
     `8` — big enough to answer `heat_cue_from_stats`'s gate/level
     *and* almost always big enough to double as the override pane's
     first page, per the "plain terms" note above). On `Some(top_n)`:
     also read the range's `best_score`/`best_count` and, if
     `current_key` is `Some`, its exact score — both guaranteed
     already present in the cache at this point, since `heat_lookup`
     just confirmed the window (and, when applicable, the current
     key) are covered — derive the cue, store `Resolved(cue)`, return
     it. On `None` (the push, if any, already happened inside
     `heat_lookup`): if a worker exists, stay `Pending`, return `None`
     for this frame; if no worker (no scoring graph, or a test
     fixture), fall back to spec 0151's synchronous logic verbatim,
     then store `Resolved(cue)`.
  Once *any* HeatState transitions from `Pending` to `Resolved` (only
  ever driven by a fresh cache check, itself only ever attempted on a
  worker-progress wakeup or a real redraw-triggering input event —
  see G8), that node is never touched again until something
  invalidates it: an override edit for that node resets its
  `heat_states[idx]` back to `Pending` (the exact call site(s) — the
  point(s) in `override_select.rs`/`resettle_node` where a node's
  *effective* current type changes — to be pinned down precisely
  during implementation by direct inspection, mirroring how spec
  0151's own cache-invalidation call sites were enumerated).
- **G7. Override-pane integration** (`tui/override_select.rs`) — the
  fix for the `t`-key freeze, using the same `App::heat_lookup` entry
  point G6 introduces, generalized to an arbitrary `[start, end)`
  rather than always `[0, HEAT_CUE_PREVIEW)`, and always called with
  `current_key: None` (the override pane never needs one specific
  type's exact score — it's just displaying a ranked list, not a
  mismatch comparison):
  - `recompute_override_candidates`'s `SortMode::Inferred` branch: on
    `self.heat_lookup(&range, None, 0, self.override_list_height)`
    returning `None` for the pane's first page (the request itself
    already pushed inside `heat_lookup`), set a new
    `self.override_candidates_pending = true`, and leave
    `override_candidates` as whatever it already was (typically
    empty, for a freshly opened pane) — the pane opens immediately,
    showing a plain "Scoring candidates…" line (reusing `self.message`,
    same one-line-status convention as spec 0151 G8's warm-up
    placeholder — not a spinner, see N3) in place of the list, rather
    than blocking. On `Some`, applies it immediately — no request at
    all, satisfying the "don't trigger a `score_all` if the partial
    cache already covers `t`'s initial pan" requirement directly:
    since heat cues proactively populate `top_n` at `[0,
    HEAT_CUE_PREVIEW)` as the user scrolls, and `override_list_height`
    is typically `<= HEAT_CUE_PREVIEW` (both are small, single-screen
    preview sizes), the common case is a `heat_lookup` hit with zero
    worker involvement.
  - `upgrade_active_override_to_complete` (scrolling an open pane's
    list past its currently-loaded window): computes the next
    window's `[start, end)` (current length, current length +
    another page) and calls `self.heat_lookup(&range, None, start,
    end)` the same way — a hit (e.g. already satisfied by `complete`
    holding this same range, perhaps filled as a free side effect of
    an *unrelated* heat-cue request for this same node) applies
    immediately; a miss (the request already pushed inside
    `heat_lookup`) sets `self.override_complete_pending = true` and
    leaves the pane's list at its current length — scrolling simply
    clamps at the boundary (not stuck, not broken) until the answer
    lands.
  - A new `App::poll_pending_override_work()`, called whenever the
    main thread wakes for a worker-progress event (G8) *and* either
    pending flag is set: re-runs the relevant `heat_lookup` call for
    whichever flag(s) are set; a hit applies the result and clears
    the flag; a miss (still pending — and, since `heat_lookup` would
    just re-push the same request, merged by range per G3, this is
    harmless) leaves both alone.
  - Both pending flags are simply reset to `false` whenever the pane
    closes or retargets to a different node (`close_override`,
    `toggle_override`'s re-open path) — the in-flight worker request
    itself is *not* cancelled (N7 still applies); it finishes and
    writes into the shared cache regardless, which is harmless (and
    useful, if that same range is revisited later) — the pane simply
    stops *waiting* for it.
- **G8. Event-driven main loop — no fixed-interval polling.** A new
  small enum and a dedicated input-reader thread, both introduced in
  a new `tui/event.rs`:
  ```rust
  pub(super) enum AppEvent {
      Term(crossterm::event::Event),
      HeatWorkerProgress,
  }
  ```
  The input-reader thread owns nothing unsafe and touches no shared
  state beyond a `Sender<AppEvent>` clone and a `stop: Arc<AtomicBool>`
  it checks between reads — it loops `event::poll(Duration::from_
  millis(200))`, forwarding a real event via `tx.send(AppEvent::
  Term(ev))` when one arrives, or just re-checking `stop` on a timeout
  (crossterm's `poll`/`read` offers no other cancellable-wait
  primitive; 200ms bounds worst-case shutdown latency for this thread
  without meaningfully affecting input latency — every real keypress
  still wakes `poll` immediately). The worker thread (G5) clones the
  same `Sender<AppEvent>` and sends `AppEvent::HeatWorkerProgress`
  after handling each popped request.

  `run_loop` receives one `mpsc::Receiver<AppEvent>` (constructed
  alongside the input-reader thread in `tui::run()`, passed down
  exactly as `terminal` already is — not an `App` field, since it's
  plumbing, not domain state) and its top becomes:
  ```rust
  let deadline = [app.message_deadline, splash_deadline].into_iter().flatten().min();
  let event = match deadline {
      Some(d) => rx.recv_timeout(d.saturating_duration_since(Instant::now()))
          .ok(), // timeout => None, same as spec 0147's poll-timeout-elapsed case
      None => rx.recv().ok(),
  };
  match event {
      Some(AppEvent::Term(ev)) => { /* existing key/mouse dispatch, unchanged */ }
      Some(AppEvent::HeatWorkerProgress) => {
          app.recheck_pending_heat_states(); // G6 — re-poll only Pending nodes' cache entries
          app.poll_pending_override_work();  // G7
      }
      None => { /* deadline elapsed with nothing received — existing auto-dismiss handling */ }
  }
  // ... existing "always redraw at the bottom of the loop" logic, unchanged
  ```
  This fully replaces spec 0147's `event::poll(timeout)`/`event::read()`
  pair (moved into the input-reader thread) and this spec's own
  earlier fixed-`HEAT_POLL_INTERVAL` idea — the loop now genuinely
  sleeps until there's a reason to wake, for however long that takes,
  with no busy-wait or wasted redraw in between.
- **G9. Explicit, deterministic shutdown of *both* threads.**
  `tui::run()`'s existing unconditional cleanup block (the one that
  already calls `restore_terminal()` regardless of `run_loop`'s
  `Ok`/`Err`) gains, in addition to the worker's `take()` + `shutdown()`
  (unchanged from earlier drafts — signal `stop`, join), the same
  shape for the input-reader thread: flip its `stop: Arc<AtomicBool>`,
  join (bounded by that thread's own 200ms poll cycle). Order between
  the two joins doesn't matter — neither depends on the other. See
  the "Shutdown and safety" subsection under Specification for why
  the *worker's* join is load-bearing for memory safety (the
  `'static` graph reference) while the input-reader thread's join is
  purely for tidiness/determinism (it holds no unsafe data — an
  un-joined leftover input-reader thread would be safe, just an
  untidy loose end the OS reaps at process exit; we join anyway).

## Non-goals

- **N1.** `override_pane::inferred_candidates`'s own signature and
  behavior are unchanged — this spec only changes *what calls it and
  from which thread*, never the function itself.
- **N2.** G8/spec-0151's warm-up pass is **not** rearchitected onto
  this queue or this event loop. It stays fully synchronous, with its
  own progress messaging, run to completion *before* either new
  thread is even spawned — the initial viewport is always fully
  answered by the time `run_loop` starts, exactly as today. The
  worker only ever handles ranges *not* covered by the warm-up pass,
  plus override-pane requests.
- **N3.** No spinner/animation for either the heat-cue case (no
  visual indicator at all — a pending range just shows no cue until
  answered, spec 0151 N3's stance, unchanged) or the override-pane
  case (a single static "Scoring candidates…" line, not a counter or
  animation).
- **N4.** No new crate dependency — `std::sync::{Mutex, Condvar, Arc,
  mpsc, atomic::AtomicBool}`, `std::thread`, all already in `std`.
  In particular, no attempt at an OS-level `select`/`eventfd`-style
  unification of the terminal file descriptor with an external
  wakeup source — the input-reader-thread-plus-channel design (G8)
  sidesteps needing one, at the cost of a bounded (200ms) shutdown
  latency for that one thread, which N9 below judges acceptable.
- **N5.** No cross-session persistence (spec 0151 N5, unchanged) —
  the worker, the input-reader thread, the queue, and the shared
  cache are all per-session.
- **N6.** No panic supervision/restart for the worker thread. A panic
  on the worker thread terminates it; `join()`'s `Err` is discarded.
  The session degrades gracefully (heat cues and override-pane
  candidate lookups simply stop gaining new entries; everything
  already cached, and every unrelated feature, keeps working) rather
  than crashing — this is exactly what G4's lock-poisoning recovery
  is for. (The input-reader thread panicking is not expected — it
  does no scoring, only channel sends and crossterm calls — but would
  similarly just stop delivering input rather than crash the session,
  since `run_loop`'s `rx.recv()` simply never returns `Term` events
  again in that case; not specifically guarded against beyond this.)
- **N7.** No cancellation of an in-flight (already-popped)
  `score_all` call, and no attempt to eliminate every possible
  duplicate/overlapping request beyond G3's merge-on-push and G5's
  defensive already-done check.
- **N8.** No change to how `close_override`'s existing
  demote-to-preview logic conceptually works — closing the pane still
  leaves whatever was already computed/cached in place; it just reads
  from `heat_caches.by_range` (shared, locked) instead of a bare
  `App` field.
- **N9.** No true zero-latency, fully-interrupt-driven shutdown of the
  input-reader thread — its 200ms `event::poll` cycle bounds shutdown
  latency for that one thread specifically (not the worker, whose
  `Condvar` wakes immediately, and not the overall session, since
  this only delays how quickly `tui::run()` returns *after* the user
  has already asked to quit — not visible as UI latency during normal
  use).

## Specification

### New module: `tui/heat_worker.rs`

Houses `HeatRequest`, `HeatRequestQueueState`, `HeatRequestQueue`,
`RangeHeatEntry`, `HeatCaches` (incl. the `window` method, G4), an
`impl App { fn heat_lookup(...) }` block (G6 — mirroring how
`heat_cue.rs` already houses its own `impl App { fn heat_cue_for
(...) }`), `heat_worker_loop`, and `HeatWorkerHandle` (spawn +
shutdown). `tui/heat_cue.rs` stays the single source of truth for the
pure, thread-agnostic derivation logic (`derive_stats`, `score_of`,
`heat_cue_from_stats`, `BoundedMru` incl. its new `pop_mru`) and gains
`HeatState`; it gains no new dependency on threading types itself —
`heat_worker.rs` depends on it, not the reverse.

```rust
const HEAT_REQUEST_QUEUE_MAX_ENTRIES: usize = 512;
const HEAT_CUE_PREVIEW: usize = 8;

pub(super) struct HeatWorkerHandle {
    queue: Arc<HeatRequestQueue>,
    join: Option<JoinHandle<()>>,
}

impl HeatWorkerHandle {
    pub(super) fn spawn(
        caches: Arc<Mutex<HeatCaches>>,
        graph: &'static ArchivedCompiledGraph,
        blob: Arc<Vec<u8>>,
        progress: mpsc::Sender<event::AppEvent>,
    ) -> Self {
        let queue = Arc::new(HeatRequestQueue::new());
        let worker_queue = Arc::clone(&queue);
        let join = thread::spawn(move || {
            heat_worker_loop(worker_queue, caches, graph, blob, progress)
        });
        HeatWorkerHandle { queue, join: Some(join) }
    }

    pub(super) fn push(&self, req: HeatRequest) {
        self.queue.push(req);
    }

    /// Signal stop, then block until the worker exits. Shared body
    /// with `Drop` below — see G9/"Shutdown and safety".
    fn shutdown_inner(&mut self) {
        self.queue.signal_stop();
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }

    pub(super) fn shutdown(mut self) {
        self.shutdown_inner();
    }
}

impl Drop for HeatWorkerHandle {
    fn drop(&mut self) {
        self.shutdown_inner();
    }
}
```

### New module: `tui/event.rs`

```rust
pub(super) enum AppEvent {
    Term(crossterm::event::Event),
    HeatWorkerProgress,
}

pub(super) struct InputReaderHandle {
    stop: Arc<AtomicBool>,
    join: Option<JoinHandle<()>>,
}

impl InputReaderHandle {
    pub(super) fn spawn(tx: mpsc::Sender<AppEvent>) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = Arc::clone(&stop);
        let join = thread::spawn(move || {
            while !thread_stop.load(Ordering::Relaxed) {
                if event::poll(Duration::from_millis(200)).unwrap_or(false) {
                    if let Ok(ev) = event::read() {
                        if tx.send(AppEvent::Term(ev)).is_err() {
                            break; // receiver gone — run_loop already exited
                        }
                    }
                }
            }
        });
        InputReaderHandle { stop, join: Some(join) }
    }

    pub(super) fn shutdown(mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}
```

### `App` field changes (`tui/mod.rs`)

Remove `heat_range_cache`, `heat_current_score_cache`, `candidate_cache`.
Add:

```rust
heat_caches: Arc<Mutex<heat_worker::HeatCaches>>,
heat_worker: Option<heat_worker::HeatWorkerHandle>,
heat_states: Vec<heat_cue::HeatState>,
override_candidates_pending: bool,
override_complete_pending: bool,
```

`heat_caches` and `heat_states` are always constructed in `App::new`
(never behind an `Option`). `heat_worker` stays `None` until
`tui::run()` spawns it (G1); every existing test fixture therefore
continues to exercise the synchronous fallback arm. `event_rx` (the
`mpsc::Receiver<AppEvent>`) and the `InputReaderHandle` are *not*
`App` fields — both are local to `tui::run()`/`run_loop`, passed as
parameters alongside `terminal` (which is already handled the same
way).

**Call sites needing mechanical updates** (found by direct inspection
of the current tree, to be re-confirmed at implementation time):
- `tui/heat_cue.rs:215,242` (spec 0151's G6 cross-population inserts)
  are *removed*, not relocked — that work now happens on the worker
  (G5).
- `tui/override_select.rs:211` (`close_override`'s demote-to-preview
  read/insert — relocked, logic unchanged, N8) and `:301`
  (`recompute_override_candidates`'s cache-hit `get` — replaced by a
  `window(...)` call, G7).
- `tui/tests/heat_cue.rs:563,573` — direct test manipulation of what
  was `app.candidate_cache`, now `app.heat_caches.lock()....by_range`.

### `tui::run()` changes

```rust
warm_up_heat_cues(&mut terminal, app)?; // unchanged, spec 0151 G8 — N2

let (tx, rx) = mpsc::channel();
let input_reader = event::InputReaderHandle::spawn(tx.clone());

if let Some(graph) = &app.ctx.graph {
    let graph_ref: &'static ArchivedCompiledGraph = graph.graph; // Copy
    let blob = Arc::new(app.blob.clone()); // one-time clone, G2
    app.heat_worker = Some(heat_worker::HeatWorkerHandle::spawn(
        Arc::clone(&app.heat_caches),
        graph_ref,
        blob,
        tx,
    ));
}

let result = run_loop(&mut terminal, app, &rx);

if let Some(worker) = app.heat_worker.take() {
    worker.shutdown();
}
input_reader.shutdown();
let _ = std::panic::take_hook();
restore_terminal();
terminal.show_cursor()?;

result
```

### `run_loop` changes

Signature gains `rx: &mpsc::Receiver<event::AppEvent>`. Its top
becomes the `recv`/`recv_timeout` dispatch shown under G8; the
existing key/mouse-dispatch body is unchanged, just now reached via
`Some(AppEvent::Term(ev))` instead of a direct `event::read()`.
`app.recheck_pending_heat_states()` (new, G6: iterate `heat_states`,
re-run the `window(...)` check only for entries still `Pending`,
promoting any now-answerable ones to `Resolved`) and
`app.poll_pending_override_work()` (G7) are both called on
`AppEvent::HeatWorkerProgress`, nowhere else.

### Shutdown and safety

`LoadedGraph::graph` is typed `&'static ArchivedCompiledGraph`, a
bald `'static` reference whose *actual* validity is tied to
`LoadedGraph`'s backing store (`Mmap` or a leaked `AlignedVec`)
staying alive — the type system doesn't enforce this (see
`load_graph`'s own safety comment in
`prototext-graph/src/score/load.rs`). Copying that reference out to
hand to the worker (G2) is only sound as long as the worker's *last*
dereference of it happens-before `app.ctx` (and the `LoadedGraph` it
owns) is dropped. `App` lives in `main()`'s stack and isn't dropped
until `tui::run()` has already returned, so `run()`'s explicit
`take()` + `shutdown()` — which blocks until the worker thread has
exited — running unconditionally before `run()` returns is what makes
this sound. A `Drop` impl on `HeatWorkerHandle` covers the one
remaining path the explicit call can't reach: a panic unwinding
through `run_loop` before that line. This repo's profile doesn't set
`panic = "abort"` (confirmed: no such key in either `Cargo.toml`), so
an unhandled panic unwinds normally, running destructors for
everything on `main()`'s stack, including `App`'s `heat_worker`
field — so even on that path, the worker is joined before `app.ctx`
can drop. This mirrors the existing panic-hook pattern already used
for `restore_terminal` (`tui/mod.rs`, predates this spec).

The input-reader thread holds no `'static`-reference-style unsafe
obligation (it only owns a `Sender<AppEvent>` clone and reads
crossterm events into owned values) — its `shutdown()` is joined
purely for deterministic, leak-free test/session teardown, not for
memory safety.

## Test plan

**`BoundedMru::pop_mru`:** insert several keys, assert `pop_mru`
returns them in most-recently-inserted order, and that a `get`/`peek`
promotion before popping changes that order accordingly (mirrors the
existing `get`/`insert` promotion tests, spec 0151).

**`HeatRequestQueue` (no real thread needed for push/pop shape):**
- Pushing the same `range.start` twice with different `[start,end)`
  windows yields **one** entry whose window is the union, not two
  entries (pins G3's merge-on-push behavior).
- Pushing two different ranges, then popping, returns the
  most-recently-*pushed-or-merged* one first (LIFO/MRU order across
  distinct keys).
- Pushing past `HEAT_REQUEST_QUEUE_MAX_ENTRIES` caps the queue length,
  dropping the least-recently-touched entry first.

**`HeatRequestQueue` shutdown (real second thread):** `pop_blocking`
on a spawned thread against an empty queue; `signal_stop()` from the
test thread; assert the spawned thread's `pop_blocking` returns
`None` and the thread joins promptly (bounded test timeout).

**`HeatCaches`/worker round trip (real worker thread, real tiny
in-memory graph, no file I/O):** build a `LoadedGraph` via
`build_from_strings` + `Box::leak` + `LoadedGraph::from_static_bytes`
(as spec 0151's own notes anticipated); construct an `App` via a new
`DescriptorContext::for_test_with_graph(graph)` test constructor;
spawn a `HeatWorkerHandle` directly (not via `tui::run()`, with a
throwaway `mpsc::Sender` for the progress parameter); push a request;
poll (a short-sleep bounded loop, not `recv` — this test isn't
exercising the event-driven wiring, just the worker/cache contract)
until `by_range` shows an entry; assert it matches what a direct,
synchronous `derive_stats`/`inferred_candidates` call against the
same bytes produces, and that `complete` now holds this same range's
full list unconditionally (G5's "always refreshed" behavior). Push a
second, narrower-or-equal request for the same range and assert (via
an injected call-counting wrapper around `inferred_candidates`, test-
only) it's answered without a second `score_all` call.

**`InputReaderHandle` (real second thread):** spawn against a real
(or a minimal fake) terminal backend; simulate/inject a crossterm
event if the test harness allows it, else limit this test to
spawn/`shutdown()` round-tripping cleanly within a bounded timeout —
confirming the 200ms-bounded join, not full event delivery (which
would require a real terminal or a crossterm-level test double
outside this spec's scope).

**`heat_cue_for`/`recompute_override_candidates`/
`upgrade_active_override_to_complete` worker-aware forks (no real
thread — `heat_worker: None` is `App::new`'s default):**
- Existing spec 0151 heat-cue tests continue to pass with only the
  mechanical field-access update noted above — no logic rewrite for
  the `heat_worker: None` fallback path.
- New: `heat_lookup` directly — a window covered by `by_range.top_n`
  but a missing `current_score` entry for the given `current_key`
  (and, symmetrically, a cached `current_score` but an insufficient
  `top_n`) both still return `None` and push a request — pinning the
  "both must hold" AND-gating described in G6, not just the window
  half of it.
- New: with a manually-installed `HeatWorkerHandle` on
  `app.heat_worker`, a `heat_cue_for` call on a `Pending` node with an
  empty cache returns `None`, pushes exactly one `HeatRequest`
  (`[0, HEAT_CUE_PREVIEW)`), and leaves `heat_states[idx]` as
  `Pending`; a second `heat_cue_for` call on the *same* node before
  any cache change pushes **no additional** request (still missing →
  `Pending` stays `Pending`, but no queue growth — since the queue
  itself would merge it anyway, this specifically exercises
  `heat_lookup`'s before-push check, not just the queue's own merge).
- New: pre-populating `heat_caches.by_range` with a `RangeHeatEntry`
  whose `top_n` already covers `[0, HEAT_CUE_PREVIEW)` (and, if a
  `current_key` is set, `current_score` too), then calling
  `heat_cue_for`, resolves to `Resolved(...)` **without** pushing any
  request at all — the direct test for "don't trigger a `score_all`
  (or even a push) if the cache already covers the ask," exercising
  `heat_lookup`'s hit path.
- New: `recompute_override_candidates` on a `heat_lookup(...)` miss
  for the pane's first page sets `override_candidates_pending` and
  pushes one request; pre-populating `by_range`'s `top_n` to already
  cover the pane's page size beforehand instead applies it
  immediately with **no** pending flag set and **no** push (same
  principle as above, exercised through the override-pane entry
  point specifically).
- New: `upgrade_active_override_to_complete` on scroll-past-window
  sets `override_complete_pending` and pushes a request for the next
  `[start, end)`; populating `heat_caches.complete` with a
  *non-matching* range and calling `poll_pending_override_work()`
  leaves the flag set (the mismatch-guard correctness note under G7);
  populating it with the *matching* range (or, alternatively,
  populating `by_range.top_n` widely enough to cover the requested
  window) clears the flag and applies the result — covering both of
  `HeatCaches::window`'s two sources.

**Explicitly not covered by this plan:** true concurrent-timing races
(e.g. an override edit landing in the exact window between the worker
popping a request and writing its result) are not mechanically
reproduced under controlled/injected timing in this plan —
correctness for those is argued in the Specification/Goals prose
(G3's merge semantics, G5's defensive re-check, G7's "complete-list
races" note) rather than exercised by a deliberately-delayed test
double. A future revision could add a `#[cfg(test)]`-only
synchronization hook to the worker loop if precise coverage of a
specific interleaving is later judged worth the added test-only
surface area.
