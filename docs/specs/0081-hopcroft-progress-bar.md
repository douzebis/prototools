<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0081 — Hopcroft progress bar

**Status:** draft
**App:** reproto / scoring-graph

---

## Background

Spec 0075 replaced the "DB step 2 — Hopcroft graph (Rust)" indicator with a
plain spinner because the total work was considered opaque.  For small schemas
this is fine, but for large corpora (e.g. googleapis: ~50 k nodes, ~3 k
symbols, ~50 M worklist iterations) the minimization phase takes tens of
seconds with no progress signal.

Instrumentation added during investigation revealed the following figures for
googleapis:

| Quantity | Value |
|---|---|
| n (nodes) | 49,373 |
| \|Σ\| (alphabet) | 2,880 |
| log₂n | 15.59 |
| Initial worklist | 11,969,280 |
| Actual iterations | 50,218,560 |
| Actual splits | 13,281 |
| n · log₂n (worst-case splits) | ~770,000 |
| Worst-case iterations n·\|Σ\|·log₂n | ~2.2 × 10⁹ |

Key observations:

1. Splits are rare (~1.7% of the worst-case split budget for googleapis).
2. Every split unconditionally adds exactly `|Σ|` new worklist entries.
3. Actual iterations = `initial_worklist + splits × |Σ|`.
4. The theoretical upper bound `n · |Σ| · log₂n` is ~44× the actual work for
   googleapis — a static denominator based on it would barely move.

---

## Goals

1. Replace the spinner for "DB step 2 — Hopcroft graph" with a real progress
   bar that reaches 100% at algorithm completion.
2. The reported progress value must be monotonically non-decreasing.
3. Use a dynamically shrinking upper bound so that the bar accelerates
   naturally as the split budget is consumed.
4. Express progress on a fixed 0–100 integer scale so Python needs no
   knowledge of internal iteration counts.
5. Decouple progress calculation (every iteration, in Rust) from progress
   reporting (Python/rich): report to Python only when the integer percentage
   advances — at most 100 callbacks per minimization run.

---

## Non-goals

- Changing the Hopcroft algorithm itself.
- Storing iteration counts across runs (no warm-start denominator caching).
- Sub-1% reporting granularity.

---

## Specification

### 1. Dynamic upper bound

At any point during the refinement loop, define:

```
splits_budget   = floor(n · log₂n)         -- worst-case total splits
remaining       = worklist.len()            -- items left in the worklist
done            = iterations_so_far         -- items already processed

remaining_upper = remaining
                + (splits_budget - splits_so_far) · |Σ|

total_upper     = done + remaining_upper
progress        = done / total_upper        -- value in [0, 1)
pct             = floor(progress × 100)     -- integer in [0, 100]
```

`total_upper` starts near `n · |Σ| · log₂n` and decreases monotonically:
each observed split reduces `splits_budget - splits_so_far` by 1, removing
`|Σ|` units from the remaining budget.  Because `total_upper` only ever
shrinks, `progress` (and therefore `pct`) is guaranteed to be monotonically
non-decreasing.

At algorithm completion: `remaining = 0`, so `remaining_upper = 0`,
`total_upper = done`, `progress = 1.0`, `pct = 100`.

### 2. Rust side: throttled callback (`hopcroft.rs`)

`minimize` gains a callback parameter `on_progress: impl FnMut(u8)` that
receives the current integer percentage (0–100).  The callback fires only
when `pct` strictly increases since the last report:

```rust
if pct > last_reported_pct {
    on_progress(pct as u8);
    last_reported_pct = pct;
}
```

This fires at most 100 times per run.  One final unconditional call with
`100u8` is made after the loop to guarantee the bar always reaches 100%.

The existing instrumentation `eprintln!` (added during investigation) is
removed in this same change.

### 3. Threading the callback through `mod.rs`

Both `build_compiled` and `build_from_strings` call `minimize` directly.
Each gains a matching `on_progress: impl FnMut(u8)` parameter and passes it
through to `minimize`.

Call sites that do not need progress reporting pass `|_| {}` to
`build_compiled` and `build_from_strings`:
- `hopcroft_dump` binary (calls `build_from_strings`)
- The 4 direct `minimize` call sites in `score/tests.rs`

`build_compiled` itself always passes `|_| {}` to `minimize` — it is only
used by the test suite and never needs a live callback.

Only the PyO3 `build_graph` function passes a live callback to
`build_from_strings`.

### 4. PyO3 layer (`scoring-graph-pyo3/src/lib.rs`)

`build_graph` gains an optional `on_progress` Python callable:

```rust
#[pyo3(signature = (scoring_graphs, emit_yaml = false, on_progress = None))]
fn build_graph<'py>(
    py: Python<'py>,
    scoring_graphs: Vec<String>,
    emit_yaml: bool,
    on_progress: Option<PyObject>,
) -> PyResult<(Bound<'py, PyBytes>, Option<String>)>
```

The GIL is released for the duration of the computation via
`py.allow_threads`.  The callback closure captures `on_progress` and
re-acquires the GIL only at each (≤100) progress report:

```rust
let result = py.allow_threads(|| {
    build_from_strings(&scoring_graphs, emit_yaml, |pct| {
        if let Some(ref cb) = on_progress {
            Python::with_gil(|py| { let _ = cb.call1(py, (pct as u64,)); });
        }
    })
})?;
```

Releasing the GIL during a long pure-Rust computation is good practice for
PyO3 extensions, even when no other Python thread is actively competing for
it.

### 5. Python side (`phases.py`)

The `spinning('Compiling global scoring graph')` call is replaced with a
`progress('Compiling global scoring graph', total=100)` bar.  Because `total=100`
is a compile-time constant, the rich `Progress` task is fully initialized
before Rust is called — no lazy setup needed.

The callback advances the bar by the delta since the last report:

```python
last_pct = 0

def on_progress(pct: int) -> None:
    nonlocal last_pct
    advance(pct - last_pct)
    last_pct = pct

with progress('Compiling global scoring graph', total=100) as advance:
    build_graph(scoring_graphs, on_progress=on_progress)
```

---

## Files changed

| File | Change |
|---|---|
| `scoring-graph/src/build_scoring_graph/hopcroft.rs` | Add `on_progress: impl FnMut(u8)`; dynamic upper bound; throttled reporting; remove instrumentation `eprintln!` |
| `scoring-graph/src/build_scoring_graph/mod.rs` | Add `on_progress` to `build_compiled` and `build_from_strings`; pass `\|_\| {}` at non-PyO3 call sites |
| `scoring-graph-pyo3/src/lib.rs` | Add `on_progress: Option<PyObject>` to `build_graph`; `py.allow_threads` + `Python::with_gil` bridge |
| `reproto/src/reproto/phases.py` | Replace `spinning` with `progress(total=100)` + delta callback for DB step 2 |

---

## Implemented in

(not yet)
