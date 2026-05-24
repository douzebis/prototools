<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0075 — Progress bars and spinners

**Status:** implemented
**App:** reproto

---

## Background

When reproto processes a large corpus of `.pb` files the rendering phase
(phase 7) can run for minutes.  There is no progress feedback during this
time — the last message the user sees is "Writing reconstructed .proto files."
followed by silence until completion.

`rich` is already a declared dependency of reproto (it was added speculatively
but is currently unused).  It provides a `Progress` widget that coexists
cleanly with console output through its `Live` context manager.

The existing display API (`cli_warning`, `cli_info`, `cli_error`,
`cli_attention` in `lib/warnings.py`) routes all output through four
`logging.Handler` subclasses in `cli.py`, each calling `click.secho(...,
err=True)`.  This is the single chokepoint for all reproto output to the
terminal.

---

## Goals

1. Show a progress bar on stderr during phase 7 that advances one step per
   rendered file.
2. Do not alter the existing `cli_warning` / `cli_info` / `cli_error` /
   `cli_attention` call signatures or semantics anywhere in the codebase.
3. Preserve colour and bold formatting for all existing message types.
4. The bar must be silent when stderr is not a TTY (redirected to a file or
   pipe) — same behaviour as `click.secho` with ANSI codes.
5. The bar must be silent when `--quiet` is passed.
6. No new CLI flags.

---

## Non-goals

- Rich markup in existing log messages.
- Changing how warnings are buffered or flushed.

---

## Specification

### 1. Rich console singleton (`lib/console.py`)

Introduce a new module `reproto/lib/console.py` that owns a single
`rich.console.Console` instance writing to stderr:

```python
console = Console(stderr=True, highlight=False)
```

`highlight=False` prevents rich from auto-highlighting numbers and strings in
log messages, which would change their appearance unexpectedly.

Expose one function:

```python
def rprint(message: str, *, style: str | None = None) -> None: ...
```

`rprint` calls `console.print(message, style=style, markup=False)`.
`markup=False` ensures that square brackets in warning messages (e.g.
`WARNING[downconvert]`) are treated as literals, not rich markup.

### 2. Replace `click.secho` with `rprint` in `cli.py`

The four `CLI*Handler.emit()` methods currently call `click.secho`.  Replace
each with a call to `rprint`, mapping the existing `fg`/`bold` arguments to
rich style strings:

| Handler               | Current style            | Rich style      |
|-----------------------|--------------------------|-----------------|
| `CLIErrorHandler`     | `fg='red', bold=True`    | `"bold red"`    |
| `CLIWarningHandler`   | `fg='yellow', bold=True` | `"bold yellow"` |
| `CLIInfoHandler`      | (plain)                  | `None`          |
| `CLIAttentionHandler` | `fg='blue', bold=True`   | `"bold blue"`   |

This is the **only** change to `cli.py`.  All call sites of `cli_warning` etc.
throughout the codebase are unaffected.

Rich's `Console` handles TTY detection automatically: ANSI codes are stripped
when stderr is not a TTY, exactly as `click.secho` does today.

### 3. Progress and spinner context managers (`lib/console.py`)

Add two context managers:

**`progress(label: str, total: int)`** — shows a `rich.progress.Progress` bar
when `total > 0` and stderr is a TTY; otherwise is a no-op.  Yields an
`advance(n=1)` callable.  Prints `label` to stderr via `rprint` after the bar
closes, so the phase name persists on the terminal.

**`spinning(label: str)`** — shows a `rich.console.Console.status` spinner
for steps whose duration is not known upfront.  No-op when stderr is not a
TTY.  Prints `label` to stderr via `rprint` after the spinner closes.

Both context managers are responsible for the persistent phase-name trace.
Callers must **not** print the phase name separately (no `cli_info` before
the `with` block).

Using the **same** `console` instance for both `rprint` and `Progress` is the
key to correctness: rich internally intercepts writes to the console while
`Live` is active and redraws the indicator below any printed lines, preventing
interleaving artefacts.

### 4. Canonical phase labels

Each phase and sub-step has a single canonical label used as the bar/spinner
title and as the persistent trace printed on completion.

| Phase / step | Indicator | Label | Total |
|---|---|---|---|
| 1a — Seed loading | `spinning` | `Loading seed files` | unknown |
| 1b — Import discovery | `spinning` | `Discovering imported files` | unknown (iterative) |
| 2 — Merging into pool | `progress` | `Merging file descriptors` | `len(topo.files)` |
| 3 — Building FQDN graph | `progress` | `Building FQDN graph` | `len(topo.files)` |
| 4 — Pruning | plain print | `Processing exclusions` | — |
| 5 — Reachability BFS | `progress` | `Computing reachability` | `len(ctx.nodes)` |
| 6 sub-pass 1 — Summoning | `progress` | `Marking summoned nodes` | `len(ctx.nodes)` |
| 6 sub-pass 2 — Import bridging | `spinning` | `Bridging import paths` | unknown (convergence loop) |
| 6 sub-pass 3 — DB closure | `spinning` | `Closing DB dependencies` | unknown |
| 7 — Rendering | `progress` | `Rendering proto files` | `len(summoned)` |
| DB step 1 — Collect graphs | `progress` | `Collecting scoring graphs` | `len(summoned_files)` |
| DB step 2 — Hopcroft (Rust) | `progress` | `Compiling global scoring graph` | 100 (dynamic %) |
| DB step 3b — WKT deps | `spinning` | `Rendering WKT dependencies` | unknown |
| DB step 4+5 — Serialize + index | `spinning` | `Writing schema DB` | unknown |

All `progress` indicators pass `total = 0` (suppressing the bar) when
`ctx.quiet` is set.  Spinners and plain prints are also suppressed when
`ctx.quiet` is set.

---

## Files changed

| File | Change |
|------|--------|
| `reproto/src/reproto/lib/console.py` | Console singleton, `rprint`, `progress` (persistent label, `advance(n=1)`), `spinning` (persistent label) |
| `reproto/src/reproto/cli.py` | Replace 4 × `click.secho` with `rprint` |
| `reproto/src/reproto/phases.py` | Canonical labels throughout; remove `cli_info` phase-name prints; add spinners for phase 6 sub-passes 2 and 3 |

---

## Implemented in

2026-05-24
