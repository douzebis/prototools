<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0075 — Rendering progress bar

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

- Progress bars for phases other than phase 7.
- Rich markup or spinners in existing log messages.
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

### 3. Progress context manager (`lib/console.py`)

Add a context manager `rendering_progress(total: int)` that:

- If stderr is not a TTY or `total == 0`: is a no-op (yields a dummy callable).
- Otherwise: starts a `rich.progress.Progress` bar on the shared console and
  yields an `advance()` callable.

```python
@contextmanager
def rendering_progress(total: int):
    if not console.is_terminal or total == 0:
        yield lambda: None
        return
    with Progress(
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        MofNCompleteColumn(),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task("Rendering", total=total)
        yield lambda: progress.advance(task)
```

`transient=True` removes the bar from the terminal once it completes, leaving
only the final log messages visible — consistent with the existing clean
output style.

Using the **same** `console` instance for both `rprint` and `Progress` is the
key to correctness: rich internally intercepts writes to the console while
`Live` is active and redraws the bar below any printed lines, preventing
interleaving artefacts.

### 4. Wire up in `_phase7_output` (`phases.py`)

Before the rendering loop, collect the files to be rendered into a list (the
loop already filters on the same conditions):

```python
summoned = [
    re_fdp for re_fdp in ctx.nodes.values()
    if isinstance(re_fdp, ReFileDescriptorProto)
    and re_fdp.is_present()
    and re_fdp.is_summoned
    and not (re_fdp.name == ctx.variant_descriptor_proto
             and not ctx.write_variant_descriptor)
]
```

Then wrap the loop:

```python
with rendering_progress(0 if ctx.quiet else len(summoned)) as advance:
    for re_fdp in summoned:
        ...  # existing rendering logic, unchanged
        advance()
```

No other changes to `phases.py` logic.

---

## Files changed

| File | Change |
|------|--------|
| `reproto/src/reproto/lib/console.py` | New — console singleton, `rprint`, `rendering_progress` |
| `reproto/src/reproto/cli.py` | Replace 4 × `click.secho` with `rprint` |
| `reproto/src/reproto/phases.py` | Collect summoned files into list; wrap loop with `rendering_progress` |

---

## Implemented in

2026-05-22
