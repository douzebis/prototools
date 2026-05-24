# SPDX-FileCopyrightText: 2026 THALES CLOUD SECURISE SAS
#
# SPDX-License-Identifier: MIT

"""Shared Rich console, progress bars, and spinner (spec 0075).

All reproto output to the terminal is routed through `rprint` so that the
Rich Live context used by `progress` can redraw the progress bar below any
log lines without interleaving artefacts.
"""

from __future__ import annotations

from collections.abc import Callable, Generator
from contextlib import contextmanager

from rich.console import Console
from rich.progress import BarColumn, MofNCompleteColumn, Progress, TextColumn, TimeElapsedColumn

# Single console instance for the whole process.
# highlight=False: prevents Rich from auto-highlighting numbers/strings in
# log messages, which would alter their appearance unexpectedly.
console = Console(stderr=True, highlight=False)


def rprint(message: str, *, style: str | None = None) -> None:
    """Print a message to stderr via the shared Rich console.

    markup=False ensures square brackets (e.g. WARNING[downconvert]) are
    treated as literals rather than Rich markup.
    """
    console.print(message, style=style, markup=False)


@contextmanager
def progress(label: str, total: int) -> Generator[Callable[..., None], None, None]:
    """Context manager that shows a progress bar for a countable step.

    Yields an advance(n=1) callable.  Calling advance() moves the bar forward
    by 1 step; calling advance(n) moves it forward by n steps.

    The bar is suppressed when:
    - stderr is not a TTY (piped/redirected output), or
    - total == 0 (caller passes 0 to opt out, e.g. --quiet mode).
    """
    if not console.is_terminal or total == 0:
        yield lambda n=1: None  # type: ignore[misc]
        rprint(label)
        return
    with Progress(
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        MofNCompleteColumn(),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    ) as prog:
        task = prog.add_task(label, total=total)
        yield lambda n=1: prog.advance(task, advance=n)  # type: ignore[misc]
    rprint(label)


@contextmanager
def spinning(label: str, quiet: bool = False) -> Generator[None, None, None]:
    """Context manager that shows a spinner for an indeterminate blocking step.

    Suppressed (no spinner, no label) when stderr is not a TTY or quiet=True.
    Prints label on completion so the phase name persists on the terminal.
    """
    if quiet:
        yield
        return
    if not console.is_terminal:
        yield
        rprint(label)
        return
    with console.status(label, spinner="dots"):
        yield
    rprint(label)
