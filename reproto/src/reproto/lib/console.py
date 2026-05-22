# SPDX-FileCopyrightText: 2026 THALES CLOUD SECURISE SAS
#
# SPDX-License-Identifier: MIT

"""Shared Rich console and rendering progress bar (spec 0075).

All reproto output to the terminal is routed through `rprint` so that the
Rich Live context used by `rendering_progress` can redraw the progress bar
below any log lines without interleaving artefacts.
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
def rendering_progress(total: int) -> Generator[Callable[[], None], None, None]:
    """Context manager that shows a progress bar during phase 7 rendering.

    Yields an advance() callable that must be called once per rendered file.

    The bar is suppressed when:
    - stderr is not a TTY (piped/redirected output), or
    - total == 0 (caller passes 0 to opt out, e.g. --quiet mode).
    """
    if not console.is_terminal or total == 0:
        yield lambda: None  # type: ignore[misc]
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
        yield lambda: progress.advance(task)  # type: ignore[misc]
