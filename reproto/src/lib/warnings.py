# SPDX-FileCopyrightText: 2026 THALES CLOUD SECURISE SAS
#
# SPDX-License-Identifier: MIT

from __future__ import annotations

import logging
from collections import Counter


def cli_error(message: str, *args, **kwargs) -> None:
    kwargs.setdefault("extra", {}).setdefault("cli_err", True)
    logging.warning(message, *args, stacklevel=2, **kwargs)

def cli_warning(message: str, *args, **kwargs) -> None:
    kwargs.setdefault("extra", {}).setdefault("cli_warn", True)
    logging.warning(message, *args, stacklevel=2, **kwargs)

def cli_info(message: str, *args, **kwargs) -> None:
    kwargs.setdefault("extra", {}).setdefault("cli_info", True)
    logging.warning(message, *args, stacklevel=2, **kwargs)

def cli_attention(message: str, *args, **kwargs) -> None:
    kwargs.setdefault("extra", {}).setdefault("cli_attn", True)
    logging.warning(message, *args, stacklevel=2, **kwargs)


class WarningCollector:
    """Buffer W1/W4/W5 warnings; print W3 immediately.

    In squashed mode (default): counts occurrences per distinct message and
    flushes a summary at the end.  In detailed mode: every warning is printed
    immediately, no buffering.

    Usage::

        collector = WarningCollector(detailed=False)
        collector.w1("third_party/foo.proto")
        collector.w4(".some.pkg.Type")
        collector.w5("third_party/bar.proto")
        collector.w3("file:a.proto pruned — ...")  # always immediate
        collector.flush()
    """

    def __init__(self, detailed: bool = False) -> None:
        self._detailed = detailed
        # Counters for squashed mode (unused in detailed mode)
        self._w1: Counter[str] = Counter()
        self._w4: Counter[str] = Counter()
        self._w5: Counter[str] = Counter()

    def w1(self, missing_file: str) -> None:
        """Missing source file (W1)."""
        msg = f"Warning: missing file '{missing_file}' (not found on -I path; skipped)"
        if self._detailed:
            cli_warning(msg)
        else:
            self._w1[missing_file] += 1

    def w4(self, type_name: str) -> None:
        """Unresolvable type reference (W4)."""
        if self._detailed:
            cli_warning(f"Warning: unresolvable type {type_name}")
        else:
            self._w4[type_name] += 1

    def w5(self, dep_file: str) -> None:
        """Missing file dependency (W5)."""
        if self._detailed:
            cli_warning(f"Warning: missing dependency file:{dep_file}")
        else:
            self._w5[dep_file] += 1

    def w3(self, message: str) -> None:
        """Duplicate symbol pruning (W3) — always printed immediately."""
        cli_warning(message)

    def flush(self) -> None:
        """Flush buffered squashed warnings to stderr."""
        if self._detailed:
            return
        suppressed = False
        for missing_file, count in sorted(self._w1.items()):
            if count == 1:
                cli_warning(f"Warning: missing file '{missing_file}' (not found on -I path; skipped)")
            else:
                cli_warning(f"Warning: missing file '{missing_file}' ({count} occurrences)")
                suppressed = True
        for type_name, count in sorted(self._w4.items()):
            if count == 1:
                cli_warning(f"Warning: unresolvable type {type_name}")
            else:
                cli_warning(f"Warning: unresolvable type {type_name} ({count} occurrences)")
                suppressed = True
        for dep_file, count in sorted(self._w5.items()):
            if count == 1:
                cli_warning(f"Warning: missing dependency file:{dep_file}")
            else:
                cli_warning(f"Warning: missing dependency file:{dep_file} ({count} occurrences)")
                suppressed = True
        if suppressed:
            cli_info("Run with --detailed-warnings to see all warning occurrences.")


# Module-level singleton — configured once at startup by reproto.py/cli.py.
_collector: WarningCollector = WarningCollector(detailed=False)


def get_collector() -> WarningCollector:
    return _collector


def configure_collector(detailed: bool) -> None:
    global _collector
    _collector = WarningCollector(detailed=detailed)

