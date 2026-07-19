# SPDX-FileCopyrightText: 2026 THALES CLOUD SECURISE SAS
#
# SPDX-License-Identifier: MIT

"""Unit tests for WarningCollector and _classify_exc (spec 0041 TC-W* and TC-C*)."""

from __future__ import annotations

import logging
from io import StringIO

from reproto.lib.warnings import WarningCollector
from reproto.anomalies import _classify_exc


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _capture_flush(collector: WarningCollector) -> list[str]:
    """Flush collector and return the non-empty stderr lines it emitted."""
    buf = StringIO()
    handler = logging.StreamHandler(buf)
    handler.setLevel(logging.WARNING)
    root = logging.getLogger()
    root.addHandler(handler)
    try:
        collector.flush()
    finally:
        root.removeHandler(handler)
    buf.seek(0)
    return [ln.rstrip() for ln in buf.read().splitlines() if ln.strip()]


def _capture_immediate(fn, *args, **kwargs) -> list[str]:
    """Call fn(*args) and return the stderr lines it produced."""
    buf = StringIO()
    handler = logging.StreamHandler(buf)
    handler.setLevel(logging.WARNING)
    root = logging.getLogger()
    root.addHandler(handler)
    try:
        fn(*args, **kwargs)
    finally:
        root.removeHandler(handler)
    buf.seek(0)
    return [ln.rstrip() for ln in buf.read().splitlines() if ln.strip()]


# ---------------------------------------------------------------------------
# TC-W1  Squashed flush format and order (W5 → W4 → W6)
# ---------------------------------------------------------------------------

def test_W1_squashed_flush_order_and_occurrences() -> None:
    c = WarningCollector(detailed=False)
    c.w5("dep.proto")
    c.w4(".pkg.Type")
    c.w4(".pkg.Type")     # second occurrence of same key
    c.w6("f.proto", "field 'x'", "Couldn't find Extension 42")

    lines = _capture_flush(c)

    w5_idx = next(i for i, ln in enumerate(lines) if "missing dependency file:dep.proto" in ln)
    w4_idx = next(i for i, ln in enumerate(lines) if "unresolvable type .pkg.Type" in ln)
    w6_idx = next(i for i, ln in enumerate(lines) if "Couldn't find Extension 42" in ln)

    assert w5_idx < w4_idx < w6_idx, "Flush order must be W5 → W4 → W6"
    assert "(1 occurrence)" in lines[w5_idx]
    assert "(2 occurrences)" in lines[w4_idx]
    assert "(1 occurrence)" in lines[w6_idx]


# ---------------------------------------------------------------------------
# TC-W2  "Run with --detailed-warnings" hint
# ---------------------------------------------------------------------------

def test_W2_hint_appears_when_count_gt1() -> None:
    c = WarningCollector(detailed=False)
    c.w4(".pkg.Type")
    c.w4(".pkg.Type")   # count = 2

    lines = _capture_flush(c)
    assert any("--detailed-warnings" in ln for ln in lines), \
        "Hint must appear when any warning has count > 1"


def test_W2_hint_absent_when_all_count_1() -> None:
    c = WarningCollector(detailed=False)
    c.w4(".pkg.UniqueType")

    lines = _capture_flush(c)
    assert not any("--detailed-warnings" in ln for ln in lines), \
        "Hint must not appear when all counts are 1"


# ---------------------------------------------------------------------------
# TC-W3  Detailed mode: events fire immediately; flush is a no-op
# ---------------------------------------------------------------------------

def test_W3_detailed_fires_immediately() -> None:
    c = WarningCollector(detailed=True)

    w4_lines = _capture_immediate(c.w4, ".pkg.Type")
    assert any("unresolvable type .pkg.Type" in ln for ln in w4_lines)

    w5_lines = _capture_immediate(c.w5, "dep.proto")
    assert any("missing dependency file:dep.proto" in ln for ln in w5_lines)

    w6_lines = _capture_immediate(c.w6, "f.proto", "field 'x'", "Couldn't find Extension 1")
    assert any("Couldn't find Extension 1" in ln for ln in w6_lines)


def test_W3_detailed_flush_is_noop() -> None:
    c = WarningCollector(detailed=True)
    c.w4(".pkg.Type")    # already fired immediately; flush must not repeat
    lines = _capture_flush(c)
    assert not any("unresolvable type" in ln for ln in lines), \
        "flush() must produce no output in detailed mode"


# ---------------------------------------------------------------------------
# TC-W4  W1 feeds the W5 counter
# ---------------------------------------------------------------------------

def test_W4_w1_merges_into_w5_counter() -> None:
    c = WarningCollector(detailed=False)
    c.w1("missing.proto")       # +1
    c.w5("missing.proto")       # +1
    c.w5("missing.proto")       # +1  → total 3

    lines = _capture_flush(c)
    w5_lines = [ln for ln in lines if "missing dependency file:missing.proto" in ln]
    assert len(w5_lines) == 1, "Exactly one squashed line for the merged key"
    assert "(3 occurrences)" in w5_lines[0]
    assert not any("missing file 'missing.proto'" in ln for ln in lines), \
        "No separate W1 line must appear"


# ---------------------------------------------------------------------------
# TC-W5  W5 suppression for pruned files
# ---------------------------------------------------------------------------

def test_W5_suppression_squashed() -> None:
    c = WarningCollector(detailed=False)
    c.register_pruned_file("pruned.proto")
    c.w5("pruned.proto")
    c.w1("pruned.proto")

    lines = _capture_flush(c)
    assert not any("pruned.proto" in ln for ln in lines), \
        "Pruned file must produce no output in squashed flush"


def test_W5_suppression_detailed() -> None:
    c = WarningCollector(detailed=True)
    c.register_pruned_file("pruned.proto")

    w5_lines = _capture_immediate(c.w5, "pruned.proto")
    w1_lines = _capture_immediate(c.w1, "pruned.proto")
    assert not any("pruned.proto" in ln for ln in w5_lines + w1_lines), \
        "Pruned file must produce no immediate output in detailed mode"


# ---------------------------------------------------------------------------
# TC-W6  W3 is always immediate in both modes
# ---------------------------------------------------------------------------

def test_W6_w3_immediate_squashed() -> None:
    c = WarningCollector(detailed=False)
    immediate = _capture_immediate(c.w3, "some w3 message")
    assert any("some w3 message" in ln for ln in immediate), \
        "W3 must fire immediately in squashed mode"

    flush_lines = _capture_flush(c)
    assert not any("some w3 message" in ln for ln in flush_lines), \
        "flush() must not repeat the W3 line"


def test_W6_w3_immediate_detailed() -> None:
    c = WarningCollector(detailed=True)
    immediate = _capture_immediate(c.w3, "another w3 message")
    assert any("another w3 message" in ln for ln in immediate)


# ---------------------------------------------------------------------------
# TC-W9  W7 (spec 0148): duplicate FDP name across -I roots, always immediate
# ---------------------------------------------------------------------------

def test_W9_w7_immediate_squashed() -> None:
    c = WarningCollector(detailed=False)
    immediate = _capture_immediate(
        c.w7, "foo.proto", "path/b/foo.textpb", "path/a/foo.textpb"
    )
    assert len(immediate) == 1
    line = immediate[0]
    assert line.startswith("Warning:")
    assert "path/b/foo.textpb" in line
    assert "file:foo.proto" in line
    assert "path/a/foo.textpb" in line

    flush_lines = _capture_flush(c)
    assert flush_lines == [], "flush() must not repeat the W7 line"


# ---------------------------------------------------------------------------
# TC-W7  Flush with no events produces no output
# ---------------------------------------------------------------------------

def test_W7_empty_flush() -> None:
    c = WarningCollector(detailed=False)
    lines = _capture_flush(c)
    assert lines == [], "Empty flush must produce no output"


# ---------------------------------------------------------------------------
# TC-W8  Multiple W5 keys sorted alphabetically
# ---------------------------------------------------------------------------

def test_W8_w5_alphabetical_sort() -> None:
    c = WarningCollector(detailed=False)
    c.w5("z/z.proto")
    c.w5("a/a.proto")

    lines = _capture_flush(c)
    w5_lines = [ln for ln in lines if "missing dependency" in ln]
    assert len(w5_lines) == 2
    assert "a/a.proto" in w5_lines[0]
    assert "z/z.proto" in w5_lines[1]


# ---------------------------------------------------------------------------
# TC-C1  _POOL_PREFIX stripped, no W4/W5
# ---------------------------------------------------------------------------

def test_C1_pool_prefix_stripped() -> None:
    prefix = "Couldn't build proto file into descriptor pool: "
    clean, w4, w5 = _classify_exc(prefix + "some other error")
    assert clean == "some other error"
    assert w4 is None
    assert w5 is None


# ---------------------------------------------------------------------------
# TC-C2  _RESOLVE_PREFIX → W4
# ---------------------------------------------------------------------------

def test_C2_resolve_prefix_gives_w4() -> None:
    clean, w4, w5 = _classify_exc("couldn't resolve name '.pkg.Type'")
    assert w4 == ".pkg.Type"
    assert w5 is None
    assert "couldn't resolve" in clean


# ---------------------------------------------------------------------------
# TC-C3  _DEPENDS_PREFIX → W5
# ---------------------------------------------------------------------------

def test_C3_depends_prefix_gives_w5() -> None:
    clean, w4, w5 = _classify_exc(
        "Depends on file 'path/to/dep.proto', but it has not been loaded"
    )
    assert w5 == "path/to/dep.proto"
    assert w4 is None


# ---------------------------------------------------------------------------
# TC-C4  Other error → neither W4 nor W5 (W6 bucket)
# ---------------------------------------------------------------------------

def test_C4_other_error_neither_w4_nor_w5() -> None:
    clean, w4, w5 = _classify_exc("Couldn't find Extension 42")
    assert w4 is None
    assert w5 is None
    assert clean == "Couldn't find Extension 42"


# ---------------------------------------------------------------------------
# TC-C5  Combined pool prefix + resolve prefix
# ---------------------------------------------------------------------------

def test_C5_combined_prefix_and_resolve() -> None:
    prefix = "Couldn't build proto file into descriptor pool: "
    clean, w4, w5 = _classify_exc(prefix + "couldn't resolve name '.foo.Bar'")
    assert w4 == ".foo.Bar"
    assert w5 is None
