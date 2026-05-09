# SPDX-FileCopyrightText: 2026 THALES CLOUD SECURISE SAS
#
# SPDX-License-Identifier: MIT

"""Regression tests for pruned-file dependency handling (spec 0041).

Before the fix, a file that imported a pruned file would crash in phase 7
with "Node ... not initialized with message".  The crash occurred for both
--prune-triggered pruning and duplicate-symbol pruning.

Fixtures (under tests/fixtures/):
  prune_base.proto          — defines prune_test.Base
  prune_importer.proto      — imports prune_base.proto, defines prune_test.Importer
  prune_duplicate_1.proto   — defines prune_dup.SharedMsg  (first copy)
  prune_duplicate_2.proto   — defines prune_dup.SharedMsg  (second copy, same package)
  prune_dup_importer.proto  — imports prune_duplicate_2.proto, defines prune_dup_consumer.Consumer
"""

from __future__ import annotations

import os
import sys
import subprocess
from pathlib import Path

from reproto.tests.conftest import compile_proto, FIXTURES_DIR


def _run_reproto(
    pb_files: list[Path],
    out_dir: Path,
    extra_args: list[str] | None = None,
) -> subprocess.CompletedProcess[str]:
    src_path = str(Path(__file__).parent.parent.parent)
    pythonpath_parts = [src_path]
    if existing := os.environ.get("PYTHONPATH"):
        pythonpath_parts.append(existing)
    env = {**os.environ, "PYTHONPATH": os.pathsep.join(pythonpath_parts)}
    env.pop("REPROTO_VARIANT", None)

    cmd = [
        sys.executable, "-m", "reproto.cli",
        "--use-variant", "descriptor",
        f"-I{FIXTURES_DIR}",
        f"--output-root={out_dir}",
    ]
    if extra_args:
        cmd.extend(extra_args)
    cmd.extend(str(p) for p in pb_files)

    return subprocess.run(cmd, capture_output=True, text=True, env=env)


# ---------------------------------------------------------------------------
# T1 — --prune: importer of pruned file renders without crash
# ---------------------------------------------------------------------------

def test_explicit_prune_no_crash(tmp_path: Path) -> None:
    """Rendering a file that imports an explicitly pruned file must not crash."""
    pb_dir = tmp_path / "pb"
    pb_dir.mkdir()
    out_dir = tmp_path / "out"
    out_dir.mkdir()

    base_pb, importer_pb = compile_proto(pb_dir, "prune_base.proto", "prune_importer.proto")

    result = _run_reproto(
        [base_pb, importer_pb], out_dir,
        extra_args=["--prune", "file:prune_base.proto"],
    )

    assert result.returncode == 0, f"reproto crashed:\n{result.stderr}"
    assert (out_dir / "prune_importer.proto").exists()
    assert not (out_dir / "prune_base.proto").exists()


# ---------------------------------------------------------------------------
# T2 — duplicate symbols: importer of pruned file renders without crash
# ---------------------------------------------------------------------------

def test_duplicate_prune_no_crash(tmp_path: Path) -> None:
    """Rendering a file that imports a duplicate-pruned file must not crash."""
    # prune_duplicate_1 and prune_duplicate_2 define the same symbol (prune_dup.SharedMsg).
    # One will be pruned by the duplicate-detection logic; which one wins is
    # non-deterministic (set iteration order), so we only assert that exactly
    # one survives.
    pb_dir = tmp_path / "pb"
    pb_dir.mkdir()
    out_dir = tmp_path / "out"
    out_dir.mkdir()

    dup1_pb, dup2_pb, importer_pb = compile_proto(
        pb_dir,
        "prune_duplicate_1.proto",
        "prune_duplicate_2.proto",
        "prune_dup_importer.proto",
    )

    result = _run_reproto([dup1_pb, dup2_pb, importer_pb], out_dir)

    assert result.returncode == 0, f"reproto crashed:\n{result.stderr}"
    assert (out_dir / "prune_dup_importer.proto").exists()
    winner_count = sum(
        1 for f in ["prune_duplicate_1.proto", "prune_duplicate_2.proto"]
        if (out_dir / f).exists()
    )
    assert winner_count == 1, (
        f"Expected exactly one of prune_duplicate_1/2 in output, got {winner_count}"
    )
    # W3 warning must appear for whichever was pruned
    assert "pruned" in result.stderr and "duplicate symbols" in result.stderr
