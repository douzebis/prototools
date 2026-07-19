# SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
#
# SPDX-License-Identifier: MIT

"""filter_config.py — load a --filter-config YAML file's seed/prune lists.

Returns raw (unresolved, unnormalised) strings, using the exact same
syntax as -s/--seed and -p/--prune CLI values. The caller applies the
same _resolve_seed_or_prune()/_normalise_fqdn() pipeline used for CLI
values (cli.py) to both sources uniformly.
"""

from __future__ import annotations

from pathlib import Path

import yaml


def load(path: Path) -> tuple[list[str], list[str]]:
    """Load seed/prune lists from a filter-config YAML file.

    Raises ValueError on any structural problem (not a mapping, unknown
    top-level key, non-list or non-string-list value). Callers are
    expected to translate ValueError into a click.UsageError.
    """
    try:
        raw = yaml.safe_load(path.read_text(encoding='utf-8'))
    except yaml.YAMLError as e:
        raise ValueError(f'{path}: invalid YAML: {e}') from e

    if raw is None:
        raw = {}
    if not isinstance(raw, dict):
        raise ValueError(
            f'{path}: filter-config must be a YAML mapping, '
            f'got {type(raw).__name__}'
        )

    unknown = set(raw) - {'seed', 'prune'}
    if unknown:
        raise ValueError(
            f'{path}: unknown filter-config key(s): {", ".join(sorted(unknown))}'
        )

    seed = raw.get('seed') or []
    prune = raw.get('prune') or []
    for key, values in (('seed', seed), ('prune', prune)):
        if not isinstance(values, list) or not all(isinstance(v, str) for v in values):
            raise ValueError(f"{path}: '{key}' must be a list of strings")

    return list(seed), list(prune)
