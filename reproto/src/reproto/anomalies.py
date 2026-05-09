# SPDX-FileCopyrightText: 2026 THALES CLOUD SECURISE SAS
#
# SPDX-License-Identifier: MIT

"""Rendering anomaly registry and reporting helpers (spec 0024).

Every anomaly that reproto detects during rendering is defined here as an
entry in ANOMALIES.  Call report() at each detection site to simultaneously
emit a cli_warning to stderr and obtain a BlockLine to insert into the
rendered .proto output.

Indirection design
------------------
ANOMALIES is a plain dict[str, Anomaly].  Each Anomaly holds two independent
format strings — one for stderr, one for the .proto comment — that use
str.format_map() against the kwargs passed to report().  The _Ignore helper
silently drops keys that a given template does not reference, so each string
uses exactly the context it needs with no coupling to the other.

To amend a message: edit the format string in ANOMALIES.
To add a new anomaly: add an entry to ANOMALIES and call report() at the
detection site.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from lib.warnings import cli_warning, get_collector

from .text import COMMENT, BlockLine


@dataclass(frozen=True)
class Anomaly:
    tag: str       # "proto3" | "downconvert" | "editions" | "render"
    severity: str  # "OMITTED" | "WARNING"
    stderr: str    # format-string printed to stderr via cli_warning()
    comment: str   # format-string for the body of the // OMITTED/WARNING line


class _Ignore(dict):
    """dict subclass that returns '' for missing keys in format_map().

    Allows each format string to reference only the kwargs it needs without
    requiring the caller to know which keys each template uses.
    """
    def __missing__(self, key: str) -> str:
        return ''


# ---------------------------------------------------------------------------
# Anomaly registry
# ---------------------------------------------------------------------------

ANOMALIES: dict[str, Anomaly] = {

    # -- A. File level --------------------------------------------------------

    "A1": Anomaly(
        tag="editions",
        severity="WARNING",
        stderr="'{file}': editions file rendered as proto2 (--force-proto2-output)",
        comment="editions file rendered as proto2 (--force-proto2-output)",
    ),

    "A2": Anomaly(
        tag="downconvert",
        severity="WARNING",
        stderr="'{file}': output syntax downconverted from {syntax} to proto2",
        comment='original file used "{syntax}" syntax; rendered as proto2',
    ),

    "A3": Anomaly(
        tag="render",
        severity="OMITTED",
        stderr="'{file}': failed to render file options: {exc_msg}",
        comment="file options could not be rendered ({exc_msg})",
    ),

    "A4": Anomaly(
        tag="proto3",
        severity="WARNING",
        stderr="'{file}': 'import weak' is not valid in proto3; rendering as plain import: \"{dep}\"",
        comment="'import weak \"{dep}\"' is not valid in proto3; rendered as plain import",
    ),

    "A5": Anomaly(
        tag="proto3",
        severity="OMITTED",
        stderr="'{file}': top-level extend block for '{extendee}' is not valid in proto3; omitting",
        comment="extend block for '{extendee}' is not valid in proto3",
    ),

    # -- B. Message level -----------------------------------------------------

    "B1": Anomaly(
        tag="proto3",
        severity="OMITTED",
        stderr="message '{msg}': nested extend block for '{extendee}' is not valid in proto3; omitting",
        comment="extend block for '{extendee}' is not valid in proto3",
    ),

    "B2": Anomaly(
        tag="proto3",
        severity="OMITTED",
        stderr="message '{msg}': extension range [{start}, {end}) is not valid in proto3; omitting",
        comment="extensions {start} to {end}; — not valid in proto3",
    ),

    "B3": Anomaly(
        tag="proto3",
        severity="WARNING",
        stderr="message '{msg}': 'message_set_wire_format' is not valid in proto3; omitting",
        comment="'message_set_wire_format = true' is not valid in proto3; omitted",
    ),

    # -- C. Field level -------------------------------------------------------

    "C1": Anomaly(
        tag="render",
        severity="WARNING",
        stderr="field '{field}': non-canonical map entry '{entry}' (found fields: {found}); rendered as repeated message — wire semantics differ",
        comment="non-canonical map entry '{entry}'; rendered as repeated message — wire semantics differ from original",
    ),

    "C2": Anomaly(
        tag="proto3",
        severity="WARNING",
        stderr="field '{name}': groups are not valid in proto3; rendering as plain message field",
        comment="group field; rendered as plain message field — wire semantics differ from original",
    ),

    "C3": Anomaly(
        tag="proto3",
        severity="WARNING",
        stderr="field '{name}': 'required' label is not valid in proto3; rendering as implicit singular",
        comment="'required' label is not valid in proto3; rendered as implicit singular",
    ),

    "C4": Anomaly(
        tag="proto3",
        severity="WARNING",
        stderr="field '{name}': explicit default values are not valid in proto3; omitting",
        comment="explicit default value is not valid in proto3; omitted",
    ),

    "C5": Anomaly(
        tag="render",
        severity="WARNING",
        stderr="'{file}' field '{name}': failed to render options: {exc_msg}",
        comment="field options could not be rendered ({exc_msg})",
    ),

    # -- D. Option rendering --------------------------------------------------

    "D1": Anomaly(
        tag="render",
        severity="WARNING",
        stderr="option '{name}': unexpected value type {type}; rendered as 0",
        comment="option '{name}': unexpected value type {type} — rendered as 0, value may be wrong",
    ),

    "D2": Anomaly(
        tag="render",
        severity="OMITTED",
        stderr="option '{name}': unrecognised descriptor type; omitting",
        comment="option '{name}' has unrecognised descriptor type",
    ),
}


# ---------------------------------------------------------------------------
# Public helper
# ---------------------------------------------------------------------------

# Prefix injected by the C extension on pool lookup failures — not user-actionable.
_POOL_PREFIX = "Couldn't build proto file into descriptor pool: "
_RESOLVE_PREFIX = "couldn't resolve name '"
_DEPENDS_PREFIX = "Depends on file '"


def _classify_exc(exc_msg: str) -> tuple[str, str | None, str | None]:
    """Parse a pool TypeError message into (clean_msg, w4_type, w5_file).

    Returns:
        clean_msg: exc_msg with the pool boilerplate prefix stripped.
        w4_type:   the unresolvable type name, or None.
        w5_file:   the missing dependency file path, or None.
    """
    msg = exc_msg
    if msg.startswith(_POOL_PREFIX):
        msg = msg[len(_POOL_PREFIX):]
    w4: str | None = None
    w5: str | None = None
    if msg.startswith(_RESOLVE_PREFIX):
        # "couldn't resolve name '.pkg.Type'"
        w4 = msg[len(_RESOLVE_PREFIX):].rstrip("'")
    elif msg.startswith(_DEPENDS_PREFIX):
        # "Depends on file 'path/to/file.proto', but it has not been loaded"
        inner = msg[len(_DEPENDS_PREFIX):]
        w5 = inner.split("'")[0]
    return msg, w4, w5


def report(code: str, depth: int, **kwargs: Any) -> BlockLine:
    """Emit a warning and return a BlockLine for the .proto comment.

    Args:
        code:   Anomaly identifier, e.g. "C3".  Must be a key in ANOMALIES.
        depth:  Indentation depth for the returned BlockLine.
        **kwargs: All available context for the format strings.  Each template
                  uses whatever subset it needs; unused keys are silently
                  ignored via _Ignore.

    Returns:
        A BlockLine of type COMMENT ready to append/insert into a Block.
        For OMITTED anomalies, insert it where the construct would have been.
        For WARNING anomalies, insert it immediately before the degraded line.
    """
    anomaly = ANOMALIES[code]

    # For A3/C5: classify W4/W5 and route through WarningCollector.
    exc_msg: str = kwargs.get('exc_msg', '')
    if code in ('A3', 'C5') and exc_msg:
        clean_msg, w4, w5 = _classify_exc(exc_msg)
        collector = get_collector()
        if w4 is not None:
            collector.w4(w4)
        elif w5 is not None:
            collector.w5(w5)
        else:
            # Other render error (e.g. "Couldn't find Extension N") — route
            # through W6 so it is buffered and sorted with the rest.
            proto_file = kwargs.get('file', '')
            field_name = kwargs.get('name', '')
            field_ctx = f"field '{field_name}'" if field_name else ''
            collector.w6(proto_file, field_ctx, clean_msg)
        kwargs = dict(kwargs, exc_msg=clean_msg)
    else:
        ctx_map = _Ignore(kwargs)
        if anomaly.stderr:
            cli_warning(anomaly.stderr.format_map(ctx_map))

    prefix = f'{anomaly.severity}[{anomaly.tag}]:'
    body = anomaly.comment.format_map(_Ignore(kwargs))
    return BlockLine(f'{prefix} {body}', depth, COMMENT)
