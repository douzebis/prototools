# SPDX-FileCopyrightText: 2026 THALES CLOUD SECURISE SAS
#
# SPDX-License-Identifier: MIT

"""Mixin providing source_code_info comment extraction for descriptor nodes.

Also provides resolve_source_code_info_locations(), which turns the pending
(path, open_line, close_line) markers accumulated in ctx.out_sci during
rendering (spec 0141) into concrete SourceCodeInfo.Location spans.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from google.protobuf.descriptor_pb2 import SourceCodeInfo

from .text import COMMENT, ORPHAN, TAB_SIZE, Block, BlockLine

if TYPE_CHECKING:
    from .context import Context


class SourceCodeInfoMixin:
    """Mixin providing render_message_comments and _calculate_source_code_info_path.

    Requires the host class to provide: _parent, name, nested_type, parent.
    """

    def render_message_comments(self, depth: int = 0) -> Block:
        """Extract and render message-level comments from source_code_info."""
        from .re_file import ReFileDescriptorProto

        out = Block()

        # Find the root file to access source_code_info
        current: Any = self
        while current.parent is not None:
            parent = current.parent
            if isinstance(parent, ReFileDescriptorProto):
                file = parent
                break
            current = parent
        else:
            return out

        if not file.source_code_info:
            return out

        path = self._calculate_source_code_info_path()
        if not path:
            return out

        for location in file.source_code_info.location:
            if list(location.path) == path:
                if location.leading_comments:
                    for line in location.leading_comments.strip().split('\n'):
                        out.append(BlockLine(line, depth, COMMENT))
                for detached in location.leading_detached_comments:
                    for line in detached.strip().split('\n'):
                        out.append(BlockLine(line, depth, COMMENT))
                if location.trailing_comments:
                    for line in location.trailing_comments.strip().split('\n'):
                        out.append(BlockLine(line, depth, COMMENT))
                break

        return out

    def _calculate_source_code_info_path(self) -> list[int] | None:
        """Calculate the source_code_info path for this message."""
        from .re_descriptor import ReDescriptorProto
        from .re_file import ReFileDescriptorProto

        path_segments = []
        current: Any = self

        while current.parent is not None:
            parent = current.parent

            if isinstance(parent, ReFileDescriptorProto):
                try:
                    index = next(i for i, m in enumerate(parent.message_type)
                                 if m.name == current.name)
                    path_segments.insert(0, [4, index])
                except StopIteration:
                    return None
                break
            elif isinstance(parent, ReDescriptorProto):
                try:
                    index = next(i for i, m in enumerate(parent.nested_type)
                                 if m.name == current.name)
                    path_segments.insert(0, [3, index])
                except StopIteration:
                    return None

            current = parent

        flat_path: list[int] = []
        for segment in path_segments:
            flat_path.extend(segment)

        return flat_path if flat_path else None


def closing_line(block: Block) -> BlockLine:
    """Return the last non-blank line of `block` (spec 0141).

    Render() methods append a trailing blank divider line after a node's
    closing brace (append_div_maybe()), so `block[-1]` is not reliably the
    closing brace itself — scan backward past any trailing blank lines.
    """
    idx = len(block) - 1
    while idx > 0 and not block[idx].text:
        idx -= 1
    return block[idx]


def _survives(line: BlockLine, ctx: Context) -> bool:
    """Whether `line` would survive Block.flush() (spec 0141).

    Mirrors flush()'s own redaction predicate: COMMENT lines are dropped
    under --redact-comments, ORPHAN lines under --redact-orphans, CODE lines
    always survive.
    """
    if line.type == COMMENT:
        return not ctx.redact_comments
    if line.type == ORPHAN:
        return not ctx.redact_orphans
    return True


def resolve_source_code_info_locations(
    out: Block,
    ctx: Context,
    pending: list[tuple[list[int], BlockLine, BlockLine]],
) -> list[SourceCodeInfo.Location]:
    """Resolve pending (path, open_line, close_line) markers into Locations.

    Must be called once `out` (the file's fully-built first-pass Block) is
    complete, and before it is mutated further by the binary side-channel's
    second pass. Line numbers are computed against the "flushed-equivalent"
    line count (i.e. matching what Block.flush() would actually emit under
    the current --redact-comments/--redact-orphans settings), so spans stay
    correct regardless of redaction. Markers whose open/close line was itself
    redacted away are silently dropped (best-effort: a missing Location is
    valid protobuf, unlike a wrong one).
    """
    line_index: dict[int, int] = {}
    counter = 0
    for line in out.lines:
        if _survives(line, ctx):
            line_index[id(line)] = counter
            counter += 1

    locations: list[SourceCodeInfo.Location] = []
    for path, open_line, close_line in pending:
        start_line = line_index.get(id(open_line))
        end_line = line_index.get(id(close_line))
        if start_line is None or end_line is None:
            continue
        start_col = open_line.level * TAB_SIZE
        end_col = close_line.level * TAB_SIZE + len(close_line.text)
        loc = SourceCodeInfo.Location()
        loc.path.extend(path)
        if start_line == end_line:
            loc.span.extend([start_line, start_col, end_col])
        else:
            loc.span.extend([start_line, start_col, end_line, end_col])
        locations.append(loc)
    return locations
