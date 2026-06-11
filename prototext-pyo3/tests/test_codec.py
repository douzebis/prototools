# SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
#
# SPDX-License-Identifier: MIT

"""Unit tests for prototext_codec_lib.

Fixtures are synthesised in-process using protobuf's Python API so that
the test suite has no dependency on protoc and no committed binary files.
"""

from __future__ import annotations

from google.protobuf.descriptor_pb2 import FileDescriptorProto, FileDescriptorSet

import prototext_codec_lib


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_fdp_bytes(name: str = "test/schema.proto") -> bytes:
    """Return a minimal serialised FileDescriptorProto."""
    fdp = FileDescriptorProto()
    fdp.name = name
    return fdp.SerializeToString()


def _fdp_schema_bytes() -> bytes:
    """Return a FileDescriptorSet describing FileDescriptorProto itself.

    register_schema expects a FileDescriptorSet (not a bare FileDescriptorProto).
    """
    fds = FileDescriptorSet()
    FileDescriptorProto.DESCRIPTOR.file.CopyToProto(fds.file.add())
    return fds.SerializeToString()


# ---------------------------------------------------------------------------
# TC-1  Empty input → returns b""
# ---------------------------------------------------------------------------

def test_format_as_text_empty() -> None:
    """format_as_text on empty bytes returns empty bytes without raising."""
    result = prototext_codec_lib.format_as_text(b"")
    assert result == b""


# ---------------------------------------------------------------------------
# TC-2  format_as_text without schema always renders (spec 0097 goal 5)
# ---------------------------------------------------------------------------

def test_format_as_text_no_schema_renders_unknown_fields() -> None:
    """format_as_text without a schema always renders unknown fields.

    Spec 0097 goal 5: when no descriptor is active, unknown fields are always
    rendered regardless of --no-annotations / include_annotations.  The
    three-step cascade (nested message → UTF-8 string → bytes) is applied.
    A FileDescriptorProto's name field (field 1, LEN) is valid UTF-8, so it
    is rendered as a quoted string.
    """
    result = prototext_codec_lib.format_as_text(_make_fdp_bytes())
    assert result == b'1: "test/schema.proto"\n'


# ---------------------------------------------------------------------------
# TC-3  format_as_text with annotations produces the #@ prototext: header
# ---------------------------------------------------------------------------

def test_format_as_text_annotations_has_prototext_header() -> None:
    """format_as_text with include_annotations=True produces a #@ prototext: header."""
    result = prototext_codec_lib.format_as_text(
        _make_fdp_bytes(), include_annotations=True
    )
    assert result.startswith(b"#@ prototext:"), (
        f"expected #@ prototext: header, got: {result[:40]!r}"
    )


# ---------------------------------------------------------------------------
# TC-4  Round-trip: format_as_bytes(format_as_text(data, annotations)) == data
# ---------------------------------------------------------------------------

def test_round_trip() -> None:
    """Encoding to annotated text and back to binary is lossless."""
    original = _make_fdp_bytes("roundtrip/check.proto")
    text = prototext_codec_lib.format_as_text(original, include_annotations=True)
    recovered = prototext_codec_lib.format_as_bytes(text)
    assert recovered == original, (
        f"round-trip mismatch: {len(original)} bytes in, {len(recovered)} bytes out"
    )


# ---------------------------------------------------------------------------
# TC-5  format_as_bytes with assume_binary=True returns input unchanged
# ---------------------------------------------------------------------------

def test_format_as_bytes_assume_binary_passthrough() -> None:
    """format_as_bytes(data, assume_binary=True) is a no-op passthrough."""
    data = _make_fdp_bytes()
    result = prototext_codec_lib.format_as_bytes(data, assume_binary=True)
    assert result == data


# ---------------------------------------------------------------------------
# TC-6  format_as_text on already-textual input returns it unchanged
# ---------------------------------------------------------------------------

def test_format_as_text_text_passthrough() -> None:
    """format_as_text on input that already starts with #@ prototext: is a no-op."""
    original = _make_fdp_bytes()
    text = prototext_codec_lib.format_as_text(original, include_annotations=True)
    assert text.startswith(b"#@ prototext:")
    # Calling format_as_text again must return the same bytes object (fast path).
    result = prototext_codec_lib.format_as_text(text)
    assert result == text


# ---------------------------------------------------------------------------
# TC-7  register_schema returns a SchemaHandle without raising
# ---------------------------------------------------------------------------

def test_register_schema_schemaless() -> None:
    """register_schema(b'', '') returns a SchemaHandle for schema-less decoding."""
    handle = prototext_codec_lib.register_schema(b"", "")
    assert isinstance(handle, prototext_codec_lib.SchemaHandle)


def test_register_schema_with_fdp() -> None:
    """register_schema with a real FileDescriptorProto schema returns a handle."""
    schema_bytes = _fdp_schema_bytes()
    handle = prototext_codec_lib.register_schema(
        schema_bytes, "google.protobuf.FileDescriptorProto"
    )
    assert isinstance(handle, prototext_codec_lib.SchemaHandle)


# ---------------------------------------------------------------------------
# TC-8  Schema-aware format_as_text includes field name annotations
# ---------------------------------------------------------------------------

def test_format_as_text_with_schema_annotations() -> None:
    """format_as_text with a schema and include_annotations=True annotates field names."""
    # Use FileDescriptorProto's own descriptor as the schema, and a
    # serialised FileDescriptorProto instance as the data.
    schema_bytes = _fdp_schema_bytes()
    handle = prototext_codec_lib.register_schema(
        schema_bytes, "google.protobuf.FileDescriptorProto"
    )
    data = _make_fdp_bytes("annotated/schema.proto")
    result = prototext_codec_lib.format_as_text(
        data, schema=handle, include_annotations=True
    )
    # The "name" field (field 1 of FileDescriptorProto) should appear as an
    # annotation comment in the output.
    assert b"name" in result, (
        f"expected 'name' annotation in output, got: {result!r}"
    )
