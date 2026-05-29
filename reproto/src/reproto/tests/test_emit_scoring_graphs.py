# SPDX-FileCopyrightText: Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
#
# SPDX-License-Identifier: MIT

"""Tests for the --emit-scoring-yaml option (spec 0045).

Each test compiles fixture .proto files with protoc, then runs the reproto CLI
with --emit-scoring-yaml and inspects the resulting YAML files.

TC-6 (spec 0086) covers canonized output paths when a variant rewrites file names.
"""

from __future__ import annotations

import os
import sys
import subprocess
from pathlib import Path
from typing import Any

import yaml

from reproto.tests.conftest import compile_proto, FIXTURES_DIR


def _load_yaml(path: Path) -> dict[str, Any]:
    data = yaml.safe_load(path.read_text())
    assert isinstance(data, dict)
    return data


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _run_reproto(
    pb_files: list[Path],
    out_dir: Path,
    extra_args: list[str] | None = None,
    include_dirs: list[Path] | None = None,
) -> subprocess.CompletedProcess[str]:
    src_path = str(Path(__file__).parent.parent.parent)
    pythonpath_parts = [src_path]
    if existing := os.environ.get("PYTHONPATH"):
        pythonpath_parts.append(existing)
    env = {**os.environ, "PYTHONPATH": os.pathsep.join(pythonpath_parts)}
    env.pop("REPROTO_VARIANT", None)

    dirs = include_dirs if include_dirs is not None else [FIXTURES_DIR]
    include_flags = [f"-I{d}" for d in dirs]

    cmd = [
        sys.executable, "-m", "reproto.cli",
        "--use-variant", "descriptor",
        *include_flags,
        f"--output-root={out_dir}",
        "--emit-scoring-yaml",
    ]
    if extra_args:
        cmd.extend(extra_args)
    cmd.extend(str(p) for p in pb_files)

    return subprocess.run(cmd, capture_output=True, text=True, env=env)


# ---------------------------------------------------------------------------
# TC-1: Basic emission — field kinds and child FQDNs
# ---------------------------------------------------------------------------

def test_TC1_basic_emission(tmp_path: Path) -> None:
    """field_comprehensive.proto: YAML is written; field kinds and child FQDNs are correct."""
    pb_dir = tmp_path / "pb"
    pb_dir.mkdir()
    out_dir = tmp_path / "out"
    out_dir.mkdir()

    (pb,) = compile_proto(pb_dir, "field_comprehensive.proto")
    result = _run_reproto([pb], out_dir)
    assert result.returncode == 0, result.stderr

    yaml_path = out_dir / "field_comprehensive.yaml"
    assert yaml_path.exists(), "YAML file must be written alongside .proto output"

    data = _load_yaml(yaml_path)
    messages = data["messages"]

    # PrimitiveTypes covers most scalar kinds (field numbers per fixture)
    prim = {f["number"]: f for f in messages["test.field.PrimitiveTypes"]["fields"]}
    assert prim[1]["type"] == "int32"      # req_int32
    assert prim[2]["type"] == "uint64"     # opt_int64  (int64 → UINT64 leaf)
    assert prim[3]["type"] == "uint32"     # rep_uint32
    assert prim[4]["type"] == "uint64"     # req_uint64
    assert prim[5]["type"] == "uint32"     # opt_sint32 (sint32 → UINT32 leaf)
    assert prim[6]["type"] == "uint64"     # rep_sint64 (sint64 → UINT64 leaf)
    assert prim[7]["type"] == "float"      # req_fixed32
    assert prim[8]["type"] == "double"     # opt_fixed64
    assert prim[9]["type"] == "float"      # rep_sfixed32
    assert prim[10]["type"] == "double"    # req_sfixed64
    assert prim[11]["type"] == "float"     # opt_float
    assert prim[12]["type"] == "double"    # rep_double
    assert prim[13]["type"] == "bool"      # req_bool
    assert prim[14]["type"] == "string"    # opt_string
    assert prim[15]["type"] == "bytes"     # rep_bytes

    # ComplexTypes: message field must have type message and correct child
    complex_fields = {f["number"]: f for f in messages["test.field.ComplexTypes"]["fields"]}
    msg_field = complex_fields[1]
    assert msg_field["type"] == "message"
    assert msg_field["child"] == "test.field.NestedMessage"
    assert "child" not in complex_fields[4]  # enum field — no child

    # No child on scalar fields
    for f in prim.values():
        assert "child" not in f

    # label: required/repeated are emitted; optional is the default (omitted)
    assert prim[1].get("label") == "required"   # req_int32  (required)
    assert prim[4].get("label") == "required"   # req_uint64 (required)
    assert prim[3].get("label") == "repeated"   # rep_uint32 (repeated)
    assert "label" not in prim[2]               # opt_int64  (optional — default, omitted)

    # Fields listed in ascending number order
    field_numbers = [f["number"] for f in messages["test.field.PrimitiveTypes"]["fields"]]
    assert field_numbers == sorted(field_numbers)

    # entries: all top-level messages in the file (sorted, full FQDNs)
    entries = data["entries"]
    assert "test.field.PrimitiveTypes" in entries
    assert "test.field.ComplexTypes" in entries
    assert "test.field.Outer" in entries
    # entries must be sorted
    assert entries == sorted(entries)
    # nested types must NOT appear in entries
    assert "test.field.Outer.Middle" not in entries
    assert "test.field.Outer.Middle.Inner" not in entries


# ---------------------------------------------------------------------------
# TC-2: Nested message types appear as top-level entries
# ---------------------------------------------------------------------------

def test_TC2_nested_message_types(tmp_path: Path) -> None:
    """Outer, Outer.Middle, Outer.Middle.Inner all appear as top-level keys."""
    pb_dir = tmp_path / "pb"
    pb_dir.mkdir()
    out_dir = tmp_path / "out"
    out_dir.mkdir()

    (pb,) = compile_proto(pb_dir, "field_comprehensive.proto")
    result = _run_reproto([pb], out_dir)
    assert result.returncode == 0, result.stderr

    data = _load_yaml(out_dir / "field_comprehensive.yaml")
    messages = data["messages"]

    assert "test.field.Outer" in messages
    assert "test.field.Outer.Middle" in messages
    assert "test.field.Outer.Middle.Inner" in messages


# ---------------------------------------------------------------------------
# TC-3: Cross-file reference
# ---------------------------------------------------------------------------

def test_TC3_cross_file_reference(tmp_path: Path) -> None:
    """address_book.yaml has child FQDN for PhoneNumber but not the type definition."""
    pb_dir = tmp_path / "pb"
    pb_dir.mkdir()
    out_dir = tmp_path / "out"
    out_dir.mkdir()

    phone_pb, ab_pb = compile_proto(pb_dir, "phone_number.proto", "address_book.proto")
    result = _run_reproto([phone_pb, ab_pb], out_dir)
    assert result.returncode == 0, result.stderr

    ab_data = _load_yaml(out_dir / "address_book.yaml")
    ab_messages = ab_data["messages"]

    # Person.phones (field 4) is repeated PhoneNumber — message with child
    person_fields = {f["number"]: f for f in ab_messages["tutorial.Person"]["fields"]}
    assert person_fields[4]["type"] == "message"
    assert person_fields[4]["child"] == "tutorial.PhoneNumber"

    # PhoneNumber must NOT be defined in address_book.yaml
    assert "tutorial.PhoneNumber" not in ab_messages

    # entries in address_book.yaml: only types defined in that file
    assert "tutorial.Person" in ab_data["entries"]
    assert "tutorial.PhoneNumber" not in ab_data["entries"]

    # PhoneNumber must be defined in phone_number.yaml
    phone_data = _load_yaml(out_dir / "phone_number.yaml")
    assert "tutorial.PhoneNumber" in phone_data["messages"]
    assert "tutorial.PhoneNumber" in phone_data["entries"]


# ---------------------------------------------------------------------------
# TC-4: Proto3 implicit packing
# ---------------------------------------------------------------------------

def test_TC4_proto3_implicit_packing(tmp_path: Path) -> None:
    """default_int (no [packed] option) -> LEN_PACKED; explicit_false -> VARINT."""
    pb_dir = tmp_path / "pb"
    pb_dir.mkdir()
    out_dir = tmp_path / "out"
    out_dir.mkdir()

    (pb,) = compile_proto(pb_dir, "packed_proto3.proto")
    result = _run_reproto([pb], out_dir)
    assert result.returncode == 0, result.stderr

    data = _load_yaml(out_dir / "packed_proto3.yaml")
    fields = {f["number"]: f for f in data["messages"]["mockup.Packed"]["fields"]}

    assert fields[1]["type"] == "LEN_PACKED"  # default_int: implicitly packed in proto3
    assert fields[2]["type"] == "LEN_PACKED"  # explicit_true
    assert fields[3]["type"] == "int32"       # explicit_false (repeated int32, not packed)


# ---------------------------------------------------------------------------
# TC-5: GROUP kind and child FQDN
# ---------------------------------------------------------------------------

def test_TC5_group_child_fqdn(tmp_path: Path) -> None:
    """GroupTest: group field entries use kind MESSAGE (spec 0058); group
    message entries carry kind GROUP at the message level."""
    pb_dir = tmp_path / "pb"
    pb_dir.mkdir()
    out_dir = tmp_path / "out"
    out_dir.mkdir()

    (pb,) = compile_proto(pb_dir, "field_comprehensive.proto")
    result = _run_reproto([pb], out_dir)
    assert result.returncode == 0, result.stderr

    data = _load_yaml(out_dir / "field_comprehensive.yaml")
    messages = data["messages"]
    fields = {f["number"]: f for f in messages["test.field.GroupTest"]["fields"]}

    # field 1: repeated group RepeatedGroup — field type is group (spec 0058)
    assert fields[1]["type"] == "group"
    assert fields[1]["child"] == "test.field.GroupTest.RepeatedGroup"

    # field 3: optional group OptionalGroup — field type is group (spec 0058)
    assert fields[3]["type"] == "group"
    assert fields[3]["child"] == "test.field.GroupTest.OptionalGroup"

    # The group message entries must have kind GROUP at the message level
    assert messages["test.field.GroupTest.RepeatedGroup"]["kind"] == "GROUP"
    assert messages["test.field.GroupTest.OptionalGroup"]["kind"] == "GROUP"


# ---------------------------------------------------------------------------
# TC-6: Canonized output paths via variant import rewrites (spec 0086)
# ---------------------------------------------------------------------------

def test_TC6_canonized_output_paths(tmp_path: Path) -> None:
    """Variant import_rewrites + namespace_rewrites: all outputs use canonized names.

    Uses address_book + phone_number fixtures with a variant that rewrites:
    - phone_number.proto -> canonical/phone_number.proto  (import_rewrites)
    - .tutorial.          -> .canonical.tutorial.          (namespace_rewrites)

    Verifies §86.1/§86.2 (file paths):
    - output .proto is at canonical/phone_number.proto (not phone_number.proto)
    - output .yaml  is at canonical/phone_number.yaml  (not phone_number.yaml)
    - import statement inside address_book.proto references canonical/phone_number.proto

    Verifies §86.3 (binary fdp.name and fdp.dependency):
    - phone_number.pb carries fdp.name == canonical/phone_number.proto
    - address_book.pb carries the canonized dependency path

    Verifies §86.4 (binary type_name):
    - address_book.pb Person.phones field carries
      type_name == .canonical.tutorial.PhoneNumber (not .tutorial.PhoneNumber)
    """
    pb_dir = tmp_path / "pb"
    pb_dir.mkdir()
    out_dir = tmp_path / "out"
    out_dir.mkdir()

    # Compile address_book + phone_number into a single FDS with --include_imports
    from reproto.tests.conftest import compile_proto_multi
    pb = compile_proto_multi(pb_dir / "ab.pb", "address_book.proto", "phone_number.proto")

    # Write a variant YAML that rewrites phone_number.proto -> canonical/phone_number.proto
    variant_yaml = tmp_path / "test_variant.yaml"
    variant_yaml.write_text(
        "name: test\n"
        "descriptor_proto: google/protobuf/descriptor.proto\n"
        "well_known: {}\n"
        "import_rewrites:\n"
        "  - match: phone_number.proto\n"
        "    action: rewrite\n"
        "    to: canonical/phone_number.proto\n"
        "namespace_rewrites:\n"
        "  - match: .tutorial.\n"
        "    action: rewrite\n"
        "    to: .canonical.tutorial.\n"
        "orphans: {}\n"
        "annotation_modules: []\n"
    )

    # The custom variant has no embedded .pb files, so --use-variant descriptor
    # cannot load the fallback from it.  Copy the embedded descriptor.pb from
    # the built-in google-protobuf variant into the temp variant directory so
    # load_embedded_proto_fallback() finds it under variant_root/variant_stem/.
    import importlib.resources
    embedded_pb = (
        importlib.resources.files("reproto.variants")
        .joinpath("google-protobuf")
        .joinpath("google").joinpath("protobuf").joinpath("descriptor.pb")
        .read_bytes()
    )
    descriptor_dir = tmp_path / "test_variant" / "google" / "protobuf"
    descriptor_dir.mkdir(parents=True)
    (descriptor_dir / "descriptor.pb").write_bytes(embedded_pb)

    src_path = str(Path(__file__).parent.parent.parent)
    import os
    pythonpath_parts = [src_path]
    if existing := os.environ.get("PYTHONPATH"):
        pythonpath_parts.append(existing)
    env = {**os.environ, "PYTHONPATH": os.pathsep.join(pythonpath_parts)}
    env.pop("REPROTO_VARIANT", None)

    result = subprocess.run(
        [
            sys.executable, "-m", "reproto.cli",
            "--proto-variant", str(variant_yaml),
            "--use-variant", "descriptor",
            f"-I{FIXTURES_DIR}",
            f"--output-root={out_dir}",
            "--emit-scoring-yaml",
            "--emit-binary",
            str(pb),
        ],
        capture_output=True, text=True, env=env,
    )
    assert result.returncode == 0, result.stderr

    # §86.1 — .proto output must be at canonized path
    assert (out_dir / "canonical" / "phone_number.proto").exists(), (
        "phone_number.proto must be written at canonical/phone_number.proto"
    )
    assert not (out_dir / "phone_number.proto").exists(), (
        "phone_number.proto must NOT be written at the original path"
    )

    # §86.2 — .yaml output must be at canonized path
    assert (out_dir / "canonical" / "phone_number.yaml").exists(), (
        "phone_number.yaml must be written at canonical/phone_number.yaml"
    )
    assert not (out_dir / "phone_number.yaml").exists(), (
        "phone_number.yaml must NOT be written at the original path"
    )

    # §86.1 — import statement inside address_book.proto must reference the canonized path
    ab_proto = (out_dir / "address_book.proto").read_text()
    assert 'import "canonical/phone_number.proto"' in ab_proto, (
        "address_book.proto must import canonical/phone_number.proto"
    )
    assert 'import "phone_number.proto"' not in ab_proto, (
        "address_book.proto must not import the original phone_number.proto path"
    )

    # §86.3 — binary phone_number.pb must carry the canonized file name
    from google.protobuf.descriptor_pb2 import FileDescriptorProto
    pn_pb_path = out_dir / "canonical" / "phone_number.pb"
    assert pn_pb_path.exists(), "phone_number.pb must be written at canonical/phone_number.pb"
    pn_fdp = FileDescriptorProto()
    pn_fdp.ParseFromString(pn_pb_path.read_bytes())
    assert pn_fdp.name == "canonical/phone_number.proto", (
        f"phone_number.pb fdp.name must be canonized, got {pn_fdp.name!r}"
    )

    # §86.3 — binary address_book.pb must carry the canonized dependency path
    ab_pb_path = out_dir / "address_book.pb"
    assert ab_pb_path.exists(), "address_book.pb must be written"
    ab_fdp = FileDescriptorProto()
    ab_fdp.ParseFromString(ab_pb_path.read_bytes())
    assert "canonical/phone_number.proto" in ab_fdp.dependency, (
        f"address_book.pb dependency must contain canonized path, got {list(ab_fdp.dependency)!r}"
    )
    assert "phone_number.proto" not in ab_fdp.dependency, (
        "address_book.pb must not contain the original phone_number.proto dependency"
    )

    # §86.4 — binary address_book.pb Person.phones field must carry the canonized type_name
    person_msg = next(m for m in ab_fdp.message_type if m.name == "Person")
    phones_field = next(f for f in person_msg.field if f.name == "phones")
    assert phones_field.type_name == ".canonical.tutorial.PhoneNumber", (
        f"phones field type_name must be canonized, got {phones_field.type_name!r}"
    )
