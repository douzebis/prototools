# SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
#
# SPDX-License-Identifier: MIT

"""Spec 0371 S1/S2 (test plan 1): `fd_is_packed` over the declaration matrix.

The declaration is what a writer follows, and the scorer charges an encoding
that contradicts it, so this must be right for every syntax — in particular
for the proto3 field that carries some other option (PROST-ISSUES.md section
1), where prost-reflect's own `is_packed()` answers false.
"""

from __future__ import annotations

from google.protobuf import descriptor_pb2, descriptor_pool
from google.protobuf.descriptor_pb2 import FieldDescriptorProto as FDP

from reproto.field_descriptor import fd_is_packed

_L_REP = FDP.LABEL_REPEATED
_L_OPT = FDP.LABEL_OPTIONAL


def _field(name, number, ty, label=_L_REP, packed=None, other_option=False,
           features=None):
    f = FDP(name=name, number=number, type=ty, label=label)
    if packed is not None:
        f.options.packed = packed
    if other_option:
        # Present-but-silent FieldOptions: the prost-reflect section 1 case.
        f.options.deprecated = False
    if features is not None:
        f.options.features.repeated_field_encoding = features
    return f


def _pool_message(
    syntax: str, fields, edition: "descriptor_pb2.Edition.ValueType | None" = None
):
    fdp = descriptor_pb2.FileDescriptorProto(
        name=f"m_{syntax}.proto", package=f"m{syntax}")
    if syntax == "editions":
        if edition is None:
            raise ValueError("an editions file needs an edition")
        fdp.syntax = "editions"
        fdp.edition = edition
    else:
        fdp.syntax = syntax
    fdp.message_type.add(name="M", field=fields)
    pool = descriptor_pool.DescriptorPool()
    pool.Add(fdp)
    return pool.FindMessageTypeByName(f"m{syntax}.M")


def test_proto2():
    m = _pool_message("proto2", [
        _field("default", 1, FDP.TYPE_INT32),
        _field("packed", 2, FDP.TYPE_INT32, packed=True),
        _field("strings", 3, FDP.TYPE_STRING),
        _field("single", 4, FDP.TYPE_INT32, label=_L_OPT),
    ])
    got = {f.name: fd_is_packed(f) for f in m.fields}
    assert got == {"default": False, "packed": True, "strings": False,
                   "single": False}


def test_proto3():
    m = _pool_message("proto3", [
        _field("default", 1, FDP.TYPE_INT32),
        _field("unpacked", 2, FDP.TYPE_INT32, packed=False),
        _field("with_option", 3, FDP.TYPE_INT32, other_option=True),
        _field("strings", 4, FDP.TYPE_STRING),
        _field("single", 5, FDP.TYPE_INT32, label=_L_OPT),
    ])
    got = {f.name: fd_is_packed(f) for f in m.fields}
    assert got == {"default": True, "unpacked": False, "with_option": True,
                   "strings": False, "single": False}


def test_editions():
    enc = descriptor_pb2.FeatureSet
    m = _pool_message("editions", [
        _field("default", 1, FDP.TYPE_INT32),
        _field("expanded", 2, FDP.TYPE_INT32,
               features=enc.RepeatedFieldEncoding.EXPANDED),
        _field("packed", 3, FDP.TYPE_INT32,
               features=enc.RepeatedFieldEncoding.PACKED),
    ], edition=descriptor_pb2.Edition.EDITION_2023)
    got = {f.name: fd_is_packed(f) for f in m.fields}
    assert got == {"default": True, "expanded": False, "packed": True}
