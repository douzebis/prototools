// SPDX-FileCopyrightText: 2025 - 2026 Frederic Ruget <fred@atlant.is> <fred@s3ns.io> (GitHub: @douzebis)
// SPDX-FileCopyrightText: 2025 - 2026 Thales Cloud Sécurisé
//
// SPDX-License-Identifier: MIT

use prost_reflect::{FieldDescriptor, Kind};

use super::FieldOrExt;

use crate::helpers::{
    decode_double, decode_fixed32, decode_fixed64, decode_float, decode_int32, decode_sfixed32,
    decode_sfixed64, decode_sint32, decode_sint64, decode_uint32, parse_varint,
};
use crate::serialize::common::{
    format_bool_protoc, format_double_protoc, format_enum_protoc, format_fixed32_protoc,
    format_fixed64_protoc, format_float_protoc, format_int32_protoc, format_int64_protoc,
    format_sfixed32_protoc, format_sfixed64_protoc, format_sint32_protoc, format_sint64_protoc,
    format_uint32_protoc, format_uint64_protoc,
};

use super::helpers::{render_invalid, wfl_prefix_n, write_dec_u64, AnnWriter};
use super::{ANNOTATIONS, CBL_START};

// ── Packed decode helpers ─────────────────────────────────────────────────────

/// Decode a fixed-width packed array (element size 4 or 8 bytes).
///
/// Returns `Ok(formatted_list)` or `Err(())` on truncation.
/// The closure `fmt` receives each decoded element's raw byte slice.
#[inline]
fn decode_packed_fixed<F>(data: &[u8], elem_size: usize, fmt: F) -> Result<String, ()>
where
    F: Fn(&[u8]) -> String,
{
    let mut vals: Vec<String> = Vec::with_capacity(data.len() / elem_size);
    let mut i = 0;
    while i < data.len() {
        if i + elem_size > data.len() {
            return Err(());
        }
        vals.push(fmt(&data[i..i + elem_size]));
        i += elem_size;
    }
    Ok(format!("[{}]", vals.join(", ")))
}

/// Decode a packed payload and return `(value_str, is_invalid, ohbs, neg_truncs, enum_nums)`.
///
/// `neg_truncs` is non-empty only for int32/enum packed fields where some elements
/// use the truncated 5-byte encoding for negative values.
/// `enum_nums` is non-empty only for enum fields; contains the raw i32 numeric values
/// for use in the annotation `EnumTypeName([n1, n2])`.
fn decode_packed_to_str(
    data: &[u8],
    fs: &FieldDescriptor,
) -> (String, bool, Vec<u64>, Vec<bool>, Vec<i32>) {
    let ok = |s| (s, false, vec![], vec![], vec![]);
    let err = || (String::new(), true, vec![], vec![], vec![]);

    match fs.kind() {
        Kind::Double => {
            match decode_packed_fixed(data, 8, |b| format_double_protoc(decode_double(b))) {
                Ok(s) => ok(s),
                Err(()) => err(),
            }
        }
        Kind::Float => {
            match decode_packed_fixed(data, 4, |b| format_float_protoc(decode_float(b))) {
                Ok(s) => ok(s),
                Err(()) => err(),
            }
        }
        Kind::Fixed64 => {
            match decode_packed_fixed(data, 8, |b| format_fixed64_protoc(decode_fixed64(b))) {
                Ok(s) => ok(s),
                Err(()) => err(),
            }
        }
        Kind::Sfixed64 => {
            match decode_packed_fixed(data, 8, |b| format_sfixed64_protoc(decode_sfixed64(b))) {
                Ok(s) => ok(s),
                Err(()) => err(),
            }
        }
        Kind::Fixed32 => {
            match decode_packed_fixed(data, 4, |b| format_fixed32_protoc(decode_fixed32(b))) {
                Ok(s) => ok(s),
                Err(()) => err(),
            }
        }
        Kind::Sfixed32 => {
            match decode_packed_fixed(data, 4, |b| format_sfixed32_protoc(decode_sfixed32(b))) {
                Ok(s) => ok(s),
                Err(()) => err(),
            }
        }
        // Varint-packed types
        _ => decode_packed_varints_to_str(data, fs),
    }
}

fn decode_packed_varints_to_str(
    data: &[u8],
    fs: &FieldDescriptor,
) -> (String, bool, Vec<u64>, Vec<bool>, Vec<i32>) {
    let is_enum = matches!(fs.kind(), Kind::Enum(_));
    let mut strs: Vec<String> = Vec::new();
    let mut ohbs: Vec<u64> = Vec::new();
    let mut neg_truncs: Vec<bool> = Vec::new();
    // For ENUM fields: collects raw i32 numerics for the annotation EnumType([n1, n2]).
    let mut enum_nums: Vec<i32> = Vec::new();
    // For ENUM fields: true if any element is not in the enum value table.
    let mut has_enum_unknown = false;
    let mut i = 0;
    while i < data.len() {
        let vr = parse_varint(data, i);
        if vr.varint_gar.is_some() {
            return (String::new(), true, vec![], vec![], vec![]);
        }
        i = vr.next_pos;
        ohbs.push(vr.varint_ohb.unwrap_or(0));
        let v = vr.varint.unwrap();
        let s = match fs.kind() {
            Kind::Int64 => format_int64_protoc(crate::helpers::decode_int64(v)),
            Kind::Uint64 => format_uint64_protoc(v),
            Kind::Int32 => {
                if v <= 0x7FFF_FFFF {
                    neg_truncs.push(false);
                    format_int32_protoc(decode_int32(v))
                } else if v <= 0xFFFF_FFFF {
                    neg_truncs.push(true);
                    format_int32_protoc(decode_int32(v))
                } else if v >= 0xFFFF_FFFF_8000_0000 {
                    neg_truncs.push(false);
                    format_int32_protoc(decode_int32(v))
                } else {
                    return (String::new(), true, vec![], vec![], vec![]);
                }
            }
            Kind::Bool => {
                if v > 1 {
                    return (String::new(), true, vec![], vec![], vec![]);
                }
                format_bool_protoc(v != 0).to_owned()
            }
            Kind::Uint32 => {
                if v >= (1 << 32) {
                    return (String::new(), true, vec![], vec![], vec![]);
                }
                format_uint32_protoc(decode_uint32(v))
            }
            Kind::Enum(ref enum_desc) => {
                let n_i32 = if v <= 0x7FFF_FFFF {
                    neg_truncs.push(false);
                    decode_int32(v)
                } else if v <= 0xFFFF_FFFF {
                    neg_truncs.push(true);
                    decode_int32(v)
                } else if v >= 0xFFFF_FFFF_8000_0000 {
                    neg_truncs.push(false);
                    decode_int32(v)
                } else {
                    return (String::new(), true, vec![], vec![], vec![]);
                };
                enum_nums.push(n_i32);
                // Look up symbolic name; fall back to numeric string.
                match enum_desc.get_value(n_i32) {
                    Some(ev) => ev.name().to_owned(),
                    None => {
                        has_enum_unknown = true;
                        format_enum_protoc(n_i32)
                    }
                }
            }
            Kind::Sint32 => {
                if v >= (1 << 32) {
                    return (String::new(), true, vec![], vec![], vec![]);
                }
                format_sint32_protoc(decode_sint32(v))
            }
            Kind::Sint64 => format_sint64_protoc(decode_sint64(v)),
            _ => return (String::new(), true, vec![], vec![], vec![]),
        };
        strs.push(s);
    }
    // Only report ohbs if any are non-zero
    let ohbs_out = if ohbs.iter().any(|&x| x > 0) {
        ohbs
    } else {
        vec![]
    };
    // Only report neg_truncs if any are true
    let neg_truncs_out = if neg_truncs.iter().any(|&x| x) {
        neg_truncs
    } else {
        vec![]
    };
    // enum_nums is non-empty only for ENUM fields; has_enum_unknown is determined
    // by the caller (render_packed) by checking enum_desc against enum_nums.
    let _ = has_enum_unknown; // caller recomputes from enum_nums + enum_desc
    let enum_nums_out = if is_enum { enum_nums } else { vec![] };
    (
        format!("[{}]", strs.join(", ")),
        false,
        ohbs_out,
        neg_truncs_out,
        enum_nums_out,
    )
}

// ── Packed field renderer ─────────────────────────────────────────────────────

/// Render a packed repeated field.
pub(super) fn render_packed(
    field_number: u64,
    fs: &FieldDescriptor,
    tag_ohb: Option<u64>,
    tag_oor: bool,
    len_ohb: Option<u64>,
    data: &[u8],
    out: &mut Vec<u8>,
) {
    let annotations = ANNOTATIONS.with(|c| c.get());
    // Decode the packed payload into a formatted "[v1, v2, ...]" string.
    // On decode error → INVALID_PACKED_RECORDS.
    let (value_str, is_invalid_packed, records_ohb, records_neg_trunc, enum_nums) =
        decode_packed_to_str(data, fs);

    // Wrap fs for functions that take Option<&FieldOrExt>.
    // Packed fields are always regular fields (never extensions).
    let foe = FieldOrExt::Field(fs.clone());

    if is_invalid_packed {
        render_invalid(
            field_number,
            Some(&foe),
            tag_ohb,
            tag_oor,
            "INVALID_PACKED_RECORDS",
            data,
            out,
        );
        return;
    }

    // For ENUM packed fields: check whether any element has no schema name.
    let enum_unknown = if let Kind::Enum(ref enum_desc) = fs.kind() {
        !enum_nums.is_empty() && enum_nums.iter().any(|&n| enum_desc.get_value(n).is_none())
    } else {
        false
    };

    // Write line directly — no intermediate String allocations.
    wfl_prefix_n(field_number, Some(&foe), false, out);
    out.extend_from_slice(value_str.as_bytes());
    if annotations {
        let mut aw = AnnWriter::new();
        // v2: field_decl FIRST, then modifiers.
        // For ENUM packed fields, pass enum_nums so the annotation emits EnumType([n1, n2]).
        let enum_packed = if !enum_nums.is_empty() {
            Some(enum_nums.as_slice())
        } else {
            None
        };
        aw.push_field_decl(out, field_number, Some(&foe), None, enum_packed);
        if let Some(v) = tag_ohb {
            aw.push_u64_mod(out, b"tag_ohb: ", v);
        }
        if tag_oor {
            aw.push(out, b"TAG_OOR");
        }
        if let Some(v) = len_ohb {
            aw.push_u64_mod(out, b"len_ohb: ", v);
        }
        if !records_ohb.is_empty() {
            aw.sep(out);
            out.extend_from_slice(b"packed_ohb: [");
            for (i, &v) in records_ohb.iter().enumerate() {
                if i > 0 {
                    out.extend_from_slice(b", ");
                }
                write_dec_u64(v, out);
            }
            out.push(b']'); // v2: no trailing `;`
        }
        if !records_neg_trunc.is_empty() {
            aw.sep(out);
            out.extend_from_slice(b"packed_truncated_neg: [");
            for (i, &b) in records_neg_trunc.iter().enumerate() {
                if i > 0 {
                    out.extend_from_slice(b", ");
                }
                out.push(if b { b'1' } else { b'0' }); // v2: 0/1 not true/false
            }
            out.push(b']'); // v2: no trailing `;`
        }
        if enum_unknown {
            aw.push(out, b"ENUM_UNKNOWN");
        }
    }
    out.push(b'\n');
    CBL_START.with(|c| c.set(out.len())); // content line: set past-end to inhibit folding
}
