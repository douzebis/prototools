// SPDX-FileCopyrightText: 2025 - 2026 Frederic Ruget <fred@atlant.is> <fred@s3ns.io> (GitHub: @douzebis)
// SPDX-FileCopyrightText: 2025 - 2026 Thales Cloud Sécurisé
//
// SPDX-License-Identifier: MIT

use std::sync::Arc;

use crate::helpers::{
    decode_bool, decode_double, decode_fixed32, decode_fixed64, decode_float, decode_int32,
    decode_int64, decode_sfixed32, decode_sfixed64, decode_sint32, decode_sint64, decode_uint32,
    decode_uint64, parse_varint, parse_wiretag, WiretagResult, WT_END_GROUP, WT_I32, WT_I64,
    WT_LEN, WT_START_GROUP, WT_VARINT,
};
use crate::schema::{proto_label, proto_type as pt, FieldInfo, MessageSchema, ParsedSchema};

// ── Data structures ───────────────────────────────────────────────────────────

/// Lossless representation of a protobuf message.
/// Corresponds to `prototext.proto / Message`.
#[derive(Debug, Default, Clone)]
pub struct ProtoTextMessage {
    /// Repeated Field (proto field 1).
    pub fields: Vec<ProtoTextField>,
}

/// Lossless representation of one protobuf field.
/// Corresponds to `prototext.proto / Field`.
#[derive(Debug, Default, Clone)]
pub struct ProtoTextField {
    // ── Metadata ─────────────────────────────────────────────────────────────
    /// Annotation strings (proto field 1, repeated string o).
    pub annotations: Vec<String>,
    /// Field number from the wire (proto field 2, optional uint64 n).
    pub field_number: Option<u64>,

    // ── Content (exactly one variant set per field) ───────────────────────────
    pub content: ProtoTextContent,

    // ── Wire-level modifiers (fields 70–78) ───────────────────────────────────
    pub tag_overhang_count: Option<u64>,
    pub tag_is_out_of_range: bool,
    pub value_overhang_count: Option<u64>,
    pub length_overhang_count: Option<u64>,
    pub missing_bytes_count: Option<u64>,
    pub mismatched_group_end: Option<u64>,
    pub open_ended_group: bool,
    pub end_tag_overhang_count: Option<u64>,
    pub end_tag_is_out_of_range: bool,

    // ── Proto2 modifiers (fields 80–82) ───────────────────────────────────────
    pub proto2_has_type_mismatch: bool,
    pub records_overhung_count: Vec<u64>,
}

/// The content of a single prototext field.
/// See DESIGN.md / ProtoTextContent enum for the proto field-number mapping.
#[derive(Debug, Clone, Default)]
pub enum ProtoTextContent {
    #[default]
    Unset,
    // Wire-level (fields 10–24)
    WireVarint(u64),                  // 10
    WireFixed64(u64),                 // 11
    WireBytes(Vec<u8>),               // 12
    WireGroup(Box<ProtoTextMessage>), // 13
    WireFixed32(u32),                 // 15
    InvalidTagType(Vec<u8>),          // 16
    InvalidVarint(Vec<u8>),           // 17
    InvalidFixed64(Vec<u8>),          // 18
    InvalidBytesLength(Vec<u8>),      // 19
    TruncatedBytes(Vec<u8>),          // 20
    InvalidPackedRecords(Vec<u8>),    // 21
    InvalidString(Vec<u8>),           // 22
    InvalidGroupEnd(Vec<u8>),         // 23
    InvalidFixed32(Vec<u8>),          // 24
    // Proto2-level (fields 31–48)
    Double(f64),                       // 31
    Float(f32),                        // 32
    Int64(i64),                        // 33
    Uint64(u64),                       // 34
    Int32(i32),                        // 35
    PFixed64(u64),                     // 36  proto2 fixed64
    PFixed32(u32),                     // 37  proto2 fixed32
    Bool(bool),                        // 38
    StringVal(String),                 // 39
    Group(Box<ProtoTextMessage>),      // 40  proto2 group
    MessageVal(Box<ProtoTextMessage>), // 41
    BytesVal(Vec<u8>),                 // 42
    Uint32(u32),                       // 43
    Enum(i32),                         // 44
    Sfixed32(i32),                     // 45
    Sfixed64(i64),                     // 46
    Sint32(i32),                       // 47
    Sint64(i64),                       // 48
    // Packed repeated (fields 51–68)
    Doubles(Vec<f64>),   // 51
    Floats(Vec<f32>),    // 52
    Int64s(Vec<i64>),    // 53
    Uint64s(Vec<u64>),   // 54
    Int32s(Vec<i32>),    // 55
    Fixed64s(Vec<u64>),  // 56
    Fixed32s(Vec<u32>),  // 57
    Bools(Vec<bool>),    // 58
    Uint32s(Vec<u32>),   // 63
    Enums(Vec<i32>),     // 64
    Sfixed32s(Vec<i32>), // 65
    Sfixed64s(Vec<i64>), // 66
    Sint32s(Vec<i32>),   // 67
    Sint64s(Vec<i64>),   // 68
}

// ── Public entry point ────────────────────────────────────────────────────────

/// Decode a binary protobuf payload into a lossless `ProtoTextMessage`.
///
/// Mirrors `decode_pb()` in `decode.py`.
pub fn ingest_pb(
    pb_bytes: &[u8],
    full_schema: &ParsedSchema,
    annotations: bool,
) -> ProtoTextMessage {
    let root = full_schema.root_schema();
    let (msg, _, _) = parse_message(pb_bytes, 0, None, root.as_deref(), full_schema, annotations);
    msg
}

// ── Core recursive parser ─────────────────────────────────────────────────────

/// Parse one protobuf message starting at `start`.
///
/// Returns `(message, next_pos, group_end_tag)`.
/// `group_end_tag` is `Some(tag)` when the parse terminated on an END_GROUP
/// wire type — the caller uses this to detect mismatched group numbers.
///
/// Mirrors `parse_message()` in `decode.py`.
pub fn parse_message(
    buf: &[u8],
    start: usize,
    my_group: Option<u64>, // Some(field_number) when inside a group
    schema: Option<&MessageSchema>,
    full_schema: &ParsedSchema, // full registry for nested type lookups
    annotations: bool,
) -> (ProtoTextMessage, usize, Option<WiretagResult>) {
    let buflen = buf.len();
    let mut pos = start;
    let mut message = ProtoTextMessage::default();

    loop {
        if pos == buflen {
            return (message, pos, None);
        }

        let mut field = ProtoTextField::default();

        // ── Parse wire tag ────────────────────────────────────────────────────

        let tag = parse_wiretag(buf, pos);

        if let Some(wtag_gar) = tag.wtag_gar {
            // Invalid wire type: consume rest of buffer
            if annotations {
                field.annotations.push("invalid field".to_string());
            }
            field.field_number = Some(0);
            field.content = ProtoTextContent::InvalidTagType(wtag_gar);
            pos = buflen;
            message.fields.push(field);
            continue;
        }

        let field_number = tag.wfield.unwrap();
        let wire_type = tag.wtype.unwrap();
        field.field_number = Some(field_number);
        if let Some(ohb) = tag.wfield_ohb {
            field.tag_overhang_count = Some(ohb);
        }
        if tag.wfield_oor.is_some() {
            field.tag_is_out_of_range = true;
        }
        pos = tag.next_pos;

        // ── Schema lookup ─────────────────────────────────────────────────────

        let field_schema: Option<&FieldInfo> =
            schema.and_then(|s| s.fields.get(&(field_number as u32)));

        if annotations {
            if schema.is_none() {
                field.annotations.push("no schema".to_string());
            } else if let Some(fs) = field_schema {
                field.annotations.push(format_annotation(fs));
            } else {
                field.annotations.push("unknown field".to_string());
            }
        }

        // ── Wire-type dispatch ────────────────────────────────────────────────

        match wire_type {
            // ── VARINT ───────────────────────────────────────────────────────
            WT_VARINT => {
                let vr = parse_varint(buf, pos);
                if let Some(varint_gar) = vr.varint_gar {
                    field.content = ProtoTextContent::InvalidVarint(varint_gar);
                    pos = buflen;
                    message.fields.push(field);
                    continue;
                }
                pos = vr.next_pos;
                if let Some(ohb) = vr.varint_ohb {
                    field.value_overhang_count = Some(ohb);
                }
                let val = vr.varint.unwrap();

                if let Some(fs) = field_schema {
                    match decode_varint_by_type(val, fs.proto_type) {
                        Ok(content) => field.content = content,
                        Err(TypeMismatch) => {
                            field.proto2_has_type_mismatch = true;
                            field.content = ProtoTextContent::WireVarint(val);
                        }
                    }
                } else {
                    field.content = ProtoTextContent::WireVarint(val);
                }
            }

            // ── FIXED64 ──────────────────────────────────────────────────────
            WT_I64 => {
                if pos + 8 > buflen {
                    field.content = ProtoTextContent::InvalidFixed64(buf[pos..].to_vec());
                    pos = buflen;
                    message.fields.push(field);
                    continue;
                }
                let data = &buf[pos..pos + 8];
                pos += 8;

                if let Some(fs) = field_schema {
                    field.content = match fs.proto_type {
                        pt::DOUBLE => ProtoTextContent::Double(decode_double(data)),
                        pt::FIXED64 => ProtoTextContent::PFixed64(decode_fixed64(data)),
                        pt::SFIXED64 => ProtoTextContent::Sfixed64(decode_sfixed64(data)),
                        _ => ProtoTextContent::WireFixed64(decode_fixed64(data)),
                    };
                } else {
                    field.content = ProtoTextContent::WireFixed64(decode_fixed64(data));
                }
            }

            // ── LENGTH-DELIMITED ─────────────────────────────────────────────
            WT_LEN => {
                let lr = parse_varint(buf, pos);
                if lr.varint_gar.is_some() {
                    field.content = ProtoTextContent::InvalidBytesLength(buf[pos..].to_vec());
                    pos = buflen;
                    message.fields.push(field);
                    continue;
                }
                pos = lr.next_pos;
                if let Some(ohb) = lr.varint_ohb {
                    field.length_overhang_count = Some(ohb);
                }
                let length = lr.varint.unwrap() as usize;

                if pos + length > buflen {
                    field.missing_bytes_count = Some((length - (buflen - pos)) as u64);
                    field.content = ProtoTextContent::TruncatedBytes(buf[pos..].to_vec());
                    pos = buflen;
                    message.fields.push(field);
                    continue;
                }
                let data = &buf[pos..pos + length];
                pos += length;

                decode_len_field(data, field_schema, full_schema, annotations, &mut field);
            }

            // ── START GROUP ──────────────────────────────────────────────────
            WT_START_GROUP => {
                // Resolve nested schema via the full registry.
                let nested_arc: Option<Arc<MessageSchema>> = field_schema
                    .filter(|fs| fs.proto_type == pt::GROUP)
                    .and_then(|fs| fs.nested_type_name.as_deref())
                    .and_then(|name| full_schema.messages.get(name))
                    .cloned();

                let (nested_msg, new_pos, end_tag) = parse_message(
                    buf,
                    pos,
                    Some(field_number),
                    nested_arc.as_deref(),
                    full_schema,
                    annotations,
                );
                pos = new_pos;

                if end_tag.is_none() {
                    field.open_ended_group = true;
                } else if let Some(ref et) = end_tag {
                    if let Some(ohb) = et.wfield_ohb {
                        field.end_tag_overhang_count = Some(ohb);
                    }
                    if et.wfield_oor.is_some() {
                        field.end_tag_is_out_of_range = true;
                    }
                    let end_field = et.wfield.unwrap_or(0);
                    if end_field != field_number {
                        field.mismatched_group_end = Some(end_field);
                    }
                }
                // Always store as proto2-level group (field 40), matching Python.
                field.content = ProtoTextContent::Group(Box::new(nested_msg));
            }

            // ── END GROUP ────────────────────────────────────────────────────
            WT_END_GROUP => {
                if my_group.is_none() {
                    // Unexpected END_GROUP outside a group
                    field.content = ProtoTextContent::InvalidGroupEnd(buf[pos..].to_vec());
                    pos = buflen;
                    message.fields.push(field);
                    continue;
                }
                // Valid END_GROUP: return WITHOUT pushing the tag as a field.
                return (message, pos, Some(tag));
            }

            // ── FIXED32 ──────────────────────────────────────────────────────
            WT_I32 => {
                if pos + 4 > buflen {
                    field.content = ProtoTextContent::InvalidFixed32(buf[pos..].to_vec());
                    pos = buflen;
                    message.fields.push(field);
                    continue;
                }
                let data = &buf[pos..pos + 4];
                pos += 4;

                if let Some(fs) = field_schema {
                    field.content = match fs.proto_type {
                        pt::FLOAT => ProtoTextContent::Float(decode_float(data)),
                        pt::FIXED32 => ProtoTextContent::PFixed32(decode_fixed32(data)),
                        pt::SFIXED32 => ProtoTextContent::Sfixed32(decode_sfixed32(data)),
                        // Fallback: Python uses field.fixed32 (proto2-level, field 37)
                        _ => ProtoTextContent::PFixed32(decode_fixed32(data)),
                    };
                } else {
                    // No schema fallback: Python uses field.fixed32 (proto2-level, field 37)
                    field.content = ProtoTextContent::PFixed32(decode_fixed32(data));
                }
            }

            _ => {
                // Wire types 0–5 are the only valid ones; wiretag parser rejects >5.
                unreachable!("wire type > 5 should have been caught by parse_wiretag");
            }
        }

        message.fields.push(field);
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

struct TypeMismatch;

/// Map a varint value to the appropriate `ProtoTextContent` variant given
/// the field's proto type.  Returns `Err(TypeMismatch)` when the value is out
/// of range for the declared type, mirroring the Python `WireTypeMismatch`.
fn decode_varint_by_type(val: u64, proto_type: i32) -> Result<ProtoTextContent, TypeMismatch> {
    match proto_type {
        pt::INT64 => {
            // val is u64 so it is always < 2^64; parse_varint already returns
            // varint_gar for values that would overflow u64.  No range check needed.
            Ok(ProtoTextContent::Int64(decode_int64(val)))
        }
        pt::UINT64 => Ok(ProtoTextContent::Uint64(decode_uint64(val))),
        pt::INT32 => {
            if val >= (1u64 << 32) {
                return Err(TypeMismatch);
            }
            Ok(ProtoTextContent::Int32(decode_int32(val)))
        }
        pt::BOOL => {
            if val > 1 {
                return Err(TypeMismatch);
            }
            Ok(ProtoTextContent::Bool(decode_bool(val)))
        }
        pt::UINT32 => {
            if val >= (1u64 << 32) {
                return Err(TypeMismatch);
            }
            Ok(ProtoTextContent::Uint32(decode_uint32(val)))
        }
        pt::ENUM => {
            if val >= (1u64 << 32) {
                return Err(TypeMismatch);
            }
            Ok(ProtoTextContent::Enum(decode_int32(val)))
        }
        pt::SINT32 => {
            if val >= (1u64 << 32) {
                return Err(TypeMismatch);
            }
            Ok(ProtoTextContent::Sint32(decode_sint32(val)))
        }
        pt::SINT64 => Ok(ProtoTextContent::Sint64(decode_sint64(val))),
        _ => Err(TypeMismatch),
    }
}

/// Decode a length-delimited field payload, updating `field.content`.
///
/// Mirrors the `case w.BYTES:` block in `parse_message()`.
fn decode_len_field(
    data: &[u8],
    field_schema: Option<&FieldInfo>,
    full_schema: &ParsedSchema,
    annotations: bool,
    field: &mut ProtoTextField,
) {
    let Some(fs) = field_schema else {
        field.content = ProtoTextContent::WireBytes(data.to_vec());
        return;
    };

    let is_repeated = fs.label == proto_label::REPEATED;

    // ── Packed repeated ───────────────────────────────────────────────────────
    if is_repeated && fs.is_packed {
        decode_packed(data, fs, field);
        return;
    }

    // ── String ────────────────────────────────────────────────────────────────
    if fs.proto_type == pt::STRING {
        match std::str::from_utf8(data) {
            Ok(s) => field.content = ProtoTextContent::StringVal(s.to_string()),
            Err(_) => field.content = ProtoTextContent::InvalidString(data.to_vec()),
        }
        return;
    }

    // ── Bytes ─────────────────────────────────────────────────────────────────
    if fs.proto_type == pt::BYTES {
        field.content = ProtoTextContent::BytesVal(data.to_vec());
        return;
    }

    // ── Nested message ────────────────────────────────────────────────────────
    if fs.proto_type == pt::MESSAGE {
        let nested_schema = fs
            .nested_type_name
            .as_deref()
            .and_then(|name| full_schema.messages.get(name))
            .map(|arc| arc.as_ref());
        let (nested_msg, _, _) =
            parse_message(data, 0, None, nested_schema, full_schema, annotations);
        field.content = ProtoTextContent::MessageVal(Box::new(nested_msg));
        return;
    }

    // ── Wire-type mismatch fallback ───────────────────────────────────────────
    field.content = ProtoTextContent::WireBytes(data.to_vec());
}

/// Decode a packed repeated field, mirroring the Python packed-records block.
fn decode_packed(data: &[u8], fs: &FieldInfo, field: &mut ProtoTextField) {
    let length = data.len();

    // When length == 0, set content to an empty vector (matching Python behavior:
    // field.sfixed64s.extend([]) still marks the field as "set", producing "sfixed64Pk: []")
    match fs.proto_type {
        pt::DOUBLE => {
            let mut vals = Vec::new();
            let mut i = 0;
            while i < length {
                if i + 8 > length {
                    field.content = ProtoTextContent::InvalidPackedRecords(data.to_vec());
                    return;
                }
                vals.push(decode_double(&data[i..i + 8]));
                i += 8;
            }
            field.content = ProtoTextContent::Doubles(vals);
        }
        pt::FLOAT => {
            let mut vals = Vec::new();
            let mut i = 0;
            while i < length {
                if i + 4 > length {
                    field.content = ProtoTextContent::InvalidPackedRecords(data.to_vec());
                    return;
                }
                vals.push(decode_float(&data[i..i + 4]));
                i += 4;
            }
            field.content = ProtoTextContent::Floats(vals);
        }
        pt::FIXED64 => {
            let mut vals = Vec::new();
            let mut i = 0;
            while i < length {
                if i + 8 > length {
                    field.content = ProtoTextContent::InvalidPackedRecords(data.to_vec());
                    return;
                }
                vals.push(decode_fixed64(&data[i..i + 8]));
                i += 8;
            }
            field.content = ProtoTextContent::Fixed64s(vals);
        }
        pt::SFIXED64 => {
            let mut vals = Vec::new();
            let mut i = 0;
            while i < length {
                if i + 8 > length {
                    field.content = ProtoTextContent::InvalidPackedRecords(data.to_vec());
                    return;
                }
                vals.push(decode_sfixed64(&data[i..i + 8]));
                i += 8;
            }
            field.content = ProtoTextContent::Sfixed64s(vals);
        }
        pt::FIXED32 => {
            let mut vals = Vec::new();
            let mut i = 0;
            while i < length {
                if i + 4 > length {
                    field.content = ProtoTextContent::InvalidPackedRecords(data.to_vec());
                    return;
                }
                vals.push(decode_fixed32(&data[i..i + 4]));
                i += 4;
            }
            field.content = ProtoTextContent::Fixed32s(vals);
        }
        pt::SFIXED32 => {
            let mut vals = Vec::new();
            let mut i = 0;
            while i < length {
                if i + 4 > length {
                    field.content = ProtoTextContent::InvalidPackedRecords(data.to_vec());
                    return;
                }
                vals.push(decode_sfixed32(&data[i..i + 4]));
                i += 4;
            }
            field.content = ProtoTextContent::Sfixed32s(vals);
        }
        // Varint-packed types
        _ => decode_packed_varints(data, fs, field),
    }
}

/// Decode varint-packed repeated fields (int32, int64, uint32, uint64, bool,
/// enum, sint32, sint64).  Tracks overhang bytes per record.
fn decode_packed_varints(data: &[u8], fs: &FieldInfo, field: &mut ProtoTextField) {
    let length = data.len();

    // When length == 0, fall through to set content to an empty vector
    // (matching Python: field.int64s.extend([]) marks the field as set → "int64Pk: []")

    let mut vals_i64: Vec<i64> = Vec::new();
    let mut vals_u64: Vec<u64> = Vec::new();
    let mut vals_i32: Vec<i32> = Vec::new();
    let mut vals_u32: Vec<u32> = Vec::new();
    let mut vals_bool: Vec<bool> = Vec::new();
    let mut vals_enum: Vec<i32> = Vec::new();
    let mut ohbs: Vec<u64> = Vec::new();
    let mut i = 0;

    while i < length {
        let vr = parse_varint(data, i);
        if vr.varint_gar.is_some() {
            field.content = ProtoTextContent::InvalidPackedRecords(data.to_vec());
            return;
        }
        i = vr.next_pos;
        ohbs.push(vr.varint_ohb.unwrap_or(0));
        let v = vr.varint.unwrap();

        match fs.proto_type {
            pt::INT64 => {
                vals_i64.push(decode_int64(v));
            } // v is u64 ⇒ always < 2^64
            pt::UINT64 => {
                vals_u64.push(v);
            }
            pt::INT32 => {
                if v >= (1u64 << 32) {
                    field.content = ProtoTextContent::InvalidPackedRecords(data.to_vec());
                    return;
                }
                vals_i32.push(decode_int32(v));
            }
            pt::BOOL => {
                if v > 1 {
                    field.content = ProtoTextContent::InvalidPackedRecords(data.to_vec());
                    return;
                }
                vals_bool.push(v != 0);
            }
            pt::UINT32 => {
                if v >= (1u64 << 32) {
                    field.content = ProtoTextContent::InvalidPackedRecords(data.to_vec());
                    return;
                }
                vals_u32.push(decode_uint32(v));
            }
            pt::ENUM => {
                if v >= (1u64 << 32) {
                    field.content = ProtoTextContent::InvalidPackedRecords(data.to_vec());
                    return;
                }
                vals_enum.push(decode_int32(v));
            }
            pt::SINT32 => {
                if v >= (1u64 << 32) {
                    field.content = ProtoTextContent::InvalidPackedRecords(data.to_vec());
                    return;
                }
                vals_i32.push(decode_sint32(v));
            }
            pt::SINT64 => {
                vals_i64.push(decode_sint64(v));
            }
            _ => {
                field.content = ProtoTextContent::InvalidPackedRecords(data.to_vec());
                return;
            }
        }
    }

    // Record overhang bytes
    if ohbs.iter().any(|&x| x > 0) {
        field.records_overhung_count = ohbs;
    }

    field.content = match fs.proto_type {
        pt::INT64 => ProtoTextContent::Int64s(vals_i64),
        pt::UINT64 => ProtoTextContent::Uint64s(vals_u64),
        pt::INT32 => ProtoTextContent::Int32s(vals_i32),
        pt::BOOL => ProtoTextContent::Bools(vals_bool),
        pt::UINT32 => ProtoTextContent::Uint32s(vals_u32),
        pt::ENUM => ProtoTextContent::Enums(vals_enum),
        pt::SINT32 => ProtoTextContent::Sint32s(vals_i32),
        pt::SINT64 => ProtoTextContent::Sint64s(vals_i64),
        _ => ProtoTextContent::InvalidPackedRecords(data.to_vec()),
    };
}

/// Format the annotation string for a field, mirroring the Python code.
fn format_annotation(fs: &FieldInfo) -> String {
    let label = match fs.label {
        1 => "optional",
        2 => "required",
        3 => "repeated",
        _ => "?",
    };
    let type_str = match fs.proto_type {
        1 => "double",
        2 => "float",
        3 => "int64",
        4 => "uint64",
        5 => "int32",
        6 => "fixed64",
        7 => "fixed32",
        8 => "bool",
        9 => "string",
        10 => "group",
        11 => "message",
        12 => "bytes",
        13 => "uint32",
        14 => "enum",
        15 => "sfixed32",
        16 => "sfixed64",
        17 => "sint32",
        18 => "sint64",
        _ => "?",
    };
    // For message/group/enum, use the short type name if available
    let type_display = if matches!(fs.proto_type, 10 | 11 | 14) {
        fs.type_display_name.as_deref().unwrap_or(type_str)
    } else {
        type_str
    };
    let packed_suffix = if fs.is_packed { " [packed=true]" } else { "" };
    format!("{}: {} {}{}", fs.name, label, type_display, packed_suffix)
}
