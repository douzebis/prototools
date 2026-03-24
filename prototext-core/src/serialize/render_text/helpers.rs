// SPDX-FileCopyrightText: 2025 - 2026 Frederic Ruget <fred@atlant.is> <fred@s3ns.io> (GitHub: @douzebis)
// SPDX-FileCopyrightText: 2025 - 2026 Thales Cloud Sécurisé
//
// SPDX-License-Identifier: MIT

use std::collections::HashMap;
use std::sync::Arc;

use prost_reflect::{Cardinality, Kind, MessageDescriptor};

use super::FieldOrExt;

use crate::serialize::common::{escape_bytes_into, escape_string_into};

use super::packed::render_packed;
use super::{enter_level, render_message, ANNOTATIONS, CBL_START, INDENT_SIZE, LEVEL};

// ── Low-level output helpers ──────────────────────────────────────────────────

/// Push the current indentation (INDENT_SIZE × LEVEL spaces) into `out`.
#[inline]
pub(super) fn push_indent(out: &mut Vec<u8>) {
    let n = INDENT_SIZE.with(|c| c.get()) * LEVEL.with(|c| c.get());
    for _ in 0..n {
        out.push(b' ');
    }
}

/// Write `v` as decimal ASCII digits into `out` — no heap allocation.
#[inline]
pub(super) fn write_dec_i32(v: i32, out: &mut Vec<u8>) {
    if v < 0 {
        out.push(b'-');
        write_dec_u64(-(v as i64) as u64, out);
    } else {
        write_dec_u64(v as u64, out);
    }
}

/// Write `v` as decimal ASCII digits into `out` — no heap allocation.
#[inline]
pub(super) fn write_dec_u64(v: u64, out: &mut Vec<u8>) {
    if v == 0 {
        out.push(b'0');
        return;
    }
    let mut buf = [0u8; 20];
    let mut pos = 20usize;
    let mut n = v;
    while n > 0 {
        pos -= 1;
        buf[pos] = b'0' + (n % 10) as u8;
        n /= 10;
    }
    out.extend_from_slice(&buf[pos..]);
}

// ── Prefix writers ────────────────────────────────────────────────────────────

/// Write field-line prefix: `{spaces}name: `
#[inline]
pub(super) fn wfl_prefix(name: &str, out: &mut Vec<u8>) {
    push_indent(out);
    out.extend_from_slice(name.as_bytes());
    out.extend_from_slice(b": ");
}

/// Write field-line prefix without String allocation.
///
/// When `is_wire_or_mismatch` is false and `fs` is `Some`, writes the schema
/// field name (or `[pkg.ext]` for extensions) directly from `fs.display_name()`.
/// Otherwise writes `num` as decimal.
#[inline]
pub(super) fn wfl_prefix_n(
    num: u64,
    fs: Option<&FieldOrExt>,
    is_wire_or_mismatch: bool,
    out: &mut Vec<u8>,
) {
    push_indent(out);
    match fs.filter(|_| !is_wire_or_mismatch) {
        Some(fi) => out.extend_from_slice(fi.display_name().as_bytes()),
        None => write_dec_u64(num, out),
    }
    out.extend_from_slice(b": ");
}

/// Write open-brace prefix: `{spaces}name {`  (caller writes annotation + `\n`).
#[allow(dead_code)]
#[inline]
pub(super) fn wob_prefix(name: &str, out: &mut Vec<u8>) {
    push_indent(out);
    out.extend_from_slice(name.as_bytes());
    out.extend_from_slice(b" {");
}

/// Write open-brace prefix without String allocation.
///
/// When `is_wire_or_mismatch` is false and `fs` is `Some`, writes the schema
/// field name (or `[pkg.ext]` for extensions) directly from `fs.display_name()`.
/// Otherwise writes `num` as decimal.
#[inline]
pub(super) fn wob_prefix_n(
    num: u64,
    fs: Option<&FieldOrExt>,
    is_wire_or_mismatch: bool,
    out: &mut Vec<u8>,
) {
    push_indent(out);
    match fs.filter(|_| !is_wire_or_mismatch) {
        Some(fi) => out.extend_from_slice(fi.display_name().as_bytes()),
        None => write_dec_u64(num, out),
    }
    out.extend_from_slice(b" {");
}

/// Write `{indent}}\n`.
#[inline]
pub(super) fn write_close_brace(out: &mut Vec<u8>) {
    CBL_START.with(|c| c.set(out.len()));
    push_indent(out);
    out.push(b'}');
    out.push(b'\n');
}

// ── Annotation helpers ────────────────────────────────────────────────────────

/// Return the protobuf type name string for a field's Kind.
#[inline]
pub(super) fn proto_type_str(kind: &Kind) -> &'static str {
    match kind {
        Kind::Double => "double",
        Kind::Float => "float",
        Kind::Int64 => "int64",
        Kind::Uint64 => "uint64",
        Kind::Int32 => "int32",
        Kind::Fixed64 => "fixed64",
        Kind::Fixed32 => "fixed32",
        Kind::Bool => "bool",
        Kind::String => "string",
        Kind::Message(_) => "message", // groups also appear as Message in prost-reflect
        Kind::Bytes => "bytes",
        Kind::Uint32 => "uint32",
        Kind::Enum(_) => "enum",
        Kind::Sfixed32 => "sfixed32",
        Kind::Sfixed64 => "sfixed64",
        Kind::Sint32 => "sint32",
        Kind::Sint64 => "sint64",
    }
}

/// Build the `"[repeated |required ]type[ [packed=true]] = N"` field declaration string.
/// v2 format: `optional` omitted as default; no trailing `;`.
/// Used only by `render_group_field` for post-hoc splice insertion.
pub(super) fn field_decl(field_number: u64, field_schema: Option<&FieldOrExt>) -> Option<String> {
    let fi = field_schema?;
    // v2: `optional` is the default — omit it; emit `repeated` / `required` explicitly.
    let label_prefix = match fi.cardinality() {
        Cardinality::Required => "required ",
        Cardinality::Repeated => "repeated ",
        Cardinality::Optional => "",
    };
    let kind = fi.kind();
    let type_str = proto_type_str(&kind);
    let type_display = match &kind {
        Kind::Message(msg_desc) => msg_desc.name().to_string(),
        Kind::Enum(enum_desc) => enum_desc.name().to_string(),
        _ => type_str.to_string(),
    };
    let packed = if fi.is_packed() { " [packed=true]" } else { "" };
    // v2: no trailing `;`
    Some(format!(
        "{}{}{} = {}",
        label_prefix, type_display, packed, field_number
    ))
}

/// Tracks whether we've started writing an annotation on the current line.
///
/// First part writes `"  # "` prefix; subsequent parts write `"; "` separator.
/// All annotation parts are written directly into the output buffer — no heap allocation.
///
/// v2 annotation format: tokens separated by `"; "`, NO trailing `";"`.
pub(super) struct AnnWriter {
    started: bool,
}

impl AnnWriter {
    #[inline]
    pub(super) fn new() -> Self {
        Self { started: false }
    }

    /// Write the inter-part separator into `out`.
    ///
    /// First call: writes `"  #@ "` to open the annotation.
    /// Subsequent calls: writes `"; "` to separate tokens (v2 format).
    #[inline]
    pub(super) fn sep(&mut self, out: &mut Vec<u8>) {
        if self.started {
            out.extend_from_slice(b"; ");
        } else {
            out.extend_from_slice(b"  #@ ");
            self.started = true;
        }
    }

    /// Push a raw annotation token (any byte slice, no trailing `;`).
    #[inline]
    pub(super) fn push(&mut self, out: &mut Vec<u8>, s: &[u8]) {
        self.sep(out);
        out.extend_from_slice(s);
    }

    /// Push a wire-type or invalid-wire-type token (no trailing `;`).
    #[inline]
    pub(super) fn push_wire(&mut self, out: &mut Vec<u8>, name: &str) {
        self.sep(out);
        out.extend_from_slice(name.as_bytes());
    }

    /// Push a `key: N` modifier (no trailing `;`).
    /// `key` must include the colon-space, e.g. `b"tag_ohb: "`.
    #[inline]
    pub(super) fn push_u64_mod(&mut self, out: &mut Vec<u8>, key: &[u8], v: u64) {
        self.sep(out);
        out.extend_from_slice(key);
        write_dec_u64(v, out);
    }

    /// Push `"[repeated |required ]type[ [packed=true]] = N"` field-declaration
    /// directly into `out` (v2 format: `optional` is omitted as default label).
    ///
    /// For ENUM fields, `enum_raw` must be `Some(numeric_value)` and the
    /// annotation emits `EnumTypeName(numeric)` instead of just `EnumTypeName`.
    /// For packed ENUM fields, `enum_packed_nums` must be `Some(&[i32])` containing
    /// the raw numeric values; the annotation emits `EnumTypeName([n1, n2])`.
    ///
    /// No-op when `fs` is `None` (unknown field).
    /// Eliminates the `field_decl() -> Option<String>` allocation at all
    /// non-GROUP call sites.
    #[inline]
    pub(super) fn push_field_decl(
        &mut self,
        out: &mut Vec<u8>,
        num: u64,
        fs: Option<&FieldOrExt>,
        enum_raw: Option<i32>,
        enum_packed_nums: Option<&[i32]>,
    ) {
        let Some(fi) = fs else { return };
        self.sep(out);
        // v2: `optional` is the default — omit it; emit `repeated` / `required` explicitly.
        match fi.cardinality() {
            Cardinality::Required => {
                out.extend_from_slice(b"required ");
            }
            Cardinality::Repeated => {
                out.extend_from_slice(b"repeated ");
            }
            Cardinality::Optional => {}
        }
        let kind = fi.kind();
        if let Kind::Enum(ref enum_desc) = kind {
            // ENUM: emit EnumTypeName(N) or EnumTypeName([n1, n2]) for packed
            let type_display = enum_desc.name();
            out.extend_from_slice(type_display.as_bytes());
            if let Some(nums) = enum_packed_nums {
                // Packed enum: EnumTypeName([n1, n2, ...])
                out.push(b'(');
                out.push(b'[');
                for (i, &n) in nums.iter().enumerate() {
                    if i > 0 {
                        out.extend_from_slice(b", ");
                    }
                    write_dec_i32(n, out);
                }
                out.push(b']');
                out.push(b')');
            } else if let Some(n) = enum_raw {
                // Scalar enum: EnumTypeName(N)
                out.push(b'(');
                write_dec_i32(n, out);
                out.push(b')');
            }
        } else {
            let type_display = match &kind {
                Kind::Message(msg_desc) => msg_desc.name().to_string(),
                _ => proto_type_str(&kind).to_string(),
            };
            out.extend_from_slice(type_display.as_bytes());
        }
        if fi.is_packed() {
            out.extend_from_slice(b" [packed=true]");
        }
        out.extend_from_slice(b" = ");
        write_dec_u64(num, out);
    }
}

// ── Field renderers ───────────────────────────────────────────────────────────

/// Render a non-varint scalar (FIXED64, FIXED32, string, bytes, wire-bytes).
///
/// `wire_type_name` (lowercase v2 name) is only emitted for unknown or raw-wire
/// fields.  Known fields emit field_decl FIRST, then modifiers.
/// `nan_bits`: when `Some`, emits `nan_bits: 0x…` as an annotation modifier (non-canonical NaN).
#[allow(clippy::too_many_arguments)]
pub(super) fn render_scalar(
    field_number: u64,
    field_schema: Option<&FieldOrExt>,
    tag_ohb: Option<u64>,
    tag_oor: bool,
    len_ohb: Option<u64>,
    wire_type_name: &str, // lowercase v2 name ("fixed64", "fixed32", "bytes", …)
    value_str: &str,
    is_wire: bool, // true for WireBytes/WireFixed* or wire-type mismatch
    nan_bits: Option<u64>,
    out: &mut Vec<u8>,
) {
    let annotations = ANNOTATIONS.with(|c| c.get());
    let unknown = field_schema.is_none();

    if !annotations && (unknown || is_wire) {
        return;
    }

    // v2 key rule: numeric for unknown/wire, named for known fields.
    let use_numeric_key = unknown || is_wire;
    wfl_prefix_n(field_number, field_schema, use_numeric_key, out);
    out.extend_from_slice(value_str.as_bytes());
    if annotations {
        let mut aw = AnnWriter::new();
        if unknown || is_wire {
            // Unknown/wire: wire type FIRST, then modifiers, NO field_decl
            aw.push_wire(out, wire_type_name);
            if let Some(v) = tag_ohb {
                aw.push_u64_mod(out, b"tag_ohb: ", v);
            }
            if tag_oor {
                aw.push(out, b"TAG_OOR");
            }
            if let Some(v) = len_ohb {
                aw.push_u64_mod(out, b"len_ohb: ", v);
            }
        } else {
            // Known field: field_decl FIRST, then modifiers
            aw.push_field_decl(out, field_number, field_schema, None, None);
            if let Some(v) = tag_ohb {
                aw.push_u64_mod(out, b"tag_ohb: ", v);
            }
            if tag_oor {
                aw.push(out, b"TAG_OOR");
            }
            if let Some(v) = len_ohb {
                aw.push_u64_mod(out, b"len_ohb: ", v);
            }
            if let Some(bits) = nan_bits {
                aw.sep(out);
                out.extend_from_slice(b"nan_bits: 0x");
                // Write hex digits: 16 for double (u64), 8 for float (u32 stored as u64)
                if bits > 0xFFFF_FFFF {
                    out.extend_from_slice(format!("{:016x}", bits).as_bytes());
                } else {
                    out.extend_from_slice(format!("{:08x}", bits).as_bytes());
                }
            }
        }
    }
    out.push(b'\n');
    CBL_START.with(|c| c.set(out.len())); // content line: set past-end to inhibit folding
}

/// Render INVALID_VARINT / INVALID_FIXED64 / INVALID_FIXED32 / INVALID_LEN /
/// INVALID_PACKED_RECORDS / INVALID_STRING / INVALID_GROUP_END as `N: "bytes"`.
///
/// v2: always uses numeric key; emits INVALID_* wire type name; no field_decl.
pub(super) fn render_invalid(
    field_number: u64,
    _field_schema: Option<&FieldOrExt>,
    tag_ohb: Option<u64>,
    tag_oor: bool,
    inv_name: &str,
    raw: &[u8],
    out: &mut Vec<u8>,
) {
    let annotations = ANNOTATIONS.with(|c| c.get());
    // v2: always numeric key for invalid fields (no field name, no field_decl).
    wfl_prefix_n(field_number, None, true, out);
    out.push(b'"');
    escape_bytes_into(raw, out);
    out.push(b'"');
    if annotations {
        let mut aw = AnnWriter::new();
        aw.push_wire(out, inv_name);
        if let Some(v) = tag_ohb {
            aw.push_u64_mod(out, b"tag_ohb: ", v);
        }
        if tag_oor {
            aw.push(out, b"TAG_OOR");
        }
        // v2: NO field_decl for invalid fields.
    }
    out.push(b'\n');
    CBL_START.with(|c| c.set(out.len())); // content line: set past-end to inhibit folding
}

/// Special case: InvalidTagType has no valid field number.
pub(super) fn render_invalid_tag_type(raw: &[u8], out: &mut Vec<u8>) {
    let annotations = ANNOTATIONS.with(|c| c.get());
    wfl_prefix("0", out);
    out.push(b'"');
    escape_bytes_into(raw, out);
    out.push(b'"');
    if annotations {
        let mut aw = AnnWriter::new();
        aw.push(out, b"INVALID_TAG_TYPE"); // v2: no trailing `;`
    }
    out.push(b'\n');
    CBL_START.with(|c| c.set(out.len())); // content line: set past-end to inhibit folding
}

/// Render a TRUNCATED_BYTES field.
///
/// v2: always numeric key; `TRUNCATED_BYTES; MISSING: N`; no field_decl.
pub(super) fn render_truncated_bytes(
    field_number: u64,
    tag_ohb: Option<u64>,
    tag_oor: bool,
    len_ohb: Option<u64>,
    missing: u64,
    raw: &[u8],
    out: &mut Vec<u8>,
) {
    let annotations = ANNOTATIONS.with(|c| c.get());
    // v2: always numeric key for invalid fields.
    wfl_prefix_n(field_number, None, true, out);
    out.push(b'"');
    escape_bytes_into(raw, out);
    out.push(b'"');
    if annotations {
        let mut aw = AnnWriter::new();
        aw.push(out, b"TRUNCATED_BYTES"); // invalid wire type, ALL CAPS
        if let Some(v) = tag_ohb {
            aw.push_u64_mod(out, b"tag_ohb: ", v);
        }
        if tag_oor {
            aw.push(out, b"TAG_OOR");
        }
        if let Some(v) = len_ohb {
            aw.push_u64_mod(out, b"len_ohb: ", v);
        }
        aw.push_u64_mod(out, b"MISSING: ", missing); // invalid modifier, ALL CAPS
                                                     // v2: NO field_decl for invalid fields.
    }
    out.push(b'\n');
    CBL_START.with(|c| c.set(out.len())); // content line: set past-end to inhibit folding
}

/// Render a length-delimited field (string, bytes, message, packed, wire-bytes).
#[allow(clippy::too_many_arguments)]
pub(super) fn render_len_field(
    field_number: u64,
    field_schema: Option<&FieldOrExt>,
    all_schemas: Option<&HashMap<String, Arc<MessageDescriptor>>>,
    tag_ohb: Option<u64>,
    tag_oor: bool,
    len_ohb: Option<u64>,
    data: &[u8],
    out: &mut Vec<u8>,
) {
    let annotations = ANNOTATIONS.with(|c| c.get());
    let Some(fs) = field_schema else {
        // Unknown field: WireBytes — skip when annotations=false (like render_scalar would).
        if !annotations {
            return;
        }
        // v2: numeric key, `bytes` wire type FIRST, no field_decl.
        wfl_prefix_n(field_number, None, true, out);
        out.push(b'"');
        escape_bytes_into(data, out);
        out.push(b'"');
        let mut aw = AnnWriter::new();
        aw.push_wire(out, "bytes");
        if let Some(v) = tag_ohb {
            aw.push_u64_mod(out, b"tag_ohb: ", v);
        }
        if tag_oor {
            aw.push(out, b"TAG_OOR");
        }
        if let Some(v) = len_ohb {
            aw.push_u64_mod(out, b"len_ohb: ", v);
        }
        out.push(b'\n');
        CBL_START.with(|c| c.set(out.len())); // content line: set past-end to inhibit folding
        return;
    };

    let is_repeated = fs.cardinality() == Cardinality::Repeated;

    // ── Packed repeated ───────────────────────────────────────────────────────
    if is_repeated && fs.is_packed() {
        // Extensions cannot be packed; unwrap is safe here.
        let fd = fs.as_field().expect("packed field must be a regular field");
        render_packed(field_number, fd, tag_ohb, tag_oor, len_ohb, data, out);
        return;
    }

    // ── String ────────────────────────────────────────────────────────────────
    if fs.kind() == Kind::String {
        match std::str::from_utf8(data) {
            Ok(s) => {
                // Valid UTF-8: write directly — no format! or escape_string allocation.
                wfl_prefix_n(field_number, Some(fs), false, out);
                out.push(b'"');
                escape_string_into(s, out);
                out.push(b'"');
                if annotations {
                    let mut aw = AnnWriter::new();
                    // v2: field_decl FIRST, then modifiers.
                    aw.push_field_decl(out, field_number, Some(fs), None, None);
                    if let Some(v) = tag_ohb {
                        aw.push_u64_mod(out, b"tag_ohb: ", v);
                    }
                    if tag_oor {
                        aw.push(out, b"TAG_OOR");
                    }
                    if let Some(v) = len_ohb {
                        aw.push_u64_mod(out, b"len_ohb: ", v);
                    }
                }
                out.push(b'\n');
                CBL_START.with(|c| c.set(out.len())); // content line: set past-end to inhibit folding
            }
            Err(_) => {
                render_invalid(
                    field_number,
                    Some(fs),
                    tag_ohb,
                    tag_oor,
                    "INVALID_STRING",
                    data,
                    out,
                );
                // render_invalid already updates CBL_START
            }
        }
        return;
    }

    // ── Bytes ─────────────────────────────────────────────────────────────────
    if fs.kind() == Kind::Bytes {
        wfl_prefix_n(field_number, Some(fs), false, out);
        out.push(b'"');
        escape_bytes_into(data, out);
        out.push(b'"');
        if annotations {
            let mut aw = AnnWriter::new();
            // v2: field_decl FIRST, then modifiers.
            aw.push_field_decl(out, field_number, Some(fs), None, None);
            if let Some(v) = tag_ohb {
                aw.push_u64_mod(out, b"tag_ohb: ", v);
            }
            if tag_oor {
                aw.push(out, b"TAG_OOR");
            }
            if let Some(v) = len_ohb {
                aw.push_u64_mod(out, b"len_ohb: ", v);
            }
        }
        out.push(b'\n');
        CBL_START.with(|c| c.set(out.len())); // content line: set past-end to inhibit folding
        return;
    }

    // ── Nested message ────────────────────────────────────────────────────────
    // Note: groups are represented as Kind::Message in prost-reflect.  A GROUP
    // field received on a LEN wire record is a wire-type mismatch — fall through
    // to the mismatch handler below.
    if let Kind::Message(nested_msg_desc) = fs.kind() {
        if !fs.is_group() {
            let nested_schema: Option<&MessageDescriptor> = all_schemas
                .and_then(|m| m.get(nested_msg_desc.full_name()))
                .map(|v| &**v);

            wob_prefix_n(field_number, Some(fs), false, out);
            if annotations {
                let mut aw = AnnWriter::new();
                // v2: NO wire type for known MESSAGE; field_decl FIRST, then modifiers.
                aw.push_field_decl(out, field_number, Some(fs), None, None);
                if let Some(v) = tag_ohb {
                    aw.push_u64_mod(out, b"tag_ohb: ", v);
                }
                if tag_oor {
                    aw.push(out, b"TAG_OOR");
                }
                if let Some(v) = len_ohb {
                    aw.push_u64_mod(out, b"len_ohb: ", v);
                }
            }
            out.push(b'\n');
            CBL_START.with(|c| c.set(out.len())); // open-brace line: set past-end to inhibit folding
            {
                let _guard = enter_level();
                render_message(data, 0, None, nested_schema, all_schemas, out);
            }
            write_close_brace(out);
            return;
        }
    }

    // ── Wire-type mismatch (schema says non-LEN type but wire says LEN) ───────
    // v2: numeric key, `bytes` wire type FIRST, no field_decl; skip when annotations=false.
    if !annotations {
        return;
    }
    wfl_prefix_n(field_number, field_schema, true, out);
    out.push(b'"');
    escape_bytes_into(data, out);
    out.push(b'"');
    let mut aw = AnnWriter::new();
    aw.push_wire(out, "bytes");
    if let Some(v) = tag_ohb {
        aw.push_u64_mod(out, b"tag_ohb: ", v);
    }
    if tag_oor {
        aw.push(out, b"TAG_OOR");
    }
    if let Some(v) = len_ohb {
        aw.push_u64_mod(out, b"len_ohb: ", v);
    }
    out.push(b'\n');
    CBL_START.with(|c| c.set(out.len())); // content line: set past-end to inhibit folding
}

/// Render a GROUP field (proto2), with greedy rendering and post-hoc fixup.
#[allow(clippy::too_many_arguments)]
pub(super) fn render_group_field(
    buf: &[u8],
    pos: &mut usize,
    field_number: u64,
    field_schema: Option<&FieldOrExt>,
    all_schemas: Option<&HashMap<String, Arc<MessageDescriptor>>>,
    tag_ohb: Option<u64>,
    tag_oor: bool,
    out: &mut Vec<u8>,
) {
    let annotations = ANNOTATIONS.with(|c| c.get());
    // Determine nested schema and whether this is a wire-type mismatch
    // (GROUP wire but schema declares a non-GROUP type).
    // A mismatch is treated as unknown: field number as name, no field_decl.
    let is_mismatch = field_schema.is_some_and(|fs| !fs.is_group());
    let nested_schema_opt: Option<&MessageDescriptor> = if let Some(fs) = field_schema {
        if fs.is_group() {
            if let Kind::Message(msg_desc) = fs.kind() {
                all_schemas
                    .and_then(|m| m.get(msg_desc.full_name()))
                    .map(|v| &**v)
            } else {
                None
            }
        } else {
            None
        }
    } else {
        None
    };

    // ── Greedy: write opening brace line immediately ──────────────────────────
    // v2 annotation structure: `group; field_decl [; modifier]*`
    //   known_field_ann := ["group" ";"] field_decl [";" modifier (";" modifier)*]
    //
    // Greedy write: write `  # group` now (the `group` token only).
    // Post-hoc splice (after recursion): insert `; field_decl [; tag_ohb: N] [; TAG_OOR]
    //   [; OPEN_GROUP | ; etag_ohb: N | ; ETAG_OOR | ; END_MISMATCH: N]` before '\n'.
    //
    // For mismatch/unknown GROUP: unknown_field_ann := wire_type [";" modifier]*
    //   Greedy: `  # group`; post-hoc: `[; tag_ohb: N] [; TAG_OOR] [; close-tag mods]`.
    //
    // Known GROUP → borrow type display name from schema; mismatch/unknown → decimal number.
    push_indent(out);
    if let Some(fs) = field_schema.filter(|fs| fs.is_group()) {
        if let Kind::Message(msg_desc) = fs.kind() {
            out.extend_from_slice(msg_desc.name().as_bytes());
        } else {
            write_dec_u64(field_number, out);
        }
    } else {
        write_dec_u64(field_number, out);
    }
    out.extend_from_slice(b" {");
    if annotations {
        let mut aw = AnnWriter::new();
        aw.push(out, b"group"); // v2: lowercase, no trailing `;` — field_decl+modifiers go post-hoc
    }
    out.push(b'\n');
    CBL_START.with(|c| c.set(out.len())); // open-brace line: set past-end to inhibit folding
                                          // The '\n' is the last byte written; record its index for post-hoc splice.
    let header_nl_pos = out.len() - 1;

    // ── Recurse: parse and render child fields ────────────────────────────────
    let start = *pos;
    let (new_pos, end_tag) = {
        let _guard = enter_level();
        render_message(
            buf,
            start,
            Some(field_number),
            nested_schema_opt,
            all_schemas,
            out,
        )
    };
    *pos = new_pos;

    // ── Collect all post-hoc annotation content ───────────────────────────────
    // v2 order (for known non-mismatch GROUP):
    //   ; field_decl [; tag_ohb: N] [; TAG_OOR] [; close-tag modifiers...]
    // v2 order (for unknown/mismatch GROUP, no field_decl):
    //   [; tag_ohb: N] [; TAG_OOR] [; close-tag modifiers...]

    // Close-tag modifiers.
    let mut close_mods: Vec<String> = Vec::new();
    if end_tag.is_none() {
        close_mods.push("OPEN_GROUP".to_owned());
    } else if let Some(ref et) = end_tag {
        if let Some(ohb) = et.wfield_ohb {
            close_mods.push(format!("etag_ohb: {}", ohb));
        }
        if et.wfield_oor.is_some() {
            close_mods.push("ETAG_OOR".to_owned());
        }
        let end_field = et.wfield.unwrap_or(0);
        if end_field != field_number {
            close_mods.push(format!("END_MISMATCH: {}", end_field));
        }
    }

    // ── Fixup: splice post-hoc content before '\n' ───────────────────────────
    let decl_opt = if annotations && !is_mismatch {
        field_decl(field_number, field_schema)
    } else {
        None
    };

    // Does annotations=true and we have anything to splice?
    let has_field_decl = decl_opt.is_some();
    let has_open_tag_mods = annotations && (tag_ohb.is_some() || tag_oor);
    let has_close_mods = annotations && !close_mods.is_empty();

    if has_field_decl || has_open_tag_mods || has_close_mods {
        // Build insert: each part contributes `"; " + text`.
        // Since `group` was already written greedily, the first element of the
        // insert begins with `"; "` to become the separator after `group`.
        let mut insert = String::new();
        if let Some(ref d) = decl_opt {
            insert.push_str("; ");
            insert.push_str(d);
        }
        if let Some(v) = tag_ohb {
            insert.push_str("; tag_ohb: ");
            insert.push_str(&v.to_string());
        }
        if tag_oor {
            insert.push_str("; TAG_OOR");
        }
        for m in &close_mods {
            insert.push_str("; ");
            insert.push_str(m);
        }
        let insert_bytes = insert.as_bytes();

        #[cfg(debug_assertions)]
        eprintln!(
            "[render_text] backtracking: field_number={} insert={:?} at offset={}",
            field_number, insert, header_nl_pos
        );

        // Insert before the '\n' at header_nl_pos.
        let n = insert_bytes.len();
        out.splice(header_nl_pos..header_nl_pos, insert_bytes.iter().copied());
        // Adjust CBL_START: the splice shifted all bytes after header_nl_pos.
        CBL_START.with(|c| c.set(c.get() + n));
    }

    write_close_brace(out);
}
