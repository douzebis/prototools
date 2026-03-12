// SPDX-FileCopyrightText: 2025-2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
// SPDX-FileCopyrightText: 2025-2026 Thales Cloud Sécurisé
//
// SPDX-License-Identifier: MIT

use crate::helpers::{
    write_varint_ohb, WT_END_GROUP, WT_I32, WT_I64, WT_LEN, WT_START_GROUP, WT_VARINT,
};
use memchr::memrchr;

mod encode_annotation;
#[cfg(test)]
use encode_annotation::parse_field_decl_into;
use encode_annotation::{parse_annotation, Ann};

// ── Constants ──────────────────────────────────────────────────────────────────

/// Sentinel stored in `next_placeholder` when there is no successor.
const NO_NEXT: u64 = 0xFF_FFFF_FFFF; // 5 bytes of 0xFF

/// Base overhead of one placeholder: waste(1) + next(5) + varint_room_base(5).
const BASE_OVERHEAD: usize = 11;

// ── Stack frame ────────────────────────────────────────────────────────────────

/// One entry on the nesting stack.
enum Frame {
    Message {
        placeholder_start: usize, // absolute offset of this placeholder in `out`
        ohb: usize,               // length_overhang_count (extra bytes in varint_room)
        content_start: usize,     // first byte of child content (after placeholder)
        acw: usize,               // accumulated child waste from inner placeholders
    },
    Group {
        field_number: u64,
        open_ended: bool,
        mismatched_end: Option<u64>,
        end_tag_ohb: Option<u64>,
        acw: usize, // accumulated child waste (propagated to parent)
    },
}

impl Frame {
    fn acw_mut(&mut self) -> &mut usize {
        match self {
            Frame::Message { acw, .. } => acw,
            Frame::Group { acw, .. } => acw,
        }
    }
}

// ── Placeholder helpers (Strategy C2) ─────────────────────────────────────────

/// Write `BASE_OVERHEAD + ohb` placeholder bytes at the current end of `out`.
///
/// Updates the forward linked list: the previously opened placeholder's
/// `next_placeholder` field is updated to point at the new placeholder.
///
/// Returns `(placeholder_start, content_start)`.
fn write_placeholder(
    out: &mut Vec<u8>,
    ohb: usize,
    first_placeholder: &mut Option<usize>,
    last_placeholder: &mut Option<usize>,
) -> (usize, usize) {
    let placeholder_start = out.len();

    // waste (1 byte, filled on `}`)
    out.push(0u8);

    // next_placeholder (5 bytes, initially SENTINEL)
    let sentinel = NO_NEXT.to_le_bytes();
    out.extend_from_slice(&sentinel[..5]);

    // varint_room (5 + ohb bytes, all zeros; filled flush-right on `}`)
    for _ in 0..5 + ohb {
        out.push(0u8);
    }

    // Link into the forward linked list (buffer order = opening order).
    if let Some(last_ph) = *last_placeholder {
        let next_bytes = (placeholder_start as u64).to_le_bytes();
        out[last_ph + 1..last_ph + 6].copy_from_slice(&next_bytes[..5]);
    }
    if first_placeholder.is_none() {
        *first_placeholder = Some(placeholder_start);
    }
    *last_placeholder = Some(placeholder_start);

    (placeholder_start, out.len())
}

/// Fill in a MESSAGE placeholder when its `}` is reached.
///
/// `frame_acw` is the accumulated waste from inner placeholders within this
/// frame's content region (needed to compute the correct compacted length).
/// Returns the total waste (placeholder waste + frame_acw) to propagate up.
fn fill_placeholder(
    out: &mut [u8],
    placeholder_start: usize,
    ohb: usize,
    content_start: usize,
    frame_acw: usize,
) -> usize {
    // Compacted child length = raw length − waste from inner placeholders.
    let child_len_raw = out.len() - content_start;
    let child_len_compacted = child_len_raw - frame_acw;

    // Encode compacted length (with optional ohb non-minimal bytes).
    let ohb_opt = if ohb > 0 { Some(ohb as u64) } else { None };
    let mut tmp = Vec::new();
    write_varint_ohb(child_len_compacted as u64, ohb_opt, &mut tmp);
    let k = tmp.len(); // actual bytes used (varint_bytes + ohb)

    // Write varint flush-right into varint_room.
    let varint_room_end = placeholder_start + BASE_OVERHEAD + ohb;
    let varint_write_start = varint_room_end - k;
    out[varint_write_start..varint_room_end].copy_from_slice(&tmp);

    // Set waste.
    let waste = BASE_OVERHEAD + ohb - k;
    out[placeholder_start] = waste as u8;

    // Return total waste to propagate to the parent frame.
    waste + frame_acw
}

// ── Forward compaction pass ───────────────────────────────────────────────────

/// Remove placeholder waste bytes in a single left-to-right pass.
///
/// Traverses the forward linked list of placeholders and uses `copy_within`
/// to compact the buffer in-place.  Each byte is moved at most once → O(n).
fn compact(out: &mut Vec<u8>, first_placeholder: usize) {
    let total_len = out.len();
    let mut read_pos = 0usize;
    let mut write_pos = 0usize;
    let mut cursor = first_placeholder;

    #[cfg(debug_assertions)]
    eprintln!(
        "[encode_text] compact: total_len={} first_placeholder={}",
        total_len, first_placeholder
    );

    loop {
        // Copy real data that sits before this placeholder.
        if cursor > read_pos {
            out.copy_within(read_pos..cursor, write_pos);
            write_pos += cursor - read_pos;
        }

        // Read waste and next BEFORE any copy_within can overwrite them.
        let waste = out[cursor] as usize;
        let mut next_bytes = [0u8; 8];
        next_bytes[..5].copy_from_slice(&out[cursor + 1..cursor + 6]);
        let next = u64::from_le_bytes(next_bytes);

        // Skip the wasted prefix; the varint starts at cursor + waste.
        read_pos = cursor + waste;

        if next == NO_NEXT {
            break;
        }
        cursor = next as usize;
    }

    // Copy everything from the last varint onwards.
    if read_pos < total_len {
        out.copy_within(read_pos..total_len, write_pos);
        write_pos += total_len - read_pos;
    }

    out.truncate(write_pos);

    #[cfg(debug_assertions)]
    eprintln!(
        "[encode_text] compact done: final_len={} (saved {} bytes)",
        write_pos,
        total_len - write_pos
    );
}

// ── Low-level tag helper ──────────────────────────────────────────────────────

#[inline]
fn write_tag_ohb_local(field_number: u64, wire_type: u32, ohb: Option<u64>, out: &mut Vec<u8>) {
    let tag_val = (field_number << 3) | (wire_type as u64);
    write_varint_ohb(tag_val, ohb, out);
}

// ── Number value ──────────────────────────────────────────────────────────────

#[derive(Clone, Copy)]
enum Num {
    Int(i64),
    Float(f64),
}

impl Num {
    #[inline]
    fn as_f64(self) -> f64 {
        match self {
            Num::Int(i) => i as f64,
            Num::Float(f) => f,
        }
    }
    #[inline]
    fn as_i64(self) -> i64 {
        match self {
            Num::Int(i) => i,
            Num::Float(f) => f as i64,
        }
    }
    #[inline]
    fn as_u64(self) -> u64 {
        self.as_i64() as u64
    }
}

fn parse_num(s: &str) -> Option<Num> {
    let s = s.trim();
    if s.starts_with("0x") || s.starts_with("0X") {
        return u64::from_str_radix(&s[2..], 16)
            .ok()
            .map(|v| Num::Int(v as i64));
    }
    if s == "nan" {
        return Some(Num::Float(f64::NAN));
    }
    if s == "inf" {
        return Some(Num::Float(f64::INFINITY));
    }
    if s == "-inf" {
        return Some(Num::Float(f64::NEG_INFINITY));
    }
    if s == "-0" {
        return Some(Num::Float(-0.0_f64));
    }
    if s.contains('.') || s.to_ascii_lowercase().contains('e') {
        return s.parse::<f64>().ok().map(Num::Float);
    }
    if let Some(neg) = s.strip_prefix('-') {
        return neg
            .parse::<u64>()
            .ok()
            .map(|v| Num::Int((v as i64).wrapping_neg()))
            .or_else(|| s.parse::<i64>().ok().map(Num::Int));
    }
    s.parse::<u64>().ok().map(|v| Num::Int(v as i64))
}

// ── String / bytes unescaping ─────────────────────────────────────────────────

/// Unescape a protoc-quoted byte literal (surrounding `"` included).
fn unescape_bytes(quoted: &str) -> Vec<u8> {
    let s = quoted
        .strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .unwrap_or(quoted);
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 1 < bytes.len() {
            match bytes[i + 1] {
                b'n' => {
                    out.push(b'\n');
                    i += 2;
                }
                b'r' => {
                    out.push(b'\r');
                    i += 2;
                }
                b't' => {
                    out.push(b'\t');
                    i += 2;
                }
                b'"' => {
                    out.push(b'"');
                    i += 2;
                }
                b'\'' => {
                    out.push(b'\'');
                    i += 2;
                }
                b'\\' => {
                    out.push(b'\\');
                    i += 2;
                }
                c if (b'0'..=b'7').contains(&c) => {
                    let j_end = (i + 4).min(bytes.len());
                    let mut j = i + 1;
                    while j < j_end && (b'0'..=b'7').contains(&bytes[j]) {
                        j += 1;
                    }
                    let oct = std::str::from_utf8(&bytes[i + 1..j]).unwrap_or("0");
                    out.push(u8::from_str_radix(oct, 8).unwrap_or(0));
                    i = j;
                }
                b'x' if i + 3 < bytes.len() => {
                    let hex = std::str::from_utf8(&bytes[i + 2..i + 4]).unwrap_or("00");
                    out.push(u8::from_str_radix(hex, 16).unwrap_or(0));
                    i += 4;
                }
                _ => {
                    out.push(bytes[i]);
                    i += 1;
                }
            }
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    out
}

// ── Scalar encoder ────────────────────────────────────────────────────────────

/// Encode a scalar field line directly into `out`.
///
/// `value_str` is the trimmed text value (right-hand side of `:`).
/// `ann` carries the annotation metadata.
fn encode_scalar_line(field_number: u64, value_str: &str, ann: &Ann<'_>, out: &mut Vec<u8>) {
    let tag_ohb = ann.tag_overhang_count;
    let val_ohb = ann.value_overhang_count;
    let len_ohb = ann.length_overhang_count;
    let wire = ann.wire_type;

    // ── Explicit error wire types ──────────────────────────────────────────────

    match wire {
        "INVALID_TAG_TYPE" => {
            // No tag; raw bytes as the entire field.
            let data = unescape_bytes(value_str);
            out.extend_from_slice(&data);
            return;
        }
        "INVALID_VARINT" => {
            write_tag_ohb_local(field_number, WT_VARINT, tag_ohb, out);
            out.extend_from_slice(&unescape_bytes(value_str));
            return;
        }
        "INVALID_FIXED64" => {
            write_tag_ohb_local(field_number, WT_I64, tag_ohb, out);
            out.extend_from_slice(&unescape_bytes(value_str));
            return;
        }
        "INVALID_FIXED32" => {
            write_tag_ohb_local(field_number, WT_I32, tag_ohb, out);
            out.extend_from_slice(&unescape_bytes(value_str));
            return;
        }
        "INVALID_LEN" => {
            write_tag_ohb_local(field_number, WT_LEN, tag_ohb, out);
            out.extend_from_slice(&unescape_bytes(value_str));
            return;
        }
        "TRUNCATED_BYTES" => {
            let data = unescape_bytes(value_str);
            let missing = ann.missing_bytes_count.unwrap_or(0) as usize;
            let declared = data.len() + missing;
            write_tag_ohb_local(field_number, WT_LEN, tag_ohb, out);
            write_varint_ohb(declared as u64, len_ohb, out);
            out.extend_from_slice(&data);
            return;
        }
        "INVALID_PACKED_RECORDS" | "INVALID_STRING" => {
            let data = unescape_bytes(value_str);
            write_tag_ohb_local(field_number, WT_LEN, tag_ohb, out);
            write_varint_ohb(data.len() as u64, len_ohb, out);
            out.extend_from_slice(&data);
            return;
        }
        "INVALID_GROUP_END" => {
            write_tag_ohb_local(field_number, WT_END_GROUP, tag_ohb, out);
            out.extend_from_slice(&unescape_bytes(value_str));
            return;
        }
        _ => {}
    }

    // ── Packed array: "[v1, v2, …]" ───────────────────────────────────────────

    if value_str.starts_with('[') {
        encode_packed_array_line(field_number, value_str, ann, out);
        return;
    }

    // ── Known wire type overrides (v2 lowercase names) ────────────────────────

    match wire {
        "varint" => {
            if let Some(num) = parse_num(value_str) {
                write_tag_ohb_local(field_number, WT_VARINT, tag_ohb, out);
                write_varint_ohb(num.as_u64(), val_ohb, out);
            } else {
                // bool literal
                let v: u64 = if value_str == "true" { 1 } else { 0 };
                write_tag_ohb_local(field_number, WT_VARINT, tag_ohb, out);
                write_varint_ohb(v, val_ohb, out);
            }
            return;
        }
        "fixed64" => {
            if let Some(num) = parse_num(value_str) {
                let v: u64 = if let Num::Float(f) = num {
                    f.to_bits()
                } else {
                    num.as_u64()
                };
                write_tag_ohb_local(field_number, WT_I64, tag_ohb, out);
                out.extend_from_slice(&v.to_le_bytes());
            }
            return;
        }
        "fixed32" => {
            if let Some(num) = parse_num(value_str) {
                let v: u32 = if let Num::Float(f) = num {
                    (f as f32).to_bits()
                } else {
                    num.as_u64() as u32
                };
                write_tag_ohb_local(field_number, WT_I32, tag_ohb, out);
                out.extend_from_slice(&v.to_le_bytes());
            }
            return;
        }
        "bytes" => {
            // Explicit wire type `bytes` (unknown field or wire-type mismatch).
            let data = unescape_bytes(value_str);
            write_tag_ohb_local(field_number, WT_LEN, tag_ohb, out);
            write_varint_ohb(data.len() as u64, len_ohb, out);
            out.extend_from_slice(&data);
            return;
        }
        _ => {}
    }

    // ── Infer encoding from field_type (no explicit wire type) ────────────────

    let ft = ann.field_type;

    // bool literal
    if value_str == "true" || value_str == "false" {
        let v: u64 = if value_str == "true" { 1 } else { 0 };
        write_tag_ohb_local(field_number, WT_VARINT, tag_ohb, out);
        write_varint_ohb(v, val_ohb, out);
        return;
    }

    // Quoted string / bytes
    if value_str.starts_with('"') {
        let is_bytes = matches!(ft, "bytes" | "");
        let data = if is_bytes {
            unescape_bytes(value_str)
        } else {
            // string field: unescape then re-encode as UTF-8
            unescape_bytes(value_str)
        };
        write_tag_ohb_local(field_number, WT_LEN, tag_ohb, out);
        write_varint_ohb(data.len() as u64, len_ohb, out);
        out.extend_from_slice(&data);
        return;
    }

    // For enum scalar fields: use the numeric value extracted from the annotation
    // (e.g. `Type(9)`) instead of parsing the LHS symbolic name (e.g. `TYPE_STRING`).
    // This avoids name-resolution and eliminates the primitive-keyword collision hazard.
    if let Some(enum_val) = ann.enum_scalar_value {
        encode_num(
            field_number,
            Num::Int(enum_val),
            "enum",
            tag_ohb,
            val_ohb,
            ann.neg_int32_truncated,
            out,
        );
        return;
    }

    // Numeric value — dispatch by field_type
    let Some(num) = parse_num(value_str) else {
        return;
    };
    encode_num(
        field_number,
        num,
        ft,
        tag_ohb,
        val_ohb,
        ann.neg_int32_truncated,
        out,
    );
}

/// Encode a numeric value according to `field_type`.
///
/// `truncated`: when `true` and `field_type` is `"int32"` or `"enum"`, produce the
/// 5-byte truncated varint form (`value as i32 as u32 as u64`).  When `false`,
/// produce the spec-correct 10-byte sign-extended form (`value as i64 as u64`).
fn encode_num(
    field_number: u64,
    num: Num,
    field_type: &str,
    tag_ohb: Option<u64>,
    val_ohb: Option<u64>,
    truncated: bool,
    out: &mut Vec<u8>,
) {
    match field_type {
        "double" => {
            write_tag_ohb_local(field_number, WT_I64, tag_ohb, out);
            out.extend_from_slice(&num.as_f64().to_le_bytes());
        }
        "fixed64" | "sfixed64" => {
            write_tag_ohb_local(field_number, WT_I64, tag_ohb, out);
            out.extend_from_slice(&num.as_u64().to_le_bytes());
        }
        "float" => {
            let f = num.as_f64() as f32;
            write_tag_ohb_local(field_number, WT_I32, tag_ohb, out);
            out.extend_from_slice(&f.to_le_bytes());
        }
        "fixed32" | "sfixed32" => {
            write_tag_ohb_local(field_number, WT_I32, tag_ohb, out);
            out.extend_from_slice(&(num.as_u64() as u32).to_le_bytes());
        }
        "sint32" => {
            let v = num.as_i64() as i32;
            let enc = ((v << 1) ^ (v >> 31)) as u32 as u64;
            write_tag_ohb_local(field_number, WT_VARINT, tag_ohb, out);
            write_varint_ohb(enc, val_ohb, out);
        }
        "sint64" => {
            let v = num.as_i64();
            let enc = ((v << 1) ^ (v >> 63)) as u64;
            write_tag_ohb_local(field_number, WT_VARINT, tag_ohb, out);
            write_varint_ohb(enc, val_ohb, out);
        }
        "bool" => {
            write_tag_ohb_local(field_number, WT_VARINT, tag_ohb, out);
            write_varint_ohb(num.as_u64() & 1, val_ohb, out);
        }
        // int32 / enum: two valid wire forms for negative values.
        //   truncated=true  → 5-byte form  (value as i32 as u32 as u64)
        //   truncated=false → 10-byte spec-correct form (value as i64 as u64)
        "int32" | "enum" => {
            let v = if truncated {
                num.as_i64() as i32 as u32 as u64 // 5-byte truncated
            } else {
                num.as_i64() as u64 // 10-byte spec-correct
            };
            write_tag_ohb_local(field_number, WT_VARINT, tag_ohb, out);
            write_varint_ohb(v, val_ohb, out);
        }
        // uint32, int64, uint64, and fallback (unknown named types)
        _ => {
            write_tag_ohb_local(field_number, WT_VARINT, tag_ohb, out);
            write_varint_ohb(num.as_u64(), val_ohb, out);
        }
    }
}

/// Encode a packed-array value line `[v1, v2, …]` into `out`.
fn encode_packed_array_line(field_number: u64, value_str: &str, ann: &Ann<'_>, out: &mut Vec<u8>) {
    let ft = ann.field_type;
    let ohbs = &ann.records_overhung_count;

    // For packed ENUM fields: ignore the LHS symbolic-name list entirely.
    // Use the raw numeric values extracted from `EnumType([n1, n2])` in the annotation.
    if ft == "enum" && !ann.enum_packed_values.is_empty() {
        let mut payload = Vec::new();
        for (i, &raw_val) in ann.enum_packed_values.iter().enumerate() {
            let ohb = ohbs.get(i).copied().filter(|&o| o > 0);
            let trunc = ann
                .records_neg_int32_truncated
                .get(i)
                .copied()
                .unwrap_or(false);
            let v = if trunc {
                raw_val as i32 as u32 as u64 // 5-byte truncated
            } else {
                raw_val as u64 // 10-byte spec-correct for negatives
            };
            write_varint_ohb(v, ohb, &mut payload);
        }
        write_tag_ohb_local(field_number, WT_LEN, ann.tag_overhang_count, out);
        write_varint_ohb(payload.len() as u64, ann.length_overhang_count, out);
        out.extend_from_slice(&payload);
        return;
    }

    let inner = value_str.trim_start_matches('[').trim_end_matches(']');

    let mut payload = Vec::new();
    for (i, elem) in inner.split(',').enumerate() {
        let elem = elem.trim();
        if elem.is_empty() {
            continue;
        }
        let ohb = ohbs.get(i).copied().filter(|&o| o > 0);
        match ft {
            "double" => {
                if let Some(n) = parse_num(elem) {
                    payload.extend_from_slice(&n.as_f64().to_le_bytes());
                }
            }
            "float" => {
                if let Some(n) = parse_num(elem) {
                    let f = n.as_f64() as f32;
                    payload.extend_from_slice(&f.to_le_bytes());
                }
            }
            "fixed64" | "sfixed64" => {
                if let Some(n) = parse_num(elem) {
                    payload.extend_from_slice(&n.as_u64().to_le_bytes());
                }
            }
            "fixed32" | "sfixed32" => {
                if let Some(n) = parse_num(elem) {
                    payload.extend_from_slice(&(n.as_u64() as u32).to_le_bytes());
                }
            }
            "sint32" => {
                if let Some(n) = parse_num(elem) {
                    let v = n.as_i64() as i32;
                    let enc = ((v << 1) ^ (v >> 31)) as u32 as u64;
                    write_varint_ohb(enc, ohb, &mut payload);
                }
            }
            "sint64" => {
                if let Some(n) = parse_num(elem) {
                    let v = n.as_i64();
                    let enc = ((v << 1) ^ (v >> 63)) as u64;
                    write_varint_ohb(enc, ohb, &mut payload);
                }
            }
            "bool" => {
                let v: u64 = if elem == "true" { 1 } else { 0 };
                write_varint_ohb(v, ohb, &mut payload);
            }
            // int32 / enum: honour per-element truncation flag.
            //   truncated=true  → 5-byte form  (n as i32 as u32 as u64)
            //   truncated=false → 10-byte spec-correct form (n as i64 as u64)
            "int32" | "enum" => {
                if let Some(n) = parse_num(elem) {
                    let trunc = ann
                        .records_neg_int32_truncated
                        .get(i)
                        .copied()
                        .unwrap_or(false);
                    let v = if trunc {
                        n.as_i64() as i32 as u32 as u64 // 5-byte truncated
                    } else {
                        n.as_i64() as u64 // 10-byte spec-correct
                    };
                    write_varint_ohb(v, ohb, &mut payload);
                }
            }
            _ => {
                if let Some(n) = parse_num(elem) {
                    write_varint_ohb(n.as_u64(), ohb, &mut payload);
                }
            }
        }
    }

    write_tag_ohb_local(field_number, WT_LEN, ann.tag_overhang_count, out);
    write_varint_ohb(payload.len() as u64, ann.length_overhang_count, out);
    out.extend_from_slice(&payload);
}

// ── Helpers: field number and line classification ─────────────────────────────

/// Extract the field number from the LHS of a line and/or annotation.
///
/// Precedence: annotation's field_decl (`= N`) > numeric LHS.
#[inline]
fn extract_field_number(lhs: &str, ann: &Ann<'_>) -> u64 {
    if let Some(fn_) = ann.field_number {
        return fn_;
    }
    lhs.trim().parse::<u64>().unwrap_or(0)
}

/// Split a line into `(value_part, annotation_str)`.
///
/// The separator is `  #@ ` (2 spaces + `#` + `@` + space).  We scan right-to-left
/// so that quoted string values containing `  #@ ` don't confuse the split.
#[inline]
fn split_at_annotation(line: &str) -> (&str, &str) {
    // Find the rightmost "  #@ " separator using SIMD-accelerated memrchr for '#',
    // then verify the surrounding bytes.  Falls back leftward on false positives
    // (a bare '#' inside a string value).
    let b = line.as_bytes();
    let mut end = b.len();
    while let Some(p) = memrchr(b'#', &b[..end]) {
        if p >= 2
            && b[p - 1] == b' '
            && b[p - 2] == b' '
            && p + 2 < b.len()
            && b[p + 1] == b'@'
            && b[p + 2] == b' '
        {
            // "  #@ " confirmed: field part ends at p-2, annotation starts at p+3
            return (&line[..p - 2], &line[p + 3..]);
        }
        end = p; // keep searching leftward
    }
    (line, "")
}

// ── Public entry point ────────────────────────────────────────────────────────

/// Decode a textual prototext byte string directly to binary wire bytes.
///
/// Input must start with `b"#@ prototext:"`.
/// The line-by-line format must have been produced with `include_annotations=true`
/// (the annotation comment on each line is required to reconstruct field numbers
/// and types when field names are used on the LHS).
///
/// Implements Proposal F — Strategy C2 for MESSAGE frames.
pub fn encode_text_to_binary(text: &[u8]) -> Vec<u8> {
    let capacity = (text.len() / 6).max(64);
    let mut out = Vec::with_capacity(capacity);

    let mut stack: Vec<Frame> = Vec::new();
    let mut first_placeholder: Option<usize> = None;
    let mut last_placeholder: Option<usize> = None;

    // The text is always valid ASCII (a subset of UTF-8).
    let text_str = match std::str::from_utf8(text) {
        Ok(s) => s,
        Err(_) => return out,
    };

    let mut lines = text_str.lines();

    // Skip the first line: "#@ prototext: protoc"
    lines.next();

    for line in lines {
        let line = line.trim_end(); // strip trailing CR/spaces

        if line.is_empty() {
            continue;
        }

        // ── Close brace ───────────────────────────────────────────────────────
        //
        // Brace-folding may place multiple `}` on one line, separated by spaces
        // (e.g. `}}` for indent_size=1, `} } }` for indent_size=2).  A close-
        // brace line consists solely of `}` and space characters after the
        // leading indentation.  Walk the trimmed line byte-by-byte and pop the
        // stack once per `}` found.

        let trimmed = line.trim_start();
        if !trimmed.is_empty() && trimmed.bytes().all(|b| b == b'}' || b == b' ') {
            for b in trimmed.bytes() {
                if b == b'}' {
                    match stack.pop() {
                        Some(Frame::Message {
                            placeholder_start,
                            ohb,
                            content_start,
                            acw,
                        }) => {
                            let total_waste = fill_placeholder(
                                &mut out,
                                placeholder_start,
                                ohb,
                                content_start,
                                acw,
                            );
                            // Propagate waste to parent frame.
                            if let Some(parent) = stack.last_mut() {
                                *parent.acw_mut() += total_waste;
                            }
                        }
                        Some(Frame::Group {
                            field_number,
                            open_ended,
                            mismatched_end,
                            end_tag_ohb,
                            acw,
                        }) => {
                            if !open_ended {
                                let end_fn = mismatched_end.unwrap_or(field_number);
                                write_tag_ohb_local(end_fn, WT_END_GROUP, end_tag_ohb, &mut out);
                            }
                            // Propagate accumulated waste from inner MESSAGE placeholders.
                            if acw > 0 {
                                if let Some(parent) = stack.last_mut() {
                                    *parent.acw_mut() += acw;
                                }
                            }
                        }
                        None => { /* unmatched `}` — ignore */ }
                    }
                }
            }
            continue;
        }

        // Split value part from annotation.
        let (value_part, ann_str) = split_at_annotation(line);

        // ── Open brace ────────────────────────────────────────────────────────

        // Detect `name {` (possibly indented, before the annotation).
        let vp_trimmed = value_part.trim_end();
        let is_open_brace = vp_trimmed.ends_with(" {") || vp_trimmed == "{";

        if is_open_brace {
            let ann = parse_annotation(ann_str);

            // Extract the field name (LHS of `name {`).
            let lhs = vp_trimmed.trim_start().trim_end_matches('{').trim_end();

            let field_number = extract_field_number(lhs, &ann);
            let tag_ohb = ann.tag_overhang_count;

            if ann.wire_type == "group" {
                write_tag_ohb_local(field_number, WT_START_GROUP, tag_ohb, &mut out);
                stack.push(Frame::Group {
                    field_number,
                    open_ended: ann.open_ended_group,
                    mismatched_end: ann.mismatched_group_end,
                    end_tag_ohb: ann.end_tag_overhang_count,
                    acw: 0,
                });
            } else {
                // MESSAGE (wire type BYTES or unspecified).
                write_tag_ohb_local(field_number, WT_LEN, tag_ohb, &mut out);
                let ohb = ann.length_overhang_count.unwrap_or(0) as usize;
                let (ph_start, content_start) =
                    write_placeholder(&mut out, ohb, &mut first_placeholder, &mut last_placeholder);
                stack.push(Frame::Message {
                    placeholder_start: ph_start,
                    ohb,
                    content_start,
                    acw: 0,
                });
            }
            continue;
        }

        // ── Scalar field line ─────────────────────────────────────────────────

        // Find the colon separating LHS from value.
        let Some(colon_pos) = value_part.find(':') else {
            continue;
        };
        let lhs = value_part[..colon_pos].trim_start(); // may be indented
        let value_str = value_part[colon_pos + 1..].trim();

        let ann = parse_annotation(ann_str);
        let field_number = extract_field_number(lhs, &ann);

        encode_scalar_line(field_number, value_str, &ann, &mut out);
    }

    // ── Forward compaction pass ───────────────────────────────────────────────

    if let Some(first_ph) = first_placeholder {
        compact(&mut out, first_ph);
    }

    // Development instrumentation — size ratio
    #[cfg(debug_assertions)]
    {
        let ratio = out.len() as f64 / text.len().max(1) as f64;
        eprintln!(
            "[encode_text] input_len={} output_len={} ratio={:.2}",
            text.len(),
            out.len(),
            ratio
        );
    }

    out
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── split_at_annotation ───────────────────────────────────────────────────

    #[test]
    fn split_bare() {
        let (field, ann) = split_at_annotation("name: 42");
        assert_eq!(field, "name: 42");
        assert_eq!(ann, "");
    }

    #[test]
    fn split_hash_at_space() {
        let (field, ann) = split_at_annotation("name: 42  #@ varint = 1");
        assert_eq!(field, "name: 42");
        assert_eq!(ann, "varint = 1");
    }

    #[test]
    fn split_hash_only() {
        // Bare '#' without '@': not a separator.
        let (field, ann) = split_at_annotation("name: 42  #");
        assert_eq!(field, "name: 42  #");
        assert_eq!(ann, "");
    }

    #[test]
    fn split_hash_at_end() {
        // "#@" at end with no space after '@': not a separator.
        let (field, ann) = split_at_annotation("name: 42  #@");
        assert_eq!(field, "name: 42  #@");
        assert_eq!(ann, "");
    }

    #[test]
    fn split_hash_at_no_space() {
        // "#@x" — '@' not followed by space: not a separator.
        let (field, ann) = split_at_annotation("name: 42  #@x");
        assert_eq!(field, "name: 42  #@x");
        assert_eq!(ann, "");
    }

    // ── parse_field_decl_into — enum suffix forms ─────────────────────────────

    fn make_ann() -> Ann<'static> {
        Ann {
            wire_type: "",
            field_type: "",
            field_number: None,
            is_packed: false,
            tag_overhang_count: None,
            value_overhang_count: None,
            length_overhang_count: None,
            missing_bytes_count: None,
            mismatched_group_end: None,
            open_ended_group: false,
            end_tag_overhang_count: None,
            records_overhung_count: vec![],
            neg_int32_truncated: false,
            records_neg_int32_truncated: vec![],
            enum_scalar_value: None,
            enum_packed_values: vec![],
        }
    }

    #[test]
    fn parse_scalar_enum() {
        let mut ann = make_ann();
        parse_field_decl_into("Type(9) = 5", &mut ann);
        assert_eq!(ann.field_type, "enum");
        assert_eq!(ann.enum_scalar_value, Some(9));
        assert_eq!(ann.field_number, Some(5));
    }

    #[test]
    fn parse_scalar_enum_neg() {
        let mut ann = make_ann();
        parse_field_decl_into("Color(-1) = 3", &mut ann);
        assert_eq!(ann.field_type, "enum");
        assert_eq!(ann.enum_scalar_value, Some(-1));
        assert_eq!(ann.field_number, Some(3));
    }

    #[test]
    fn parse_packed_enum() {
        let mut ann = make_ann();
        parse_field_decl_into("Label([1, 2, 3]) [packed=true] = 4", &mut ann);
        assert_eq!(ann.field_type, "enum");
        assert!(ann.is_packed);
        assert_eq!(ann.enum_packed_values, vec![1, 2, 3]);
        assert_eq!(ann.field_number, Some(4));
    }

    #[test]
    fn parse_primitive_int32() {
        let mut ann = make_ann();
        parse_field_decl_into("int32 = 25", &mut ann);
        assert_eq!(ann.field_type, "int32");
        assert_eq!(ann.field_number, Some(25));
        assert_eq!(ann.enum_scalar_value, None);
    }

    #[test]
    fn parse_enum_named_float() {
        // Latent-bug regression (spec 0004 §5.1): an enum whose type name
        // collides with the 'float' primitive must route to varint, not fixed32.
        let mut ann = make_ann();
        parse_field_decl_into("float(1) = 1", &mut ann);
        assert_eq!(
            ann.field_type, "enum",
            "enum named 'float' must set field_type='enum', not 'float'"
        );
        assert_eq!(ann.enum_scalar_value, Some(1));
    }

    // ── ENUM_UNKNOWN silencing ────────────────────────────────────────────────

    #[test]
    fn enum_unknown_encodes_correctly() {
        // A field annotated with ENUM_UNKNOWN must encode the varint from the
        // annotation's EnumType(N) suffix, not fail or produce wrong bytes.
        // Field 1, value 99 → tag 0x08 (field=1, wire=varint), varint 0x63.
        let input = b"#@ prototext: protoc\nkind: 99  #@ Type(99) = 1; ENUM_UNKNOWN\n";
        let wire = encode_text_to_binary(input);
        assert_eq!(
            wire,
            vec![0x08, 0x63],
            "ENUM_UNKNOWN field 1 value 99: expected [0x08, 0x63]"
        );
    }
}
