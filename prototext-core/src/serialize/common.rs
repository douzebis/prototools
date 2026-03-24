// SPDX-FileCopyrightText: 2025 - 2026 Frederic Ruget <fred@atlant.is> <fred@s3ns.io> (GitHub: @douzebis)
// SPDX-FileCopyrightText: 2025 - 2026 Thales Cloud Sécurisé
//
// SPDX-License-Identifier: MIT

use crate::decoder::{ProtoTextContent, ProtoTextField};

// ── Byte / string escaping ────────────────────────────────────────────────────
// Mirrors escape_bytes() / escape_string() in common.py.

pub fn escape_bytes(b: &[u8]) -> String {
    let mut out = String::with_capacity(b.len());
    for &byte in b {
        match byte {
            b'\\' => out.push_str("\\\\"),
            b'"' => out.push_str("\\\""),
            b'\'' => out.push_str("\\'"),
            b'\n' => out.push_str("\\n"),
            b'\r' => out.push_str("\\r"),
            b'\t' => out.push_str("\\t"),
            32..=126 => out.push(byte as char),
            _ => {
                out.push('\\');
                out.push_str(&format!("{:03o}", byte));
            }
        }
    }
    out
}

/// Zero-allocation variant of `escape_bytes`: appends escaped bytes directly to `out`.
#[inline]
pub fn escape_bytes_into(b: &[u8], out: &mut Vec<u8>) {
    for &byte in b {
        match byte {
            b'\\' => out.extend_from_slice(b"\\\\"),
            b'"' => out.extend_from_slice(b"\\\""),
            b'\'' => out.extend_from_slice(b"\\'"),
            b'\n' => out.extend_from_slice(b"\\n"),
            b'\r' => out.extend_from_slice(b"\\r"),
            b'\t' => out.extend_from_slice(b"\\t"),
            32..=126 => out.push(byte),
            _ => {
                // Octal escape: \NNN
                out.push(b'\\');
                out.push(b'0' + (byte >> 6));
                out.push(b'0' + ((byte >> 3) & 7));
                out.push(b'0' + (byte & 7));
            }
        }
    }
}

pub fn escape_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 32 => {
                out.push_str(&format!("\\{:03o}", c as u32));
            }
            c => out.push(c),
        }
    }
    out
}

/// Zero-allocation variant of `escape_string`: appends escaped bytes directly to `out`.
#[inline]
pub fn escape_string_into(s: &str, out: &mut Vec<u8>) {
    for c in s.chars() {
        match c {
            '\\' => out.extend_from_slice(b"\\\\"),
            '"' => out.extend_from_slice(b"\\\""),
            '\n' => out.extend_from_slice(b"\\n"),
            '\r' => out.extend_from_slice(b"\\r"),
            '\t' => out.extend_from_slice(b"\\t"),
            c if (c as u32) < 32 => {
                // Octal escape: \NNN (c < 32 so top octal digit is always 0)
                let v = c as u32;
                out.push(b'\\');
                out.push(b'0' + (v >> 6) as u8);
                out.push(b'0' + ((v >> 3) & 7) as u8);
                out.push(b'0' + (v & 7) as u8);
            }
            c => {
                let mut buf = [0u8; 4];
                out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
            }
        }
    }
}

// ── Float / double formatting ─────────────────────────────────────────────────
// Mirrors format_double_like_text_format / format_float_like_text_format.
//
// The Python functions delegate to protobuf's C++ text_format for exact
// compatibility.  The Rust versions replicate the same algorithm:
//
//   double: Python str(float64) shortest round-trip.
//   float:  ToShortestFloat — try 6..=9 significant digits until f32 round-trips.

pub fn format_double(v: f64) -> String {
    if v.is_nan() {
        let bits = v.to_bits();
        return if bits == f64::NAN.to_bits() {
            "nan".to_owned()
        } else {
            format!("nan(0x{:016x})", bits)
        };
    }
    if v.is_infinite() {
        return if v > 0.0 {
            "inf".to_owned()
        } else {
            "-inf".to_owned()
        };
    }

    // Match Python's str(float) behavior: use scientific notation when
    // the exponent is < -4 or >= 16 (matching Python's default float repr).
    // This ensures compatibility with Python's text_format output.
    let abs_v = v.abs();
    let use_scientific = abs_v >= 1e16 || (abs_v != 0.0 && abs_v < 1e-4);

    let s = if use_scientific {
        // Use scientific notation, then convert to Python style
        format!("{:e}", v)
    } else {
        // Use default formatting (which may already include .0 for integers)
        format!("{}", v)
    };
    python_exponent_style(&s)
}

pub fn format_float(v: f32) -> String {
    if v.is_nan() {
        let bits = v.to_bits();
        return if bits == f32::NAN.to_bits() {
            "nan".to_owned()
        } else {
            format!("nan(0x{:08x})", bits)
        };
    }
    if v.is_infinite() {
        return if v > 0.0 {
            "inf".to_owned()
        } else {
            "-inf".to_owned()
        };
    }
    for prec in 6usize..=9 {
        let s = format!("{:.prec$e}", v, prec = prec - 1);
        let g_str = rust_sci_to_g_style(&s, prec);
        if let Ok(reparsed) = g_str.parse::<f32>() {
            if reparsed == v {
                return python_exponent_style(&g_str);
            }
        }
    }
    let s = format!("{:.8e}", v);
    python_exponent_style(&rust_sci_to_g_style(&s, 9))
}

/// Protoc-style double: try 15 significant digits (%g), fall back to 17.
///
/// Mirrors Python's `_format_floating_point_like_protoc(short_precision=15, long_precision=17)`:
/// `f'{value:.15g}'`, falling back to `f'{value:.17g}'` if needed for exact round-trip.
pub fn format_double_protoc(v: f64) -> String {
    if v.is_nan() {
        return "nan".to_owned();
    }
    if v.is_infinite() {
        return if v > 0.0 {
            "inf".to_owned()
        } else {
            "-inf".to_owned()
        };
    }
    let s15 = format!("{:.14e}", v);
    let g15 = rust_sci_to_g_style(&s15, 15);
    if let Ok(r) = g15.parse::<f64>() {
        if r == v {
            return protoc_exponent_style(&g15);
        }
    }
    let s17 = format!("{:.16e}", v);
    protoc_exponent_style(&rust_sci_to_g_style(&s17, 17))
}

/// Protoc-style float: try 6 significant digits (%g), fall back to 9.
///
/// Mirrors Python's `_format_floating_point_like_protoc(short_precision=6, long_precision=9)`
/// with the vanilla protoc (Google C++) exact bit-level round-trip check:
/// re-parse the 6g string as f32 and compare bits, falling back to 9g only when
/// the bit patterns differ.  This replaces the former approximate `1e-7` tolerance (D3 fix).
pub fn format_float_protoc(v: f32) -> String {
    if v.is_nan() {
        return "nan".to_owned();
    }
    if v.is_infinite() {
        return if v > 0.0 {
            "inf".to_owned()
        } else {
            "-inf".to_owned()
        };
    }
    let s6 = format!("{:.5e}", v);
    let g6 = rust_sci_to_g_style(&s6, 6);
    if let Ok(r) = g6.parse::<f32>() {
        if r.to_bits() == v.to_bits() {
            return protoc_exponent_style(&g6);
        } // D3: exact bit check
    }
    let s9 = format!("{:.8e}", v);
    protoc_exponent_style(&rust_sci_to_g_style(&s9, 9))
}

// ── Per-type protoc-compatible scalar formatters ───────────────────────────────
//
// One function per proto2 type, matching `protoc --decode` output exactly.
// See ext/prototext_codec/FLOATS_AND_DOUBLES.md §1 for the ground-truth tables.
//
// All of these are trivial wrappers today; they exist so that:
//   (a) render_text.rs and format_protoc_value have a single named call-site per type,
//   (b) future changes (e.g. adopting ryu for double) are made in one place only.

/// `int32` → signed decimal.
#[inline]
pub fn format_int32_protoc(v: i32) -> String {
    v.to_string()
}
/// `int64` → signed decimal.
#[inline]
pub fn format_int64_protoc(v: i64) -> String {
    v.to_string()
}
/// `uint32` → unsigned decimal.
#[inline]
pub fn format_uint32_protoc(v: u32) -> String {
    v.to_string()
}
/// `uint64` → unsigned decimal.
#[inline]
pub fn format_uint64_protoc(v: u64) -> String {
    v.to_string()
}
/// `sint32` → signed decimal (caller has already applied zigzag decode).
#[inline]
pub fn format_sint32_protoc(v: i32) -> String {
    v.to_string()
}
/// `sint64` → signed decimal (caller has already applied zigzag decode).
#[inline]
pub fn format_sint64_protoc(v: i64) -> String {
    v.to_string()
}
/// `fixed32` → unsigned decimal (NOT hex; protoc renders `fixed32` as decimal).
#[inline]
pub fn format_fixed32_protoc(v: u32) -> String {
    v.to_string()
}
/// `fixed64` → unsigned decimal (NOT hex).
#[inline]
pub fn format_fixed64_protoc(v: u64) -> String {
    v.to_string()
}
/// `sfixed32` → signed decimal.
#[inline]
pub fn format_sfixed32_protoc(v: i32) -> String {
    v.to_string()
}
/// `sfixed64` → signed decimal.
#[inline]
pub fn format_sfixed64_protoc(v: i64) -> String {
    v.to_string()
}
/// `bool` → `"true"` or `"false"`.
#[inline]
pub fn format_bool_protoc(v: bool) -> &'static str {
    if v {
        "true"
    } else {
        "false"
    }
}
/// `enum` → signed decimal (same representation as `int32`).
#[inline]
pub fn format_enum_protoc(v: i32) -> String {
    v.to_string()
}

// ── Wire-type fallback formatters ─────────────────────────────────────────────
//
// Used for unknown fields (field number absent from schema) and wire-type
// mismatches (field in schema but wire type differs from declared type).
//
// Protoc renders any such field solely by its actual wire type — schema is ignored.
// `--decode_raw` and `--decode=Msg` produce byte-for-byte identical output.
// See FLOATS_AND_DOUBLES.md §1.3 and §2.2 D2 for ground truth.

/// Unknown / mismatch VARINT (wt=0) → unsigned decimal (uint64).
#[inline]
pub fn format_wire_varint_protoc(v: u64) -> String {
    v.to_string()
}
/// Unknown / mismatch FIXED32 (wt=5) → `0x` + 8 lowercase hex digits (zero-padded).
#[inline]
pub fn format_wire_fixed32_protoc(v: u32) -> String {
    format!("0x{:08x}", v)
}
/// Unknown / mismatch FIXED64 (wt=1) → `0x` + 16 lowercase hex digits (zero-padded).
#[inline]
pub fn format_wire_fixed64_protoc(v: u64) -> String {
    format!("0x{:016x}", v)
}

/// Format exponent notation for protoc style (Python `%g`).
///
/// Normalises scientific notation to Python style (`e+01` → `e+01`, `e-04` → `e-04`).
/// Unlike `python_exponent_style`, does NOT append `.0` for whole numbers —
/// Python's `%g` format already omits trailing decimal points.
fn protoc_exponent_style(s: &str) -> String {
    if let Some(e_pos) = s.find('e') {
        let mantissa = &s[..e_pos];
        let exp_part = &s[e_pos + 1..];
        let (sign, digits) = if let Some(rest) = exp_part.strip_prefix('-') {
            ("-", rest)
        } else if let Some(rest) = exp_part.strip_prefix('+') {
            ("+", rest)
        } else {
            ("+", exp_part)
        };
        let digits: String = digits.trim_start_matches('0').to_owned();
        let digits = if digits.is_empty() {
            "0".to_owned()
        } else {
            digits
        };
        let formatted_exp = if digits.len() < 2 {
            format!("0{}", digits)
        } else {
            digits
        };
        format!("{}e{}{}", mantissa, sign, formatted_exp)
    } else {
        // No scientific notation — return as-is (do NOT add ".0")
        s.to_owned()
    }
}

fn python_exponent_style(s: &str) -> String {
    if let Some(e_pos) = s.find('e') {
        let mantissa = &s[..e_pos];
        let exp_part = &s[e_pos + 1..];
        let (sign, digits) = if let Some(rest) = exp_part.strip_prefix('-') {
            ("-", rest)
        } else if let Some(rest) = exp_part.strip_prefix('+') {
            ("+", rest)
        } else {
            ("+", exp_part)
        };
        let digits: String = digits.trim_start_matches('0').to_owned();
        let digits = if digits.is_empty() {
            "0".to_owned()
        } else {
            digits
        };
        let formatted_exp = if digits.len() < 2 {
            format!("0{}", digits)
        } else {
            digits
        };
        format!("{}e{}{}", mantissa, sign, formatted_exp)
    } else if !s.contains('.') && !s.contains('n') && !s.contains('i') {
        format!("{}.0", s)
    } else {
        s.to_owned()
    }
}

fn rust_sci_to_g_style(rust_sci: &str, prec: usize) -> String {
    let (mantissa_str, exp_str) = if let Some(pos) = rust_sci.find('e') {
        (&rust_sci[..pos], &rust_sci[pos + 1..])
    } else {
        return rust_sci.to_owned();
    };
    let exp: i32 = exp_str.parse().unwrap_or(0);
    let is_neg = mantissa_str.starts_with('-');
    let digits_str = mantissa_str.trim_start_matches('-').replace('.', "");
    let sig_digits: Vec<char> = digits_str.chars().collect();

    if exp >= -4 && exp < prec as i32 {
        // Keep decimal_pos as i32: (exp + 1) is negative when exp < -1, and
        // casting a negative i32 to usize would silently wrap to near-usize::MAX,
        // causing a capacity overflow panic in the .repeat() calls below.
        let decimal_pos = exp + 1; // i32; ≤ 0 when exp ∈ {-4,-3,-2,-1}
        let mut result = String::new();
        if is_neg {
            result.push('-');
        }
        if decimal_pos <= 0 {
            // exp < 0: output is "0.000…XYZ" with (-exp-1) leading zeros.
            // (-exp-1) as usize is safe here: exp ∈ [-4..-1] → value ∈ [0..3].
            result.push('0');
            result.push('.');
            result.push_str(&"0".repeat((-exp - 1) as usize));
            for d in &sig_digits {
                result.push(*d);
            }
        } else if decimal_pos as usize >= sig_digits.len() {
            // decimal_pos > 0 here, so the cast to usize is safe.
            for d in &sig_digits {
                result.push(*d);
            }
            result.push_str(&"0".repeat(decimal_pos as usize - sig_digits.len()));
            // No trailing ".0" — Python %g strips the decimal point entirely
            // for whole numbers (e.g. 1.0f32 → "1", not "1.0").
        } else {
            for (i, d) in sig_digits.iter().enumerate() {
                if i == decimal_pos as usize {
                    result.push('.');
                }
                result.push(*d);
            }
        }
        trim_trailing_zeros_after_dot(&mut result);
        result
    } else {
        let mut result = String::new();
        if is_neg {
            result.push('-');
        }
        if sig_digits.is_empty() {
            result.push('0');
        } else {
            result.push(sig_digits[0]);
            if sig_digits.len() > 1 {
                result.push('.');
                for d in &sig_digits[1..] {
                    result.push(*d);
                }
                trim_trailing_zeros_after_dot(&mut result);
            }
        }
        if exp >= 0 {
            result.push_str(&format!("e+{:02}", exp));
        } else {
            result.push_str(&format!("e-{:02}", -exp));
        }
        result
    }
}

fn trim_trailing_zeros_after_dot(s: &mut String) {
    if s.contains('.') {
        let trimmed = s.trim_end_matches('0').trim_end_matches('.');
        *s = trimmed.to_owned();
    }
}

// ── format_protoc_value ───────────────────────────────────────────────────────
//
// Mirrors `format_protoc_value()` in common.py.
// Returns `None` for fields that should be skipped (INVALID_*, packed repeats,
// untyped BYTES/message when handling is done as nested).
// `include_wire_types`: true for protoc, false for protoc_meticulous.

pub fn format_protoc_value(field: &ProtoTextField, include_wire_types: bool) -> Option<String> {
    match &field.content {
        // Always skip invalid fields
        ProtoTextContent::InvalidTagType(_)
        | ProtoTextContent::InvalidVarint(_)
        | ProtoTextContent::InvalidFixed64(_)
        | ProtoTextContent::InvalidFixed32(_)
        | ProtoTextContent::InvalidBytesLength(_)
        | ProtoTextContent::TruncatedBytes(_)
        | ProtoTextContent::InvalidPackedRecords(_)
        | ProtoTextContent::InvalidString(_)
        | ProtoTextContent::InvalidGroupEnd(_) => None,

        // Generic wire types: only in protoc (include_wire_types=true)
        ProtoTextContent::WireVarint(v) => {
            if include_wire_types {
                Some(format_wire_varint_protoc(*v))
            } else {
                None
            }
        }
        ProtoTextContent::WireFixed64(v) => {
            if include_wire_types {
                Some(format_wire_fixed64_protoc(*v))
            } else {
                None
            }
        }
        ProtoTextContent::WireFixed32(v) => {
            if include_wire_types {
                Some(format_wire_fixed32_protoc(*v))
            } else {
                None
            }
        }
        ProtoTextContent::WireBytes(b) => {
            if include_wire_types {
                Some(format!("\"{}\"", escape_bytes(b)))
            } else {
                None
            }
        }

        // Typed VARINT
        ProtoTextContent::Int64(v) => Some(format_int64_protoc(*v)),
        ProtoTextContent::Uint64(v) => Some(format_uint64_protoc(*v)),
        ProtoTextContent::Int32(v) => Some(format_int32_protoc(*v)),
        ProtoTextContent::Uint32(v) => Some(format_uint32_protoc(*v)),
        ProtoTextContent::Bool(v) => Some(format_bool_protoc(*v).to_owned()),
        ProtoTextContent::Enum(v) => Some(format_enum_protoc(*v)),
        ProtoTextContent::Sint32(v) => Some(format_sint32_protoc(*v)),
        ProtoTextContent::Sint64(v) => Some(format_sint64_protoc(*v)),

        // Typed FIXED64
        ProtoTextContent::Double(v) => Some(format_double_protoc(*v)),
        ProtoTextContent::PFixed64(v) => Some(format_fixed64_protoc(*v)),
        ProtoTextContent::Sfixed64(v) => Some(format_sfixed64_protoc(*v)),

        // Typed FIXED32
        ProtoTextContent::Float(v) => Some(format_float_protoc(*v)),
        ProtoTextContent::PFixed32(v) => Some(format_fixed32_protoc(*v)),
        ProtoTextContent::Sfixed32(v) => Some(format_sfixed32_protoc(*v)),

        // Length-delimited scalars
        ProtoTextContent::StringVal(s) => Some(format!("\"{}\"", escape_string(s))),
        ProtoTextContent::BytesVal(b) => Some(format!("\"{}\"", escape_bytes(b))),

        // Nested (handled as child block, not here)
        ProtoTextContent::MessageVal(_)
        | ProtoTextContent::Group(_)
        | ProtoTextContent::WireGroup(_) => None,

        // Packed repeated: render as "[val1, val2, ...]" (matching Python's protoc output)
        ProtoTextContent::Doubles(vs) => Some(format!(
            "[{}]",
            vs.iter()
                .map(|v| format_double_protoc(*v))
                .collect::<Vec<_>>()
                .join(", ")
        )),
        ProtoTextContent::Floats(vs) => Some(format!(
            "[{}]",
            vs.iter()
                .map(|v| format_float_protoc(*v))
                .collect::<Vec<_>>()
                .join(", ")
        )),
        ProtoTextContent::Int64s(vs) => Some(format!(
            "[{}]",
            vs.iter()
                .map(|v| format_int64_protoc(*v))
                .collect::<Vec<_>>()
                .join(", ")
        )),
        ProtoTextContent::Uint64s(vs) => Some(format!(
            "[{}]",
            vs.iter()
                .map(|v| format_uint64_protoc(*v))
                .collect::<Vec<_>>()
                .join(", ")
        )),
        ProtoTextContent::Int32s(vs) => Some(format!(
            "[{}]",
            vs.iter()
                .map(|v| format_int32_protoc(*v))
                .collect::<Vec<_>>()
                .join(", ")
        )),
        ProtoTextContent::Fixed64s(vs) => Some(format!(
            "[{}]",
            vs.iter()
                .map(|v| format_fixed64_protoc(*v))
                .collect::<Vec<_>>()
                .join(", ")
        )),
        ProtoTextContent::Fixed32s(vs) => Some(format!(
            "[{}]",
            vs.iter()
                .map(|v| format_fixed32_protoc(*v))
                .collect::<Vec<_>>()
                .join(", ")
        )),
        ProtoTextContent::Bools(vs) => Some(format!(
            "[{}]",
            vs.iter()
                .map(|v| format_bool_protoc(*v))
                .collect::<Vec<_>>()
                .join(", ")
        )),
        ProtoTextContent::Uint32s(vs) => Some(format!(
            "[{}]",
            vs.iter()
                .map(|v| format_uint32_protoc(*v))
                .collect::<Vec<_>>()
                .join(", ")
        )),
        ProtoTextContent::Enums(vs) => Some(format!(
            "[{}]",
            vs.iter()
                .map(|v| format_enum_protoc(*v))
                .collect::<Vec<_>>()
                .join(", ")
        )),
        ProtoTextContent::Sfixed32s(vs) => Some(format!(
            "[{}]",
            vs.iter()
                .map(|v| format_sfixed32_protoc(*v))
                .collect::<Vec<_>>()
                .join(", ")
        )),
        ProtoTextContent::Sfixed64s(vs) => Some(format!(
            "[{}]",
            vs.iter()
                .map(|v| format_sfixed64_protoc(*v))
                .collect::<Vec<_>>()
                .join(", ")
        )),
        ProtoTextContent::Sint32s(vs) => Some(format!(
            "[{}]",
            vs.iter()
                .map(|v| format_sint32_protoc(*v))
                .collect::<Vec<_>>()
                .join(", ")
        )),
        ProtoTextContent::Sint64s(vs) => Some(format!(
            "[{}]",
            vs.iter()
                .map(|v| format_sint64_protoc(*v))
                .collect::<Vec<_>>()
                .join(", ")
        )),

        ProtoTextContent::Unset => None,
    }
}

// ── is_nested / is_invalid helpers ───────────────────────────────────────────

#[inline]
pub fn is_nested(content: &ProtoTextContent) -> bool {
    matches!(
        content,
        ProtoTextContent::MessageVal(_)
            | ProtoTextContent::Group(_)
            | ProtoTextContent::WireGroup(_)
    )
}

#[inline]
pub fn is_invalid(content: &ProtoTextContent) -> bool {
    matches!(
        content,
        ProtoTextContent::InvalidTagType(_)
            | ProtoTextContent::InvalidVarint(_)
            | ProtoTextContent::InvalidFixed64(_)
            | ProtoTextContent::InvalidFixed32(_)
            | ProtoTextContent::InvalidBytesLength(_)
            | ProtoTextContent::TruncatedBytes(_)
            | ProtoTextContent::InvalidPackedRecords(_)
            | ProtoTextContent::InvalidString(_)
            | ProtoTextContent::InvalidGroupEnd(_)
    )
}

// ── Modifier lines ────────────────────────────────────────────────────────────
//
// Mirrors `get_modifier_strings(include_type=True)` in common.py.

pub struct Modifier {
    pub text: String,
}

pub fn get_modifiers(field: &ProtoTextField) -> Vec<Modifier> {
    let mut out = Vec::new();

    if let Some(v) = field.tag_overhang_count {
        out.push(Modifier {
            text: format!("tag_overhang_count: {}", v),
        });
    }
    if field.tag_is_out_of_range {
        out.push(Modifier {
            text: "tag_is_out_of_range: true".to_owned(),
        });
    }
    if let Some(v) = field.value_overhang_count {
        out.push(Modifier {
            text: format!("value_overhang_count: {}", v),
        });
    }
    if let Some(v) = field.length_overhang_count {
        out.push(Modifier {
            text: format!("length_overhang_count: {}", v),
        });
    }
    if let Some(v) = field.missing_bytes_count {
        out.push(Modifier {
            text: format!("missing_bytes_count: {}", v),
        });
    }
    if let Some(v) = field.mismatched_group_end {
        out.push(Modifier {
            text: format!("mismatched_group_end: {}", v),
        });
    }
    if field.open_ended_group {
        out.push(Modifier {
            text: "open_ended_group: true".to_owned(),
        });
    }
    if let Some(v) = field.end_tag_overhang_count {
        out.push(Modifier {
            text: format!("end_tag_overhang_count: {}", v),
        });
    }
    if field.end_tag_is_out_of_range {
        out.push(Modifier {
            text: "end_tag_is_out_of_range: true".to_owned(),
        });
    }
    if field.proto2_has_type_mismatch {
        out.push(Modifier {
            text: "proto2_has_type_mismatch: true".to_owned(),
        });
    }
    if !field.records_overhung_count.is_empty() {
        let vals: Vec<String> = field
            .records_overhung_count
            .iter()
            .map(|v| v.to_string())
            .collect();
        out.push(Modifier {
            text: format!("records_overhung_count: [{}]", vals.join(", ")),
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── format_double_protoc — negative-exponent decimal form ─────────────────
    //
    // Regression for capacity-overflow panic in rust_sci_to_g_style.
    // Values with |v| ∈ [1e-4, 1e-2) have exponents -4, -3, -2.  Before the
    // fix, `decimal_pos = (exp + 1) as usize` wrapped a negative i32 to
    // near-usize::MAX, making `.repeat()` panic with a capacity overflow.

    #[test]
    fn double_protoc_exp_minus4() {
        // exp = -4 was the deepest broken case (decimal_pos → usize::MAX - 2).
        assert_eq!(format_double_protoc(1e-4_f64), "0.0001");
        assert_eq!(format_double_protoc(-1e-4_f64), "-0.0001");
        assert_eq!(format_double_protoc(5.5e-4_f64), "0.00055");
    }

    #[test]
    fn double_protoc_exp_minus3() {
        assert_eq!(format_double_protoc(1e-3_f64), "0.001");
        assert_eq!(format_double_protoc(-1.5e-3_f64), "-0.0015");
    }

    #[test]
    fn double_protoc_exp_minus2() {
        assert_eq!(format_double_protoc(1e-2_f64), "0.01");
        assert_eq!(format_double_protoc(3.75e-2_f64), "0.0375");
    }

    // ── Adjacent exponents that were always correct (boundary sanity) ─────────

    #[test]
    fn double_protoc_exp_minus1() {
        assert_eq!(format_double_protoc(1e-1_f64), "0.1");
        assert_eq!(format_double_protoc(2.5e-1_f64), "0.25");
    }

    #[test]
    fn double_protoc_exp_zero_and_positive() {
        assert_eq!(format_double_protoc(1.0_f64), "1");
        assert_eq!(format_double_protoc(1.5_f64), "1.5");
        assert_eq!(format_double_protoc(123.456_f64), "123.456");
    }

    #[test]
    fn double_protoc_scientific_below_threshold() {
        // exp = -5: below the -4 threshold, stays in scientific form.
        assert_eq!(format_double_protoc(1e-5_f64), "1e-05");
    }

    #[test]
    fn double_protoc_special_values() {
        assert_eq!(format_double_protoc(f64::NAN), "nan");
        assert_eq!(format_double_protoc(f64::INFINITY), "inf");
        assert_eq!(format_double_protoc(f64::NEG_INFINITY), "-inf");
    }

    // ── format_float_protoc — same broken range applies to f32 ────────────────

    #[test]
    fn float_protoc_exp_minus4() {
        assert_eq!(format_float_protoc(1e-4_f32), "0.0001");
        assert_eq!(format_float_protoc(5.5e-4_f32), "0.00055");
    }

    #[test]
    fn float_protoc_exp_minus3() {
        assert_eq!(format_float_protoc(1.5e-3_f32), "0.0015");
    }

    #[test]
    fn float_protoc_exp_minus2() {
        assert_eq!(format_float_protoc(1e-2_f32), "0.01");
    }
}
