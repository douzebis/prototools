// SPDX-FileCopyrightText: 2025-2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
// SPDX-FileCopyrightText: 2025-2026 Thales Cloud Sécurisé
//
// SPDX-License-Identifier: MIT

mod helpers;
mod packed;
mod varint;

use std::cell::Cell;
use std::collections::HashMap;
use std::sync::Arc;

use crate::helpers::{
    decode_double, decode_fixed32, decode_fixed64, decode_float, decode_sfixed32, decode_sfixed64,
};
use crate::helpers::{
    parse_varint, parse_wiretag, WiretagResult, WT_END_GROUP, WT_I32, WT_I64, WT_LEN,
    WT_START_GROUP, WT_VARINT,
};
use crate::schema::{proto_type as pt, FieldInfo, MessageSchema, ParsedSchema};
use crate::serialize::common::{
    format_double_protoc, format_fixed32_protoc, format_fixed64_protoc, format_float_protoc,
    format_sfixed32_protoc, format_sfixed64_protoc, format_wire_fixed32_protoc,
    format_wire_fixed64_protoc,
};

use helpers::{
    render_group_field, render_invalid, render_invalid_tag_type, render_len_field, render_scalar,
    render_truncated_bytes,
};
use varint::{decode_varint_typed, render_varint_field, VarintKind};

// Magic prefix that identifies a textual prototext payload.
const PROTOTEXT_MAGIC: &[u8] = b"#@ prototext:";

// ── Render-mode state ─────────────────────────────────────────────────────────
//
// `CBL_START` tracks the byte offset of the start of the most recently started
// output line.  It is used by `write_close_brace` to fold consecutive `}`
// lines into one.
//
// Update discipline (key to correctness):
//   - Non-close-brace writes: set `CBL_START = out.len()` **after** `out.push(b'\n')`.
//     This puts `CBL_START` past the end of `out`, so the bounds check in
//     `write_close_brace` always fails → no spurious folding.
//   - Fresh close-brace write: set `CBL_START = out.len()` **before** writing
//     the `}\n` line, so `CBL_START` points to the start of that line and the
//     next close-brace can patch it.
//   - Folded close-brace write: do **not** update `CBL_START` — it still
//     points to the close-brace line being extended.
//
thread_local! {
    pub(super) static CBL_START:    Cell<usize> = const { Cell::new(0) };
    // Set once per `decode_and_render` call; read by every internal render fn.
    pub(super) static ANNOTATIONS:  Cell<bool>  = const { Cell::new(false) };
    pub(super) static INDENT_SIZE:  Cell<usize> = const { Cell::new(2) };
    // Tracks recursion depth; managed via `enter_level()` / `LevelGuard`.
    pub(super) static LEVEL:        Cell<usize> = const { Cell::new(0) };
}

/// RAII guard for `LEVEL`: increments on construction, decrements on drop.
/// Guarantees the level is restored even if the callee panics.
pub(super) struct LevelGuard;

impl Drop for LevelGuard {
    fn drop(&mut self) {
        LEVEL.with(|l| l.set(l.get() - 1));
    }
}

pub(super) fn enter_level() -> LevelGuard {
    LEVEL.with(|l| l.set(l.get() + 1));
    LevelGuard
}

/// Return `true` when `data` is already rendered prototext text (fast-path).
pub fn is_prototext_text(data: &[u8]) -> bool {
    data.starts_with(PROTOTEXT_MAGIC)
}

// ── Public entry point ────────────────────────────────────────────────────────

/// Decode raw protobuf binary and render as protoc-style text in one pass.
///
/// Writes the `#@ prototext: protoc\n` header followed by field lines directly
/// into a pre-allocated `Vec<u8>`.
///
/// Parameters mirror `format_as_text` in `lib.rs`.
pub fn decode_and_render(
    buf: &[u8],
    schema: Option<&ParsedSchema>,
    annotations: bool,
    indent_size: usize,
) -> Vec<u8> {
    let capacity = buf.len() * 8;
    let mut out = Vec::with_capacity(capacity);

    // Header
    out.extend_from_slice(b"#@ prototext: protoc\n");
    // Initialise render-mode state.
    // CBL_START past the end so the first write_close_brace always takes
    // the fresh-write path.
    CBL_START.with(|c| c.set(out.len()));
    ANNOTATIONS.with(|c| c.set(annotations));
    INDENT_SIZE.with(|c| c.set(indent_size));
    LEVEL.with(|c| c.set(0));

    // Hold Arc to keep root MessageSchema alive for the duration of this call.
    let root_arc: Option<Arc<MessageSchema>> = schema.and_then(|s| s.root_schema());
    let root_ref: Option<&MessageSchema> = root_arc.as_deref();

    let all_schemas: Option<&HashMap<String, Arc<MessageSchema>>> =
        schema.map(|s| s.all_schemas.as_ref());

    render_message(buf, 0, None, root_ref, all_schemas, &mut out);

    // Development instrumentation — truncate event
    #[cfg(debug_assertions)]
    {
        let actual = out.len();
        if actual < capacity {
            eprintln!(
                "[render_text] truncate: input_len={} capacity={} actual={} ratio={:.2}x",
                buf.len(),
                capacity,
                actual,
                actual as f64 / buf.len().max(1) as f64
            );
        }
    }

    out
}

// ── Core recursive render-while-decode ───────────────────────────────────────

/// Parse and render one protobuf message into `out`.
///
/// Returns `(next_pos, group_end_tag)`:
/// - `next_pos`: byte position after this message (for the caller to
///   continue its own parse loop, or for GROUP end detection).
/// - `group_end_tag`: `Some(tag)` when parsing terminated on a `WT_END_GROUP`.
pub(super) fn render_message(
    buf: &[u8],
    start: usize,
    my_group: Option<u64>,
    schema: Option<&MessageSchema>,
    all_schemas: Option<&HashMap<String, Arc<MessageSchema>>>,
    out: &mut Vec<u8>,
) -> (usize, Option<WiretagResult>) {
    let buflen = buf.len();
    let mut pos = start;

    loop {
        if pos == buflen {
            return (pos, None);
        }

        // ── Parse wire tag ────────────────────────────────────────────────────

        let tag = parse_wiretag(buf, pos);

        if let Some(ref wtag_gar) = tag.wtag_gar {
            // Invalid wire tag: consume rest of buffer as INVALID_TAG_TYPE
            render_invalid_tag_type(wtag_gar, out);
            return (buflen, None);
        }

        let field_number = tag.wfield.unwrap();
        let wire_type = tag.wtype.unwrap();
        let tag_ohb = tag.wfield_ohb;
        let tag_oor = tag.wfield_oor.is_some();
        pos = tag.next_pos;

        // ── Schema lookup ─────────────────────────────────────────────────────

        let field_schema: Option<&FieldInfo> =
            schema.and_then(|s| s.fields.get(&(field_number as u32)));

        // ── Wire-type dispatch ────────────────────────────────────────────────

        match wire_type {
            // ── VARINT ───────────────────────────────────────────────────────
            WT_VARINT => {
                let vr = parse_varint(buf, pos);
                if let Some(ref varint_gar) = vr.varint_gar {
                    render_invalid(
                        field_number,
                        field_schema,
                        tag_ohb,
                        tag_oor,
                        "INVALID_VARINT",
                        varint_gar,
                        out,
                    );
                    return (buflen, None);
                }
                pos = vr.next_pos;
                let val_ohb = vr.varint_ohb;
                let val = vr.varint.unwrap();

                let (content_kind, typed_val) = if let Some(fs) = field_schema {
                    decode_varint_typed(val, fs)
                } else {
                    (VarintKind::Wire, val)
                };

                render_varint_field(
                    field_number,
                    field_schema,
                    tag_ohb,
                    tag_oor,
                    val_ohb,
                    content_kind,
                    typed_val,
                    out,
                );
            }

            // ── FIXED64 ──────────────────────────────────────────────────────
            WT_I64 => {
                if pos + 8 > buflen {
                    let raw = &buf[pos..];
                    render_invalid(
                        field_number,
                        field_schema,
                        tag_ohb,
                        tag_oor,
                        "INVALID_FIXED64",
                        raw,
                        out,
                    );
                    return (buflen, None);
                }
                let data = &buf[pos..pos + 8];
                pos += 8;

                let is_mismatch;
                let value_str = if let Some(fs) = field_schema {
                    match fs.proto_type {
                        pt::DOUBLE => {
                            is_mismatch = false;
                            format_double_protoc(decode_double(data))
                        }
                        pt::FIXED64 => {
                            is_mismatch = false;
                            format_fixed64_protoc(decode_fixed64(data))
                        }
                        pt::SFIXED64 => {
                            is_mismatch = false;
                            format_sfixed64_protoc(decode_sfixed64(data))
                        }
                        _ => {
                            is_mismatch = true;
                            format_wire_fixed64_protoc(decode_fixed64(data))
                        } // mismatch → hex
                    }
                } else {
                    is_mismatch = false;
                    format_wire_fixed64_protoc(decode_fixed64(data)) // unknown → hex
                };

                render_scalar(
                    field_number,
                    field_schema,
                    tag_ohb,
                    tag_oor,
                    None,
                    "fixed64",
                    &value_str,
                    is_mismatch,
                    out,
                );
            }

            // ── LENGTH-DELIMITED ─────────────────────────────────────────────
            WT_LEN => {
                let lr = parse_varint(buf, pos);
                if let Some(ref varint_gar) = lr.varint_gar {
                    render_invalid(
                        field_number,
                        field_schema,
                        tag_ohb,
                        tag_oor,
                        "INVALID_LEN",
                        varint_gar,
                        out,
                    );
                    return (buflen, None);
                }
                let len_ohb = lr.varint_ohb;
                pos = lr.next_pos;
                let length = lr.varint.unwrap() as usize;

                if pos + length > buflen {
                    let missing = (length - (buflen - pos)) as u64;
                    let raw = &buf[pos..];
                    render_truncated_bytes(
                        field_number,
                        tag_ohb,
                        tag_oor,
                        len_ohb,
                        missing,
                        raw,
                        out,
                    );
                    return (buflen, None);
                }
                let data = &buf[pos..pos + length];
                pos += length;

                render_len_field(
                    field_number,
                    field_schema,
                    all_schemas,
                    tag_ohb,
                    tag_oor,
                    len_ohb,
                    data,
                    out,
                );
            }

            // ── START GROUP ──────────────────────────────────────────────────
            WT_START_GROUP => {
                render_group_field(
                    buf,
                    &mut pos,
                    field_number,
                    field_schema,
                    all_schemas,
                    tag_ohb,
                    tag_oor,
                    out,
                );
            }

            // ── END GROUP ────────────────────────────────────────────────────
            WT_END_GROUP => {
                if my_group.is_none() {
                    // Unexpected END_GROUP outside a group
                    let raw = &buf[pos..];
                    render_invalid(
                        field_number,
                        field_schema,
                        tag_ohb,
                        tag_oor,
                        "INVALID_GROUP_END",
                        raw,
                        out,
                    );
                    return (buflen, None);
                }
                // Valid END_GROUP: return to parent without rendering a field.
                return (pos, Some(tag));
            }

            // ── FIXED32 ──────────────────────────────────────────────────────
            WT_I32 => {
                if pos + 4 > buflen {
                    let raw = &buf[pos..];
                    render_invalid(
                        field_number,
                        field_schema,
                        tag_ohb,
                        tag_oor,
                        "INVALID_FIXED32",
                        raw,
                        out,
                    );
                    return (buflen, None);
                }
                let data = &buf[pos..pos + 4];
                pos += 4;

                let is_mismatch;
                let value_str = if let Some(fs) = field_schema {
                    match fs.proto_type {
                        pt::FLOAT => {
                            is_mismatch = false;
                            format_float_protoc(decode_float(data))
                        }
                        pt::FIXED32 => {
                            is_mismatch = false;
                            format_fixed32_protoc(decode_fixed32(data))
                        }
                        pt::SFIXED32 => {
                            is_mismatch = false;
                            format_sfixed32_protoc(decode_sfixed32(data))
                        }
                        _ => {
                            is_mismatch = true;
                            format_wire_fixed32_protoc(decode_fixed32(data))
                        } // mismatch → hex (D2)
                    }
                } else {
                    is_mismatch = false;
                    format_wire_fixed32_protoc(decode_fixed32(data)) // unknown → hex
                };

                render_scalar(
                    field_number,
                    field_schema,
                    tag_ohb,
                    tag_oor,
                    None,
                    "fixed32",
                    &value_str,
                    is_mismatch,
                    out,
                );
            }

            _ => unreachable!("wire type > 5 caught by parse_wiretag"),
        }
    }
}

// ── Unit tests ────────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use crate::{parse_schema, render_as_bytes, render_as_text, RenderOpts};

    fn load_schema(name: &str, msg: &str) -> crate::ParsedSchema {
        let path = std::path::Path::new(env!("OUT_DIR")).join(name);
        let bytes = std::fs::read(&path).unwrap();
        parse_schema(&bytes, msg).unwrap()
    }

    fn enum_schema() -> crate::ParsedSchema {
        load_schema("enum_collision.pb", "EnumCollision")
    }

    fn opts(annotations: bool) -> RenderOpts {
        RenderOpts::new(true, annotations, 1)
    }

    // ── §7.1 Symbolic enum lookup — known value ───────────────────────────────

    #[test]
    fn enum_known_value_renders_symbolic_name() {
        // EnumCollision field 2 'color' (Color enum): wire value 1 = GREEN.
        // Tag: field 2, wire type varint = 0x10. Value: 0x01.
        let wire = vec![0x10, 0x01];
        let schema = enum_schema();
        let text = render_as_text(&wire, Some(&schema), opts(true)).unwrap();
        let text_str = String::from_utf8(text).unwrap();
        // Value token should be the symbolic name GREEN.
        assert!(
            text_str.contains("GREEN"),
            "expected symbolic name GREEN in: {text_str}"
        );
        // Annotation should contain Color(1).
        assert!(
            text_str.contains("Color(1)"),
            "expected Color(1) in annotation: {text_str}"
        );
    }

    // ── §7.2 Symbolic enum lookup — unknown value ─────────────────────────────

    #[test]
    fn enum_unknown_value_renders_numeric_with_enum_unknown() {
        // EnumCollision field 2 'color' (Color enum): wire value 99 — not in enum.
        let wire = vec![0x10, 0x63]; // field 2 varint, value 99
        let schema = enum_schema();
        let text = render_as_text(&wire, Some(&schema), opts(true)).unwrap();
        let text_str = String::from_utf8(text).unwrap();
        // Value token should be the raw numeric.
        assert!(
            text_str.contains("99"),
            "expected numeric 99 in: {text_str}"
        );
        // Annotation should contain ENUM_UNKNOWN.
        assert!(
            text_str.contains("ENUM_UNKNOWN"),
            "expected ENUM_UNKNOWN in annotation: {text_str}"
        );
    }

    // ── §7.3 Packed enum — symbolic names + annotation ────────────────────────

    #[test]
    fn packed_enum_renders_symbolic_names() {
        // EnumCollision field 5 'colors_pk' (repeated Color, packed).
        // Tag: field 5, wire type LEN = (5<<3)|2 = 0x2A. Payload: varint 1 (GREEN), varint 2 (BLUE).
        let wire = vec![0x2A, 0x02, 0x01, 0x02]; // tag, len=2, GREEN=1, BLUE=2
        let schema = enum_schema();
        let text = render_as_text(&wire, Some(&schema), opts(true)).unwrap();
        let text_str = String::from_utf8(text).unwrap();
        assert!(
            text_str.contains("GREEN"),
            "expected GREEN in packed: {text_str}"
        );
        assert!(
            text_str.contains("BLUE"),
            "expected BLUE in packed: {text_str}"
        );
        // Annotation should contain Color([1, 2]).
        assert!(
            text_str.contains("Color([1, 2])"),
            "expected Color([1, 2]) in annotation: {text_str}"
        );
    }

    // ── §7.4 Enum annotation roundtrip ───────────────────────────────────────

    #[test]
    fn enum_annotation_roundtrips_wire() {
        // EnumCollision field 2 'color' = GREEN (1).
        let wire = vec![0x10, 0x01];
        let schema = enum_schema();
        let text = render_as_text(&wire, Some(&schema), opts(true)).unwrap();
        let wire2 = render_as_bytes(&text, opts(true)).unwrap();
        assert_eq!(wire2, wire, "enum annotation must round-trip byte-for-byte");
    }

    // ── §7.5 No-annotations mode ──────────────────────────────────────────────

    #[test]
    fn no_annotations_omits_unknown_fields() {
        // Unknown field (no schema): wire type varint, field 99.
        let wire = vec![0xb8, 0x06, 0x01]; // field 99, varint, value 1
        let schema = enum_schema();
        let text = render_as_text(&wire, Some(&schema), opts(false)).unwrap();
        let text_str = String::from_utf8(text).unwrap();
        // Without annotations, unknown fields are omitted.
        assert!(
            !text_str.contains("99"),
            "unknown field should be omitted without annotations: {text_str}"
        );
    }

    // ── §7.6 Enum named `float` — wire encoding ───────────────────────────────

    #[test]
    fn enum_named_float_roundtrip_is_varint() {
        // EnumCollision field 1 'kind' (enum float): value 1 = FLOAT_ONE.
        // Wire: tag field 1 varint = 0x08, value 0x01. Total 2 bytes.
        let wire = vec![0x08, 0x01];
        let schema = enum_schema();
        let text = render_as_text(&wire, Some(&schema), opts(true)).unwrap();
        let wire2 = render_as_bytes(&text, opts(true)).unwrap();
        assert_eq!(
            wire2, wire,
            "enum named 'float' must round-trip as varint (2 bytes), not fixed32 (5 bytes)"
        );
        assert_eq!(
            wire2.len(),
            2,
            "re-encoded wire must be 2 bytes (varint), not 5 (fixed32)"
        );
    }
}
