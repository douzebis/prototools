// SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

//! Any-field expansion for `google.protobuf.Any` (spec 0089).

use std::sync::Arc;

use prost_reflect::MessageDescriptor;

use super::super::{
    enter_level, render_message, FieldOrExt, ANNOTATIONS, ANY_LOADER, CBL_START, EXPAND_ANY,
};
use super::annotations::{push_tag_modifiers, AnnWriter};
use super::output::{push_indent, wob_prefix_n, write_close_brace};

use crate::helpers::{
    parse_varint, parse_wiretag, WT_I32, WT_I64, WT_LEN, WT_START_GROUP, WT_VARINT,
};
use crate::serialize::common::escape_string_into;

// ── Wire scan helper ──────────────────────────────────────────────────────────

/// Minimal scan result from a flat `Any` payload.
struct AnyFields<'a> {
    type_url: &'a str,
    value: Option<&'a [u8]>,
}

/// Scan `data` for field 1 (type_url string) and field 2 (value bytes).
/// Returns `None` if the payload cannot be scanned, type_url is absent/empty,
/// or if value appeared before type_url.
fn scan_any_fields(data: &[u8]) -> Option<AnyFields<'_>> {
    let mut pos = 0;
    let buflen = data.len();

    let mut type_url: Option<&str> = None;
    let mut value: Option<&[u8]> = None;
    let mut value_before_type_url = false;

    while pos < buflen {
        let tag = parse_wiretag(data, pos);
        if tag.wtag_gar.is_some() {
            return None;
        }
        let field_number = tag.wfield.unwrap();
        let wire_type = tag.wtype.unwrap();
        pos = tag.next_pos;

        match wire_type {
            WT_VARINT => {
                let vr = parse_varint(data, pos);
                if vr.varint_gar.is_some() {
                    return None;
                }
                pos = vr.next_pos;
            }
            WT_I64 => {
                if pos + 8 > buflen {
                    return None;
                }
                pos += 8;
            }
            WT_LEN => {
                let lr = parse_varint(data, pos);
                if lr.varint_gar.is_some() {
                    return None;
                }
                pos = lr.next_pos;
                let len = lr.varint.unwrap() as usize;
                if pos + len > buflen {
                    return None;
                }
                let payload = &data[pos..pos + len];
                pos += len;
                match field_number {
                    1 => {
                        // type_url
                        let s = std::str::from_utf8(payload).ok()?;
                        if s.is_empty() {
                            return None;
                        }
                        type_url = Some(s);
                    }
                    2 => {
                        // value bytes
                        if type_url.is_none() {
                            value_before_type_url = true;
                        }
                        value = Some(payload);
                    }
                    _ => {}
                }
            }
            WT_START_GROUP => {
                // skip blindly
                pos = skip_group(data, pos, field_number)?;
            }
            WT_I32 => {
                if pos + 4 > buflen {
                    return None;
                }
                pos += 4;
            }
            _ => return None,
        }
    }

    if value_before_type_url {
        return None;
    }
    let type_url = type_url?;
    Some(AnyFields { type_url, value })
}

/// Blind group skip: consume bytes until matching END_GROUP for `expected_field`.
fn skip_group(buf: &[u8], mut pos: usize, expected_field: u64) -> Option<usize> {
    let buflen = buf.len();
    loop {
        if pos == buflen {
            return None;
        }
        let tag = parse_wiretag(buf, pos);
        if tag.wtag_gar.is_some() {
            return None;
        }
        let field_number = tag.wfield.unwrap();
        let wire_type = tag.wtype.unwrap();
        pos = tag.next_pos;
        match wire_type {
            WT_VARINT => {
                let vr = parse_varint(buf, pos);
                if vr.varint_gar.is_some() {
                    return None;
                }
                pos = vr.next_pos;
            }
            WT_I64 => {
                if pos + 8 > buflen {
                    return None;
                }
                pos += 8;
            }
            WT_LEN => {
                let lr = parse_varint(buf, pos);
                if lr.varint_gar.is_some() {
                    return None;
                }
                pos = lr.next_pos;
                let len = lr.varint.unwrap() as usize;
                if pos + len > buflen {
                    return None;
                }
                pos += len;
            }
            WT_START_GROUP => {
                pos = skip_group(buf, pos, field_number)?;
            }
            4 /* WT_END_GROUP */ => {
                if field_number != expected_field {
                    return None;
                }
                return Some(pos);
            }
            WT_I32 => {
                if pos + 4 > buflen {
                    return None;
                }
                pos += 4;
            }
            _ => return None,
        }
    }
}

// ── Public entry point ────────────────────────────────────────────────────────

/// Try to render a `google.protobuf.Any` field with expansion.
///
/// Called in place of the normal `wob_prefix_n + render_message + write_close_brace`
/// sequence in `render_len_field` when:
/// - `EXPAND_ANY` is true, and
/// - the field's schema type is `google.protobuf.Any`.
///
/// Returns `true` when expansion was performed (caller must return immediately).
/// Returns `false` when expansion is not possible (caller falls through to
/// normal rendering).
#[allow(clippy::too_many_arguments)]
pub(in super::super) fn render_any_expansion(
    field_number: u64,
    fs: &FieldOrExt,
    schema_present: bool,
    tag_ohb: Option<u64>,
    tag_oor: bool,
    len_ohb: Option<u64>,
    data: &[u8],
    out: &mut Vec<u8>,
) -> bool {
    if !EXPAND_ANY.with(|c| c.get()) {
        return false;
    }

    let fields = match scan_any_fields(data) {
        Some(f) => f,
        None => return false,
    };

    // Resolve FQDN from type_url: segment after last '/'.
    let fqdn = if let Some(slash) = fields.type_url.rfind('/') {
        &fields.type_url[slash + 1..]
    } else {
        fields.type_url
    };

    // JIT-load via ANY_LOADER (spec 0099); re-derives fresh from the
    // canonical pool on every call, never caches a value across calls
    // (spec 0106 S2 — the `all_schemas` snapshot fast path is gone).
    let resolved_desc: Option<Arc<MessageDescriptor>> =
        ANY_LOADER.with(|l| l.borrow_mut().as_mut().and_then(|f| f(fqdn)));
    let resolved_desc = match resolved_desc {
        Some(d) => d,
        None => return false,
    };

    let annotations = ANNOTATIONS.with(|c| c.get());

    // ── Step 5: write the Any field opener ────────────────────────────────────
    wob_prefix_n(field_number, Some(fs), false, out);
    if annotations {
        let mut aw = AnnWriter::new();
        aw.push_field_decl(out, field_number, Some(fs), None, None);
        push_tag_modifiers(&mut aw, out, tag_ohb, tag_oor, len_ohb);
    }
    out.push(b'\n');
    CBL_START.with(|c| c.set(out.len()));

    // ── Step 6: enter indentation level ──────────────────────────────────────
    let outer_guard = enter_level();

    // ── Step 7: write type_url line ───────────────────────────────────────────
    push_indent(out);
    out.extend_from_slice(b"type_url: \"");
    escape_string_into(fields.type_url, out);
    out.push(b'"');
    if annotations {
        let mut aw = AnnWriter::new();
        aw.push(out, b"string = 1");
    }
    out.push(b'\n');
    CBL_START.with(|c| c.set(out.len()));

    // ── Step 8: write value { opener ──────────────────────────────────────────
    push_indent(out);
    out.extend_from_slice(b"value {");
    if annotations {
        let mut aw = AnnWriter::new();
        aw.sep(out);
        out.extend_from_slice(resolved_desc.name().as_bytes());
        out.extend_from_slice(b" = 2");
    }
    out.push(b'\n');
    CBL_START.with(|c| c.set(out.len()));

    // ── Steps 9–10: recurse into value bytes ──────────────────────────────────
    {
        let inner_guard = enter_level();
        let value_bytes: &[u8] = fields.value.unwrap_or(&[]);
        render_message(
            value_bytes,
            0,
            None,
            Some(&*resolved_desc),
            schema_present,
            out,
        );
        drop(inner_guard); // decrement LEVEL before write_close_brace for value
    }

    // ── Step 11: close value block ────────────────────────────────────────────
    write_close_brace(out);

    // ── Step 12: close Any block ──────────────────────────────────────────────
    // Drop outer_guard to decrement LEVEL back to the Any field's level before
    // writing the closing brace.
    drop(outer_guard);
    write_close_brace(out);

    true
}
