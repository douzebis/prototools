// SPDX-FileCopyrightText: 2025-2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
// SPDX-FileCopyrightText: 2025-2026 THALES CLOUD SECURISE SAS
//
// SPDX-License-Identifier: MIT

use prost_reflect::{Cardinality, Kind, MessageDescriptor};

use super::super::{
    enter_level, render_message, FieldOrExt, ANNOTATIONS, CBL_START, EXPAND_ANY,
    EXPAND_MESSAGE_SET, HIDE_UNKNOWN,
};
use super::annotations::{field_decl, push_tag_modifiers, AnnWriter};
use super::any_field::render_any_expansion;
use super::message_set_field::{is_message_set, render_message_set_expansion};
use super::output::{wfl_prefix_n, wob_prefix_n, write_close_brace, write_dec_u64};
use super::scalar::render_invalid;

use crate::serialize::common::{escape_bytes_into, escape_string_into};

use super::super::packed::render_packed;

/// Render a length-delimited field (string, bytes, message, packed, wire-bytes).
#[allow(clippy::too_many_arguments)]
pub(in super::super) fn render_len_field(
    field_number: u64,
    field_schema: Option<&FieldOrExt>,
    schema_present: bool,
    tag_ohb: Option<u64>,
    tag_oor: bool,
    len_ohb: Option<u64>,
    data: &[u8],
    out: &mut Vec<u8>,
) {
    let annotations = ANNOTATIONS.with(|c| c.get());
    let Some(fs) = field_schema else {
        // Unknown LEN field: three-step cascade (spec 0097).
        //
        // When no descriptor is active, every field is unknown — suppress
        // nothing regardless of hide_unknown_fields (spec 0097 S5).
        // When a descriptor is active but this field number is absent, honour
        // hide_unknown_fields (spec 0103).
        let hide_unknown = HIDE_UNKNOWN.with(|c| c.get());
        if hide_unknown && schema_present {
            return;
        }

        // Step 1: probe as nested message.  Parse with no schema; rendering
        // failures inside the nested message do not affect this probe.
        let empty_schema = crate::schema::ParsedSchema::empty();
        let (_, next_pos, _, malformities) =
            crate::decoder::parse_message(data, 0, None, None, &empty_schema, false);
        if malformities == 0 && next_pos == data.len() {
            wob_prefix_n(field_number, None, true, out);
            if annotations {
                let mut aw = AnnWriter::new();
                aw.push_wire(out, "message");
                push_tag_modifiers(&mut aw, out, tag_ohb, tag_oor, len_ohb);
            }
            out.push(b'\n');
            CBL_START.with(|c| c.set(out.len()));
            {
                let _guard = enter_level();
                render_message(data, 0, None, None, schema_present, out);
            }
            write_close_brace(out);
            return;
        }
        // Step 2: try UTF-8 string.
        if let Ok(s) = std::str::from_utf8(data) {
            wfl_prefix_n(field_number, None, true, out);
            out.push(b'"');
            escape_string_into(s, out);
            out.push(b'"');
            if annotations {
                let mut aw = AnnWriter::new();
                aw.push_wire(out, "string");
                push_tag_modifiers(&mut aw, out, tag_ohb, tag_oor, len_ohb);
            }
            out.push(b'\n');
            CBL_START.with(|c| c.set(out.len()));
            return;
        }
        // Step 3: raw bytes.
        wfl_prefix_n(field_number, None, true, out);
        out.push(b'"');
        escape_bytes_into(data, out);
        out.push(b'"');
        if annotations {
            let mut aw = AnnWriter::new();
            aw.push_wire(out, "bytes");
            push_tag_modifiers(&mut aw, out, tag_ohb, tag_oor, len_ohb);
        }
        out.push(b'\n');
        CBL_START.with(|c| c.set(out.len()));
        return;
    };

    let is_repeated = fs.cardinality() == Cardinality::Repeated;

    // ── Packed repeated ───────────────────────────────────────────────────────
    let is_packable_kind = matches!(
        fs.kind(),
        Kind::Bool
            | Kind::Int32
            | Kind::Int64
            | Kind::Uint32
            | Kind::Uint64
            | Kind::Sint32
            | Kind::Sint64
            | Kind::Fixed32
            | Kind::Fixed64
            | Kind::Sfixed32
            | Kind::Sfixed64
            | Kind::Float
            | Kind::Double
            | Kind::Enum(_)
    );
    // Determine whether this LEN record encodes a packed repeated field.
    //
    // Normally we trust prost-reflect's precomputed `is_packed()`.  However,
    // prost-reflect has a bug (see docs/PROST-ISSUES.md §1): for proto3
    // repeated scalar/enum fields, `is_packed()` returns false when
    // `FieldOptions` is present-but-empty in the FDS (e.g. because an
    // unrelated custom option such as `google.api.field_behavior` is set on
    // another field in the same message).  The proto3 spec mandates packed
    // encoding for such fields unless `[packed=false]` is explicitly set.
    //
    // When the `prost-bug-workaround` feature is enabled and the conditions
    // for the bug are met (proto3, repeated, packable kind), we apply the
    // correct rule ourselves: packed unless `raw_packed_option()` is
    // `Some(false)`.
    let use_packed = if is_repeated && is_packable_kind {
        #[cfg(feature = "prost-bug-workaround")]
        {
            if fs.parent_file_syntax() == prost_reflect::Syntax::Proto3 {
                // Correct proto3 rule: packed unless explicitly set to false.
                fs.raw_packed_option() != Some(false)
            } else {
                fs.is_packed()
            }
        }
        #[cfg(not(feature = "prost-bug-workaround"))]
        {
            fs.is_packed()
        }
    } else {
        false
    };
    if use_packed {
        render_packed(field_number, fs, tag_ohb, tag_oor, len_ohb, data, out);
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
                    push_tag_modifiers(&mut aw, out, tag_ohb, tag_oor, len_ohb);
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
            push_tag_modifiers(&mut aw, out, tag_ohb, tag_oor, len_ohb);
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
            // Any expansion intercept (spec 0089): if the field type is
            // google.protobuf.Any and EXPAND_ANY is set, try to expand the
            // value inline using the resolved type from type_url.
            if EXPAND_ANY.with(|c| c.get())
                && nested_msg_desc.full_name() == "google.protobuf.Any"
                && render_any_expansion(
                    field_number,
                    fs,
                    schema_present,
                    tag_ohb,
                    tag_oor,
                    len_ohb,
                    data,
                    out,
                )
            {
                return;
            }

            // MessageSet expansion intercept (spec 0100): if the field type
            // is a MessageSet (structural heuristic), expand groups inline.
            if EXPAND_MESSAGE_SET.with(|c| c.get()) && is_message_set(&nested_msg_desc) {
                render_message_set_expansion(
                    &nested_msg_desc,
                    field_number,
                    fs,
                    schema_present,
                    tag_ohb,
                    tag_oor,
                    len_ohb,
                    data,
                    out,
                );
                return;
            }

            let nested_schema: Option<&MessageDescriptor> = Some(&nested_msg_desc);

            wob_prefix_n(field_number, Some(fs), false, out);
            if annotations {
                let mut aw = AnnWriter::new();
                // v2: NO wire type for known MESSAGE; field_decl FIRST, then modifiers.
                aw.push_field_decl(out, field_number, Some(fs), None, None);
                push_tag_modifiers(&mut aw, out, tag_ohb, tag_oor, len_ohb);
            }
            out.push(b'\n');
            CBL_START.with(|c| c.set(out.len())); // open-brace line: set past-end to inhibit folding
            {
                let _guard = enter_level();
                render_message(data, 0, None, nested_schema, schema_present, out);
            }
            write_close_brace(out);
            return;
        }
    }

    // ── Wire-type mismatch (schema says non-LEN type but wire says LEN) ───────
    // v2: numeric key, `bytes` wire type FIRST, TYPE_MISMATCH modifier, no field_decl;
    // skip when hide_unknown_fields is set (spec 0103) or annotations are off
    // (mismatch rendering requires annotations to be meaningful).
    let hide_unknown = HIDE_UNKNOWN.with(|c| c.get());
    if hide_unknown || !annotations {
        return;
    }
    wfl_prefix_n(field_number, field_schema, true, out);
    out.push(b'"');
    escape_bytes_into(data, out);
    out.push(b'"');
    let mut aw = AnnWriter::new();
    aw.push_wire(out, "bytes");
    if field_schema.is_some() {
        aw.push(out, b"TYPE_MISMATCH");
    }
    push_tag_modifiers(&mut aw, out, tag_ohb, tag_oor, len_ohb);
    out.push(b'\n');
    CBL_START.with(|c| c.set(out.len())); // content line: set past-end to inhibit folding
}

/// Render a GROUP field (proto2), with greedy rendering and post-hoc fixup.
#[allow(clippy::too_many_arguments)]
pub(in super::super) fn render_group_field(
    buf: &[u8],
    pos: &mut usize,
    field_number: u64,
    field_schema: Option<&FieldOrExt>,
    schema_present: bool,
    tag_ohb: Option<u64>,
    tag_oor: bool,
    out: &mut Vec<u8>,
) {
    let annotations = ANNOTATIONS.with(|c| c.get());
    // Determine nested schema and whether this is a wire-type mismatch
    // (GROUP wire but schema declares a non-GROUP type).
    // A mismatch is treated as unknown: field number as name, no field_decl.
    let is_mismatch = field_schema.is_some_and(|fs| !fs.is_group());
    // `msg_desc` from `fs.kind()` is already live and correct — no lookup
    // needed (spec 0106 S1).
    let nested_msg_desc: Option<MessageDescriptor> = field_schema.and_then(|fs| {
        if fs.is_group() {
            if let Kind::Message(msg_desc) = fs.kind() {
                Some(msg_desc)
            } else {
                None
            }
        } else {
            None
        }
    });
    let nested_schema_opt: Option<&MessageDescriptor> = nested_msg_desc.as_ref();

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
    use super::output::push_indent;
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
            schema_present,
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
    let mismatch_mod = annotations && is_mismatch && field_schema.is_some();

    // Does annotations=true and we have anything to splice?
    let has_field_decl = decl_opt.is_some();
    let has_open_tag_mods = annotations && (tag_ohb.is_some() || tag_oor);
    let has_close_mods = annotations && !close_mods.is_empty();

    if has_field_decl || mismatch_mod || has_open_tag_mods || has_close_mods {
        // Build insert: each part contributes `"; " + text`.
        // Since `group` was already written greedily, the first element of the
        // insert begins with `"; "` to become the separator after `group`.
        let mut insert = String::new();
        if let Some(ref d) = decl_opt {
            insert.push_str("; ");
            insert.push_str(d);
        }
        if mismatch_mod {
            insert.push_str("; TYPE_MISMATCH");
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
