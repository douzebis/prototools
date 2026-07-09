// SPDX-FileCopyrightText: 2025-2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
// SPDX-FileCopyrightText: 2025-2026 THALES CLOUD SECURISE SAS
//
// SPDX-License-Identifier: MIT

mod helpers;
mod packed;
mod sink;
mod varint;

use std::cell::{Cell, RefCell};
use std::sync::Arc;

use prost_reflect::{Cardinality, ExtensionDescriptor, FieldDescriptor, Kind, MessageDescriptor};

use crate::helpers::{
    parse_varint, parse_wiretag, WiretagResult, WT_END_GROUP, WT_I32, WT_I64, WT_LEN,
    WT_START_GROUP, WT_VARINT,
};

use helpers::{render_group_field, render_len_field};
use sink::{IndexingTextSink, MalformedKind, ScalarValue, Sink, TagFacts, TextSink};

pub use sink::NodeSpan;

// Magic prefix that identifies a textual prototext payload.
const PROTOTEXT_MAGIC: &[u8] = b"#@ prototext:";

// ── FieldOrExt adapter ────────────────────────────────────────────────────────

/// Unifies `FieldDescriptor` (regular field) and `ExtensionDescriptor`
/// (extension field) for the subset of accessors used by the renderer.
pub(super) enum FieldOrExt {
    Field(FieldDescriptor),
    Ext(ExtensionDescriptor),
}

impl FieldOrExt {
    pub(super) fn kind(&self) -> Kind {
        match self {
            FieldOrExt::Field(f) => f.kind(),
            FieldOrExt::Ext(e) => e.kind(),
        }
    }

    pub(super) fn cardinality(&self) -> Cardinality {
        match self {
            FieldOrExt::Field(f) => f.cardinality(),
            FieldOrExt::Ext(e) => e.cardinality(),
        }
    }

    /// Returns `true` only for regular group fields; extensions cannot be groups.
    pub(super) fn is_group(&self) -> bool {
        match self {
            FieldOrExt::Field(f) => f.is_group(),
            FieldOrExt::Ext(_) => false,
        }
    }

    pub(super) fn is_packed(&self) -> bool {
        match self {
            FieldOrExt::Field(f) => f.is_packed(),
            FieldOrExt::Ext(_) => false,
        }
    }

    /// Returns the raw value of the `packed` field option from the descriptor:
    /// - `None`  — option absent (proto3 default applies)
    /// - `Some(true)`  — `[packed=true]` explicitly set
    /// - `Some(false)` — `[packed=false]` explicitly set
    ///
    /// Uses `prost_types::FieldDescriptorProto.options.packed: Option<bool>` directly —
    /// O(1), zero allocation (no DynamicMessage decoding).
    #[cfg(feature = "prost-bug-workaround")]
    pub(super) fn raw_packed_option(&self) -> Option<bool> {
        let proto = match self {
            FieldOrExt::Field(f) => f.field_descriptor_proto(),
            FieldOrExt::Ext(e) => e.field_descriptor_proto(),
        };
        proto.options.as_ref().and_then(|o| o.packed)
    }

    #[cfg(feature = "prost-bug-workaround")]
    pub(super) fn parent_file_syntax(&self) -> prost_reflect::Syntax {
        match self {
            FieldOrExt::Field(f) => f.parent_file().syntax(),
            FieldOrExt::Ext(e) => e.parent_file().syntax(),
        }
    }

    /// The name to use in field-line output.
    ///
    /// Regular field: `"name"` (bare field name).
    /// Extension field: `"[full.qualified.name]"`.
    pub(super) fn display_name(&self) -> String {
        match self {
            FieldOrExt::Field(f) => f.name().to_owned(),
            FieldOrExt::Ext(e) => format!("[{}]", e.full_name()),
        }
    }

    /// Returns the underlying `FieldDescriptor` if this is a regular field,
    /// or `None` for extension fields.
    ///
    /// Used to pass to functions that still take `Option<&FieldDescriptor>`.
    #[allow(dead_code)]
    pub(super) fn as_field(&self) -> Option<&FieldDescriptor> {
        match self {
            FieldOrExt::Field(f) => Some(f),
            FieldOrExt::Ext(_) => None,
        }
    }
}

/// Boxed JIT loader callback for `Any`/`MessageSet` type resolution (spec 0099).
pub type AnyLoader = Box<dyn FnMut(&str) -> Option<Arc<MessageDescriptor>>>;

// ── Render-mode state ─────────────────────────────────────────────────────────
//
// `CBL_START` is set to `out.len()` by `write_close_brace` before writing a
// `}\n` line, and reset to `out.len()` (past-end) by every other write.  It
// is currently unused beyond being maintained; the close-brace folding feature
// it was intended to support has been removed.
//
thread_local! {
    pub(super) static CBL_START:   Cell<usize> = const { Cell::new(0) };
    // Set once per `decode_and_render` call; read by every internal render fn.
    pub(super) static ANNOTATIONS: Cell<bool>  = const { Cell::new(false) };
    pub(super) static INDENT_SIZE: Cell<usize> = const { Cell::new(2) };
    // Tracks recursion depth; managed via `enter_level()` / `LevelGuard`.
    pub(super) static LEVEL:       Cell<usize> = const { Cell::new(0) };
    // When true, google.protobuf.Any fields are expanded inline (spec 0089).
    pub(super) static EXPAND_ANY:  Cell<bool>  = const { Cell::new(true) };
    // When true, fields absent from the schema are suppressed (spec 0103).
    pub(super) static HIDE_UNKNOWN: Cell<bool> = const { Cell::new(false) };
    // When true, MessageSet groups are expanded inline (spec 0103).
    pub(super) static EXPAND_MESSAGE_SET: Cell<bool> = const { Cell::new(true) };
    // Optional header lines injected after the magic line (e.g. # Type / # Score).
    pub static EXTRA_HEADER: RefCell<String> = const { RefCell::new(String::new()) };
    // JIT loader for Any/MessageSet type resolution (spec 0099).
    // Set by `set_any_loader` before rendering; cleared by `clear_any_loader` after.
    // Safety invariant: the raw pointer inside the Box is valid for the duration
    // of the rendering call that set it.  Always cleared before the setting
    // stack frame returns.
    pub(super) static ANY_LOADER: RefCell<Option<AnyLoader>> = const { RefCell::new(None) };
}

/// Install a JIT loader for `Any` (and future `MessageSet`) type resolution
/// (spec 0099).  Must be paired with `clear_any_loader` after rendering.
///
/// # Safety
/// The caller guarantees that the closure (and any references it captures)
/// remains valid until `clear_any_loader` is called.
pub fn set_any_loader(loader: AnyLoader) {
    ANY_LOADER.with(|l| *l.borrow_mut() = Some(loader));
}

/// Clear the JIT loader installed by `set_any_loader`.
pub fn clear_any_loader() {
    ANY_LOADER.with(|l| *l.borrow_mut() = None);
}

/// RAII guard for `LEVEL`: increments on construction, decrements on drop.
/// Guarantees the level is restored even if the callee panics.
pub(super) struct LevelGuard;

impl Drop for LevelGuard {
    fn drop(&mut self) {
        LEVEL.with(|l| l.set(l.get() - 1));
    }
}

/// Enter one recursion level, tracked via the shared thread-local `LEVEL`
/// counter — but only when `sink.tracks_level()` says this sink actually
/// depends on it (see that method's doc comment). Returns `None` for sinks
/// like `ProbeSink` that must not mutate shared render-mode state.
fn enter_level<S: Sink>(sink: &S) -> Option<LevelGuard> {
    if sink.tracks_level() {
        LEVEL.with(|l| l.set(l.get() + 1));
        Some(LevelGuard)
    } else {
        None
    }
}

/// Return `true` when `data` is already rendered prototext text (fast-path).
pub fn is_prototext_text(data: &[u8]) -> bool {
    data.starts_with(PROTOTEXT_MAGIC)
}

/// Probe `data` as a schemaless message via `ProbeSink` (spec 0110 §2),
/// without producing any output. Returns `(next_pos, malformity_count)`.
///
/// Exposed crate-wide so the (pre-retirement — spec 0110 Step 6)
/// `decoder` module's own unknown-LEN-field cascade can share this probe
/// instead of its old `decoder::parse_message`-based one.
pub(crate) fn probe_message(data: &[u8]) -> (usize, u64) {
    let mut probe = sink::ProbeSink::default();
    let (next_pos, _) = render_message(data, 0, None, None, false, &mut probe);
    (next_pos, probe.malformity_count())
}

// ── Public entry point ────────────────────────────────────────────────────────

/// Decode raw protobuf binary and render as protoc-style text in one pass.
///
/// Writes field lines into a pre-allocated `Vec<u8>`.  When `annotations` is
/// true, a `#@ prototext: protoc\n` header is prepended; without annotations
/// the header is omitted (encode is not possible without field annotations
/// regardless).
///
/// `root_desc` is the already-resolved root message descriptor, if any (the
/// caller is responsible for resolving it from whatever pool it has — see
/// spec 0106 S4). `None` means no schema is active (`--raw`/no-descriptor
/// mode).
///
/// Parameters mirror `format_as_text` in `lib.rs`.
pub fn decode_and_render(
    buf: &[u8],
    root_desc: Option<&MessageDescriptor>,
    annotations: bool,
    indent_size: usize,
    expand_any: bool,
    hide_unknown_fields: bool,
    expand_message_set: bool,
    initial_level: usize,
    emit_header: bool,
) -> Vec<u8> {
    let capacity = buf.len() * 8;
    let mut sink = TextSink::new(capacity);

    // Header — only emitted when annotations are on and the caller wants
    // one; without field-level annotations prototext encode cannot
    // reconstruct the binary anyway, so the header would be misleading.
    // `emit_header: false` is used for sub-renders destined to be spliced
    // into an existing document's text, which must not repeat the header.
    if annotations && emit_header {
        sink.write_header(b"#@ prototext: protoc\n");
    }
    EXTRA_HEADER.with(|h| {
        let h = h.borrow();
        if !h.is_empty() {
            sink.write_header(h.as_bytes());
        }
    });
    // Initialise render-mode state.
    // CBL_START past the end so the first write_close_brace always takes
    // the fresh-write path.
    CBL_START.with(|c| c.set(sink.out.len()));
    ANNOTATIONS.with(|c| c.set(annotations));
    INDENT_SIZE.with(|c| c.set(indent_size));
    LEVEL.with(|c| c.set(initial_level));
    EXPAND_ANY.with(|c| c.set(expand_any));
    HIDE_UNKNOWN.with(|c| c.set(hide_unknown_fields));
    EXPAND_MESSAGE_SET.with(|c| c.set(expand_message_set));

    let schema_present = root_desc.is_some();

    render_message(buf, 0, None, root_desc, schema_present, &mut sink);

    let out = sink.into_inner();

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

/// Sibling to `decode_and_render`, sharing the exact same parameter list,
/// but internally rendering through an `IndexingTextSink` instead of a bare
/// `TextSink`, and returning both the rendered text and its `NodeSpan`
/// index alongside it (spec 0110 §3). `decode_and_render` itself stays
/// `TextSink`-only: its production callers have no use for the index and
/// shouldn't pay `IndexingTextSink`'s small extra bookkeeping cost.
pub fn decode_and_render_indexed(
    buf: &[u8],
    root_desc: Option<&MessageDescriptor>,
    annotations: bool,
    indent_size: usize,
    expand_any: bool,
    hide_unknown_fields: bool,
    expand_message_set: bool,
    initial_level: usize,
    emit_header: bool,
) -> (Vec<u8>, Vec<NodeSpan>) {
    let capacity = buf.len() * 8;
    let mut sink = IndexingTextSink::new(capacity);

    if annotations && emit_header {
        sink.write_header(b"#@ prototext: protoc\n");
    }
    EXTRA_HEADER.with(|h| {
        let h = h.borrow();
        if !h.is_empty() {
            sink.write_header(h.as_bytes());
        }
    });
    CBL_START.with(|c| c.set(sink.out_len()));
    ANNOTATIONS.with(|c| c.set(annotations));
    INDENT_SIZE.with(|c| c.set(indent_size));
    LEVEL.with(|c| c.set(initial_level));
    EXPAND_ANY.with(|c| c.set(expand_any));
    HIDE_UNKNOWN.with(|c| c.set(hide_unknown_fields));
    EXPAND_MESSAGE_SET.with(|c| c.set(expand_message_set));

    let schema_present = root_desc.is_some();

    render_message(buf, 0, None, root_desc, schema_present, &mut sink);

    sink.into_parts()
}

// ── Core recursive render-while-decode ───────────────────────────────────────

/// Parse and render one protobuf message into `sink`.
///
/// Returns `(next_pos, group_end_tag)`:
/// - `next_pos`: byte position after this message (for the caller to
///   continue its own parse loop, or for GROUP end detection).
/// - `group_end_tag`: `Some(tag)` when parsing terminated on a `WT_END_GROUP`.
fn render_message<S: Sink>(
    buf: &[u8],
    start: usize,
    my_group: Option<u64>,
    schema: Option<&MessageDescriptor>,
    schema_present: bool,
    sink: &mut S,
) -> (usize, Option<WiretagResult>) {
    let buflen = buf.len();
    let mut pos = start;

    loop {
        if pos == buflen {
            return (pos, None);
        }

        // ── Parse wire tag ────────────────────────────────────────────────────

        let field_start = pos;
        let tag = parse_wiretag(buf, pos);

        if let Some(ref wtag_gar) = tag.wtag_gar {
            // Invalid wire tag: consume rest of buffer as INVALID_TAG_TYPE
            sink.malformed(
                0,
                TagFacts::default(),
                MalformedKind::InvalidTagType,
                wtag_gar,
            );
            return (buflen, None);
        }

        let field_number = tag.wfield.unwrap();
        let wire_type = tag.wtype.unwrap();
        let tag_ohb = tag.wfield_ohb;
        let tag_oor = tag.wfield_oor.is_some();
        pos = tag.next_pos;

        // ── Schema lookup ─────────────────────────────────────────────────────

        let field_schema: Option<FieldOrExt> = schema.and_then(|s| {
            if let Some(f) = s.get_field(field_number as u32) {
                Some(FieldOrExt::Field(f))
            } else {
                s.get_extension(field_number as u32).map(FieldOrExt::Ext)
            }
        });

        // ── Wire-type dispatch ────────────────────────────────────────────────

        match wire_type {
            // ── VARINT ───────────────────────────────────────────────────────
            WT_VARINT => {
                let vr = parse_varint(buf, pos);
                if let Some(ref varint_gar) = vr.varint_gar {
                    sink.malformed(
                        field_number,
                        TagFacts {
                            tag_ohb,
                            tag_oor,
                            len_ohb: None,
                        },
                        MalformedKind::InvalidVarint,
                        varint_gar,
                    );
                    return (buflen, None);
                }
                pos = vr.next_pos;
                let val_ohb = vr.varint_ohb;
                let val = vr.varint.unwrap();

                sink.scalar_field(
                    field_number,
                    field_schema.as_ref(),
                    TagFacts {
                        tag_ohb,
                        tag_oor,
                        len_ohb: None,
                    },
                    ScalarValue::Varint {
                        raw_val: val,
                        val_ohb,
                    },
                    field_start..pos,
                    schema_present,
                );
            }

            // ── FIXED64 ──────────────────────────────────────────────────────
            WT_I64 => {
                if pos + 8 > buflen {
                    let raw = &buf[pos..];
                    sink.malformed(
                        field_number,
                        TagFacts {
                            tag_ohb,
                            tag_oor,
                            len_ohb: None,
                        },
                        MalformedKind::InvalidFixed64,
                        raw,
                    );
                    return (buflen, None);
                }
                let mut data = [0u8; 8];
                data.copy_from_slice(&buf[pos..pos + 8]);
                pos += 8;

                sink.scalar_field(
                    field_number,
                    field_schema.as_ref(),
                    TagFacts {
                        tag_ohb,
                        tag_oor,
                        len_ohb: None,
                    },
                    ScalarValue::Fixed64(data),
                    field_start..pos,
                    schema_present,
                );
            }

            // ── LENGTH-DELIMITED ─────────────────────────────────────────────
            WT_LEN => {
                let lr = parse_varint(buf, pos);
                if let Some(ref varint_gar) = lr.varint_gar {
                    sink.malformed(
                        field_number,
                        TagFacts {
                            tag_ohb,
                            tag_oor,
                            len_ohb: None,
                        },
                        MalformedKind::InvalidLen,
                        varint_gar,
                    );
                    return (buflen, None);
                }
                let len_ohb = lr.varint_ohb;
                pos = lr.next_pos;
                let length = lr.varint.unwrap() as usize;

                if pos + length > buflen {
                    let missing = (length - (buflen - pos)) as u64;
                    let raw = &buf[pos..];
                    sink.malformed(
                        field_number,
                        TagFacts {
                            tag_ohb,
                            tag_oor,
                            len_ohb,
                        },
                        MalformedKind::TruncatedBytes { missing },
                        raw,
                    );
                    return (buflen, None);
                }
                let data = &buf[pos..pos + length];
                pos += length;

                render_len_field(
                    field_number,
                    field_schema.as_ref(),
                    schema_present,
                    TagFacts {
                        tag_ohb,
                        tag_oor,
                        len_ohb,
                    },
                    field_start..pos,
                    data,
                    sink,
                );
            }

            // ── START GROUP ──────────────────────────────────────────────────
            WT_START_GROUP => {
                render_group_field(
                    buf,
                    &mut pos,
                    field_number,
                    field_schema.as_ref(),
                    schema_present,
                    TagFacts {
                        tag_ohb,
                        tag_oor,
                        len_ohb: None,
                    },
                    field_start,
                    sink,
                );
            }

            // ── END GROUP ────────────────────────────────────────────────────
            WT_END_GROUP => {
                if my_group.is_none() {
                    // Unexpected END_GROUP outside a group
                    let raw = &buf[pos..];
                    sink.malformed(
                        field_number,
                        TagFacts {
                            tag_ohb,
                            tag_oor,
                            len_ohb: None,
                        },
                        MalformedKind::InvalidGroupEnd,
                        raw,
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
                    sink.malformed(
                        field_number,
                        TagFacts {
                            tag_ohb,
                            tag_oor,
                            len_ohb: None,
                        },
                        MalformedKind::InvalidFixed32,
                        raw,
                    );
                    return (buflen, None);
                }
                let mut data = [0u8; 4];
                data.copy_from_slice(&buf[pos..pos + 4]);
                pos += 4;

                sink.scalar_field(
                    field_number,
                    field_schema.as_ref(),
                    TagFacts {
                        tag_ohb,
                        tag_oor,
                        len_ohb: None,
                    },
                    ScalarValue::Fixed32(data),
                    field_start..pos,
                    schema_present,
                );
            }

            _ => unreachable!("wire type > 5 caught by parse_wiretag"),
        }
    }
}

// ── Tests: `decode_and_render`'s `initial_level`/`emit_header` params ─────────

#[cfg(test)]
mod tests {
    use super::*;

    // field 1 (varint) = 42: tag 0x08, value 0x2A.
    const VARINT_FIELD: [u8; 2] = [0x08, 0x2A];

    #[test]
    fn initial_level_indents_output() {
        let out = decode_and_render(&VARINT_FIELD, None, false, 2, false, false, false, 3, false);
        let text = String::from_utf8(out).unwrap();
        let first_line = text.lines().next().unwrap();
        let indent = first_line.len() - first_line.trim_start().len();
        assert_eq!(indent, 2 * 3); // indent_size * initial_level
    }

    #[test]
    fn initial_level_zero_matches_default() {
        let out = decode_and_render(&VARINT_FIELD, None, false, 2, false, false, false, 0, false);
        let text = String::from_utf8(out).unwrap();
        let first_line = text.lines().next().unwrap();
        assert_eq!(first_line, "1: 42");
    }

    #[test]
    fn emit_header_true_writes_header() {
        let out = decode_and_render(&VARINT_FIELD, None, true, 2, false, false, false, 0, true);
        let text = String::from_utf8(out).unwrap();
        assert!(text.starts_with("#@ prototext: protoc\n"));
    }

    #[test]
    fn emit_header_false_suppresses_header() {
        let out = decode_and_render(&VARINT_FIELD, None, true, 2, false, false, false, 0, false);
        let text = String::from_utf8(out).unwrap();
        assert!(!text.starts_with("#@ prototext: protoc\n"));
    }

    // ── `ProbeSink` (spec 0110 Step 4 / Open Issue #1) ─────────────────────

    #[test]
    fn probe_sink_recognizes_valid_nested_message() {
        // field 1 (unknown, LEN) whose payload is itself a well-formed
        // message: field 1 (varint) = 42.
        let buf = [0x0A, 0x02, 0x08, 0x2A];
        let out = decode_and_render(&buf, None, false, 2, false, false, false, 0, false);
        let text = String::from_utf8(out).unwrap();
        assert_eq!(text, "1 {\n  1: 42\n}\n");
    }

    #[test]
    fn probe_sink_rolls_up_nested_group_malformity() {
        // field 1 (unknown, LEN) whose payload is: a GROUP (field 5) opened,
        // containing a field 1 varint with a truncated (garbage) varint byte
        // (0x80, continuation bit set, no terminating byte).  The nested
        // group's own malformity must roll up into the outer probe's count
        // (spec 0110 Open Issue #1), causing Step 1 (nested-message probe) to
        // fail and fall through to the raw-bytes fallback — rather than being
        // incorrectly accepted as a valid nested message.
        let payload = [0x2B, 0x08, 0x80];
        let mut buf = vec![0x0A, payload.len() as u8];
        buf.extend_from_slice(&payload);
        let out = decode_and_render(&buf, None, false, 2, false, false, false, 0, false);
        let text = String::from_utf8(out).unwrap();
        // Fallback rendering (invalid-UTF-8 payload -> escaped bytes leaf),
        // not a nested `1 { ... }` block.
        assert!(!text.starts_with("1 {"), "got: {text}");
        assert!(text.starts_with("1: \""), "got: {text}");
    }
}
