// SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

//! Decode a binary protobuf blob into rendered text plus a navigation tree.
//!
//! Mirrors (simplified) `prototext`'s own `DescriptorContext` / `infer_type`
//! machinery (`prototext/src/run.rs`) — no `LazyPool`/`index.rkyv` fast path,
//! no embedded-WKT-descriptor fallback: spec 0111 v1 always requires an
//! explicit `--descriptor-set`.

use std::fmt;
use std::path::Path;

use prost_reflect::prost_types::field_descriptor_proto::{Label, Type};
use prost_reflect::prost_types::{DescriptorProto, FieldDescriptorProto, FileDescriptorProto};
use prost_reflect::{DescriptorPool, MessageDescriptor};
use prototext_core::helpers::{write_tag, write_varint, WT_LEN};
use prototext_core::serialize::render_text::{
    decode_and_render_indexed, DecodeRenderOpts, NodeSpan,
};
use prototext_core::{decode_pool, render_as_bytes, RenderOpts};
use prototext_graph::score::{
    load::{load_graph, LoadedGraph},
    score_all, ScoringOpts,
};

use crate::colorize::{self, SyntaxRole};

// ── Errors ──────────────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum DecodeError {
    Io(String),
    Schema(String),
    Determination(String),
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DecodeError::Io(msg) => write!(f, "{msg}"),
            DecodeError::Schema(msg) => write!(f, "{msg}"),
            DecodeError::Determination(msg) => write!(f, "{msg}"),
        }
    }
}

impl std::error::Error for DecodeError {}

// ── DescriptorContext ─────────────────────────────────────────────────────

/// A resolved `--descriptor-set`: a pool for type lookup plus an optional
/// Hopcroft scoring graph (`<stem>/hopcroft.rkyv` sidecar, if present).
pub struct DescriptorContext {
    pool: DescriptorPool,
    pub graph: Option<LoadedGraph>,
    /// Canonicalized binary bytes `load()` decoded `pool` from — i.e.
    /// after `read_descriptor_file`'s `#@ prototext`-to-binary conversion,
    /// same normalization `main.rs` applies to the target blob (spec 0114
    /// §1.1). Basis for `override_pane::sha256_hex`'s
    /// `descriptor_set_sha256` (spec 0117 §4).
    pub raw_bytes: Vec<u8>,
}

impl DescriptorContext {
    pub fn pool(&self) -> &DescriptorPool {
        &self.pool
    }

    /// Mutable pool access — needed by `tui.rs`'s `splice_override` (spec
    /// 0118 §4) to call `register_wrapper` for an arbitrary target type,
    /// mirroring `decode()`'s own (in-module, private-field) access.
    pub(crate) fn pool_mut(&mut self) -> &mut DescriptorPool {
        &mut self.pool
    }

    /// Load a `DescriptorContext` from a `--descriptor-set` path. v1 has no
    /// schemaless/embedded-WKT fallback (spec 0111 Goal 2): the caller must
    /// always supply a path.
    pub fn load(path: &Path) -> Result<Self, DecodeError> {
        let bytes = read_descriptor_file(path)?;
        let pool = decode_pool(&bytes)
            .map_err(|e| DecodeError::Schema(format!("descriptor '{}': {e}", path.display())))?;

        let stem = path.with_extension("");
        let rkyv_path = stem.join("hopcroft.rkyv");
        let graph = if rkyv_path.exists() {
            Some(load_graph(&rkyv_path).map_err(|e| {
                DecodeError::Schema(format!("loading graph '{}': {e}", rkyv_path.display()))
            })?)
        } else {
            None
        };

        Ok(DescriptorContext {
            pool,
            graph,
            raw_bytes: bytes,
        })
    }

    /// A trivially empty pool/no-graph context — `tui.rs`'s unit tests
    /// exercise `App` state directly against synthetic `Decoded` fixtures
    /// (no real `--descriptor-set` file), and `App` now needs *some*
    /// `DescriptorContext` to hold (spec 0114 §3's candidate-list
    /// computation reads `ctx.pool()`/`ctx.graph`). `pool`/`graph` are
    /// private, so this constructor — not a struct literal — is the only
    /// way for another module's tests to build one.
    #[cfg(test)]
    pub(crate) fn empty_for_test() -> Self {
        DescriptorContext {
            pool: DescriptorPool::new(),
            graph: None,
            raw_bytes: Vec::new(),
        }
    }
}

/// Read a descriptor file: accepts binary `FileDescriptorSet`, `#@` prototext
/// `FileDescriptorSet`, or a single `FileDescriptorProto` — same acceptance
/// rule as `prototext`'s own `read_descriptor_file` (prototext/src/run.rs).
/// `pub(crate)`: also reused by `complete::complete_type_names`, so `--type`
/// completion accepts the same descriptor formats as decoding itself.
pub(crate) fn read_descriptor_file(path: &Path) -> Result<Vec<u8>, DecodeError> {
    let bytes = std::fs::read(path)
        .map_err(|e| DecodeError::Io(format!("cannot read '{}': {e}", path.display())))?;
    // The prototext_core parser handles both binary and #@ prototext FDS/FDP
    // transparently via render_as_bytes — but we need raw binary FDS bytes for
    // decode_pool. If the file starts with the #@ magic, decode it first.
    if bytes.starts_with(b"#@") {
        let opts = RenderOpts {
            assume_binary: false,
            include_annotations: false,
            indent: 1,
            expand_any: false,
            ..RenderOpts::default()
        };
        render_as_bytes(&bytes, opts).map_err(|e| {
            DecodeError::Schema(format!(
                "decoding prototext descriptor '{}': {e}",
                path.display()
            ))
        })
    } else {
        Ok(bytes)
    }
}

// ── Root-type determination ────────────────────────────────────────────────

/// Resolve the root message type to decode `blob` as.
///
/// - `type_override` given: looked up directly in the pool; a lookup
///   failure is a hard error (the user asked for a specific type).
/// - `type_override` absent: tries autoinference via a scoring graph
///   (`ctx.graph`). Returns `Ok(None)` — not an error — whenever inference
///   doesn't produce a clean winner (no graph available, no candidates,
///   all candidates vetoed, or a top-score tie): the caller then renders
///   the blob with no type known (spec 0114, "protolens command line
///   should not require --type").
pub fn determine_root_type(
    blob: &[u8],
    ctx: &DescriptorContext,
    type_override: Option<&str>,
) -> Result<Option<MessageDescriptor>, DecodeError> {
    if let Some(fqdn) = type_override {
        return ctx
            .pool()
            .get_message_by_name(fqdn)
            .map(Some)
            .ok_or_else(|| {
                DecodeError::Determination(format!("type '{fqdn}' not found in descriptor set"))
            });
    }

    let Some(graph) = ctx.graph.as_ref() else {
        return Ok(None);
    };

    let scoring_opts = ScoringOpts::default();
    let mut results = score_all(blob, graph, &scoring_opts);
    results.sort_by(|a, b| match (a.vetoed, b.vetoed) {
        (false, true) => std::cmp::Ordering::Less,
        (true, false) => std::cmp::Ordering::Greater,
        (true, true) => a.fqdn.cmp(&b.fqdn),
        (false, false) => b.score().cmp(&a.score()).then(a.fqdn.cmp(&b.fqdn)),
    });

    if results.is_empty() {
        return Ok(None);
    }
    let non_vetoed: Vec<_> = results.iter().filter(|r| !r.vetoed).collect();
    if non_vetoed.is_empty() {
        return Ok(None);
    }

    let top_score = non_vetoed[0].score();
    let tied = non_vetoed.iter().filter(|r| r.score() == top_score).count();
    if tied > 1 {
        return Ok(None);
    }

    let fqdn = &non_vetoed[0].fqdn;
    Ok(ctx.pool().get_message_by_name(fqdn))
}

// ── Navigation tree ─────────────────────────────────────────────────────────

/// One node of the local arena built over the flat `Vec<NodeSpan>` returned
/// by `decode_and_render_indexed` — see spec 0111 "Tree construction
/// (ingestion)".
///
/// NOT index-parallel to document order: `IndexingTextSink` pushes a
/// container's own `NodeSpan` only in `end_nested`, i.e. *after* all of its
/// descendants — the emitted `Vec<NodeSpan>` is post-order, not pre-order.
/// (Spec 0111 originally assumed pre-order; corrected here after discovering
/// the actual `begin_nested`/`end_nested` call shape in
/// `prototext-core/src/serialize/render_text/sink.rs`.) `doc_next`/
/// `doc_prev` provide an explicit document-order chain (by `raw_range.start`)
/// for `j`/`k`, since raw array-index arithmetic no longer gives that for
/// free.
#[derive(Debug)]
pub struct TreeNode {
    pub span: NodeSpan,
    pub parent: Option<usize>,
    pub first_child: Option<usize>,
    pub last_child: Option<usize>,
    pub next_sibling: Option<usize>,
    pub prev_sibling: Option<usize>,
    pub doc_next: Option<usize>,
    pub doc_prev: Option<usize>,
    /// Which override (if any) currently produced this node's rendering,
    /// paired with the field name it was rendered under (spec 0118 §2.1,
    /// extended by spec 0119 G4) — `None` until the first `render()` pass
    /// touches it (freshly built by `build_tree`, whether from the
    /// initial raw decode or a splice's local tree). Both halves of the
    /// pair are inputs to the actual rendered text (the type via
    /// `splice_override`'s target, the name via a synthetic wrapper's
    /// field label), so either one changing must trigger a re-splice —
    /// tracking only the type here would miss a name-only change (e.g.
    /// spec 0119 G4's per-entry rename).
    pub rendered_as: Option<(Option<Option<String>>, String)>,
}

/// Build the navigation arena from a flat, level-annotated, post-order
/// `Vec<NodeSpan>` in a single `O(n)` pass, using a stack of "subtree roots
/// completed so far" (spec 0111 "Tree construction (ingestion)").
///
/// For each incoming node `i` at `level`, every stack entry with a greater
/// level is one of `i`'s children (post-order guarantees they were fully
/// built already) — pop them all, in left-to-right order, as `i`'s children.
/// The (now topmost) remaining stack entry, if at the same level as `i`, is
/// `i`'s immediate previous sibling — link incrementally, so by the time any
/// node is pushed its sibling chain up to that point is already correct.
pub(crate) fn build_tree(spans: Vec<NodeSpan>) -> Vec<TreeNode> {
    let mut nodes: Vec<TreeNode> = spans
        .into_iter()
        .map(|span| TreeNode {
            span,
            parent: None,
            first_child: None,
            last_child: None,
            next_sibling: None,
            prev_sibling: None,
            doc_next: None,
            doc_prev: None,
            rendered_as: None,
        })
        .collect();

    // Stack of (index, level) for completed subtree roots not yet claimed
    // by a parent.
    let mut stack: Vec<(usize, usize)> = Vec::new();

    for i in 0..nodes.len() {
        let level = nodes[i].span.level;

        let mut children = Vec::new();
        while let Some(&(top, top_level)) = stack.last() {
            if top_level > level {
                children.push(top);
                stack.pop();
            } else {
                break;
            }
        }
        children.reverse(); // restore left-to-right document order

        for &c in &children {
            nodes[c].parent = Some(i);
        }
        if let Some(&first) = children.first() {
            nodes[i].first_child = Some(first);
        }
        if let Some(&last) = children.last() {
            nodes[i].last_child = Some(last);
        }

        if let Some(&(top, top_level)) = stack.last() {
            if top_level == level {
                nodes[i].prev_sibling = Some(top);
                nodes[top].next_sibling = Some(i);
            }
        }

        stack.push((i, level));
    }

    // Document-order chain: sort by raw_range.start. Every NodeSpan is
    // backed by a real tag/length prefix of its own (spec 0120 — Any/
    // MessageSet expansion is disabled at the prototext-core level, so
    // no virtual wrapper node with a borrowed/shared range ever reaches
    // this function), so raw_range.start values never tie.
    let mut doc_order: Vec<usize> = (0..nodes.len()).collect();
    doc_order.sort_by_key(|&i| nodes[i].span.raw_range.start);
    for w in doc_order.windows(2) {
        let (a, b) = (w[0], w[1]);
        nodes[a].doc_next = Some(b);
        nodes[b].doc_prev = Some(a);
    }

    nodes
}

// ── Public entry point ──────────────────────────────────────────────────────

pub struct Decoded {
    pub lines: Vec<String>,
    pub tree: Vec<TreeNode>,
    pub root_type: String,
    /// The wrapped blob actually decoded (spec 0114 §1.1): a real tag+length
    /// prefix (field 1, `WT_LEN`) prepended to the caller's original blob,
    /// so every `NodeSpan::raw_range` in `tree` is relative to *this* blob,
    /// not the caller's original one.
    pub blob: Vec<u8>,
    /// Width in bytes of the wrapper's own tag+length prefix — subtract this
    /// from any `raw_range` coordinate to recover the caller's original
    /// (pre-wrap) numbering.
    pub wrapper_offset: usize,
    /// Syntax-highlighting spans (spec 0116 §7), one entry per `lines`,
    /// each holding that line's `(column range, role)` pairs — the
    /// initial-load counterpart of `apply_override`'s per-splice
    /// colorize pass (`protolens/src/tui.rs`).
    pub style_hints: Vec<Vec<(std::ops::Range<usize>, SyntaxRole)>>,
}

/// Build (or reuse, if already registered) a synthetic one-field message
/// descriptor `protolens_internal.Wrapper_<field_number>_<sanitized
/// target_fqdn>` whose sole field `field_number` is message-typed,
/// referencing `target_desc` — the virtual encompassing protobuf of spec
/// 0114 §1.1, generalized (spec 0118 §4) to an arbitrary field number so
/// `splice_override` can wrap any node's own field, not just the document
/// root (always field `1`). Named per-`(field_number, target_fqdn)` so
/// that registering wrappers for different targets on the same pool (as
/// happens across repeated `decode()`/`splice_override` calls) never
/// collides. `pub(crate)`: also called from `tui.rs`'s `splice_override`.
pub(crate) fn register_wrapper(
    pool: &mut DescriptorPool,
    field_number: u64,
    field_name: &str,
    target_desc: &MessageDescriptor,
) -> Result<MessageDescriptor, DecodeError> {
    let target_fqdn = target_desc.full_name();
    // `field_name` is part of the cache/registration key, not just
    // `field_number`+`target_fqdn` (spec 0119 §G2): two nodes can share
    // the same field number and override target while having different
    // real field names (e.g. field 1 named differently in two distinct
    // parent messages) — without this, the second registration would
    // silently reuse the first one's field name via `get_message_by_name`
    // returning the cached descriptor unchanged.
    let suffix = format!(
        "{field_number}_{field_name}_{}",
        target_fqdn.replace('.', "_")
    );
    let full_name = format!("protolens_internal.Wrapper_{suffix}");
    if let Some(existing) = pool.get_message_by_name(&full_name) {
        return Ok(existing);
    }

    let field = FieldDescriptorProto {
        name: Some(field_name.to_string()),
        number: Some(field_number as i32),
        label: Some(Label::Optional as i32),
        r#type: Some(Type::Message as i32),
        type_name: Some(format!(".{target_fqdn}")),
        ..Default::default()
    };
    let message = DescriptorProto {
        name: Some(format!("Wrapper_{suffix}")),
        field: vec![field],
        ..Default::default()
    };
    let file = FileDescriptorProto {
        name: Some(format!("protolens_internal/wrapper_{suffix}.proto")),
        package: Some("protolens_internal".to_string()),
        dependency: vec![target_desc.parent_file().name().to_string()],
        syntax: Some("proto2".to_string()),
        message_type: vec![message],
        ..Default::default()
    };
    pool.add_file_descriptor_proto(file)
        .map_err(|e| DecodeError::Schema(format!("registering wrapper descriptor: {e}")))?;
    pool.get_message_by_name(&full_name)
        .ok_or_else(|| DecodeError::Schema("wrapper descriptor registered but not found".into()))
}

/// FQDN of the synthetic, globally-shared "Item" shape used to represent
/// a MessageSet group entry generically — `type_id` (field 2) and
/// `message` (field 3, raw bytes) — before the specific extension type
/// is known (spec 0120 §G2 tier 1).  Registered once per pool
/// (`register_message_set_item`), reused by every MessageSet occurrence
/// in the document: the shape is always identical, independent of any
/// particular extendee.
pub(crate) const MESSAGE_SET_ITEM_FQDN: &str = "protolens_internal.MessageSetItem";

/// Build (or reuse, if already registered) the synthetic
/// `protolens_internal.MessageSetItem` descriptor: `type_id: int32 = 2`,
/// `message: bytes = 3` — the generic tier-1 shape for a MessageSet
/// group entry (spec 0120 §G2). Unlike `register_wrapper`, this has no
/// per-target parameters: the shape never varies, so it's registered
/// exactly once and shared by every MessageSet in the document.
/// `pub(crate)`: also called from `tui.rs`'s `auto_expand_type`.
pub(crate) fn register_message_set_item(
    pool: &mut DescriptorPool,
) -> Result<MessageDescriptor, DecodeError> {
    if let Some(existing) = pool.get_message_by_name(MESSAGE_SET_ITEM_FQDN) {
        return Ok(existing);
    }
    let type_id_field = FieldDescriptorProto {
        name: Some("type_id".to_string()),
        number: Some(2),
        label: Some(Label::Optional as i32),
        r#type: Some(Type::Int32 as i32),
        ..Default::default()
    };
    let message_field = FieldDescriptorProto {
        name: Some("message".to_string()),
        number: Some(3),
        label: Some(Label::Optional as i32),
        r#type: Some(Type::Bytes as i32),
        ..Default::default()
    };
    let message = DescriptorProto {
        name: Some("MessageSetItem".to_string()),
        field: vec![type_id_field, message_field],
        ..Default::default()
    };
    let file = FileDescriptorProto {
        name: Some("protolens_internal/message_set_item.proto".to_string()),
        package: Some("protolens_internal".to_string()),
        syntax: Some("proto2".to_string()),
        message_type: vec![message],
        ..Default::default()
    };
    pool.add_file_descriptor_proto(file)
        .map_err(|e| DecodeError::Schema(format!("registering MessageSetItem descriptor: {e}")))?;
    pool.get_message_by_name(MESSAGE_SET_ITEM_FQDN)
        .ok_or_else(|| {
            DecodeError::Schema("MessageSetItem descriptor registered but not found".into())
        })
}

/// Prepend a real tag(`field_number`, `WT_LEN`)+length-varint prefix to
/// `blob`, making it a genuinely valid encoding of a wrapper message's
/// sole field (spec 0114 §1.1, generalized spec 0118 §4 to an arbitrary
/// field number). `pub(crate)`: also called from `tui.rs`'s
/// `splice_override`.
pub(crate) fn wrap_blob(field_number: u64, blob: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(blob.len() + 10);
    write_tag(field_number as u32, WT_LEN, &mut out);
    write_varint(blob.len() as u64, &mut out);
    out.extend_from_slice(blob);
    out
}

pub fn decode(
    blob: &[u8],
    ctx: &mut DescriptorContext,
    type_override: Option<&str>,
    indent_size: usize,
    annotations: bool,
) -> Result<Decoded, DecodeError> {
    let root_desc = determine_root_type(blob, ctx, type_override)?;
    let (root_type, wrapper_desc) = match &root_desc {
        Some(desc) => (
            desc.full_name().to_string(),
            Some(register_wrapper(&mut ctx.pool, 1, "0", desc)?),
        ),
        None => ("<raw / no type>".to_string(), None),
    };

    let wrapped_blob = wrap_blob(1, blob);
    let wrapper_offset = wrapped_blob.len() - blob.len();

    let opts = DecodeRenderOpts {
        annotations,
        indent_size,
        // Any/MessageSet expansion is handled by protolens itself, as
        // automatic overrides (spec 0120), not by prototext-core's own
        // virtual-node expansion — disabling both here lets Any/
        // MessageSet-typed fields fall through to ordinary
        // nested-message / unknown-field rendering, giving every field
        // (including `type_url`/`type_id`) a real `NodeSpan`.
        expand_any: false,
        expand_message_set: false,
        ..Default::default()
    };
    let (text, spans) = decode_and_render_indexed(&wrapped_blob, wrapper_desc.as_ref(), opts);

    let mut text = String::from_utf8(text)
        .map_err(|e| DecodeError::Schema(format!("rendered text is not valid UTF-8: {e}")))?;
    // The document root has no real field name of its own — `"0"` is
    // just `register_wrapper`'s synthetic placeholder (spec 0114 §1.1),
    // never meant to be shown. Strip it from the root's own header line
    // (its first two bytes, unconditionally, since nothing precedes it —
    // `emit_header` is left `false` here) whenever a schema was resolved
    // (`wrapper_desc.is_some()`; the raw/no-type case never emits a `"0"`
    // token at all, since `render_message` falls back to the field
    // number, not a field name, when `root_desc` is `None`). Done here,
    // before splitting into lines/colorizing, since `NodeSpan::text_range`
    // is line-indexed, not byte-indexed (spec 0110), so shortening line 0
    // in place can't desync anything downstream.
    if wrapper_desc.is_some() {
        if let Some(stripped) = text.strip_prefix("0 ") {
            text = stripped.to_string();
        }
    }
    let lines: Vec<String> = text.lines().map(str::to_string).collect();
    let style_hints = colorize::hints_by_line(&lines, &colorize::colorize(&text));
    let tree = build_tree(spans);

    Ok(Decoded {
        lines,
        tree,
        root_type,
        blob: wrapped_blob,
        wrapper_offset,
        style_hints,
    })
}

#[cfg(test)]
mod tests {
    use prost::Message as _;
    use prost_reflect::prost_types::FileDescriptorSet;

    use super::*;

    #[test]
    fn determine_root_type_returns_none_without_override_or_graph() {
        let ctx = DescriptorContext::empty_for_test();
        let blob = [0x08u8, 0x05];
        let resolved = determine_root_type(&blob, &ctx, None).unwrap();
        assert!(resolved.is_none());
    }

    /// Spec 0114: `--type` is optional — with no graph (autoinference
    /// unavailable), `decode()` must not error but instead render the
    /// blob with no known type. The virtual wrapper's own top-level node
    /// (spec 0114 §1.1) still probes as message-shaped even with no
    /// schema (spec 0097's unknown-LEN-field cascade), so it is the sole
    /// node in the tree, with `type_fqdn: None` — the same representation
    /// `apply_override(None)` would produce, i.e. this initial render
    /// already stands in for "the first override of the session".
    #[test]
    fn decode_without_type_override_or_graph_renders_raw_not_error() {
        let inner_desc = DescriptorProto {
            name: Some("Inner".to_string()),
            field: vec![FieldDescriptorProto {
                name: Some("id".to_string()),
                number: Some(1),
                label: Some(Label::Optional as i32),
                r#type: Some(Type::Int32 as i32),
                ..Default::default()
            }],
            ..Default::default()
        };
        let file = FileDescriptorProto {
            name: Some("test_decode_raw_fallback.proto".to_string()),
            package: Some("test".to_string()),
            message_type: vec![inner_desc],
            syntax: Some("proto3".to_string()),
            ..Default::default()
        };
        let fds = FileDescriptorSet { file: vec![file] };

        let descriptor_path =
            std::env::temp_dir().join("protolens-decode-raw-fallback-descriptor.pb");
        std::fs::write(&descriptor_path, fds.encode_to_vec()).unwrap();
        let mut ctx = DescriptorContext::load(&descriptor_path).unwrap();
        std::fs::remove_file(&descriptor_path).unwrap();

        // A single varint field (tag 0x08, value 5) — no --type, and this
        // context has no hopcroft.rkyv, so autoinference is unavailable.
        let blob = [0x08u8, 0x05];

        let decoded = decode(&blob, &mut ctx, None, 2, true).unwrap();
        assert_eq!(decoded.root_type, "<raw / no type>");
        // The wrapper's own top-level field (the "virtual encompassing
        // message", spec 0114 §1.1) — level 0, no type resolved.
        let wrapper = decoded
            .tree
            .iter()
            .find(|n| n.span.level == 0)
            .expect("tree must contain the wrapper's top-level node");
        assert!(wrapper.span.is_message);
        assert_eq!(wrapper.span.type_fqdn, None);
    }

    /// The document root has no real field name of its own —
    /// `register_wrapper`'s synthetic `"0"` placeholder (spec 0114 §1.1)
    /// must never leak into the rendered header line when no G4 name
    /// override applies (there is none yet at initial `decode()` time).
    #[test]
    fn decode_omits_the_synthetic_root_field_name_from_the_header_line() {
        let msg_desc = DescriptorProto {
            name: Some("Msg".to_string()),
            field: vec![FieldDescriptorProto {
                name: Some("id".to_string()),
                number: Some(1),
                label: Some(Label::Optional as i32),
                r#type: Some(Type::Int32 as i32),
                ..Default::default()
            }],
            ..Default::default()
        };
        let file = FileDescriptorProto {
            name: Some("test_decode_root_name.proto".to_string()),
            package: Some("test".to_string()),
            message_type: vec![msg_desc],
            syntax: Some("proto3".to_string()),
            ..Default::default()
        };
        let fds = FileDescriptorSet { file: vec![file] };

        let descriptor_path = std::env::temp_dir().join("protolens-decode-root-name-descriptor.pb");
        std::fs::write(&descriptor_path, fds.encode_to_vec()).unwrap();
        let mut ctx = DescriptorContext::load(&descriptor_path).unwrap();
        std::fs::remove_file(&descriptor_path).unwrap();

        let blob = [0x08u8, 0x05];
        let decoded = decode(&blob, &mut ctx, Some("test.Msg"), 2, true).unwrap();
        assert!(
            !decoded.lines[0].starts_with("0 "),
            "root header line must not show the synthetic \"0\" field name: {:?}",
            decoded.lines[0]
        );
        assert!(decoded.lines[0].starts_with('{'));
    }

    /// Spec 0120: `decode()` disables `expand_any`/`expand_message_set`,
    /// so a `google.protobuf.Any` field is *not* auto-expanded at this
    /// layer (that's `tui.rs`'s `render_overrides`/`auto_expand_type`'s
    /// job, spec 0120 §G1) — instead it falls through to ordinary
    /// nested-message rendering under Any's own real 2-field descriptor,
    /// giving `type_url` (field 1) and `value` (field 2) real,
    /// correctly-ordered `NodeSpan`s of their own (no virtual wrapper, no
    /// fabricated `field_number: 0`). Fixture mirrors `prototext/tests/
    /// node_span.rs`'s own `any_schema`/`any_wire_bytes`.
    #[test]
    fn decode_leaves_any_fields_unexpanded_with_real_type_url_and_value_spans() {
        let any_msg = DescriptorProto {
            name: Some("Any".to_string()),
            field: vec![
                FieldDescriptorProto {
                    name: Some("type_url".to_string()),
                    number: Some(1),
                    label: Some(Label::Optional as i32),
                    r#type: Some(Type::String as i32),
                    ..Default::default()
                },
                FieldDescriptorProto {
                    name: Some("value".to_string()),
                    number: Some(2),
                    label: Some(Label::Optional as i32),
                    r#type: Some(Type::Bytes as i32),
                    ..Default::default()
                },
            ],
            ..Default::default()
        };
        let any_file = FileDescriptorProto {
            name: Some("google/protobuf/any.proto".to_string()),
            syntax: Some("proto3".to_string()),
            package: Some("google.protobuf".to_string()),
            message_type: vec![any_msg],
            ..Default::default()
        };

        let payload_msg = DescriptorProto {
            name: Some("Payload".to_string()),
            field: vec![FieldDescriptorProto {
                name: Some("label".to_string()),
                number: Some(1),
                label: Some(Label::Optional as i32),
                r#type: Some(Type::String as i32),
                ..Default::default()
            }],
            ..Default::default()
        };
        let container_msg = DescriptorProto {
            name: Some("Container".to_string()),
            field: vec![FieldDescriptorProto {
                name: Some("payload".to_string()),
                number: Some(1),
                label: Some(Label::Optional as i32),
                r#type: Some(Type::Message as i32),
                type_name: Some(".google.protobuf.Any".to_string()),
                ..Default::default()
            }],
            ..Default::default()
        };
        let acme_file = FileDescriptorProto {
            name: Some("acme.proto".to_string()),
            syntax: Some("proto2".to_string()),
            package: Some("acme".to_string()),
            dependency: vec!["google/protobuf/any.proto".to_string()],
            message_type: vec![payload_msg, container_msg],
            ..Default::default()
        };
        let fds = FileDescriptorSet {
            file: vec![any_file, acme_file],
        };

        let descriptor_path =
            std::env::temp_dir().join("protolens-decode-any-expansion-descriptor.pb");
        std::fs::write(&descriptor_path, fds.encode_to_vec()).unwrap();
        let mut ctx = DescriptorContext::load(&descriptor_path).unwrap();
        std::fs::remove_file(&descriptor_path).unwrap();

        // Container { payload: Any { type_url:
        // "type.googleapis.com/acme.Payload", value: Payload { label:
        // "hello" } } }.
        let label = b"hello";
        let mut payload_bytes = vec![0x0au8, label.len() as u8];
        payload_bytes.extend_from_slice(label);
        let type_url = b"type.googleapis.com/acme.Payload";
        let mut any_bytes = vec![0x0au8, type_url.len() as u8];
        any_bytes.extend_from_slice(type_url);
        any_bytes.push(0x12);
        any_bytes.push(payload_bytes.len() as u8);
        any_bytes.extend_from_slice(&payload_bytes);
        let mut blob = vec![0x0au8, any_bytes.len() as u8];
        blob.extend_from_slice(&any_bytes);

        let decoded = decode(&blob, &mut ctx, Some("acme.Container"), 2, true).unwrap();
        let any_idx = decoded
            .tree
            .iter()
            .position(|n| n.span.type_fqdn.as_deref() == Some("google.protobuf.Any"))
            .expect("tree must contain the unexpanded Any node itself");
        let type_url_idx = decoded.tree[any_idx]
            .first_child
            .expect("Any node must have type_url as its first child");
        let value_idx = decoded.tree[type_url_idx]
            .next_sibling
            .expect("Any node must have value as its second child");
        assert_eq!(decoded.tree[type_url_idx].span.field_number, 1);
        assert_eq!(decoded.tree[value_idx].span.field_number, 2);
        assert!(
            decoded.tree[value_idx].span.type_fqdn.is_none(),
            "value must stay unexpanded (plain bytes) at decode() layer: {:#?}",
            decoded.tree[value_idx].span
        );
        assert!(
            !decoded
                .tree
                .iter()
                .any(|n| n.span.type_fqdn.as_deref() == Some("acme.Payload")),
            "acme.Payload must not appear — auto-expansion is tui.rs's job, \
             not decode()'s: {:#?}",
            decoded.lines
        );
        // Real tag/length-backed ranges, in document order: type_url's
        // range must end before value's own range starts.
        assert!(
            decoded.tree[type_url_idx].span.raw_range.end
                <= decoded.tree[value_idx].span.raw_range.start,
            "type_url and value must have real, non-overlapping, correctly \
             ordered raw ranges: {:#?}",
            (
                &decoded.tree[type_url_idx].span,
                &decoded.tree[value_idx].span
            )
        );
    }
}
