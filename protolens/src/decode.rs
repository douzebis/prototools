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

/// Maximum number of tied type names shown in an ambiguity error.
const MAX_AMBIGUOUS_TYPES: usize = 10;

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
}

impl DescriptorContext {
    pub fn pool(&self) -> &DescriptorPool {
        &self.pool
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

        Ok(DescriptorContext { pool, graph })
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
/// - `type_override` given: looked up directly in the pool, no scoring.
/// - `type_override` absent: requires a scoring graph (`ctx.graph`); errors
///   if the graph is missing, if all candidates are vetoed, or if multiple
///   candidates tie at the top score (spec 0111 Goal 2).
pub fn determine_root_type(
    blob: &[u8],
    ctx: &DescriptorContext,
    type_override: Option<&str>,
) -> Result<MessageDescriptor, DecodeError> {
    if let Some(fqdn) = type_override {
        return ctx.pool().get_message_by_name(fqdn).ok_or_else(|| {
            DecodeError::Determination(format!("type '{fqdn}' not found in descriptor set"))
        });
    }

    let graph = ctx.graph.as_ref().ok_or_else(|| {
        DecodeError::Determination(
            "no --type given and no hopcroft.rkyv scoring graph next to the descriptor set; \
             pass --type explicitly"
                .to_string(),
        )
    })?;

    let scoring_opts = ScoringOpts::default();
    let mut results = score_all(blob, graph, &scoring_opts);
    results.sort_by(|a, b| match (a.vetoed, b.vetoed) {
        (false, true) => std::cmp::Ordering::Less,
        (true, false) => std::cmp::Ordering::Greater,
        (true, true) => a.fqdn.cmp(&b.fqdn),
        (false, false) => b.score().cmp(&a.score()).then(a.fqdn.cmp(&b.fqdn)),
    });

    if results.is_empty() {
        return Err(DecodeError::Determination(
            "schema DB is empty; cannot determine message type".to_string(),
        ));
    }
    let non_vetoed: Vec<_> = results.iter().filter(|r| !r.vetoed).collect();
    if non_vetoed.is_empty() {
        return Err(DecodeError::Determination(
            "all candidate types vetoed; pass --type explicitly".to_string(),
        ));
    }

    let top_score = non_vetoed[0].score();
    let mut tied: Vec<&str> = non_vetoed
        .iter()
        .filter(|r| r.score() == top_score)
        .map(|r| r.fqdn.as_str())
        .collect();

    if tied.len() > 1 {
        tied.sort_unstable();
        tied.truncate(MAX_AMBIGUOUS_TYPES);
        return Err(DecodeError::Determination(format!(
            "ambiguous type (top score {top_score} tied among: {}); pass --type explicitly",
            tied.join(", ")
        )));
    }

    let fqdn = &non_vetoed[0].fqdn;
    ctx.pool().get_message_by_name(fqdn).ok_or_else(|| {
        DecodeError::Determination(format!(
            "resolved type '{fqdn}' not found in descriptor set"
        ))
    })
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
fn build_tree(spans: Vec<NodeSpan>) -> Vec<TreeNode> {
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

    // Document-order chain: sort by raw_range.start (stable — ties broken
    // by array position, harmless since ties don't occur for real spans).
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
}

/// Build (or reuse, if already registered) a synthetic one-field message
/// descriptor `protolens_internal.Wrapper_<sanitized root_fqdn>` whose sole
/// field 1 is message-typed, referencing `root_fqdn` — the virtual
/// encompassing protobuf of spec 0114 §1.1. Named per-root so that
/// registering wrappers for two different root types on the same pool (as
/// happens across repeated `decode()` calls) never collides.
fn register_wrapper(
    pool: &mut DescriptorPool,
    root_desc: &MessageDescriptor,
) -> Result<MessageDescriptor, DecodeError> {
    let root_fqdn = root_desc.full_name();
    let suffix = root_fqdn.replace('.', "_");
    let full_name = format!("protolens_internal.Wrapper_{suffix}");
    if let Some(existing) = pool.get_message_by_name(&full_name) {
        return Ok(existing);
    }

    let field = FieldDescriptorProto {
        name: Some("root".to_string()),
        number: Some(1),
        label: Some(Label::Optional as i32),
        r#type: Some(Type::Message as i32),
        type_name: Some(format!(".{root_fqdn}")),
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
        dependency: vec![root_desc.parent_file().name().to_string()],
        syntax: Some("proto2".to_string()),
        message_type: vec![message],
        ..Default::default()
    };
    pool.add_file_descriptor_proto(file)
        .map_err(|e| DecodeError::Schema(format!("registering wrapper descriptor: {e}")))?;
    pool.get_message_by_name(&full_name)
        .ok_or_else(|| DecodeError::Schema("wrapper descriptor registered but not found".into()))
}

/// Prepend a real tag(field 1, `WT_LEN`)+length-varint prefix to `blob`,
/// making it a genuinely valid encoding of the wrapper message (spec 0114
/// §1.1).
fn wrap_blob(blob: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(blob.len() + 10);
    write_tag(1, WT_LEN, &mut out);
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
    let root_type = root_desc.full_name().to_string();

    let wrapper_desc = register_wrapper(&mut ctx.pool, &root_desc)?;
    let wrapped_blob = wrap_blob(blob);
    let wrapper_offset = wrapped_blob.len() - blob.len();

    let opts = DecodeRenderOpts {
        annotations,
        indent_size,
        ..Default::default()
    };
    let (text, spans) = decode_and_render_indexed(&wrapped_blob, Some(&wrapper_desc), opts);

    let text = String::from_utf8(text)
        .map_err(|e| DecodeError::Schema(format!("rendered text is not valid UTF-8: {e}")))?;
    let lines: Vec<String> = text.lines().map(str::to_string).collect();
    let tree = build_tree(spans);

    Ok(Decoded {
        lines,
        tree,
        root_type,
        blob: wrapped_blob,
        wrapper_offset,
    })
}
