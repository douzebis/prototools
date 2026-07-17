// SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

use super::*;

use prost_reflect::prost_types::field_descriptor_proto::Type;

impl App {
    /// Recursively collect every current descendant of `idx` (any depth),
    /// via `first_child`/`next_sibling` pointer traversal — never array
    /// position (spec 0114 §5's splice design: post-order array
    /// contiguity does not survive a *second* override of the same node,
    /// since the first override's new nodes are appended at the array's
    /// end, breaking it). Used to find which array entries become orphans
    /// once `idx`'s subtree is replaced, so they can be scrubbed from
    /// `self.folded`.
    pub(super) fn collect_descendants(&self, idx: usize, out: &mut Vec<usize>) {
        let mut child = self.tree[idx].first_child;
        while let Some(c) = child {
            out.push(c);
            self.collect_descendants(c, out);
            child = self.tree[c].next_sibling;
        }
    }

    /// Looks up `idx`'s own field on its parent's schema (spec 0119
    /// §G1/§G2's shared lookup): requires both that `idx`'s parent has a
    /// resolved `type_fqdn` and that its schema declares `idx`'s
    /// `field_number`. Returns `None` when either fails (no parent,
    /// unresolved parent type, or the field isn't declared) — the same
    /// failure mode `natural_type`/`field_name_for` both fall back from.
    pub(super) fn parent_field(&self, idx: usize) -> Option<prost_reflect::FieldDescriptor> {
        let parent = self.tree[idx].parent?;
        let fqdn = self.tree[parent].span.type_fqdn.as_ref()?;
        let field_number = self.tree[idx].span.field_number;
        self.ctx
            .pool()
            .get_message_by_name(fqdn)?
            .get_field(field_number as u32)
    }

    /// The type `idx` would naturally have from its parent's schema, used
    /// as the fallback when no active override applies (spec 0119 §G1) —
    /// `None` only when genuinely no type information is available (no
    /// parent schema, field not declared, or a non-message field kind).
    pub(super) fn natural_type(&self, idx: usize) -> Option<String> {
        match self.parent_field(idx)?.kind() {
            prost_reflect::Kind::Message(desc) => Some(desc.full_name().to_string()),
            _ => None,
        }
    }

    /// `true` when `idx`'s resolved type is `google.protobuf.Any` — spec
    /// 0120 §G1's detection rule, a plain FQDN match (per review).
    pub(super) fn is_any_typed(&self, idx: usize) -> bool {
        self.tree[idx].span.type_fqdn.as_deref() == Some("google.protobuf.Any")
    }

    /// `true` when `idx`'s resolved type is a MessageSet — spec 0120 §G2's
    /// detection rule: `message_set_wire_format = true` in the resolved
    /// `MessageDescriptor`'s own options, and zero declared fields. Mirrors
    /// `prototext-core`'s own (private, unreachable from this crate)
    /// `is_message_set` heuristic — an independent replica, not a shared
    /// helper, since protolens already has direct `prost_reflect`/
    /// `ctx.pool()` access and needs no new plumbing (spec 0120's
    /// assessment).
    pub(super) fn is_message_set_typed(&self, idx: usize) -> bool {
        let Some(fqdn) = self.tree[idx].span.type_fqdn.as_ref() else {
            return false;
        };
        let Some(desc) = self.ctx.pool().get_message_by_name(fqdn) else {
            return false;
        };
        let msf = desc
            .descriptor_proto()
            .options
            .as_ref()
            .and_then(|o| o.message_set_wire_format)
            .unwrap_or(false);
        msf && desc.fields().count() == 0
    }

    /// The sibling of `idx` (another child of `idx`'s own parent) whose
    /// `field_number` is `field_number`, if any — used by
    /// `auto_expand_type` to locate Any's `type_url` next to `value`, and
    /// MessageSet's `type_id` next to `message`.
    pub(super) fn find_sibling(&self, idx: usize, field_number: u64) -> Option<usize> {
        let parent = self.tree[idx].parent?;
        let mut c = self.tree[parent].first_child;
        while let Some(ci) = c {
            if self.tree[ci].span.field_number == field_number {
                return Some(ci);
            }
            c = self.tree[ci].next_sibling;
        }
        None
    }

    /// Reads `idx`'s own raw payload (tag/length stripped, per
    /// `extract::message_payload_range`) as a UTF-8 string — used to read
    /// Any's `type_url` value directly off the wire, independent of how
    /// (or whether) it's currently rendered.
    pub(super) fn read_string_field(&self, idx: usize) -> Option<String> {
        let span = &self.tree[idx].span;
        let payload =
            extract::message_payload_range(&self.blob, &span.raw_range, span.packed_record_start);
        String::from_utf8(self.blob[payload].to_vec()).ok()
    }

    /// Reads `idx`'s own raw payload as a varint — used to read
    /// MessageSet's `type_id` value directly off the wire.
    pub(super) fn read_varint_field(&self, idx: usize) -> Option<u64> {
        let span = &self.tree[idx].span;
        let payload =
            extract::message_payload_range(&self.blob, &span.raw_range, span.packed_record_start);
        prototext_core::helpers::parse_varint(&self.blob, payload.start).varint
    }

    /// `true` when `idx` is structurally *eligible* for Any/MessageSet
    /// auto-expansion (spec 0120) — regardless of whether the actual
    /// target type turns out to be resolvable. Used by `render_overrides`
    /// to widen its child-recursion gate (normally `span.is_message`
    /// only) just enough to give these two specific field shapes a
    /// chance to be visited and auto-overridden, without reopening the
    /// spec 0119 bug where every plain scalar LEN-wire field got
    /// incorrectly demoted to raw by being recursed into at all.
    pub(super) fn is_auto_expand_candidate(&self, idx: usize) -> bool {
        let Some(parent) = self.tree[idx].parent else {
            return false;
        };
        let field_number = self.tree[idx].span.field_number;
        if field_number == 2 && self.is_any_typed(parent) {
            return true;
        }
        // MessageSet tier 1 (the "Item" group wrapper itself) needs no
        // entry here: it's already `is_message == true` naturally (a
        // real decoded group), so `render_overrides`'s own `is_message`
        // half of its recursion gate already reaches it.
        if field_number == 3
            && self.tree[parent].span.type_fqdn.as_deref() == Some(decode::MESSAGE_SET_ITEM_FQDN)
        {
            if let Some(grandparent) = self.tree[parent].parent {
                return self.is_message_set_typed(grandparent);
            }
        }
        false
    }

    /// The Any/MessageSet auto-derived type for `idx`, if `idx` is one of
    /// the two eligible field shapes (spec 0120 §G1/§G2) and the type it
    /// points at is resolvable in `ctx.pool()` — `None` otherwise (either
    /// not an eligible shape, or an unresolvable `type_url`/`type_id`,
    /// both of which fall back to plain raw rendering like any other
    /// unresolvable type). Consulted as a fallback tier between an
    /// explicit active override and `natural_type` in `render_overrides`.
    pub(super) fn auto_expand_type(&mut self, idx: usize) -> Option<String> {
        let parent = self.tree[idx].parent?;
        let field_number = self.tree[idx].span.field_number;

        // Any's `value` (field 2): FQDN read from the sibling `type_url`
        // (field 1), stripped of any leading `.../` host/prefix segment
        // (mirrors `any_field.rs`'s own `rfind('/')` resolution).
        if field_number == 2 && self.is_any_typed(parent) {
            let type_url_idx = self.find_sibling(idx, 1)?;
            let type_url = self.read_string_field(type_url_idx)?;
            let fqdn = match type_url.rfind('/') {
                Some(slash) => &type_url[slash + 1..],
                None => type_url.as_str(),
            };
            return self
                .ctx
                .pool()
                .get_message_by_name(fqdn)
                .map(|d| d.full_name().to_string());
        }

        // MessageSet tier 1: the "Item" group wrapper (field 1,
        // `WT_START_GROUP`) auto-derives to the synthetic, globally
        // shared `protolens_internal.Item` shape (`type_id` +
        // `message`) — registered once per pool and reused across every
        // MessageSet occurrence in the document.
        if field_number == 1
            && self.tree[idx].span.wire_type == prototext_core::helpers::WT_START_GROUP
            && self.is_message_set_typed(parent)
        {
            return decode::register_message_set_item(self.ctx.pool_mut())
                .ok()
                .map(|d| d.full_name().to_string());
        }

        // MessageSet tier 2: "message" (field 3) of an Item already
        // retyped (tier 1) to `protolens_internal.Item` — extension type
        // resolved from the sibling `type_id` (field 2), keyed against
        // the MessageSet container's (idx's grandparent) own extensions.
        if field_number == 3
            && self.tree[parent].span.type_fqdn.as_deref() == Some(decode::MESSAGE_SET_ITEM_FQDN)
        {
            let grandparent = self.tree[parent].parent?;
            if self.is_message_set_typed(grandparent) {
                let type_id_idx = self.find_sibling(idx, 2)?;
                let type_id = self.read_varint_field(type_id_idx)?;
                let grandparent_fqdn = self.tree[grandparent].span.type_fqdn.clone()?;
                let extendee = self.ctx.pool().get_message_by_name(&grandparent_fqdn)?;
                let ext = extendee.get_extension(type_id as u32)?;
                if let prost_reflect::Kind::Message(inner) = ext.kind() {
                    return Some(inner.full_name().to_string());
                }
            }
        }

        None
    }

    /// The display name to use for `idx`'s synthetic wrapper field in
    /// `splice_override` (spec 0119 §G2, extended by §G4): the resolved
    /// active override entry's own `name` override when set (§G4 takes
    /// priority); otherwise `idx`'s real field name when resolvable from
    /// the parent's schema; otherwise `idx`'s field number as a string
    /// (protobuf field names can never be all-digits, so this can't
    /// collide with a real name) — the document root is not special-
    /// cased: it's always field number 1 of the virtual encompassing
    /// message, so it falls through to this same field-number case.
    pub(super) fn field_name_for(&self, idx: usize) -> String {
        if let Some(name) = self
            .resolve_active_override_entry(idx)
            .and_then(|e| e.name.clone())
        {
            return name;
        }
        if let Some(field) = self.parent_field(idx) {
            field.name().to_string()
        } else {
            self.tree[idx].span.field_number.to_string()
        }
    }

    /// Resolves `idx`'s applicable override entry, per the priority
    /// `Path > PathField > FqdnField` (spec 0117), or `None` when no
    /// active entry applies at all — spec 0118 §2. Only `active` entries
    /// are considered (at most one active entry per origin, per spec
    /// 0117's invariant). Shared by `resolve_active_override` (the
    /// entry's `r#type`) and `field_name_for` (spec 0119 §G4's `name`).
    pub(super) fn resolve_active_override_entry(
        &self,
        idx: usize,
    ) -> Option<&override_pane::OverrideEntry> {
        let path = self.positional_path(idx);
        for e in self.overrides.entries() {
            if e.active {
                if let OverrideOrigin::Path { path: p } = &e.origin {
                    if *p == path {
                        return Some(e);
                    }
                }
            }
        }
        let parent = self.tree[idx].parent?;
        let field = self.tree[idx].span.field_number;
        let parent_path = self.positional_path(parent);
        for e in self.overrides.entries() {
            if e.active {
                if let OverrideOrigin::PathField { path: p, field: f } = &e.origin {
                    if *p == parent_path && *f == field {
                        return Some(e);
                    }
                }
            }
        }
        if let Some(fqdn) = &self.tree[parent].span.type_fqdn {
            for e in self.overrides.entries() {
                if e.active {
                    if let OverrideOrigin::FqdnField {
                        fqdn: f,
                        field: fld,
                    } = &e.origin
                    {
                        if f == fqdn && *fld == field {
                            return Some(e);
                        }
                    }
                }
            }
        }
        None
    }

    /// Resolves to the type (or `None` = raw) that should currently be
    /// used to render `idx`'s payload, or the outer `None` when no active
    /// override applies at all — spec 0118 §2.
    pub(super) fn resolve_active_override(&self, idx: usize) -> Option<Option<String>> {
        self.resolve_active_override_entry(idx)
            .map(|e| e.r#type.clone())
    }

    /// Spec 0132 §G3: settles `idx`'s main-pane rendering to its current
    /// "effective" override target (`resolve_active_override`'s
    /// explicit type if one is active, else `natural_type(idx)` when
    /// nothing is active at all) — splicing only if it doesn't already
    /// match `self.tree[idx].rendered_as` (the same no-op-when-already-
    /// current guard `render_overrides` always used, verbatim). Factored
    /// out of `render_overrides` itself (which calls this for `idx`
    /// before recursing into children) so the override-pane's live-
    /// preview revert (on close/cancel) can reuse the exact same
    /// "effective type" computation — including the natural-type
    /// fallback a plain `resolve_active_override_entry`-only revert
    /// would get wrong.
    ///
    /// 2026-07-17: no longer demotes a stale `auto` entry whose
    /// ancestor context has since changed (spec 0120's original
    /// design) — `auto`/`manual` is provenance only (how an entry was
    /// created, shown via `manage_entry_style`), and must have no
    /// effect on whether an *active* entry actually applies. An
    /// active entry, auto-derived or not, applies exactly as long as
    /// its path still resolves to a live node — the same fallback
    /// `splice_override` already relies on for a manual override that
    /// no longer cleanly matches its target (a `TYPE_MISMATCH`-style
    /// annotation, not a silent revert to raw).
    pub(super) fn resettle_node(&mut self, idx: usize) {
        let target = self.resolve_active_override(idx);
        let field_name = self.field_name_for(idx);
        let current = Some((target.clone(), field_name));
        if current != self.tree[idx].rendered_as {
            let effective = match &target {
                Some(explicit) => explicit.clone(),
                None => self.natural_type(idx),
            };
            match self.splice_override(idx, effective) {
                Ok(()) => self.tree[idx].rendered_as = current,
                Err(e) => self.message = format!("cannot apply override: {e}"),
            }
        }
    }

    /// Whether `entry` (assumed `auto == true`) would still be re-derived
    /// with the same `r#type` if `render_overrides` visited its node
    /// again right now — i.e. it is still "in scope" (spec 0125 §G2).
    /// Sole remaining use (2026-07-17, since `resettle_node` dropped its
    /// own demotion check): `handle_manage_key`'s `Delete`/`Backspace`
    /// handling, which still needs to distinguish "deleting this would
    /// just make the next `render_overrides` pass re-seed an identical
    /// entry" (still in scope) from "deleting this is final" (out of
    /// scope). Lives on `App` (not `OverrideCollection`) because it
    /// needs `auto_expand_type`, which resolves against the live tree/
    /// descriptor pool, not just the override collection itself.
    /// Auto-seeded entries only ever have a `Path` origin
    /// (`render_overrides` always calls `activate_auto` with
    /// `OverrideOrigin::Path`), so a single `resolve_path` lookup
    /// suffices.
    pub(super) fn auto_entry_in_scope(&mut self, entry: &override_pane::OverrideEntry) -> bool {
        let OverrideOrigin::Path { path } = &entry.origin else {
            return false;
        };
        let Some(idx) = self.resolve_path(path) else {
            return false;
        };
        self.auto_expand_type(idx) == entry.r#type
    }

    /// Recursive override-driven rendering pass (spec 0118 §3): resolves
    /// `idx`'s applicable override and splices a fresh render whenever the
    /// resolved target no longer matches what's currently displayed
    /// (`TreeNode::rendered_as`, spec 0118 §2.1) — comparing against
    /// provenance, not just "is there an override right now?", is what
    /// correctly detects a demotion (an override that used to apply no
    /// longer does), not just fresh promotions/retypes.
    ///
    /// Any/MessageSet auto-expansion (spec 0120) is seeded as a real,
    /// persisted `OverrideEntry` (`OverrideOrigin::Path`) the first time
    /// `idx` is visited with *no entry at all yet existing* for its path —
    /// checked via `self.overrides.entries()`, not via
    /// `resolve_active_override`: the latter can't distinguish "never
    /// seeded" from "user explicitly deactivated the seeded entry", and
    /// naively re-seeding (calling `activate` again) on every subsequent
    /// pass would both silently resurrect a deactivation the user just
    /// made in the manage pane, and — since `activate` unconditionally
    /// resorts the entries list — reshuffle `manage_highlight`'s raw index
    /// out from under the very keypress that triggered this pass. Once
    /// truly first-seeded, `auto_expand_type(idx)` computes the derived
    /// type, `self.overrides.activate` records it, and — because this
    /// happens *before* `target`/`current` are computed below — the very
    /// same pass's `resolve_active_override` already sees it, so no
    /// separate fallback tier is needed in the splice logic itself. This
    /// makes the derived type a real, visible, user-editable/removable
    /// entry in the override management pane (rather than a silent
    /// dynamic fallback), and means every subsequent pass resolves it via
    /// the ordinary entries scan instead of re-deriving it from the wire
    /// each time. When no active override applies at all after seeding
    /// (`target == None`, e.g. the type wasn't resolvable, or the user
    /// deactivated it), the effective splice target falls back to
    /// `natural_type(idx)` — `idx`'s inherited type from its parent's
    /// schema. That fallback never fires when an active entry explicitly
    /// says raw (`target == Some(None)`), which still renders raw, since
    /// that's an explicit user choice. The *outer* `Option` of `target` is
    /// still what gets stored into `rendered_as`, preserving the
    /// provenance distinction for the next pass — paired with
    /// `field_name_for(idx)` (spec 0119 §G4): either half changing (a
    /// retype, or a name-only rename of the governing entry) is enough to
    /// trigger a re-splice, since both feed directly into the rendered
    /// text.
    ///
    /// Named `render_overrides` (not `render`) to avoid colliding with the
    /// unrelated `render(&mut self, frame: &mut Frame)` ratatui draw
    /// method below.
    pub(super) fn render_overrides(&mut self, idx: usize) {
        let origin = OverrideOrigin::Path {
            path: self.positional_path(idx),
        };
        let already_seeded = self.overrides.entries().iter().any(|e| e.origin == origin);
        if !already_seeded {
            if let Some(t) = self.auto_expand_type(idx) {
                // MessageSet tier 1's synthetic wrapper field has no
                // schema-declared name to fall back on (`field_name_for`
                // would otherwise show the bare field number "1"), so
                // seed it with the display name `prototext-core`'s native
                // MessageSet rendering uses for it ("Item") — spec 0120
                // §G2's follow-up cosmetic fix.
                let is_message_set_item = self.tree[idx].span.field_number == 1
                    && self.tree[idx].span.wire_type == prototext_core::helpers::WT_START_GROUP
                    && self.tree[idx]
                        .parent
                        .is_some_and(|p| self.is_message_set_typed(p));
                self.overrides.activate_auto(origin.clone(), Some(t));
                if is_message_set_item {
                    if let Some(entry_idx) = self
                        .overrides
                        .entries()
                        .iter()
                        .position(|e| e.origin == origin)
                    {
                        self.overrides.rename(entry_idx, Some("Item".to_string()));
                    }
                }
            }
        }
        self.resettle_node(idx);
        let mut child = self.tree[idx].first_child;
        while let Some(c) = child {
            // Recurse into every node actually rendered as message/group
            // (`NodeSpan::is_message`) — the set of nodes that can carry
            // nested overridable children at all (spec 0119) — plus the
            // two specific plain-scalar shapes eligible for Any/
            // MessageSet auto-expansion (spec 0120's
            // `is_auto_expand_candidate`): those aren't `is_message` yet
            // (they're still bytes/varint until auto-overridden), but
            // must still be visited once so `auto_expand_type` above gets
            // a chance to promote them. Recursing into every plain
            // scalar LEN-wire field unconditionally would reopen the
            // spec 0119 bug this same gate was introduced to fix
            // (`natural_type` demoting an ordinary string/bytes field to
            // a raw record dump) — `is_auto_expand_candidate` is
            // deliberately narrow, matching only these two shapes. Also
            // recurse into any child carrying its own active override
            // entry (spec 0135 §G3 gap, found post-implementation): a
            // primitive override on a plain scalar leaf is exactly such
            // a node — not `is_message`, not an auto-expand candidate —
            // and would otherwise never actually get spliced by
            // `:type-as` (which, unlike the override pane's live
            // preview, applies solely through this recursive walk). Also
            // recurse into any child already carrying a `rendered_as`
            // (spec 0135 follow-up, found post-implementation): once a
            // plain scalar leaf has been spliced under an override at
            // least once, it must keep being revisited on every future
            // pass, even after that override is deactivated — otherwise
            // `resolve_active_override_entry(c)` above goes back to
            // `None` (deactivated) the moment the gate condition it
            // relies on stops holding, permanently orphaning the node
            // before `resettle_node` gets a chance to fall it back to
            // its natural type.
            if self.tree[c].span.is_message
                || self.is_auto_expand_candidate(c)
                || self.resolve_active_override_entry(c).is_some()
                || self.tree[c].rendered_as.is_some()
            {
                self.render_overrides(c);
            }
            child = self.tree[c].next_sibling;
        }
    }

    /// Unified splice mechanic (spec 0118 §4, reworked spec 0135 G1):
    /// regenerates the *whole* rendering of `idx` — header, interior, and
    /// footer alike — under `target` (`None` = revert to raw, `Some(fqdn)`
    /// = retype/promote to a message FQDN, `Some(keyword)` = retype to a
    /// wire-compatible primitive type, G3/G4). No existing rendering of
    /// `idx` is ever reused verbatim: decodes `idx`'s own real tag+payload
    /// bytes (`old_span.raw_range`) directly against a synthetic one-field
    /// descriptor (`decode::register_wrapper`) whose sole field has `idx`'s
    /// own real field number and the target's declared type — the node's
    /// real wire framing (message/group/scalar) is reproduced by
    /// `TextSink` for free, no header patching needed (spec 0135
    /// Background). This is what fixes task #34 (a stale `#@` type
    /// annotation surviving a retype) as a byproduct, for every node.
    ///
    /// `idx` keeps its own tree-array identity (so `cursor`/`folded`/
    /// back-jump state referencing it stays valid) — only its `span`
    /// (`raw_range` excepted: the underlying bytes haven't moved) and its
    /// children (old ones orphaned via `collect_descendants`, new ones
    /// appended and stitched in) are replaced.
    ///
    /// For a packed-repeated element (`packed_record_start.is_some()`),
    /// `idx` is first reassigned to `siblings[0]` — the packed run's own
    /// receiving node (spec 0135 G1's "sibling merge"): every sibling
    /// element sharing the same packed record is collapsed into this one
    /// node, regardless of which specific element the caller invoked the
    /// override on.
    pub(super) fn splice_override(
        &mut self,
        mut idx: usize,
        target: Option<String>,
    ) -> Result<(), String> {
        let mut old_span = self.tree[idx].span.clone();
        let is_packed = old_span.packed_record_start.is_some();

        // Packed-record reconstruction + sibling merge (spec 0135 G1):
        // collapse every sibling element of the same packed record into
        // `siblings[0]` before proceeding through the ordinary path below.
        let mut packed_next_sibling_of_run = None;
        let mut packed_seam_after = None;
        let mut packed_run_is_last_child = false;
        let mut packed_orphans: Vec<usize> = Vec::new();
        if is_packed {
            let siblings = self.packed_record_siblings(idx);
            let last = *siblings
                .last()
                .expect("packed_record_siblings always returns at least idx itself");
            let (raw_range, text_range) = self.packed_record_extent(&siblings);
            idx = siblings[0];
            old_span = self.tree[idx].span.clone();
            old_span.raw_range = raw_range;
            old_span.text_range = text_range;

            packed_next_sibling_of_run = self.tree[last].next_sibling;
            packed_seam_after = self.tree[last].doc_next;
            if let Some(parent) = self.tree[idx].parent {
                packed_run_is_last_child = self.tree[parent].last_child == Some(last);
            }
            for &s in &siblings[1..] {
                packed_orphans.push(s);
                self.collect_descendants(s, &mut packed_orphans);
            }
        }

        let field_number = old_span.field_number;
        let field_name = self.field_name_for(idx);

        // Resolve `target` into the synthetic field's declared `Type`
        // (spec 0135 G1's "second subtlety" + G3): a message FQDN yields
        // `Type::Group` only when the node's real wire framing is
        // `WT_START_GROUP`, else `Type::Message`; a primitive keyword
        // yields the matching primitive `Type` directly; `None` (raw)
        // yields no synthetic field at all.
        let (target_desc, field_type) = match &target {
            None => (None, None),
            Some(name) => {
                if let Some(desc) = self.ctx.pool().get_message_by_name(name) {
                    let ft = if old_span.wire_type == prototext_core::helpers::WT_START_GROUP {
                        Type::Group
                    } else {
                        Type::Message
                    };
                    (Some(desc), Some(ft))
                } else if let Some(prim) = decode::primitive_type_for_keyword(name) {
                    (None, Some(prim))
                } else {
                    return Err(format!("type '{name}' not found in descriptor set"));
                }
            }
        };

        // Decode `idx`'s own real tag+payload bytes directly (spec 0135
        // G1) — no synthetic tag prepended.
        let field_bytes = self.blob[old_span.raw_range.clone()].to_vec();

        // Render-cache key: `(interior_range, target)` — no longer
        // `field_name` (G2 makes the cached render field-name-invariant).
        // `interior_range` is the same "interior" quantity the cache
        // already keyed on before this spec, just computed from the
        // resolved `raw_range`, with `packed_record_start` always `None`
        // (the packed case has already been normalized above).
        let interior_range = extract::message_payload_range(&self.blob, &old_span.raw_range, None);
        let cache_key = (interior_range, target.clone());
        let (mut new_lines, new_spans, new_style_hints) = match self.render_cache.get(&cache_key) {
            Some(cached) => cached,
            None => {
                let wrapper_desc = match field_type {
                    Some(ft) => Some(
                        decode::register_wrapper(
                            self.ctx.pool_mut(),
                            field_number,
                            ft,
                            target_desc.as_ref(),
                        )
                        .map_err(|e| e.to_string())?,
                    ),
                    None => None,
                };
                let opts = DecodeRenderOpts {
                    // Always on (spec 0133): annotations are a pure
                    // main-pane display concern, not a decode-time input.
                    annotations: true,
                    indent_size: self.indent_size,
                    initial_level: old_span.level,
                    emit_header: false,
                    // Any/MessageSet expansion is handled by protolens
                    // itself, as automatic overrides (spec 0120), not by
                    // prototext-core's own virtual-node expansion.
                    expand_any: false,
                    expand_message_set: false,
                    ..Default::default()
                };
                let (new_text, new_spans) =
                    decode_and_render_indexed(&field_bytes, wrapper_desc.as_ref(), opts);
                let new_text = String::from_utf8(new_text)
                    .map_err(|e| format!("rendered text is not valid UTF-8: {e}"))?;
                let new_lines: Vec<String> = new_text.lines().map(str::to_string).collect();
                let new_style_hints = colorize::colorize(&new_text);
                let value = (new_lines, new_spans, new_style_hints);
                self.render_cache.insert(cache_key, value.clone());
                value
            }
        };

        // G2: the only remaining header patch is a plain substring
        // replacement of the synthetic field's placeholder name (`"_"`,
        // `register_wrapper`'s fixed literal) with the real display name
        // — the header line itself is otherwise already correct (spec
        // 0135 G1). No patch is needed at all for the raw (`target:
        // None`) case, since there is no synthetic field/placeholder
        // there. Nor for `Type::Group`: `TextSink::begin_nested` labels a
        // group header with the group's own message type name, never the
        // field's declared name — standard proto2 group text-format
        // convention — so the `"_"` placeholder is never actually
        // present there. Any group target that needs a display name
        // other than its own type name must instead be named that way
        // at the source (e.g. `register_message_set_item`'s synthetic
        // shape is itself named `Item`, matching `prototext-core`'s own
        // native MessageSet rendering convention) rather than patched
        // here after the fact.
        let mut new_line_styles = colorize::hints_by_line(&new_lines, &new_style_hints);
        if matches!(field_type, Some(ft) if ft != Type::Group) {
            new_lines[0] = new_lines[0].replacen('_', &field_name, 1);
            new_line_styles[0] =
                colorize::hints_by_line(&new_lines[..1], &colorize::colorize(&new_lines[0]))
                    .remove(0);
        }

        let delta = new_lines.len() as isize
            - (old_span.text_range.end - old_span.text_range.start) as isize;

        // Collect old descendants (pointer-based, before any pointer is
        // overwritten below) and scrub them from `folded` — otherwise
        // `rebuild_visible_rows` could read their now-meaningless stale
        // `text_range` and hide unrelated post-splice content. `idx`
        // itself is deliberately left in `folded` untouched (spec 0118
        // §7 — fold state on `idx` survives its own retype). For a
        // packed sibling merge, `packed_orphans` (siblings[1..] and their
        // own descendants) are unioned in too (spec 0135 G1).
        let mut old_descendants = Vec::new();
        self.collect_descendants(idx, &mut old_descendants);
        old_descendants.extend(packed_orphans);
        for d in &old_descendants {
            self.folded.remove(d);
        }
        let old_descendants: HashSet<usize> = old_descendants.into_iter().collect();

        // The live node immediately following the *whole* old subtree in
        // document order — the seam the new subtree must be spliced back
        // into. For a packed sibling merge this is `siblings.last()`'s
        // own `doc_next`, not `idx`'s (spec 0135 G1) — `idx` is now
        // `siblings[0]`, but the whole run is being replaced.
        let mut after = if is_packed {
            packed_seam_after
        } else {
            self.tree[idx].doc_next
        };
        while let Some(a) = after {
            if old_descendants.contains(&a) {
                after = self.tree[a].doc_next;
            } else {
                break;
            }
        }

        // Replace `idx`'s *whole* line range (header, interior, and
        // footer alike) — not just its interior, unlike the old
        // `apply_override`.
        self.lines.splice(
            old_span.text_range.start..old_span.text_range.end,
            new_lines,
        );
        self.line_styles.splice(
            old_span.text_range.start..old_span.text_range.end,
            new_line_styles,
        );

        // Translate the freshly built local tree (raw_range-relative
        // coordinates) into this document's global coordinates and append
        // it at the array's end. `build_tree` always emits a container's
        // own span last (post-order) — the local tree's final entry is
        // always idx's *new* self (the decoded field, whatever shape it
        // turned out to be); everything else is its descendants.
        let base = self.tree.len();
        let byte_offset = old_span.raw_range.start as isize;
        let local_len = new_spans.len();
        let local_root_idx = local_len - 1;
        let local_tree = decode::build_tree(new_spans);
        for node in local_tree {
            let mut span = node.span;
            span.raw_range = (span.raw_range.start as isize + byte_offset) as usize
                ..(span.raw_range.end as isize + byte_offset) as usize;
            span.text_range = (span.text_range.start + old_span.text_range.start)
                ..(span.text_range.end + old_span.text_range.start);
            let translate = |o: Option<usize>| o.map(|i| i + base);
            // `idx`'s new self is *not* pushed as a separate live entry
            // (its own span/children are folded into `self.tree[idx]`
            // below) — root-level local nodes (parent `None`) and its
            // direct children (local parent == the local root) both
            // become `idx`'s children, so both map their parent to `idx`.
            let parent = if node.parent.is_none() || node.parent == Some(local_root_idx) {
                Some(idx)
            } else {
                node.parent.map(|p| p + base)
            };
            self.tree.push(TreeNode {
                span,
                parent,
                first_child: translate(node.first_child),
                last_child: translate(node.last_child),
                next_sibling: translate(node.next_sibling),
                prev_sibling: translate(node.prev_sibling),
                doc_next: translate(node.doc_next),
                doc_prev: translate(node.doc_prev),
                rendered_as: None,
            });
        }

        // The pushed copy of the local root (at `new_self_idx`) is left
        // orphaned, never referenced again — its span/children are copied
        // into the live `idx` entry instead, same "abandon in place"
        // pattern already used for old descendants.
        let new_self_idx = base + local_root_idx;
        let mut new_self_span = self.tree[new_self_idx].span.clone();
        // Defensive restatement: byte-offset translation above already
        // reproduces `old_span.raw_range` exactly, since `field_bytes` is
        // `idx`'s complete original tag+payload span decoded as-is (spec
        // 0135 G1) — no synthetic tag ever separates the two.
        new_self_span.raw_range = old_span.raw_range.clone();
        self.tree[idx].span = new_self_span;
        self.tree[idx].first_child = self.tree[new_self_idx].first_child;
        self.tree[idx].last_child = self.tree[new_self_idx].last_child;

        // Packed sibling-merge pointer repair (spec 0135 G1): skip
        // `idx`'s sibling linkage past the absorbed run. `idx`'s own
        // `prev_sibling` and the parent's `first_child` need no change —
        // the run's leading edge is unaffected by absorbing what follows.
        if is_packed {
            self.tree[idx].next_sibling = packed_next_sibling_of_run;
            if let Some(next) = packed_next_sibling_of_run {
                self.tree[next].prev_sibling = Some(idx);
            }
            if packed_run_is_last_child {
                if let Some(parent) = self.tree[idx].parent {
                    self.tree[parent].last_child = Some(idx);
                }
            }
        }

        if local_len > 1 {
            let first_new = self.tree[new_self_idx].doc_next;
            let last_new = (base..base + local_len)
                .find(|&i| self.tree[i].doc_next.is_none())
                .expect("local tree with descendants has a document-order last node");
            self.tree[idx].doc_next = first_new;
            if let Some(fnw) = first_new {
                self.tree[fnw].doc_prev = Some(idx);
            }
            self.tree[last_new].doc_next = after;
            if let Some(a) = after {
                self.tree[a].doc_prev = Some(last_new);
            }
        } else {
            self.tree[idx].doc_next = after;
            if let Some(a) = after {
                self.tree[a].doc_prev = Some(idx);
            }
        }

        // Forward doc-chain shift: every node from `after` onward has its
        // own text_range shifted by `delta`.
        let mut cur = after;
        while let Some(c) = cur {
            let r = &mut self.tree[c].span.text_range;
            r.start = (r.start as isize + delta) as usize;
            r.end = (r.end as isize + delta) as usize;
            cur = self.tree[c].doc_next;
        }
        // Ancestor closing-brace-line shift: each ancestor's own opening
        // line is unaffected, only its closing line moves.
        let mut p = self.tree[idx].parent;
        while let Some(pi) = p {
            self.tree[pi].span.text_range.end =
                (self.tree[pi].span.text_range.end as isize + delta) as usize;
            p = self.tree[pi].parent;
        }

        // Full rebuild — walking the doc chain (not array order) so
        // orphaned entries are naturally excluded.
        self.line_to_node.clear();
        self.footer_line_to_node.clear();
        let mut cur = Some(self.first_node);
        while let Some(c) = cur {
            self.line_to_node
                .insert(self.tree[c].span.text_range.start, c);
            if self.tree[c].first_child.is_some() {
                self.footer_line_to_node
                    .insert(self.tree[c].span.text_range.end - 1, c);
            }
            cur = self.tree[c].doc_next;
        }
        self.rebuild_visible_rows();

        Ok(())
    }

    /// Every current sibling of `idx` that shares the same
    /// `packed_record_start` (spec 0135 G1) — i.e. every element of the
    /// same packed-repeated record, in document order. Always returns at
    /// least `idx` itself, even when `idx` has no parent.
    pub(super) fn packed_record_siblings(&self, idx: usize) -> Vec<usize> {
        let target = self.tree[idx].span.packed_record_start;
        let Some(parent) = self.tree[idx].parent else {
            return vec![idx];
        };
        let mut out = Vec::new();
        let mut c = self.tree[parent].first_child;
        while let Some(ci) = c {
            if self.tree[ci].span.packed_record_start == target {
                out.push(ci);
            }
            c = self.tree[ci].next_sibling;
        }
        out
    }

    /// The raw-byte and text-line extent of a packed record's whole run
    /// (spec 0135 G1), re-parsing the record's real tag+length from
    /// `packed_record_start` (mirroring `extract::message_payload_range`'s
    /// own packed-record handling). `siblings` must be non-empty and in
    /// document order, as returned by `packed_record_siblings`.
    pub(super) fn packed_record_extent(
        &self,
        siblings: &[usize],
    ) -> (std::ops::Range<usize>, std::ops::Range<usize>) {
        let start = self.tree[siblings[0]]
            .span
            .packed_record_start
            .expect("packed_record_extent called with non-packed siblings");
        let tag = prototext_core::helpers::parse_wiretag(&self.blob, start);
        let len = prototext_core::helpers::parse_varint(&self.blob, tag.next_pos);
        let raw_end = len.next_pos + len.varint.unwrap_or(0) as usize;
        let last = *siblings.last().expect("siblings never empty");
        let text_range =
            self.tree[siblings[0]].span.text_range.start..self.tree[last].span.text_range.end;
        (start..raw_end, text_range)
    }

    /// Origin for a brand-new override, targeting node `idx` — always
    /// created as kind `Path` (spec 0134 G1). Delegates to
    /// `origin_for_kind`.
    pub(super) fn override_origin_for_kind(&self, idx: usize) -> Result<OverrideOrigin, String> {
        self.origin_for_kind(idx, OverrideKind::Path)
    }

    /// Origin for an arbitrary `kind`, targeting node `idx` (spec 0117
    /// §2's derivation rules, generalized in spec 0124 G2 so the
    /// manage-pane `z` key can rederive an origin under a rotated kind).
    /// `PathField`/`FqdnField` error out when `idx` is the wrapper root
    /// (no parent) or, for `FqdnField`, when the parent's `type_fqdn` is
    /// unresolved.
    pub(super) fn origin_for_kind(
        &self,
        idx: usize,
        kind: OverrideKind,
    ) -> Result<OverrideOrigin, String> {
        match kind {
            OverrideKind::Path => Ok(OverrideOrigin::Path {
                path: self.positional_path(idx),
            }),
            OverrideKind::PathField => {
                let parent = self.tree[idx]
                    .parent
                    .ok_or_else(|| "cursor is the wrapper root (no parent)".to_string())?;
                Ok(OverrideOrigin::PathField {
                    path: self.positional_path(parent),
                    field: self.tree[idx].span.field_number,
                })
            }
            OverrideKind::FqdnField => {
                let parent = self.tree[idx]
                    .parent
                    .ok_or_else(|| "cursor is the wrapper root (no parent)".to_string())?;
                let fqdn = self.tree[parent]
                    .span
                    .type_fqdn
                    .clone()
                    .ok_or_else(|| "parent's type is unresolved".to_string())?;
                Ok(OverrideOrigin::FqdnField {
                    fqdn,
                    field: self.tree[idx].span.field_number,
                })
            }
        }
    }

    /// Third `OverrideKind` — the one that is neither `a` nor `b` (spec
    /// 0134 G2 step 5's `other_kind`; there are only 3 kinds total).
    pub(super) fn third_kind(a: OverrideKind, b: OverrideKind) -> OverrideKind {
        [
            OverrideKind::Path,
            OverrideKind::PathField,
            OverrideKind::FqdnField,
        ]
        .into_iter()
        .find(|k| *k != a && *k != b)
        .expect("3 kinds total, 2 excluded, 1 remains")
    }
}
