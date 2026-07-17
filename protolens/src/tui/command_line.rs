// SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

use super::*;

impl App {
    /// Edit the in-progress command-line buffer at `command_cursor`
    /// (a proper single-line text-input model — `Left`/`Right`/`Home`/`End`
    /// move it, `Backspace`/`Delete`/typing act relative to it), or
    /// execute/cancel the buffer. `Backspace` on an empty buffer cancels,
    /// matching vim's own command line.
    pub(super) fn handle_command_key(&mut self, key: KeyEvent) {
        // Any key other than Tab/Shift-Tab ends an in-progress completion
        // cycle (spec 0113 D26) — a fresh Tab press afterward starts a new
        // one from scratch, against whatever the buffer/cursor now are.
        if !matches!(key.code, KeyCode::Tab | KeyCode::BackTab) {
            self.completion = None;
        }
        match key.code {
            KeyCode::Tab if self.command_kind == CommandLineKind::Command => {
                self.handle_tab_key(true)
            }
            KeyCode::BackTab if self.command_kind == CommandLineKind::Command => {
                self.handle_tab_key(false)
            }
            KeyCode::Enter => {
                let buf = self.command_buffer.take().unwrap_or_default();
                self.command_cursor = 0;
                match self.command_kind {
                    CommandLineKind::Command => self.run_command(&buf),
                    // Vim convention: `/`/`?` confirmed with an empty
                    // pattern re-uses the last active pattern, searching
                    // in the newly chosen direction (which may differ
                    // from the direction that pattern was originally
                    // searched in — unlike `n`, which always repeats in
                    // the same direction as last time). Which pane's
                    // search actually runs is determined by whichever
                    // pane has focus right now — `override_focus`/
                    // `manage_focus` are untouched by typing into
                    // `command_buffer` (spec 0114 §4/0117 §3, extended by
                    // this rework to share the main pane's own bar).
                    CommandLineKind::Search(dir) if self.override_focus => {
                        let pattern = if buf.is_empty() {
                            self.last_override_search
                                .as_ref()
                                .map(|(_, p)| p.clone())
                                .unwrap_or(buf)
                        } else {
                            buf
                        };
                        self.last_override_search = Some((dir, pattern.clone()));
                        self.jump_to_override_match(dir, &pattern);
                    }
                    CommandLineKind::Search(dir) if self.manage_open && self.manage_focus => {
                        let pattern = if buf.is_empty() {
                            self.last_manage_search
                                .as_ref()
                                .map(|(_, p)| p.clone())
                                .unwrap_or(buf)
                        } else {
                            buf
                        };
                        self.last_manage_search = Some((dir, pattern.clone()));
                        self.jump_to_manage_match(dir, &pattern);
                    }
                    CommandLineKind::Search(dir) => {
                        let pattern = if buf.is_empty() {
                            self.last_search
                                .as_ref()
                                .map(|(_, p)| p.clone())
                                .unwrap_or(buf)
                        } else {
                            buf
                        };
                        self.last_search = Some((dir, pattern.clone()));
                        self.jump_to_match(dir, &pattern);
                    }
                }
            }
            KeyCode::Esc => {
                self.command_buffer = None;
                self.command_cursor = 0;
                self.message.clear();
            }
            KeyCode::Left => self.command_cursor = self.command_cursor.saturating_sub(1),
            KeyCode::Right => {
                let len = self.command_buffer_char_len();
                self.command_cursor = (self.command_cursor + 1).min(len);
            }
            KeyCode::Home => self.command_cursor = 0,
            KeyCode::End => self.command_cursor = self.command_buffer_char_len(),
            KeyCode::Backspace => {
                let empty = match &self.command_buffer {
                    Some(buf) => buf.is_empty(),
                    None => true,
                };
                if empty {
                    self.command_buffer = None;
                    self.command_cursor = 0;
                } else if self.command_cursor > 0 {
                    self.command_cursor -= 1;
                    self.remove_char_at(self.command_cursor);
                }
            }
            KeyCode::Delete => {
                if self.command_cursor < self.command_buffer_char_len() {
                    self.remove_char_at(self.command_cursor);
                }
            }
            KeyCode::Char(c) => {
                let byte_idx = self.char_byte_index(self.command_cursor);
                if let Some(buf) = self.command_buffer.as_mut() {
                    buf.insert(byte_idx, c);
                }
                self.command_cursor += 1;
            }
            _ => {}
        }
    }

    /// `Tab` (`forward`)/`Shift-Tab` (`!forward`) in the command line (spec
    /// 0113 D26): continue an already-cycling completion, or start a new
    /// one against the current token.
    pub(super) fn handle_tab_key(&mut self, forward: bool) {
        if let Some(state) = &self.completion {
            if state.candidates.len() > 1 {
                let n = state.candidates.len();
                let new_index = match state.index {
                    Some(i) if forward => (i + 1) % n,
                    Some(i) => (i + n - 1) % n,
                    None if forward => 0,
                    None => n - 1,
                };
                let candidate = state.candidates[new_index].clone();
                let token_start = state.token_start;
                let suffix = state.suffix.clone();
                self.replace_token(token_start, &suffix, &candidate);
                if let Some(state) = &mut self.completion {
                    state.index = Some(new_index);
                }
                return;
            }
        }
        self.start_tab_completion();
    }

    /// Complete the token the cursor currently sits in: the first token
    /// (the command name, before any space) always; the second token, once
    /// exactly one space precedes the cursor, only when the first token
    /// has already unambiguously resolved to `type-as` (spec 0114 §7) — an
    /// FQDN argument, completed against `all_type_fqdns`. Anywhere else
    /// (past `type-as`'s single argument, or a second token following any
    /// other command) is a silent no-op.
    pub(super) fn start_tab_completion(&mut self) {
        let buf = self.command_buffer.clone().unwrap_or_default();
        let cursor_byte = self.char_byte_index(self.command_cursor);
        let prefix = &buf[..cursor_byte];
        match prefix.split_once(' ') {
            None => self.complete_command_name(prefix),
            Some((cmd, arg_prefix))
                if !arg_prefix.contains(' ') && resolve_command(cmd) == Ok("type-as") =>
            {
                self.complete_type_as_fqdn(cmd, arg_prefix);
            }
            Some((cmd, arg_prefix))
                if matches!(
                    resolve_command(cmd),
                    Ok("save-overrides") | Ok("restore-overrides")
                ) =>
            {
                self.complete_fs_path(cmd, arg_prefix);
            }
            Some(_) => {}
        }
    }

    /// First-token (command-name) completion — see `start_tab_completion`.
    pub(super) fn complete_command_name(&mut self, prefix: &str) {
        let mut matches = complete_prefix(prefix, COMMANDS.iter().copied());
        if matches.is_empty() {
            self.message = format!("no command matches '{prefix}'");
            return;
        }
        matches.sort_unstable();
        let candidates: Vec<String> = matches.into_iter().map(String::from).collect();
        self.apply_completion(0, prefix.chars().count(), candidates);
    }

    /// `:type-as <FQDN>`'s argument completion (spec 0114 §7) — candidates
    /// are `all_type_fqdns` (the same session-global, lexicographically-
    /// sorted list §3.2/§6 already compute and cache), reused here rather
    /// than recomputed, plus (spec 0135 §G4) the primitive type keywords
    /// wire-compatible with the cursor node's current wire type (a packed
    /// element's own effective wire type is always `WT_LEN`, per its
    /// reconstructed record — spec 0135 §G1).
    pub(super) fn complete_type_as_fqdn(&mut self, cmd: &str, arg_prefix: &str) {
        let span = &self.tree[self.cursor].span;
        let wire_type = if span.packed_record_start.is_some() {
            prototext_core::helpers::WT_LEN
        } else {
            span.wire_type
        };
        // Collected into owned `String`s upfront (rather than borrowing
        // `self.all_type_fqdns` for `matches`'s lifetime) so the
        // subsequent `self.replace_token`/`self.completion = ...` calls
        // below aren't blocked by a live immutable borrow of `self`.
        let candidates = decode::primitive_keywords_for_wire_type(wire_type)
            .iter()
            .copied()
            .chain(self.all_type_fqdns.iter().map(String::as_str));
        let mut matches: Vec<String> = complete_prefix(arg_prefix, candidates)
            .into_iter()
            .map(String::from)
            .collect();
        if matches.is_empty() {
            self.message = format!("no type matches '{arg_prefix}'");
            return;
        }
        matches.sort_unstable();
        let token_start = cmd.chars().count() + 1;
        self.apply_completion(token_start, arg_prefix.chars().count(), matches);
    }

    /// `:save-overrides`/`:restore-overrides`'s argument completion (spec
    /// 0117 §4) — candidates are `std::fs::read_dir`'s entries for the
    /// argument's directory portion (everything up to and including its
    /// last `/`, or the current directory if there is none), filtered by
    /// its final path segment; directory entries get a trailing `/`
    /// appended, so a further Tab press descends into them. No
    /// `!arg_prefix.contains(' ')` guard, unlike `complete_type_as_fqdn` —
    /// a path argument is everything after the command name's single
    /// space, embedded spaces included.
    pub(super) fn complete_fs_path(&mut self, cmd: &str, arg_prefix: &str) {
        let (dir_part, file_prefix) = match arg_prefix.rfind('/') {
            Some(i) => (&arg_prefix[..=i], &arg_prefix[i + 1..]),
            None => ("", arg_prefix),
        };
        let read_dir_path = if dir_part.is_empty() {
            Path::new(".")
        } else {
            Path::new(dir_part)
        };
        let entries = match std::fs::read_dir(read_dir_path) {
            Ok(rd) => rd,
            Err(e) => {
                self.message = format!("cannot list '{}': {e}", read_dir_path.display());
                return;
            }
        };
        let mut matches: Vec<String> = Vec::new();
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if !name.starts_with(file_prefix) {
                continue;
            }
            let is_dir = entry.file_type().map(|t| t.is_dir()).unwrap_or(false);
            let mut candidate = format!("{dir_part}{name}");
            if is_dir {
                candidate.push('/');
            }
            matches.push(candidate);
        }
        if matches.is_empty() {
            self.message = format!("no path matches '{arg_prefix}'");
            return;
        }
        matches.sort_unstable();
        let token_start = cmd.chars().count() + 1;
        self.apply_completion(token_start, arg_prefix.chars().count(), matches);
    }

    /// Shared tail of Tab-completion (spec 0114 §7): `candidates` (already
    /// filtered/sorted by the caller) either replaces the in-progress
    /// token outright (a single candidate) or extends it to the longest
    /// common prefix, stashing `candidates` in `self.completion` for a
    /// subsequent Tab press to cycle through (spec 0113 D26). `prefix_len`
    /// is the char length of what the user already typed, used to decide
    /// whether the LCP actually extends it.
    fn apply_completion(&mut self, token_start: usize, prefix_len: usize, candidates: Vec<String>) {
        let cursor_byte = self.char_byte_index(self.command_cursor);
        let buf = self.command_buffer.clone().unwrap_or_default();
        let suffix = buf[cursor_byte..].to_string();
        if candidates.len() == 1 {
            self.replace_token(token_start, &suffix, &candidates[0]);
            return;
        }
        let refs: Vec<&str> = candidates.iter().map(String::as_str).collect();
        let lcp = longest_common_prefix(&refs);
        if lcp.chars().count() > prefix_len {
            self.replace_token(token_start, &suffix, &lcp);
        }
        self.completion = Some(CompletionState {
            token_start,
            suffix,
            candidates,
            index: None,
        });
    }

    /// Replace `command_buffer[token_start..command_cursor]` with
    /// `replacement`, re-appending `suffix` (the text that originally
    /// followed the token) verbatim, and move the cursor to just past the
    /// replacement.
    pub(super) fn replace_token(&mut self, token_start: usize, suffix: &str, replacement: &str) {
        let start_byte = self.char_byte_index(token_start);
        let mut new_buf = String::with_capacity(start_byte + replacement.len() + suffix.len());
        if let Some(buf) = &self.command_buffer {
            new_buf.push_str(&buf[..start_byte]);
        }
        new_buf.push_str(replacement);
        new_buf.push_str(suffix);
        self.command_cursor = token_start + replacement.chars().count();
        self.command_buffer = Some(new_buf);
    }

    pub(super) fn command_buffer_char_len(&self) -> usize {
        self.command_buffer
            .as_deref()
            .map(|b| b.chars().count())
            .unwrap_or(0)
    }

    /// Byte offset in `command_buffer` of the `char_idx`-th character (or
    /// the buffer's end, if `char_idx` is at/past its length).
    pub(super) fn char_byte_index(&self, char_idx: usize) -> usize {
        let buf = self.command_buffer.as_deref().unwrap_or("");
        buf.char_indices()
            .nth(char_idx)
            .map(|(i, _)| i)
            .unwrap_or(buf.len())
    }

    /// Remove the character at char index `char_idx` from `command_buffer`.
    pub(super) fn remove_char_at(&mut self, char_idx: usize) {
        let byte_idx = self.char_byte_index(char_idx);
        if let Some(buf) = self.command_buffer.as_mut() {
            if byte_idx < buf.len() {
                buf.remove(byte_idx);
            }
        }
    }

    pub(super) fn run_command(&mut self, cmd: &str) {
        let mut tokens = cmd.split_whitespace();
        let Some(name) = tokens.next() else {
            return;
        };
        match resolve_command(name) {
            Ok("extract") => self.run_extract(tokens.collect()),
            // Item 9 (2026-07-17 feedback): `:quit` (or any unambiguous
            // prefix, e.g. `:q` — no other command starts with `q`)
            // quits directly, same effect as confirming `q` twice —
            // typing the full command out is itself the deliberate
            // action `qq`'s second press otherwise confirms.
            Ok("quit") => self.should_quit = true,
            Ok("type-as") => self.run_type_as(tokens.collect()),
            Ok("type-as-raw") => self.run_type_as_raw(),
            Ok("save-overrides") => self.run_save_overrides(tokens.collect()),
            Ok("restore-overrides") => self.run_restore_overrides(tokens.collect()),
            Ok(other) => unreachable!("resolve_command returned unregistered command: {other}"),
            Err(e) => self.message = e,
        }
    }

    /// `type-as <FQDN>` — apply `FQDN` as the cursor node's type override,
    /// bypassing the override pane entirely (spec 0114 Goal 4/§5/§7). Same
    /// validation/application as picking a ranked candidate from the pane.
    pub(super) fn run_type_as(&mut self, args: Vec<&str>) {
        if args.is_empty() {
            self.message = "type-as: missing type FQDN".to_string();
            return;
        }
        let fqdn = args.join(" ");
        self.message = match self.type_as(Some(&fqdn)) {
            Ok(()) => format!("overridden as {fqdn}"),
            Err(e) => e,
        };
    }

    /// `type-as-raw` — mark the cursor node's range as explicitly raw/
    /// unschema'd (spec 0114 §3.1/§5/§7), bypassing the override pane.
    pub(super) fn run_type_as_raw(&mut self) {
        self.message = match self.type_as(None) {
            Ok(()) => "overridden as raw".to_string(),
            Err(e) => e,
        };
    }

    /// Shared application logic for `type-as`/`type-as-raw` (spec 0114 §5
    /// step 1, spec 0118 §6): validates the cursor is on an eligible node
    /// (`can_override`, §1) — same refusal `t` gives — then activates a
    /// `Path`-kind override for the cursor node's positional path and
    /// runs the recursive `render_overrides` pass (§4/§6), without ever
    /// opening the override pane. Unlike the old `apply_override`-based
    /// one-shot splice, this persists the override in the collection.
    ///
    /// A primitive type keyword (spec 0135 §G3/§G4) is rejected upfront,
    /// before `render_overrides` runs, when it isn't wire-compatible with
    /// the cursor node's current wire type (a packed element's own
    /// effective wire type is always `WT_LEN`, per its reconstructed
    /// record — spec 0135 §G1) — mirroring today's "type not found"
    /// failure shape, but caught early so it surfaces as a clear
    /// message-line error rather than being masked by `run_type_as`'s
    /// own success message. A message-FQDN target falls back to today's
    /// (unchanged) deferred resolution inside `splice_override`.
    pub(super) fn type_as(&mut self, new_fqdn: Option<&str>) -> Result<(), String> {
        if !self.can_override(self.cursor) {
            return Err(
                "cannot override: not a message/group or length-delimited field".to_string(),
            );
        }
        if let Some(name) = new_fqdn {
            if decode::primitive_type_for_keyword(name).is_some() {
                let span = &self.tree[self.cursor].span;
                let wire_type = if span.packed_record_start.is_some() {
                    prototext_core::helpers::WT_LEN
                } else {
                    span.wire_type
                };
                if !decode::primitive_keywords_for_wire_type(wire_type).contains(&name) {
                    return Err(format!(
                        "type '{name}' not wire-compatible with this node's wire type"
                    ));
                }
            }
        }
        let origin = OverrideOrigin::Path {
            path: self.positional_path(self.cursor),
        };
        self.overrides.activate(origin, new_fqdn.map(String::from));
        self.render_overrides(self.first_node);
        Ok(())
    }

    /// `extract [--binary|--text] <path>` — default format is `#@ prototext`
    /// text (0113 D21); the underlying render always carries full
    /// annotations now (spec 0133), so there's no longer a binary-default
    /// fallback case.
    pub(super) fn run_extract(&mut self, args: Vec<&str>) {
        let mut format = ExtractFormat::Text;
        let mut path_parts = Vec::new();
        for a in args {
            match a {
                "--binary" => format = ExtractFormat::Binary,
                "--text" => format = ExtractFormat::Text,
                other => path_parts.push(other),
            }
        }
        if path_parts.is_empty() {
            self.message = "extract: missing path".to_string();
            return;
        }
        let path = path_parts.join(" ");
        let node = &self.tree[self.cursor];
        match extract::extract(Path::new(&path), format, &self.blob, &self.lines, node) {
            Ok(()) => self.message = format!("extracted to {path}"),
            Err(e) => self.message = format!("extract error: {e}"),
        }
    }

    /// `idx`'s extracted rendering, in the requested format — the
    /// byte-vector counterpart to `run_extract`'s file-writing TUI
    /// command, for a caller with no `Path` to write to (spec 0123's
    /// batch mode, writing to stdout or an explicit `-o`/`--output`).
    pub(crate) fn extract_bytes(&self, idx: usize, format: ExtractFormat) -> Vec<u8> {
        extract::extract_bytes(format, &self.blob, &self.lines, &self.tree[idx])
    }

    /// Propose a default `:save-overrides` path — same directory/stem as
    /// the target blob, `.yaml` extension (spec 0117 §4, mirroring
    /// `default_extract_path`).
    pub(super) fn default_save_overrides_path(&self) -> String {
        let stem = self
            .blob_path
            .file_stem()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| "overrides".to_string());
        let filename = format!("{stem}.yaml");
        match self.blob_path.parent() {
            Some(dir) if !dir.as_os_str().is_empty() => {
                dir.join(filename).to_string_lossy().into_owned()
            }
            _ => filename,
        }
    }

    /// SHA-256 hex digests of the currently-loaded blob/descriptor set,
    /// canonicalized-binary bytes (spec 0117 §4's `blob_sha256`/
    /// `descriptor_set_sha256`) — the caller's original (pre-wrap) blob,
    /// and the descriptor set's own canonicalized bytes (`ctx.raw_bytes`).
    pub(super) fn target_hashes(&self) -> (String, String) {
        let blob_sha256 = override_pane::sha256_hex(&self.blob[self.wrapper_offset..]);
        let descriptor_set_sha256 = override_pane::sha256_hex(&self.ctx.raw_bytes);
        (blob_sha256, descriptor_set_sha256)
    }

    /// `idx`'s `pos`-th child (1-based, document order) — the sibling-chain
    /// counterpart to `sibling_position`.
    pub(super) fn nth_child(&self, idx: usize, pos: usize) -> Option<usize> {
        let mut cur = self.tree[idx].first_child;
        for _ in 1..pos {
            cur = cur.and_then(|c| self.tree[c].next_sibling);
        }
        cur
    }

    /// Inverse of `positional_path`: resolves a canonical `/1/2/3`-style
    /// path (or bare `/` for the wrapper root) back to a tree index.
    /// `None` if any segment doesn't parse as a 1-based position, or
    /// doesn't resolve against the current tree (spec 0117 §4 restore-time
    /// validation). `pub(crate)`: also reused by `main.rs`'s batch `extract`
    /// subcommand (spec 0123) to resolve its `path` argument.
    pub(crate) fn resolve_path(&self, path: &str) -> Option<usize> {
        let root = self.tree.iter().position(|n| n.parent.is_none())?;
        if path == "/" {
            return Some(root);
        }
        let mut cur = root;
        for seg in path.trim_start_matches('/').split('/') {
            let pos: usize = seg.parse().ok()?;
            cur = self.nth_child(cur, pos)?;
        }
        Some(cur)
    }

    /// Whether `origin` resolves against the currently-loaded tree/
    /// descriptor pool (spec 0117 §4 restore-time validation): `Path`
    /// needs the path to resolve to a node; `PathField` additionally
    /// needs that node to have at least one child with the given field
    /// number; `FqdnField` needs the FQDN to resolve in the descriptor
    /// pool and that message to declare the given field number.
    pub(super) fn origin_resolves(&self, origin: &OverrideOrigin) -> bool {
        match origin {
            OverrideOrigin::Path { path } => self.resolve_path(path).is_some(),
            OverrideOrigin::PathField { path, field } => match self.resolve_path(path) {
                Some(idx) => {
                    let mut child = self.tree[idx].first_child;
                    while let Some(c) = child {
                        if self.tree[c].span.field_number == *field {
                            return true;
                        }
                        child = self.tree[c].next_sibling;
                    }
                    false
                }
                None => false,
            },
            OverrideOrigin::FqdnField { fqdn, field } => self
                .ctx
                .pool()
                .get_message_by_name(fqdn)
                .and_then(|m| m.get_field(*field as u32))
                .is_some(),
        }
    }

    /// `save-overrides <path>` (spec 0117 §4): writes the entire
    /// collection, plus the current target's hashes, to `<path>` as YAML.
    pub(super) fn run_save_overrides(&mut self, args: Vec<&str>) {
        if args.is_empty() {
            self.message = "save-overrides: missing path".to_string();
            return;
        }
        let path = args.join(" ");
        let (blob_sha256, descriptor_set_sha256) = self.target_hashes();
        let yaml = self.overrides.to_yaml(blob_sha256, descriptor_set_sha256);
        match std::fs::write(&path, yaml) {
            Ok(()) => self.message = format!("saved overrides to {path}"),
            Err(e) => self.message = format!("save-overrides error: {e}"),
        }
    }

    /// Shared core of `restore-overrides`/batch `--load-overrides` (spec
    /// 0117 §4, spec 0123 G4): loads and parses the YAML override
    /// collection at `path`, silently drops any entry that doesn't
    /// resolve against the current tree/descriptor pool, then replaces
    /// `self.overrides` wholesale and re-renders (spec 0118 §6:
    /// replacing the whole collection can change the resolved override
    /// for any node). Returns the list of non-blocking hash-mismatch
    /// warnings (empty if none) on success — a hash mismatch alone is
    /// never a failure — or `Err(diagnostic)` if the file couldn't be
    /// read or parsed as valid YAML in the first place, which the two
    /// callers (`run_restore_overrides`, batch mode) treat differently:
    /// the TUI just displays it and keeps running; batch mode (spec 0123
    /// G4) treats it as a hard error.
    pub(crate) fn load_overrides(&mut self, path: &str) -> Result<Vec<&'static str>, String> {
        let text = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
        let (mut collection, target) = override_pane::OverrideCollection::from_yaml(&text)?;
        collection.retain_resolvable(|origin| self.origin_resolves(origin));
        let (blob_sha256, descriptor_set_sha256) = self.target_hashes();
        let mut warnings = Vec::new();
        if target.blob_sha256 != blob_sha256 {
            warnings.push("blob hash mismatch");
        }
        if target.descriptor_set_sha256 != descriptor_set_sha256 {
            warnings.push("descriptor-set hash mismatch");
        }
        // The document root's own type is external input (CLI `--type`,
        // auto-inference, or an interactive retype) — unlike every other
        // node, it's never re-derivable from the schema once lost, since
        // `natural_type` infers a node's type by walking up to its
        // *parent's* resolved field descriptor, and root has no parent.
        // It must therefore survive a wholesale collection replace as a
        // persistent baseline entry — otherwise root (and, transitively,
        // every schema-typed descendant whose own `natural_type` walks
        // back up through it) silently reverts to raw rendering, even
        // though the loaded file's own explicit overrides are all
        // individually intact. Preserve the currently-resolved root type
        // unless the loaded file defines its own active root entry.
        let root_origin = OverrideOrigin::Path {
            path: "/".to_string(),
        };
        let has_root_entry = collection
            .entries()
            .iter()
            .any(|e| e.active && e.origin == root_origin);
        let current_root_type = self.resolve_active_override(self.first_node).flatten();
        self.overrides = collection;
        if !has_root_entry {
            self.overrides.seed_root(current_root_type);
        }
        self.render_overrides(self.first_node);
        self.manage_highlight = 0;
        self.manage_scroll = 0;
        self.manage_pan_offset = 0;
        self.manage_pending_kind = None;
        Ok(warnings)
    }

    /// `restore-overrides <path>` (spec 0117 §4): replaces the collection
    /// wholesale with `<path>`'s contents — see `load_overrides`.
    pub(super) fn run_restore_overrides(&mut self, args: Vec<&str>) {
        if args.is_empty() {
            self.message = "restore-overrides: missing path".to_string();
            return;
        }
        let path = args.join(" ");
        self.message = match self.load_overrides(&path) {
            Ok(warnings) if warnings.is_empty() => format!("restored overrides from {path}"),
            Ok(warnings) => format!(
                "restored overrides from {path} (warning: {})",
                warnings.join(", ")
            ),
            Err(e) => format!("restore-overrides error: {e}"),
        };
    }
}
