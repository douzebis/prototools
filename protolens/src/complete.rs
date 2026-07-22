// SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

//! Dynamic shell completion — mirrors `prototext`'s own `complete.rs`
//! (`prototext/src/complete.rs`).
//!
//! `complete_type_names` scans the partially-typed command line for
//! `--descriptor-set`, reads that descriptor file, and lists its message
//! type names filtered by the prefix typed so far.
//!
//! `complete_path_under` (and its thin wrappers) provide path completion
//! for `--descriptor-set`, `--proto-root`, and the positional `blob`
//! argument, in place of clap_complete's built-in default path completer.
//! That built-in completer self-appends a trailing `/` to directory
//! candidates (`clap_complete::engine::custom::complete_path`), which
//! collides with the shell's own directory marking and produces a
//! doubled `//`. Omitting the trailing slash here — letting the shell add
//! it alone — avoids the stutter.

use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};

use clap_complete::engine::CompletionCandidate;
use prototext_core::decode_pool;

use crate::decode::read_descriptor_file;

// ── Partial-args scanner ──────────────────────────────────────────────────────

/// Scan the partial command line (`std::env::args_os`, post `--`) for a flag
/// with a value. Returns the value of the last occurrence of `long`, e.g.
/// `flag_value_from_args("--descriptor-set")`.
///
/// When the shell invokes the binary for completion it passes all
/// already-typed words as argv after a `--` sentinel, so `args_os()` is
/// safe to read here.
fn flag_value_from_args(long: &str) -> Option<OsString> {
    let mut args = std::env::args_os().peekable();
    for a in args.by_ref() {
        if a == "--" {
            break;
        }
    }
    let mut found = None;
    while let Some(a) = args.next() {
        let s = a.to_string_lossy();
        // --flag VALUE (value as a separate token)
        if s == long {
            if let Some(val) = args.next() {
                found = Some(val);
            }
        }
        // --flag=VALUE
        else if let Some(rest) = s.strip_prefix(&format!("{long}=")) {
            found = Some(OsString::from(rest));
        }
    }
    found
}

/// Complete message type names for `--type`, reading whichever
/// `--descriptor-set` was already typed on the partial command line.
/// Empty if `--descriptor-set` is missing, unreadable, or invalid.
pub fn complete_type_names(incomplete: &OsStr) -> Vec<CompletionCandidate> {
    let Some(path) = flag_value_from_args("--descriptor-set") else {
        return vec![];
    };
    let Ok(bytes) = read_descriptor_file(Path::new(&path)) else {
        return vec![];
    };
    let Ok(pool) = decode_pool(&bytes) else {
        return vec![];
    };

    let prefix = incomplete.to_string_lossy();
    pool.all_messages()
        .map(|m| m.full_name().to_string())
        .filter(|name| name.starts_with(prefix.as_ref()))
        .map(CompletionCandidate::new)
        .collect()
}

// ── Filesystem listing helpers ────────────────────────────────────────────────

/// Complete paths under `base` (the effective root directory), mirroring
/// clap_complete's own `complete_path` logic.
///
/// - `incomplete` is the raw token the user has typed so far.
/// - Its directory part is resolved relative to `base`; its filename part
///   is used as a prefix filter on directory entries.
/// - Directories and files are both returned, without a trailing `/` on
///   directories — the shell adds it on its own.
/// - Each candidate is the full value to insert (same format as the
///   built-in `PathCompleter`).
fn complete_path_under(
    incomplete: &OsStr,
    base: &Path,
    dirs_only: bool,
) -> Vec<CompletionCandidate> {
    let s = incomplete.to_string_lossy();
    let incomplete_path = Path::new(incomplete);

    // Split into the already-typed directory prefix and the partial
    // filename. A trailing `/` means the user has completed a directory
    // name and wants its contents — treat the whole token as the prefix
    // with an empty stem.
    let (typed_prefix, filename_stem) = if s.ends_with('/') {
        (incomplete_path.to_path_buf(), String::new())
    } else {
        let parent = incomplete_path.parent().unwrap_or(Path::new(""));
        let stem = incomplete_path
            .file_name()
            .unwrap_or(OsStr::new(""))
            .to_string_lossy()
            .into_owned();
        (parent.to_path_buf(), stem)
    };

    let search_root = base.join(&typed_prefix);

    let Ok(rd) = std::fs::read_dir(&search_root) else {
        return vec![];
    };

    let mut completions: Vec<CompletionCandidate> = rd
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().starts_with(&filename_stem))
        .filter_map(|e| {
            let name = e.file_name();
            let ft = e.file_type().ok()?;
            if ft.is_dir() {
                // No trailing slash — the shell adds it.
                let p = typed_prefix.join(&name);
                Some(CompletionCandidate::new(p.as_os_str().to_os_string()))
            } else if ft.is_file() && !dirs_only {
                let p = typed_prefix.join(&name);
                Some(CompletionCandidate::new(p.as_os_str().to_os_string()))
            } else {
                None
            }
        })
        .collect();

    completions.sort_by(|a, b| a.get_value().cmp(b.get_value()));
    completions
}

/// Complete any file or directory path relative to cwd.
pub fn complete_any_path(incomplete: &OsStr) -> Vec<CompletionCandidate> {
    let base = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    complete_path_under(incomplete, &base, false)
}

/// Complete directory paths only relative to cwd.
pub fn complete_dir_path(incomplete: &OsStr) -> Vec<CompletionCandidate> {
    let base = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    complete_path_under(incomplete, &base, true)
}
