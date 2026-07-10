// SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

//! Dynamic shell completion for `--type` — mirrors `prototext`'s own
//! `complete.rs` (`prototext/src/complete.rs`): scans the partially-typed
//! command line for `--descriptor-set`, reads that descriptor file, and
//! lists its message type names filtered by the prefix typed so far.

use std::ffi::{OsStr, OsString};
use std::path::Path;

use clap_complete::engine::CompletionCandidate;
use prototext_core::decode_pool;

use crate::decode::read_descriptor_file;

/// Scan the partial command line (`std::env::args_os`, post `--`) for
/// `--descriptor-set`'s value. Returns the value of its last occurrence.
///
/// When the shell invokes the binary for completion it passes all
/// already-typed words as argv after a `--` sentinel, so `args_os()` is
/// safe to read here.
fn descriptor_set_from_args() -> Option<OsString> {
    let mut args = std::env::args_os().peekable();
    for a in args.by_ref() {
        if a == "--" {
            break;
        }
    }
    let mut found = None;
    while let Some(a) = args.next() {
        let s = a.to_string_lossy();
        // --descriptor-set VALUE (value as a separate token)
        if s == "--descriptor-set" {
            if let Some(val) = args.next() {
                found = Some(val);
            }
        }
        // --descriptor-set=VALUE
        else if let Some(rest) = s.strip_prefix("--descriptor-set=") {
            found = Some(OsString::from(rest));
        }
    }
    found
}

/// Complete message type names for `--type`, reading whichever
/// `--descriptor-set` was already typed on the partial command line.
/// Empty if `--descriptor-set` is missing, unreadable, or invalid.
pub fn complete_type_names(incomplete: &OsStr) -> Vec<CompletionCandidate> {
    let Some(path) = descriptor_set_from_args() else {
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
