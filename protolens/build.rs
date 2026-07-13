// SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

//! Build script: link the Nix-built `tree-sitter-textproto` static library.
//!
//! `nix/rust.nix`'s `commonArgs.env` (Nix builds) and `nix/shells.nix`'s
//! `_hook_rust` (manual `nix-shell` builds) both export
//! `TREE_SITTER_TEXTPROTO_LIB_DIR`/`TREE_SITTER_TEXTPROTO_QUERIES_DIR`,
//! pointing at `treeSitterTextprotoRustLib`'s `lib/`/`queries/` output
//! (spec 0116 §7). This script never compiles C or runs `tree-sitter
//! generate` itself — that already happened in Nix; it only emits the
//! linker flags and forwards the queries dir to `colorize.rs` via
//! `env!()`.

fn main() {
    let lib_dir = std::env::var("TREE_SITTER_TEXTPROTO_LIB_DIR")
        .expect("TREE_SITTER_TEXTPROTO_LIB_DIR not set — see nix/rust.nix / nix/shells.nix");
    let queries_dir = std::env::var("TREE_SITTER_TEXTPROTO_QUERIES_DIR")
        .expect("TREE_SITTER_TEXTPROTO_QUERIES_DIR not set — see nix/rust.nix / nix/shells.nix");

    println!("cargo:rustc-link-search=native={lib_dir}");
    println!("cargo:rustc-link-lib=static=tree-sitter-textproto");

    // Forwarded to compile-time `env!()` so `colorize.rs` can
    // `include_str!(concat!(env!("TREE_SITTER_TEXTPROTO_QUERIES_DIR"), "/highlights.scm"))`.
    println!("cargo:rustc-env=TREE_SITTER_TEXTPROTO_QUERIES_DIR={queries_dir}");

    println!("cargo:rerun-if-env-changed=TREE_SITTER_TEXTPROTO_LIB_DIR");
    println!("cargo:rerun-if-env-changed=TREE_SITTER_TEXTPROTO_QUERIES_DIR");
}
