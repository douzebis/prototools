// SPDX-FileCopyrightText: 2025-2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
// SPDX-FileCopyrightText: 2025-2026 Thales Cloud Sécurisé
//
// SPDX-License-Identifier: MIT

//! Build script: compile `enum_collision.proto` into `$OUT_DIR/enum_collision.pb`
//! for use by unit tests in this crate.

use prost::Message as _;

fn main() {
    let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR not set");
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set");
    // Proto sources live in the sibling prototext crate.
    let schemas_dir = format!("{manifest_dir}/../prototext/fixtures/schemas");

    let descriptor = protox::compile(&["enum_collision.proto"], &[&schemas_dir])
        .unwrap_or_else(|e| panic!("failed to compile enum_collision.proto: {e}"));
    let bytes = descriptor.encode_to_vec();
    std::fs::write(format!("{out_dir}/enum_collision.pb"), bytes)
        .unwrap_or_else(|e| panic!("failed to write enum_collision.pb: {e}"));

    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=../prototext/fixtures/schemas/enum_collision.proto");
}
