// SPDX-FileCopyrightText: 2025 - 2026 Frederic Ruget <fred@atlant.is> <fred@s3ns.io> (GitHub: @douzebis)
// SPDX-FileCopyrightText: 2025 - 2026 Thales Cloud Sécurisé
//
// SPDX-License-Identifier: MIT

//! Build script: compile proto schemas into `$OUT_DIR/*.pb` using `protox`
//! (pure-Rust protobuf compiler — no system `protoc` required).
//!
//! Files generated:
//!   - `descriptor.pb`    — FileDescriptorSet for google/protobuf/descriptor.proto
//!   - `knife.pb`         — FileDescriptorSet for fixtures/schemas/knife.proto
//!   - `enum_collision.pb`— FileDescriptorSet for fixtures/schemas/enum_collision.proto
//!
//! `descriptor.pb` is embedded into the binary at compile time via:
//!   `include_bytes!(concat!(env!("OUT_DIR"), "/descriptor.pb"))`
//!
//! `knife.pb` and `enum_collision.pb` are used by integration tests only.

use prost::Message as _;

fn compile(files: &[&str], includes: &[&str], out_dir: &str, out_name: &str) {
    let descriptor = protox::compile(files, includes)
        .unwrap_or_else(|e| panic!("failed to compile {files:?}: {e}"));
    let bytes = descriptor.encode_to_vec();
    std::fs::write(format!("{out_dir}/{out_name}"), bytes)
        .unwrap_or_else(|e| panic!("failed to write {out_name}: {e}"));
}

fn main() {
    let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR not set");
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set");
    let schemas_dir = format!("{manifest_dir}/fixtures/schemas");

    compile(
        &["google/protobuf/descriptor.proto"],
        &[""],
        &out_dir,
        "descriptor.pb",
    );
    compile(&["knife.proto"], &[&schemas_dir], &out_dir, "knife.pb");
    compile(
        &["enum_collision.proto"],
        &[&schemas_dir],
        &out_dir,
        "enum_collision.pb",
    );

    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=fixtures/schemas/knife.proto");
    println!("cargo:rerun-if-changed=fixtures/schemas/enum_collision.proto");
}
