// SPDX-FileCopyrightText: 2025-2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
// SPDX-FileCopyrightText: 2025-2026 THALES CLOUD SECURISE SAS
//
// SPDX-License-Identifier: MIT

//! Build script: copy committed files into `$OUT_DIR`, where the crate
//! `include_bytes!`es them.
//!
//! Nothing here runs a tool: every input is committed (spec 0405 S1, S2), so
//! a plain `cargo build -p prototext` needs no `protoc`, no `reproto` and no
//! feature flag, in Nix, in nixpkgs and from crates.io alike.
//!
//! - `fixtures/prebuilt/*.pb`, compiled by `default.nix`'s
//!   `prototextFixtures` and checked by `prototext-fixtures-check`:
//!   - `descriptor.pb`     — the well-known types, embedded in the binary;
//!   - `knife.pb`, `enum_collision.pb`, `message_set.pb` — for the tests.
//! - `wkt/prebuilt/*.rkyv` (with `wkt-db`), the WKT scoring graph, generated
//!   by `default.nix`'s `wktRkyv` and checked by `wkt-prebuilt-check`.

use std::path::Path;

const FIXTURES: [&str; 4] = [
    "descriptor.pb",
    "knife.pb",
    "enum_collision.pb",
    "message_set.pb",
];

#[cfg(feature = "wkt-db")]
const WKT_GRAPH: [&str; 2] = ["wkt.rkyv", "wkt_index.rkyv"];

fn copy_all(from: &Path, names: &[&str], out_dir: &Path) {
    for name in names {
        let src = from.join(name);
        std::fs::copy(&src, out_dir.join(name))
            .unwrap_or_else(|e| panic!("failed to copy {}: {e}", src.display()));
        println!("cargo:rerun-if-changed={}", src.display());
    }
}

fn main() {
    let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR not set");
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set");
    let (out_dir, manifest_dir) = (Path::new(&out_dir), Path::new(&manifest_dir));

    copy_all(&manifest_dir.join("fixtures/prebuilt"), &FIXTURES, out_dir);
    #[cfg(feature = "wkt-db")]
    copy_all(&manifest_dir.join("wkt/prebuilt"), &WKT_GRAPH, out_dir);

    println!("cargo:rerun-if-changed=build.rs");
}
