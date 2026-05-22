// SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

// Simulates prototext's build.rs.
//
// Two modes:
//
// - PREBUILT_DATA env var set (Nix build, fixed store path):
//   Copy from the pre-built Nix derivation.  The source path is a stable
//   Nix store path, so the copied bytes are identical across sandboxes and
//   Cargo fingerprints remain valid.
//
// - PREBUILT_DATA not set (fallback / local dev):
//   Copy fixtures/prebuilt/data.bin from the workspace source.
//   patchPhase must have written the file before cargo build runs.
//
fn main() {
    let out_dir = std::env::var("OUT_DIR").unwrap();
    let dst = std::path::Path::new(&out_dir).join("data.bin");

    if let Ok(src) = std::env::var("PREBUILT_DATA") {
        // Fast path: use the stable Nix store path.
        std::fs::copy(&src, &dst)
            .unwrap_or_else(|e| panic!("failed to copy PREBUILT_DATA '{src}': {e}"));
    } else {
        // Fallback: read from fixtures/prebuilt/ (patchPhase must have run).
        let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
        let src = std::path::Path::new(&manifest_dir).join("fixtures/prebuilt/data.bin");
        std::fs::copy(&src, &dst).unwrap();
    }

    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=fixtures/prebuilt/data.bin");
}
