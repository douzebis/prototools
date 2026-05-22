// SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

// Simulate prototext's include_bytes!(concat!(env!("OUT_DIR"), "/descriptor.pb")).
// This embeds an OUT_DIR-absolute path at compile time, making Cargo fingerprints
// sandbox-specific and breaking depsCache reuse across Crane derivations.
static EMBEDDED_DATA: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/data.bin"));

fn main() {
    println!("{}", lib_crate::hello());
    println!("data len: {}", EMBEDDED_DATA.len());
    #[cfg(feature = "extra")]
    println!("extra feature enabled");
}
