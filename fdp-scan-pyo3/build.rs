// SPDX-FileCopyrightText: Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

// Spec 0402 S6: libpython is linked only where something embeds Python.
//
// The cdylib is a Python extension: Python loads it, so it must not link
// libpython itself (pyo3's `extension-module` feature leaves it out, and a
// PyPI wheel that links it is wrong). The stub generator binary and the unit
// tests do run Python, so they link it — per target, rather than through a
// workspace-wide RUSTFLAGS that every crate, and the dependency cache's
// fingerprints, would share.
//
// Binaries get it through `rustc-link-arg-bins`. Unit tests are the library
// itself compiled as a test binary, which no per-target instruction reaches,
// so this script also writes `libpython.rs`, a `#[link]` attribute naming
// the library, for `lib.rs` to include under `#[cfg(test)]`.
fn main() {
    // macOS: an extension resolves Python's symbols when it is loaded
    // (`-undefined dynamic_lookup`). A no-op elsewhere.
    pyo3_build_config::add_extension_module_link_args();

    let config = pyo3_build_config::get();
    let mut link = String::new();
    if let Some(dir) = config.lib_dir() {
        println!("cargo:rustc-link-arg-bins=-L{dir}");
        // A search path only: harmless to the cdylib, needed by the tests.
        println!("cargo:rustc-link-search=native={dir}");
    }
    if let Some(name) = config.lib_name() {
        println!("cargo:rustc-link-arg-bins=-l{name}");
        link = format!("#[link(name = \"{name}\")]\nunsafe extern \"C\" {{}}\n");
    }
    let out = std::env::var("OUT_DIR").expect("cargo sets OUT_DIR");
    std::fs::write(std::path::Path::new(&out).join("libpython.rs"), link)
        .expect("writing libpython.rs");
}
