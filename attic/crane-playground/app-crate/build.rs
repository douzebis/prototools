// Simulates prototext's build.rs: copies a prebuilt file into OUT_DIR.
fn main() {
    let out_dir = std::env::var("OUT_DIR").unwrap();
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let src = std::path::Path::new(&manifest_dir).join("fixtures/prebuilt/data.bin");
    let dst = std::path::Path::new(&out_dir).join("data.bin");
    std::fs::copy(&src, &dst).unwrap();
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=fixtures/prebuilt/data.bin");
}
