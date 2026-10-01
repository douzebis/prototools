// SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

//! Compiles `life.proto` and writes its `FileDescriptorProto` for the
//! binaries to embed (spec 0375 S3).
//!
//! The embedded blob is the one `FileDescriptorProto` of `life.proto`, not
//! a `FileDescriptorSet`: that is what `protoscan` looks for in a binary.

use prost::Message;
use prost_types::FileDescriptorSet;
use std::{env, fs, path::PathBuf};

const PROTO: &str = "proto/grehack/life/v1/life.proto";

fn main() {
    let out = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR"));
    let set_path = out.join("life.fds");

    tonic_prost_build::configure()
        .file_descriptor_set_path(&set_path)
        // The service reads a request's tags before decoding it (spec 0377
        // S2): the generated code builds this codec in place of the default
        // ProstCodec, in both the client and the server.
        .codec_path("crate::codec::TagReadingCodec")
        .compile_protos(&[PROTO], &["proto"])
        .unwrap_or_else(|e| panic!("compiling {PROTO}: {e}"));

    let set =
        FileDescriptorSet::decode(&fs::read(&set_path).expect("reading the descriptor set")[..])
            .expect("decoding the descriptor set");
    let [file] = &set.file[..] else {
        panic!("{PROTO} imports nothing, so its set must hold exactly one file");
    };
    fs::write(out.join("life.fdp"), file.encode_to_vec()).expect("writing life.fdp");

    println!("cargo::rerun-if-changed={PROTO}");
}
