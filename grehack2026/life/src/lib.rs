// SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

//! What `life-server` and `life-client` share: the generated gRPC code and
//! the embedded descriptor. The game logic is not here — it is the
//! server's alone (spec 0375 N4).

/// The generated messages and service of `grehack.life.v1`.
pub mod pb {
    tonic::include_proto!("grehack.life.v1");
}

/// The serialized `FileDescriptorProto` of `life.proto`, which `protoscan`
/// finds in each binary (spec 0375 S3). The service is not reflected: this
/// blob is the only way to the schema.
pub static DESCRIPTOR: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/life.fdp"));

/// The fully qualified name of the one method, read from [`DESCRIPTOR`]:
/// `/grehack.life.v1.Life/Step`.
///
/// Reading the descriptor at startup, rather than only holding it, is what
/// guarantees the linker keeps it.
pub fn step_path() -> String {
    use prost::Message;
    let file = prost_types::FileDescriptorProto::decode(DESCRIPTOR)
        .expect("the embedded descriptor is written by build.rs");
    let service = &file.service[0];
    format!(
        "/{}.{}/{}",
        file.package(),
        service.name(),
        service.method[0].name()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_descriptor_names_the_method() {
        assert_eq!(step_path(), "/grehack.life.v1.Life/Step");
    }
}
