// SPDX-FileCopyrightText: 2025-2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
// SPDX-FileCopyrightText: 2025-2026 THALES CLOUD SECURISE SAS
//
// SPDX-License-Identifier: MIT

//! End-to-end tests driven by the craft_a fixture registry (spec 0009).

use std::path::{Path, PathBuf};
use std::process::Command;

// Pull in the protocraft module (test-only).
#[path = "../src/protocraft/mod.rs"]
mod protocraft;

use protocraft::craft_a;

// ── Helpers ───────────────────────────────────────────────────────────────────

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).to_path_buf()
}

fn index_schema(name: &str) -> Option<(String, String)> {
    let index_path = repo_root().join("fixtures/index.toml");
    let text = std::fs::read_to_string(&index_path)
        .unwrap_or_else(|e| panic!("cannot read {}: {}", index_path.display(), e));
    let doc: toml::Value = text
        .parse()
        .unwrap_or_else(|e| panic!("cannot parse index.toml: {e}"));
    doc.get("fixture")
        .and_then(|v| v.as_array())
        .unwrap_or(&vec![])
        .iter()
        .find(|entry| entry["name"].as_str() == Some(name))
        .map(|entry| {
            (
                entry["schema"].as_str().unwrap().to_owned(),
                entry["message"].as_str().unwrap().to_owned(),
            )
        })
}

fn schema_path(schema_rel: &str) -> PathBuf {
    let generated = ["descriptor.pb", "knife.pb", "enum_collision.pb"];
    if let Some(name) = generated
        .iter()
        .find(|&&n| schema_rel == format!("fixtures/schemas/{n}"))
    {
        return PathBuf::from(env!("OUT_DIR")).join(name);
    }
    repo_root().join(schema_rel)
}

/// Run `prototext --descriptor-set <schema> decode --type <message>` on binary
/// input, then `prototext encode` on the text output.
/// Returns (text, re-encoded binary).
fn cli_roundtrip(
    wire: &[u8],
    schema_path: &Path,
    message: &str,
    annotations: bool,
) -> (Vec<u8>, Vec<u8>) {
    let bin = env!("CARGO_BIN_EXE_prototext");

    let mut decode_cmd = Command::new(bin);
    decode_cmd
        .arg("--descriptor-set")
        .arg(schema_path)
        .arg("decode")
        .args(["--type", message]);
    if !annotations {
        decode_cmd.arg("--no-annotations");
    }
    let decode_out = decode_cmd
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("failed to spawn prototext")
        .wait_with_output_and_stdin(wire);

    assert!(
        decode_out.status.success(),
        "prototext decode failed:\n{}",
        String::from_utf8_lossy(&decode_out.stderr)
    );
    let text = decode_out.stdout;

    let encode_out = Command::new(bin)
        .arg("encode")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("failed to spawn prototext")
        .wait_with_output_and_stdin(&text);

    assert!(
        encode_out.status.success(),
        "prototext encode failed:\n{}",
        String::from_utf8_lossy(&encode_out.stderr)
    );

    (text, encode_out.stdout)
}

trait SpawnExt {
    fn wait_with_output_and_stdin(self, input: &[u8]) -> std::process::Output;
}

impl SpawnExt for std::process::Child {
    fn wait_with_output_and_stdin(mut self, input: &[u8]) -> std::process::Output {
        use std::io::Write;
        if let Some(mut stdin) = self.stdin.take() {
            stdin.write_all(input).ok();
        }
        self.wait_with_output().expect("wait_with_output failed")
    }
}

// ── §3.1 Lossless round-trip with annotations (all fixtures) ─────────────────

/// CLI: `prototext decode` then `prototext encode` must reproduce the original wire bytes.
///
/// Pipeline: craft_a() → wire → `prototext decode` → text → `prototext encode` → wire2
/// Assert: wire2 == wire (bit-exact).
#[test]
fn fixture_roundtrip_annotated_craft_a() {
    let mut ran = 0;
    let mut skipped = 0;

    for &(name, func) in craft_a::ALL_FIXTURES {
        let Some((schema_rel, message)) = index_schema(name) else {
            eprintln!("SKIP  {name} (not in index.toml)");
            skipped += 1;
            continue;
        };

        let wire = func();
        let sp = schema_path(&schema_rel);
        let (text, wire2) = cli_roundtrip(&wire, &sp, &message, true);

        assert_eq!(
            wire2,
            wire,
            "{name}: binary→text→binary round-trip must be bit-exact\n  text:\n{}",
            String::from_utf8_lossy(&text),
        );
        ran += 1;
    }

    eprintln!("fixture_roundtrip_annotated_craft_a: {ran} passed, {skipped} skipped");
    assert!(ran > 0, "no fixtures ran");
}

// ── §3.3 Unknown LEN field decoded as nested message (spec 0097) ─────────────

/// A hand-crafted SwissArmyKnife wire payload that contains a known field
/// (field 25 / int32Op = 42) followed by an unknown LEN field (field 9001)
/// whose payload is itself a valid protobuf message.
///
/// Spec 0097 S3 requires that the unknown LEN field be rendered as a nested
/// message (not raw bytes), and that the round-trip is lossless.
///
/// Wire layout (16 bytes):
///   \xc8\x01      — tag: field 25, wire type 0 (varint)
///   \x2a          — value: 42
///   \xca\xb2\x04  — tag: field 9001, wire type 2 (LEN)
///   \x09          — length: 9
///   \x08\x07      — inner field 1, varint 7
///   \x12\x05hello — inner field 2, string "hello"
#[test]
fn unknown_len_decoded_as_nested_message() {
    #[rustfmt::skip]
    let wire: &[u8] = &[
        0xc8, 0x01,              // tag: field 25, varint
        0x2a,                    // value: 42
        0xca, 0xb2, 0x04,        // tag: field 9001, LEN
        0x09,                    // length: 9
        0x08, 0x07,              // inner: field 1 varint 7
        0x12, 0x05,              // inner: field 2 LEN length 5
        b'h', b'e', b'l', b'l', b'o', // "hello"
    ];

    let sp = schema_path("fixtures/schemas/knife.pb");
    let (text, wire2) = cli_roundtrip(wire, &sp, "SwissArmyKnife", true);
    let text_str = String::from_utf8_lossy(&text);

    // The unknown field must be rendered as a nested message (brace syntax),
    // not as raw bytes.
    assert!(
        text_str.contains("9001 {"),
        "unknown LEN field must be rendered as nested message, got:\n{text_str}"
    );

    // Round-trip must be lossless.
    assert_eq!(
        wire2, wire,
        "binary→text→binary round-trip must be bit-exact\n  text:\n{text_str}"
    );
}

// ── §3.2 No crash without annotations (all fixtures) ─────────────────────────

/// CLI: `prototext decode --no-annotations` must exit 0 for every fixture.
///
/// Without annotations the header is suppressed and encode is not possible,
/// so this test only checks that decode itself succeeds cleanly.
#[test]
fn fixture_no_panic_no_annotations() {
    let mut ran = 0;
    let mut skipped = 0;
    let bin = env!("CARGO_BIN_EXE_prototext");

    for &(name, func) in craft_a::ALL_FIXTURES {
        let Some((schema_rel, message)) = index_schema(name) else {
            eprintln!("SKIP  {name} (not in index.toml)");
            skipped += 1;
            continue;
        };

        let wire = func();
        let sp = schema_path(&schema_rel);
        let out = Command::new(bin)
            .arg("--descriptor-set")
            .arg(&sp)
            .arg("decode")
            .args(["--type", &message])
            .arg("--no-annotations")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("failed to spawn prototext")
            .wait_with_output_and_stdin(&wire);
        assert!(
            out.status.success(),
            "{name}: prototext decode --no-annotations must exit 0:\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
        ran += 1;
    }

    eprintln!("fixture_no_panic_no_annotations: {ran} passed, {skipped} skipped");
    assert!(ran > 0, "no fixtures ran");
}
