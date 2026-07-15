// SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

//! CLI-level (black-box, subprocess) integration tests for `protolens`'s
//! batch `extract` subcommand — spec 0123 Test plan items 2-6.
//!
//! `protolens` is a binary-only crate (no `lib.rs`), so unlike
//! `prototext/tests/e2e.rs` (which pulls in `protocraft` via a `#[path]`
//! include), these tests can't reach any of `protolens`'s own internal
//! modules. Fixtures are therefore rebuilt from scratch here using
//! `prost-types` (already a `[dev-dependencies]` entry), and the CLI is
//! exercised purely as a subprocess via `CARGO_BIN_EXE_protolens`.

use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};

use prost::Message as _;
use prost_types::descriptor_proto::ExtensionRange;
use prost_types::field_descriptor_proto::{Label, Type};
use prost_types::{
    DescriptorProto, FieldDescriptorProto, FileDescriptorProto, FileDescriptorSet, MessageOptions,
};

// ── Helpers ──────────────────────────────────────────────────────────────

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_protolens")
}

fn run(args: &[&str]) -> Output {
    Command::new(bin())
        .args(args)
        .output()
        .expect("failed to spawn protolens")
}

/// A unique path under the system temp dir — never created, just named
/// (tests run in parallel and must not collide with each other, nor with
/// leftovers from prior runs).
fn temp_path(name: &str) -> PathBuf {
    static COUNTER: AtomicUsize = AtomicUsize::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "protolens-batch-extract-{name}-{}-{n}.tmp",
        std::process::id()
    ))
}

/// Deletes its wrapped path on drop — keeps every test's temp files from
/// piling up regardless of pass/fail/panic.
struct TempFile(PathBuf);

impl Drop for TempFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

impl TempFile {
    fn path(&self) -> &str {
        self.0.to_str().expect("temp path must be valid UTF-8")
    }
}

fn write_temp(name: &str, bytes: &[u8]) -> TempFile {
    let path = temp_path(name);
    std::fs::write(&path, bytes).unwrap();
    TempFile(path)
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    format!("{:x}", Sha256::digest(bytes))
}

/// `Outer { inner: Inner { x: int32 } }`, wired as
/// `Outer{ inner: Inner{ x: 1 } }` = `0x0A 0x02 0x08 0x01`
/// (field 1 LEN, payload = field 1 varint 1).
fn outer_inner_fixture() -> (TempFile, TempFile) {
    let inner = DescriptorProto {
        name: Some("Inner".to_string()),
        field: vec![FieldDescriptorProto {
            name: Some("x".to_string()),
            number: Some(1),
            label: Some(Label::Optional as i32),
            r#type: Some(Type::Int32 as i32),
            ..Default::default()
        }],
        ..Default::default()
    };
    let outer = DescriptorProto {
        name: Some("Outer".to_string()),
        field: vec![FieldDescriptorProto {
            name: Some("inner".to_string()),
            number: Some(1),
            label: Some(Label::Optional as i32),
            r#type: Some(Type::Message as i32),
            type_name: Some(".test.Inner".to_string()),
            ..Default::default()
        }],
        ..Default::default()
    };
    let file = FileDescriptorProto {
        name: Some("test.proto".to_string()),
        package: Some("test".to_string()),
        message_type: vec![outer, inner],
        syntax: Some("proto3".to_string()),
        ..Default::default()
    };
    let fds = FileDescriptorSet { file: vec![file] };
    let descriptor = write_temp("outer-inner-desc", &fds.encode_to_vec());
    let blob = write_temp("outer-inner-blob", &[0x0A, 0x02, 0x08, 0x01]);
    (descriptor, blob)
}

/// Same `TestMessageSet`/`ExtPayload`/`Container` schema and
/// `Container{ extensions: TestMessageSet{ Item{ type_id: 100, message:
/// ExtPayload{ label: "hi" } } } }` blob as `tui.rs`'s (private)
/// `message_set_fixture` unit-test helper (spec 0120) — rebuilt here for
/// the reason given in this file's header comment.
fn message_set_fixture() -> (TempFile, TempFile) {
    let message_set_msg = DescriptorProto {
        name: Some("TestMessageSet".to_string()),
        options: Some(MessageOptions {
            message_set_wire_format: Some(true),
            ..Default::default()
        }),
        extension_range: vec![ExtensionRange {
            start: Some(1),
            end: Some(536870912),
            ..Default::default()
        }],
        ..Default::default()
    };
    let ext_payload_msg = DescriptorProto {
        name: Some("ExtPayload".to_string()),
        field: vec![FieldDescriptorProto {
            name: Some("label".to_string()),
            number: Some(1),
            label: Some(Label::Optional as i32),
            r#type: Some(Type::String as i32),
            ..Default::default()
        }],
        ..Default::default()
    };
    let extension_field = FieldDescriptorProto {
        name: Some("ext_payload".to_string()),
        number: Some(100),
        label: Some(Label::Optional as i32),
        r#type: Some(Type::Message as i32),
        type_name: Some(".ms_test.ExtPayload".to_string()),
        extendee: Some(".ms_test.TestMessageSet".to_string()),
        ..Default::default()
    };
    let container_msg = DescriptorProto {
        name: Some("Container".to_string()),
        field: vec![FieldDescriptorProto {
            name: Some("extensions".to_string()),
            number: Some(2),
            label: Some(Label::Optional as i32),
            r#type: Some(Type::Message as i32),
            type_name: Some(".ms_test.TestMessageSet".to_string()),
            ..Default::default()
        }],
        ..Default::default()
    };
    let file = FileDescriptorProto {
        name: Some("ms_test.proto".to_string()),
        syntax: Some("proto2".to_string()),
        package: Some("ms_test".to_string()),
        message_type: vec![message_set_msg, ext_payload_msg, container_msg],
        extension: vec![extension_field],
        ..Default::default()
    };
    let fds = FileDescriptorSet { file: vec![file] };
    let descriptor = write_temp("message-set-desc", &fds.encode_to_vec());

    // Container { extensions: TestMessageSet {
    //   Item { type_id: 100, message: ExtPayload { label: "hi" } }
    // } }.
    let ext_payload_bytes = [0x0au8, 0x02, b'h', b'i'];
    let mut item_bytes = vec![0x0bu8, 0x10, 100u8];
    item_bytes.push(0x1a);
    item_bytes.push(ext_payload_bytes.len() as u8);
    item_bytes.extend_from_slice(&ext_payload_bytes);
    item_bytes.push(0x0c); // END_GROUP
    let mut blob_bytes = vec![0x12u8, item_bytes.len() as u8];
    blob_bytes.extend_from_slice(&item_bytes);

    let blob = write_temp("message-set-blob", &blob_bytes);
    (descriptor, blob)
}

// ── Item 2: `extract /` matches the fixture's known-good rendering ───────

#[test]
fn extract_root_produces_the_expected_prototext() {
    let (descriptor, blob) = outer_inner_fixture();
    let out = run(&[
        "--descriptor-set",
        descriptor.path(),
        "--type",
        "test.Outer",
        blob.path(),
        "extract",
        "/",
    ]);
    assert!(
        out.status.success(),
        "extract / must succeed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        text.starts_with("#@ prototext: protoc\n"),
        "text output must start with the prototext header, got: {text}"
    );
    assert!(
        text.contains("inner {"),
        "expected the nested `inner` field, got: {text}"
    );
    assert!(
        text.contains("x: 1"),
        "expected the inner `x` field (x: 1), got: {text}"
    );
}

// ── Item 3: `--load-overrides` alongside a MessageSet auto-override ──────

#[test]
fn extract_with_load_overrides_still_shows_message_set_auto_expansion() {
    let (descriptor, blob) = message_set_fixture();
    let descriptor_bytes = std::fs::read(&descriptor.0).unwrap();
    let blob_bytes = std::fs::read(&blob.0).unwrap();

    // `load_overrides` *replaces* the whole collection (spec 0117 §4),
    // including spec 0120's auto-detected entries seeded at `App::new`
    // time — so the loaded collection must itself carry the two
    // MessageSet auto-override tiers (tier 1: the `Item` group retyped to
    // the synthetic `protolens_internal.MessageSetItem`, cosmetically
    // named "Item"; tier 2: its `message` field retyped to the resolved
    // extension type), at their positional paths (`/1/1` = the sole
    // `Item`, `/1/1/2` = `Item`'s 2nd child, `message`) — exactly what a
    // real `:save-overrides` from an already-auto-expanded session would
    // have written. The document root's own type is deliberately *not*
    // included here: it's meant to be preserved automatically across a
    // wholesale collection replace, not something a hand-authored
    // overrides file is expected to carry.
    let yaml = format!(
        r#"version: 1
target:
  blob_sha256: "{}"
  descriptor_set_sha256: "{}"
overrides:
  - path: "/1/1"
    type: protolens_internal.MessageSetItem
    active: true
    name: Item
  - path: "/1/1/2"
    type: ms_test.ExtPayload
    active: true
"#,
        sha256_hex(&blob_bytes),
        sha256_hex(&descriptor_bytes),
    );
    let overrides = write_temp("message-set-overrides", yaml.as_bytes());

    let out = run(&[
        "--descriptor-set",
        descriptor.path(),
        "--type",
        "ms_test.Container",
        blob.path(),
        "extract",
        "/",
        "--load-overrides",
        overrides.path(),
    ]);
    assert!(
        out.status.success(),
        "extract with a hash-matching --load-overrides must succeed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        out.stderr.is_empty(),
        "matching target hashes must not warn: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        text.contains("label") && text.contains("hi"),
        "MessageSet Item must auto-expand to the resolved extension type \
         (not raw bytes) even with --load-overrides applied, got:\n{text}"
    );
}

// ── Item 4: an unresolvable extract path is a hard error, no TUI ─────────

#[test]
fn extract_unresolvable_path_fails_without_entering_the_tui() {
    let (descriptor, blob) = outer_inner_fixture();
    // Command::output() would hang forever waiting for a child that has
    // entered the TUI's raw-mode input loop (stdin/stdout are not a TTY
    // here, but the TUI still blocks reading events) — this test's own
    // completion is itself proof that batch mode returned instead of
    // calling `tui::run`.
    let out = run(&[
        "--descriptor-set",
        descriptor.path(),
        "--type",
        "test.Outer",
        blob.path(),
        "extract",
        "/99",
    ]);
    assert!(
        !out.status.success(),
        "extract with an unresolvable path must fail"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("does not resolve"),
        "expected a resolution diagnostic, got: {stderr}"
    );
}

// ── Item 4a: bad --load-overrides is a hard error ─────────────────────────

#[test]
fn extract_load_overrides_missing_file_is_a_hard_error() {
    let (descriptor, blob) = outer_inner_fixture();
    let missing = temp_path("missing-overrides");
    let out = run(&[
        "--descriptor-set",
        descriptor.path(),
        "--type",
        "test.Outer",
        blob.path(),
        "extract",
        "/",
        "--load-overrides",
        missing.to_str().unwrap(),
    ]);
    assert!(
        !out.status.success(),
        "--load-overrides pointing at a missing file must fail"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("--load-overrides"),
        "expected a --load-overrides diagnostic, got: {stderr}"
    );
}

#[test]
fn extract_load_overrides_malformed_yaml_is_a_hard_error() {
    let (descriptor, blob) = outer_inner_fixture();
    let overrides = write_temp("malformed-overrides", b"{not valid yaml: [1, 2\n");
    let out = run(&[
        "--descriptor-set",
        descriptor.path(),
        "--type",
        "test.Outer",
        blob.path(),
        "extract",
        "/",
        "--load-overrides",
        overrides.path(),
    ]);
    assert!(
        !out.status.success(),
        "--load-overrides pointing at malformed YAML must fail"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("--load-overrides"),
        "expected a --load-overrides diagnostic, got: {stderr}"
    );
}

/// By contrast (spec 0123 Test plan item 4a's clarifying note): a
/// hash-mismatched but otherwise-valid overrides collection is a
/// stderr-only warning, not a hard error — same policy as the TUI's own
/// `:restore-overrides`.
#[test]
fn extract_load_overrides_hash_mismatch_warns_but_still_succeeds() {
    let (descriptor, blob) = outer_inner_fixture();
    let yaml = format!(
        "version: 1\ntarget:\n  blob_sha256: \"{}\"\n  descriptor_set_sha256: \"{}\"\noverrides: []\n",
        "0".repeat(64),
        "0".repeat(64),
    );
    let overrides = write_temp("hash-mismatch-overrides", yaml.as_bytes());
    let out = run(&[
        "--descriptor-set",
        descriptor.path(),
        "--type",
        "test.Outer",
        blob.path(),
        "extract",
        "/",
        "--load-overrides",
        overrides.path(),
    ]);
    assert!(
        out.status.success(),
        "a hash mismatch must warn, not fail: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("warning") && stderr.contains("hash mismatch"),
        "expected a hash-mismatch warning, got: {stderr}"
    );
}

// ── Item 5: --format text + --no-annotations is a startup error ──────────

#[test]
fn extract_format_text_with_no_annotations_is_a_startup_error() {
    let (descriptor, blob) = outer_inner_fixture();
    let out = run(&[
        "--descriptor-set",
        descriptor.path(),
        "--type",
        "test.Outer",
        "--no-annotations",
        blob.path(),
        "extract",
        "/",
        "--format",
        "text",
    ]);
    assert!(
        !out.status.success(),
        "--format text with --no-annotations must be a startup error"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("--format text is incompatible with --no-annotations"),
        "got: {stderr}"
    );
}

#[test]
fn extract_no_annotations_defaults_to_binary_output() {
    let (descriptor, blob) = outer_inner_fixture();
    let out = run(&[
        "--descriptor-set",
        descriptor.path(),
        "--type",
        "test.Outer",
        "--no-annotations",
        blob.path(),
        "extract",
        "/",
    ]);
    assert!(
        out.status.success(),
        "extract / --no-annotations must succeed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !out.stdout.starts_with(b"#@"),
        "no explicit --format with --no-annotations must default to \
         binary output (no #@ prototext text header), got: {:?}",
        out.stdout
    );
}

// ── Item 6: round-trip regression, extract + encode == original blob ─────

/// `extract /`'s text output, piped through `prototext encode`'s
/// equivalent library function (`encode_text_to_binary` — used directly
/// rather than spawning the sibling `prototext` binary, since
/// `CARGO_BIN_EXE_<name>` is only guaranteed for the current package's own
/// binaries), must byte-for-byte reproduce the original blob.
#[test]
fn extract_root_round_trips_losslessly_through_encode() {
    let (descriptor, blob) = outer_inner_fixture();
    let original = std::fs::read(&blob.0).unwrap();
    let out = run(&[
        "--descriptor-set",
        descriptor.path(),
        "--type",
        "test.Outer",
        blob.path(),
        "extract",
        "/",
    ]);
    assert!(
        out.status.success(),
        "extract / must succeed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let reencoded = prototext_core::serialize::encode_text::encode_text_to_binary(&out.stdout);
    assert_eq!(
        reencoded, original,
        "extract + encode round-trip must be byte-for-byte lossless"
    );
}

#[test]
fn extract_message_set_round_trips_losslessly_through_encode() {
    let (descriptor, blob) = message_set_fixture();
    let original = std::fs::read(&blob.0).unwrap();
    let out = run(&[
        "--descriptor-set",
        descriptor.path(),
        "--type",
        "ms_test.Container",
        blob.path(),
        "extract",
        "/",
    ]);
    assert!(
        out.status.success(),
        "extract / must succeed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let reencoded = prototext_core::serialize::encode_text::encode_text_to_binary(&out.stdout);
    assert_eq!(
        reencoded, original,
        "extract + encode round-trip must be byte-for-byte lossless"
    );
}
