// SPDX-FileCopyrightText: 2025 - 2026 Frederic Ruget <fred@atlant.is> <fred@s3ns.io> (GitHub: @douzebis)
// SPDX-FileCopyrightText: 2025 - 2026 Thales Cloud Sécurisé
//
// SPDX-License-Identifier: MIT

//! End-to-end tests driven by the craft_a fixture registry (spec 0009).

use std::path::{Path, PathBuf};

use prototext_core::{parse_schema, render_as_bytes, render_as_text, RenderOpts};

// Pull in the protocraft module (test-only).
#[path = "../src/protocraft/mod.rs"]
mod protocraft;

use protocraft::craft_a;

// ── Helpers ───────────────────────────────────────────────────────────────────

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).to_path_buf()
}

fn load_case_text(name: &str) -> Option<Vec<u8>> {
    let path = repo_root()
        .join("fixtures/cases")
        .join(format!("{name}.pb"));
    match std::fs::read(&path) {
        Ok(b) => Some(b),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => panic!("cannot read {}: {e}", path.display()),
    }
}

fn to_wire(text: &[u8]) -> Vec<u8> {
    render_as_bytes(text, opts(false)).expect("render_as_bytes failed")
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

fn load_schema(schema_rel: &str, message: &str) -> prototext_core::ParsedSchema {
    let path = schema_path(schema_rel);
    let bytes = std::fs::read(&path)
        .unwrap_or_else(|e| panic!("cannot read schema {}: {e}", path.display()));
    parse_schema(&bytes, message)
        .unwrap_or_else(|e| panic!("cannot parse schema {schema_rel}:{message}: {e}"))
}

fn opts(annotations: bool) -> RenderOpts {
    RenderOpts::new(false, annotations, 1)
}

// ── §2 Validate craft_a against committed fixture files ───────────────────────

/// Each craft_a function must produce bytes identical to the committed .pb file.
#[test]
fn craft_a_matches_committed_fixtures() {
    let mut ran = 0;
    let mut skipped = 0;

    for &(name, func) in craft_a::ALL_FIXTURES {
        let generated = func();
        let Some(committed_text) = load_case_text(name) else {
            eprintln!("SKIP  {name} (case file missing)");
            skipped += 1;
            continue;
        };
        let committed = to_wire(&committed_text);
        assert_eq!(
            generated,
            committed,
            "craft_a::{name} output does not match fixtures/cases/{name}.pb\n  generated: {generated:?}\n  committed: {committed:?}"
        );
        ran += 1;
    }

    eprintln!("craft_a_matches_committed_fixtures: {ran} passed, {skipped} skipped");
    assert!(
        ran > 0,
        "no fixtures ran — ALL_FIXTURES empty or all case files missing"
    );
}

// ── §3.1 Lossless round-trip with annotations (all fixtures) ─────────────────

/// render_as_bytes(render_as_text(wire, annotations=true)) == wire for all fixtures.
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
        let schema = load_schema(&schema_rel, &message);
        let text = render_as_text(&wire, Some(&schema), opts(true))
            .unwrap_or_else(|e| panic!("{name}: render_as_text failed: {e}"));
        let wire2 = render_as_bytes(&text, opts(false))
            .unwrap_or_else(|e| panic!("{name}: render_as_bytes failed: {e}"));

        assert_eq!(
            wire2,
            wire,
            "{name}: round-trip with annotations must be bit-exact\n  text:\n{}",
            String::from_utf8_lossy(&text),
        );
        ran += 1;
    }

    eprintln!("fixture_roundtrip_annotated_craft_a: {ran} passed, {skipped} skipped");
    assert!(ran > 0, "no fixtures ran");
}

// ── §3.2 No panic without annotations (all fixtures) ─────────────────────────

/// render_as_text(wire, annotations=false) must not panic or return Err.
#[test]
fn fixture_no_panic_no_annotations() {
    let mut ran = 0;
    let mut skipped = 0;

    for &(name, func) in craft_a::ALL_FIXTURES {
        let Some((schema_rel, message)) = index_schema(name) else {
            eprintln!("SKIP  {name} (not in index.toml)");
            skipped += 1;
            continue;
        };

        let wire = func();
        let schema = load_schema(&schema_rel, &message);
        render_as_text(&wire, Some(&schema), opts(false))
            .unwrap_or_else(|e| panic!("{name}: render_as_text (no annotations) failed: {e}"));
        ran += 1;
    }

    eprintln!("fixture_no_panic_no_annotations: {ran} passed, {skipped} skipped");
    assert!(ran > 0, "no fixtures ran");
}
