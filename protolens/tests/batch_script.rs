// SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

//! CLI-level (black-box, subprocess) integration tests for `protolens`'s
//! batch `script` subcommand — spec 0271 S14, and the smoke test the
//! `tests/fixtures/anomalies.script` walk exists to be.
//!
//! The transcript reports the *resolved* outcome of every directive, so
//! a script that has drifted out of sync with its blob shows up here as
//! a diagnostic line rather than as a talk that falls apart on stage.

use std::path::PathBuf;
use std::process::{Command, Output};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_protolens")
}

/// The workspace root — `CARGO_MANIFEST_DIR` is `protolens/`.
fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("protolens/ has a parent")
        .to_path_buf()
}

fn run(args: &[&str]) -> Output {
    Command::new(bin())
        .args(args)
        // Spec 0228 S8, as in `batch_export.rs`: the dev shell exports a
        // descriptor set and nix-build does not, so both are cleared to
        // make the two environments resolve the same one.
        .env_remove("PROTOTEXT_DESCRIPTOR_SET")
        .env_remove("PROTOTEXT_DEFAULT_DESCRIPTOR")
        .output()
        .expect("failed to spawn protolens")
}

/// The `anomalies.pb` invocation the README documents, plus a subcommand.
fn anomalies(extra: &[&str]) -> Output {
    let root = repo();
    let descriptor = root.join("prototext-core/fixtures/descriptor.pb");
    let blob = root.join("tests/fixtures/anomalies.pb");
    let mut args = vec![
        "--descriptor-set",
        descriptor.to_str().unwrap(),
        "--type",
        "google.protobuf.FileDescriptorProto",
    ];
    args.extend_from_slice(extra);
    args.push(blob.to_str().unwrap());
    args.push("script");
    run(&args)
}

/// Spec 0271 test-plan item 7. The script is found beside the blob, every
/// position in it resolves, and every step is walked.
///
/// Deliberately not a golden file of the whole transcript: the row ranges
/// in it move with any change to how a line is rendered, which would make
/// this a test of the renderer rather than of the script. What must not
/// drift is that each directive still finds what it names — and that is
/// exactly what an `error:` line reports.
#[test]
fn anomalies_script_walks_without_a_broken_position() {
    let out = anomalies(&[]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "stderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    // Spec 0198 S2: a successful batch subcommand says nothing.
    assert!(
        out.stderr.is_empty(),
        "stderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );

    let transcript = String::from_utf8(out.stdout).expect("the transcript is text");
    assert!(
        transcript.starts_with("script: anomalies.script\n"),
        "the implicit script beside the blob must be the one walked:\n{transcript}"
    );

    let broken: Vec<&str> = transcript
        .lines()
        .filter(|l| l.trim_start().starts_with("error:"))
        .collect();
    assert!(
        broken.is_empty(),
        "every position in anomalies.script must still resolve: {broken:?}"
    );

    let steps = transcript
        .lines()
        .filter(|l| l.starts_with("step "))
        .count();
    assert!(steps > 1, "the walk must have steps:\n{transcript}");
    assert!(
        transcript.contains(&format!("step {steps}/{steps}")),
        "and it must reach the last one:\n{transcript}"
    );
}

/// Spec 0271 S1: `--no-script` suppresses the implicit discovery, and
/// then the subcommand has nothing to walk.
#[test]
fn no_script_suppresses_the_script_beside_the_blob() {
    let out = anomalies(&["--no-script"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("needs a script"),
        "stderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// Spec 0271 S1: an explicit script that is not there is a hard error,
/// and it is reported before the descriptor set is even loaded.
#[test]
fn a_missing_explicit_script_is_refused() {
    let missing = std::env::temp_dir().join("protolens-no-such.script");
    let out = anomalies(&["--script", missing.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("cannot read script"), "stderr:\n{stderr}");
    assert!(
        !stderr.contains("loading descriptor set"),
        "the refusal must come before the wait it would have caused:\n{stderr}"
    );
}

/// The heading label a top-level `dependency` line carries — `"2.c."` in
/// `dependency: "2.c. A bool written as 2 instead of 1."` — or `None` for
/// any other top-level line.
fn heading_label(line: &str) -> Option<&str> {
    line.strip_prefix("dependency: \"")?
        .split_whitespace()
        .next()
}

/// The label a step's text cites: its first `N.x.` token, else its first
/// bare `N.` token. A section's opening step cites both (`2. Values…`,
/// then `2.a. -1 written…`), and the lettered one is the step's own.
fn cited_label(text: &str) -> Option<&str> {
    let is_label = |t: &&str, lettered: bool| {
        let Some(num) = t.strip_suffix('.') else {
            return false;
        };
        match num.split_once('.') {
            Some((n, x)) if lettered => {
                !n.is_empty()
                    && n.bytes().all(|b| b.is_ascii_digit())
                    && x.len() == 1
                    && x.bytes().all(|b| b.is_ascii_lowercase())
            }
            None if !lettered => !num.is_empty() && num.bytes().all(|b| b.is_ascii_digit()),
            _ => false,
        }
    };
    let tokens: Vec<&str> = text.split_whitespace().collect();
    tokens
        .iter()
        .find(|t| is_label(t, true))
        .or_else(|| tokens.iter().find(|t| is_label(t, false)))
        .copied()
}

/// Spec 0372 test-plan item 8. Every step whose `node` lies under a
/// top-level wrapper cites that wrapper's heading.
///
/// `anomalies_script_walks_without_a_broken_position` only catches a
/// position that no longer resolves. The script addresses the blob by
/// position, and a wrapper's position is twice its anomaly's number, so
/// inserting an anomaly shifts every later wrapper by two — and almost
/// every stale path still resolves, to the wrong anomaly. This catches
/// that: the step's text and the heading beside its node must agree.
///
/// A heading with no letter (`4.`) covers the lettered steps the script
/// walks through it (`4.a.`, `4.b.`).
#[test]
fn every_step_lands_under_its_heading() {
    let root = repo();
    let blob = std::fs::read_to_string(root.join("tests/fixtures/anomalies.pb")).unwrap();
    let script = std::fs::read_to_string(root.join("tests/fixtures/anomalies.script")).unwrap();

    // Top-level nodes, 1-based as positional paths count them.
    let top: Vec<&str> = blob
        .lines()
        .filter(|l| !l.is_empty() && !l.starts_with([' ', '#', '}']))
        .collect();

    let mut checked = 0;
    for step in script.split("\n  - text: |\n").skip(1) {
        let text: String = step
            .lines()
            .take_while(|l| l.is_empty() || l.starts_with("      "))
            .collect::<Vec<_>>()
            .join("\n");
        let Some(node) = step
            .lines()
            .find_map(|l| l.trim_start().strip_prefix("node: "))
        else {
            continue;
        };
        let Some(k) = node
            .trim()
            .strip_prefix('/')
            .and_then(|p| p.split('/').next())
            .and_then(|k| k.parse::<usize>().ok())
        else {
            continue; // the root: not under any wrapper
        };
        // The heading is the node itself, or the line just before it.
        let heading = heading_label(top[k - 1])
            .or_else(|| (k >= 2).then(|| heading_label(top[k - 2])).flatten())
            .unwrap_or_else(|| panic!("node {node} has no heading beside it"));
        let cited = cited_label(&text)
            .unwrap_or_else(|| panic!("the step at {node} cites no heading:\n{text}"));
        let lands =
            cited == heading || (heading.matches('.').count() == 1 && cited.starts_with(heading));
        assert!(
            lands,
            "the step citing {cited} has node {node}, which lies under heading {heading}"
        );
        // Every other position the step names — `wire_node`, `wire_line`,
        // a `wire_lines` range, its `fold` entries — must be under the
        // same wrapper, or a renumbering that missed one key goes unseen.
        for line in step.lines().map(str::trim_start) {
            let Some((key, value)) = line.split_once(": ") else {
                continue;
            };
            if !matches!(key, "wire_node" | "wire_line" | "from" | "to" | "fold") {
                continue;
            }
            for path in value.split(['"', ' ', '[', ',']) {
                let Some(top) = path
                    .strip_prefix('/')
                    .and_then(|p| p.split('/').next())
                    .and_then(|t| t.parse::<usize>().ok())
                else {
                    continue; // not a path, or the root
                };
                assert_eq!(
                    top, k,
                    "the step at {node} names {key} {path}, under another wrapper"
                );
            }
        }
        checked += 1;
    }
    assert!(checked > 20, "only {checked} steps were checked");
}
