// SPDX-FileCopyrightText: 2025 - 2026 Frederic Ruget <fred@atlant.is> <fred@s3ns.io> (GitHub: @douzebis)
// SPDX-FileCopyrightText: 2025 - 2026 Thales Cloud Sécurisé
//
// SPDX-License-Identifier: MIT

use std::path::PathBuf;

use clap::{CommandFactory, Parser};
use clap_complete::{engine::ArgValueCompleter, CompleteEnv};

use complete::{complete_input_paths, complete_pb_files, complete_type_names};

mod complete;
mod inputs;
mod run;

// ── Embedded descriptor ───────────────────────────────────────────────────────

/// `descriptor.pb` compiled from `google/protobuf/descriptor.proto`.
/// Covers all `google.protobuf.*` types without requiring a file on disk.
pub(crate) static EMBEDDED_DESCRIPTOR: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/descriptor.pb"));

// ── CLI definition ────────────────────────────────────────────────────────────

/// Convert between binary protobuf and protoc-style text (enhanced textproto).
///
/// Enable shell completion:
///   bash:  source <(PROTOTEXT_COMPLETE=bash prototext)
///   zsh:   source <(PROTOTEXT_COMPLETE=zsh prototext)
///   fish:  PROTOTEXT_COMPLETE=fish prototext | source
#[derive(Debug, Parser)]
#[command(name = "prototext", version, about, long_about = None)]
pub(crate) struct Cli {
    // ── Mode (exactly one required) ───────────────────────────────────────────
    /// Decode: treat input as binary protobuf, emit text.
    #[arg(short = 'd', long = "decode", conflicts_with = "encode")]
    pub decode: bool,

    /// Encode: treat input as textual prototext, emit binary.
    #[arg(short = 'e', long = "encode", conflicts_with = "decode")]
    pub encode: bool,

    // ── Schema ────────────────────────────────────────────────────────────────
    /// Compiled .pb descriptor file.
    #[arg(
        short = 'D',
        long = "descriptor",
        value_name = "PATH",
        add = ArgValueCompleter::new(complete_pb_files),
    )]
    pub descriptor: Option<PathBuf>,

    /// Fully-qualified root message type name (e.g. pkg.MyMessage).
    /// When given without --descriptor, uses the embedded descriptor
    /// (covers all google.protobuf.* types).
    #[arg(
        short = 't',
        long = "type",
        value_name = "NAME",
        add = ArgValueCompleter::new(complete_type_names),
    )]
    pub r#type: Option<String>,

    // ── Output ────────────────────────────────────────────────────────────────
    /// Emit inline wire-type/field-number comments (default).
    /// Required for lossless round-trip encode.
    #[arg(long, default_value_t = true, overrides_with = "no_annotations")]
    pub annotations: bool,

    /// Suppress inline wire-type/field-number comments.
    /// Output will not be losslessly round-trippable.
    #[arg(long, overrides_with = "annotations")]
    pub no_annotations: bool,

    /// Write output to PATH (single input only; exclusive with --output-root).
    #[arg(
        short = 'o',
        long = "output",
        value_name = "PATH",
        conflicts_with = "output_root"
    )]
    pub output: Option<PathBuf>,

    /// Root directory for output files in batch mode (exclusive with --output
    /// and --in-place).
    #[arg(
        short = 'O',
        long = "output-root",
        value_name = "DIR",
        conflicts_with_all = ["output", "in_place"],
    )]
    pub output_root: Option<PathBuf>,

    // ── Input ─────────────────────────────────────────────────────────────────
    /// Root directory: positional paths and globs are resolved relative to DIR.
    /// Absolute positional paths are an error when --input-root is given.
    #[arg(short = 'I', long = "input-root", value_name = "DIR")]
    pub input_root: Option<PathBuf>,

    /// Rewrite each input file in place (exclusive with --output-root).
    /// Each file is read fully into memory before being overwritten (sponge).
    #[arg(short = 'i', long = "in-place", conflicts_with = "output_root")]
    pub in_place: bool,

    // ── Other ─────────────────────────────────────────────────────────────────
    /// Suppress warnings on stderr (errors are always printed).
    #[arg(short = 'q', long = "quiet")]
    pub quiet: bool,

    /// Input files, glob patterns, or directories (recursive).
    /// When absent, reads from stdin.
    #[arg(
        value_name = "PATH",
        add = ArgValueCompleter::new(complete_input_paths),
    )]
    pub paths: Vec<String>,
}

// ── Entry point ───────────────────────────────────────────────────────────────

fn main() {
    // Dynamic shell completion — same model as Cargo.
    // When PROTOTEXT_COMPLETE=<shell> is set, print the completion script and exit.
    CompleteEnv::with_factory(Cli::command)
        .var("PROTOTEXT_COMPLETE")
        .complete();

    let cli = Cli::parse();

    if let Err(e) = run::run(cli) {
        eprintln!("error: {}", e);
        std::process::exit(1);
    }
}
