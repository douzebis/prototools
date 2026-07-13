// SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

mod complete;
mod decode;
mod extract;
mod override_pane;
mod tui;

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{CommandFactory, Parser};
use clap_complete::engine::ArgValueCompleter;
use clap_complete::CompleteEnv;
use prototext_core::{render_as_bytes, RenderOpts};

/// Interactive TUI to decode, navigate, and extract raw bytes from a binary
/// protobuf.
///
/// Enable shell completion:
///   bash:  source <(PROTOLENS_COMPLETE=bash protolens)
///   zsh:   source <(PROTOLENS_COMPLETE=zsh protolens)
///   fish:  PROTOLENS_COMPLETE=fish protolens | source
#[derive(Parser)]
#[command(name = "protolens", version, about)]
struct Cli {
    /// FileDescriptorSet for root-type determination and type resolution.
    /// May be a raw binary FileDescriptorSet or a `#@ prototext`-format
    /// FileDescriptorSet.
    #[arg(long = "descriptor-set", env = "PROTOLENS_DESCRIPTOR_SET")]
    descriptor_set: Option<PathBuf>,

    /// Root message type. If omitted, inferred automatically from
    /// --descriptor-set (requires a hopcroft.rkyv scoring graph next to
    /// it); if inference is unavailable or inconclusive, the blob is
    /// rendered with no known type.
    #[arg(
        short = 't',
        long = "type",
        add = ArgValueCompleter::new(complete::complete_type_names),
    )]
    r#type: Option<String>,

    /// Number of spaces per nesting level in the rendered text.
    #[arg(long = "indent", default_value_t = 2)]
    indent: usize,

    /// Suppress inline `#@ ...` annotations (wire type, field decl,
    /// modifiers). On by default: annotations are important for reversing
    /// unknown/mismatched wire data to a plausible type.
    #[arg(long = "no-annotations")]
    no_annotations: bool,

    /// Binary protobuf to decode.
    blob: PathBuf,
}

fn main() -> ExitCode {
    // Dynamic shell completion — same model as Cargo/prototext. When
    // PROTOLENS_COMPLETE=<shell> is set, print the completion script and
    // exit.
    CompleteEnv::with_factory(Cli::command)
        .var("PROTOLENS_COMPLETE")
        .complete();

    let cli = Cli::parse();

    let Some(descriptor_set) = cli.descriptor_set.as_deref() else {
        eprintln!(
            "error: --descriptor-set is required in v1 (no schemaless mode); \
             pass --descriptor-set <path>"
        );
        return ExitCode::FAILURE;
    };

    let blob = match std::fs::read(&cli.blob) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("error: cannot read '{}': {e}", cli.blob.display());
            return ExitCode::FAILURE;
        }
    };

    // Accept a `#@ prototext` text blob transparently: convert it to raw
    // binary wire bytes first, same as `prototext`'s own
    // `read_descriptor_file` (prototext/src/run.rs). Binary input is
    // returned unchanged (pass-through).
    let blob = match render_as_bytes(&blob, RenderOpts::default()) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("error: '{}': {e}", cli.blob.display());
            return ExitCode::FAILURE;
        }
    };

    let mut ctx = match decode::DescriptorContext::load(descriptor_set) {
        Ok(ctx) => ctx,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::FAILURE;
        }
    };

    let decoded = match decode::decode(
        &blob,
        &mut ctx,
        cli.r#type.as_deref(),
        cli.indent,
        !cli.no_annotations,
    ) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::FAILURE;
        }
    };

    let blob_label = cli
        .blob
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| cli.blob.display().to_string());

    let mut app = tui::App::new(
        decoded,
        &blob_label,
        cli.blob.clone(),
        !cli.no_annotations,
        cli.indent,
        ctx,
    );
    if let Err(e) = tui::run(&mut app) {
        eprintln!("error: {e}");
        return ExitCode::FAILURE;
    }

    ExitCode::SUCCESS
}
