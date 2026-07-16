// SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

mod colorize;
mod complete;
mod decode;
mod extract;
mod override_pane;
mod render_cache;
mod theme;
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
    /// Batch action to perform and exit. If omitted, protolens launches
    /// the interactive TUI (spec 0123).
    #[command(subcommand)]
    command: Option<Command>,

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

    /// Syntax-highlighting color palette (spec 0116 §9). `system` probes
    /// the terminal's actual background once at startup and resolves to
    /// `dark` or `light`.
    #[arg(long = "theme", value_enum, default_value = "system")]
    theme: theme::ThemeKind,

    /// Binary protobuf to decode.
    blob: PathBuf,
}

/// Batch (non-interactive) subcommands (spec 0123).
#[derive(clap::Subcommand)]
enum Command {
    /// Extract one node's rendering and exit, without entering the
    /// interactive TUI.
    Extract {
        /// Field path of the node to extract, in positional-path
        /// notation (`/` = document root; `/1/2` = root's 1st child's
        /// 2nd child — same notation the TUI's status line displays per
        /// node).
        path: String,

        /// Previously-saved override collection (spec 0117 §4 YAML, the
        /// same file `:save-overrides` writes) to apply before
        /// extraction. A target-hash mismatch against the loaded blob/
        /// descriptor-set is a warning (to stderr), not a hard error —
        /// same policy as the `:restore-overrides` TUI command. A
        /// missing file or malformed YAML, unlike the TUI, is a hard
        /// error.
        #[arg(long = "load-overrides")]
        load_overrides: Option<PathBuf>,

        /// Output format. Defaults to `text`.
        #[arg(long = "format", value_enum)]
        format: Option<ExtractFormatArg>,

        /// Write to this file instead of stdout.
        #[arg(short = 'o', long = "output")]
        output: Option<PathBuf>,
    },
}

/// Mirrors `extract::ExtractFormat`'s two variants — a separate type
/// since `ExtractFormat` itself has no `clap::ValueEnum` derive.
#[derive(Clone, Copy, clap::ValueEnum)]
enum ExtractFormatArg {
    Text,
    Binary,
}

impl From<ExtractFormatArg> for extract::ExtractFormat {
    fn from(f: ExtractFormatArg) -> Self {
        match f {
            ExtractFormatArg::Text => extract::ExtractFormat::Text,
            ExtractFormatArg::Binary => extract::ExtractFormat::Binary,
        }
    }
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

    let decoded = match decode::decode(&blob, &mut ctx, cli.r#type.as_deref(), cli.indent) {
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

    // Theme/color resolution is irrelevant to batch mode's plain stdout/
    // file output (spec 0123 Non-goals) — only resolved, and only probes
    // the terminal, when actually about to enter the TUI.
    let theme = match &cli.command {
        None => {
            // Resolved exactly once, before any rendering (spec 0116 §9)
            // — no live re-detection while running.
            let theme = match cli.theme {
                theme::ThemeKind::System => theme::resolve_system(),
                resolved => resolved,
            };
            // Primes the XTGETTCAP RGB probe now, before `tui::run` takes
            // over the terminal with its own crossterm event loop (see
            // `prime_supports_rgb` doc comment).
            theme::prime_supports_rgb();
            theme
        }
        Some(_) => theme::ThemeKind::Dark,
    };

    let mut app = tui::App::new(
        decoded,
        &blob_label,
        cli.blob.clone(),
        cli.indent,
        ctx,
        theme,
    );

    match cli.command {
        Some(Command::Extract {
            path,
            load_overrides,
            format,
            output,
        }) => {
            if let Some(overrides_path) = &load_overrides {
                match app.load_overrides(&overrides_path.to_string_lossy()) {
                    Ok(warnings) => {
                        for w in warnings {
                            eprintln!("warning: --load-overrides: {w}");
                        }
                    }
                    Err(e) => {
                        eprintln!(
                            "error: --load-overrides '{}': {e}",
                            overrides_path.display()
                        );
                        return ExitCode::FAILURE;
                    }
                }
            }

            let format = format
                .map(Into::into)
                .unwrap_or(extract::ExtractFormat::Text);

            let Some(idx) = app.resolve_path(&path) else {
                eprintln!("error: extract path '{path}' does not resolve");
                return ExitCode::FAILURE;
            };

            let bytes = app.extract_bytes(idx, format);
            match output {
                Some(out_path) => {
                    if let Err(e) = std::fs::write(&out_path, &bytes) {
                        eprintln!("error: cannot write '{}': {e}", out_path.display());
                        return ExitCode::FAILURE;
                    }
                }
                None => {
                    use std::io::Write as _;
                    if let Err(e) = std::io::stdout().write_all(&bytes) {
                        eprintln!("error: writing to stdout: {e}");
                        return ExitCode::FAILURE;
                    }
                }
            }
            ExitCode::SUCCESS
        }
        None => {
            if let Err(e) = tui::run(&mut app) {
                eprintln!("error: {e}");
                return ExitCode::FAILURE;
            }
            ExitCode::SUCCESS
        }
    }
}
