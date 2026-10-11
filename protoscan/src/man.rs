// SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

//! Man page generation from the live clap definition (spec 0407 S4).
//!
//! Driven by an environment variable, as protolens's is, rather than a
//! separate `protoscan-gen-man` binary that users would never run.
//!
//! Usage:
//!   PROTOSCAN_GEN_MAN=man/man1 protoscan

use std::path::PathBuf;

/// Write `<$PROTOSCAN_GEN_MAN>/protoscan.1` and exit, or return if the
/// variable is unset.
///
/// Called before `Cli::parse()`, so FILE does not have to be supplied to
/// generate the page.
pub fn generate_and_exit_if_requested(cmd: clap::Command) {
    let Some(dir) = std::env::var_os("PROTOSCAN_GEN_MAN") else {
        return;
    };
    let out_dir = PathBuf::from(dir);
    std::fs::create_dir_all(&out_dir).expect("cannot create output directory");

    let man = clap_mangen::Man::new(cmd)
        .title("PROTOSCAN")
        .section("1")
        .source("protoscan")
        .manual("User Commands");

    let mut buf = Vec::new();
    man.render(&mut buf).expect("man page rendering failed");
    buf.extend_from_slice(EXTRA_SECTIONS.as_bytes());

    let dest = out_dir.join("protoscan.1");
    std::fs::write(&dest, &buf).unwrap_or_else(|e| panic!("cannot write {}: {e}", dest.display()));

    eprintln!("wrote {}", dest.display());
    std::process::exit(0);
}

/// Sections clap cannot derive.
const EXTRA_SECTIONS: &str = r#"
.SH ENVIRONMENT
.TP
\fBPROTOSCAN_COMPLETE\fR
When set to \fBbash\fR, \fBzsh\fR, or \fBfish\fR, print a shell completion
script to stdout and exit.
.TP
\fBPROTOSCAN_GEN_MAN\fR
When set to a directory, write this man page there as \fBprotoscan.1\fR
and exit.
.SH EXAMPLES
.SS List the descriptors a program embeds
.PP
.nf
protoscan ./some_binary
.fi
.SS Extract them, then decode one with prototext
.PP
.nf
protoscan --proto-out extracted/ ./some_binary
prototext decode -t google.protobuf.FileDescriptorProto extracted/foo/v1/foo.pb
.fi
.SS Enable bash completion
.PP
.nf
source <(PROTOSCAN_COMPLETE=bash protoscan)
.fi
.SH SEE ALSO
\fBprototext\fR(1), \fBprotolens\fR(1), \fBreproto\fR(1)
"#;
