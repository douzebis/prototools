<!--
SPDX-FileCopyrightText: 2025 - 2026 Frederic Ruget <fred@atlant.is> <fred@s3ns.io> (GitHub: @douzebis)
SPDX-FileCopyrightText: 2025 - 2026 Thales Cloud Sécurisé

SPDX-License-Identifier: MIT
-->

[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/douzebis/prototools)
[![crates.io](https://img.shields.io/crates/v/prototext.svg)](https://crates.io/crates/prototext)

# prototools

A collection of protobuf utilities written in Rust.

## Tools

### `prototext`

Lossless, bidirectional converter between binary protobuf wire format and a
human-readable text representation.

Three promises:

1. **Schema-aware** — supply a compiled `.pb` descriptor and a root message
   type to get field names, proto types, and enum values.  A schema is never
   required; without one every field is decoded by wire type and field number.
2. **Lossless round-trip** — `binary → text → binary` is byte-for-byte
   identical for any input: well-formed, non-canonical, or malformed.
3. **protoc-compatible** — for canonical protobuf messages the text output is
   identical to `protoc --decode`.

#### Text format

The text side is a superset of the
[protobuf text format](https://protobuf.dev/reference/protobuf/textformat-spec/)
as produced by `protoc`.  Every field line carries an inline annotation comment
that encodes enough metadata to reconstruct the exact binary bytes on
re-encoding:

```
#@ prototext: protoc
doubleOp: 2.718  #@ optional double = 21;
floatRp: [1.5, 2.5, 3.5]  #@ repeated float [packed=true] = 42;
messageOp {  #@ optional SwissArmyKnife = 31;
  int32Op: 200  #@ optional int32 = 25;
}
GroupOp {  #@ GROUP; optional GroupOp = 30;
  uint64Op: 111  #@ optional uint64 = 130;
}
999: 12345  #@ VARINT;
stringOp: "hello"  #@ optional string = 29; tag_overhang_count: 2;
99: "\001\002"  #@ TRUNCATED_BYTES; missing_bytes_count: 5; optional bytes = 99;
type: TYPE_STRING  #@ Type(9) = 5
type: 99  #@ Type(99) = 5; ENUM_UNKNOWN
```

The annotation format is documented in
[`docs/annotation-format.md`](docs/annotation-format.md).

`google.protobuf.*` types are available without supplying a descriptor
(embedded at compile time).

#### Usage

```
prototext -d [-D descriptor.pb -t pkg.Message] [FILE ...]   # binary → text
prototext -e [FILE ...]                                      # text   → binary
```

Key flags:

| Flag | Meaning |
|---|---|
| `-d` / `--decode` | Binary → text (exclusive with `-e`) |
| `-e` / `--encode` | Text → binary (exclusive with `-d`) |
| `-D` / `--descriptor PATH` | Compiled `.pb` descriptor file |
| `-t` / `--type NAME` | Root message type (e.g. `pkg.MyMessage`) |
| `-o PATH` | Write output to file (single input) |
| `-O DIR` | Output root directory (batch mode) |
| `-I DIR` | Input root directory |
| `-i` / `--in-place` | Rewrite each input file in place |
| `-q` / `--quiet` | Suppress warnings |

#### Install

**Nix (recommended)** — installs the binary, man page, and shell completions
for bash, zsh, and fish:

```
nix-build https://github.com/douzebis/prototools/archive/main.tar.gz
```

**Nix dev shell** — builds from source, generates the man page, and activates
bash completion in the current shell:

```
nix-shell https://github.com/douzebis/prototools/archive/main.tar.gz
```

**cargo install** — installs the binary and a helper for generating the man
page; shell completions must be activated manually:

```
cargo install prototext
```

After `cargo install`, activate completions in your shell:

```bash
# bash
source <(PROTOTEXT_COMPLETE=bash prototext)

# zsh
source <(PROTOTEXT_COMPLETE=zsh prototext)

# fish
PROTOTEXT_COMPLETE=fish prototext | source
```

Generate and install the man page:

```bash
cargo install prototext          # also installs prototext-gen-man
prototext-gen-man ~/.local/share/man/man1
```

From the GitHub repository:

```
cargo install --git https://github.com/douzebis/prototools prototext
```

#### Quick start

The examples below use two tiny fixture files from `fixtures/cases/` in the
cloned repository.  No schema is needed — `prototext` decodes them
schemalessly, rendering each field by wire type and field number.

**Canonical encoding** — `fixtures/cases/qs_canonical.pb` holds the text
representation of a single varint field:

```
$ cat fixtures/cases/qs_canonical.pb
#@ prototext: protoc
1: 42  #@ varint
```

Encode to binary, inspect the two bytes, then round-trip back to text:

```
$ prototext -e fixtures/cases/qs_canonical.pb | od -A n -t x1
 08 2a

$ prototext -e fixtures/cases/qs_canonical.pb | prototext -d
#@ prototext: protoc
1: 42  #@ varint
```

**Non-canonical encoding** — `fixtures/cases/qs_noncanonical.pb` encodes the
same value with one redundant continuation byte (`val_ohb: 1`):

```
$ cat fixtures/cases/qs_noncanonical.pb
#@ prototext: protoc
1: 42  #@ varint; val_ohb: 1
```

The annotation tells the encoder to preserve the extra byte.  The binary is
three bytes instead of two — same value, different encoding:

```
$ prototext -e fixtures/cases/qs_noncanonical.pb | od -A n -t x1
 08 aa 00

$ prototext -e fixtures/cases/qs_noncanonical.pb | prototext -d
#@ prototext: protoc
1: 42  #@ varint; val_ohb: 1
```

#### Shell completion

```bash
# bash (workaround for known clap_complete path-completion bugs):
source <(PROTOTEXT_COMPLETE=bash prototext | sed \
  -e '/^\s*) )$/a\    compopt -o filenames 2>/dev/null' \
  -e 's|words\[COMP_CWORD\]="$2"|local _cur="${COMP_LINE:0:$COMP_POINT}"; _cur="${_cur##* }"; words[COMP_CWORD]="$_cur"|')
```

## License

MIT — see [`LICENSES/MIT.txt`](LICENSES/MIT.txt).
