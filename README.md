<!--
SPDX-FileCopyrightText: 2025-2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
SPDX-FileCopyrightText: 2025-2026 Thales Cloud Sécurisé

SPDX-License-Identifier: MIT
-->

# prototools

A collection of protobuf utilities written in Rust.

## Tools

### `prototext`

Lossless, bidirectional converter between binary protobuf wire format and an
annotated text representation.

**The core guarantee:** `binary → text → binary` is byte-for-byte identical for
any input — well-formed, malformed, non-canonical, or schema-unknown.

#### Text format

The text side is a superset of the
[protobuf text format](https://protobuf.dev/reference/protobuf/textformat-spec/)
as produced by `protoc`.  Every field line carries an inline annotation comment
that encodes enough information to reconstruct the exact binary bytes on
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
[`docs/annotation-format.md`](docs/annotation-format.md) (grammar reference
with annotated examples and a proposed v2 format).

Annotations can be suppressed with `--no-annotations`; the output is then
mostly\* compatible with `protoc --decode` but cannot be re-encoded losslessly.

#### Schema

A compiled `.pb` descriptor and a root message type can be provided to resolve
field names and proto types.  Without a schema every field is treated as unknown
and rendered by field number.

`google.protobuf.*` types are available without supplying a descriptor (embedded
at compile time).

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
| `--no-annotations` | Suppress inline annotations (not round-trippable) |
| `-o PATH` | Write output to file (single input) |
| `-O DIR` | Output root directory (batch mode) |
| `-I DIR` | Input root directory |
| `-i` / `--in-place` | Rewrite each input file in place |
| `-q` / `--quiet` | Suppress warnings |

#### Install

From [crates.io](https://crates.io/crates/prototext) (once published):

```
cargo install prototext
```

From the GitHub repository:

```
cargo install --git https://github.com/douzebis/prototools prototext
```

Both install `prototext` to `~/.cargo/bin/`.

#### Quick start

The examples below use two tiny fixture files from `fixtures/cases/` in the
cloned repository.  No schema file is needed — `prototext` decodes them
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
$ prototext -e fixtures/cases/qs_canonical.pb | hexdump -C
00000000  08 2a                                             |.*|
00000002

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
$ prototext -e fixtures/cases/qs_noncanonical.pb | hexdump -C
00000000  08 aa 00                                          |...|
00000003

$ prototext -e fixtures/cases/qs_noncanonical.pb | prototext -d
#@ prototext: protoc
1: 42  #@ varint; val_ohb: 1
```

The core guarantee holds for both: `text → binary → text` is byte-for-byte
identical, even for non-canonical encodings.

#### Shell completion

```bash
# bash (workaround for known clap_complete path-completion bugs):
source <(PROTOTEXT_COMPLETE=bash prototext | sed \
  -e '/^\s*) )$/a\    compopt -o filenames 2>/dev/null' \
  -e 's|words\[COMP_CWORD\]="$2"|local _cur="${COMP_LINE:0:$COMP_POINT}"; _cur="${_cur##* }"; words[COMP_CWORD]="$_cur"|')
```

## License

MIT — see [`LICENSES/MIT.txt`](LICENSES/MIT.txt).

---

\* Output differs from `protoc --decode` in that packed
repeated fields use bracket notation (`floatRp: [1.5, 2.5, 3.5]`) rather than
one entry per line.
