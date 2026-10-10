<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0406 — bash completion from the raw command line

Status: implemented
Implemented in: 2026-10-10
App: prototext, protolens (bash completion)
Refs: docs/specs/0405-prototools-in-nixpkgs-one-small-pr-at-a-time.md
      (S3, which this spec replaces: the nixpkgs recipe installs the
      completion script without patching it);
      clap-rs/clap#6280 and clap-rs/clap#6364 (the upstream discussion,
      and our open PR there)

## Background

prototext and protolens get their completions from clap_complete's
`CompleteEnv`: `PROTOTEXT_COMPLETE=bash prototext` prints a bash script,
and the script calls the binary back on each Tab. `nix/rust.nix` patches
that script with a `sed` at install time, and yb's nixpkgs recipe
carries the same patch.

Measured on 2026-10-10 by pressing Tab in an interactive bash through a
pseudo-terminal, with prototext 0.2.1:

| Typed, then Tab | clap_complete's script | With our `sed` (shipped today) |
|---|---|---|
| `decode da` | `data ` (no `/`) | `data/` |
| `decode dir` (a dir with spaces) | `dir with space ` (three words) | `dir\ with\ space/` |
| `decode "dir w` | `"dir with space" ` | no completion |
| `decode dir\ w` | no completion | no completion |
| `decode a:` | lists every option | `a:a\:b/`: the line is corrupted |
| `--descriptor-set=da` | no completion | `--descriptor-set=da--descriptor-set\=data `: the line is corrupted |

Two problems, which the `sed` only half fixes:

1. **No `-o filenames`.** bash treats completed paths as plain words: no
   `/` after a directory, no escaping of spaces. The `sed` adds it, and
   that part works.
2. **bash splits words at `COMP_WORDBREAKS`** (`=`, `:` and others), so
   clap's engine receives `--descriptor-set`, `=`, `da` instead of
   `--descriptor-set=da`, and readline replaces only the text after the
   last break. The `sed`'s second change, which rebuilds the current word
   from `COMP_LINE`, breaks quoted words, the case it was meant for, and
   corrupts the line after a `:` or `=`.

So the completion we ship today, in Nix and in the GreHack image,
corrupts the command line in common cases (`--descriptor-set=…`, paths
containing `:`).

Upstream (#6280), four fixes are on the table: changing
`COMP_WORDBREAKS`, stripping prefixes, depending on bash-completion, and
reassembling `COMP_WORDS` (our #6364). None is decided. The maintainer's
stated ideal is that the shell should not split words at all: "We have a
full CLI parser and don't need the assistance of the shell."

## Goals

- **G1.** Tab completion in bash is correct for every row of the table
  above, and for options, values and subcommands, as in the "Measured
  outcome" target below. A completion never corrupts the line.
- **G2.** No `sed` and no other patching anywhere: the script the binary
  prints is the script that gets installed, by `nix/rust.nix`, by the
  nixpkgs recipe (spec 0405), and by a user following the README.
- **G3.** Only clap_complete's public API, and one implementation shared
  by prototext and protolens.

## Non-goals

- **N1.** zsh, fish, elvish and PowerShell. Their scripts stay
  clap_complete's, unchanged.
- **N2.** reproto, a Python CLI with its own hand-written
  `completions.sh`, and protoscan, a Python CLI using click's
  completion. protoscan gets this completion when it is rewritten in
  Rust (spec 0407).
- **N3.** Shell syntax beyond words, quotes and backslashes: `$'…'`,
  variables, command substitutions, globs and redirections in the line
  being completed. Completion of such a line falls back to bash's
  default completion (`-o bashdefault`).
- **N4.** Changing `COMP_WORDBREAKS`. It is a global setting that other
  completion scripts depend on.

## Specification

- **S1. The script.** For bash, `PROTOTEXT_COMPLETE=bash prototext`
  prints this registration, about ten lines, held as one string constant
  in our code. `NAME`, `BIN` and `COMPLETER` are filled in as
  clap_complete does:

  ```bash
  _prototools_complete_NAME() {
      local IFS=$'\013'
      COMPREPLY=( $( _CLAP_IFS="$IFS" VAR=bash \
          "COMPLETER" -- "${COMP_LINE:0:$COMP_POINT}" "$2" ) )
      [[ ${#COMPREPLY[@]} -eq 1 && ${COMPREPLY[0]} == */ ]] && compopt -o nospace
  }
  complete -o filenames -o bashdefault -F _prototools_complete_NAME BIN
  ```

  The function passes the binary two strings: the raw line up to the
  cursor, and `$2`, the word readline is completing. It never uses
  `COMP_WORDS`, so bash's word splitting is never involved. After a
  single directory it adds no space, so the next Tab completes inside
  it. `nosort` is kept when bash is new enough to support it, as in
  clap_complete.
- **S2. The completer.** A type implementing clap_complete's public
  `EnvCompleter` trait, registered for bash through
  `CompleteEnv::shells(Shells(&[...]))`, in place of
  `clap_complete::env::Bash` and alongside clap_complete's other
  shells. `CompleteEnv` already separates the two requests (print the
  script, or complete), and passes `write_complete` everything after
  `--`, which is exactly the two strings of S1. `write_complete` then:
  1. **Splits the line as the shell would:** whitespace separates words;
     single quotes, double quotes (with `\"`, `\\`, `` \` ``, `\$`) and
     backslashes are handled; an unterminated quote at the cursor is
     allowed. The result is the list of words, and whether the cursor is
     inside an open quote. A line ending in unquoted whitespace ends with
     an empty current word.
  2. **Asks clap's engine,** `clap_complete::engine::complete(cmd,
     words, index_of_last_word, current_dir)`, which returns whole words,
     for example `--descriptor-set=data` for `--descriptor-set=da`. A
     directory candidate gets a trailing `/`, which clap's engine does
     not add. readline adds one itself only when the text it inserts is
     a directory; after `a:` it inserts the `b` of `a:b` and finds no
     `b`. Inside an open quote the `/` is dropped again, since readline
     adds it after closing the quote. For `--opt=value` the value is
     what is tested.
  3. **Keeps only what readline replaces.** readline replaces only its
     own word, `$2`. Inside an open quote that is the literal text after
     the quote; otherwise it is shell text, split by the rules of step 1.
     The candidate loses its leading part: the length of the unquoted
     current word minus the length of readline's word. A candidate that
     does not start with the text it would lose is dropped.
  4. **Prints the candidates** separated by `_CLAP_IFS`, as clap_complete
     does.
- **S3. Where it lives.** In a new workspace crate, `prototools-complete`,
  that prototext and protolens both depend on. It is small: about ten
  lines of bash and about a hundred of Rust, plus its tests. When
  prototext is published to crates.io, this crate is published with it.
  - Not in prototext-core: it would bring clap into the codec library,
    which the internal package and the Python extensions also build.
  - Not as a module copied into both binaries: two copies is the drift
    this spec removes.
- **S4. Every consumer installs it as is.**
  - `nix/rust.nix`: both `sed` pipelines go, and completions install
    from `<(PROTOTEXT_COMPLETE=bash $out/bin/prototext)` and protolens's
    equivalent.
  - The README's `source <(PROTOTEXT_COMPLETE=bash prototext)` is
    unchanged and now gets the fixed script.
  - Nothing else changes: zsh and fish install as today.
- **S5. clap_complete's engine is behind its `unstable-dynamic` feature**,
  which both binaries already enable for `CompleteEnv`. `Cargo.lock`
  pins its version, and the tests (S6) are what a clap_complete update
  has to pass.
- **S6. Tests.**
  - **Unit tests, pure Rust,** in `prototools-complete`: the line
    splitting (words, quotes, backslashes, an open quote, trailing
    whitespace, UTF-8) and the trimming of step 3, one case per row of
    the table. They run in `cargo test` and so in `ci`.
  - **End to end: an interactive bash, driven through a
    pseudo-terminal,** pressing Tab after each typed line, in a
    directory holding `data/x.pb`, `dir with space/y.pb`, `a:b/z.pb`,
    `ka:li.pb` and `été/`. Each line must complete to the expected text
    below. It runs for prototext and for protolens, as a `ci` derivation
    if the Nix sandbox provides a pseudo-terminal, and otherwise as a
    script run by the dev-shell and documented as such.

## Alternatives considered

### Keep the `sed`, minus its harmful half

Only `-o filenames`: paths complete and the line is never corrupted. But
`--descriptor-set=…` and paths containing `:` still do not complete, and
every recipe, nixpkgs included, carries a patch. It is the fallback if
this spec stalls, not the goal.

### Reassemble `COMP_WORDS` in bash (our clap PR #6364)

Correct, but it is a bash reimplementation of bash-completion's
`_comp__reassemble_words`, which is the hard part, in the language
hardest to test. It is also still a patch to clap_complete's script:
carried in our code, it would be the `sed` again in another form.

### Depend on bash-completion (`_get_comp_words_by_ref`, `__ltrim_colon_completions`)

The standard bash approach (clap #6311). But completion would break
silently on systems without the bash-completion package: minimal
containers, and macOS's default bash, which would need it installed
separately.

### Change `COMP_WORDBREAKS`

It is global to the shell, and other completion scripts depend on it.
Changing it inside the function is too late, since bash has already
split the line, and changing it in the script changes every other
command's completion (clap #6283, closed by its author for that
reason).

### Wait for clap upstream

#6280 has been open since February, and #6364 is parked as a draft
pending a decision there. This spec does not compete with it. If
upstream settles, the completer can switch to it, and S6's tests say
whether it covers the same cases. Proposing this approach on #6280,
once it is proven here, is a separate decision.

## Test plan

1. The S6 unit tests.
2. The S6 end-to-end test. Expected results, for prototext (and the same
   for protolens with its own options):

   | Typed, then Tab | Completes to |
   |---|---|
   | `prototext decode da` | `prototext decode data/` |
   | `prototext decode dir` | `prototext decode dir\ with\ space/` |
   | `prototext decode "dir w` | `prototext decode "dir with space"/` |
   | `prototext decode 'dir w` | `prototext decode 'dir with space'/` |
   | `prototext decode dir\ w` | `prototext decode dir\ with\ space/` |
   | `prototext decode a:` | `prototext decode a:b/` |
   | `prototext decode a:b/` | `prototext decode a:b/z.pb ` |
   | `prototext decode ka:` | `prototext decode ka:li.pb ` |
   | `prototext --descriptor-set=da` | `prototext --descriptor-set=data/` |
   | `prototext --descriptor-set=dir\ w` | `prototext --descriptor-set=dir\ with\ space/` |
   | `prototext --descriptor-set="dir w` | `prototext --descriptor-set="dir with space"/` |
   | `prototext --descriptor-set da` | `prototext --descriptor-set data/` |
   | `prototext decode ét` | `prototext decode été/` |
   | `prototext decode data/x` | `prototext decode data/x.pb ` |
   | `prototext decode --t` | `prototext decode --type ` |
   | `prototext dec` | `prototext decode ` |

   A prototype of the S1 script, with a stand-in for the binary that
   completes only file names, gave the first fourteen rows on
   2026-10-10. The last two rows (options and subcommands) need the real
   engine.
3. `nix/rust.nix` contains no `sed` on a completion script, and the
   installed `prototext.bash` is byte-identical to
   `PROTOTEXT_COMPLETE=bash prototext` output.
4. zsh and fish scripts are unchanged from clap_complete's.
5. `ci`, the image and its smoke test pass.

## Measured outcome

Implemented 2026-10-10, in `prototools-complete/` (`src/lib.rs`), used by
prototext and protolens through `CompleteEnv::shells`.

- **S1, S2:** the script and completer as specified. One step was added
  at implementation: clap's engine returns directories without a `/`
  (`data`, `b`), so the completer appends it (step 2). The prototype's
  stand-in had added it itself, which is why the prototype missed it:
  `decode a:` gave `a:b ` instead of `a:b/` in the first run against the
  real engine.
- **S4:** both `sed` pipelines are gone from `nix/rust.nix`. The
  installed `prototext.bash` is what `PROTOTEXT_COMPLETE=bash prototext`
  prints.
- **S6, unit tests:** 7, in `prototools-complete`, covering line
  splitting, trimming and directory marking.
- **S6, end to end:** `prototools-complete/tests/tab_completion.py`.
  Every row of the test plan's table passes for both tools: 16 rows for
  prototext, and 15 for protolens, which has no subcommand row.
  - It runs in `ci` as `completionTests`, which needs `bashInteractive`
    (stdenv's bash has no readline).
  - The Nix sandbox provides a pseudo-terminal (`/dev/pts`), checked on
    x86-64 Linux. macOS is first exercised by the CI's macos-15 job.
