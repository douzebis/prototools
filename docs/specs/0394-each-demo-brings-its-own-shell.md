<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0394 — each demo brings its own shell

Status: implemented
Implemented in: 2026-10-05
App: nix (dev-shell, demo shells), grehack2026, grpconf2026
Refs: docs/specs/0374-a-workshop-image-for-every-laptop.md (the
      `runtime` tool set the workshop image ships, reused here);
      docs/specs/0388-the-demo-runs-from-grehack2026.md (S4: the three
      grehack2026 windows, set up in the dev-shell);
      docs/specs/0393-only-dumpcap-runs-as-root.md (what the grehack
      tap needs: dumpcap, tshark)

## Background

Both demos run their windows in the repository's development shell,
`nix-shell dev-shell.nix`, entered at the repository root before
changing to the demo directory. That shell carries what each demo needs:

- grehack2026: `grehackLife` (life-server, life-client, life-tap),
  `wireshark-cli` (dumpcap, tshark) and `fortune`;
- grpconf2026: `grpconfDemo` (bobapp, its log and capture), copied into
  `grpconf2026/{bob,alice}` by `_hook_demo`, and the googleapis schema
  database, `googleapisDb` and `googleapisPbs`, exported as
  `PROTOTEXT_GOOGLEAPIS_SET` and `PROTOTEXT_GOOGLEAPIS_PBS`.

Building `googleapisDb` fetches the pinned googleapis corpus, runs
`protoc` over all of it, and runs `reproto --schema-db-out`. That is a
noticeable delay whenever its inputs change, paid by every developer
entering the dev-shell, demo or not. `grehackLife` is rebuilt at the
next dev-shell entry after any change to `grehack2026/game`.

The demo tools also come from the development tree: `bin/` wrappers and
`target/release/`, which hold whatever was last built with cargo, not
what is committed or what the workshop image ships.

The dev-shell cannot simply be entered from a demo directory: its hooks
assume the repository root (`_hook_cargo` builds
`$PWD/target/release/…`; `_hook_python` writes `python.env`,
`pyrightconfig.json` and `ruff.toml` into `$PWD`).

## Goals

- **G1.** Each demo directory has a `shell.nix`: `cd` there, run
  `nix-shell`, and the window has everything that demo needs.
  grehack2026: `grehack2026/`, `grehack2026/eve/`, `grehack2026/bob/`.
  grpconf2026: `grpconf2026/`.
- **G2.** The demo shells take every tool from Nix, built from committed
  sources, as the workshop image does, and never from `target/release/`
  or `bin/`.
- **G3.** `dev-shell.nix` carries nothing demo-specific: no
  `grehackLife`, `wireshark-cli`, `fortune`, `grpconfDemo` or googleapis
  database, and no `_hook_demo`.
- **G4.** Uses of the googleapis database outside the demos keep
  working, building it on demand.

## Non-goals

- **N1.** No change to the workshop image or its smoke test. The image
  sets its own environment.
- **N2.** Cheap, general packages stay in the dev-shell: `figlet`,
  `toilet`, `imagemagick`, `chafa`. They come from nixpkgs' cache and
  cost nothing to keep.
- **N3.** The demo shells are not development shells: no cargo, no
  Python environment, no hooks writing into the tree.

## Specification

- **S1. Two shell attributes in `default.nix`**, defined in a new
  `nix/demo-shells.nix`:
  - `grehack2026-shell`: `grehack2026.runtime` (prototext, protolens
    with its lean Neovim, reproto, protoscan, the WKT database, life,
    wireshark-cli, fortune), plus `teleprompt` (S3), `protobuf`
    (`protoc`, used by the deck) and `util-linux` (`hexdump`).
  - `grpconf2026-shell`: the same tool set without life, wireshark-cli
    and fortune, plus `teleprompt`, `protobuf`, `grpconfDemo`, and the
    googleapis database.

- **S2. The `shell.nix` files.** `grehack2026/shell.nix` and
  `grpconf2026/shell.nix` are each `(import ../default.nix { })` and
  the matching attribute. `grehack2026/eve/shell.nix` and
  `grehack2026/bob/shell.nix` are `import ../shell.nix`: `nix-shell`
  only reads the current directory's file, and this keeps one
  definition. `grpconf2026/bob` and `grpconf2026/alice` are generated
  and gitignored, so they get no `shell.nix`; the grpconf demo runs from
  `grpconf2026/`.

- **S3. `teleprompt` as a derivation** (`nix-build -A teleprompt`).
  `bin/teleprompt`, taken as a store path and wrapped with `wrapProgram`
  so that everything it calls is on its PATH: `python3` (its readline
  coprocess, which finds libreadline through `TELEPROMPT_LIBREADLINE`,
  also set by the wrapper), `magick` and `chafa` (`header`), `nvim`
  (`view`, `view_textproto`), and `tput`/`stty`. The demo shells do not put
  `bin/` on PATH: its `prototext`, `reproto` and `protoscan` wrappers
  point at `target/release/` (G2).

- **S4. Environment.** Both demo shells export
  `PROTOTEXT_DESCRIPTOR_SET` (the WKT database), and grpconf's also
  `PROTOTEXT_GOOGLEAPIS_SET` and `PROTOTEXT_GOOGLEAPIS_PBS`. They do
  not export `NIXSHELL_REPO`: they are not development shells (N3).
  They `unset` it, since `nix-shell` inherits the caller's environment
  and a demo shell entered from the dev-shell would otherwise keep it.
  So the post-edit lint hook treats them like any foreign shell and asks
  for the dev-shell before linting.

- **S5. grpconf's stage.** `_hook_demo` moves from the dev-shell to
  `grpconf2026-shell`'s shellHook, with `stage="$PWD"` instead of
  `"$PWD/grpconf2026"`. It keeps its sentinel, so re-entering costs
  nothing.

- **S6. One grpconf deck, run from `grpconf2026/`.** The long deck,
  `grpconf2026.sh`, is no longer in use (decided with the user,
  2026-10-05). It is removed with its `.init` and both `.license`
  sidecars. The 20-minute deck takes over its name:
  - `grpconf2026-20min.sh` becomes `grpconf2026.sh`;
  - `grpconf2026-20min.init` becomes `grpconf2026.init`, since
    teleprompt sources the `.init` that shares the deck's stem
    (`bin/teleprompt`);
  - both `.license` sidecars are renamed with them.

  The 20-minute deck already runs from `grpconf2026/` (all its paths are
  relative to it), so it needs no path changes.

- **S7. The dev-shell loses the demo parts (G3).** `nix/shells.nix`
  drops `grehackLife`, `wireshark-cli`, `fortune`, `grpconfDemo`,
  `googleapisDb` and `googleapisPbs` from its inputs and packages,
  `_hook_demo`, and the googleapis exports in `_hook_env`.
  `default.nix` stops passing them.

- **S8. googleapis on demand (G4).** `bin/profile`'s `startup` target,
  when `PROTOTEXT_GOOGLEAPIS_SET` is unset, builds the database itself
  (`nix-build -A googleapis-db --no-out-link`) and uses the result,
  instead of telling the user to enter the dev shell.
  `docs/prototext/walk-profiles.md` says the same.

- **S9. Docs.**
  - The grehack deck's setup notes and `synopsis.md` say: in each
    window, `cd` to the window's directory, then `nix-shell`.
  - `grehack2026/README.md` gains the same workflow.
  - `grpconf2026/artifacts.md`, which describes where `bob/` comes from,
    names the new shell.
  - `grpconf2026/speaker-notes.md`, the only other file naming
    `grpconf2026-20min`, names `grpconf2026.sh`.
  - `nix/shells.nix`'s header comment drops `_hook_demo`.

## Alternatives considered

### Point the demo `shell.nix` at the dev-shell

The simplest file, but the dev-shell's hooks write into and build from
`$PWD` (Background), so entering it from a demo directory would scatter
`python.env` and friends there. It would also keep the demos' slow
inputs in everyone's dev-shell.

### Tools from `target/release/`

What the dev-shell gives today: the latest cargo build appears at once.
But what is rehearsed then differs from what is committed and from what
the workshop image ships. Decided against with the user (2026-10-05).

### A dev-shell argument (`--arg withDemos true`)

Keeps one file, but the workflow is still "enter at the root, then
`cd`", and the argument is easy to forget. One `shell.nix` per demo
directory makes the right shell the default where it is needed.

## Test plan

1. `nix-build -A teleprompt` builds. (A `mkShell` derivation is not
   meant to be built, so the shells themselves are checked by entering
   them, items 2–3.)
2. In `grehack2026/`, `grehack2026/eve/` and `grehack2026/bob/`,
   `nix-shell --run 'command -v protolens prototext reproto protoscan
   life-server life-client life-tap teleprompt protoc hexdump'`: every
   tool resolves into `/nix/store`, none into the repository.
3. In `grpconf2026/`, the same for the grpconf tools, plus
   `PROTOTEXT_GOOGLEAPIS_SET` set and `bob/app` populated; a second
   entry skips the copy.
4. `nix-shell dev-shell.nix --run 'env'` from the repository root has no
   `PROTOTEXT_GOOGLEAPIS_*`, and its build closure no longer contains
   googleapis-db, grpconf-demo or life.
5. `bin/profile startup` works with `PROTOTEXT_GOOGLEAPIS_SET` unset.
6. A dry run of each deck's first section in its demo shell, the
   grpconf one as `teleprompt grpconf2026.sh`, checking that its
   (renamed) `.init` is sourced.
7. Time a dev-shell entry from cold, before and after, with
   `googleapisDb`'s inputs changed. This is the measurement behind the
   Background's "noticeable delay".

## Measured outcome

Measured 2026-10-05 on the development machine.

- Item 1: `teleprompt` builds, its shebang patched to the store's bash.
  It uses no bash line-editing builtins (its Python coprocess edits), so
  plain `bash` serves.
- Item 2: from `grehack2026/`, `eve/` and `bob/`, all twelve tools
  checked (the four prototools, the three `life-*`, `teleprompt`,
  `protoc`, `hexdump`, `dumpcap`, `tshark`) resolve into `/nix/store`.
  `PROTOTEXT_DESCRIPTOR_SET` is set and `NIXSHELL_REPO` unset. The first
  check found `NIXSHELL_REPO` set, inherited from the calling dev-shell,
  which is why S4 now unsets it.
- Item 3: entered from an empty scratch directory named `grpconf2026`,
  the shell populated `bob/` (`app` executable, `logfile`, `capture`)
  and `alice/`. A second entry skipped the copy. The tools resolve into
  `/nix/store`, and the three database variables name existing files.
- Item 4: the dev-shell's derivation depended on `googleapis-db`,
  `grpconf-demo`, the `life` package and `wireshark-cli` at HEAD, and
  depends on none of them after (`nix-store -qR` on
  `nix-instantiate dev-shell.nix`). Entering it runs every hook but the
  removed `_hook_demo`, and exports no `PROTOTEXT_GOOGLEAPIS_*`.
- Item 5: the new lines of `bin/profile` resolve the database from
  another working directory (`googleapis.desc`, 25 MB). A full
  `bin/profile startup` run, which builds and runs `perf`, was not done.
- Not done: item 6 (a dry run of each deck, which needs a terminal) and
  item 7 (timing a cold dev-shell entry with googleapis's inputs
  changed). Item 4 shows the dependency is gone; its cost was not
  measured.
- S6: the two grpconf `.init` files were identical, so nothing was lost
  with the long deck's. The 20-minute deck had no `[CUT n]` markers
  left, so `speaker-notes.md`'s two-version timing section became a
  single table.
