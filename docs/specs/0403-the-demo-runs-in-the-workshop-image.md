<!--
SPDX-FileCopyrightText: Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0403 — the demo runs in the workshop image

Status: implemented (pending: test plan items 4 and 6)
Implemented in: 2026-10-09
App: grehack2026 (deck, init, SETUP.md), life-tap, teleprompt, nix
        (grehack2026.nix, demo-shells.nix)
Refs: docs/specs/0374-a-workshop-image-for-every-laptop.md (the image
        this extends, its closure rule S2; may be merged into it),
        docs/specs/0393-only-dumpcap-runs-as-root.md (how life-tap
        picks its dumpcap), docs/specs/0394-each-demo-brings-its-own-shell.md
        (the demo shells), docs/specs/0395-the-teleprompt-deck-reads-more-easily.md
        (the Neovim config),
        docs/specs/0399-the-tap-stops-when-the-teleprompt-quits.md (the
        tap's exit hook)

## Background

The workshop image (spec 0374) carries the tools. The GreHack demo runs
only natively, from `grehack2026/` in the `grehack2026-shell`. The
audience can replay the game, but not the talk.

Running the deck in the image is possible. Measured on 2026-10-09
against the image's closure (1,070 MiB unpacked, ~240 MB compressed),
here is what the demo shell would add:

| Need | Demo shell today | Added to the image |
|---|---|---|
| Neovim and buf (`view`, `view_proto`) | full `neovim`, full `buf` | 0 when teleprompt uses the image's lean ones (`neovimLean`, `bufLean`). The full ones would add 120 MiB for buf alone, and pull in perl, which the closure check (0374 S2) rejects. |
| `header` banners | ImageMagick renders the SVG, then chafa draws it | ImageMagick: +112 MiB, and perl again. `imagemagick_light` cannot read SVG (tested). chafa reads SVG itself (tested). |
| `picture`, `header` | chafa | +74 MiB (librsvg, fontconfig, image codecs) |
| `hexdump` | util-linux | +8.5 MiB (`util-linuxMinimal`) |
| python3, protoc, readline | — | already in the image |

With chafa drawing the SVG and the lean editors, the demo adds about
85 MiB unpacked, 30 MiB gzipped.

The rest of the demo breaks in the container in five places:

1. **`sudo`.** The deck starts the tap with `sudo -v && (life-tap -q &)`.
   The image has no `sudo` and cannot have a working one: a Nix store
   holds no setuid binaries.
2. **The tap runs as root only.** It needs `CAP_NET_RAW` for dumpcap.
   - Podman (`--user 0`): the shell is root, and `life-tap` already runs
     dumpcap directly when it is root (0393 S1).
   - Docker (`--user 1000` by default): the shell is not root. The
     capability granted with `--cap-add` is not effective for a
     non-root process. Today SETUP.md works around this with
     `docker exec -u 0 workshop life-tap` in a separate terminal.
3. **The capture directory.** `life-tap` writes to `/work/capture` when
   `/work` exists, otherwise to `./capture`. The deck, `protolens`
   commands and the 0399 exit hook all expect `./capture` next to the
   deck. In the container, `/work` exists.
4. **Kitty's terminfo.** The image has no `xterm-kitty` terminfo, and
   SETUP.md passes `-e TERM`. From a kitty window, `less`, `tput` and
   Neovim inside the container then complain about an unknown terminal
   type.
5. **The material is not in the image.** The deck, init, beats and
   images are not in `/workshop`, and the deck writes next to itself
   (`capture/`, `life.desc`, `life/`, `eve/server.log`), so it needs a
   writable copy.

## Goals

- **G1.** The same deck runs unchanged in two places:
  - natively, from `grehack2026/` in the demo shell;
  - in the workshop image, under Podman and Docker, on Linux and macOS.
- **G2.** One configuration for both. The tools, the teleprompt wrapper,
  the Neovim config, the environment variables and the deck are all one
  Nix definition or one file, used by both. The only difference left is
  where the material sits (the git tree, or `/workshop/grehack2026`).
- **G3.** No `sudo` in the deck. Starting the tap is one command, the
  same everywhere, and it asks for privilege only where it needs to.
- **G4.** The image grows by at most 100 MiB unpacked, and still passes
  the 0374 S2 closure check (no perl, no ruby).
- **G5.** SETUP.md recommends kitty, as optional, and the image works
  from a kitty window.

## Non-goals

- **N1.** Running the demo as a non-root user inside the container. The
  tap needs root there (Background item 2), and the demo's files live
  in `/workshop`, not on the laptop, so root-owned files cost nothing.
- **N2.** File capabilities or a setuid helper for dumpcap in the image.
  The Nix store holds neither, and `dockerTools` layers do not carry
  the extended attributes file capabilities live in (not verified for
  `streamLayeredImage`, not pursued).
- **N3.** Making the grpconf2026 deck run in the image.
- **N4.** Requiring kitty. Every other terminal keeps working, with
  character-block pictures.

## Specification

### One tool set

- **S1. `demoTools`.** `nix/grehack2026-demo.nix` defines one list,
  `demoTools`, of what the deck calls beyond the prototools: the
  teleprompt, chafa, the lean Neovim and buf, protoc,
  `util-linuxMinimal` (for `hexdump`) and `kitty.terminfo`. It is its
  own file because `demo-shells.nix` takes the image's runtime as an
  input, so the image cannot take anything from it. Both of these use
  it:
  - `grehack2026-shell`: `grehackRuntime ++ demoTools`;
  - the image: `contents` gains `demoTools`.
- **S2. One teleprompt.**
  - teleprompt is wrapped with the lean Neovim and buf (`neovimLean`,
    `bufLean`, already in the image), not `pkgs.neovim` and full
    `buf`. The native shell gets the same lean pair on its PATH, so
    protolens's `v` behaves the same in both.
  - The Neovim config (`XDG_CONFIG_HOME`, spec 0395) stays in the
    wrapper and is the same store path in both.
- **S3. `header` without ImageMagick.**
  - chafa renders the SVG banner directly.
  - The title's width, which places the right-hand chevrons, is summed
    from a table of DejaVu Sans Bold advances at 28 px (`_TP_ADVANCES`
    in `bin/teleprompt`, read from the font's hmtx table). It replaces
    the `magick … -trim` measurement.
  - The SVG carries `width`/`height` at four times its viewBox, so
    librsvg rasterizes it sharp enough for kitty (ImageMagick rendered
    it at 300 dpi).
  - The wrapper sets `FONTCONFIG_FILE` to DejaVu Sans and Sans Bold
    (1.5 MiB). The image has no `/etc/fonts`, and this makes the face
    the same everywhere. A side effect: natively, today's banners came
    out in the regular weight, because the host's fontconfig had no
    DejaVu Sans Bold. The bundled font draws them truly bold.
  - ImageMagick leaves the wrapper, natively too.
  - **Gate:** before merging, compare each deck banner (`prototools`,
    the five section titles, `Annex`) old and new, side by side, in
    kitty and in a non-graphics terminal. If the chafa banners are
    visibly worse, stop and reopen: keep ImageMagick natively only, and
    accept that G2 fails for `header`.

### Starting the tap: no sudo in the deck

- **S4. `life-tap --detach`.** The new flag starts the tap in the
  background, then returns. Privilege is settled in the foreground,
  before it detaches, in 0393 S1's order:
  1. NixOS capability wrapper: nothing to do;
  2. root (the container): nothing to do;
  3. `sudo` on PATH: if `sudo -n -v` fails and stdin is a terminal, run
     `sudo -v` interactively (the password prompt). Then detach, and
     capture with `sudo -n dumpcap` as today;
  4. otherwise: fail before detaching, with `CAPTURE_HELP`.

  The tap is the same program, run again without `--detach`, in a
  process group of its own so that a Ctrl-C does not reach it. Its
  output goes to the terminal, as with `&`; its own "capturing" line
  says it started. `--detach` returns 0 once `tap.pid` holds the
  child's pid, or fails if the child exits first. The interactive
  `sudo -v` also applies without `--detach`, whenever stdin is a
  terminal. A backgrounded process cannot prompt
  for a password (`&` gets SIGTTIN on reading the terminal), which is
  why the deck has `sudo -v` on its own line today.
- **S5. The deck's tap line.** It becomes, everywhere:

  ```sh
  life-tap -q --detach --out capture
  ```

  `--out capture` keeps the capture next to the deck in the container
  too (Background item 3). The 0399 exit hook already passes `--out`.
- **S6. The container is root for the demo, under both runtimes.**
  - SETUP.md's demo section runs Docker with `--user 0` too, so the
    command is the same as Podman's apart from the binary name.
  - The "on Linux add `--user $(id -u):$(id -g)`" advice stays for the
    workshop's own exercises in `/work`, and does not apply to the
    demo.
  - life-tap already gives its files to the owner of `/work`
    (`owner()`). Everything else the demo writes stays in `/workshop`.
  - Docker run as non-root still fails cleanly: S4 step 4 prints
    `CAPTURE_HELP`, whose container line now reads "as root: podman
    runs as root already; with docker, run or exec with -u 0".

### The material in the image

- **S7. `/workshop/grehack2026`.** The image's `extraCommands` copies
  in, writable (`1777` directories, `0666` files, as 0374 S4 does for
  `/workshop`):
  - `grehack2026.sh`, `grehack2026.init`, `beats/`, `images/*.jpeg`;
  - `eve/` and `bob/`, empty;
  - `anomalies.pb`.

  The copy comes from a `lib.fileset` over exactly these paths, so
  natively and in the image the deck reads the same committed files.
- **S8. Three windows, the same cues.** The deck's cues name a window
  and a directory ("In Eve's window (eve/)"), never a command that
  only exists natively.
  - **Natively:** `cd grehack2026/eve && nix-shell`, as today.
  - **In the container:**
    `podman exec -it -w /workshop/grehack2026/eve workshop bash`, or
    with `docker`.
  - SETUP.md gets a section, *Replay the talk*, with the three
    commands per runtime and `teleprompt grehack2026.sh` for Alice's
    window.
  - The login banner (0374 S5) gets one line: "The talk:
    cd grehack2026 && teleprompt grehack2026.sh".
- **S9. Same environment.** `PROTOTEXT_DESCRIPTOR_SET` is set the
  same way in the image's `Env` and in the shell's `shellHook`, from
  one Nix attrset (`demoEnv`) that both read. `LANG` and
  `TERMINFO_DIRS` stay image-only: natively, the presenter's own
  locale and terminal setup apply.

### Kitty

- **S10. Terminfo.** `kitty.terminfo` is in `demoTools` (S1), so the
  image has `xterm-kitty` under `/share/terminfo`. ncurses reads only
  its own directory, so the image's `Env` sets
  `TERMINFO_DIRS=/share/terminfo`.
- **S11. tmux passes kitty images through.** The image's tmux gets
  `set -g allow-passthrough on` in a system `tmux.conf`. Whether chafa
  then draws real images in a pane is in the test plan. If not, SETUP.md
  says: run the deck in a plain `exec` terminal, not a tmux pane.
- **S12. SETUP.md recommends kitty.** Section 1 adds a line: "Optional:
  kitty (<https://sw.kovidgoyal.net/kitty/>) shows the talk's pictures
  as images; any other terminal shows them as character blocks". It
  also names WezTerm, Ghostty and iTerm2 as terminals chafa can draw
  real images in.

## Alternatives considered

- **A `sudo` shim in the image.** A script that runs its arguments when
  the caller is root and fails otherwise. The deck would then stay as
  it is. Dismissed for three reasons:
  - it lies to participants who type `sudo` for anything else;
  - it does nothing for Docker as non-root;
  - the deck would still carry a `sudo -v` line that means nothing in
    the container.

  S4 puts the privilege step in the one program that needs it.
- **The tap in its own `exec -u 0` window, as SETUP.md does for the
  workshop.** It needs a fourth window and a different deck step in the
  container (G1). It also loses the 0399 exit hook, since the
  teleprompt no longer started the tap.
- **Full Neovim and ImageMagick in the image.** +232 MiB, and perl in
  the closure (0374 S2). It fails G4.
- **Two decks, native and container.** That is exactly the drift G2
  exists to prevent.

## Test plan

1. **Closure and size.** `nix-build -A grehack2026.closureCheck`
   passes. The added closure is ≤ 100 MiB unpacked (`nix-store -qR`
   diff against today's image, as in Background).
2. **Banners.** The S3 gate: old and new, side by side, in kitty and in
   a plain terminal.
3. **Tap privileges.** Run `life-tap -q --detach --out capture` in each
   case below. It must start, write `tap.pid`, and `--stop` must leave
   complete files:
   - natively, without a sudo timestamp: it prompts;
   - natively, with one: it does not prompt;
   - under Podman (`--user 0`);
   - under Docker (`--user 0`).

   Under Docker as uid 1000, it fails before detaching with
   `CAPTURE_HELP`. `choose_dumpcap` already has unit tests; the
   interactive step gets one for "no tty, no timestamp → error".
4. **The whole talk.** A full rehearsal in the image, three `exec`
   windows, on Linux under Podman and on macOS under Colima. Every deck
   step, every beat, and the 0399 exit hook all work.
5. **Same configuration.** `grehack2026-shell` and the image share the
   store paths of `teleprompt`, the Neovim config and `demoTools`.
   Check with `nix-store -q --references` on both.
6. **Kitty.** From a kitty window:
   - `less`, `tput cols` and Neovim run in the container without a
     terminfo warning;
   - `picture` draws a real image, in a plain `exec` and inside a tmux
     pane (S11).
7. **Smoke test.** `grehack2026/smoke-test.sh` gains three checks:
   - every command the deck calls resolves (`command -v` on each);
   - `teleprompt --help` runs;
   - `header test` renders without error.

## Measured outcome

Measured on 2026-10-09, x86-64, Podman 5, on a local build.

- **Size:** the image went from 1,150 to 1,239 MiB unpacked (+89 MiB,
  228 store paths). The closure check passes, with no perl and no ruby.
- **Smoke test:** 23 of 23 checks pass. The 5 new ones are:
  - the talk's tools and material;
  - the banners' font;
  - kitty's terminfo;
  - the deck's tap under `--detach`, then `--stop`, as root;
  - no denied store path.
- **Same configuration (item 5):** the demo shell and the image share
  the `teleprompt`, Neovim, buf, protoc and kitty-terminfo store paths,
  and all eight members of the runtime.
- **The tap natively (item 3):** `--detach` with cached sudo
  credentials detached, captured, and stopped cleanly. The prompt path
  is not tested: this VM's sudo needs no password. It is covered by
  the unit test of `credentials()` and needs a check on a machine
  whose sudo asks.
- **Banners (item 2), the S3 gate passed:** in kitty, the chafa-only
  banners come out slightly larger than the ImageMagick ones and look
  good, so they are kept. A PNG side by side also shows the chevrons
  placed correctly by the width table.
- **Not done:** the full rehearsals (item 4) and the kitty checks
  (item 6), on Linux under Podman and on macOS under Colima.
