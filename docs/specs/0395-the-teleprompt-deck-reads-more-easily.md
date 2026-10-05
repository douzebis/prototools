<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0395 — the teleprompt deck reads more easily

Status: implemented
Implemented in: 2026-10-05
App: grehack2026 (teleprompt deck, bin/teleprompt), nix (demo shells)
Refs: docs/specs/0388-the-demo-runs-from-grehack2026.md (the deck and its
      capture sections); docs/specs/0393-only-dumpcap-runs-as-root.md
      (the background tap and the pause-and-step captures the Eve section
      builds on); docs/specs/0394-each-demo-brings-its-own-shell.md (the
      demo shells, which stopped running the dev-shell's `_hook_nvim` —
      the cause of the lost `view` coloring here)

## Background

A rehearsal of `grehack2026.sh` surfaced several rough edges:

- The opening `hexdump` of a captured message printed straight to the
  terminal, unpaged, while every other file view in the deck goes
  through `view`.
- Nothing marked the move from one prototool to the next; the four tools
  blended into a wall of narration.
- The on-screen narration was dense: banner blocks ran together with no
  breathing room.
- `view`, called from the deck, no longer syntax-colored `.proto` and
  `.textproto` source. It had, when the deck ran in the dev-shell:
  the coloring comes from an nvim config that `_hook_nvim` writes, and
  the demo shells (spec 0394) do not run that hook.
- The "Eve is spying" section led with the tap and a capture, which made
  an abstract claim concrete only at the very end. And its hints told the
  audience the `whoami` → `experiment` round trip up front, spoiling the
  reveal that protolens is supposed to deliver.

## Goals

- **G1.** The opening `hexdump` is paged like every other view (`| view`).
- **G2.** A small on-screen banner announces the first use of each
  prototool.
- **G3.** The narration has room to breathe: blank lines between thoughts.
- **G4.** `view` syntax-colors `.proto` and `.textproto` in the demo
  shells, as it did in the dev-shell.
- **G5.** The Eve section shows the capability live before dissecting it,
  and does not name the smuggled payload until protolens reveals it.

## Non-goals

- **N1.** No change to what the tools do, only to how the deck presents
  them.
- **N2.** No new nvim features. G4 restores the highlighting the deck
  already had; it does not add to it.

## Specification

- **S1. `| view` on the opening hexdump (G1).** `hexdump -v -C
  capture/000001-request.pb | view`.

- **S2. A `splash` helper (G2).** `bin/teleprompt` gains `splash TEXT`:
  a small boxed banner in bright cyan, set apart from the blue narration
  and the large `header` title by its box and color. The deck calls it
  once before each tool's first use: `ENTER PROTOSCAN`, `ENTER REPROTO`,
  `ENTER PROTOTEXT`, `ENTER PROTOLENS`. Only the first use of each tool
  is announced.

- **S3. Spacing (G3).** Banner blocks carry blank narration lines (a
  `#` line padded to width, no text) between distinct thoughts, so the
  window is not a solid wall of text.

- **S4. `view` is colored in the demo shells (G4).** The wrapped
  `teleprompt` (spec 0394 S3) sets `XDG_CONFIG_HOME` to a Nix-built nvim
  config directory holding `nvim/init.lua`, so `view`, `view_textproto`
  and `view_proto` get the desert theme and the proto/textproto
  highlighting. The config source is `nix/demo-nvim/init.lua`, the same
  highlighting the dev-shell's `_hook_nvim` writes inline (`buf` is on
  teleprompt's PATH for the proto LSP the config starts).

- **S5. The Eve section, in two parts (G5).**
  - Section 2, "Eve is spying": Bob runs the client (running, no
    `--paused`); Eve types shell commands on the server's stdin —
    `ls ~/.ssh`, `id` — and their output appears on her screen a few
    steps later. The narration names this for what it is: a remote shell
    hidden in the game. Then Bob quits the client. No tap yet.
  - Section 2b, "Hidden bits": one controlled capture. Eve queues
    `whoami`; the tap starts; Bob runs `life-client --paused` and steps
    twice; the tap stops. `protoc` shows nothing; protolens reveals the
    spurious continuation bits, and only there does the narration name
    the `whoami` → `experiment` exchange.
  - The hints in both parts never name the payload before protolens
    reveals it (G5). Section 2b's header renders within 80 columns
    (spec 0388's banner width), unlike a longer title.

## Alternatives considered

### Duplicate the nvim init.lua into the teleprompt wrapper

The dev-shell writes the config inline in `_hook_nvim`. Copying those
~100 lines of Lua into the wrapper too would be a second copy to keep in
step. A committed `nix/demo-nvim/init.lua`, built into the wrapper's
config, is one source the dev-shell can later share.

### A `header`-style SVG banner for each tool

`header` renders a large image; one per tool would dominate the window
and slow each transition. A one-line boxed banner is enough to say
"now this tool".

## Test plan

1. `bin/teleprompt`: `splash "ENTER PROTOSCAN"` draws a box whose top
   and bottom borders match the text width.
2. `nix-build -A teleprompt`: the wrapper sets `XDG_CONFIG_HOME` to a
   config dir holding `nvim/init.lua`.
3. Under that config, `nvim --headless -R x.proto` reports filetype
   `proto` and `hlexists("protoKeyword")`.
4. `bash -n grehack2026.sh`; every banner continuation ends at display
   column 80; headers render within 80 columns.
5. A dry run of the deck in the grehack2026 demo shell: the splash
   banners appear, `view` is colored, and the Eve section reads in two
   parts with no payload named before protolens.

## Measured outcome

Measured 2026-10-05 on the development machine.

- S1–S3, S5: `bash -n` passes; every banner continuation is at display
  column 80; the deck's headers all render at ≤80 columns (the new
  "2b. Hidden bits" is 79). `splash` draws a correct box.
- S4: `nix-build -A teleprompt` wraps with
  `XDG_CONFIG_HOME=…-teleprompt-nvim-config`, whose `nvim/init.lua`
  carries the desert theme and proto keywords. Headless nvim under it
  reports filetype `proto` with `protoKeyword` highlighting present.
- Not done: test plan item 5, a full dry run in the demo shell, which
  needs a terminal.
