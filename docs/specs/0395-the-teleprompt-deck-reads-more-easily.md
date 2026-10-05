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
- **G6.** A command whose output the audience is meant to read is
  followed by an empty-command pause, so the reader's attention rests on
  the output before the narration continues.

## Non-goals

- **N1.** No change to what the tools do, only to how the deck presents
  them.
- **N2.** No new nvim features. G4 restores the highlighting the deck
  already had; it does not add to it.

## Specification

- **S1. `| view` on the opening hexdump (G1).** `hexdump -v -C
  capture/000001-request.pb | view`.

- **S2. An inline banner on each tool's first command (G2).** The marker
  is a framed box written as a trailing `#`-comment on the command line
  itself: `protoscan life-client # \` followed by the banner's
  `\`-continued comment lines. Because it is a shell comment, `eval` runs
  only the command; the banner is display-only, shown with the command in
  one step, above its output. It appears for the first use of each tool:
  "Enters protoscan", "Enters reproto", "Enters prototext", "Enters
  protolens". The box is drawn in the deck, each line re-padded to display
  column 80 like any narration line. (An earlier version used a separate
  `splash TEXT` helper in `bin/teleprompt`; the inline form ties the
  announcement to the command as one beat, with no extra Enter, so the
  helper was dropped. Decided with the user, 2026-10-05.)

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

- **S6. An empty-command pause after a read-this command (G6).** A blank
  line in the deck is one steppable entry with nothing to run: the
  presenter advances past an empty prompt with Enter, leaving the
  command's output on screen with a bare prompt below it. The deck
  carries one such blank after each command whose output the audience
  reads before the narration resumes — `protoscan`, `prototext
  list-schemas`, the `ls` listings, `protoc --decode_raw`, the `tail` of
  `tap.log`. A pager command (`view`, `view_textproto`, interactive
  `protolens`) gets none: the pager already holds focus until the
  presenter quits it. Exactly one blank, never two in a row, so there is
  one Enter to press, not two.

## Alternatives considered

### Duplicate the nvim init.lua into the teleprompt wrapper

The dev-shell writes the config inline in `_hook_nvim`. Copying those
~100 lines of Lua into the wrapper too would be a second copy to keep in
step. A committed `nix/demo-nvim/init.lua`, built into the wrapper's
config, is one source the dev-shell can later share.

### A `header`-style SVG banner for each tool

`header` renders a large image; one per tool would dominate the window
and slow each transition. A framed text box is enough to say "now this
tool".

### A separate `splash TEXT` command before the command

A `splash` helper on its own line would render a distinct cyan box, but
it is its own step — an extra Enter and an extra screen before the
command. The inline comment banner shows the announcement and the
command together, one Enter, which paces better.

## Test plan

1. The inline banner is display-only: loading and `eval`-ing
   `protoscan life-client # \` + banner runs only `protoscan
   life-client` (the rest is a shell comment).
2. `nix-build -A teleprompt`: the wrapper sets `XDG_CONFIG_HOME` to a
   config dir holding `nvim/init.lua`.
3. Under that config, `nvim --headless -R x.proto` reports filetype
   `proto` and `hlexists("protoKeyword")`.
4. `bash -n grehack2026.sh`; every banner continuation ends at display
   column 80; headers render within 80 columns.
5. The deck's loader (teleprompt's read loop) turns a blank line into
   one empty command entry, and the deck has exactly one after each
   read-this command and none after a pager (G6).
6. A dry run of the deck in the grehack2026 demo shell: the tool banners appear, `view` is colored, the Eve section reads in two
   parts with no payload named before protolens, and each read-this
   command is followed by an empty prompt.

## Measured outcome

Measured 2026-10-05 on the development machine.

- S1–S3, S5: `bash -n` passes; every banner continuation is at display
  column 80; the deck's headers all render at ≤80 columns (the new
  "2b. Hidden bits" is 79). Replaying teleprompt's loader on the
  `protoscan` banner shows `eval` runs only `protoscan life-client`, the
  banner being a comment.
- S4: `nix-build -A teleprompt` wraps with
  `XDG_CONFIG_HOME=…-teleprompt-nvim-config`, whose `nvim/init.lua`
  carries the desert theme and proto keywords. Headless nvim under it
  reports filetype `proto` with `protoKeyword` highlighting present.
- S6/G6: the loader yields one entry per blank line (confirmed by
  replaying teleprompt's read loop on a two-command script with a blank
  between: three entries, the middle one empty). The deck has one blank
  after each read-this command, none doubled, and none after a pager.
- Not done: test plan item 6, a full dry run in the demo shell, which
  needs a terminal.
