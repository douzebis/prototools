<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0388 — the demo runs from grehack2026/

Status: implemented
Implemented in: 2026-10-04
App: grehack2026 (life crate, teleprompt deck, workshop image)
Refs: docs/specs/0375-a-game-of-life-to-spy-on.md (the crate, its Nix
      build and `life-spy`, renamed here);
      docs/specs/0381-a-step-survives-the-connection-renewal.md (why a
      tap started mid-connection misses traffic until the client renews);
      docs/specs/0384-smuggle-through-plain-varint-fields.md and
      docs/specs/0385-the-smuggled-payload-is-exactly-the-bytes.md (one
      message carries a whole command or reply, exactly its bytes);
      docs/specs/0386-the-server-writes-a-truncated-protobuf-log.md
      (`--log-file`, the log section 3 opens)

## Background

The teleprompt deck `grehack2026/grehack2026.sh` assumes it runs from
`grehack2026/`, but that directory cannot host it today:

- `reproto --schema-db-out life.desc` writes its stub to `life/`, which
  is where the crate lives (`grehack2026/life/`).
- `grehack2026.init` runs `rm -rf "${_init_dir}/life"` with `_init_dir`
  set to `grehack2026/`: resetting the demo deletes the crate.

The deck also opens `capture/000050-*` and `capture/000100-*`. Which
messages those are depends on how long the tap ran, so section 2 may
open a message sent before Eve typed her command, with nothing in it.

Finally, the terminals have no fixed home: the server writes its log
wherever it was started, and the tap is called `life-spy` although in
the story Eve is the spy and the tap is Alice's tool for catching her.

## Goals

- **G1.** `teleprompt grehack2026.sh`, run from `grehack2026/` inside
  the dev-shell, drives the whole demo; resetting it touches only files
  the demo generated.
- **G2.** Eve and Bob each have a working directory, `grehack2026/eve/`
  and `grehack2026/bob/`; Eve's log is `eve/server.log`.
- **G3.** The captures the deck opens are fixed in advance: section 1
  opens `000001-*`; in section 2, `000001-response.pb` carries Eve's
  command and `000002-request.pb` carries Bob's machine's reply.
- **G4.** `life-spy` is renamed `life-tap`.

## Non-goals

- **N1.** No launcher script per terminal. The windows are opened and
  put in the dev-shell before the talk, and the presenter's own shell
  init already shows the directory in `PS1`.
- **N2.** No background tap. Its one line per message would scroll
  through the narration, and a backgrounded `sudo` cannot prompt for a
  password. `life-tap --stop` stays in the tool for the workshop.
- **N3.** No rename of `life-server`, `life-client`, or the Cargo
  package `life`.
- **N4.** Earlier specs keep saying `life-spy`; they record what was
  decided then.

## Specification

### Layout

- **S1. The crate moves to `grehack2026/game/`.** `git mv
  grehack2026/life grehack2026/game`, then update every path that names
  it: `Cargo.toml` (workspace `exclude` and its comment), `default.nix`
  (the fileset entry and the `import` of the crate's `default.nix`),
  `game/default.nix` (the repo-rooted fileset and `postUnpack`'s `cd`),
  `game/Cargo.toml`'s build comment, `.gitignore`, `nix/shells.nix`'s
  comment, and `synopsis.md`. The `prototext-core` path dependency
  (`../../prototext-core`) is unchanged: `game/` is at the same depth.

- **S2. `grehack2026/` holds only demo material and what the demo
  generates.** It has these entries:

  ```
  grehack2026/
    grehack2026.sh, grehack2026.init   the deck, run from here
    beats/                             protolens scripts
    anomalies.pb                       the bonus section's blob (S12)
    eve/                               Eve's terminal; eve/server.log
    bob/                               Bob's terminal
    game/                              the crate (S1)
    capture/  life.desc  life/         generated; wiped by the .init
    life-client                        Alice's copy of the client (S3)
  ```

  `eve/` and `bob/` are tracked through a `.gitkeep` each, covered by a
  `REUSE.toml` annotation. `.gitignore` lists the generated entries:
  `/grehack2026/capture/`, `/grehack2026/life.desc`, `/grehack2026/life/`,
  `/grehack2026/eve/server.log`, `/grehack2026/life-client`. The workshop files (`SETUP.md`,
  `load.sh`, `smoke-test.sh`, `synopsis.md`, `README.md`) stay where
  they are.

- **S3. The .init removes only generated files.** It removes
  `capture/`, `life.desc`, `life/` and `eve/server.log`. Before
  removing anything, it refuses to run if `life/Cargo.toml` exists: a
  checkout from before S1 would otherwise lose the crate.

  It then copies the client binary to `grehack2026/life-client`, so that
  the deck's `protoscan life-client` and `reproto -I life-client` read a
  file in the current directory. On the Nix PATH, `life-client` is a
  `wrapProgram` script (it adds `bash` and `fortune` to the PATH), with
  no descriptors in it; the init copies the `.life-client-wrapped` beside
  it instead when there is one.

### Terminals

- **S4. Three windows, set up before the talk, all in the dev-shell.**

  | Window | Directory | Runs |
  |---|---|---|
  | Eve | `grehack2026/eve/` | `life-server` |
  | Bob | `grehack2026/bob/` | `life-client` |
  | Alice | `grehack2026/` | `teleprompt grehack2026.sh` |

  The tap runs inside Alice's window (S5); with no `/work`, it writes to
  `./capture`, so `grehack2026/capture/`.

- **S5. The tap runs in the foreground, from the deck:**
  `sudo env PATH="$PATH" life-tap`. `sudo` resets `PATH`, and the
  binary is only on the dev-shell's. The presenter stops it with
  Ctrl-C, which ends the tap and leaves teleprompt running (checked by
  hand with `life-spy`, 2026-10-04). Because the deck waits until the
  tap exits, the banner just before the tap command lists everything to
  do in the other windows while it runs.

### Deterministic captures

- **S6. Each capture starts on a paused game and a fresh directory.**
  The steps:
  1. 👉 Bob: Space pauses the game.
  2. Deck: `rm -rf capture`, then the tap (S5).
  3. The actions for the section (S7, S8).
  4. Deck: Ctrl-C stops the tap.

  The game stays paused for at least `--renew-every` before the first
  step, so that step opens a new connection and the tap sees it from the
  start (spec 0381). The client's default drops from 5 s to **2 s**, so
  the hint asks for a two-second wait. Spec 0381 measured renewal at
  `--renew-every 1` (20,000-step runs, and the smoke test's 65 s run), so
  2 s stays inside what was tested; the cost is one new connection every
  2 s.

- **S7. Section 1:** 👉 Bob presses `n` a few times. The deck opens
  `capture/000001-request.pb` and `capture/000001-response.pb`.

- **S8. Section 2:**
  1. 👉 Eve types `whoami`. The server sends a typed command once, in
     the next response, and the game is paused, so nothing is sent yet.
  2. 👉 Bob presses `n`. `000001-response.pb` carries `whoami`; the
     client runs it on a worker thread.
  3. 👉 Bob presses `n` again. `000002-request.pb` carries the output.

  `experiment` lands in request 2 only because the command finished
  before the next step. Free-running at about 10 steps a second, the
  reply could slip to request 3; stepping by hand leaves it plenty of
  time. A whole command or reply fits in one message (spec 0384 S4).

- **S9. Neither payload carries a newline.** The server strips the
  newline from what Eve types, so the command is exactly `whoami`. The
  client trims the ends of the command's output before sending it back
  (`life::tags::command_output`), so the reply is exactly `experiment`,
  10 bytes. The bit tables in the deck and in `beats/smuggle` show 10.
  (Corrected 2026-10-04, spec 0391: an earlier version of this item said
  the reply kept `whoami`'s trailing newline. A logged run showed the
  reply as `"experiment"`.)

### The rename

- **S10. `life-spy` becomes `life-tap`; `spy.log` becomes `tap.log`.**
  The rename covers the binary directory `src/bin/life-spy/` (and its
  `[[bin]]` entry, if any), the `life-spy:` prefix and help text, the
  log file name, `smoke-test.sh`, `SETUP.md`, the workshop banner and
  comments in `nix/grehack2026.nix`, the comments in `nix/shells.nix`,
  `default.nix` and `.gitignore`, and `synopsis.md`. In the workshop
  image the capture still defaults to `/work/capture`.

### The deck

- **S11. The deck follows the layout.**
  - The captures it opens are those of S7 and S8.
  - Section 3 opens `eve/server.log`, which the server has been writing
    since section 0 (S14), so nobody restarts anything. The deck does not
    explain the log up front: `ls -lh` shows the file, `protoc
    --decode_raw` fails on it, and only after protolens has opened it
    does the narration say what it is (a truncated traffic log whose type
    is not in the client).
  - The hints for the other windows are `# \` blocks, one per capture,
    not runs of `#` one-liners.
  - The cast diagrams show three windows, with the tap as a process in
    Alice's window.
  - The narration says one message carries the whole command or reply,
    not "one fragment per message".
  - The beats only show reminders; they never move protolens's cursor.
    So only their invocation comments name the new captures. The `v`
    demo (formerly section 2b, `beats/jump`) is folded into section 1b
    and `beats/capture`. Each reminder beat ends with "Type `:q` to quit
    protolens": Enter quits only a script whose last step says
    `command: quit`, as `beats/anomalies` does.
  - Every `header` title renders within 80 columns, the width of the
    deck's banners. `header` draws the title five rows high, so its width
    grows with the title's length (it drops a leading `N. `, but not
    `1b. `). Measured with chafa forced to character cells, the old
    titles ran from 86 to 188 columns. The new ones run from 53 to 80:
    "Why prototools" 80, "The cast" 53, "On the wire" 65, "1b. Schema DB"
    79, "Eve is spying" 70, "No schema" 62, "Anomalies" 60, "Takeaways"
    62. The `.init`'s splash header, "Dissecting protobuf" (97), becomes
    "prototools" (59); the full title is printed as text below it.

### Standalone

- **S12. The anomaly bonus uses copies in `grehack2026/`.**
  `anomalies.pb` (and its `.license`) is copied from `grpconf2026/`, and
  `anomalies.script` becomes `beats/anomalies`. Section 4 runs
  `protolens --type google.protobuf.FileDescriptorSet anomalies.pb
  --script beats/anomalies`; the dev-shell's `PROTOTEXT_DESCRIPTOR_SET`
  supplies the well-known types. The demo then reads nothing outside
  `grehack2026/`.

### The log is on by default

- **S14. `life-server` writes `server.log` unless told not to.**
  `--log-file` defaults to `server.log`, in the working directory, so
  Eve's server writes `eve/server.log` from the moment she starts it.
  `--no-log` turns it off, and conflicts with `--log-file`. If the file
  cannot be opened, the server still stops at startup, as with an
  explicit path before. Everything is logged, about 15 KB per step at a
  terminal-sized grid. The presenter keeps the log small by pausing the
  client after a few seconds, and protolens handles large blobs. In the
  workshop image, the working directory `/workshop` is mode 1777, so
  the default log works for any user.

### No `--use-variant`

- **S13. The binaries embed `descriptor.proto` beside `life.proto`.**
  `reproto` refuses to build a schema DB without
  `google/protobuf/descriptor.proto` in its input set, even though
  `life.proto` imports nothing ("descriptor.proto not found in the input
  set; add it to your -I tree or use --use-variant descriptor"). So
  `build.rs` also compiles `descriptor.proto`, from protoc's own include
  directory, and writes its FDP. `lib.rs` embeds it as `DESCRIPTOR_PROTO`
  next to `DESCRIPTOR`, and passes it through `std::hint::black_box`,
  since nothing reads it and the linker would otherwise drop it. The deck
  runs `reproto -I life-client --schema-db-out life.desc`, and protoscan
  now lists two files in each binary. `log.proto` stays out (spec 0386
  G4).

## Alternatives considered

### Run the deck from `grehack2026/alice/`

This keeps the crate where it is. It was dropped because it brings
Alice in before the cast introduces her, and section 3 would open
`../eve/server.log` instead of `eve/server.log`.

### Rename the schema DB instead of moving the crate

For example `client.desc` and `client/`. That needs no Nix changes, but
the crate would remain in the directory the audience sees. The move
was chosen.

### The tap in a fourth window, or in the background

A fourth window adds one more screen to switch to. Backgrounding it
from the deck runs into N2. In the foreground, its output is visible
and part of the story.

### Fixed capture numbers on a running game (`000050`, `000100`)

Which message has which number depends on when Ctrl-C is pressed, and
in section 2 on when Eve finishes typing. Pausing and stepping (S6)
removes both.

## Test plan

1. `smoke-test.sh` passes with `life-tap`; its assertions on the
   "N requests and N responses saved" line are unchanged.
2. Rebuild after the move:
   `nix-build -A grehack2026.life --no-out-link` (or the attribute the
   move leaves). Grep the new binary for a string new in this change
   (`life-tap:`), so a stale cached build cannot pass.
3. `nix-shell dev-shell.nix --run 'command -v life-server life-client life-tap'`.
4. Run the `.init` from a checkout where `grehack2026/life/Cargo.toml`
   still exists: it refuses and removes nothing. Run it with a Nix-wrapped
   `life-client` on the PATH: `protoscan life-client` on the copy finds
   `grehack/life/v1/life.proto`.
5. `reuse lint` is clean; `bash -n grehack2026/grehack2026.sh` passes.
6. Dry run of sections 1 and 2 by hand. After section 2, `capture/`
   holds exactly `000001-*` and `000002-*`. `prototext` shows `whoami`
   in `000001-response.pb` and `experiment\n` in `000002-request.pb`.

## Measured outcome

Measured 2026-10-04 on the development machine.

- `cargo test` in `grehack2026/game/`: 64 tests pass. Clippy and
  `cargo fmt --check` are clean.
- `nix-build -A grehack2026.life`: the built `life-tap` carries
  `life-tap: capturing` and `2 s (--renew-every)`, and `life-client`
  carries the new `--renew-every` help, so the build is not a stale
  cache.
- In the dev-shell, `life-server`, `life-client` and `life-tap` are on
  the PATH, and `life-client --help` shows `[default: 2]`.
- The `.init` guard: with `life/Cargo.toml` present it removes nothing;
  without it, it removes the generated files. With a Nix-wrapped
  `life-client` on the PATH, `protoscan` on the copy finds
  `grehack/life/v1/life.proto`.
- `reuse lint` is clean. Every deck banner ends at display column 80,
  and `bash -n` passes.
- `smoke-test.sh`: all 18 checks pass, under both rootless Podman and
  Docker 29.8 (rootless). Colima on macOS was not tested. Getting there
  took three fixes to the smoke test:
  - The two tap checks now pass `--cap-add NET_RAW`, as `SETUP.md`
    already does. Rootless Podman does not grant it by default; Docker
    does.
  - The protoscan check reads `.life-client-wrapped`, the binary behind
    the client's `wrapProgram` script. "Only the binaries carry the
    schema" accepts that file too.
  - The late-tap check pins `--renew-every 5`. With the new 2 s default,
    the next connection could open before the tap, started 1 s in,
    missed anything.
- S13: `protoscan` on both release binaries lists
  `grehack/life/v1/life.proto` and `google/protobuf/descriptor.proto`.
  `reproto -I life-client --schema-db-out life.desc` exits 0 without
  `--use-variant`. The DB now also holds a decompiled
  `life/proto/google/protobuf/descriptor.proto`, which the flagged run
  did not render. `list-schemas` still types the capture as
  `StepResponse` (score 3087).
- Not done: the dry run of sections 1 and 2 by hand (test plan 6). It
  needs a terminal and `sudo`, which the agent shell does not have.
