<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0393 — only dumpcap runs as root

Status: draft
App: grehack2026 (life-tap, life-client, teleprompt deck)
Refs: docs/specs/0375-a-game-of-life-to-spy-on.md (the tap, its
      dumpcap | tee | tshark pipeline, and running it as root);
      docs/specs/0388-the-demo-runs-from-grehack2026.md (S5: the deck runs
      the tap in the foreground with `sudo env PATH="$PATH" life-tap`;
      S6–S8: the pause-and-step captures)

## Background

The tap runs `dumpcap -w - | tee capture.pcapng | tshark …` and reads
tshark's lines (spec 0375). Capturing needs privilege, so today the whole
tap runs as root (`sudo env PATH="$PATH" life-tap`), and tshark with it.
Wireshark's own guidance is the opposite: give capture privilege to
dumpcap alone, and never run the dissectors as root, since they parse
untrusted traffic. The tap itself only reads tshark's output and writes
files; it needs no privilege either.

In the deck, the tap runs in the foreground (spec 0388 S5). Its
instructions for the other windows must therefore come *before* the
command that starts it, since the deck waits until the tap exits. Read
in that order, the hints describe steps the audience has not seen
started yet.

On startup, the tap also prints a block giving the `dumpcap | tshark`
commands to adapt by hand. That is useful in the workshop, but it is
noise on stage.

`life-client` starts paused (`running: false` in its UI state): nothing
is sent until the player presses Space or `n`. The deck's section 0 says
"Bob starts his client", then that "the grid steps", which a paused
client does not do.

## Goals

- **G1.** The tap runs as the user. Only dumpcap runs with capture
  privilege; tshark and the tap never do.
- **G2.** The deck starts the tap in the background, gives the hints for
  the other windows while it runs, then stops it and waits until its
  files are complete.
- **G3.** `life-tap -q` leaves out the startup block of commands to
  adapt.
- **G4.** The workshop container, where the tap already runs as root and
  `sudo` may be absent, keeps working unchanged.
- **G5.** `life-client` starts running: it sends its first step as soon
  as it is started, so section 0 of the deck reads true as it stands.
  `life-client --paused` starts it paused instead, which is what makes
  each capture's message numbers deterministic.

## Non-goals

- **N1.** `-q` does not silence the per-message lines or the closing
  summary. In the demo the client is stepped by hand, so the lines are
  few, and seeing them back in Alice's window is part of the story.
- **N2.** No capture through file capabilities set by the tap itself
  (`setcap` on a dumpcap copy): that needs root to install, and the
  NixOS wrapper already covers the capabilities case.

## Specification

- **S1. How the tap gets dumpcap.** In this order:
  1. The NixOS wrapper, `/run/wrappers/bin/dumpcap`, when it works (the
     `wireshark` group): run directly, as today.
  2. The tap already running as root (the workshop container,
     `docker exec -u 0`, `podman exec`): `dumpcap` from PATH, directly,
     as today.
  3. Otherwise: `sudo -n dumpcap` (`sudo -n`, with its full path from
     PATH). `-n` never prompts: run in the background, sudo cannot read
     a password, and without `-n` it would hang. If the credentials are
     not cached, sudo fails at once, and the tap reports "capturing
     needs root: run `sudo -v` first, then start the tap again", plus
     `CAPTURE_HELP`.

  tshark always runs as the tap's own user.

- **S2. Stopping through sudo.** The tap stops dumpcap by sending
  SIGTERM to the process it spawned, after `STOP_GRACE`. In case 3 that
  process is `sudo`. A user cannot signal a root `dumpcap`, but can
  signal the `sudo` it started (sudo keeps the user's real uid), and
  sudo passes SIGTERM on to dumpcap. The tap then waits for `sudo`,
  which exits when dumpcap does. `life-tap --stop` therefore needs no
  sudo in case 3: the tap it signals runs as the user.

- **S3. File ownership.** The tap gives its files to `owner()`. In case
  3 it runs as the user, so its files are already the user's, and
  `owner()` returns the tap's own ids. Cases 1 and 2 keep today's rule
  (the `sudo` user, or `/work`'s owner).

- **S4. `-q`.** `life-tap -q` (`--quiet`) does not print the startup
  block: the "commands, to adapt in a root terminal of your own" line
  and the pipeline after it. The first line (`capturing gRPC on port …
  into …`) is still printed, and everything still goes to `tap.log`. In
  case 3, the printed pipeline begins `sudo dumpcap …`, and the heading
  no longer says "root terminal".

- **S5. The deck.** Each capture (sections 1 and 2) becomes:
  1. 👉 Bob's window: Ctrl-C quits the client. (In section 2 it is
     already quit, so this step is skipped.)
  2. Here: `rm -rf capture`, then `sudo -v && (life-tap -q &)`. The
     subshell backgrounds only the tap, after `sudo -v` has prompted in
     the foreground, and keeps the tap out of the deck shell's job
     table.
  3. The hints for the other windows, now that the tap is running:
     - section 1: 👉 Bob's window: `life-client --paused`, then `n`
       three times, then Ctrl-C;
     - section 2: 👉 Eve's window: `whoami`; then 👉 Bob's window:
       `life-client --paused`, `n` (response 1 carries `whoami`), `n`
       again (request 2 carries `experiment`), then Ctrl-C.
  4. Here: `life-tap --stop`, which returns once the files are written.
  5. Here: `tail -n 3 capture/tap.log`, showing the per-message lines
     and the "N requests and N responses saved" summary.

  The client is quit at the end of each capture, so nothing is sent
  while Alice reads it, and the server's log (spec 0388 S14) stops
  growing. Spec 0388's "Space sets the game running again" hints are
  dropped.

  Each capture's client is a new process, started after the tap. Its
  connection therefore opens while the tap is watching, and the tap
  sees it from its start. Spec 0388 S6's 2-second wait before the first
  `n`, which existed to force a fresh connection, is dropped.

  Section 2's numbering (spec 0388 S8) holds: the server sends a typed
  command once, in the next response; the client is paused until Bob's
  first `n`; so response 1 carries `whoami`, and request 2 carries the
  reply.

- **S6. Help and docs.** `CAPTURE_HELP` describes the three cases.
  `SETUP.md` keeps its container commands, which are case 2. The
  synopsis follows the deck.

- **S7. The client starts running, unless `--paused`.** `life-client`'s
  TUI starts with `running: true`, so it steps from launch, as if Space
  had been pressed. `--paused` starts it with `running: false`, as
  today: nothing is sent until Space or `n`. The keys are unchanged.
  Headless mode (`--steps`) ignores `--paused`: it plays its steps.
  Section 0 of the deck is left as it is, and now reads true.

## Alternatives considered

### `sudo -v && sudo env PATH="$PATH" life-tap &`

Backgrounds the whole `&&` chain, `sudo -v` included, which then cannot
prompt. It also keeps tshark as root (G1).

### `sudo pkill life-tap` to stop

Returns as soon as the signal is sent, while the tap keeps capturing
for `STOP_GRACE` and then finishes writing. The deck's next command
could read files that are not there yet. `--stop` waits.

### Pause the client between captures, without `--paused`

Bob could pause with Space instead of quitting, and step the paused
client with `n` in section 2. But that client's connection predates the
tap, so the 2-second wait (spec 0388 S6) would be needed to force a
fresh one, and section 1 would still capture whatever the running client
sent before Bob paused it. A new `--paused` client per capture makes
both captures start on a connection the tap sees whole.

### Keep the client starting paused

The deck's section 0 would need a "Space starts the game" step, and a
player trying the game in the workshop would see a still grid until they
found the key. Decided against with the user (2026-10-05).

### Plain `sudo dumpcap` without `-n`

In the background, a prompt would stop or hang the tap with no
message. `-n` turns that into an immediate, explained failure.

## Test plan

1. Unit: the dumpcap choice. Wrapper first, then root, then
   `sudo -n dumpcap`. Factored as a function of (wrapper usable, euid),
   so it is testable without capturing.
2. Unit: `-q` leaves out the block and keeps the first line.
3. `life-client`: the TUI's initial state is running, and paused with
   `--paused` (S7); its existing tests that assumed a paused start are
   updated.
4. `smoke-test.sh`: the two tap checks still pass. They run as root, so
   they cover case 2.
5. By hand on this machine (case 3, no wrapper): `sudo -v && (life-tap
   -q &)`, a few client steps, then `life-tap --stop`. Check:
   - the files are complete, and owned by the user;
   - `ps` shows only dumpcap as root, with tshark and life-tap as the
     user;
   - `--stop` returns after the summary is written;
   - with the credentials expired (`sudo -k`), the tap fails at once
     with S1's message.

## Measured outcome

Filled in at implementation.
