<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0380 — the client runs a shell command on 's'

Status: implemented
Implemented in: 2026-10-01
App: grehack2026 (life-client)
Refs: docs/specs/0375-a-game-of-life-to-spy-on.md (the client's TUI, its
      event loop, raw mode and alternate screen, the single-call-in-flight
      rhythm);
      docs/specs/0379-the-tags-carry-an-echo-handshake.md (the echo
      handshake the step calls keep running alongside this)

## Background

`life-client` is a ratatui TUI: it draws the grid, polls for key and
mouse events, and once per tick calls `life-server` for the next
generation (spec 0375 S5). The loop runs in raw mode on the alternate
screen, with one gRPC call in flight at a time (`run`, `on_key`, `call`
in `life-client/main.rs`).

The workshop wants the client to double as a local command runner, so a
participant can shell out without leaving the game: press `s`, type a
short command, and see its output — while the life protocol keeps
stepping and the echo handshake (spec 0379) keeps riding the requests.

Two facts shape the design. First, the TUI owns the terminal: it is in
raw mode on the alternate screen, and both stdout and stderr render into
that screen, so a `println!`/`eprintln!` would be swallowed or would
smear across the grid. The result therefore goes to a **log file**,
which a participant can watch with `tail -f` — out of the TUI's way, and
persistent across the run. Second, the event loop must not block: a
command that takes a second must not freeze the game for that second, so
the command runs in the background and its output is collected when it
finishes, not awaited inline.

## Goals

- **G1. A command prompt on `s`.** In the running TUI, pressing `s`
  opens a single-line prompt at the status line. The user types a
  command and presses Enter to run it, or Escape to cancel. While the
  prompt is open the game is paused and other keys edit the line
  (printable characters, Backspace), not the game.

- **G2. The command runs in the background.** On Enter, the client
  spawns the line as a child process via the shell (`sh -c <line>`),
  with its stdout and stderr captured, and returns to the game at once.
  The event loop keeps drawing and (if it was running before the prompt,
  N-handling aside) keeps stepping while the child runs. The client does
  not block on the child.

- **G3. The result is logged when the command completes.** When the
  child exits, the client appends to a log file the command line, its
  exit status, and its captured stdout and stderr. The TUI is never
  disturbed: the grid is intact throughout, and the file is readable
  during and after the run (`tail -f`).

- **G4. One command at a time.** While a command is running, `s` is
  inert (or shows a brief "busy" note); a second command cannot be
  started until the first has printed its result. This matches the
  client's single-in-flight discipline for step calls (spec 0375 S5) and
  keeps the output unambiguous.

- **G5. The game and the handshake are unchanged.** Running a command
  does not touch the step calls, the grid, the rules, or the echo
  handshake (spec 0379). The command is a side activity local to the
  client; it is not smuggled to the server and does not ride the tags.

## Non-goals

- **N1. A remote command channel.** This runs commands the *local* user
  types at the *local* client; nothing is read from the server, and no
  command rides the gRPC conversation. Executing a command sent by the
  far side is not a feature of this software.

- **N2. Interactive or streaming commands.** The child's output is
  collected once, at exit, and logged whole (G3). A command that reads
  from stdin, needs a TTY, or streams output over a long run is out of
  scope — it would need a pty and incremental rendering. The feature is
  for short, non-interactive commands (`ls`, `id`, `cat /etc/hostname`).

- **N3. A scrollback pane inside the TUI.** The result is not laid out
  in a ratatui widget with its own scroll region, nor printed on the
  screen; it goes to the log file (S6). Building an in-TUI log viewer is
  more than the demo needs.

- **N4. Headless mode.** `--steps` is the scriptable, non-interactive
  path (spec 0375) and has no keyboard; the prompt and runner exist only
  in the TUI (`tui`/`run`), not in `headless`.

- **N5. A command queue or history.** No queue (N1 of this spec is
  enforced by G4), no up-arrow recall, no saved history. One command,
  typed fresh each time.

- **N6. Sandboxing or an allow-list.** The command runs with the
  client's own privileges, exactly as a shell would. The workshop image
  is the boundary (spec 0374); the client does not second-guess what the
  participant types.

## Specification

- **S1. An input-mode state.** The TUI gains a mode: either `Game` (the
  present behavior) or `Prompt { line: String }` (collecting a command).
  `s` in `Game` mode switches to `Prompt` with an empty line and pauses
  the game (`ui.running = false`), remembering nothing it needs to
  restore — the user resumes with space as today. The mode lives beside
  `Ui` in `run`.

- **S2. Key handling branches on the mode.** `on_key` dispatches on the
  mode before the current game keymap:
  - In `Prompt` mode: a printable `KeyCode::Char(c)` appends to the
    line; `Backspace` pops the last char; `Esc` cancels (drop the line,
    return to `Game`); `Enter` submits (S3). Ctrl-C still quits, as it
    does in `Game` mode (it is the only signal path in raw mode, spec
    0375). No game key (`space`, `n`, `r`, …) acts while the prompt is
    open.
  - In `Game` mode: the present keymap, plus `s` → open the prompt (S1).
    `s` is inert while a command is already running (S5, G4).

- **S3. Submit spawns a background child.** On `Enter` with a non-empty
  line, the client spawns `std::process::Command::new("sh").arg("-c")
  .arg(&line)` with `stdin(Stdio::null())`, `stdout(Stdio::piped())`,
  and `stderr(Stdio::piped())`. The piped handles are drained on a
  dedicated `std::thread` (not the tokio step runtime, and not the UI
  thread), which calls `child.wait_with_output()` and sends the result —
  the line, the `ExitStatus`, and the captured stdout/stderr — back to
  the UI loop over an `std::sync::mpsc` channel. The UI thread holds the
  `Receiver`; the worker holds the `Sender`. An empty line submits
  nothing and returns to `Game` mode. After a successful spawn the mode
  returns to `Game` and a `running_command` flag is set (S5).

  Draining on a thread, rather than letting the pipes fill: a child that
  writes more than a pipe buffer (64 KiB on Linux) would block on write
  if nothing reads, so the reader must run concurrently. The thread does
  the blocking `wait_with_output`; the UI loop never blocks.

- **S4. The loop polls the channel each tick.** `run`'s loop, once per
  iteration (it already wakes at least every 250 ms, spec 0375), tries
  the `Receiver` non-blockingly (`try_recv`). On a result it logs it
  (S6), clears `running_command`, and continues. A disconnected channel
  with no result pending is treated as "no command running". The poll
  adds nothing to the loop's latency: it is a non-blocking check beside
  the existing `event::poll`.

- **S5. One at a time.** A `running_command: bool` beside `Ui` is set on
  spawn (S3) and cleared on result (S4). While set, `s` does not open
  the prompt; the status line may show a short `running …` note so the
  key feels acknowledged (G4). This mirrors the single-call-in-flight
  rule for steps (spec 0375 S5): the client does one slow thing at a
  time and keeps the output legible.

- **S6. The result is appended to a log file.** The TUI owns stdout and
  stderr (both render into the alternate screen), so the result goes to
  a file instead (G3), leaving the TUI untouched — no leave/re-enter, no
  flicker. The file is opened once at `run` startup in append mode and
  its handle kept beside `Ui`; its path is `--command-log`, default
  `/tmp/life-client-commands.log` (a writable, predictable place to
  `tail -f`, independent of the client's working directory). For each
  result the
  client writes a small block: the command line (`$ id`), the exit
  status (`exit 0`, or the terminating signal), then the captured stdout
  and, if non-empty, the captured stderr, each labeled, followed by a
  blank line so blocks are distinguishable. The writes are flushed, so a
  `tail -f` sees each block as its command finishes. Output decoding:
  stdout/stderr are written as text when valid UTF-8, else as a byte
  count with a lossy rendering, so a binary-spewing command does not
  corrupt the log.

- **S7. Draw the prompt.** In `Prompt` mode, the status line (the last
  terminal row, where the keymap hint lives today) shows the prompt and
  the line being typed, e.g. `cmd> ls -la`, with a distinct style so the
  mode is obvious. The grid above is drawn as usual. No separate layout
  work beyond repurposing the one status row.

## Alternatives considered

### Block the loop on the child

The simplest code: on Enter, `Command::output()` and print. Rejected: it
freezes the game and the UI for the command's whole run (G2) — a
`sleep 5` would hang the client for five seconds, mouse and keys dead —
and it reads both pipes only after the child exits, so a chatty command
could deadlock on a full pipe before it ever exits (S3's note). The
background thread costs little and removes both problems.

### Run the child on the tokio runtime (`tokio::process`)

The client already has a tokio `Runtime` for the step calls. Spawning
the child as a tokio task would reuse it. Rejected: the runtime is
single-threaded and is entered only inside `game.step`'s `block_on`
(`life-client/main.rs`); the UI loop itself is plain blocking code, so
there is no async context to spawn into without restructuring the loop
around the runtime. A `std::thread` with an `mpsc` channel fits the
existing blocking loop with no such change, and keeps the child's
lifetime visibly separate from the gRPC conversation (G5).

### Print into a ratatui widget instead of a log file

Keep the alternate screen and render the output in a pane or scroll
region (N3). Rejected: it is a log-viewer feature — wrapping, scrolling,
sizing — for output a `tail -f` on the log file (S6) shows for free, with
no TUI work and no risk of tearing the grid.

### Leave the TUI to print on the primary screen

Drop out of the alternate screen for each result, print to real stdout,
then re-enter (the enter/leave dance `tui` already does). Rejected: it
flickers the whole screen once per command and briefly surrenders the
grid, and the log file (S6) keeps the output persistently without ever
disturbing the TUI — which is what "a log file" asks for.

### A persistent reader thread per command vs. a pool

One thread spawned per command (S3), joined implicitly when it finishes
sending. A pool or a single long-lived worker was considered and
dropped: at most one command runs at a time (G4, S5), so there is never
more than one such thread alive, and a fresh short-lived thread per
command is simpler than managing a worker's lifecycle across the app.

## Test plan

1. A unit test of the spawn/collect worker (S3): feed it a line
   (`printf 'out'; printf 'err' 1>&2; exit 3`), run the worker
   synchronously, and assert the received result carries exit code 3,
   stdout `out`, stderr `err`. A line writing more than 64 KiB to stdout
   returns the whole output (the drain does not deadlock).
2. A unit test of the prompt state machine (S1, S2): from `Game`, `s`
   enters `Prompt` with an empty line and pauses; chars and Backspace
   edit the line; `Esc` returns to `Game` dropping the line; `Enter` on
   an empty line returns to `Game` spawning nothing; `Enter` on a
   non-empty line requests a spawn and sets `running_command`.
3. A unit test of G4 (S5): with `running_command` set, `s` is inert (no
   mode change); once a result is delivered over the channel and polled
   (S4), `running_command` clears and `s` opens the prompt again.
4. In the image (a `grehack2026/smoke-test.sh` check, if the TUI can be
   driven there) or a manual walkthrough: start the client against a
   running server with `tail -f` on the command log, press `space` to
   run the game, press `s`, type `id`, Enter; the game keeps stepping
   while the command runs; on exit the log gains a block with `$ id`,
   `exit 0`, and the `id` output; the grid is never disturbed; the step
   calls and the echo handshake (spec 0379) are unaffected.
5. A `sleep 2 && echo done` run confirms the UI stays responsive (keys,
   draw, stepping) for the two seconds, then the log gains `done` (G2).

## Measured outcome

Implemented 2026-10-01 on the x86-64 NixOS VM. The runner lives in
`life-client/command.rs`; `main.rs` wires it into the TUI.

**Structure.** The testable pieces are a crossterm-free module
(`command.rs`): `Mode` (`Game` | `Prompt { line }`, S1); `on_prompt_key`
over a `PromptKey` shape returning a `PromptAction` (S2); `run_command`
(the `sh -c` worker, S3) and `spawn_command` (its thread); `Pending` (the
one-slot channel holder, `start`/`poll`/`is_running`, S4/S5); and
`format_result`/`log_result` (the log block, S6). `main.rs` holds only the
crossterm wiring: `on_key` maps keys to `PromptKey` in `Prompt` mode and
adds `s` in `Game` mode (inert when `pending.is_running()`), the loop polls
`pending` each iteration, and `draw` shows `cmd> <line>` in `Prompt` mode
and a `running command …` note when busy.

**Tests.** 10 `life-client` tests pass (45 across the crate), clippy clean,
`cargo fmt` clean, `reuse lint` clean. The worker captures stdout, stderr
and exit code (`exit 3`); a 200 KB stdout — well past the 64 KiB pipe
buffer — returns whole, so `wait_with_output`'s concurrent drain does not
deadlock (S3); `Pending` polls a real child to completion and frees the
slot; the prompt state machine edits, cancels, and submits (empty and
non-empty) as specified; `format_result` labels stdout/stderr, omits an
empty stderr, and summarizes non-UTF-8 output by byte count (S6).

**Not covered by automated tests.** The live TUI walkthrough (test plan
items 4–5 — the game stepping while a `sleep 2` runs, the grid intact, the
log gaining each block) needs a driven terminal and was not scripted; the
design keeps the UI loop non-blocking (the child is on its own thread, the
poll is `try_recv`), which is what those items check.
