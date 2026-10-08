<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0399 — the tap stops when the teleprompt quits

Status: implemented
Implemented in: 2026-10-08
App: teleprompt (bin/teleprompt), grehack2026
Refs: docs/specs/0393-only-dumpcap-runs-as-root.md (the tap runs as the
      user and owns its sudo'd dumpcap; `life-tap --stop`);
      docs/specs/0394-each-demo-brings-its-own-shell.md (the deck runs
      from grehack2026/, so `capture/` is the tap's default output);
      docs/specs/0388-the-demo-runs-from-grehack2026.md (S3: the init's
      reset and life-client copy)

## Background

The grehack2026 deck starts the tap detached, `sudo -v && (life-tap -q &)`,
and nothing ever stops it. Rehearsals left taps running: measured on
2026-10-06, five root `life-tap`/`dumpcap` pairs (from the pre-0393 way
of starting the tap, `sudo env PATH=… life-tap`) and one user-run tap
with parent pid 1, its root `dumpcap` still attached.

Three things combine:

- **Quitting the teleprompt does not stop the tap.** The teleprompt's
  only exit handler is `trap 'stty sane' EXIT`.
- **The reset hides a running tap.** `life-tap` refuses to start while
  `capture/tap.pid` names a live process, but `grehack2026.init` ran
  `rm -rf capture` at every launch, deleting `tap.pid` from under the old
  tap. The guard then sees nothing, and the next run starts a second tap
  beside the first.
- **An orphaned dumpcap can wait forever.** It notices that its reader is
  gone only on its next write, and a paused game sends no packets.

## Goals

- **G1.** Quitting the teleprompt with Ctrl-D or Ctrl-C at the prompt,
  or closing its terminal, stops the tap the deck started. Ctrl-Z, which
  suspends the teleprompt, does not.
- **G2.** A tap left behind by a session that did not exit cleanly is
  stopped before the next run removes `capture/`, never hidden by it.
- **G3.** Removing a previous run's artifacts is a deck step the
  presenter can skip, to keep them.

## Non-goals

- **N1.** No watchdog inside `life-tap` (a tap that stops itself when a
  watched pid disappears). See *Alternatives considered*.
- **N2.** The teleprompt learns nothing about `life-tap`. It gains a
  generic exit hook; the grehack2026 init is what registers the stop.
- **N3.** No change to what a Ctrl-C typed *while a command runs* does to
  the background tap. The teleprompt runs commands without job control,
  so the tap may share its process group and catch that SIGINT. Whether
  it does is measured (test plan item 7); a fix, if needed, is its own
  spec.

## Specification

- **S1. A generic exit hook in the teleprompt (G1, N2).** The teleprompt
  defines `teleprompt_at_exit CMD`, which appends `CMD` to a list. Its
  EXIT trap runs every registered command, in registration order, each
  with its failure ignored, and then `stty sane` as today. The function
  is defined before the init is sourced, so an init can call it.

  A hook, rather than letting the init set its own trap: bash keeps one
  EXIT trap per shell, so an init's `trap … EXIT` would replace the
  teleprompt's `stty sane`.

- **S2. Every quit reaches the EXIT trap (G1).** Ctrl-D and Ctrl-C at the
  prompt already do: the readline coprocess replies `eof`, the loop
  breaks, and the script ends. The teleprompt adds `trap … HUP` and
  `trap … TERM`, which redirect output to `/dev/null` (the terminal may be
  gone) and `exit` with 129 and 143, so a closed terminal or a plain
  `kill` runs the hooks too. The `INT` trap (`true`, so that Ctrl-C
  during a command kills the command and not the teleprompt) and the
  SIGTSTP handling are unchanged: Ctrl-Z suspends, nothing exits.

- **S3. The grehack2026 init registers the stop (G1).** It calls

  ```bash
  teleprompt_at_exit "[ -e '${dir}/capture/tap.pid' ] && life-tap --out '${dir}/capture' --stop"
  ```

  with `dir` the init's own directory, which is where the deck runs and
  where its `life-tap -q` writes by default. The pid-file test keeps a
  session that never started a tap from printing "no tap is writing".
  `--stop` needs no sudo: it signals the tap, which runs as the user, and
  the tap stops its own dumpcap and finishes writing its files.

- **S4. The reset is the deck's first step, and it stops a leftover tap
  first (G2, G3).** The init no longer removes anything. The deck opens
  with

  ```bash
  # Remove the artifacts of a previous run (skip this step to keep them):
  [ -e capture/tap.pid ] && life-tap --stop; rm -rf capture life.desc life eve/server.log
  ```

  Stopping before removing is what keeps G2: the leftover tap is stopped
  while `tap.pid` still names it. When the step is skipped and a tap is
  still running, the deck's own `life-tap -q` later refuses with "a tap
  is already writing", since `tap.pid` survived: the guard is intact.

  The init's guard against a pre-0388 checkout (`life/Cargo.toml`, where
  `life/` was the crate) is dropped: a checkout that old also has the old
  deck, so the new step never runs there.

## Alternatives considered

### A watchdog in `life-tap`

`life-tap --watch-pid PID` (or an environment variable the init sets)
would stop the tap when the watched process disappears. Beyond S1–S4 it
covers one case: the teleprompt dying without running its EXIT trap —
SIGKILL, the OOM killer, a crash of bash itself. That is rare during a
demo, and its cost is small once S4 is in: the leftover tap idles on a
paused game until the next run's first step stops it. A watchdog would
mean a Rust change, a pid-passing convention between init and tap, and
the pid-reuse caveat. Left out; worth revisiting if taps still leak.

### `PR_SET_PDEATHSIG` in `life-tap`

The tap's parent is the `( … &)` subshell, which exits at once, so the
signal would fire immediately. Dropping the subshell would make the
teleprompt's bash the parent, but would also kill a tap started by hand
whenever the shell that started it exits.

### Keep the reset in the init and stop the tap there

Fixes G2 but not G3: the presenter could only keep a previous run's
artifacts with `--no-init`, which also skips the life-client copy and
the splash.

### `pkill life-tap`

Not targeted: it stops every tap on the machine, including one another
session owns, and cannot reach root-owned leftovers without sudo.

## Test plan

Manual, on the presenter's machine, from `grehack2026/` in its nix-shell,
running the deck through its first section; after each case,
`ps -eo pid,user,comm | grep -E 'life-tap|dumpcap'`.

1. Ctrl-D at the prompt → no tap, no dumpcap left.
2. Ctrl-C at the prompt → same.
3. Ctrl-Z → the tap still runs; `fg`, then Ctrl-D → stopped.
4. Close the terminal window → stopped.
5. `kill -9` the teleprompt → the tap remains (N1); relaunch, run the
   first step → stopped, then `capture/` removed.
6. Skip the first step while a tap runs → the tap step refuses ("a tap
   is already writing").
7. N3: with the tap running, Ctrl-C a foreground command (e.g. `view`)
   → record whether the tap stopped.
8. The grpconf2026 deck, which registers no hook, quits as before.

## Measured outcome

Measured 2026-10-08 on the development machine, without a terminal: the
teleprompt itself needs one, so its exit-hook block was exercised
verbatim in a scratch script, and the S3/S4 command strings against the
real `life-tap --stop` with a stand-in tap (a process that writes
`tap.pid` and removes it on SIGTERM, as the tap does).

- S1/S2: on a normal end, SIGTERM and SIGHUP, the hooks run in
  registration order, a failing hook does not stop the next, then
  `stty sane`; exit codes 0, 143, 129. Stopped (SIGSTOP), nothing runs;
  continued and ended, the hooks run once. With no hook registered (the
  grpconf2026 init registers none), only `stty sane` runs.
- S3: the init's hook, built with a capture path containing a space,
  stops the stand-in tap and its `tap.pid` is gone; with no tap it prints
  nothing.
- S4: the deck's first step stops the stand-in tap, then removes
  `capture/`, `life.desc`, `life/` and `eve/server.log`; with no tap it
  prints nothing and still removes them.

**Not yet measured:** the manual test plan (items 1–8) on a real
terminal with a real tap, including N3. To be run at the next rehearsal.
