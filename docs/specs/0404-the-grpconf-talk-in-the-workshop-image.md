<!--
SPDX-FileCopyrightText: Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0404 — the gRPConf talk in the workshop image

Status: implemented (pending: test plan item 6, the rehearsals)
Implemented in: 2026-10-09
App: grpconf2026 (deck, init, beats), nix (demo-shells.nix, a new
        grpconf2026-demo.nix, grehack2026.nix), grehack2026/SETUP.md,
        grehack2026/smoke-test.sh
Refs: docs/specs/0403-the-demo-runs-in-the-workshop-image.md (the
        packaging this copies: one Nix definition for shell and image),
        docs/specs/0394-each-demo-brings-its-own-shell.md (the grpconf
        shell and its bob/ staging),
        docs/specs/0374-a-workshop-image-for-every-laptop.md (the image,
        its closure rule S2)

## Background

Spec 0403 gave the GreHack talk a single packaging, shared by the native
demo shell and the workshop image:

- one Nix file (`nix/grehack2026-demo.nix`) defines the teleprompt, the
  tools the deck calls, the environment, and the deck's material;
- the shell and the image both use it.

The gRPConf 2026 talk (`grpconf2026/`) predates that. It already has
its own `grpconf2026/shell.nix`, which selects `grpconf2026-shell`
(spec 0394), the same pattern as `grehack2026/shell.nix`. But that shell
has three problems:

1. **The deck calls tools its shell lacks.** `bat` (section 4),
   `tree` and `rsync` (annex B) are not in the shell. They run only when
   the presenter's host happens to have them. The workshop image has
   none of them either.
2. **An unset variable.** Annex C runs
   `protolens --descriptor-set $PROTOTEXT_WKT_SET …`. Only the
   dev-shell exports that variable (`nix/shells.nix:210`), so in the demo
   shell the command gets an empty argument.
3. **Its definitions sit inline in `demo-shells.nix`:**
   - the environment, three `export`s in a `shellHook`;
   - the `bob/` staging, a shell function copying from `grpconfDemo`;
   - `deckTools`, with the full `util-linux` for a `hexdump` this deck
     never calls.

   An image cannot reuse any of it.

The talk would make a good stretch goal for GreHack participants who
finish the workshop early. It shows the same tools on a real-world
corpus (googleapis, 8,000 files), with three guided protolens beats.
Unlike the GreHack talk, it needs no root (no tap) and no network:
`bobapp` is only scanned and decompiled, never run.

Measured on 2026-10-09 against the 0403 image (1,239 MiB unpacked),
grpconf adds:

| Need | Added (unpacked) |
|---|---|
| `bobapp` + `capture` + `logfile` (`grpconfDemo`) | +6.1 MiB |
| teleprompt, Neovim, buf, protoc, bash, coreutils, the googleapis and WKT databases | 0, already in the image |
| `bat`, `tree`, `rsync`, if kept (S4 replaces them) | +8.4 MiB |

The image has neither `find` nor `sed`, so the S4 replacements use only
bash and coreutils.

## Goals

- **G1.** One configuration for the grpconf talk, native and in the
  image: the same Nix definition of the tools, the environment and the
  material. This is 0403 G2, applied to grpconf.
- **G2.** The grpconf deck runs unchanged in the workshop image, as the
  image's default user (no `--user 0`), under Podman and Docker, with no
  network.
- **G3.** The deck calls only tools the image already has: no tool from
  the host, and no unset variable.
- **G4.** Participants find it. The login banner and SETUP.md present
  two optional stretch goals: the gRPConf scenario and the
  `anomalies.pb` study.
- **G5.** The image grows by at most 10 MiB and still passes the 0374 S2
  closure check.

## Non-goals

- **N1.** Making the talk self-guided beyond what the deck and beats
  already say. The deck is a speaker's deck: its long comment blocks
  are its narration, and they read as one. Rewriting it for
  self-study is a separate piece of work.
- **N2.** Running `bobapp`. It calls the Places and Routes APIs with an
  API key, which no participant has. The talk never runs it.
- **N3.** Shipping `speech.md`, `speaker-notes.md`, `artifacts.md` or
  `mint-fixtures.sh`. These are for the presenter and the maintainer,
  not for the audience.
- **N4.** One file for both talks' demo definitions. They share the
  teleprompt and the editor, and the per-talk parts stay per talk
  (S1).
- **N5.** A new `grpconf2026/shell.nix`. It exists already, and S2
  changes only what it selects.

## Specification

### One definition, shell and image

- **S1. `nix/grpconf2026-demo.nix`.** It mirrors
  `nix/grehack2026-demo.nix`, and exports:
  - `demoTools`: the teleprompt, the lean Neovim and buf, and protoc.
    The teleprompt is the one from `grehack2026-demo.nix`; both talks
    share it, and the grpconf file takes it as an argument.
  - `demoEnv`, with:
    - `PROTOTEXT_DESCRIPTOR_SET` and `PROTOTEXT_WKT_SET` (both the WKT
      database, as the dev-shell has them);
    - `PROTOTEXT_GOOGLEAPIS_SET` and `PROTOTEXT_GOOGLEAPIS_PBS`.
  - `deck`: the committed material, as a `lib.fileset`. It holds
    `grpconf2026.sh`, `grpconf2026.init`, `anomalies.pb`,
    `anomalies.script` and `beats/`, plus `bob/` staged from
    `grpconfDemo` (`app`, `capture`, `logfile`).

  `deckTools` and the inline definitions in `demo-shells.nix` go away.
- **S2. The native shell.**
  - `grpconf2026-shell` takes its packages from `demoTools` and its
    environment from `demoEnv`, the same way `grehack2026-shell` does.
  - `grpconf2026/shell.nix` is unchanged.
  - The `bob/` staging stays; it now copies from the `deck`'s `bob/`,
    which keeps its one Nix source.
  - The sentinel logic (spec 0394 S5) is unchanged.
- **S3. In the image.**
  - `contents` gains grpconf's `demoTools`. All of it is already in the
    image from 0403.
  - `extraCommands` copies `deck` to `/workshop/grpconf2026`, writable,
    as 0403 S7 does for GreHack: `1777` directories, `0666` files,
    `bob/app` `0777`.
  - `Env` gains `demoEnv`. The GreHack and grpconf `demoEnv` agree on
    `PROTOTEXT_DESCRIPTOR_SET`, and the build asserts it.

### The deck uses only what the image has

- **S4. Three lines change in `grpconf2026.sh`.** Each replacement was
  checked with bash and coreutils alone.

  | Today | Replacement | Why it works |
  |---|---|---|
  | `prototext … list-schemas bob/capture \| bat -l yaml --style=plain` | `prototext … list-schemas bob/capture` | The output is a few lines of YAML; it loses only its colors and prints in place as before. |
  | `tree -P "*.pb" alice/places`, and the same for `*.proto` | `(shopt -s globstar; ls -1 alice/places/**/*.pb)`, and the same for `*.proto` | One path per line instead of a tree. The narration ("34 files") still reads true. |
  | `rsync -a --include="*/" --include="*.pb" --exclude="*" alice/places/ alice/places-incomplete/` | `mkdir -p alice/places-incomplete && (shopt -s globstar; cd alice/places && cp --parents **/*.pb ../places-incomplete/)` | `cp --parents` keeps the directory tree, as rsync did. |

  - The subshells keep `globstar` from leaking into the teleprompt's
    shell.
  - The comment lines around the three commands are rewrapped if they
    name `tree` or `rsync`.
  - The deck's banner padding rule applies to every comment line
    touched.

### Runnable by participants

- **S5. As the default user.**
  - The grpconf init removes and recreates `alice/` next to itself,
    and the deck writes only there. `/workshop/grpconf2026` is
    world-writable, so uid 1000, or any `--user` uid under Docker on
    Linux, runs it.
  - Nothing in the deck needs root.
- **S6. One window.** The grpconf deck has no second or third window
  (there is no client or server). It runs in the window `run` gave:

  ```sh
  cd /workshop/grpconf2026 && teleprompt grpconf2026.sh
  ```
- **S7. SETUP.md section 6, "Stretch goals (optional)".** Two goals,
  each with what it shows and how to start it.
  - **6.1, the gRPConf scenario.**
    - What it shows: protoc's limits, schema recovery from a binary,
      the googleapis corpus, lossless re-encoding.
    - It needs no root and no network.
    - The command is S6's.
  - **6.2, the anomalies study.**
    - What it shows: `/workshop/anomalies.pb`, one example of each
      category of encoding anomaly protolens annotates.
    - It is walked step by step with the guided script that is already
      in the image:

      ```sh
      cd /workshop
      protolens --type google.protobuf.FileDescriptorProto anomalies.pb \
          --script anomalies.script
      ```
    - `/workshop/README.md` explains each anomaly.
    - The gRPConf deck's annex C walks the same taxonomy, with its own
      blob: `grpconf2026/anomalies.pb`, a `FileDescriptorSet`, which
      differs from the workshop's `FileDescriptorProto` blob.
- **S8. The login banner.** Its existing `Material:` line, which suggests
  `anomalies.pb`, is replaced by two lines:

  ```
  Stretch goals (SETUP.md, section 6):
    cd grpconf2026 && teleprompt grpconf2026.sh       the gRPConf talk
    protolens … anomalies.pb --script anomalies.script   the anomalies
  ```

## Alternatives considered

- **Leave grpconf native-only.** It fails G1: its shell keeps
  depending on host tools (Background items 1 and 2). It also costs
  the participants a stretch goal for 6 MiB.
- **A separate grpconf image.** It would mean a second download, a
  second registry entry, and a second smoke test, for a 6 MiB
  difference.
- **Add `bat`, `tree` and `rsync` to the image (+8.4 MiB).** It would
  leave the deck untouched. Only the `bat` line belongs to the talk as
  presented (section 4); `tree` and `rsync` sit in annex B, after the
  thank-you, which the 20-minute speech never reaches. Dismissed: three
  tools for three lines, where bash and coreutils do the same job (S4).
  The image should not grow to spare an edit.
- **Leave the annexes out of the image's copy.** Annexes B and C were
  never presented. But as a self-paced stretch goal, B (reproto on an
  incomplete descriptor set) is a fair exercise, and C walks the same
  taxonomy as stretch goal 6.2. They ship, with S4's
  replacements.
- **`view -c "set ft=yaml"` in place of `bat`.** It would keep the
  colors but open an editor, which needs `:q`, for six lines of output.
  Plain output stays in place like `bat --style=plain` did.

## Test plan

1. **Closure and size.** `nix-build -A grehack2026.closureCheck`
   passes. The image grows by ≤ 10 MiB.
2. **Smoke test: tools and material.**
   - Every command the grpconf deck calls resolves (`command -v`).
   - The image has no `bat`, `tree` or `rsync`, so nothing silently
     depends on them.
   - `/workshop/grpconf2026` has the deck, the beats and
     `bob/{app,capture,logfile}`, and its directories are 1777.
3. **Smoke test: the deck's pipeline, as uid 1000, no network
   (`--network none`).**
   - `reproto --desc-root bob/app --schema-db-out alice/app.desc`
     succeeds.
   - The `capture` and `app.desc` beats walk (`… script`) with no
     `error:`.
   - Annex B's S4 commands run: the reproto extraction, `ls` with
     globstar, and the `cp --parents` copy. The copy holds the same
     `.pb` files as the source.
   - Annex C's protolens command runs with `$PROTOTEXT_WKT_SET`.
   - The `googleapis.desc` beat needs `alice/overrides`, which the
     presenter saves interactively, so it is covered by item 6.
4. **Smoke test: the anomalies study.** The 6.2 command walks
   (`… script`) with no `error:`. The existing "protolens script walk"
   check already does this; it is kept.
5. **Same configuration.** `grpconf2026-shell` and the image share the
   store paths of `demoTools`. This is the 0403 test plan item 5 check,
   for grpconf.
6. **Rehearsal.** The whole grpconf deck, annexes included: once
   natively, and once in the container as uid 1000.

## Measured outcome

Measured on 2026-10-09, x86-64, Podman 5, on a local build.

- **Size:** the image went from 1,240 to 1,246 MiB unpacked (+6 MiB:
  `bobapp` and its two fixtures; everything else was already there).
  The closure check passes.
- **Smoke test:** 26 of 26 checks pass. The two new ones:
  - **tools and material:** no `bat`, `tree` or `rsync`;
    `PROTOTEXT_WKT_SET` set;
  - **the pipeline, as uid 1000 with `--network none`:** reproto from
    `bob/app`, the `capture` and `app.desc` beats walked with no
    error, annex B's globstar `ls` and `cp --parents` (every `.pb`
    copied), and annex C's protolens command.
- **Native shell:** entered in a scratch `grpconf2026/`, it staged
  `bob/` from the deck, exported `PROTOTEXT_WKT_SET`, and has the
  teleprompt, nvim and protoc on PATH.
- **Implementation choices:**
  - The new argument of `demo-shells.nix` and of the image is named
    `grpconfTalk`, since `grpconfDemo` already names the bobapp stage
    in `default.nix`.
  - The image's banner keeps a bare `Material:  /workshop` line above
    the two stretch-goal lines.
- **Not done:** the rehearsals (item 6), natively and in the container
  as uid 1000.
