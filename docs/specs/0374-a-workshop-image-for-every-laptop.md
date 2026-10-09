<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0374 — a workshop image for every laptop

Status: implemented (S1–S13); S14 is the release procedure, run by hand
Implemented in: 2026-09-30
App: grehack2026, nix, CI
Refs: .github/workflows/nix.yml (the x86-64 and arm64 runners this
      builds on); default.nix `prototools` (the bundle the image
      carries); prototext/wkt/prebuilt/README.md (the committed WKT
      graph the image embeds); docs/specs/0375-a-game-of-life-to-spy-on.md
      (what the image gained since: the game, the tap, wireshark-cli,
      fortune, tmux, and the smoke checks that go with them)

## Background

prototools is presented at GreHack 2026, followed by a hands-on workshop.
Participants bring their own laptop and run the tools from a container
image. The laptops are Linux on x86-64, Linux on arm64 (Snapdragon and
other ARM laptops, Asahi on Apple hardware), and macOS on Apple silicon
or Intel. Everything the participant installs must be open source and
free of commercial licences.

### What is already true (checked 2026-09-29)

- **The whole stack builds and tests natively on arm64 Linux.**
  `.github/workflows/nix.yml` runs `nix-build -A ci` on `ubuntu-latest`
  (x86-64) *and* `ubuntu-24.04-arm` (arm64), and `nix/pypi.nix` already
  ships `manylinux_2_28_aarch64` wheels. A `linux/arm64` image needs no
  new porting work, only a build on that runner.
- **`default.nix` already has the bundle.** `prototools` is a
  `symlinkJoin` of `prototext`, `protolens`, `reproto`, `protoscan` and
  `wktDb`.
- **That bundle's closure is 1.7 GiB (576 store paths), much of it
  leaked build inputs.** The largest members: the vendored Cargo
  dependency tree `prototools-deps-deps` (292 MiB, referenced by the
  bundle directly), `tree-sitter-language-pack` (158 MiB), `buf`
  (121 MiB, via `protolens`), Python (114 MiB), perl (62 MiB, via
  `protolens` → `neovim` → `wl-clipboard`) and two Windows `winapi`
  crates (104 MiB together). An image carrying that closure unchanged
  would be a multi-gigabyte download on conference Wi-Fi.
- **Both leaks have a precise cause.**
  - *The Cargo cache.* `nix/rust.nix` builds protolens with
    `doInstallCargoArtifacts = true`, so crane copies its build cache
    (`target.tar.zst`, and `target.tar.zst.prev` pointing at
    `prototools-deps-deps`) into the protolens package. The cache
    references the vendored crate registry, which is where the `winapi`
    crates come from. Nothing consumes protolens's cache (unlike
    `prototextBare`'s, which the full `prototext` build reuses), and the
    final `prototext` package is already clean (`bin`, `share`).
  - *perl.* nixpkgs' Neovim wrapper puts `wl-clipboard` on `PATH`
    whenever `waylandSupport` is on (the default on Linux), and
    `wl-clipboard` brings perl. That is a feature, not a leak: it lets
    Neovim, opened by protolens, copy to a Wayland desktop's clipboard.
    A container has no desktop clipboard to reach.
- **With both removed, and googleapis added (S4), the image is about
  225 MiB gzip-compressed per architecture** (about 1.2 GiB
  uncompressed), estimated by set difference over the current closure,
  not measured on a built image, and before S2's lean Neovim, which
  removes about 200 MiB more uncompressed. None of the denylisted names
  (S2) remains in it.
- **The rest of the toolchain is in the pinned nixpkgs** (nixos-25.11):
  `dockerTools.streamLayeredImage`, `dockerTools.fakeNss`, `crane`
  0.20.6, `skopeo` 1.20.0.
- **Both CI runners have Docker.** The `ubuntu-24.04-arm` partner image
  (`actions/partner-runner-images`, maintained by Arm) lists Docker,
  Docker Compose and Docker Buildx, and Podman; the standard
  `ubuntu-latest` image has them too. The smoke test (S7) can run the
  image natively on both.
- **The googleapis database has never been built on arm64.** It is in
  `full-tests` only, and CI runs `ci` on the arm runner. The first arm64
  image build is its first arm64 build.

### The Rosetta question

On an Apple-silicon Mac, every container runtime runs a Linux VM, and
containers are Linux containers. An `amd64`-only image runs there through
Rosetta 2 in that VM (Colima `--vm-type vz --vz-rosetta`, recent
`podman machine` on `applehv`), or through QEMU user emulation when
Rosetta is unavailable, which is several times slower. An arm64 Linux
laptop has no Rosetta and would get QEMU only.

Since the arm64 build already works, an OCI **image index** — one tag,
one `linux/amd64` and one `linux/arm64` image behind it — gives every
laptop a native image. Participants still type one image reference; the
runtime picks the matching architecture. Rosetta becomes a fallback
rather than the plan.

## Goals

- **G1.** One image reference that runs natively on `linux/amd64` and
  `linux/arm64`, covering Linux x86-64, Linux arm64, and macOS on Apple
  silicon (through the runtime's arm64 VM) and on Intel.
- **G2.** Produced by an automated, reproducible process: a CI workflow
  on the two existing native runners, and the same Nix attribute
  runnable on a developer machine for the local architecture — which is
  where it is developed and tested first (S9).
- **G3.** The image carries a **runtime-only** closure: none of the
  build inputs listed above. Target: the compressed download of each
  architecture **under 300 MiB** (estimated at about 225 MiB before the
  lean Neovim of S2; revised with the measured figure).
- **G4.** It can be run with open-source runtimes only: Docker Engine or
  Podman on Linux, Colima or Podman on macOS. Nothing requires Docker
  Desktop or OrbStack — though participants who already have Docker
  Desktop can use it.
- **G7.** No extra Rust compilation: the regular build and the image
  share one compiled protolens (S2).
- **G5.** protolens's TUI works inside the container: colors, mouse,
  resize, and its `neovim` integration.
- **G6.** Participants can work offline: the image is also published as
  per-architecture archive files that can be handed out on USB keys and
  loaded without a registry.

## Non-goals

- **N1. The workshop exercises.** What the participants do is a separate
  piece of work; this spec produces the vehicle. The image has a slot for
  the material (S4) and ships the existing `tests/fixtures/anomalies.pb`
  walkthrough in it.
- **N2. Windows.** Not requested. WSL2 with Podman or Docker Engine
  inside it would run the `linux/amd64` image unchanged; documenting that
  is a small follow-up if needed.
- **N3. A GUI container tool.** Participants use a terminal.
- **N4. Signing the image** (e.g. cosign). Worth adding for a public
  tag, but not required for a workshop.
- **N5. Rosetta as the primary path.** Kept only as the fallback
  described in the participant guide (S8).

## Specification

### The image

- **S1. Built by Nix, not by a Dockerfile.**
  `pkgs.dockerTools.streamLayeredImage`, as a new attribute
  `grehack2026.image` in `default.nix`, for the system Nix builds on.
  Nix already builds every component; a Dockerfile would duplicate that
  build and lose its reproducibility. `streamLayeredImage` also needs no
  container daemon to build, and it spreads store paths across layers,
  so rebuilding after a code change re-uploads only the layers that
  changed.
- **S2. A runtime-only closure, without compiling twice.**
  - **In the regular build, for everyone:** protolens is built with
    `doInstallCargoArtifacts = false`. Nothing consumes its cargo cache,
    so this only drops the 292 MiB dependency tree and the `winapi`
    crates from every install of prototools. It costs one rebuild of
    protolens, once.
  - **protolens is split in two:** `protolens-unwrapped`, the compiled
    binary, built once; and a thin wrapper derivation that puts Neovim
    and `buf` on its `PATH`, as `postInstall` does today. The wrapper is
    a shell script, built in seconds. Today the wrapper script is part of
    protolens's own output and references the default Neovim, so an
    image built on it would carry the clipboard chain, and overriding
    Neovim there would recompile protolens.
  - **The regular bundle** wraps protolens with the default Neovim, so
    desktop users keep the clipboard.
  - **The image** wraps it with a lean Neovim,
    `wrapNeovimUnstable neovim-unwrapped { waylandSupport = false;
    withRuby = false; withPython3 = false; }`. (`neovim.override {
    waylandSupport = false; }` does not evaluate: the argument belongs to
    `wrapNeovimUnstable`, not to the `neovim` package.) The Neovim
    wrapper is only a script around the shared compiled Neovim, so this
    costs no compilation. Measured on the pinned nixpkgs, the Neovim
    closure goes from 407 MiB (default) to 292 MiB with `waylandSupport`
    off alone — Ruby remains — and to **98 MiB** with the Ruby and
    Python providers off as well. protolens needs neither provider: it
    starts Neovim with its own `protolens/nvim/init.lua` (`-u`), which is
    pure Lua and uses Neovim's built-in LSP client
    (`vim.lsp.start` with `buf lsp serve`).
  - `buf` stays in both: it is `buf lsp serve`, the protobuf language
    server behind the editor integration (G5).
  - The image's contents come from a new `prototools-runtime` bundle
    built this way.
  - **Two denylist checks** fail the build when a store path whose name
    matches enters a closure:
    - on the regular `prototools` bundle: `-deps-deps`, `winapi`,
      `cargo-package` — the leaks, which help nobody. `ci` builds the
      packages but not the `prototools` bundle, so this is its own small
      derivation, `prototools-closure-check`, over `prototools`'s
      closure (`closureInfo`), added to `ci`;
    - on the image, additionally `wl-clipboard`, `perl` and `ruby`,
      which are features on a desktop and dead weight in a container.
- **S3. Base contents.** Besides the tools: `bashInteractive`,
  `coreutils`, `gnugrep` (1 MiB, and what participants reach for first on
  a decoded blob), `less`, `ncurses` (for `reset`), `cacert`, and a login
  shell. No package manager and no distro base image. Terminfo is not
  needed by protolens (crossterm writes ANSI directly), but `ncurses`'
  terminfo set is included so `less` and `reset` behave under any
  `$TERM`, `xterm-kitty` included.
- **S4. Layout and defaults.**
  - Non-root user `hacker`, uid and gid 1000, with entries in
    `/etc/passwd` and `/etc/group` (`dockerTools.fakeNss`, plus the
    `hacker` lines), so the prompt and `whoami` work. The image's
    `User` is `1000:1000`; working directory `/workshop`.
  - `HOME=/home/hacker` is set explicitly and the directory is created
    mode `1777`, like `/tmp`. Docker users on Linux run with
    `--user "$(id -u):$(id -g)"` (S8), which is often not uid 1000; with
    `HOME` set and writable by anyone, Neovim's state and cache, and any
    tool writing to `~`, work for every uid, with or without a passwd
    entry.
  - `/tmp` exists, mode `1777`. A Nix-built image has none by default,
    and protolens needs one: its Neovim socket and some blob scratch
    files go to `std::env::temp_dir()` (`protolens/src/tui/neovim.rs`,
    `protolens/src/blob.rs`), so without `/tmp` the editor key fails.
  - `/workshop` holds the workshop material, starting with
    `tests/fixtures/anomalies.pb`, its script and its README. It is mode
    `1777` as well, so participants can write next to the material
    whatever their uid; files they want to keep go to the mounted
    `/work`.
  - The googleapis schema database (`googleapis-db`: `googleapis.desc`,
    its graph and index, and the decompiled `proto/` tree) and
    `googleapis-pbs` ship in the image, with `PROTOTEXT_GOOGLEAPIS_SET`
    and `PROTOTEXT_GOOGLEAPIS_PBS` set as the dev shell sets them. These
    are conveniences for people and scripts — no tool reads them — so
    commands pass them explicitly (`--descriptor-set
    "$PROTOTEXT_GOOGLEAPIS_SET"`). It is
    176 MiB on disk but 20 MiB compressed (mostly `.proto` source), so it
    costs the download little. It goes in its own layer, which a change
    to the tools does not invalidate.
  - `PROTOTEXT_DESCRIPTOR_SET` points at the image's WKT database, as the
    dev shell does, so `prototext decode -t google.protobuf…` works with
    no flag.
  - The entrypoint is a login `bash` that prints a short banner: the
    tools, where the material is, and how to mount a directory from the
    laptop.
- **S5. Reproducibility.** Fixed creation time (the Nix default, epoch),
  so the same commit produces byte-identical images and the same
  digests. The labels `org.opencontainers.image.source`, `.revision`
  and `.licenses` are set from the repository.

### The process

- **S6. CI workflow** `.github/workflows/workshop-image.yml`, run by
  hand (`workflow_dispatch`) and on tags `grehack2026-*`:
  1. On `ubuntu-latest` and `ubuntu-24.04-arm`, in parallel:
     `nix-build -A grehack2026.image`, then a smoke test (S7), then a
     push with `skopeo copy` (Apache-2.0, in nixpkgs, daemonless) to
     `ghcr.io/douzebis/prototools-workshop:<revision>-<arch>`. Each also
     uploads a `docker-archive` file of its image,
     `prototools-workshop-<arch>.tar`, as a workflow artifact (G6).
  2. Then one job assembles the index with `crane index append`
     (Apache-2.0, go-containerregistry, in nixpkgs) and pushes it as
     `:<revision>` and `:grehack2026`. The same job assembles the USB-key
     bundle as one artifact: both archives, `load.sh`, `SHA256SUMS` and
     `SETUP.md`.
  The image is `ghcr.io/douzebis/prototools-workshop`. GitHub Container
  Registry is free for public images and the pull is anonymous; Docker
  Hub was not used because it rate-limits anonymous pulls per IP
  address, and a conference room shares one. Behind the index, a pull
  fetches only the image for the laptop's own architecture.
  The workflow needs `permissions: packages: write`. A package published
  from a workflow is likely created **private**; switching it to public
  in the package settings is a one-time manual step, to confirm on the
  first publication.
- **S7. Smoke test, on each native runner, against the built image:**
  - `prototext --version`, `protolens --version`, `reproto --help`;
  - `prototext decode -t google.protobuf.FileDescriptorProto` on
    `anomalies.pb`, round-tripped through `prototext encode`
    byte-exactly;
  - `protolens … anomalies.pb script` (the batch walk, no TTY needed)
    completes with no `error:` line;
  - a decode that infers its type against the googleapis database, with
    `--descriptor-set "$PROTOTEXT_GOOGLEAPIS_SET"` passed explicitly
    (without it, inference would silently run against the WKT
    database), which exercises that database on each architecture — on
    arm64 for the first time;
  - protolens's editor path without a terminal: Neovim starts headless
    with protolens's `init.lua`, which exercises `/tmp`, `$HOME` and
    the lean Neovim;
  - the S2 denylist check, and the image size, recorded in the job
    summary.
- **S8. Participant guide** `grehack2026/SETUP.md`: short, because a
  GreHack audience can install a container runtime. It says any OCI
  runtime works, recommends one per platform and links to its official
  install instructions rather than repeating them:
  - **Linux:** Podman (Apache-2.0), rootless, run with `--user 0`; or
    Docker Engine (Apache-2.0). Amended by spec 0375 S8: rootless
    Podman keeps what the container writes owned by the participant.
  - **macOS:** Colima (MIT) with the `docker` CLI, or Podman.
  - Docker Desktop works too, for those who already have it; it is
    simply not what the guide recommends, since its licence is not open
    source and requires a subscription in larger organisations.
  - **The run command,** e.g.
    `docker run -it --rm -e TERM -e COLORTERM -v "$PWD":/work ghcr.io/douzebis/prototools-workshop:grehack2026`,
    with `--user "$(id -u):$(id -g)"` for Docker on Linux so files
    written to `/work` are owned by the participant (rootless Podman
    maps this already).
  - **Before the event:** install the runtime and start it once, checked
    with `docker run --rm hello-world` (or `podman run …`). On macOS,
    Colima and `podman machine` download a Linux VM image on first
    start, a few hundred MB that a USB key does not provide. Pulling the
    workshop image at home is recommended but optional.
  - **At the event, offline:** the USB key's `load.sh` picks the archive
    for the laptop from `uname -m` (`x86_64` → amd64,
    `arm64`/`aarch64` → arm64), checks it against `SHA256SUMS` — with
    `sha256sum` on Linux and `shasum -a 256` on macOS, which lacks the
    former — and runs `docker load -i` (or `podman load -i`). One archive per
    architecture, not one archive holding both: support for loading a
    multi-architecture archive varies across Docker and Podman
    versions.
  - **Fallback:** on a Mac whose runtime cannot run the arm64 image, the
    `amd64` image with `--platform linux/amd64` under Rosetta.
- **S9. Local first, then CI.** Development and testing happen locally
  on x86-64: `nix-build -A grehack2026.image`, loaded with
  `./result | docker load` (or `podman load`), run, and checked with
  S7's smoke test as a script (`grehack2026/smoke-test.sh`) that CI runs
  unchanged. The script runs on the host and drives `docker run` against
  a given image reference, so the same script tests a local build and a
  CI build. CI then adds what a single machine cannot: the arm64 image,
  the index and the publication. Building arm64 locally through
  binfmt/QEMU is possible but not part of the process.

### Amended 2026-10-09 (implemented the same day)

Two things a participant cannot get today without the repository at
hand: an explanation on the image's registry page, and a download that
outlives the workflow run. The USB-key bundle exists only as a workflow
artifact, which GitHub deletes after its retention period (90 days by
default) and serves only to signed-in users. And the guard that keeps the
workflow from running in the ThalesGroup mirror, whose build budget is
strict, is on one job and implied for the other.

- **S10. The workflow runs only in douzebis/prototools.** Every job
  carries `if: github.repository == 'douzebis/prototools'`. The image job
  has it already; the index job is skipped today only because the job it
  `needs` was, which a later edit (`if: always()`, a new job without
  `needs`) would silently undo. In the ThalesGroup mirror a tag push or a
  dispatch then starts a run whose jobs all skip, and a skipped job
  consumes no runner minutes.

- **S11. The registry page says how to run the image.** The index pushed
  as `:<revision>` and `:grehack2026` carries the annotation
  `org.opencontainers.image.description`: what the image is, the run
  command from S8, and the URL of `grehack2026/SETUP.md` on GitHub. For a
  multi-architecture image GitHub reads the description from the index,
  not from the per-architecture images; the per-architecture images carry
  the same text as a label (`config.Labels`), so `docker inspect` shows it
  too. The text lives once, in `grehack2026/image-description.txt` (411
  characters; GitHub shows up to 512), which the image's label and the
  workflow both read.

  The index is an OCI index, not the Docker manifest list
  `--docker-empty-base` used to make: the registry page reads an OCI
  index's annotations. `crane mutate --annotation` refuses an index ("not
  yet supported", crane 0.20.6), so the workflow fetches the index's
  JSON, adds the annotation, and puts it back with `crane edit manifest`.
  This was checked against crane's own test registry (`crane registry
  serve`). Whether the package page displays it is checked at the first
  publication (S14).

- **S12. A GitHub Release per `grehack2026-*` tag.** On a tag push (not on
  a dispatch, which publishes no version), the index job creates a GitHub
  Release named after the tag, with the USB-key bundle's files as assets:
  `prototools-workshop-amd64.tar`, `prototools-workshop-arm64.tar`,
  `load.sh`, `SHA256SUMS` and `SETUP.md`. Its notes give the pull command,
  explain `load.sh`, and link `SETUP.md` at the released revision. The
  image is also tagged with the release's name, so a release names an
  image that later pushes cannot move. Unlike a workflow artifact, a
  release asset does not expire and needs no sign-in. The job gains
  `permissions: contents: write`, and repeats `packages: write`, since a
  job's permissions replace the workflow's. Each archive is about 1.25
  GiB, under GitHub's 2 GiB limit per asset.

- **S13. A README inside the image.** `/workshop/README.md` explains the
  image itself — the tools, the game in three terminals (SETUP.md section
  4), where `/work` is — and points at `anomalies.pb` as the first thing
  to open. The anomalies fixture's own README, copied there today under
  that name, moves to `/workshop/anomalies.md`. The source is
  `grehack2026/workshop-README.md`. It also names the two talks (specs
  0403, 0404), which came after this amendment.

- **S14. Releasing, by hand, in order.**
  1. Push a `grehack2026-*` tag to `origin` (douzebis/prototools).
  2. Wait for the workflow: both images built and smoke-tested, the
     index pushed, the release created.
  3. On the first publication only: switch the package to public in its
     settings (S6).
  4. Check that the index lists both platforms:
     `crane manifest ghcr.io/douzebis/prototools-workshop:grehack2026`.
  5. Pull and run the image on an amd64 machine and on an arm64 one (a
     Mac), as a participant would, following `SETUP.md`.
  6. Copy the release's assets to the USB keys.

## Alternatives considered

### A single `amd64` image, run under Rosetta on Macs

What was first asked for. Rejected as the primary path: arm64 Linux
laptops have no Rosetta and would fall back to QEMU user emulation,
several times slower; Rosetta itself needs a runtime and VM configured
for it (Colima with `vz`, recent Podman on `applehv`), which is one more
setup step to go wrong in a workshop; and protolens's type inference is
CPU-bound, so emulation shows. The arm64 build already exists (CI),
which is what makes the index nearly free. The single-image path
survives as S8's fallback.

### A Dockerfile

Rejected: it would rebuild the Rust and Python stack a second way,
outside the Nix build that CI already tests on both architectures, and
lose byte-for-byte reproducibility.

### Cross-compiling arm64 from the x86-64 runner

Rejected while native arm64 runners are free for public repositories:
cross-compiling the Python extensions and the Rust workspace through
`pkgsCross` is real work, and QEMU emulation of a full build is slow.

### Recommending Docker Desktop

Not open source, and its licence requires a paid subscription in larger
organisations, so the guide does not recommend it — though it runs the
image like any other runtime.

## Test plan

1. `nix-build -A grehack2026.image` on x86-64 Linux loads and runs; S7's
   checks pass locally.
2. The CI workflow on a test tag produces both per-arch images, the
   index, and the two archive artifacts; S7 passes on both runners.
3. Both S2 denylist checks fail when a denied path is deliberately put
   into their closure (neither check is vacuous), and pass on the real
   ones.
4. The regular `prototools` bundle keeps `wl-clipboard` (desktop users
   keep the clipboard) and no longer contains `prototools-deps-deps` or
   `winapi`; protolens compiles once for both bundles (the image's
   protolens binary is the regular one's store path).
5. Pulling the index resolves to `amd64` on an x86-64 machine and to
   `arm64` on an arm64 one (`docker image inspect` → `Architecture`).
6. Manual, before the workshop: the setup guide followed from scratch on
   a Linux x86-64 laptop, an Apple-silicon Mac with Colima, and one with
   Podman — protolens's TUI checked for colors, mouse, resize and the
   editor key.
7. The same image built twice from one commit has the same digest (S5).
8. The image runs with `--user` set to a uid other than 1000: `$HOME`
   is writable, Neovim starts, and protolens's editor key works.
9. The USB bundle, offline: `load.sh` on an x86-64 and an arm64
   machine loads the matching archive, and rejects a corrupted one.

## Measured outcome

**Re-measured 2026-10-09,** locally on x86-64 Linux, rootless Podman
5.8.7, after spec 0375 added the game, the tap, wireshark-cli, fortune
and tmux: `nix-build -A grehack2026.image` and
`grehack2026.closureCheck` pass; the image is 1150 MiB unpacked, 180
store paths (from 859 MiB and 122); `DOCKER=podman
grehack2026/smoke-test.sh` passes all 18 checks (from nine). arm64 is
still measured only by CI. S10–S14 are not implemented yet.

Measured 2026-09-30, locally on x86-64 Linux (Docker 29.8.0).

**Image (linux/amd64).** 239 MiB gzip-compressed (the stream piped
through `gzip -6`), 859 MiB unpacked, 122 store paths in 99 layers.
Well under the 300 MiB target. The largest paths: `googleapis-db`
(176 MiB unpacked), reproto's `tree-sitter-language-pack` (159 MiB),
`buf` (121 MiB, of which the two `protoc-gen-buf-*` plugins protolens
does not use are 72 MiB), Python (114 MiB). A second glibc (2.42 besides
2.40, 36 MiB) comes with `buf`, which is pinned to its own nixpkgs
revision on purpose (default.nix). linux/arm64 is measured by the first
CI run.

**S2.** The regular `prototools` closure went from 1.7 GiB and 576 store
paths (Background) to 873 MiB and 187 paths, with `wl-clipboard` kept
and no `-deps-deps`, `winapi` or `cargo-package` path. There were two
leaks, not one:
protolens's `doInstallCargoArtifacts`, as expected, and the three pyo3
extensions, whose `.so` embed the vendored sources' store paths as panic
locations. crane strips those in a `postInstall` hook that the extensions'
custom `installPhase` never ran; it now runs it (nix/rust.nix,
`makePyo3Extension`). The image does not add a store path to what the
tools need: the image's `protolens-unwrapped` is the regular bundle's.

**Test plan.**

1. Passes: `grehack2026/smoke-test.sh` passes all nine checks against
   the local build, and fails four when `anomalies.pb` is removed.
2. Pending: the first run of `.github/workflows/workshop-image.yml`.
   Rehearsed locally instead: skopeo pushed the image to a local
   registry (`distribution`), `crane index append --docker-empty-base`
   made a manifest list whose entry has the platform `linux/amd64` read
   from the config, and `docker pull` of the index tag ran the image.
   actionlint and shellcheck are clean.
3. Passes: with `perl` passed as `buf` (`--arg buf`), the image check
   fails naming the perl path. The regular check failed on the real
   leaks until they were fixed, and passes now; both are in `ci`.
4. Passes (see S2 above).
5. Pending: CI (arm64).
6. Pending: manual, before the workshop.
7. Passes: two streams of the same build have the same SHA-256; the
   image's store path is unchanged across rebuilds.
8. Passes: the smoke test runs the headless editor check as uid 4242.
9. Half: on x86-64, `load.sh` checked and loaded the archive, and
   rejected one with a byte appended. arm64 pending with the CI
   archives.

**Changes to the specification at implementation.** S3 adds `gnugrep`.
S5's `revision` label comes from a `gitRevision` argument to
default.nix, which CI passes; a local build has no revision label. S6's
tools come from `grehack2026.publishTools` (skopeo 1.20.0, crane 0.20.6,
from the repository's nixpkgs pin), and skopeo runs with
`--insecure-policy`, since runners need not have a
`/etc/containers/policy.json` and the source is always the archive just
built. S7's round trip is encode → decode → encode: `anomalies.pb` is
authored in prototext, so the check is that the two binaries are the
same.
