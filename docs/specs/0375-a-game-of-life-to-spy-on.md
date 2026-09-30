<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0375 — a game of life to spy on

Status: draft
App: grehack2026 (life-server, life-client, life-spy), nix
Refs: docs/specs/0374-a-workshop-image-for-every-laptop.md (the image
      this ships in, and its size budget);
      docs/specs/0241-a-real-call-leaves-bytes-worth-opening.md (bobapp:
      a tonic app kept out of the Cargo workspace, and a descriptor
      embedded with `include_bytes!`)

## Background

The GreHack 2026 workshop needs a target: a small client-server
application whose traffic the participants capture and take apart with
prototools. This spec is its first version; features come later.

The application is Conway's game of life in a text terminal. The
client draws the grid and takes the user's input, but has no game
logic. The server receives a grid, computes the next generation and
returns it. They talk gRPC over cleartext HTTP/2 (h2c). The grid is
repeated rows of repeated cell states, which are enums. The request also
carries the rule parameters: the birth and survival thresholds.

### What is already true (checked 2026-09-30)

All measured with the pinned nixpkgs (nixos-25.11), inside the spec
0374 image, with a throwaway grpcio echo server and client standing in
for the application.

- **tshark is in the pin:** `wireshark-cli` 4.6.4, with `tshark` and
  `dumpcap`. It adds 53 store paths to the image, 298 MiB uncompressed
  and **71 MiB gzip-compressed**, taking the image from 239 MiB to about
  310 MiB, over spec 0374's 300 MiB target. `wireshark-cli` itself is
  169 MiB of this.
- **tshark decodes h2c gRPC** once told the port is HTTP/2
  (`-d tcp.port==50051,http2`; h2c on a non-standard port is not
  detected on its own). The gRPC dissector strips the 5-byte gRPC
  message prefix, so `grpc.message_data` is the bare protobuf message,
  which `prototext decode --raw` then opens as it is. The request path
  (`/grehack.life.v1.Life/Step`) is in `http2.header.value`, and the
  direction follows from `tcp.dstport`. A packed repeated enum field
  shows under `--raw` as an opaque length-delimited string, which is a
  good first puzzle.
- **A capture started mid-connection does not see gRPC.** HTTP/2
  compresses headers (HPACK) against a table built since the connection
  opened; a late capture lacks it, so `:path` and `content-type` decode
  as `<unknown>`, the DATA frames are not handed to the gRPC dissector,
  and `grpc.message_data` is empty. The `http2_fake_headers` preference
  meant for this did not take effect in a quick attempt (4.6.4, a
  `content-type: application/grpc` entry for port 50051, both
  directions). Hence S4's connection age.
- **Capturing needs root in the container.** The image's user `hacker`
  cannot capture even with `--cap-add NET_RAW --cap-add NET_ADMIN`:
  Docker does not grant ambient capabilities, and a Nix store file
  cannot carry file capabilities. Root with Docker's default
  capabilities can (`NET_RAW` is among them). That root is the
  container's, reached with `docker exec -u 0` and no password; it is
  no step for this audience. Rootless Podman (containers run as the
  user, with container root mapped to the user's own uid) leaves
  `NET_RAW` out of its defaults, so the spy would fail there with a
  permission error unless the container is started with
  `--cap-add NET_RAW`: not yet checked.

## Goals

- **G1.** A playable game of life in a terminal, whose every generation
  crosses the wire as a gRPC request and response.
- **G2.** The wire format gives prototools something to find: nested
  repeated messages, packed repeated enums, and a request mixing the
  grid with scalar parameters.
- **G3.** No server reflection, and no `.proto` in the image. The schema
  is recoverable only from the binaries: each embeds its binary
  FileDescriptorProto, which `protoscan` finds.
- **G4.** A one-command spy that shows the traffic as it happens and
  saves every message as a `.pb` file prototools opens directly.
- **G5.** Everything ships in the spec 0374 image, built by Nix, on
  amd64 and arm64.

## Non-goals

- **N1. TLS.** The traffic must be readable by a passive capture.
- **N2. Streaming RPCs.** One unary call per generation. A streaming
  variant is a candidate later feature.
- **N3. The workshop exercises.** What participants do with the traffic
  is separate work.
- **N4. Client-side game logic,** even as a fallback: the client cannot
  compute a generation.
- **N5. Rules beyond ranges** (arbitrary birth/survival sets such as
  HighLife's B36/S23). A later feature if wanted; S2 leaves room for it.

## Specification

### Layout

- **S1.** The application lives in `grehack2026/life/`: one Cargo
  package with two binaries, `life-server` and `life-client`, its own
  `Cargo.lock`, and an entry in the root manifest's
  `[workspace] exclude`, as `demo/bobapp` has (spec 0241): tonic, hyper
  and tokio must not enter the workspace graph or `depsCache`. The schema
  is `grehack2026/life/proto/grehack/life/v1/life.proto`; the spy is
  `grehack2026/life/life-spy`. Built by a Nix derivation exported as
  `grehack2026.life`.

### The wire

- **S2. The schema.**

  ```proto
  syntax = "proto3";
  package grehack.life.v1;

  enum CellState {
    CELL_STATE_DEAD  = 0;
    CELL_STATE_ALIVE = 1;
  }

  message Row  { repeated CellState cells = 1; }  // packed (proto3)
  message Grid { repeated Row rows = 1; }

  // Inclusive bounds on the number of live neighbors.
  message Range { uint32 min = 1; uint32 max = 2; }

  enum Topology {
    TOPOLOGY_BOUNDED = 0;  // outside the grid is dead
    TOPOLOGY_TORUS   = 1;  // edges wrap
  }

  message Rules {
    Range    birth    = 1;  // a dead cell becomes alive
    Range    survival = 2;  // a live cell stays alive
    Topology topology = 3;
  }

  message StepRequest {
    Grid   grid       = 1;
    Rules  rules      = 2;
    uint64 generation = 3;  // the grid's generation, echoed + 1
  }

  message StepResponse {
    Grid   grid       = 1;
    uint64 generation = 2;
  }

  service Life {
    rpc Step(StepRequest) returns (StepResponse);
  }
  ```

  Conway's rules are birth `[3, 3]`, survival `[2, 3]`. A dead row is
  still on the wire (packed zeros), so every row carries its width.
  Ranges, not sets, because the request is meant to be read by people
  who have no schema: two small integers per rule are easy to spot.

- **S3. The embedded descriptor.** `build.rs` compiles `life.proto`
  (with `tonic-prost-build`, protoc from Nix) and writes the serialized
  `FileDescriptorProto` of `life.proto` alone — not a
  `FileDescriptorSet` — to `OUT_DIR`. Both binaries embed it with
  `include_bytes!` and read it at startup (the server logs the service
  name from it, the client its method path), so the linker keeps it.
  Neither serves reflection. Test: `protoscan` on each binary finds
  exactly one FileDescriptorProto, `grehack/life/v1/life.proto`.

### The server

- **S4.** `life-server [--listen ADDR] [--max-connection-age SECS]`:
  - listens on h2c, default `127.0.0.1:50051`. Each participant runs
    their own server, in their own container: the traffic stays on the
    container's loopback, where the spy captures it;
  - answers `Step` with the next generation under `rules`, and
    `generation + 1`. An absent `rules`, `birth` or `survival` means
    Conway's (birth `[3, 3]`, survival `[2, 3]`), rather than an error:
    a participant crafting requests by hand gets an answer, and the
    default is itself something to discover;
  - rejects with `INVALID_ARGUMENT`: rows of different lengths, a grid
    over 512 × 512 cells, a range with `min > max` or `max > 8`, and an
    unknown enum value in a cell;
  - closes each connection after `--max-connection-age` (default 10 s,
    tonic's `max_connection_age`). The client reconnects on its own, and
    a spy started late has full traffic within 10 s (Background);
  - logs one line per request to stderr: time, peer, grid size,
    generation, and the time spent;
  - on Ctrl-C (SIGINT) or SIGTERM, stops accepting connections, finishes
    the calls in flight and exits 0.

### The client

- **S5.** `life-client [--server URL] [--birth MIN-MAX]
  [--survival MIN-MAX] [--torus] [--pattern NAME] [--size WxH]
  [--steps N]`, with ratatui and crossterm as in protolens:
  - the grid fills the terminal, one cell per two columns (`██`), since
    a character cell is about twice as tall as it is wide; a resize
    keeps the top-left cells and pads or trims the rest;
  - defaults: Conway's rules, bounded topology, 10 generations per
    second (`+`/`-` within 1 to 60), 25 % live cells for a random fill;
  - one call in flight at a time: the next request is sent when the
    response to the previous one has arrived, so the traffic is one
    request, one response, in order;
  - keys: `space` run/pause, `n` one step, `r` random fill, `c` clear,
    `+`/`-` speed, `q` or Ctrl-C quit; a mouse click toggles a cell. In
    raw mode Ctrl-C arrives as a key, not a signal, so the client
    handles it itself, and it restores the terminal on every exit path,
    a panic included;
  - when a call fails, the run pauses and the status line shows the
    error; the next step retries, so a server started after the client
    is picked up;
  - a status line shows the generation, the rules, the speed, the round
    trip time, and the server's last error;
  - `--pattern` starts from a named pattern (at least `glider`,
    `r-pentomino`, `gosper-gun`);
  - `--steps N` runs N generations without the TUI, on a `--size` grid
    (default 40x20), and prints the final generation number and live
    cell count: the scriptable client the smoke test uses.

### The spy

- **S6.** `life-spy [--port N] [--out DIR] [--proto-path DIR] [--stop]`, a bash
  script around `dumpcap` and `tshark`, run as root in the container
  with the application (Background):

  ```sh
  docker exec -it -u 0 workshop life-spy
  ```

  - first prints the exact `dumpcap` and `tshark` command lines it
    runs, ready to copy: the spy is a worked example of driving
    Wireshark's tools on gRPC, not a black box, and participants adapt
    those commands in a terminal of their own;
  - runs one pipeline, `dumpcap -w - | tee DIR/capture.pcapng |
    tshark -l -i - …`, which decodes each message as it crosses the wire
    (about 10 ms after it, measured with the stand-in pair) and saves
    the capture at the same time;
  - captures loopback traffic on the port (default 50051) and prints
    one line per gRPC message: time, `→` request or `←` response, the
    method path when known, the length, and the file it wrote;
  - writes each message's bytes (`grpc.message_data`) to
    `DIR/NNNNNN-request.pb` or `DIR/NNNNNN-response.pb`, where `NNNNNN`
    numbers the call, so a request and its response share it (the call
    is its connection and HTTP/2 stream); a frame holding several
    messages yields several files. The whole capture goes to
    `DIR/capture.pcapng` for Wireshark on the host; `DIR`
    defaults to `/work/capture`, so files land on the laptop, and to
    `./capture` where there is no `/work` (S10). The spy runs as root,
    so it gives every file it writes to the user it works for: the owner
    of `/work` in the image (`stat -c %u:%g /work`; with Docker on
    Linux, root-owned files would otherwise need `sudo` to delete on the
    laptop), `$SUDO_UID:$SUDO_GID` under `sudo`;
  - `--proto-path DIR` adds tshark's protobuf search path, so the
    printed lines show field names — for the participant who has
    rebuilt the `.proto` from the binary (protoscan, then reproto);
  - counts the messages it misses because their connection predates it
    (HTTP/2 DATA frames that tshark could not attribute to gRPC), and
    says so once, rather than dropping them silently: "N messages
    missed: their connection predates the spy; the server renews
    connections every 10 s". It does not decode those frames itself;
  - writes what it prints to `DIR/spy.log` as well, so a detached spy
    can be followed from any terminal (S8);
  - stops on Ctrl-C (in its terminal) or SIGTERM: it ends the pipeline,
    so that `capture.pcapng` is complete, hands its files to the user,
    removes its pid file and exits 0. It writes its pid to
    `DIR/spy.pid`; `life-spy --stop` signals that pid, which is how a
    spy started detached, with no terminal for Ctrl-C, is stopped (S8).

### The image

- **S7.** The spec 0374 image adds `life-server`, `life-client`,
  `life-spy` and `wireshark-cli`, and the image's closure check keeps
  passing. It does not carry `life.proto`, the crate's source or
  anything else naming the schema's fields (G3).
- **S8. One container, several terminals.** Server, client and spy all
  run in the participant's own container, each in its own terminal.
  SETUP.md's run command gains `--name workshop`, so that further
  terminals reach the same container, and `--cap-add NET_RAW`, which
  Docker grants anyway and rootless Podman needs for the spy:

  ```sh
  docker run -it --rm --name workshop --cap-add NET_RAW -e TERM -e COLORTERM \
      -v "$PWD":/work ghcr.io/douzebis/prototools-workshop:grehack2026
                                           # the first terminal: the client
  docker exec -it workshop bash            # a second terminal: the server
  docker exec -it -u 0 workshop life-spy   # a third: the spy
  ```

  Each stops with Ctrl-C in its own terminal.

  The login banner lists these three commands.

  The image also has tmux (built with `withSystemd = false`: 0.9 MiB
  compressed, against 2.5 MiB with systemd's libraries), for
  participants who prefer one window. Its panes run as `hacker` and the
  image has no `sudo`, so the spy cannot be started from a pane; it runs
  detached instead, and a pane follows its log:

  ```sh
  docker exec -d -u 0 workshop life-spy          # from the laptop
  tail -f /work/capture/spy.log                  # in a tmux pane
  docker exec -u 0 workshop life-spy --stop      # from the laptop, to stop it
  ```

  Separate terminals remain the documented way; tmux is the
  alternative the banner mentions.
- **S9. The size budget.** tshark takes the image to about 310 MiB
  compressed. The image's `buf` keeps only `bin/buf`: the two
  `protoc-gen-buf-*` plugins are 72 MiB unpacked, and protolens runs
  only `buf lsp serve`. This applies to the image's lean protolens
  only, as the lean Neovim does (spec 0374 S2); the regular bundle keeps
  `buf` whole. If the image is still over 300 MiB, spec 0374's target
  moves to 350 MiB, with the measurement in both specs.

### Outside the image

- **S10. On a Nix machine, without the image.** The same derivations run
  directly, for the organizers' own testing and demos:
  - `grehack2026.life` holds `life-server`, `life-client` and
    `life-spy`; the spy is wrapped with `wireshark-cli` on its `PATH`, so
    `nix-build -A grehack2026.life` is all it takes. The dev shell
    carries it too;
  - server and client run as the user, on the host's loopback;
  - the spy needs the capture privilege: `sudo life-spy`, or, on NixOS,
    `programs.wireshark.enable = true` with the user in the `wireshark`
    group, which installs a `dumpcap` with capture capabilities at
    `/run/wrappers/bin/dumpcap`. The spy uses that wrapper when it
    exists, and then needs no `sudo`;
  - the spy says which it needs when it can do neither, rather than
    failing on `dumpcap`'s error.

## Alternatives considered

### A gRPC-aware proxy instead of a capture

A relay between client and server (mitmproxy, the unmaintained
`grpc-dump`, or a small Rust relay in this crate) would need no root
and would never miss headers. Rejected for the first version: it
changes the topology the participant is studying (the client must be
pointed at the proxy), mitmproxy adds a Python stack to the image, and
tshark is the tool this audience already knows. A Rust relay mode for
`life-spy` remains a good later feature if root in the container proves
awkward.

### tcpdump in the container, Wireshark on the host

Needs root just the same, and the host Wireshark is not something the
workshop can assume. The spy's `capture.pcapng` keeps this path open
for those who have it.

### A shared server on the event network

One server run by the organizers would put the traffic on each laptop's
network interface rather than loopback, so the spy would need
`--network host` or a capture on the host, and one server's failure
would stop the whole room. Each participant runs their own (S4, S8).

### Server reflection

Would hand the schema to anyone with `grpcurl`, which removes the
exercise. The embedded descriptor (S3) is the intended way in.

## Test plan

1. `protoscan` on `life-server` and on `life-client` finds
   `grehack/life/v1/life.proto`, and the recovered descriptor is equal
   to the one built from `life.proto`.
2. A server unit test for each rule and topology: a blinker oscillates,
   a block is stable, a glider on a square torus of side w returns to
   its start after 4w generations; each rejection case of S4 gets its
   error; a request without `rules` is answered under Conway's.
3. In the image, as a new check in `grehack2026/smoke-test.sh`, so CI
   runs it on both architectures: `life-server &`, the spy as root
   (`--user 0`) with `--out /tmp/cap &`, then `life-client --steps N`.
   `/tmp/cap` holds requests and responses numbered 1 to N in pairs,
   `prototext decode --raw` opens each, and `life-spy --stop` leaves a
   complete `capture.pcapng` that tshark reads without error.
4. The late spy: start the spy after the client has run for 20 s; within
   `--max-connection-age` it prints method paths and writes files, and
   it has reported the messages it missed before that.
5. `--proto-path` with the `.proto` that reproto rebuilds from the
   protoscan output: tshark shows the field names.
6. `grpcurl -plaintext localhost:50051 list` fails (no reflection).
7. The image's size, compressed, per architecture, against S9; the
   image's `buf` has no `protoc-gen-buf-*`, and protolens's editor path
   (spec 0374's smoke test) still passes.
8. The image holds no `life.proto` and no file naming a schema field
   (`grep -r CellState` over the image's `/nix/store` finds only the
   two binaries).
9. Files the spy writes to `/work/capture` are owned by the owner of
   `/work`.
   The command lines the spy prints at start, run by hand in a root
   terminal, produce the same message list.
10. Manual, before the workshop: client, server and spy, each in its own
    terminal, on Linux x86-64 (Docker), macOS arm64 (Colima), and
    rootless Podman with `--cap-add NET_RAW` (and without it, to confirm
    the spy's error is clear).
    Once more with tmux: server and client in panes, the spy detached,
    its log followed in a third pane.
11. On the NixOS development VM, outside the image (S10): the spy under
    `sudo`, writing to `./capture` files owned by the user; and, with
    `programs.wireshark.enable`, without `sudo`.

## Measured outcome

Filled in at implementation.
