<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# GreHack 2026 — demo synopsis

Running order for the live demo that follows the talk: what happens on screen, in which window, and the point each step makes. The teleprompt deck `grehack2026.sh` is the source of truth; this file follows it section by section. If the two disagree, the deck wins and this file is out of date.

The demo app is the crate in `game/`: a Game of Life client and server talking cleartext gRPC (`life-client`, `life-server`), plus a network tap (`life-tap`). The tools under the lens are `protoscan`, `reproto`, `prototext` and `protolens`.

## Setup

Three windows, all opened beforehand and already inside the repository's dev-shell (`nix-shell dev-shell.nix`), which puts the three `life-*` binaries and the prototools on the PATH:

| Window | Directory | Runs |
|---|---|---|
| Eve 👩 | `grehack2026/eve/` | `life-server`; its stdout shows what Eve's covert channel brings back |
| Bob 🙂 | `grehack2026/bob/` | `life-client`, the Game of Life TUI |
| Alice 🕵️ | `grehack2026/` | `teleprompt grehack2026.sh`, the control tower |

The shell prompt names each window's directory, which tells the audience whose window is whose.

The deck runs in Alice's window. The `#` lines are on-screen narration: teleprompt shows them in blue, and the audience reads them. Real commands run as written. Lines starting with 👉 say what to do in another window, with the exact keys or command. `header "…"` draws section banners, `view` / `view_textproto` page a file or a decoded protobuf, and `protolens --script beats/<name>` loads a reminder pane for the presenter. Those reminder panes do not drive protolens; the presenter quits it with `:q`.

`grehack2026.init` runs when teleprompt starts:
- It wipes what earlier runs generated: `capture/`, `life.desc`, `life/` and `eve/server.log`.
- It copies the client binary to `grehack2026/life-client`, which is "the client binary Alice has". On a Nix PATH, `life-client` is a wrapper script, and the copy is the real binary behind it.

The tap runs in Alice's window, in the foreground, as `sudo env PATH="$PATH" life-tap`. `sudo` asks for the password on stage. The tap prints one line per message, saves each message as `capture/NNNNNN-request.pb` / `-response.pb`, and stops on Ctrl-C. While it runs the deck waits, so the 👉 hints for the other windows come right before it.

Every capture starts the same way. Bob pauses the game (Space), the deck runs `rm -rf capture` and starts the tap, and Bob then plays single steps with `n`. A capture therefore always starts at `000001`, and the deck can name its files in advance. The two-second wait before the first `n` makes sure the client opens a new connection, which the tap sees from the start (`life-client --renew-every`, 2 s by default).

## Why prototools

- At S3NS we operate a Trusted Partner Cloud. Google ships us software update packages, and we audit each one before it reaches production.
- Inside them, protobuf is everywhere: it is how Google's infrastructure serializes configuration, RPCs, logs and stored data. On the wire it is opaque.
- So we built prototools, to dissect protobufs even when nobody hands us the schema. The demo is a made-up investigation; the tools and their features are real.

## 0. The cast

- **Bob** 🙂 plays the Game of Life, and **Eve** 👩 runs the server that computes each generation. In their windows, Eve starts `life-server` and Bob starts `life-client`. A diagram shows the two exchanging `StepRequest` / `StepResponse` over cleartext gRPC.
- **Alice** 🕵️ taps the wire between them. She has the capture and the client binary, nothing else. A second diagram adds her window, where `life-tap` feeds `capture/*.pb` to prototools.
- Goal: take an unknown protobuf stream and, with no help from either endpoint, work out its structure, read it, then notice what it is not telling us.

## 1. On the wire

- Capture: Bob pauses, the tap starts, Bob presses `n` three times, Ctrl-C stops the tap, and Bob resumes the game.
- `hexdump -v -C capture/000001-request.pb`: opaque. Protobuf is self-describing only up to field numbers and wire types; reading values needs a schema, that is, a descriptor set and a root type.
- `protoscan life-client`: the client carries its own schema. protoscan lists the embedded `FileDescriptorProto`s: the game's `grehack/life/v1/life.proto`, and the well-known `google/protobuf/descriptor.proto`. `--proto_out DIR` would extract them.
- `reproto -I life-client --schema-db-out life.desc` turns those descriptors into a schema database. reproto needs `descriptor.proto` in its input set, and the client carries it, so no `--use-variant` is needed.

## 1b. Schema DB

- `ls -lhd life.desc life/*`:
  - `life.desc` is the descriptor set, the reusable schema DB;
  - `life/hopcroft.rkyv` is the type-inference scoring graph;
  - `life/proto/` holds the decompiled `.proto` sources;
  - `life/index.rkyv` is the fast-access index.
- `view life/proto/grehack/life/v1/life.proto`: a faithful `.proto` rebuilt from binary descriptors, with no access to the source. Everything reproto needed came from the binary.
- `prototext --descriptor-set life.desc list-schemas capture/000001-response.pb` infers the capture's type by scoring it against the DB.
- `protoc --decode=grehack.life.v1.StepRequest` on `000001-request.pb` works, but it is spartan.
- `protolens --descriptor-set life.desc capture/000001-response.pb --script beats/capture` gives the better view: annotations, the inferred type, and the wire level one keystroke (`w`) away. On a field whose type is a named message or enum, `v` opens Neovim at that type's declaration in the reconstructed `.proto`. This works because of the `SourceCodeInfo` reproto synthesized, and the `life/proto/` stub beside `life.desc`. Schema recovery is not just a list of types: we go from a byte on the wire to the line of source that defines it, and back.

## 2. Eve is spying

- Claim: Eve's server is exfiltrating from Bob's client, and the server drives the channel. A whole command rides in one response, and the whole answer comes back in a later request; neither changes the decoded grid.
- Capture:
  1. Bob pauses, and the tap starts.
  2. In her window, Eve types `whoami`. The server sends it once, in the next response.
  3. Bob presses `n`: `000001-response.pb` carries `whoami`, and the client runs it.
  4. Bob presses `n` again: `000002-request.pb` carries the output, which then shows up in Eve's window.
  5. Ctrl-C stops the tap, and Bob resumes the game.
- `protoc --decode` on `000002-request.pb` shows a perfectly ordinary message: the channel preserves every value, so a decode that follows the schema shows nothing.
- `protolens … capture/000002-request.pb --script beats/smuggle` flags the fields that do not sit the way the schema expects. At wire level (`w`), a VARINT is base-128, in little-endian 7-bit groups, and the high bit of each byte means "another byte follows". The trick is a spurious continuation byte: one hidden bit per field, with the value unchanged.
- Read across the fields, the bits group into bytes, and the bytes are ASCII. The request gives `experiment` (the client trims the output's ends, so no newline), and the response gives `whoami`. The deck and the beat show the bit table.

## 3. No schema

- Eve's server has been writing `eve/server.log` since she started it (`life-server` logs to `server.log` by default; `--no-log` turns that off). The deck does not say what the file is: the audience finds out.
- `ls -lh eve/server.log`, then `protoc --decode_raw < eve/server.log`: protoc gives up on the whole file.
- `protolens --descriptor-set life.desc eve/server.log --script beats/logfile` opens it, but no known root type matches, and the tail is flagged as truncated. That is the reveal: a protobuf after all, Eve's traffic log, cut off mid-field (by construction, spec 0386). Its type is not in the client, and the server does not embed its descriptor.
- Every entry is the same field (42) and has the same shape: a `Capture` (spec 0391), one per message the server saw. Its type is in no schema we hold, but the heat cues recognize the game's own `StepRequest` or `StepResponse` inside each entry, and overrides pin those types to rebuild the record, truncated tail and all.
- One field of each entry, 666, is a string no schema we hold declares. Where it is set, it reads `whoami` (in the entry of the response that smuggled it) or `experiment` (in the entry of the request that brought it back): Eve's log records her own contraband.

## 4. Anomalies

- `protolens --type google.protobuf.FileDescriptorSet anomalies.pb --script beats/anomalies` walks through one example of every encoding anomaly prototext reports, from bytes every parser accepts to bytes none can read.
- `anomalies.pb` and `beats/anomalies` are copies of `grpconf2026/anomalies.pb` and `grpconf2026/anomalies.script`, kept here so the demo stands alone. The root type is `FileDescriptorSet`. The dev-shell's `PROTOTEXT_DESCRIPTOR_SET` supplies the well-known types.

## 5. Takeaways

1. Descriptors are usually hiding in the binary itself: protoscan finds them, and reproto gives the `.proto` back.
2. A corpus can type a message it has never seen, piece by piece, because that message is built from messages it does know. That is what protolens's heat cues are for.
3. What your decoder normalizes away is evidence: a shadowed value, a spurious continuation bit, a truncated tail. prototools surfaces it, all the way back to the original bytes.

Then a pointer to <https://github.com/ThalesGroup/prototools>.

## Specs behind the demo

- `docs/specs/0375-a-game-of-life-to-spy-on.md`: the client, the server, and the tap (then called `life-spy`).
- `docs/specs/0381-a-step-survives-the-connection-renewal.md`: connection renewal, and why a tap started late misses traffic.
- `docs/specs/0384-smuggle-through-plain-varint-fields.md`: the covert channel rides plain VARINT values.
- `docs/specs/0385-the-smuggled-payload-is-exactly-the-bytes.md`: the command and its output, exactly, with no prefix or special number.
- `docs/specs/0386-the-server-writes-a-truncated-protobuf-log.md`: the server's traffic log (on by default since spec 0388 S14).
- `docs/specs/0387-a-request-and-a-response-score-apart.md`: the log's two old entry types, replaced by spec 0391.
- `docs/specs/0388-the-demo-runs-from-grehack2026.md`: this layout, the tap's rename, and the fixed captures.
- `docs/specs/0391-every-log-entry-is-a-capture.md`: one log entry type, `Capture`, with the contraband field.
