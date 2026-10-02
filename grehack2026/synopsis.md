<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# GreHack 2026 — demo synopsis

Status: draft

Running order for the live demo that follows the talk. Each step is what the presenter does on screen and the point it makes. Commands are the real invocations; a few depend on changes not yet made, flagged inline as **CHANGE-REQ-n** and collected at the end.

The demo app is `grehack2026/life`: a Game of Life client and server talking cleartext gRPC, with a network tap (`life-spy`). The tools under the lens are `prototext`, `protoscan`, `reproto`, and `protolens`.

Paths below assume the capture directory is `capture/` and the reconstructed schema database is `life.desc` (with its `life/` stub beside it). Adjust to the workshop layout as needed.

## Terminal layout

The demo drives four terminals:

1. **Eve's server** 👩 — `life-server` runs here; the audience watches its stdout/stderr (later, what it quietly reveals, and the log file it writes).
2. **Bob's client** 🙂 — `life-client` runs here; the Game of Life TUI.
3. **Spy** — `life-spy` runs here, capturing the gRPC frames to `capture/`. This is Alice's tap.
4. **Alice's teleprompt (control tower)** 🕵️ — a `teleprompt`-driven window where most of the analysis commands are pre-provisioned. It paces the demo, shows section headers, and whenever something must be done in terminal 1, 2, or 3 it displays the hint for that action. All `prototext` / `protoscan` / `reproto` / `protolens` commands below run here unless a step says otherwise.

The teleprompt window follows the `grpconf2026/` conventions (see `grpconf2026/grpconf2026-20min.sh`): the pre-provisioned script is a bash script that `teleprompt` steps through; real commands run as written. The `#`-comment lines are **on-screen narration** — teleprompt displays them in blue, in the same window, so they are part of what the audience sees, not off-screen speaker notes. They are `\`-continued into blocks whose trailing `\` lands at display column 80. `teleprompt` supplies the built-in helpers used below — `header "…"` for section banners, and `view` / `view_textproto` for paging a file or a decoded protobuf. `protolens` steps can be scripted through `beats/<name>` files loaded with `--script`. As in the grpconf talk, downloaded inputs live under one directory and reconstructed artifacts under another, the latter wiped and repopulated by the demo's `.init`; name them to taste for the workshop (e.g. `capture/` for the spy's output, `life/` for the reproto stub).

---

## 0. Intro

- The subject is **dissecting protobuf** — the serialization format behind gRPC and the bulk of message/data-structure exchange in GCP-style infrastructure. It is everywhere, and on the wire it is opaque.
- Goal of the demo: take an unknown protobuf stream and, with no cooperation from the endpoints, work out its structure, read it, and then notice what it is *not* telling us.

### Cast

- **Bob** 🙂 — the player. He runs the Game of Life client and thinks he is just playing.
- **Eve** 👩 — the server administrator. Her server plays Life with Bob's client. (Keep an eye on her.)
- **Alice** 🕵️ — the investigator. She has a network capture and the client binary, nothing else, and uses prototools to reconstruct what is really going on.

### The setup

Bob's client and Eve's server exchange Life steps over cleartext gRPC. Alice sits on the wire with a tap and reconstructs the traffic — she never touches either endpoint:

```
        ┌─────────────┐   StepRequest  / StepResponse   ┌─────────────┐
        │   Bob 🙂    │ ───────────────────────────────▶ │   Eve 👩    │
        │  life-client│ ◀─────────────────────────────── │  life-server│
        └─────────────┘         cleartext gRPC           └─────────────┘
                 │                                               
                 │  frames mirrored to the tap                  
                 ▼                                               
          ┌─────────────┐        capture/*.pb        ┌──────────────┐
          │  life-spy    │ ─────────────────────────▶ │  Alice 🕵️    │
          │ (the tap)    │                            │  prototools  │
          └─────────────┘                             └──────────────┘
```

So far, so ordinary: a game and someone watching the wire. Whether there is anything more to it is exactly what Alice is about to find out (step 2).

## 1. Normal situation — reading the wire

- Eve's server (terminal 1) and Bob's client (terminal 2) are both running. On screen it is an ordinary Game of Life: the grid steps, nothing looks amiss.
- Alice wants to see what actually goes over the wire.
- Launch the network tap (terminal 3):

  ```sh
  life-spy            # captures the gRPC frames into capture/
  ```

- Look at one captured request as raw bytes (terminal 4):

  ```sh
  hexdump -v -C capture/000050-request.pb
  ```

  → quite opaque. Protobuf is self-describing only up to field numbers and wire types; to read values we need the **schema** — a descriptor set and a root **type**.
- Where would a schema come from? The client binary carries its own. Scan for embedded `FileDescriptorProto` blobs:

  ```sh
  protoscan life-client            # lists the FDPs discovered in the binary
  ```

  → with no option, `protoscan` just lists the embedded `FileDescriptorProto`s it finds (here `grehack/life/v1/life.proto`); `--proto_out DIR` would extract them to disk. So there are FDPs in the client.
- Extract them and build a schema database:

  ```sh
  reproto --use-variant descriptor -I life-client --schema-db-out life.desc
  ```

  (`-I`/`--desc-root` reads the binary as a blob of embedded descriptors; `--schema-db-out` writes the reusable DB and its `life/` proto stub.)

## 1b. What reproto produced — schema recovery

- Look at what `reproto` wrote beside `life.desc`. It does not just repack the descriptors, it **extracts, indexes, and decompiles** them — as the grpconf talk puts it. List the artifacts:

  ```sh
  ls -lhd life.desc life/*
  # life.desc:          the extracted descriptor set (the reusable schema DB)
  # life/hopcroft.rkyv: the type-inference scoring graph
  # life/proto/:        all decompiled .proto source files
  # life/index.rkyv:    the fast-access index
  ```

- Browse one decompiled `.proto` to show it reads like hand-written source:

  ```sh
  view life/proto/grehack/life/v1/life.proto
  ```

- Point out reproto's capabilities on screen:
  - a faithful `.proto` rebuilt from binary `FileDescriptorProto`s — messages, enums, fields, nesting, packages — with no access to the original source;
  - `--use-variant descriptor` substitutes the toolchain's own copy of the well-known `descriptor.proto` for whatever the binary embedded, so the imports resolve cleanly;
  - the `hopcroft.rkyv` scoring graph is what lets `prototext`/`protolens` **infer** a blob's type against this DB (steps below);
  - synthesized `SourceCodeInfo` (on by default for `--schema-db-out`), which is what later lets `protolens` jump straight to a type's declaration (see step 2b);
  - the output doubles as a reusable **schema database** (`life.desc`) that every other tool here consumes.

- Find the type of a capture by scoring it against the DB:

  ```sh
  prototext --descriptor-set life.desc list-schemas capture/000050-response.pb
  ```

- Decode it. First the baseline tool, to show it works but is spartan:

  ```sh
  protoc --descriptor_set_in=life.desc \
         --decode=grehack.life.v1.StepRequest < capture/000050-request.pb \
    | view_textproto
  ```

- Then the better view — more convenient, and it shows more (wire-level detail, scoring, navigation):

  ```sh
  protolens --descriptor-set life.desc capture/000050-response.pb
  ```

## 2. Smuggled traffic — Eve is spying

- Claim: Eve's server is not an innocent Life server — it is exfiltrating from Bob's client. Demonstrate the capability: Eve types a command on her server, and the answer surfaces on her terminal (terminal 1) a few Life steps later, having been run on Bob's machine.

  ```sh
  whoami            # Eve smuggles this to Bob; Bob's answer `experiment` comes back
  ```

- The reveal: Eve 😈 is not just running a game server — she hides a second conversation inside the ordinary-looking Life messages, and it runs the *opposite* way to what you would expect — the server drives it:

  ```
     Eve 😈  ──  "whoami"  (hidden in the response tags)   ──▶  Bob 🙂
     Eve 😈  ◀──  "experiment"  (hidden in the request tags) ──  Bob 🙂
              every Life message carries one smuggled fragment,
              steganographically, without changing the decoded grid
  ```

- Alice takes a fresh capture and looks at it with `protoc` → nothing surfaces: the smuggled payload is value-preserving, so a schema-faithful decode shows a perfectly ordinary message.
- She looks again with `protolens` → **anomalies** show up: the rendering flags fields that do not sit the way the schema expects.
- Zoom into an anomaly with `w` (wire level):
  - explain what a **VARINT** is (base-128, little-endian groups, high bit = continuation);
  - explain the **spurious continuation bit** — the trick that hides a bit per field without changing the decoded value.
  - **CHANGE-REQ-1** — explaining the channel is hard because tags are hybrid (field number + wire type packed together). It would read far more simply if the smuggled bits rode **plain VARINT fields** rather than tags.
- Alice reads the anomaly pattern across fields, reconstructs the hidden bits into bytes, and maps the bytes to ASCII. The smuggled text is lowercase ASCII, so this short table is enough on screen to turn bytes into letters:

  ```
  char  hex  dec  binary        char  hex  dec  binary        char  hex  dec  binary
   a    61    97  01100001       j    6a   106  01101010       s    73   115  01110011
   b    62    98  01100010       k    6b   107  01101011       t    74   116  01110100
   c    63    99  01100011       l    6c   108  01101100       u    75   117  01110101
   d    64   100  01100100       m    6d   109  01101101       v    76   118  01110110
   e    65   101  01100101       n    6e   110  01101110       w    77   119  01110111
   f    66   102  01100110       o    6f   111  01101111       x    78   120  01111000
   g    67   103  01100111       p    70   112  01110000       y    79   121  01111001
   h    68   104  01101000       q    71   113  01110001       z    7a   122  01111010
   i    69   105  01101001       r    72   114  01110010
  ```

  Worked example — the request-side fragment decodes byte by byte to `experiment`:

  ```
  01100101 01111000 01110000 01100101 01110010 01101001 01101101 01100101 01101110 01110100
     e        x        p        e        r        i        m        e        n        t
  ```

  and the response-side fragment to `whoami`:

  ```
  01110111 01101000 01101111 01100001 01101101 01101001
     w        h        o        a        m        i
  ```

  The covert channel is now legible end to end: Eve asked `whoami`, Bob's machine answered `experiment`.
  - **CHANGE-REQ-2** — the response-side smuggled message is currently prefixed with `fortune ` (and `42` is a factorize special case). Both are demo noise: drop the `fortune ` prefix and remove the `42`/factorize special case so the reconstructed bytes are exactly the payload.
- Conclusion of the step: we understand the mechanism and can read both directions.

## 2b. Jump to the definition — `v` in protolens

- Still inside `protolens`, move the cursor onto a field whose type is a named message or enum, and press **`v`**.
- `protolens` hands off to Neovim opened at that type's **declaration** in the reconstructed `.proto` source — made possible by the `SourceCodeInfo` reproto synthesized (step 1b) and the `proto/` stub it resolves against (`--proto-root`, or the `<stub>/proto/` beside `--descriptor-set`).
- The point: schema recovery is not just a flat type list — we can navigate from a byte on the wire to the exact line of (reconstructed) source that defines it, and back.

## 3. When we do not have a complete descriptor database

- **CHANGE-REQ-3** — give the server a `--log-file` option. The log is itself a protobuf: a message with `repeated Request` and `repeated Response` fields. Write it in chunks that always **stop mid-field** (a deliberately truncated protobuf), and arrange that:
  - the client does **not** have the descriptor for the log type, and
  - the server is compiled **without** embedding its FDPs,
  so the audience is in the realistic position of having a blob and no schema for it.
- See that the server (terminal 1) produces a log file → what is it?
- `protoc --decode_raw` chokes on it:

  ```sh
  protoc --decode_raw < server.log        # fails: the file is truncated
  ```

- `protolens` with only the client-derived DB opens it, but no known type matches:

  ```sh
  protolens --descriptor-set life.desc server.log
  ```

- Show the **heat cues** feature → `protolens` still recognizes the `Request` and `Response` substructures from their field shapes, and the **override** feature lets us pin those types and reconstruct the record even with a truncated tail and no matching root type.
  - **CHANGE-REQ-4** — make `Request` and `Response` different enough that the scoring does not confuse the two.

## 4. Bonus — the anomaly taxonomy

- Show, quickly, the full taxonomy of anomalies `protolens` can surface:

  ```sh
  protolens --type google.protobuf.FileDescriptorSet \
            ../../grpconf2026/anomalies.pb
  ```

## 5. Conclusion

- Recap the arc: opaque bytes → schema recovered from the binary → read the wire → spot and reconstruct the covert channel → cope with no schema at all via heat cues and overrides.
- Point to the tools on GitHub: the **ThalesGroup** prototools repository.

---

## Pending changes to the demo (CHANGE-REQ)

- **CHANGE-REQ-1** — smuggle through plain VARINT fields instead of tags, so the wire-level explanation is simpler.
- **CHANGE-REQ-2** — drop the `fortune ` prefix on the response-side smuggled message and remove the `42`/factorize special case.
- **CHANGE-REQ-3** — add `life-server --log-file`: a protobuf log of `repeated Request`/`repeated Response`, written in chunks that stop mid-field; the log type's descriptor is absent from the client and the server is built without embedding its FDPs.
- **CHANGE-REQ-4** — make `Request` and `Response` distinct enough that `protolens` scoring does not confuse them.
