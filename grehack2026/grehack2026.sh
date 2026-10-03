# SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
#
# SPDX-License-Identifier: MIT

clear && header "0. The cast"

# \
# This is Alice's control tower. Most of the analysis runs here; when          \
# something must happen on another terminal, this window says so.              \

# \
# The subject is dissecting protobuf — the serialization format behind         \
# gRPC and the bulk of data exchange in GCP-style infrastructure. It is        \
# everywhere, and on the wire it is opaque.                                    \

# \
# Three people:                                                                \
# - Bob 🙂  the player. He runs the Game of Life client and thinks he is       \
#   just playing.                                                              \
# - Eve 👩  the server administrator. Her server plays Life with Bob's         \
#   client. Keep an eye on her.                                                \
# - Alice 🕵️  the investigator. She has a network capture and the client       \
#   binary, nothing else.                                                      \

# \
# Goal: take an unknown protobuf stream and, with no help from either          \
# endpoint, work out its structure, read it, then notice what it is not        \
# telling us.                                                                  \


clear && header "1. Reading the wire"

# \
# Eve's server (terminal 1) and Bob's client (terminal 2) are both             \
# running. On screen it is an ordinary Game of Life: the grid steps,           \
# nothing looks amiss. Alice wants to see what goes over the wire.             \

# 👉 Terminal 3 — Alice launches the network tap:
#        life-spy
#    It captures the gRPC frames into capture/.

# Look at one captured request as raw bytes:
hexdump -v -C capture/000050-request.pb
# \
# Quite opaque. Protobuf is self-describing only up to field numbers and       \
# wire types; to read values we need the schema — a descriptor set and a       \
# root type.                                                                   \

# \
# Where would a schema come from? The client binary carries its own. Our       \
# first prototool, protoscan, scans any blob for embedded descriptors:         \

protoscan life-client
# \
# There they are: protoscan found the FileDescriptorProtos embedded in         \
# the client (here grehack/life/v1/life.proto). With --proto_out DIR it        \
# would extract them to disk.                                                  \

# \
# Let's process those descriptors with our second prototool, reproto, so       \
# we can read them in the clear and enable type inference:                     \

reproto --use-variant descriptor -I life-client --schema-db-out life.desc


clear && header "1b. What reproto produced"

# \
# reproto does not just repack the descriptors — it extracts, indexes,         \
# and decompiles them. Let's see what it wrote beside life.desc:               \

ls -lhd life.desc life/* \
# reproto delivered 💪:                                                        \
# - life.desc:          the extracted descriptor set (the reusable schema DB)  \
# - life/hopcroft.rkyv: the type-inference scoring graph                       \
# - life/proto/:        all decompiled .proto source files                     \
# - life/index.rkyv:    the fast-access index                                  \

# Browse one decompiled .proto — it reads like hand-written source:
view life/proto/grehack/life/v1/life.proto
# \
# A faithful .proto rebuilt from binary FileDescriptorProtos — messages,       \
# enums, fields, nesting, packages — with no access to the original            \
# source. --use-variant descriptor substituted the toolchain's own copy        \
# of the well-known descriptor.proto, so the imports resolve cleanly.          \

# \
# Now that we have a corpus, our third prototool, prototext, can infer         \
# the type of a capture by scoring it against the DB:                          \

prototext --descriptor-set life.desc list-schemas capture/000050-response.pb

# \
# Let's decode a capture. First the baseline tool, protoc — it works, but      \
# it is spartan:                                                               \

protoc --descriptor_set_in=life.desc \
       --decode=grehack.life.v1.StepRequest < capture/000050-request.pb \
  | view_textproto

# \
# Then the better view: our fourth prototool, protolens — more                 \
# convenient, and it shows wire-level detail, scoring, and navigation:         \

protolens --descriptor-set life.desc capture/000050-response.pb \
  --script beats/capture


clear && header "2. Smuggled traffic — Eve is spying"

# \
# Claim: Eve's server is not an innocent Life server — it is exfiltrating      \
# from Bob's client. And the covert channel runs the opposite way to what      \
# you would expect: the server drives it.                                      \

# 👉 Terminal 1 — Eve types a command on her server's stdin:
#        whoami
#    A few Life steps later, the answer — run on Bob's machine — surfaces
#    on Eve's terminal.

# \
#    Eve 😈  ──  "whoami"      (hidden in the responses)   ──▶  Bob 🙂         \
#    Eve 😈  ◀──  "experiment"  (hidden in the requests)    ──   Bob 🙂        \
#    Every Life message carries one smuggled fragment, without changing        \
#    the decoded grid.                                                         \

# Alice takes a fresh capture and decodes it with protoc → nothing surfaces:
protoc --descriptor_set_in=life.desc \
       --decode=grehack.life.v1.StepRequest < capture/000100-request.pb \
  | view_textproto
# \
# A perfectly ordinary message. The smuggled payload is value-preserving,      \
# so a schema-faithful decode shows nothing.                                   \

# Now look again with protolens — the anomalies show up:
protolens --descriptor-set life.desc capture/000100-request.pb \
  --script beats/smuggle
# \
# protolens flags the fields that do not sit the way the schema expects.       \
# At wire level: a VARINT is base-128, little-endian groups, high bit = a      \
# continuation. The trick is a spurious continuation bit — one hidden bit      \
# per field, with the decoded value unchanged.                                 \

# \
# Reading the pattern across fields reconstructs the hidden bits into          \
# bytes, and the bytes map to lowercase ASCII:                                 \

# \
#   01100101 01111000 01110000 01100101 01110010 01101001 ...                  \
#      e        x        p        e        r        i      → experiment        \
#   01110111 01101000 01101111 01100001 01101101 01101001                      \
#      w        h        o        a        m        i      → whoami            \

# \
# The channel is legible end to end: Eve asked "whoami", Bob's machine         \
# answered "experiment". We understand the mechanism and can read both         \
# directions.                                                                  \


clear && header "2b. Jump to the definition — v in protolens"

# \
# Still inside protolens, move the cursor onto a field whose type is a         \
# named message or enum, and press v.                                          \

protolens --descriptor-set life.desc capture/000050-response.pb \
  --script beats/jump
# \
# protolens hands off to Neovim, opened at that type's declaration in the      \
# reconstructed .proto source — made possible by the SourceCodeInfo            \
# reproto synthesized and the proto/ stub it resolves against.                 \

# \
# Schema recovery is not just a flat type list: we navigate from a byte on     \
# the wire to the exact line of reconstructed source that defines it, and      \
# back.                                                                        \


clear && header "3. When the descriptor DB is incomplete"

# \
# Eve's server also keeps a log. 👉 Terminal 1 — she runs it with a log        \
# file; after a while she stops it with Ctrl-C:                                \
#        life-server --log-file server.log                                     \

# \
# The log is itself a protobuf, written in chunks that always stop             \
# mid-field — a deliberately truncated blob. The log's own type is not in      \
# the client, and the server was built without embedding its descriptor.       \
# So we are in the realistic position of a blob with no schema for it.         \

# protoc --decode_raw chokes on it: the file is truncated.
protoc --decode_raw < server.log

# \
# protolens with only the client-derived DB opens it anyway — but no known     \
# root type matches:                                                           \

protolens --descriptor-set life.desc server.log \
  --script beats/logfile
# \
# The heat cues still recognize the Request and Response substructures         \
# from their field shapes, and the override feature lets us pin those          \
# types and reconstruct the record — truncated tail and no root type and       \
# all. Request and Response are shaped differently enough that the scoring     \
# does not confuse the two.                                                    \


clear && header "4. Bonus — the anomaly taxonomy"

# \
# Not every protobuf anomaly is accidental. Some are fingerprints, some        \
# are covert channels, some hide data below the application layer.             \
# protolens detects and annotates every category. The full vocabulary:         \

protolens --type google.protobuf.FileDescriptorSet \
          ../grpconf2026/anomalies.pb


clear && header "5. Three takeaways"

# \
# 1. Descriptors are usually hiding in the binary itself. You rarely have      \
#    to guess a schema — protoscan finds them and reproto gives you the        \
#    .proto back.                                                              \

# \
# 2. A corpus can type a message it has never seen, piece by piece,            \
#    because that message is built out of messages it does know. That is       \
#    what protolens's heat cues are for.                                       \

# \
# 3. What your decoder normalizes away is evidence — a shadowed value, a       \
#    spurious continuation bit, a truncated tail. prototools surfaces it,      \
#    all the way back to the original bytes.                                   \


# https://github.com/ThalesGroup/prototools — pull requests welcome 🙂

# Thank you 👋
