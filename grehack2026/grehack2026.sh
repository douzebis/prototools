clear && header "Why prototools"

# \
# At S3NS we operate a Trusted Partner Cloud (TPC). Google ships us its        \
# software update packages, and before any of them reaches production we       \
# audit it, to make sure it does nothing it should not.                        \

# \
# Inside those packages, protobuf is everywhere: it is the data                \
# serialization format of the Google infrastructure — configuration,           \
# RPCs, logs, stored data. And on the wire, protobuf is opaque.                \

# \
# So we built prototools: a suite of tools to dissect protobufs, even          \
# when nobody hands us the schema.                                             \

# \
# What follows is a demo of prototools, told as a toy cyber-investigation.     \
# The scenario is made up; the tools and their features are real.              \


clear && header "0. The cast"

# \
# Meet Bob 🙂, the player. He runs a Game of Life client and thinks he         \
# is just playing.                                                             \

# \
# Meet Eve 👩, the server administrator. Her server computes each Life         \
# generation for Bob's client. Keep an eye on her.                             \

# \
#    ┌──────────────┐        StepRequest         ┌──────────────┐              \
#    │     Bob      │ ─────────────────────────▶ │     Eve      │              \
#    │ life-client  │ ◀───────────────────────── │ life-server  │              \
#    └──────────────┘        StepResponse        └──────────────┘              \
#                           cleartext gRPC                                     \

# \
# 👉 Eve's window (eve/) — Eve starts her server:                              \
#        life-server                                                           \
# 👉 Bob's window (bob/) — Bob starts his client:                              \
#        life-client                                                           \

# \
# On screen it is an ordinary Game of Life: the grid steps, nothing looks      \
# amiss.                                                                       \

# \
# Now meet Alice 🕵️, the investigator. She taps the wire between Bob and       \
# Eve. She has the network capture and the client binary, nothing else —       \
# no help from either endpoint.                                                \

# \
#    ┌──────────────┐        StepRequest         ┌──────────────┐              \
#    │     Bob      │ ───────────┬─────────────▶ │     Eve      │              \
#    │ life-client  │ ◀──────────┼────────────── │ life-server  │              \
#    └──────────────┘            │ StepResponse  └──────────────┘              \
#                                ▼                                             \
#              ┌───────────────────────────────────────────────┐               \
#              │ Alice — this window                           │               \
#              │   life-tap ──▶ capture/*.pb ──▶ prototools    │               \
#              └───────────────────────────────────────────────┘               \

# \
# This window is Alice's control tower. The analysis runs here; when           \
# something must happen in Eve's or Bob's window, this window says so,         \
# with the exact keys or command to type.                                      \

# \
# Goal: take an unknown protobuf stream and, with no help from either          \
# endpoint, work out its structure, read it, then notice what it is not        \
# telling us.                                                                  \


clear && header "1. On the wire"

# \
# Alice starts her tap. It needs root, so she types her password; it then      \
# prints one line per message, and saves each message in capture/.             \

# \
# 👉 Bob's window — Space pauses the game.                                     \
# 👉 Here — the next two commands start the tap on an empty capture/.          \
# 👉 Bob's window — wait two seconds, then press n three times: three          \
#    Life steps, one at a time, each a request and a response.                 \
# 👉 Here — Ctrl-C stops the tap.                                              \
# 👉 Bob's window — Space sets the game running again.                         \

rm -rf capture
sudo env PATH="$PATH" life-tap

# Look at the first captured request as raw bytes:
hexdump -v -C capture/000001-request.pb
# \
# Quite opaque. Protobuf is self-describing only up to field numbers and       \
# wire types; to read values we need the schema — a descriptor set and a       \
# root type.                                                                   \

# \
# Where would a schema come from? The client binary carries its own. Our       \
# first prototool, protoscan, scans any blob for embedded descriptors:         \

protoscan life-client
# \
# There they are: protoscan found two FileDescriptorProtos embedded in         \
# the client — the game's own grehack/life/v1/life.proto, and the              \
# well-known google/protobuf/descriptor.proto. With --proto_out DIR it         \
# would extract them to disk.                                                  \

# \
# Let's process those descriptors with our second prototool, reproto, so       \
# we can read them in the clear and enable type inference:                     \

reproto -I life-client --schema-db-out life.desc


clear && header "1b. Schema DB"

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
# source. The client also carried the well-known descriptor.proto, so          \
# reproto had everything it needed from the binary alone.                      \

# \
# Now that we have a corpus, our third prototool, prototext, can infer         \
# the type of a capture by scoring it against the DB:                          \

prototext --descriptor-set life.desc list-schemas capture/000001-response.pb

# \
# Let's decode a capture. First the baseline tool, protoc — it works, but      \
# it is spartan:                                                               \

protoc --descriptor_set_in=life.desc \
       --decode=grehack.life.v1.StepRequest < capture/000001-request.pb \
  | view_textproto

# \
# Then the better view: our fourth prototool, protolens — more                 \
# convenient, and it shows wire-level detail, scoring, and navigation:         \

protolens --descriptor-set life.desc capture/000001-response.pb \
  --script beats/capture
# \
# On a field whose type is a named message or enum, v hands off to Neovim,     \
# opened at that type's declaration in the reconstructed .proto — thanks       \
# to the SourceCodeInfo reproto synthesized. Schema recovery is not just a     \
# flat type list: we go from a byte on the wire to the line of source that     \
# defines it, and back.                                                        \


clear && header "2. Eve is spying"

# \
# Claim: Eve's server is not an innocent Life server — it is exfiltrating      \
# from Bob's client. And the covert channel runs the opposite way to what      \
# you would expect: the server drives it.                                      \

# \
#    Eve 😈  ──  "whoami"      (hidden in a response)  ──▶  Bob 🙂             \
#    Eve 😈  ◀──  "experiment"  (hidden in a request)   ──   Bob 🙂            \
#    One Life message carries a whole command, and the next one the            \
#    whole answer — without changing the decoded grid.                         \

# \
# 👉 Bob's window — Space pauses the game.                                     \
# 👉 Here — the next two commands start the tap on an empty capture/.          \
# 👉 Eve's window — Eve types a command on her server's stdin:                 \
#        whoami                                                                \
#    It waits for the next Life step.                                          \
# 👉 Bob's window — wait two seconds, then press n: response 1                 \
#    carries "whoami", and Bob's client runs it. Press n again:                \
#    request 2 carries the answer, which surfaces in Eve's window.             \
# 👉 Here — Ctrl-C stops the tap.                                              \
# 👉 Bob's window — Space sets the game running again.                         \

rm -rf capture
sudo env PATH="$PATH" life-tap

# Alice decodes the second request with protoc → nothing surfaces:
protoc --descriptor_set_in=life.desc \
       --decode=grehack.life.v1.StepRequest < capture/000002-request.pb \
  | view_textproto
# \
# A perfectly ordinary message. The smuggled payload is value-preserving,      \
# so a schema-faithful decode shows nothing.                                   \

# Now look again with protolens — the anomalies show up:
protolens --descriptor-set life.desc capture/000002-request.pb \
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
#   01100101 01111000 01110000 ... 01101110 01110100 00001010                  \
#      e        x        p     ...    n        t        \n  → experiment       \
#   01110111 01101000 01101111 01100001 01101101 01101001                      \
#      w        h        o        a        m        i      → whoami            \

# \
# The channel is legible end to end: Eve asked "whoami", Bob's machine         \
# answered "experiment". We understand the mechanism and can read both         \
# directions.                                                                  \


clear && header "3. No schema"

# \
# Eve's server has been leaving a file in her directory all along.             \
# What is it?                                                                  \

ls -lh eve/server.log

# Our usual first try on an unknown blob:
protoc --decode_raw < eve/server.log
# \
# protoc gives up on the whole file. Let's see what protolens makes of         \
# it, with only the schema we recovered from the client:                       \

protolens --descriptor-set life.desc eve/server.log \
  --script beats/logfile
# \
# A protobuf after all: Eve's traffic log, cut off mid-field. protoc           \
# rejects the whole file for its truncated tail; protolens reads up to it      \
# and flags it. The log's own type is nowhere in the client, yet the heat      \
# cues recognize the Request and Response substructures from their field       \
# shapes, and overrides pin those types to rebuild the record — truncated      \
# tail, no root type and all.                                                  \


clear && header "4. Anomalies"

# \
# Not every protobuf anomaly is accidental. Some are fingerprints, some        \
# are covert channels, some hide data below the application layer.             \
# protolens detects and annotates every category. The full vocabulary:         \

protolens --type google.protobuf.FileDescriptorSet anomalies.pb \
  --script beats/anomalies


clear && header "5. Takeaways"

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
