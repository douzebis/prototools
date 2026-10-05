clear && header "Why prototools"
# \
#                                                                              \
#                                                                              \
# At S3NS we operate a Trusted Partner Cloud (TPC). Google ships us its        \
# software update packages, and before any of them reaches production we       \
# audit them, to make sure they do nothing they should not.                    \
#                                                                              \
# Inside those packages, protobuf is everywhere: it is the data                \
# serialization format of the Google infrastructure — configuration,           \
# RPCs, logs, stored data. And on the wire, protobuf is opaque.                \
#                                                                              \
# So we built prototools: a suite of tools to dissect protobufs, even          \
# when nobody hands us the schema.                                             \
#                                                                              \
# What follows is a demo of prototools, told as a toy cyber-investigation.     \
# The scenario is made up; the tools and their features are real.              \
#                                                                              \


clear && header "0. The cast"
# \
#                                                                              \
#                                                                              \
# Meet Bob 🙂, the player. He runs a Game of Life client and thinks he         \
# is just playing.                                                             \
#                                                                              \
#                                                                              \
# Meet Eve 👩, the server administrator. Her server computes each Life         \
# generation for Bob's client. Keep an eye on her.                             \
#                                                                              \
#                                                                              \
#    ┌──────────────┐        StepRequest         ┌──────────────┐              \
#    │     Bob      │ ─────────────────────────▶ │     Eve      │              \
#    │ life-client  │ ◀───────────────────────── │ life-server  │              \
#    └──────────────┘        StepResponse        └──────────────┘              \
#                           cleartext gRPC                                     \
#                                                                              \
#                                                                              \


# \
#                                                                              \
# 👉 In Eve's window (eve/) — Eve starts her server:                           \
#        life-server                                                           \
# 👉 In Bob's window (bob/) — Bob starts his client:                           \
#        life-client                                                           \
#                                                                              \
#                                                                              \
# On screen it is an ordinary Game of Life: the grid steps, nothing looks      \
# amiss.                                                                       \
#                                                                              \


# \
#                                                                              \
# Now meet Alice 🕵️, the investigator. She taps the wire between Bob and       \
# Eve. She has the network capture and the client binary, nothing else —       \
# no help from either endpoint.                                                \
#                                                                              \
#                                                                              \
#    ┌──────────────┐        StepRequest         ┌──────────────┐              \
#    │     Bob      │ ───────────┬─────────────▶ │     Eve      │              \
#    │ life-client  │ ◀──────────┼────────────── │ life-server  │              \
#    └──────────────┘            │ StepResponse  └──────────────┘              \
#                                ▼                                             \
#              ┌───────────────────────────────────────────────┐               \
#              │ Alice — this window                           │               \
#              │   life-tap ──▶ capture/*.pb ──▶ prototools    │               \
#              └───────────────────────────────────────────────┘               \
#                                                                              \
#                                                                              \


# \
#                                                                              \
# This window is Alice's control tower. The analysis runs here; when           \
# something must happen in Eve's or Bob's window, this window says so,         \
# with the exact keys or command to type.                                      \
#                                                                              \
#                                                                              \
# Goal: take an unknown protobuf stream and, with no help from either          \
# endpoint, work out its structure, read it, then notice what it is not        \
# telling us.                                                                  \
#                                                                              \


clear && header "1. On the wire"
# \
#                                                                              \
# Alice starts her tap, in the background. Only its capture needs root,        \
# so she types her password once. The tap prints one line per message,         \
# and saves each message in capture/.                                          \

rm -rf capture
sudo -v && (life-tap -q &)
# \
#                                                                              \
# 👉 In Bob's window — play the game of life, then pause it:                   \

ls -lrt capture | head

# Look at the first captured request as raw bytes:
hexdump -v -C capture/000001-request.pb | view
# \
# Quite opaque. Protobuf is self-describing only up to field numbers and       \
# wire types; to read values we need the schema — a descriptor set and a       \
# root type.                                                                   \

# \
# As is usual with gRPC applications, the client binary carries its own        \
# descriptor set in binary format.                                             \
# Our first prototool, protoscan, scans any blob for embedded descriptors:     \

# \
#                                                                              \
# ######################################################################       \
# #                          Enters protoscan                          #       \
# ######################################################################       \
#                                                                              \
protoscan life-client

# \
# There they are: protoscan found two FileDescriptorProtos embedded in         \
# the client — the game's own grehack/life/v1/life.proto, and the              \
# standard google/protobuf/descriptor.proto.                                   \

# \
# Let's extract and decompile those descriptors with our second prototool,     \
# reproto, so we can read them in the clear and use them for rendering the     \
# capture files.                                                               \

reproto -I life-client --schema-db-out life.desc # \
#                                                                              \
# ######################################################################       \
# #                           Enters reproto                           #       \
# ######################################################################       \
#                                                                              \
# reproto -I life-client --schema-db-out life.desc

# \
# reproto does not just extract the descriptors — it decompiles, indexes,      \
# and processes them for type inference. Let's see what we have:               \

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

prototext --descriptor-set life.desc list-schemas capture/000001-response.pb # \
#                                                                              \
# ######################################################################       \
# #                          Enters prototext                          #       \
# ######################################################################       \
#                                                                              \
# prototext --descriptor-set life.desc list-schemas capture/000001-response.pb

# \
# Let's decode a capture. First the baseline tool, protoc — it works, but      \
# it is spartan:                                                               \

protoc --descriptor_set_in=life.desc \
       --decode=grehack.life.v1.StepRequest < capture/000001-request.pb \
  | view_textproto

# \
# Then the better view: our fourth prototool, protolens — more                 \
# convenient, and it shows wire-level detail, scoring, and navigation:         \

protolens --descriptor-set life.desc capture/000001-response.pb --script beats/capture # \
#                                                                              \
# ######################################################################       \
# #                          Enters protolens                          #       \
# ######################################################################       \
#
# \
# On a field whose type is a named message or enum, v hands off to Neovim,     \
# opened at that type's declaration in the reconstructed .proto — thanks       \
# to the SourceCodeInfo reproto synthesized. Schema recovery is not just a     \
# flat type list: we go from a byte on the wire to the line of source that     \
# defines it, and back.                                                        \


clear && header "2. Eve is spying"

# \
#                                                                              \
# Claim: Eve's server is not an innocent Life server.                          \
#                                                                              \
# Watch her server's window. The grid plays on as usual — but Eve is           \
# about to make it do more than play.                                          \

# \
#                                                                              \
# 👉 In Bob's window — resume the game                                         \

# \
#                                                                              \
# 👉 In Eve's window — Eve types shell commands on her server's stdin, and     \
#    a their output appears back on her screen:                                \
#        ls ~/.ssh                                                             \
#        id                                                                    \
#                                                                              \
# Those commands ran on Bob's machine. Eve's "Life server" is a remote         \
# shell, hidden inside an ordinary-looking game.                               \

# \
#                                                                              \
# 👉 Bob's window — Ctrl-C quits the client.                                   \
#                                                                              \
# So the channel exists. Now Alice, who only has the wire, has to find         \
# it. She takes one clean capture of a single exchange.                        \


clear && header "3. Hidden bits"

# \
#                                                                              \
# The channel exists; Alice has to find it on the wire. She does not           \
# control Eve, so she cannot choose which message carries contraband —         \
# she takes one capture and looks for the message that is encoded oddly.       \

# \
#                                                                              \
# 👉 Bob's window — resume the game for a few steps, then pause it.            \
#    (Eve may or may not be typing; Alice does not know.)                      \

rm -rf capture
sudo -v && (life-tap -q &)
life-tap --stop
tail -n 3 capture/tap.log

# \
#                                                                              \
# A well-formed protobuf has one canonical encoding. prototext checks          \
# each captured message against that — no schema needed:                       \

prototext is-canonical capture/*.pb

# \
#                                                                              \
# Most are canonical. One or two are not: "overhanging bytes in values"        \
# — spurious padding on varints that a normal encoder never emits. That        \
# is where something is hidden. Open one of the flagged captures:              \

protolens --descriptor-set life.desc capture/NNNNNN-request.pb \
  --script beats/smuggle

# \
#                                                                              \
# protolens flags the fields that do not sit the way the schema expects.       \
#                                                                              \
# At wire level, a VARINT is base-128: little-endian groups, the high bit      \
# a continuation flag. The trick is a spurious continuation bit — one          \
# hidden bit per field, with the decoded value unchanged.                      \

# \
#                                                                              \
# Read those hidden bits across the fields, group them into bytes, and         \
# they are ASCII:                                                              \

# \
#                                                                              \
#   01100101 01111000 01110000 ... 01101110 01110100                           \
#      e        x        p     ...    n        t      → experiment             \
#                                                                              \
#   01110111 01101000 01101111 01100001 01101101 01101001                      \
#      w        h        o        a        m        i      → whoami            \

# \
#                                                                              \
# There it is, recovered from the wire alone: Eve asked "whoami", and          \
# Bob's machine answered "experiment". The server drives the channel,          \
# hidden inside the responses; the answers ride home inside the requests.      \


clear && header "4. No schema"

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
# and flags it. The log's own type is nowhere in the client, yet every         \
# entry has the same shape: the heat cues recognize the game's StepRequest     \
# and StepResponse inside, and overrides pin them.                             \

# \
# One field in each entry is in no schema we hold: 666, a string. Where it     \
# is set, it reads "whoami" or "experiment". Eve logs her own contraband.      \


clear && header "5. Anomalies"

# \
# Not every protobuf anomaly is accidental. Some are fingerprints, some        \
# are covert channels, some hide data below the application layer.             \
# protolens detects and annotates every category. The full vocabulary:         \

protolens --type google.protobuf.FileDescriptorSet anomalies.pb \
  --script beats/anomalies


clear && header "6. Takeaways"

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
