clear && header "Why prototools"
# \
#                                                                              \
#                                                                              \
# At S3NS we run a Trusted Partner Cloud: we audit Google's update             \
# packages before production.                                                  \
#                                                                              \
# Protobuf is everywhere inside them — and opaque on the wire.                 \
#                                                                              \
# prototools dissects protobufs, even with no schema.                          \
#                                                                              \
# A toy cyber-investigation: scenario made up, tools real.                     \
#                                                                              \


clear && header "0. The cast"
# \
#                                                                              \
#                                                                              \
# Bob 🙂 — the player. Runs a Game of Life client, thinks he's just            \
# playing.                                                                     \
#                                                                              \
#                                                                              \
# Eve 👩 — the server admin. Her server steps the Life grid for Bob.           \
# Keep an eye on her.                                                          \
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
# Alice 🕵️ — the investigator. Taps the wire between Bob and Eve.              \
# Has the capture and the client binary, nothing else.                         \
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
# This window is Alice's control tower. When Bob's or Eve's window must        \
# act, it says so, with the exact keys.                                        \
#                                                                              \
#                                                                              \
# Goal: an unknown protobuf stream → its structure, its contents, then         \
# what it hides.                                                               \
#                                                                              \


clear && header "1. On the wire"
# \
#                                                                              \
# Alice starts her tap in the background. Only the capture needs root —        \
# password once. One line per message; each saved in capture/.                 \

rm -rf capture
sudo -v && (life-tap -q &)
# \
#                                                                              \
# 👉 In Bob's window — play the game of life, then pause it:                   \

ls -lrt capture | head

# Look at the first captured request as raw bytes:
hexdump -v -C capture/000001-request.pb | view
# \
# Opaque. Protobuf self-describes only field numbers and wire types.           \
# To read values: the schema — descriptor set + root type.                     \

# \
# gRPC clients usually embed their own descriptor set.                         \
# protoscan scans any blob for embedded descriptors:                           \

# \
#                                                                              \
# ######################################################################       \
# #                          Enters protoscan                          #       \
# ######################################################################       \
#                                                                              \

protoscan life-client

# \
# Two FileDescriptorProtos in the client: the game's life.proto, and the       \
# standard descriptor.proto.                                                   \

# \
# reproto extracts and decompiles them — a reusable schema DB:                 \

# \
#                                                                              \
# ######################################################################       \
# #                           Enters reproto                           #       \
# ######################################################################       \
#                                                                              \

reproto -I life-client --schema-db-out life.desc

# \
# Not just extraction: it decompiles, indexes, and scores for inference.       \

ls -lhd life.desc life/* \
# reproto delivered 💪:                                                        \
# - life.desc:          the extracted descriptor set (the reusable schema DB)  \
# - life/hopcroft.rkyv: the type-inference scoring graph                       \
# - life/proto/:        all decompiled .proto source files                     \
# - life/index.rkyv:    the fast-access index                                  \

# Browse one decompiled .proto — it reads like hand-written source:
view life/proto/grehack/life/v1/life.proto
# \
# A faithful .proto rebuilt from the binary alone — messages, enums,           \
# fields, nesting, packages. No original source needed.                        \

# \
# With a corpus, prototext infers a capture's type by scoring it:              \

# \
#                                                                              \
# ######################################################################       \
# #                          Enters prototext                          #       \
# ######################################################################       \
#                                                                              \

prototext --descriptor-set life.desc list-schemas capture/000001-response.pb

# \
# Decode one capture. The baseline, protoc — works, but spartan:               \

protoc --descriptor_set_in=life.desc \
       --decode=grehack.life.v1.StepRequest < capture/000001-request.pb \
  | view_textproto

# \
# protolens: wire-level detail, scoring, navigation.                           \

# \
#                                                                              \
# ######################################################################       \
# #                          Enters protolens                          #       \
# ######################################################################       \
#                                                                              \

protolens --descriptor-set life.desc capture/000001-request.pb \
    --script beats/capture # \


# \
# Schema recovery reaches the source: `v` jumps to the type's .proto.          \


clear && header "2. Eve is spying"

# \
#                                                                              \
# Claim: Eve's server is no innocent Life server.                              \
# Watch her window — the grid plays on, but she's about to do more.            \

# \
#                                                                              \
# 👉 In Bob's window — resume the game                                         \
#                                                                              \
# 👉 In Eve's window — Eve types shell commands on her server's stdin, and     \
#    their output appears back on her screen:                                  \
#        ls ~/.ssh                                                             \
#        id                                                                    \
#                                                                              \
# Those commands ran on Bob's machine. Eve's "Life server" is a remote         \
# shell, hidden inside an ordinary game.                                       \


clear && header "3. Hidden bits"

# \
#                                                                              \
# A hidden channel — Alice must find it on the wire. Look for oddly            \
# encoded messages. prototext has `is-canonical`:                              \

prototext is-canonical capture/*.pb || echo Some messages have anomalies

# \
# Which ones carry anomalies:                                                  \

prototext is-canonical capture/*.pb | grep -v canonical

# \
# A closer look:                                                               \

protolens --descriptor-set life.desc capture/NNNNNN-response.pb \
  --script beats/smuggle

# \
#                                                                              \
# From the wire alone: Eve asked "whoami", Bob answered "experiment".          \
# Commands ride the responses; answers ride home in the requests.              \


clear && header "4. No schema"

# \
# Eve's server left a file in her directory all along. What is it?             \

ls -lh eve/server.log

# Our usual first try on an unknown blob:
protoc --decode_raw < eve/server.log

# \
# protoc gives up on the whole file. protolens, with only the recovered        \
# client schema:                                                               \

protolens --descriptor-set life.desc eve/server.log \
  --script beats/logfile
# \
# A schema reverse-crafted from a truncated, type-less blob — Eve's own log.   \


clear && header "5. Anomalies"

# \
# Not every anomaly is accidental: fingerprints, covert channels, data         \
# below the app layer. protolens annotates every category:                     \

protolens --type google.protobuf.FileDescriptorSet anomalies.pb \
  --script beats/anomalies


clear && header "6. Takeaways"

# \
# 1. Descriptors usually hide in the binary. protoscan finds them,             \
#    reproto gives the .proto back.                                            \

# \
# 2. A corpus types a message it has never seen, piece by piece, from the      \
#    messages it does know. That's what heat cues are for.                     \

# \
# 3. What a decoder normalizes away is evidence — a shadowed value, a          \
#    padding bit, a truncated tail. prototools surfaces it, back to bytes.     \


# https://github.com/ThalesGroup/prototools — pull requests welcome 🙂

# Thank you 👋
