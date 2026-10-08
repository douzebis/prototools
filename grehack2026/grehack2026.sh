# Remove the artifacts of a previous run (skip this step to keep them):
[ -e capture/tap.pid ] && life-tap --stop; rm -rf capture life.desc life eve/server.log

clear && header "Why prototools"
# \
#                                                                              \
#                                                                              \
# At S3NS we run a Trusted Partner Cloud: we audit Google's update             \
# packages before production.                                                  \
#                                                                              \
# Protobufs are everywhere inside them — and opaque on the wire.               \
# They efficiently encode data as binary and require a "schema" for decoding.  \
#                                                                              \
# prototools dissects protobufs, even with no schema.                          \
#                                                                              \
# The demo: prototools in action -> a toy cyber-investigation.                 \
#                                                                              \


clear && header "0. The cast"
# \
#                                                                              \
#                                                                              \
# Bob 🙂 — the player. Thinks he's just playing.                               \
#                                                                              \
#                                                                              \
# Eve 👩 — the server admin. Keep an eye on her.                               \
#                                                                              \
#                                                                              \
# Bob plays the Game of Life with software Eve provides: his client asks       \
# her server for each next generation over gRPC — one pair of protobuf         \
# messages per step.                                                           \
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

clear
# \
#                                                                              \
# Alice 🕵️ — the investigator. Bob, idly curious whether his game only         \
# plays Life, asks her to audit the traffic. She has his client binary and     \
# her own tap of the wire — nothing from the server.                           \
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
# Goal: understand the stream's structure, its contents, then what it hides    \
#                                                                              \


clear && header "1. On the wire"
# \
#                                                                              \
# Alice starts her tap in the background.                                      \
# One capture per message; each saved in capture/.                             \


sudo -v && (life-tap -q &)

# Look at the first captured request as raw bytes:
hexdump -v -C capture/000001-request.pb | view
# \
#                                                                              \
# Opaque. Protobuf self-describes only field numbers and wire types.           \
# To read values: the schema — descriptor set + root type.                     \

# \
#                                                                              \
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
#                                                                              \
# Two FileDescriptorProtos in the client: the game's life.proto, and the       \
# standard descriptor.proto.                                                   \

# \
#                                                                              \
# reproto extracts them — a reusable schema DB:                                \

# \
#                                                                              \
# ######################################################################       \
# #                           Enters reproto                           #       \
# ######################################################################       \
#                                                                              \


reproto -I life-client --schema-db-out life.desc

# \
#                                                                              \
# Not just extraction: it decompiles, and analyzes for type inference.         \

ls -lhd life.desc life/* \
# reproto delivered 💪:                                                        \
# - life.desc:          the extracted descriptor set (the reusable schema DB)  \
# - life/hopcroft.rkyv: the type-inference scoring graph                       \
# - life/proto/:        all decompiled .proto source files                     \
# - life/index.rkyv:    the fast-access index                                  \


# Browse one decompiled .proto — it reads like hand-written source:
view life/proto/grehack/life/v1/life.proto # \
#                                                                              \
# A faithful .proto rebuilt from the life-client binary alone — messages,      \
# enums, fields, nesting, packages. No original source needed.                 \

# \
#                                                                              \
# Read a capture with protolens and a descriptor set — it infers the type      \
# and shows wire-level detail, scoring, navigation:                            \

# \
#                                                                              \
# ######################################################################       \
# #                          Enters protolens                          #       \
# ######################################################################       \
#                                                                              \


protolens --descriptor-set life.desc capture/000001-request.pb \
    --script beats/capture


# \
#                                                                              \
# Alice can now read every message in the clear. But is the server only        \
# playing Life?                                                                \


clear && header "2. Eve is spying"

# \
#                                                                              \
# A look behind the curtain — what Alice cannot see. Watch Eve's window:       \
# the grid plays on, but she's about to do more.                               \

# \
#                                                                              \
# 👉 In Bob's window — resume the game                                         \
#                                                                              \
# 👉 In Eve's window — Eve types shell commands on her server's stdin, and     \
#    their output appears back on her screen:                                  \
#        pwd                                                                   \
#        whoami                                                                \
#                                                                              \

# \
#                                                                              \
# Those commands ran on Bob's machine: Eve's "Life server" is a remote         \
# shell, hidden in an ordinary game. Alice saw none of this — she has only     \
# the wire. Can she find it there?                                             \


clear && header "3. Hidden bits"

# \
#                                                                              \
# She can. A covert channel has to bend the encoding — so Alice hunts          \
# non-canonical protobufs. prototext has `is-canonical`:                       \

# \
#                                                                              \
# ######################################################################       \
# #                          Enters prototext                          #       \
# ######################################################################       \
#                                                                              \


prototext is-canonical capture/*.pb || echo Some messages have anomalies

# Which ones carry anomalies:
prototext is-canonical capture/*.pb | grep anomalous

# protoc decodes the flagged messages cleanly — blind to the anomalies:
protoc --descriptor_set_in=life.desc \
       --decode=grehack.life.v1.StepResponse < capture/000000-response.pb \
  | view_textproto

# A closer look, with protolens:
protolens --descriptor-set life.desc capture/000000-response.pb \
  --script beats/smuggle

protolens --descriptor-set life.desc capture/000000-request.pb \
  --script beats/smuggle2

# \
#                                                                              \
# Alice has it, from the wire alone: Eve asked "whoami", Bob answered          \
# "experiment". Commands ride the responses, answers the requests.             \


clear && header "4. Eve's own log"

# \
#                                                                              \
# With the wire evidence in hand, Eve's server is pulled — and it kept a       \
# log. What is it?                                                             \

ls -lh eve/server.log

# \
#                                                                              \
# We have no descriptor set for Eve's server. All we hold is the client's —    \
# try it as an ersatz against the blob:                                        \


protolens --descriptor-set life.desc eve/server.log \
  --script beats/logfile


clear && header "5. Takeaways"

# \
#                                                                              \
# 1. Descriptors usually hide in the binary. protoscan finds them,             \
#    reproto gives the .proto back.                                            \
#                                                                              \
#                                                                              \
# 2. A corpus types a message it has never seen, piece by piece, from the      \
#    messages it does know. That's what heat cues are for.                     \
#                                                                              \
#                                                                              \
# 3. What a decoder normalizes away is evidence — a shadowed value, a          \
#    padding bit, a truncated tail. prototools surfaces it, back to bytes.     \
#                                                                              \


# https://github.com/ThalesGroup/prototools — pull requests welcome 🙂

# Thank you 👋




clear && header "Annex: anomalies"

# \
#                                                                              \
# Not every anomaly is accidental: fingerprints, covert channels, data         \
# below the app layer. protolens annotates every category:                     \

protolens --type google.protobuf.FileDescriptorSet anomalies.pb \
  --script beats/anomalies
