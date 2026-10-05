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

# \
#                                                                              \
# ######################################################################       \
# #                           Enters reproto                           #       \
# ######################################################################       \
#                                                                              \

reproto -I life-client --schema-db-out life.desc

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

# \
#                                                                              \
# ######################################################################       \
# #                          Enters prototext                          #       \
# ######################################################################       \
#                                                                              \

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
# Claim: Eve's server is not an innocent Life server.                          \
#                                                                              \
# Watch her server's window. The grid plays on as usual — but Eve is           \
# about to make it do more than play.                                          \

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
# shell, hidden inside an ordinary-looking game.                               \


clear && header "3. Hidden bits"

# \
#                                                                              \
# A hidden channel exists; Alice has to find it on the wire.                   \
# She looks for messages that could be encoded oddly.                          \
#
# prototext has a command for just that: `is-canonical`                        \

prototext is-canonical capture/*.pb || echo Some messages have anomalies

# \
# Let's spot which protobufs have anomalies                                    \

prototext is-canonical capture/*.pb | grep -v canonical

# \
# Let's have a closer look...                                                  \

protolens --descriptor-set life.desc capture/NNNNNN-response.pb \
  --script beats/smuggle

# \
#                                                                              \
# Recovered from the wire alone: Eve asked "whoami", Bob's machine             \
# answered "experiment". The server drives the channel, hidden in the          \
# responses; the answers ride home in the requests.                            \


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
# A schema reverse-crafted from a truncated, type-less blob — Eve's own log.   \


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
