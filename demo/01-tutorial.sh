# \
#                                                                                \
# prototools live demo                                                           \
#                                                                                \
# Full tutorial:                                                                 \
#   github.com/ThalesGroup/prototools/blob/main/docs/tutorial.md                 \
#                                                                                \
# Run from the repo root:  ./demo/prompt --splash prototools demo/01-tutorial.sh \
# Generated files go under ./stash/ (gitignored).                                \
#

demo/header "1. Protobufs are everywhere"
demo/header "1. Protobufs are

# \
#                                                                                \
# "I spent 2.5 years at Google, and most of what I did was pushing one protobuf  \
#  from one place to another."                                                   \
#   — Hacker News, 2018, anonymous ex-Googler (item 18189458)                    \
#                                                                                \
# "Protocol buffers are the most commonly-used data format at Google.  They are  \
#  used extensively in inter-server communications as well as for archival       \
#  storage of data on disk."                                                     \
#   — protobuf.dev/overview, Google                                              \
#

# \
#                                                                                \
# Protobufs are compact (binary), self-describing (with a schema), and           \
# language-neutral — the lingua franca of microservice communication.            \
#

demo/header "2. Setup"

# Meet our two tools.
prototext --version && reproto --version

# Build the googleapis schema DB — we will use it throughout.
#export GOOGLEAPIS_DB=$(nix-build -A googleapis-db --no-out-link)/googleapis.desc
export GOOGLEAPIS_DB=/nix/store/qmnwx5798np062iydkky60g0jfq0dam9-googleapis-db/googleapis.desc
# Companion paths: binary instances and decompiled .proto sources.
GOOGLEAPIS_PBS=$(dirname $GOOGLEAPIS_DB)/instances
GOOGLEAPIS_DESCS=$(dirname $GOOGLEAPIS_DB)/reproto-out

demo/header "3. What's inside a protobuf?"

# \
#                                                                                \
# Quick vocabulary:                                                              \
#   protobuf  — a binary-encoded message on the wire                             \
#   schema    — the .proto definition that names fields and assigns types        \
#   descriptor — a compiled schema, itself serialised as a protobuf              \
#

# Our running example: a postal address, serialised as a protobuf.
ls -lh $GOOGLEAPIS_PBS/google/type/PostalAddress.pb

# Raw bytes — this is what travels on the wire.
hexdump -C $GOOGLEAPIS_PBS/google/type/PostalAddress.pb

# No schema yet: we see field numbers and wire types, but no names.
prototext --descriptor-set $GOOGLEAPIS_DB decode -a --type google.protobuf.Empty \
    $GOOGLEAPIS_PBS/google/type/PostalAddress.pb

# With the right schema: the message becomes readable.
prototext --descriptor-set $GOOGLEAPIS_DB decode --type google.type.PostalAddress \
    $GOOGLEAPIS_PBS/google/type/PostalAddress.pb

# Here is the schema that unlocked it — the .proto source.
cat $GOOGLEAPIS_DESCS/google/type/postal_address.proto

demo/header "4. Schemas are protobufs too"

# \
#                                                                                \
# A .proto source file can itself be serialised as a protobuf — a                \
# FileDescriptorProto.  The schema for FileDescriptorProto is defined in         \
# descriptor.proto, which is itself a .proto file.  Self-referential!            \
#

# Let's decode the PostalAddress schema as a FileDescriptorProto.
prototext --descriptor-set $GOOGLEAPIS_DB \
    decode --type google.protobuf.FileDescriptorProto \
    $GOOGLEAPIS_DESCS/google/type/postal_address.pb | head -20 && echo ...

demo/header "5. Schema auto-inference"

# \
#                                                                                \
# prototext can infer the schema automatically: it scores every type in the DB   \
# against the binary and picks the best match.  The score consolidates field     \
# coverage, wire type matches, value plausibility, and more.                     \
#

# Watch prototext infer the schema with no hint from us.
prototext --descriptor-set $GOOGLEAPIS_DB \
    decode $GOOGLEAPIS_PBS/google/type/PostalAddress.pb

# \
#                                                                                \
# Notice the score at the top of the output — the higher, the better the fit.    \
# The googleapis DB contains thousands of types; prototext scores them all and   \
# picks the best candidate.                                                      \
#
# \
#                                                                                \
# Inference is not always unambiguous: sometimes two types tie on the score.     \
#

# Here prototext finds a tie and asks us to be explicit.
prototext --descriptor-set $GOOGLEAPIS_DB \
    decode \
    $GOOGLEAPIS_PBS/google/cloud/compute/v1beta/UsableSubnetwork.pb

# With --type the ambiguity is resolved.
prototext --descriptor-set $GOOGLEAPIS_DB \
    decode --type google.cloud.compute.v1beta.UsableSubnetwork \
    $GOOGLEAPIS_PBS/google/cloud/compute/v1beta/UsableSubnetwork.pb

demo/header "6. Non-canonical protobufs"

# \
#                                                                                \
# The wire format allows encodings that are valid but non-canonical: repeated    \
# optional fields, over-long varints, unexpected field ordering.  Standard       \
# decoders silently normalise or discard them — a potential side channel.        \
# prototext decode -a exposes every anomaly; prototext encode preserves them.    \
#

# \
#                                                                                \
# --- Hidden field ---                                                           \
#                                                                                \
# proto3 last-write-wins: an earlier occurrence of an optional field is silently \
# discarded by standard decoders.  This is a real steganographic / exfiltration  \
# vector.  prototext decode preserves wire order and exposes all occurrences.    \
#

# Craft postal_hidden.pb: slip a secret organization field before the real one.
prototext --descriptor-set $GOOGLEAPIS_DB \
    decode -a $GOOGLEAPIS_PBS/google/type/PostalAddress.pb \
  | sed '/^organization: "S3NS"/i organization: "Entrance secret PIN code: 666*"  #@ string = 11' \
  | prototext encode > stash/postal_hidden.pb

# The extra field is invisible to the naked eye — but it is in there.
hexdump -C stash/postal_hidden.pb

# Standard decoder (protoc): only sees the last occurrence — secret gone.
protoc --proto_path $GOOGLEAPIS_DESCS --decode google.type.PostalAddress \
    google/type/postal_address.proto \
  < stash/postal_hidden.pb

# prototext decode: preserves wire order — both occurrences visible.
prototext --descriptor-set $GOOGLEAPIS_DB decode stash/postal_hidden.pb

# \
#                                                                                \
# --- Over-long varint ---                                                       \
#                                                                                \
# An extra byte on a varint field does not change its value, but makes the       \
# encoding non-minimal.  Standard decoders strip it without a word.  prototext   \
# decode -a flags it and preserves it through encode.                            \
#

# Craft postal_patched.pb: inject an over-long varint on the revision field.
prototext --descriptor-set $GOOGLEAPIS_DB \
    decode -a \
    $GOOGLEAPIS_PBS/google/type/PostalAddress.pb \
  | sed 's/#@ int32 = 1$/#@ int32 = 1; val_ohb: 1/' \
  | prototext encode > stash/postal_patched.pb

# Spot the difference: one extra byte.
hexdump -C $GOOGLEAPIS_PBS/google/type/PostalAddress.pb | head -1
hexdump -C stash/postal_patched.pb | head -1

# prototext -a flags it: look for val_ohb on the revision field.
# (val_ohb = over-hung byte — the extra byte that shouldn't be there.)
prototext --descriptor-set $GOOGLEAPIS_DB \
    decode -a \
    stash/postal_patched.pb | head -6 && echo ...

# \
#                                                                                \
# Compare with the canonical version: the score drops because of the anomaly.    \
#

# prototext round-trip: the over-hung byte is preserved exactly.
prototext --descriptor-set $GOOGLEAPIS_DB \
    decode -a \
    stash/postal_patched.pb \
  | prototext encode \
  | diff - stash/postal_patched.pb \
  && echo byte-exact

# protoc round-trip: silently normalises the varint — byte-exact is lost.
protoc --proto_path $GOOGLEAPIS_DESCS \
    --decode google.type.PostalAddress \
    google/type/postal_address.proto \
  < stash/postal_patched.pb \
  | protoc --proto_path $GOOGLEAPIS_DESCS \
    --encode google.type.PostalAddress \
    google/type/postal_address.proto \
  | diff - stash/postal_patched.pb \
  || echo not-byte-exact

demo/header "7. There is more"

# \
#                                                                                \
# reproto turns a serialised schema (FileDescriptorProto) back into readable     \
# .proto source.  Useful when you have the binary but not the original source:   \
# auditing a third-party API, inspecting a schema DB, or understanding what a    \
# binary descriptor actually defines.                                            \
#

prototext decode $GOOGLEAPIS_DESCS/google/type/postal_address.pb | vim +'set ft=pbtxt' -
# Decompile the PostalAddress descriptor back to .proto source.
reproto -O stash/reproto-out \
    --use-variant descriptor \
    $GOOGLEAPIS_DESCS/google/type/postal_address.pb

# Human-readable .proto source, recovered from the binary.
cat stash/reproto-out/google/type/postal_address.proto | tee /dev/tty | vim +'set ft=proto' -

# \
#                                                                                \
# reproto can also decompile an entire schema DB back to .proto sources.         \
# The full googleapis DB contains thousands of files.                            \
#
# Decompile the entire googleapis DB: thousands of .proto files reconstructed.
rm -rf stash/meet-out stash/meet-seed stash/meet-pruned
reproto -O stash/meet-out --use-variant descriptor \
    -I $GOOGLEAPIS_DESCS .

# Browse the reconstructed sources — full import graph, all navigable.
tree stash/meet-out

# Open one file in VS Code: imports are live links to the sibling .proto files.
code stash/meet-out/google/apps/meet/v2/service.proto

# \
#                                                                                \
# That reconstructed thousands of files.  What if you only care about one        \
# message type?  Pass its descriptor as the seed: reproto pulls only its         \
# transitive closure.                                                            \
#
# Seed on ConferenceRecord only: thousands of files collapse to 4.
reproto -O stash/meet-seed \
    --use-variant descriptor \
    -I $GOOGLEAPIS_DESCS google/apps/meet/v2/resource.pb

tree stash/meet-seed

# \
#                                                                                \
# You can also go the other way: start from the same seed and prune away         \
# the boilerplate annotation files you don't need.  4 files become 2.           \
#
# Prune the google/api annotation files present in the ConferenceRecord closure.
reproto -O stash/meet-pruned \
    --use-variant descriptor \
    -I $GOOGLEAPIS_DESCS google/apps/meet/v2/resource.pb \
    --prune 'file:google/api/field_behavior.proto' \
    --prune 'file:google/api/resource.proto'

tree stash/meet-pruned

# THE END
