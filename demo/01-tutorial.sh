# \
#                                                                                \
# prototools demo — narrative arc per spec 0079                                  \
#                                                                                \
# Usage:  ./prompt 01-tutorial.sh                                                \
# Run from the repo root.                                                        \
# All generated files go under ./stash/ (gitignored).                            \
#                                                                                \
#

# \
#                                                                                \
# --- S1: Protobufs are everywhere ---                                           \
#                                                                                \
# "I spent 2.5 years at Google, and most of what I did was pushing one protobuf  \
#  from one place to another."                                                   \
#   — HN, 2018, anonymous ex-Googler (item 18189458)                             \
#                                                                                \
# "Protocol buffers are the most commonly-used data format at Google.  They are  \
#  used extensively in inter-server communications as well as for archival       \
#  storage of data on disk."                                                     \
#   — protobuf.dev/overview, Google                                              \
#                                                                                \
#

# \
#                                                                                \
# Protobufs are compact (binary), self-describing (with a schema), and           \
# language-neutral — the lingua franca of microservice communication.            \
#                                                                                \
#

prototext --version
reproto --version

# \
#                                                                                \
# --- S2: What's inside a protobuf? ---                                          \
#                                                                                \
#

export GOOGLEAPIS_DB=$(nix-build -A googleapis-db --no-out-link)/googleapis.desc
INST=$(dirname $GOOGLEAPIS_DB)/instances

hexdump -C $INST/google/type/PostalAddress.pb

cat $INST/google/type/PostalAddress.pb | protoc --decode_raw

prototext --descriptor $GOOGLEAPIS_DB \
    decode \
    $INST/google/type/PostalAddress.pb

# \
#                                                                                \
# --- S3: Schemas are protobufs too ---                                          \
#                                                                                \
# A descriptor is a compiled .proto schema, serialised as a binary protobuf      \
# (FileDescriptorSet / FileDescriptorProto).  The descriptor format is itself    \
# defined in descriptor.proto — so a descriptor file is a protobuf whose schema  \
# is google.protobuf.FileDescriptorSet.  Self-referential!                       \
#                                                                                \
#

# \
#                                                                                \
# Demonstrate with a small self-contained descriptor for PostalAddress only.     \
#                                                                                \
#

reproto --use-variant descriptor \
    -O stash/googleapis-src \
    $GOOGLEAPIS_DB

protoc \
    -Istash/googleapis-src \
    --descriptor_set_out=stash/postal_address.pb \
    --include_imports \
    google/type/postal_address.proto

reproto \
    --build-schema-db=stash/postal_address.desc \
    stash/postal_address.pb

prototext --descriptor stash/postal_address.desc \
    decode stash/postal_address.pb | head -40

# \
#                                                                                \
# --- S4: When the binary alone isn't enough ---                                 \
#                                                                                \
# Sometimes the binary alone is not enough: two types tie on the score.          \
#                                                                                \
#

prototext --descriptor $GOOGLEAPIS_DB \
    list-schemas \
    $INST/google/cloud/compute/v1beta/UsableSubnetwork.pb

prototext --descriptor $GOOGLEAPIS_DB \
    decode --type google.cloud.compute.v1beta.UsableSubnetwork \
    $INST/google/cloud/compute/v1beta/UsableSubnetwork.pb

# \
#                                                                                \
# --- S5: The hidden field ---                                                   \
#                                                                                \
# proto3 last-write-wins: an earlier occurrence of an optional field is silently \
# discarded by standard decoders.  This is a real steganographic / exfiltration  \
# vector.  prototext decode preserves wire order and exposes all occurrences.    \
#                                                                                \
#

prototext --descriptor $GOOGLEAPIS_DB \
    decode -a \
    $INST/google/type/PostalAddress.pb \
  | sed '/^organization: "S3NS"/i organization: "Entrance secret PIN code: 666*"  #@ string = 11' \
  > stash/postal_hidden.textpb
prototext encode < stash/postal_hidden.textpb > stash/postal_hidden.pb

protoc --proto_path stash/googleapis-src \
    --decode google.type.PostalAddress \
    google/type/postal_address.proto \
  < stash/postal_hidden.pb

prototext --descriptor $GOOGLEAPIS_DB decode stash/postal_hidden.pb

# \
#                                                                                \
# --- S6: The invisible byte ---                                                 \
#                                                                                \
# One extra byte on a varint field: standard decoders silently normalise it,     \
# leaving no trace.  prototext decode -a annotates it; score drops to -11.       \
# Lossless round-trip via prototext encode still works.                          \
#                                                                                \
#

prototext --descriptor $GOOGLEAPIS_DB \
    decode -a \
    $INST/google/type/PostalAddress.pb > stash/PostalAddress.textpb
sed -i 's/#@ int32 = 1$/#@ int32 = 1; val_ohb: 1/' stash/PostalAddress.textpb
prototext encode < stash/PostalAddress.textpb > stash/postal_patched.pb

hexdump -C $INST/google/type/PostalAddress.pb | head -1
hexdump -C stash/postal_patched.pb | head -1

prototext --descriptor $GOOGLEAPIS_DB \
    decode -a \
    stash/postal_patched.pb | head -6

prototext --descriptor $GOOGLEAPIS_DB \
    decode -a \
    stash/postal_patched.pb \
  | prototext encode \
  | diff - stash/postal_patched.pb \
  && echo byte-exact

# \
#                                                                                \
# --- S7: There is more ---                                                      \
#                                                                                \
# reproto decompiles any FileDescriptorSet back to .proto source.                \
# (The S3a step above already showed this for googleapis.desc.)                  \
# It can also translate editions-syntax descriptors to proto2 output.            \
#                                                                                \
#

cat stash/googleapis-src/google/protobuf/timestamp.proto
