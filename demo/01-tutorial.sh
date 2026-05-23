# SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
#
# SPDX-License-Identifier: MIT

# ============================================================
# prototools demo — follows docs/tutorial.md
# Usage:  ./prompt 01-tutorial.sh
# Run from the repo root.
# All generated files go under ./stash/ (gitignored).
# ============================================================

# --- Section 1: Setup ---

# Confirm the tools are available
prototext --version
reproto --version

# --- Section 2: Build the googleapis schema DB (one-time) ---

export GOOGLEAPIS_DB=$(nix-build -A googleapis-db --no-out-link)/googleapis.desc

# --- Section 2 (cont): Decode a sample message (auto-inference, no --type needed) ---

prototext --descriptor $GOOGLEAPIS_DB \
    decode \
    $(dirname $GOOGLEAPIS_DB)/instances/google/type/PostalAddress.pb

# --- Section 3: Schema inference — the ambiguous case ---

prototext --descriptor $GOOGLEAPIS_DB \
    list-schemas \
    $(dirname $GOOGLEAPIS_DB)/instances/google/cloud/compute/v1beta/UsableSubnetwork.pb

# Decode with explicit type to resolve the tie
prototext --descriptor $GOOGLEAPIS_DB \
    decode --type google.cloud.compute.v1beta.UsableSubnetwork \
    $(dirname $GOOGLEAPIS_DB)/instances/google/cloud/compute/v1beta/UsableSubnetwork.pb

# Multi-file auto-inference: unambiguous files decoded, ambiguous ones warned
INST=$(dirname $GOOGLEAPIS_DB)/instances
prototext --descriptor $GOOGLEAPIS_DB decode -O stash/decoded \
    $INST/google/type/PostalAddress.pb \
    $INST/google/cloud/compute/v1beta/UsableSubnetwork.pb

# --- Section 4: Build a schema DB from scratch (WKT example) ---

# 4a — compile WKT .proto files into a FileDescriptorSet
PROTOC_INCLUDE=$(dirname $(which protoc))/../include
protoc \
    -I$PROTOC_INCLUDE \
    --descriptor_set_out=stash/wkt.pb \
    --include_imports \
    google/protobuf/descriptor.proto \
    google/protobuf/timestamp.proto \
    google/protobuf/duration.proto \
    google/protobuf/any.proto

# 4b — build the schema DB with reproto
reproto \
    --build-schema-db=stash/wkt.desc \
    stash/wkt.pb

# 4c — decode the descriptor itself (self-referential: wkt.pb IS a FileDescriptorSet)
prototext --descriptor stash/wkt.desc \
    decode stash/wkt.pb | head -12

# --- Section 5: Annotations and non-canonical encoding ---

INST=$(dirname $GOOGLEAPIS_DB)/instances
prototext --descriptor $GOOGLEAPIS_DB \
    decode -a \
    $INST/google/type/PostalAddress.pb

# Save annotated output, then inject a non-canonical over-hanging byte
prototext --descriptor $GOOGLEAPIS_DB \
    decode -a \
    $INST/google/type/PostalAddress.pb > stash/PostalAddress.textpb

# Patch: change  #@ int32 = 1  to  #@ int32 = 1; val_ohb: 1
sed -i 's/#@ int32 = 1$/#@ int32 = 1; val_ohb: 1/' stash/PostalAddress.textpb

# Re-encode with the patched annotation
prototext encode < stash/PostalAddress.textpb > stash/postal_patched.pb

# Compare first bytes: canonical vs patched (81 00 instead of 01)
hexdump -C $INST/google/type/PostalAddress.pb | head -1
hexdump -C stash/postal_patched.pb | head -1

# Decode the patched file — val_ohb is preserved, score reflects non-canonical byte
prototext --descriptor $GOOGLEAPIS_DB \
    decode -a \
    stash/postal_patched.pb | head -6

# --- Section 6: Hidden fields ---

# Craft a binary with a secret value hidden in a duplicate optional field.
# The secret is inserted BEFORE the legitimate value, so last-write-wins
# decoders silently overwrite it and see only "S3NS".
INST=$(dirname $GOOGLEAPIS_DB)/instances
prototext --descriptor $GOOGLEAPIS_DB \
    decode -a \
    $INST/google/type/PostalAddress.pb \
  | sed '/^organization: "S3NS"/i organization: "Entrance secret PIN code: 666*"  #@ string = 11' \
  > stash/postal_hidden.textpb

prototext encode < stash/postal_hidden.textpb > stash/postal_hidden.pb

# protoc sees only the last (innocent) value
protoc --proto_path stash/googleapis-src \
    --decode google.type.PostalAddress \
    google/type/postal_address.proto \
  < stash/postal_hidden.pb

# prototext decode exposes both occurrences in wire order
prototext --descriptor $GOOGLEAPIS_DB decode stash/postal_hidden.pb

# --- Section 7: Lossless round-trip ---

# Canonical binary round-trips byte-exact through decode -a | encode
INST=$(dirname $GOOGLEAPIS_DB)/instances
prototext --descriptor $GOOGLEAPIS_DB \
    decode -a \
    $INST/google/type/PostalAddress.pb \
  | prototext encode \
  | diff - $INST/google/type/PostalAddress.pb \
  && echo byte-exact

# Non-canonical binary also round-trips byte-exact
prototext --descriptor $GOOGLEAPIS_DB \
    decode -a \
    stash/postal_patched.pb \
  | prototext encode \
  | diff - stash/postal_patched.pb \
  && echo byte-exact

# --- Section 8: Decompile binary descriptors with reproto ---

reproto --use-variant descriptor \
    -O stash/googleapis-src \
    $GOOGLEAPIS_DB

# Inspect a reconstructed file
cat stash/googleapis-src/google/protobuf/timestamp.proto

# --- Section 9: Translate editions descriptor to proto2 ---

# Compile the editions fixture to a descriptor set
protoc \
    --descriptor_set_out=stash/editions_rendering.pb \
    --include_imports \
    -Ireproto/src/reproto/tests/fixtures \
    reproto/src/reproto/tests/fixtures/editions_rendering.proto

# Reconstruct as editions (default — no flag)
reproto --use-variant descriptor \
    --output-root=stash/out_editions \
    stash/editions_rendering.pb
cat stash/out_editions/editions_rendering.proto

# Reconstruct as proto2 (--force-proto2-output)
reproto --use-variant descriptor \
    --force-proto2-output \
    --output-root=stash/out_proto2 \
    stash/editions_rendering.pb
cat stash/out_proto2/editions_rendering.proto
