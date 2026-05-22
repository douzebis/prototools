# ============================================================
# prototools demo — follows docs/tutorial.md
# Usage:  ./prompt 01-tutorial.sh
# ============================================================

# --- Section 1: Setup ---

# Confirm the tools are available
prototext --version
reproto --version

# --- Section 2: Build the googleapis schema DB (one-time) ---

export GOOGLEAPIS_DB=$(nix-build -A googleapis-db --no-out-link)/googleapis.desc

# --- Section 2: Decode a sample message (auto-inference, no --type needed) ---

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
prototext --descriptor $GOOGLEAPIS_DB decode -O /tmp/decoded \
    $INST/google/type/PostalAddress.pb \
    $INST/google/cloud/compute/v1beta/UsableSubnetwork.pb

# --- Section 4: Build a schema DB from scratch (WKT example) ---

# 4a — compile WKT .proto files into a FileDescriptorSet
protoc \
    --descriptor_set_out=/tmp/wkt.pb \
    --include_imports \
    google/protobuf/descriptor.proto \
    google/protobuf/timestamp.proto \
    google/protobuf/duration.proto \
    google/protobuf/any.proto

# 4b — build the schema DB with reproto
reproto \
    --build-schema-db=/tmp/wkt.desc \
    /tmp/wkt.pb

# 4c — decode the descriptor itself (self-referential: wkt.pb IS a FileDescriptorSet)
prototext --descriptor /tmp/wkt.desc \
    decode /tmp/wkt.pb | head -12

# --- Section 5: Annotations and non-canonical encoding ---

INST=$(dirname $GOOGLEAPIS_DB)/instances
prototext --descriptor $GOOGLEAPIS_DB \
    decode -a \
    $INST/google/type/PostalAddress.pb

# Save annotated output, then inject a non-canonical over-hanging byte
prototext --descriptor $GOOGLEAPIS_DB \
    decode -a \
    $INST/google/type/PostalAddress.pb > /tmp/PostalAddress.textpb

# Patch: change  #@ int32 = 1  to  #@ int32 = 1; val_ohb: 1
sed -i 's/#@ int32 = 1$/#@ int32 = 1; val_ohb: 1/' /tmp/PostalAddress.textpb

# Re-encode with the patched annotation
prototext encode < /tmp/PostalAddress.textpb > /tmp/postal_patched.pb

# Compare first bytes: canonical vs patched (81 00 instead of 01)
hexdump -C $INST/google/type/PostalAddress.pb | head -1
hexdump -C /tmp/postal_patched.pb | head -1

# Decode the patched file — val_ohb is preserved, score reflects non-canonical byte
prototext --descriptor $GOOGLEAPIS_DB \
    decode -a \
    /tmp/postal_patched.pb | head -6

# --- Section 6: Lossless round-trip ---

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
    /tmp/postal_patched.pb \
  | prototext encode \
  | diff - /tmp/postal_patched.pb \
  && echo byte-exact

# --- Section 7: Decompile binary descriptors with reproto ---

reproto --use-variant descriptor \
    -O /tmp/googleapis-src \
    $GOOGLEAPIS_DB

# Inspect a reconstructed file
cat /tmp/googleapis-src/google/protobuf/timestamp.proto

# --- Section 8: Translate editions descriptor to proto2 ---

# Compile the editions fixture to a descriptor set
protoc \
    --descriptor_set_out=/tmp/editions_rendering.pb \
    --include_imports \
    -Ireproto/src/reproto/tests/fixtures \
    reproto/src/reproto/tests/fixtures/editions_rendering.proto

# Reconstruct as editions (default — no flag)
reproto --use-variant descriptor \
    --output-root=/tmp/out_editions \
    /tmp/editions_rendering.pb
cat /tmp/out_editions/editions_rendering.proto

# Reconstruct as proto2 (--force-proto2-output)
reproto --use-variant descriptor \
    --force-proto2-output \
    --output-root=/tmp/out_proto2 \
    /tmp/editions_rendering.pb
cat /tmp/out_proto2/editions_rendering.proto
