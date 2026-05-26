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

demo/header "1. Setup"

# Meet our two tools.
prototext --version && reproto --version

# Build the googleapis schema DB — we will use it throughout.
export GOOGLEAPIS_DB=$(nix-build -A googleapis-db --no-out-link)/googleapis.desc
export GOOGLEAPIS_PBS=$(dirname $GOOGLEAPIS_DB)/instances
export GOOGLEAPIS_DESCS=$(dirname $GOOGLEAPIS_DB)/reproto-out

# Pre-clean stash output dirs to avoid stale files from previous runs.
rm -rf stash/*

demo/header "2. Protobufs are everywhere"

# \
#                                                                                \
# "I spent 2.5 years at Google, and most of what I did was pushing one protobuf  \
#  from one place to another."                                                   \
#   — Hacker News, 2018, anonymous ex-Googler (item 18189458)                    \
#
# \
#                                                                                \
# And the vendor agrees:                                                         \
# "Protocol buffers are the most commonly-used data format at Google.  They are  \
#  used extensively in inter-server communications as well as for archival       \
#  storage of data on disk."                                                     \
#   — protobuf.dev/overview, Google                                              \
#
# \
#                                                                                \
# Protobufs are compact (binary), self-describing (with a schema), and           \
# language-neutral — the lingua franca of microservice communication.            \
#                                                                                \
# So when something goes wrong on the wire — a hidden field, a tampered value,   \
# an anomalous encoding — standard tools won't show it.  They normalise the      \
# input before you ever see it.  You need a tool that reads what was actually    \
# sent, not what the SDK chose to show you.                                      \
#

demo/header "3. What's inside a protobuf?"

# Our running example: a postal address, serialised as a protobuf.
ls -lh $GOOGLEAPIS_PBS/google/type/PostalAddress.pb

# Raw bytes — this is what travels on the wire.
hexdump -C $GOOGLEAPIS_PBS/google/type/PostalAddress.pb | tee /dev/tty | vim -

# Let's decode it as a protobuf:
prototext decode --raw \
    $GOOGLEAPIS_PBS/google/type/PostalAddress.pb \
    | tee /dev/tty | vim +'set ft=pbtxt' -
# 👆 No schema yet: field numbers and wire types, but no names.

# With the right schema: the message becomes readable.
prototext --descriptor-set $GOOGLEAPIS_DB \
    decode --type google.type.PostalAddress \
    $GOOGLEAPIS_PBS/google/type/PostalAddress.pb \
    | tee /dev/tty | vim +'set ft=pbtxt' -

# Here is the schema that unlocked it — the .proto source.
vim $GOOGLEAPIS_DESCS/google/type/postal_address.proto

demo/header "4. Schema auto-inference"

# \
#                                                                                \
# The googleapis schema DB bundles thousands of compiled schemas —               \
# one per message type across the entire Google Cloud API surface.               \
# prototext scores every type in the DB against the binary and picks             \
# the best match, consolidating field coverage, wire type matches,               \
# and value plausibility.                                                        \
#

# Watch prototext infer the schema with no hint from us.
prototext --descriptor-set $GOOGLEAPIS_DB \
    decode $GOOGLEAPIS_PBS/google/type/PostalAddress.pb \
    | tee /dev/tty | vim +'set ft=pbtxt' -
# \
# 👆 Notice the score at the top of the output — the higher, the better the fit. \
# The googleapis DB contains thousands of types; prototext scores them all and   \
# picks the best candidate.                                                      \
#
# \
#                                                                                \
# Let's try another example.                                                     \
#
prototext --descriptor-set $GOOGLEAPIS_DB \
    decode \
    $GOOGLEAPIS_PBS/google/cloud/compute/v1beta/UsableSubnetwork.pb
# 👆 prototext finds a tie and asks us to be explicit.

# With --type the ambiguity is resolved.
prototext --descriptor-set $GOOGLEAPIS_DB \
    decode --type google.cloud.compute.v1beta.UsableSubnetwork \
    $GOOGLEAPIS_PBS/google/cloud/compute/v1beta/UsableSubnetwork.pb \
    | tee /dev/tty | vim +'set ft=pbtxt' -

demo/header "5. Non-canonical protobufs"

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
vim $GOOGLEAPIS_DESCS/google/type/postal_address.proto
# \
#                                                                                \
# We are going to slip a secret value before the real organization field,        \
# hidden in plain sight inside a valid protobuf.                                 \
#

# Craft postal_hidden.pb: slip a secret organization field before the real one.
# (The #@ annotations are prototext's wire-encoding hints — field number and type.)
prototext --descriptor-set $GOOGLEAPIS_DB \
    decode -a $GOOGLEAPIS_PBS/google/type/PostalAddress.pb \
  | sed '/^organization: "S3NS"/i organization: "Entrance secret PIN code: 666*"  #@ string = 11' \
  | prototext encode > stash/postal_hidden.pb

# Let's look at the resulting protobuf:
hexdump -C stash/postal_hidden.pb | tee /dev/tty | vim -
# 👆 The hidden field is right there in the binary.

# Standard decoder (protoc): only sees the last occurrence — secret gone.
protoc \
    --proto_path $GOOGLEAPIS_DESCS \
    --decode google.type.PostalAddress \
    google/type/postal_address.proto \
    < stash/postal_hidden.pb \
    | tee /dev/tty | vim +'set ft=pbtxt' -

# prototext decode: preserves all contents.
prototext --descriptor-set $GOOGLEAPIS_DB \
    decode stash/postal_hidden.pb \
    | tee /dev/tty | vim +'set ft=pbtxt' -
# 👆 Both occurrences visible: the secret first, then the real value.
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

# Let's look at what has been produced:
hexdump -C $GOOGLEAPIS_PBS/google/type/PostalAddress.pb | head -1
hexdump -C stash/postal_patched.pb | head -1
# 👆 Spot the difference: one extra byte — `01` has become `81 00`.

prototext --descriptor-set $GOOGLEAPIS_DB \
    decode -a \
    stash/postal_patched.pb \
    | tee /dev/tty | vim +'set ft=pbtxt' -
# \
# 👆 prototext -a flags it: look for val_ohb on the revision field.              \
# (val_ohb = over-hung byte — the extra byte that shouldn't be there.)           \
#
# \
#                                                                                \
# protoc is oblivious: it decodes the patched protobuf as if nothing happened.   \
# The OHB disappears without a trace.                                            \
#

# protoc decode: the OHB is silently normalised — the revision field looks clean.
protoc \
    --proto_path $GOOGLEAPIS_DESCS \
    --decode google.type.PostalAddress \
    google/type/postal_address.proto \
    < stash/postal_patched.pb \
    | tee /dev/tty | vim +'set ft=pbtxt' -

# prototext round-trip: the over-hung byte is preserved exactly.
prototext --descriptor-set $GOOGLEAPIS_DB \
    decode -a \
    stash/postal_patched.pb \
  | prototext encode \
  | diff - stash/postal_patched.pb \
  && echo byte-exact

demo/header "6. Building a scoring database"

# \
#                                                                                \
# Quick vocabulary recap:                                                        \
#   protobuf   — a binary-encoded message on the wire                            \
#   schema     — the .proto definition that names fields and assigns types       \
#   descriptor — a .proto compiled into a binary protobuf (FileDescriptorProto)  \
#
# \
#                                                                                \
# A .proto source file compiles into a descriptor — a FileDescriptorProto.       \
# postal_address.pb is exactly that: the PostalAddress schema, serialised as     \
# a protobuf.  prototext can decode it:                                          \
#

prototext --descriptor-set $GOOGLEAPIS_DB \
    decode --type google.protobuf.FileDescriptorProto \
    $GOOGLEAPIS_DESCS/google/type/postal_address.pb \
    | tee >((head -10 && echo ...)> /dev/tty) | vim +'set ft=pbtxt' -
# \
# 👆 The schema for FileDescriptorProto is defined in descriptor.proto —         \
# which is itself a .proto file.  Self-referential!                              \
#
# \
#                                                                                \
# From descriptors, reproto can build a scoring DB — a compiled schema with      \
# a scoring graph baked in.  --build-schema-db produces it from any seed.        \
#

# Build a scoring DB: 8 standard OperationMetadata + Cloud Functions v2.
# Cloud Functions v2 has a richer shape: extra fields for build stages,
# source token, build name, and operation type.
reproto \
    --build-schema-db stash/opmeta.desc \
    --emit-scoring-html stash/opmeta.html \
    --use-variant descriptor \
    -I $GOOGLEAPIS_DESCS \
    --seed 'desc:.google.cloud.apigeeregistry.v1.OperationMetadata' \
    --seed 'desc:.google.cloud.apihub.v1.OperationMetadata' \
    --seed 'desc:.google.cloud.apphub.v1.OperationMetadata' \
    --seed 'desc:.google.cloud.auditmanager.v1.OperationMetadata' \
    --seed 'desc:.google.cloud.baremetalsolution.v2.OperationMetadata' \
    --seed 'desc:.google.cloud.batch.v1.OperationMetadata' \
    --seed 'desc:.google.cloud.batch.v1alpha.OperationMetadata' \
    --seed 'desc:.google.cloud.beyondcorp.appconnections.v1.AppConnectionOperationMetadata' \
    --seed 'desc:.google.cloud.functions.v2.OperationMetadata' \
    $GOOGLEAPIS_DB

# Auto-infer a Cloud Functions deployment operation — unique match, score 26.
prototext --descriptor-set stash/opmeta.desc \
    decode $GOOGLEAPIS_PBS/google/cloud/functions/v2/OperationMetadata.pb \
    | tee /dev/tty | vim +'set ft=pbtxt' -
# 👆 Score 26, unique match: functions/v2 has extra fields (stages, build_name,
# source_token, operation_type) that distinguish it from the other 8 types.
# \
#                                                                                \
# Now try a batch OperationMetadata — same 7-field shape as 8 of the 9 types.    \
# prototext cannot pick a winner: all 8 score equally.                           \
#
prototext --descriptor-set stash/opmeta.desc \
    decode $GOOGLEAPIS_PBS/google/cloud/batch/v1/OperationMetadata.pb \
    | tee /dev/tty | vim +'set ft=pbtxt' -
# 👆 8-way tie at score 8: the wire bytes are consistent with all 8 standard     \
# OperationMetadata types.  This is expected — they are wire-identical.          \
# The scoring graph cannot distinguish what the schema cannot distinguish.       \
# \
#                                                                                \
# The raw scoring graph encodes every distinct wire shape in the seed set.       \
# Open it: each seed type is its own amber node, even the wire-identical ones.   \
#
# The scoring graph: open in browser.
xdg-open stash/opmeta.html
# \
#                                                                                \
# Graph legend:                                                                  \
#   nodes  — amber/gold = top-level message; 5 brightness steps (Fibonacci):     \
#               1 type → darkest  2 → dim  3-4 → mid  5-7 → bright  8+ → gold    \
#             blue      = internal sub-message (no top-level name)               \
#   edges  — blue       = optional field                                         \
#             light blue = repeated field                                        \
#             purple    = packed repeated field                                  \
#             red       = required field (proto2 only)                           \
#   label  — short type name; "+N" suffix if N extra types collapsed into it     \
#
# \
#                                                                                \
# Many nodes are structurally identical: 8 teams defined their own               \
# OperationMetadata with the same 7 fields.  They are separate nodes here,       \
# but they could be merged — a binary consistent with one is consistent with     \
# all.  Hopcroft minimisation collapses them automatically.                      \
#

# Hopcroft graph: 8 OperationMetadata states collapsed into 1 amber+8 node.
xdg-open stash/opmeta-hopcroft.html
# \
#                                                                                \
# To see deduplication at work on a small example: IpRules (5 → 4 nodes).        \
# Allowed and Denied have opposite semantics but identical wire structure:       \
#   message Allowed { repeated IpRule ip_rules = 1; }                            \
#   message Denied  { repeated IpRule ip_rules = 1; }                            \
# Hopcroft merges them automatically.                                            \
#

# IpRules toy example: 5 nodes raw, 4 nodes after Hopcroft.
reproto -q \
    --build-schema-db stash/iprules.desc \
    --emit-scoring-html stash/iprules.html \
    --use-variant descriptor \
    -I $GOOGLEAPIS_DESCS \
    --seed 'desc:.google.cloud.securitycenter.v2.Allowed' \
    --seed 'desc:.google.cloud.securitycenter.v2.Denied' \
    --seed 'desc:.google.cloud.securitycenter.v2.IpRule' \
    --seed 'desc:.google.cloud.securitycenter.v2.IpRules' \
    google/cloud/securitycenter/v2/ip_rules.pb

xdg-open stash/iprules.html

xdg-open stash/iprules-hopcroft.html

demo/header "7. Decompiling descriptors"

# \
#                                                                                \
# Descriptors are often available — embedded as reflection data inside           \
# compiled binaries, shipped alongside gRPC services, or stored in schema        \
# registries — even when the original .proto source is not.                      \
#                                                                                \
# reproto turns a descriptor back into readable .proto source.  Useful when      \
# you need to write code that audits or processes the corresponding protobufs.   \
#

# First, let's decode the PostalAddress descriptor itself — a binary .pb file
# that encodes the schema of PostalAddress as a FileDescriptorProto.
prototext decode $GOOGLEAPIS_DESCS/google/type/postal_address.pb \
    | tee >({ head -10; echo '...'; } > /dev/tty) | vim +'set ft=pbtxt' -

# Decompile the PostalAddress descriptor back to .proto source.
reproto -q \
    -O stash/reproto-out \
    --use-variant descriptor \
    $GOOGLEAPIS_DESCS/google/type/postal_address.pb
# Let's see the result.
cat stash/reproto-out/google/type/postal_address.proto \
    | tee /dev/tty | vim +'set ft=proto' -
# \
# 👆 Human-readable .proto source, recovered from the binary descriptor.
# \
#                                                                                \
# reproto can decompile an entire schema DB — thousands of files at once.        \
#

# Decompile the entire googleapis DB: thousands of .proto files reconstructed.
reproto -O stash/googleapis-out \
    --use-variant descriptor \
    -I $GOOGLEAPIS_DESCS .
# \
#                                                                                \
# Browse the reconstructed sources in VSCode.  The proto language server         \
# understands the import graph: Go to Definition navigates across files,         \
# find-all-references works, and the full type hierarchy is explorable.          \
#

code --reuse-window stash/googleapis-out
# \
#                                                                                \
# What if some descriptors are missing — imported files not available?           \
# reproto handles incomplete inputs gracefully: missing imports are noted        \
# as orphan comments (///) in the output, so nothing is silently dropped.        \
# The --prune flag makes this explicit and controlled.                           \
#

demo/header "8. Seeding and pruning"

# \
#                                                                                \
# Thousands of files — but Simon's audit team does not need all of googleapis.   \
# They only care about one message: AuditLog, the record of every Cloud API      \
# call.  Pass its descriptor as the seed: reproto pulls only its transitive      \
# closure.                                                                       \
#

# Seed on AuditLog: thousands of files collapse to 8.
reproto -q \
    -O stash/audit-seed \
    --use-variant descriptor \
    -I $GOOGLEAPIS_DESCS \
    google/cloud/audit/audit_log.pb
find stash/audit-seed -name '*.proto' | sort
# \
# 👆 The transitive closure: every file AuditLog depends on, nothing more.
# \
#                                                                                \
# 8 files instead of thousands.  Let's browse the decompiled AuditLog source.    \
#
code --reuse-window stash/audit-seed/google/cloud/audit/audit_log.proto
# \
#                                                                                \
# But Simon's tool only decodes payloads — it never needs to interpret RPC       \
# error statuses.  Prune google/rpc/status.proto: reproto drops the file and     \
# orphans the field that referenced it, leaving a /// comment so nothing is      \
# silently lost.                                                                 \
#

# Prune status.proto: 8 files become 7, AuditLog.status becomes a /// orphan.
reproto -q \
    -O stash/audit-pruned \
    --use-variant descriptor \
    -I $GOOGLEAPIS_DESCS \
    --prune 'file:google/rpc/status.proto' \
    google/cloud/audit/audit_log.pb

find stash/audit-pruned -name '*.proto' | sort
# \
#                                                                                \
# The orphaned field is preserved as a /// comment — not silently dropped.       \
# Simon's team can see exactly what was cut and why.                             \
#

code --reuse-window stash/audit-pruned/google/cloud/audit/audit_log.proto

demo/header "Conclusion"

# \
#                                                                                \
# prototools gives you:                                                          \
#   — a forensic decoder that preserves wire anomalies standard tools hide       \
#   — a schema DB that infers protobuf types without knowing the .proto source   \
#   — a decompiler that recovers .proto sources from binary descriptors          \
#   — a schema DB builder that collapses structurally equivalent types           \
#   — a scalpel for extracting exactly the schema slice your tool needs          \
#

# THE END




# 👆 Intentionally adding a few newlines sentinel before exiting