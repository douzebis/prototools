<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

Beyond protoc --decode: Schema Inference, Lossless Decoding, and Descriptor Archaeology

Every gRPC engineer eventually faces a binary .pb blob of unknown type, a compiled descriptor with no .proto source, or an editions descriptor a downstream toolchain cannot consume. Standard tooling stops short: protoc --decode requires the original descriptor and exact type name, silently discards non-canonical bytes, crashes on malformed input.

prototools is a pair of open-source CLI tools that fill this gap.

prototext decodes binary protobuf with or without a schema. Supply a descriptor DB, it automatically infers the message type — ranking all candidates from a corpus of thousands of types in seconds. It also preserves every non-canonical byte via inline annotations and round-trips byte-exact, even for malformed protobufs.

reproto reconstructs compilable .proto source files from any FileDescriptorSet, handling proto2, proto3, and editions. It also builds the indexed descriptor databases that power prototext's auto-inference.

The talk is built around a live terminal demo.