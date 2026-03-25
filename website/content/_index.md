+++
title = "prototext docs"
+++

# prototext

Lossless, bidirectional converter between binary protobuf wire format and
human-readable text.

## User documentation

- [README](readme) — Overview, installation, and usage guide
- [Man page](man-page) — Reference manual
- [Annotation format](annotation-format) — Wire annotation syntax reference

## Design documentation

- [Design](design) — Architecture, data flow, and key design decisions
- [Performance](performance) — Benchmark results and optimisation history
- [protoc --decode compatibility](protoc-decode-compatibility) — Compatibility
  analysis with `protoc --decode` output
- [protoc --decode anomalous input](protoc-decode-anomalous-input) — How
  protoc behaves on malformed or non-canonical input
- [Fixture coverage model](fixture-macro-reference) — Fixture macro reference
- [Benchmark process](bench-process) — Performance benchmarking methodology

## Specs

| Spec | Title | Status |
|------|-------|--------|
| [0003](specs/0003-cli) | `prototext` CLI design | implemented |
| [0004](specs/0004-enum-annotation-syntax) | Enum annotation syntax and `#@` delimiter | implemented |
| [0006](specs/0006-fixture-coverage-model) | Fixture coverage model and gap-filling fixtures | implemented |
| [0007](specs/0007-string-bytes-encoding-policy) | String and bytes field encoding policy | implemented |
| [0008](specs/0008-nan-encoding) | NaN encoding for float and double fields | implemented |
| [0009](specs/0009-protocraft-and-e2e-tests) | Protocraft port and end-to-end test suite | implemented |
| [0010](specs/0010-protoc-compatibility) | protoc --decode compatibility for canonical wire input | implemented |
| [0011](specs/0011-prost-reflect-schema) | Replace hand-rolled schema with prost-reflect | implemented |
| [0012](specs/0012-extension-field-rendering) | Extension field rendering | implemented |
| [0013](specs/0013-protocraft-schema-aware-builder) | Protocraft schema-aware builder | implemented |
