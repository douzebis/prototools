<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# Changelog

## [Unreleased]

## 0.3.0 — 2026-10-10

The first release with one version for every tool, crate and Python
package, from github.com/douzebis/prototools.

### New

- **protolens**, an interactive terminal browser for binary protobufs:
  type inference with per-range heat cues, the raw bytes behind every line,
  overrides, search, export, and guided scripts.
- **prototext**: `is-canonical`; whole-file scoring; a truncated message
  says which fields it is missing, and a truncated field keeps its declared
  type.
- **reproto**: reads a blob as a root, and applies the FDP plugin at every
  parse.
- **protoscan**: asks the schema where a descriptor ends.

### Changed

- Bash completion for prototext and protolens no longer depends on bash's
  word splitting: arguments containing `:` or `=`, quoted paths and escaped
  spaces complete correctly, and a completion never corrupts the line.
- Scoring: a bool is any varint, and a packing mismatch scores net zero.
- The builds need no `protoc` or `reproto`: the descriptors and the WKT
  scoring graph they used to generate are committed.

## 0.2.1 — 2026-06-19

prototext, protoscan and reproto, as published on crates.io and PyPI.
