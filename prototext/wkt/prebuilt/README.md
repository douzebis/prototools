<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# prototext/wkt/prebuilt

The WKT scoring graph every build embeds, committed to git: prototext's
`build.rs` copies it in, with no feature flag and no tool to run (specs
0401 S2, 0405 S2). The workspace build in `nix/rust.nix`, the crates.io
package and the nixpkgs recipe all use it, so no build has to run reproto
first.

## Files

- `wkt.rkyv` — Hopcroft scoring graph for all Well-Known Types
- `wkt_index.rkyv` — lazy FDS index for all Well-Known Types

Both files are in little-endian rkyv format and are platform-independent.

## Kept in sync by `ci`

`nix-build -A wkt-prebuilt-check` (part of `ci`) regenerates the graph from
the code as it is (`wkt-rkyv`) and compares it with these files. When they
differ, it fails and prints the refresh:

```bash
cp $(nix-build -A wkt-rkyv)/{wkt,wkt_index}.rkyv prototext/wkt/prebuilt/
```

They change when the rkyv version in `Cargo.toml`, the Hopcroft algorithm
in the `scoring-graph` crate, or the WKT `.proto` sources listed in
`wkt/SOURCES` change. Commit the refreshed files with the change that
caused them.

## When the scoring-graph format version changes

Nothing special: a `GRAPH_VERSION` bump
(`prototext-graph/src/build_scoring_graph/serial.rs`) is refreshed like any
other change. `wkt-rkyv` no longer waits for the tests, which embed the old
graph and fail until the refresh, so `nix-build -A wkt-rkyv` works across the
bump (spec 0401 S3, test plan 3). Check the version byte afterwards:
`xxd -s 8 -l 1 -p prototext/wkt/prebuilt/wkt.rkyv`.
