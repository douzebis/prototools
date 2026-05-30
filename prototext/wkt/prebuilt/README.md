<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# prototext/wkt/prebuilt

Pre-generated WKT scoring graph files, committed to git for use by the
nixpkgs `package.nix` build (`--features wkt-db,prebuilt-wkt`).

## Files

- `wkt.rkyv` — Hopcroft scoring graph for all Well-Known Types
- `wkt_index.rkyv` — lazy FDS index for all Well-Known Types

Both files are in little-endian rkyv format and are platform-independent.

## When to regenerate

Regenerate whenever any of the following change:

- The rkyv version in `Cargo.toml` (version bump changes the binary format)
- The Hopcroft algorithm in the `scoring-graph` crate
- The WKT `.proto` sources listed in `wkt/SOURCES`

## How to regenerate

From the repository root, inside the dev-shell:

```bash
nix-build -A prototext 2>&1 | tee /tmp/nix-build-prototext.log
store=$(grep -oP '/nix/store/\S+-wkt-rkyv(?=/)' /tmp/nix-build-prototext.log | head -1)
cp "$store/wkt.rkyv"       prototext/wkt/prebuilt/wkt.rkyv
cp "$store/wkt_index.rkyv" prototext/wkt/prebuilt/wkt_index.rkyv
```

Commit the updated files as part of the same changeset that triggered the
regeneration.
