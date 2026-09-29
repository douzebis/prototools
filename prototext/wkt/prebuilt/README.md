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

## When the scoring-graph format version changes

The procedure above does not work across a `GRAPH_VERSION` bump
(`prototext-graph/src/build_scoring_graph/serial.rs`). The workspace tests
embed *this* prebuilt file, the graph extension that builds `wkt-rkyv` is
gated on those tests, and the loader refuses the old version — so the build
never reaches `wkt-rkyv`. Bootstrap the first file of the new version
locally, from the working tree (spec 0371, measured outcome):

```bash
# The graph extension, built from this tree, laid out as a package that
# shadows the installed one.
cargo build --profile quick -p prototext_graph_lib
mkdir -p /tmp/wkt-boot/pyext/prototext_graph_lib /tmp/wkt-boot/out
inst=$(python3 -c "import prototext_graph_lib,os;print(os.path.dirname(prototext_graph_lib.__file__))")
cp "$inst/__init__.py" /tmp/wkt-boot/pyext/prototext_graph_lib/
cp target/quick/libprototext_graph_lib.so \
   /tmp/wkt-boot/pyext/prototext_graph_lib/prototext_graph_lib.so

# The wkt-rkyv recipe from default.nix, with reproto's own interpreter.
inc=$(dirname "$(dirname "$(command -v protoc)")")/include
protoc -I"$inc" --descriptor_set_out=/tmp/wkt-boot/out/wkt.desc --include_imports \
    $(grep -v '^$' prototext/wkt/SOURCES)
PP=$(grep '^PYTHONPATH=' python.env | cut -d= -f2-)
PY=$(grep '^PYTHON_INTERPRETER=' python.env | cut -d= -f2-)
PYTHONPATH=/tmp/wkt-boot/pyext:$PP $PY -m reproto.cli \
    --schema-db-out=/tmp/wkt-boot/out/wkt-db.desc --emit-extension-ranges \
    -I /tmp/wkt-boot/out -O /tmp/wkt-boot/out/wkt-db/proto wkt.desc
cp /tmp/wkt-boot/out/wkt-db/hopcroft.rkyv prototext/wkt/prebuilt/wkt.rkyv
cp /tmp/wkt-boot/out/wkt-db/index.rkyv    prototext/wkt/prebuilt/wkt_index.rkyv
```

Check the version byte (`xxd -s 8 -l 1 -p prototext/wkt/prebuilt/wkt.rkyv`)
and `cmp -l` against the old file: the difference should be exactly what the
format change explains. Once committed, the ordinary procedure works again.
