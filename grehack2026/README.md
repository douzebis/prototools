<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# GreHack 2026 — prototools talk and workshop

Material for presenting prototools at GreHack 2026, and for the hands-on
workshop that follows the talk.

Workshop participants run the tools from a container image, on their own
laptop: Linux (x86-64 or arm64) or macOS (Apple silicon or Intel). How that
image is produced is specified in
`docs/specs/0374-a-workshop-image-for-every-laptop.md`; the participant
setup instructions will live beside this file.

## Rehearsing the demo

The demo runs in three windows, each in its own directory, each in the
demo's own Nix shell (spec 0394):

```sh
cd grehack2026      && nix-shell   # Alice: teleprompt grehack2026.sh
cd grehack2026/eve  && nix-shell   # Eve:   life-server
cd grehack2026/bob  && nix-shell   # Bob:   life-client
```

Every tool in these shells is built by Nix from committed sources, as in
the workshop image; nothing comes from `target/release/`. The running
order is in `synopsis.md`.
