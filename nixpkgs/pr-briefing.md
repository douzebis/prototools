# Briefing: nixpkgs PR `prototext: init at 0.3.0`

Notes for the maintainer before marking the PR ready, so that reviewer
questions can be answered first-hand (nixpkgs automation/AI policy: the
contributor must understand the change and answer without relaying to an
AI tool).

## What the recipe does, line by line

- **`src`**: the `v0.3.0` tag of douzebis/prototools. douzebis is a fork of
  ThalesGroup/prototools on GitHub, but it is where releases are made.
- **`cargoBuildFlags`/`cargoTestFlags = [ "-p" "prototext" ]`**: the
  repository is a Cargo workspace (prototext, protolens, three Python
  extensions, libraries). `-p prototext` builds and tests that one crate
  and the workspace crates it uses (prototext-core, prototext-graph,
  prototext-schema, prototools-complete). `cargoHash` covers the whole
  workspace's `Cargo.lock`, which is one file for all of them.
- **`nativeCheckInputs = [ protobuf ]`**: some roundtrip tests compare
  prototext's decoding with `protoc --decode`. Without protoc they print
  `SKIP` and pass, so this only makes them run.
- **`postInstall`**, behind `canExecute` (cross builds cannot run the
  binary):
  - completions: `PROTOTEXT_COMPLETE=<shell> prototext` prints the script
    (clap_complete's `CompleteEnv`). For bash, the script is upstream's own
    (`prototools-complete` crate): it passes the raw command line to the
    binary instead of bash's word-split one, so `--opt=value` and paths
    with `:` complete correctly. Nothing is patched.
  - man page: `prototext-gen-man` (a second binary of the crate, like yb's
    `yb-gen-man`) writes `prototext.1`; its output does not depend on the
    date, locale or time zone.
- **`versionCheckHook`**: `prototext --version` prints `prototext 0.3.0`.
- **93 tests** run in the check phase (x86_64-linux, nixpkgs master
  `62ad4c2`, 170 s), none skipped.

## Questions a reviewer may ask

- **"The repository contains binary files (`*.pb`, `*.rkyv`); are they
  prebuilt artifacts?"** They are data, not code: protobuf descriptor sets
  (compiled from the well-known types and three test schemas) and a scoring
  graph of the well-known types, which the binary embeds. Upstream commits
  them so a build needs neither `protoc` nor upstream's Python tooling, and
  its CI regenerates them on every run and fails if the committed copies
  differ (`prototext-fixtures-check`, `wkt-prebuilt-check`).
- **"Why not the ThalesGroup repository, as in #525997?"** Releases and CI
  live on douzebis; ThalesGroup mirrors it.
- **"Why one package, not `prototools`?"** Following the review of #525997:
  protoscan, reproto and protolens come as separate PRs, protoscan next
  (being rewritten in Rust upstream, so it will have this same shape).
- **"`prototext-gen-man` ends up in `bin/`."** As with yb. It could be
  removed after use in `postInstall` if the reviewer prefers.

## What was checked before opening

- Built from the tag with the real hashes: on nixos-26.05 (upstream's pin)
  and on nixpkgs master `62ad4c2`.
- To do in the nixpkgs checkout: `nix-build -A prototext`, `nixpkgs-review
  rev HEAD`, then run `result/bin/prototext` on a file.
