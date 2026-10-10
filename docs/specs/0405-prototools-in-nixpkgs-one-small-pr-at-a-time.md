<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0405 — prototools in nixpkgs, one small PR at a time

Status: draft
App: nix packaging (prototext first; protoscan, reproto, protolens later)
Refs: docs/specs/0406-bash-completion-from-the-raw-command-line.md
      (S3: done first, so the recipe installs completions unpatched);
      docs/specs/0402-a-nixpkgs-friendly-build.md (S9–S10, the upstream
      draft and the overlay, which this spec replaces);
      docs/specs/0104-nixpkgs-pr1-review-response.md (the review of
      NixOS/nixpkgs#525997, the PR this spec closes);
      ../yb/nixpkgs/README.md and yb's spec 0029 (the staging model this
      spec copies)

## Background

NixOS/nixpkgs#525997, "prototools: init at 0.2.0", has been open since
May 2026, and nothing has happened on it since June 21. All 60 review
threads are resolved, but nobody has approved it. Its reviewer, Gaétan
Lepage (GaetanLepage), a nixpkgs committer, found it "incredibly complex
for not much" and advises splitting it into several PRs.

The complexity comes from our repository, not from nixpkgs:

- **One package for two tools in two languages.** A `prototools` package
  joins the Rust CLI prototext and the Python CLI protoscan with
  `symlinkJoin`.
- **A protoc step.** `prototext/build.rs` copies four `.pb` files from
  `prototext/fixtures/prebuilt/`, which git ignores. So the recipe needs
  a `fixtures` derivation that runs `protoc` four times, and a
  `patchPhase` to copy its output.
- **Feature flags.** The recipe sets `buildNoDefaultFeatures` and
  `--features wkt-db,prebuilt-wkt`. Without `prebuilt-wkt`, `build.rs`
  runs `protoc` and `reproto`, which a nixpkgs build cannot do.
- **A patched bash completion.** The recipe pipes `PROTOTEXT_COMPLETE=bash`
  through `sed` to work around two `clap_complete` quirks. yb's review
  asked for that kind of fix upstream.
- **Hand-built Python extensions.** fdp-scan and prototext-codec declare
  hatchling as their build backend, and the recipe runs `cargo build` in
  `preBuild` and copies the `.so` by hand. nixpkgs builds pyo3 extensions
  with maturin and `maturinBuildHook`.

Two more problems:
- **It fetches from the wrong repository.** The PR fetches from
  ThalesGroup/prototools. douzebis/prototools is a fork on GitHub, but in
  practice it is upstream: releases, CI, the workshop image and
  `meta.homepage` (spec 0402 S4) all live there.
- **The versions disagree.** prototext is 0.2.1, protolens 0.1.0,
  prototext-core 0.3.0, the Python packages 0.2.1, and the latest tag,
  `prototext-v0.2.1`, is months behind `main`.

yb went through the same process and its packages are in nixpkgs:
NixOS/nixpkgs#514826 was merged, and #572336 is open. Its model is the
template here: the files under `nixpkgs/` are exactly what a PR submits,
and CI builds them from the local tree.

### What the tools are

| Tool | Language | Depends on |
|---|---|---|
| prototext | Rust CLI | prototext-core |
| protolens | Rust CLI | prototext-core, the tree-sitter textproto grammar; Neovim and buf for its editor key |
| protoscan | Python CLI today, Rust after spec 0407 (S9) | fdp-scan (pyo3) today; the fdp-scan Rust crate after |
| reproto | Python CLI | prototext-codec, prototext-graph, fdp-scan (pyo3); the tree-sitter textproto Python extension |

**Names.** Every name is free in nixpkgs master (checked 2026-10-10):
`prototext`, `protolens`, `protoscan` and `reproto` under
`pkgs/by-name`, and `prototext-codec`, `fdp-scan` and `prototext-graph`
under `python-modules`. Two of our names are taken upstream by unrelated
projects: `protolens` on crates.io (chunhuitrue/protolens) and `reproto`
on PyPI (ys1231/reproto). That is why our reproto ships on PyPI as
`prototext-reproto`.

## Goals

- **G1.** The first PR is **`prototext: init at <version>`**: one file,
  `pkgs/by-name/pr/prototext/package.nix`, as plain and idiomatic as
  yb's. Every complication above is removed upstream, not worked around
  in the recipe.
- **G2.** The staged recipe cannot rot: CI builds it from the local tree
  and checks its formatting and version, as in yb.
- **G3.** The tools stay visibly one project in nixpkgs. They have one
  version, are fetched from one repository at one tag, and share one
  homepage. A later package reuses the first one's source instead of
  fetching it again.
- **G4.** A clear order for the PRs that follow, each small enough to
  review in one sitting.

## Non-goals

- **N1.** Packaging protoscan, reproto or protolens now. They come
  afterwards, one PR each (S9), each with its own spec section or spec
  once prototext is merged. Starting them first would bring back the
  size Gaétan objected to.
- **N2.** Making the staged recipe our release build, as yb does. yb is
  one crate. Our workspace has seven crates, three pyo3 extensions and
  the workshop image, and crane's single shared dependency cache is what
  keeps CI at its current speed (spec 0401). The staged recipe is built
  as well, not instead. See C1.
- **N3.** Publishing to crates.io or PyPI. They are separate channels
  with separate names: `protolens` on crates.io is taken, for instance.
- **N4.** Spec 0402 S10, the overlay: once the packages are in nixpkgs,
  an overlay adds little.

## Specification

### Constraints

- **C1. Our own build is unchanged in shape.**
  - `nix-build -A ci` stays the single local and CI target; the staged
    recipe joins it (S7) and replaces nothing.
  - The GreHack images (`grehack2026.image`, spec 0374) build and pass
    their smoke test after every step.
- **C2. The internal `prototools` package keeps working.** It imports
  our `default.nix` with its own `{ pkgs, pythonPkgs }` (nixos-26.05),
  and uses these attributes: `prototools`, `prototext`, `protolens`,
  `protoscan`, `reproto` and `prototext-codec`. Its Rust extensions take
  `prototext-core` as a Cargo git dependency, pinned by commit. Every
  step keeps those arguments, those attribute names and prototext-core's
  public API. A step that cannot is paired with an update of the
  internal package in the same cycle, which is cheap: spec 0407's Rust
  protoscan is one such step (it ends `import protoscan`).
- **C3. The internal package fetches from ThalesGroup.** It fetches the
  commit its `Cargo.lock` pins from ThalesGroup/prototools, or from the
  corporate mirror of it. So the commits it moves to have to reach
  ThalesGroup too. Today `thales/main` is 114 commits behind `main`.
  The order of a release is douzebis, then ThalesGroup, then the
  internal package. nixpkgs fetches from douzebis (S5).

### Upstream: make the recipe plain (before PR 1)

- **S1. Commit the prototext fixtures.**
  - Commit the four `.pb` files under `prototext/fixtures/prebuilt/`
    (`descriptor.pb`, `knife.pb`, `enum_collision.pb`, `message_set.pb`)
    and stop ignoring them, as `prototext/wkt/prebuilt/` already does.
    Their licensing goes in `REUSE.toml`.
  - `protoPostPatch` (default.nix) goes away.
  - A check derivation, like `wkt-prebuilt-check`, regenerates them with
    the pinned `protoc` and fails when they differ. That keeps them
    honest across nixpkgs bumps: a bump changes `descriptor.pb` as it
    changed the WKT graph (spec 0402 S2).
- **S2. The committed WKT graph is the only one.** `prototext/build.rs`
  always copies `wkt/prebuilt/*.rkyv`, so the `prebuilt-wkt` feature and
  its `cfg(not(...))` branch (which runs `protoc` and `reproto`) are
  removed. Since spec 0401 every build already embeds the committed
  graph, and `wkt-prebuilt-check` regenerates it. A plain `cargo build -p
  prototext` then needs no feature flags. Whether `wkt-db` stays a
  feature is settled at implementation: kept only if something builds
  without it.
- **S3. The bash completion needs no patch.** Spec 0406, done first:
  prototext and protolens print a bash completion script of our own,
  which installs as is, with no `sed`. The recipe installs
  `<(PROTOTEXT_COMPLETE=bash $out/bin/prototext)`.
- **S4. The man page is reproducible without help.** `prototext-gen-man`
  writes the same bytes whatever `SOURCE_DATE_EPOCH` and the locale are,
  so the recipe sets neither. Checked by generating twice under
  different values. If it already is reproducible, this is only the
  check.
- **S5. One version, one tag** (both confirmed 2026-10-10).
  - The workspace gets a single version, `workspace.package.version`,
    which every crate and `pyproject.toml` takes: **0.3.0**, one above
    the highest version in use today (prototext-core 0.3.0 is
    unpublished; crates.io has 0.2.1).
  - Spec 0402 S3 already reads every Nix version from the manifests, so
    nothing in `nix/` changes.
  - The release is the commit that completes S1–S5, tagged **`v0.3.0`**
    on douzebis/prototools. This is "the most recent commit", given a
    tag. nixpkgs packages tags: `nix-update` and the r-ryantm bot follow
    them. An untagged commit would need a `0.3.0-unstable-YYYY-MM-DD`
    version, which `versionCheckHook` cannot match against
    `prototext --version`.
  - `CHANGELOG.md` gets a `0.3.0` section.
  - Between releases, `main` carries `X.Y.Z-dev`, as yb does.

### Staging (G2)

- **S6. The staged recipe.**
  - `nixpkgs/pkgs/by-name/pr/prototext/package.nix` holds the file PR 1
    submits, nixfmt-formatted, with no SPDX header (its licensing is
    declared in `REUSE.toml`, as yb does).
  - The current staged files are deleted: the `prototools` symlinkJoin
    and the three python-modules. git history keeps them.
  - `nixpkgs/README.md` maps each staged file to its nixpkgs path and
    gives the release procedure (S8).
- **S7. CI builds it.**
  - A new attribute, `nixpkgs-staging`, `callPackage`s the staged file
    against the pinned nixpkgs. Its `src` is replaced by the local tree
    and its `cargoDeps` by `rustPlatform.importCargoLock` on
    `Cargo.lock`, so no hash has to be updated between releases.
  - `nixpkgs-staging-check` runs `nixfmt --check` and the version rule:
    the staged version equals the manifests' at a release, and is older
    while `main` carries `-dev`.
  - Both join `ci`.

  The pin is nixos-26.05, while a PR is built against nixpkgs master. The
  recipe uses only stable `buildRustPackage` interfaces, and S8 builds it
  on master before the PR is opened.

### The PRs

- **S8. PR 1: `prototext: init at 0.3.0`.**
  - The staged file, which after S1–S5 has yb's shape:

    ```nix
    rustPlatform.buildRustPackage (finalAttrs: {
      pname = "prototext";
      version = "0.3.0";
      src = fetchFromGitHub {
        owner = "douzebis";
        repo = "prototools";
        tag = "v${finalAttrs.version}";
        hash = "…";
      };
      cargoHash = "…";
      cargoBuildFlags = [ "-p" "prototext" ];
      cargoTestFlags = [ "-p" "prototext" ];
      nativeBuildInputs = [ installShellFiles ];
      postInstall = lib.optionalString (stdenv.buildPlatform.canExecute stdenv.hostPlatform) ''
        installShellCompletion --cmd prototext \
          --bash <($out/bin/prototext …) --zsh <(…) --fish <(…)
        $out/bin/prototext-gen-man $out/share/man/man1
      '';
      nativeInstallCheckInputs = [ versionCheckHook ];
      doInstallCheck = true;
      passthru.updateScript = nix-update-script { };
      meta = { description, homepage, changelog, license, maintainers = [ douzebis ], mainProgram, platforms };
    })
    ```

    No protoc, no feature flags, no `sed`, no environment variables.
  - Procedure, in a checkout of nixpkgs master:
    1. copy the staged file;
    2. `nix-update prototext` (fills `hash` and `cargoHash`);
    3. build it;
    4. run `nixpkgs-review`;
    5. open the PR;
    6. copy the hashes back into the staged file.
  - Before asking for review: a briefing in `nixpkgs/pr-briefing.md`,
    so every reviewer question can be answered firsthand (nixpkgs's
    automation/AI policy).
  - When PR 1 opens, #525997 is closed with a link to it, so its review
    history stays findable.
- **S9. The order after prototext** (each its own spec section, written
  when its turn comes):
  2. **`protoscan`, rewritten in Rust (spec 0407, to be written).**
     Today protoscan is about 40 lines of Python around
     `fdp_scan_lib.scan`, a Rust function exposed through pyo3, plus
     `descriptor_pb2` to read each blob's `name`. The rewrite:
     - moves the scanner out of `fdp-scan-pyo3` into a plain Rust crate,
       which the pyo3 wrapper and the new CLI both use;
     - makes protoscan a Rust binary (clap, prost-types for `name`, the
       same completions and man page as prototext).

     Then PR 2 has exactly prototext's shape, and protoscan no longer
     needs Python at all. **Moved ahead of the Python extensions:** with
     protoscan in Rust, fdp-scan is needed only by reproto.

     C2: the internal package does `import protoscan` in its import
     check, and gets `fdp_scan_lib` through protoscan. Both change with
     the rewrite; `fdp_scan_lib` still reaches it through reproto.
  3. **`python3Packages.fdp-scan` and `python3Packages.prototext-codec`**
     (one PR, or two if review prefers). Upstream first: both
     `pyproject.toml` move to maturin, so each recipe is the standard
     `buildPythonPackage` + `maturinBuildHook` + vendored Cargo
     dependencies. Our own build (`makePyo3Extension`, `nix/pypi.nix`)
     moves with them.
  4. **`python3Packages.prototext-graph`**, then **`reproto`**. Upstream
     first: the tree-sitter textproto grammar ships its generated
     `parser.c`, as tree-sitter grammars conventionally do, and the
     Python extension builds from the package's own build backend,
     replacing today's separate `treeSitterTextproto` derivation. Its
     name in nixpkgs, `reproto` (the program) or `prototext-reproto`
     (its PyPI name), is decided then. The PyPI name exists only
     because of the clash there.
  5. **`protolens`**. Upstream first: `build.rs` compiles the committed
     `parser.c` with the `cc` crate, instead of reading
     `TREE_SITTER_TEXTPROTO_LIB_DIR`. How its editor key finds Neovim
     and buf in nixpkgs (a wrapper, or `PATH` with a clear error) is
     decided then.

  Each later package fetches nothing of its own. It takes
  `inherit (prototext) version src;` and, for Rust code, the same
  `cargoDeps`, since the workspace has one `Cargo.lock`. So one
  `nix-update prototext` moves every tool, and in nixpkgs the tools read
  as one project (G3).

## Alternatives considered

### Refresh #525997 as it is

It has no open comments, so it might be approved as it stands. But its
reviewer judged it too complex, and it packages a version months
behind `main`. Approving it would also not make the next update any
simpler.

### One PR with every tool

What #525997 started as. It mixes four packages, two languages and
python-packages.nix in one review, which is exactly what the reviewer
advised against.

### Fetch an untagged commit

`version = "0.2.1-unstable-2026-10-10"` with `rev` instead of `tag`.
nixpkgs accepts it, but `versionCheckHook` cannot match it, the
update bot cannot follow it, and reviewers ask for a release anyway.
Tagging the same commit costs nothing.

### A `prototools` meta-package joining the tools

One attribute to install everything. It is the symlinkJoin the reviewer
objected to. Users install the tools they want, and the shared source
and version (S9) already show they belong together.

### The staged recipe as our release build (yb's model in full)

See N2: it would replace crane's shared dependency cache with one cargo
build per package, for every derivation in `ci`.

## Test plan

1. `nix-build -A nixpkgs-staging` builds the staged prototext recipe from
   the local tree, its tests and version check included.
2. `nix-build -A nixpkgs-staging-check`: nixfmt and the version rule
   pass. Both fail on a deliberately unformatted file, and on a staged
   version newer than the manifests'.
3. The fixtures check fails when a `.proto` under `fixtures/schemas`
   changes without its `.pb`, and passes otherwise.
4. Spec 0406's test plan passes (S3).
5. `prototext-gen-man` gives identical bytes under two different
   `SOURCE_DATE_EPOCH` values and locales (S4).
6. In a nixpkgs master checkout: `nix-build -A prototext` and
   `nixpkgs-review` pass, with the recipe copied verbatim.
7. `ci`, the image and the smoke test still pass after S1–S5 (C1).
8. The internal package builds against the S1–S5 commit, with its
   attribute uses and its prototext-core git dependency unchanged (C2).

## Measured outcome

Filled in at implementation.
