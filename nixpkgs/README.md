# nixpkgs staging

The files under `pkgs/` are prototools' nixpkgs packages, laid out as in the
nixpkgs tree (spec 0405):

| Here | In nixpkgs |
|---|---|
| `pkgs/by-name/pr/prototext/package.nix` | same path |

They are what a nixpkgs PR submits, copied verbatim: nixfmt-formatted, with
no SPDX header (their licensing is declared in `REUSE.toml`).

`nix-build -A nixpkgs-staging` builds the prototext recipe from the local
tree, through the same `callPackage`, with `src` and the vendored
dependencies taken from here instead of the tag, so its tests and version
check run on today's code. `nix-build -A nixpkgs-staging-check` checks the
formatting and the version: at a release the staged `version` equals the
workspace's (`Cargo.toml`, `workspace.package.version`); between releases
the workspace carries the next version with a `-dev` suffix and the staged
one, which nixpkgs ships, is older. Both are part of `ci`.

The other packages (protoscan, the Python extensions, reproto, protolens)
follow one PR at a time, in the order of spec 0405 S9.

## Releasing

1. Set `workspace.package.version` in `Cargo.toml` and `version` in each
   `pyproject.toml` to the release (evaluation fails if a `pyproject.toml`
   disagrees). Add the release's section to `CHANGELOG.md`. Set the same
   `version` in the staged `package.nix` (the check above requires it).
2. Commit, tag `vX.Y.Z`, push the tag to douzebis/prototools; then push
   to ThalesGroup/prototools (spec 0405 C3).
3. nixpkgs, in a checkout of `master`:
   - copy the staged file;
   - `nix-update prototext` (sets `hash` and `cargoHash`);
   - build it, run `nixpkgs-review`, open the PR
     (`prototext: init at X.Y.Z`, then `prototext: A.B.C -> X.Y.Z`).
4. Copy the updated `package.nix` back here (with its `hash` and
   `cargoHash`), and commit.
5. Start the next cycle: set the workspace and every `pyproject.toml` to
   the next version with a `-dev` suffix, add an `[Unreleased]` section to
   `CHANGELOG.md`, commit.
