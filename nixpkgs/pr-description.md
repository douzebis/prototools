prototext: init at 0.3.0

Add `prototext`, a lossless converter between binary protobuf and an
enhanced textproto: it decodes with or without the message's schema,
infers the message type from a schema database, reports encoding anomalies
in the text, and encodes back byte for byte.
Changelog: https://github.com/douzebis/prototools/blob/v0.3.0/CHANGELOG.md

This replaces #525997 (`prototools: init at 0.2.0`), as suggested in its
review: one package, one language, the plain `buildRustPackage` shape.
The other prototools CLIs follow as separate PRs.

Upstream changed so that the recipe needs nothing special: the descriptor
sets the build embeds are committed (no `protoc` at build time), there are
no feature flags to set, the bash completion script installs as printed
(no patching), and the man page is reproducible without environment
variables. Upstream builds and tests this exact recipe (staged in the
repository's `nixpkgs/` directory) in its CI.

## Things done

- Built on platform:
  - [x] x86_64-linux
  - [ ] aarch64-linux
  - [ ] aarch64-darwin
  - (aarch64-linux and aarch64-darwin: built and tested by upstream CI with
    this recipe, against nixos-26.05 rather than master.)
- Tested, as applicable:
  - [ ] [NixOS tests] in [nixos/tests].
  - [ ] [Package tests] at `passthru.tests`.
  - [ ] Tests in [lib/tests] or [pkgs/test] for functions and "core" functionality.
- [ ] Ran `nixpkgs-review` on this PR. See [nixpkgs-review usage].
- [x] Tested basic functionality of all binary files, usually in `./result/bin/`.
- Nixpkgs Release Notes
  - [ ] Package update: when the change is major or breaking.
- NixOS Release Notes
  - [ ] Module addition: when adding a new NixOS module.
  - [ ] Module update: when the change is significant.
- [x] Fits [CONTRIBUTING.md], [pkgs/README.md], [maintainers/README.md] and other READMEs.
- [x] Follows the [automation/AI policy].

## AI disclosure

This package was prepared with Claude Code (Claude Opus 5.5): the recipe,
the upstream changes it relies on, the commit message and this description
were drafted with it and reviewed by me, the maintainer, who is
responsible for them. The commit carries an `Assisted-by:` trailer.

[NixOS tests]: https://nixos.org/manual/nixos/unstable/index.html#sec-nixos-tests
[Package tests]: https://github.com/NixOS/nixpkgs/blob/master/pkgs/README.md#package-tests
[nixpkgs-review usage]: https://github.com/Mic92/nixpkgs-review#usage

[CONTRIBUTING.md]: https://github.com/NixOS/nixpkgs/blob/master/CONTRIBUTING.md
[automation/AI policy]: https://github.com/NixOS/nixpkgs/blob/master/CONTRIBUTING.md#automationai-policy
[lib/tests]: https://github.com/NixOS/nixpkgs/blob/master/lib/tests
[maintainers/README.md]: https://github.com/NixOS/nixpkgs/blob/master/maintainers/README.md
[nixos/tests]: https://github.com/NixOS/nixpkgs/blob/master/nixos/tests
[pkgs/README.md]: https://github.com/NixOS/nixpkgs/blob/master/pkgs/README.md
[pkgs/test]: https://github.com/NixOS/nixpkgs/blob/master/pkgs/test

🤖 Generated with [Claude Code](https://claude.com/claude-code)
