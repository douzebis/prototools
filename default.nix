# SPDX-FileCopyrightText: 2025 - 2026 Frederic Ruget <fred@atlant.is> <fred@s3ns.io> (GitHub: @douzebis)
# SPDX-FileCopyrightText: 2025 - 2026 Thales Cloud Sécurisé
#
# SPDX-License-Identifier: MIT

{ pkgs ? (import (fetchTarball {
    url    = "https://nixos.org/channels/nixos-25.11/nixexprs.tar.xz";
    sha256 = "0qc4yszky11gjspiqh3q3jam1w4gysfrv4384lq9zf5q0afk83wv";
  }) {}) }:

let
  crane = pkgs.callPackage (pkgs.fetchgit {
    url    = "https://github.com/ipetkov/crane.git";
    rev    = "80ceeec0dc94ef967c371dcdc56adb280328f591";
    sha256 = "sha256-e1idZdpnnHWuosI3KsBgAgrhMR05T2oqskXCmNzGPq0=";
  }) { inherit pkgs; };

  # ---------------------------------------------------------------------------
  # Source filtered to only what Cargo needs, keeping the hash stable when
  # unrelated files (docs, fixtures, etc.) change.
  # ---------------------------------------------------------------------------
  src = pkgs.lib.cleanSourceWith {
    src    = pkgs.lib.cleanSource ./.;
    # Keep Cargo sources plus fixtures/ (integration tests + proto schemas).
    filter = path: type:
      (crane.filterCargoSources path type) ||
      (pkgs.lib.hasInfix "/fixtures/" path);
  };

  # Common arguments shared by all Crane derivations.
  commonArgs = {
    inherit src;
    pname   = "prototools";
    version = "0.1.4";
    strictDeps = true;
    nativeBuildInputs = [ pkgs.cargo pkgs.rustc ];
  };

  # ---------------------------------------------------------------------------
  # Shared dependency cache — built once, reused by tests, clippy, and the
  # final package.  Only rebuilt when Cargo.lock or dependency sources change.
  # ---------------------------------------------------------------------------
  depsCache = crane.buildDepsOnly (commonArgs // {
    pname = "prototools-deps";
  });

  # ---------------------------------------------------------------------------
  # Lint checks — separate derivations for Nix-level caching and parallelism.
  #
  # cargoFmt needs no compiled artifacts.
  # cargoClippy reuses depsCache so only the thin analysis layer is added.
  # ---------------------------------------------------------------------------
  rustFmt = crane.cargoFmt (commonArgs // {
    pname = "prototools-fmt";
  });

  rustClippy = crane.cargoClippy (commonArgs // {
    pname              = "prototools-clippy";
    cargoArtifacts     = depsCache;
    cargoClippyExtraArgs = "-- --deny warnings";
  });

  # ---------------------------------------------------------------------------
  # Tests — workspace-wide, reusing depsCache.
  # ---------------------------------------------------------------------------
  rustTests = crane.cargoTest (commonArgs // {
    pname             = "prototools-tests";
    cargoArtifacts    = depsCache;
    nativeBuildInputs = (commonArgs.nativeBuildInputs or []) ++ [ pkgs.protobuf ];
  });

  # ---------------------------------------------------------------------------
  # Final package — builds only the prototext binary.
  # checkPhase asserts that fmt, clippy, and tests all passed by referencing
  # their store paths (Nix fails the build if any derivation is missing).
  # ---------------------------------------------------------------------------
  prototools = crane.buildPackage (commonArgs // {
    pname          = "prototools";
    version        = "0.1.0";
    cargoArtifacts = depsCache;
    cargoExtraArgs = "-p prototext";

    nativeBuildInputs = (commonArgs.nativeBuildInputs or []) ++ [ pkgs.installShellFiles ];

    checkPhase = ''
      echo "fmt:    ${rustFmt}"
      echo "clippy: ${rustClippy}"
      echo "tests:  ${rustTests}"
    '';

    postInstall = ''
      # Install shell completions.
      installShellCompletion --cmd prototext \
        --bash <(PROTOTEXT_COMPLETE=bash $out/bin/prototext | sed \
          -e '/^\s*) )$/a\    compopt -o filenames 2>/dev/null' \
          -e 's|words\[COMP_CWORD\]="$2"|local _cur="''${COMP_LINE:0:''${COMP_POINT}}"; _cur="''${_cur##* }"; words[COMP_CWORD]="''${_cur}"|') \
        --zsh  <(PROTOTEXT_COMPLETE=zsh  $out/bin/prototext) \
        --fish <(PROTOTEXT_COMPLETE=fish $out/bin/prototext)

      # Generate and install man page.
      $out/bin/prototext-gen-man $out/share/man/man1
    '';

    meta = with pkgs.lib; {
      description  = "Command-line utilities for Protocol Buffer messages (prototext binary)";
      longDescription = ''
        prototools is a collection of CLI utilities for working with Protocol
        Buffer messages.  The first tool, prototext, converts between binary
        protobuf wire format and protoc-style enhanced textproto, with lossless
        round-trip by default.
      '';
      homepage    = "https://github.com/douzebis/prototools";
      license     = licenses.mit;
      maintainers = with maintainers; [ ];  # add: douzebis once registered
      mainProgram = "prototext";
      platforms   = platforms.unix;
    };
  });

  # ---------------------------------------------------------------------------
  # Development shell
  # ---------------------------------------------------------------------------
  dev-shell = pkgs.mkShell {
    name = "prototools-dev";

    # Allow cargo to write build artifacts to target/ (outside /nix/store).
    NIX_ENFORCE_PURITY = 0;

    nativeBuildInputs = with pkgs; [
      cargo
      rustc
      rustfmt
      clippy
      reuse
      gh
      protobuf
      mandoc
      zola
    ];

    shellHook = ''
      old_opts=$(set +o)
      set -euo pipefail

      # Detected by ~/.claude/hooks/claude-hook-post-edit-lint to confirm
      # that the active nix-shell belongs to this repo.
      export NIXSHELL_REPO="${toString ./.}"

      # Add the cargo release build to PATH so prototext is available after cargo build --release.
      export PATH="${toString ./.}/target/release:$PATH"

      # Build prototext if not already built.
      cargo build --release --locked -p prototext

      # Generate man page into man/man1/ and expose it via MANPATH.
      if command -v prototext-gen-man &>/dev/null; then
        mkdir -p man/man1
        prototext-gen-man man/man1
        export MANPATH="$PWD/man:''${MANPATH:-}"
        makewhatis "$PWD/man" 2>/dev/null || true
      fi

      # bash completion for prototext (workaround for clap_complete path-completion bugs)
      if command -v prototext &>/dev/null; then
        source <(PROTOTEXT_COMPLETE=bash prototext | sed \
          -e '/^\s*) )$/a\    compopt -o filenames 2>/dev/null' \
          -e 's|words\[COMP_CWORD\]="$2"|local _cur="''${COMP_LINE:0:''${COMP_POINT}}"; _cur="''${_cur##* }"; words[COMP_CWORD]="''${_cur}"|')
      fi

      eval "$old_opts"
    '';
  };

in
{
  default      = prototools;
  prototools   = prototools;
  rust-fmt     = rustFmt;
  rust-clippy  = rustClippy;
  rust-tests   = rustTests;
  dev-shell    = dev-shell;
}
