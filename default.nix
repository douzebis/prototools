# SPDX-FileCopyrightText: 2025-2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
# SPDX-FileCopyrightText: 2025-2026 Thales Cloud Sécurisé
#
# SPDX-License-Identifier: MIT

{ lib ? (import <nixpkgs> {}).lib
, rustPlatform ? (import <nixpkgs> {}).rustPlatform
, pkgs ? (import <nixpkgs> {})
}:

let
  prototools = rustPlatform.buildRustPackage {
    pname   = "prototools";
    version = "0.1.0";

    src = lib.cleanSource ./.;

    # Update with: nix-prefetch-url --unpack <src>
    # or leave as lib.fakeHash and run nix-build to get the correct hash.
    cargoHash = "sha256-/i6+Mlu/7EwzsQZSix1wzkP8LEkAZNZ2K788GWTuI/k=";

    # Build only the prototext binary crate; prototext-core is a library dep.
    buildAndTestSubdir = null;
    cargoBuildFlags = [ "-p" "prototext" ];
    cargoTestFlags  = [ "--workspace" ];

    meta = with lib; {
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
  };

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
      cargo build --release -p prototext

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
  default  = prototools;
  dev-shell = dev-shell;
}
