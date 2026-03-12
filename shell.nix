# SPDX-FileCopyrightText: 2025-2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
# SPDX-FileCopyrightText: 2025-2026 Thales Cloud Sécurisé
#
# SPDX-License-Identifier: MIT

{ nixpkgs ? builtins.fetchTarball {
    url    = "https://github.com/NixOS/nixpkgs/archive/refs/heads/nixpkgs-25.05-darwin.tar.gz";
    # Replace with the sha256 from: nix-prefetch-url --unpack <url>
    sha256 = "0jnmv6gpzhqb0jyhj7qi7vjfwbn4cqs5blm5xia7q5i0ma2bbkcd";
  }
}:

let
  pkgs = import nixpkgs {};
in
pkgs.mkShell {
  name = "prototools-dev";

  buildInputs = with pkgs; [
    cargo
    rustc
    rustfmt
    clippy
    reuse
  ];
}
