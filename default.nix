# SPDX-FileCopyrightText: 2025-2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
# SPDX-FileCopyrightText: 2025-2026 Thales Cloud Sécurisé
#
# SPDX-License-Identifier: MIT

{ lib ? (import <nixpkgs> {}).lib
, rustPlatform ? (import <nixpkgs> {}).rustPlatform
}:

rustPlatform.buildRustPackage {
  pname   = "prototools";
  version = "0.1.0";

  src = lib.cleanSource ./.;

  # Update with: nix-prefetch-url --unpack <src>
  # or leave as lib.fakeHash and run nix-build to get the correct hash.
  cargoHash = "sha256-nMll+I/WIPXk5g5pYiD7tuvznk/bmQ8wMljtBAFkPjU=";

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
}
