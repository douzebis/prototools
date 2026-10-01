# SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
#
# SPDX-License-Identifier: MIT

# grehack2026/life/default.nix — life-server, life-client and life-spy
# (spec 0375).
#
# A standalone Cargo project with its own Cargo.lock, excluded from the root
# workspace and subtracted from default.nix's workspaceSrc, like demo/bobapp
# (spec 0241 S1): tonic, hyper and tokio must not enter the workspace graph.
#
# build.rs runs protoc on proto/grehack/life/v1/life.proto; the binaries
# embed its FileDescriptorProto for protoscan to find (spec 0375 S3). The
# unit tests run as part of the build (crane's cargo test).
#
# life-spy runs dumpcap and tshark, so it is wrapped with wireshark-cli on
# its PATH and runs the same in the workshop image and on any Nix machine
# (spec 0375 S10). It still needs the capture privilege: root, or NixOS's
# programs.wireshark.
#
# Inputs:
#   pkgs   — the same nixpkgs pin as the root default.nix
#   crane  — the same crane as the root default.nix
#
# Output: $out/bin/{life-server,life-client,life-spy}

{ pkgs, crane }:

let
  # The source is rooted at the repository, not at life/, so life-server's
  # path dependency on prototext-core (spec 0377 S2) is reachable — the
  # workspace-not-at-source-root technique bobapp uses (spec 0241, its
  # default.nix). postUnpack enters life/ and sets sourceRoot=".", so cargo
  # resolves "../../prototext-core" and "../../prototext-core"'s own
  # "../workspace-hack" naturally.
  repoRoot = ../..;

  src = pkgs.lib.fileset.toSource {
    root    = repoRoot;
    fileset = pkgs.lib.fileset.unions [
      (crane.fileset.commonCargoSources (repoRoot + /grehack2026/life))
      (repoRoot + /grehack2026/life/proto)
      # Path dependencies of life, and their own path dependencies.
      (crane.fileset.commonCargoSources (repoRoot + /prototext-core))
      (crane.fileset.commonCargoSources (repoRoot + /workspace-hack))
    ];
  };

  commonArgs = {
    inherit src;
    pname   = "life";
    version = "0.1.0";
    strictDeps = true;
    # prost-build runs protoc; PROTOC names it rather than relying on PATH.
    nativeBuildInputs = [ pkgs.protobuf pkgs.makeWrapper ];
    PROTOC = "${pkgs.protobuf}/bin/protoc";

    cargoLock  = ./Cargo.lock;
    cargoToml  = ./Cargo.toml;
    postUnpack = ''
      cd $sourceRoot/grehack2026/life
      sourceRoot="."
    '';
  };

  depsCache = crane.buildDepsOnly commonArgs;

in crane.buildPackage (commonArgs // {
  cargoArtifacts = depsCache;

  postInstall = ''
    wrapProgram $out/bin/life-spy \
      --prefix PATH : ${pkgs.lib.makeBinPath [ pkgs.wireshark-cli ]}
  '';

  meta = {
    description = "Game of life over cleartext gRPC, and a spy on its traffic (GreHack 2026)";
    license     = pkgs.lib.licenses.mit;
    mainProgram = "life-client";
  };
})
