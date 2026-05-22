# SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
#
# SPDX-License-Identifier: MIT

let
  pkgs = import (fetchTarball {
    url    = "https://github.com/NixOS/nixpkgs/archive/1073dad219cb244572b74da2b20c7fe39cb3fa9e.tar.gz";
    sha256 = "0xgsq0cfjnl2axbzzw579jrjq9g8mhbgjgfippl3qx03im636p5l";
  }) {};

  crane = pkgs.callPackage (pkgs.fetchgit {
    url    = "https://github.com/ipetkov/crane.git";
    rev    = "80ceeec0dc94ef967c371dcdc56adb280328f591";
    sha256 = "sha256-e1idZdpnnHWuosI3KsBgAgrhMR05T2oqskXCmNzGPq0=";
  }) { inherit pkgs; };

  src = pkgs.lib.fileset.toSource {
    root    = ./.;
    fileset = pkgs.lib.fileset.unions [
      (crane.fileset.commonCargoSources ./.)
      ./app-crate/fixtures
    ];
  };

  # commonArgs: no protoc equivalent — mirrors real project's commonArgs used
  # only for depsCache.
  commonArgs = {
    inherit src;
    strictDeps        = true;
    nativeBuildInputs = [ pkgs.cargo pkgs.rustc ];
  };

  # protocArgs: adds pkgs.which as a stand-in for pkgs.protobuf in the real
  # project. Used by all derivations except depsCache.
  protocArgs = commonArgs // {
    nativeBuildInputs = commonArgs.nativeBuildInputs ++ [ pkgs.which ];
  };

  # patchPhase: simulates protoPatchPhase — rewrites the prebuilt fixture,
  # as protoc regenerates .pb files in the real project.
  patchPhase = ''
    runHook prePatch
    echo "patched data" > app-crate/fixtures/prebuilt/data.bin
    runHook postPatch
  '';

  # ---------------------------------------------------------------------------
  # prebuiltData: standalone Nix derivation that produces data.bin at a fixed
  # store path.  Mirrors the proposed prebuiltPbs derivation for the real
  # project: the file content is stable across all Crane sandboxes, so
  # include_bytes!(env!("OUT_DIR")/data.bin) always embeds the same bytes,
  # and Cargo fingerprints are valid across depsCache, rustTests, etc.
  #
  # In the real project this derivation runs protoc; here it just writes a
  # fixed string to simulate the output.
  # ---------------------------------------------------------------------------
  prebuiltData = pkgs.runCommand "pg-prebuilt-data" {} ''
    mkdir -p "$out"
    echo "patched data" > "$out/data.bin"
  '';

  # ---------------------------------------------------------------------------
  # depsCache: built from protocArgs (includes pkgs.which stand-in for protoc),
  # no patchPhase.  PREBUILT_DATA points at the stable store path so build.rs
  # copies from a fixed location — OUT_DIR contents are identical across all
  # sandboxes and Cargo fingerprints stay valid.
  # ---------------------------------------------------------------------------
  depsCache = crane.buildDepsOnly (protocArgs // {
    pname          = "pg-deps";
    cargoExtraArgs = "--workspace";
    PREBUILT_DATA  = "${prebuiltData}/data.bin";
  });

  # ---------------------------------------------------------------------------
  # appTests: independent cargoTest from depsCache, with protocArgs.
  # PREBUILT_DATA passed — no patchPhase needed because build.rs uses the
  # stable store path instead of fixtures/prebuilt/.
  # Mirrors rustTests in the real project.
  # ---------------------------------------------------------------------------
  appTests = crane.cargoTest (protocArgs // {
    pname          = "pg-app-tests";
    cargoArtifacts = depsCache;
    cargoExtraArgs = "--workspace";
    PREBUILT_DATA  = "${prebuiltData}/data.bin";
  });

  # ---------------------------------------------------------------------------
  # Scenario F: representative of the real prototextBare → prototext chain.
  #
  # appBare_F: protocArgs, from depsCache, doCheck=false.
  #            doInstallCargoArtifacts=true so appFull_F can inherit artifacts.
  #            Mirrors prototextBare.
  #
  # appFull_F: protocArgs, chained off appBare_F, doCheck=false.
  #            Adds --features extra (mirrors wkt-db in prototext).
  #            Mirrors prototext (full).
  #
  # Expected: serde and lib-crate compile 0x in both appBare_F and appFull_F
  #           (reused from depsCache); app-crate compiles 1x in each.
  # ---------------------------------------------------------------------------
  appBare_F = crane.buildPackage (protocArgs // {
    pname                   = "pg-app-bare-F";
    cargoArtifacts          = depsCache;
    cargoExtraArgs          = "--no-default-features -p app-crate";
    doCheck                 = false;
    doInstallCargoArtifacts = true;
    PREBUILT_DATA           = "${prebuiltData}/data.bin";
  });

  appFull_F = crane.buildPackage (protocArgs // {
    pname          = "pg-app-full-F";
    cargoArtifacts = appBare_F;
    cargoExtraArgs = "--no-default-features --features extra -p app-crate";
    doCheck        = false;
    PREBUILT_DATA  = "${prebuiltData}/data.bin";
  });

in {
  inherit prebuiltData depsCache appTests appBare_F appFull_F;
}
