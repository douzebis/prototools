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
  # depsCache: built from protocArgs (includes pkgs.which stand-in for protoc),
  # no patchPhase. buildDepsOnly stubs build.rs so protoc is never invoked, but
  # including it in nativeBuildInputs matches the environment of all consumers
  # (protocArgs), preventing fingerprint mismatches that would force external
  # deps to recompile in every downstream derivation.
  # ---------------------------------------------------------------------------
  depsCache = crane.buildDepsOnly (protocArgs // {
    pname          = "pg-deps";
    cargoExtraArgs = "--workspace";
  });

  # ---------------------------------------------------------------------------
  # appTests: independent cargoTest from depsCache, with protocArgs+patchPhase.
  # Mirrors rustTests in the real project.
  # ---------------------------------------------------------------------------
  appTests = crane.cargoTest (protocArgs // {
    inherit patchPhase;
    pname          = "pg-app-tests";
    cargoArtifacts = depsCache;
    cargoExtraArgs = "--workspace";
  });

  # ---------------------------------------------------------------------------
  # Scenario F: representative of the real prototextBare → prototext chain.
  #
  # appBare_F: protocArgs + patchPhase, from depsCache, doCheck=false.
  #            doInstallCargoArtifacts=true so appFull_F can inherit artifacts.
  #            Mirrors prototextBare.
  #
  # appFull_F: protocArgs + patchPhase, chained off appBare_F, doCheck=false.
  #            Adds --features extra (mirrors wkt-db in prototext).
  #            Mirrors prototext (full).
  #
  # Expected: serde and lib-crate compile 0x in both appBare_F and appFull_F
  #           (reused from depsCache); app-crate compiles 1x in each.
  # ---------------------------------------------------------------------------
  appBare_F = crane.buildPackage (protocArgs // {
    inherit patchPhase;
    pname                   = "pg-app-bare-F";
    cargoArtifacts          = depsCache;
    cargoExtraArgs          = "--no-default-features -p app-crate";
    doCheck                 = false;
    doInstallCargoArtifacts = true;
  });

  appFull_F = crane.buildPackage (protocArgs // {
    inherit patchPhase;
    pname          = "pg-app-full-F";
    cargoArtifacts = appBare_F;
    cargoExtraArgs = "--no-default-features --features extra -p app-crate";
    doCheck        = false;
  });

in {
  inherit depsCache appTests appBare_F appFull_F;
}
