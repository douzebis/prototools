# SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
#
# SPDX-License-Identifier: MIT

# nix/rust.nix — Crane derivations: dep cache, fmt, clippy, tests, the one
#                release build of the workspace, and what ships from it.
#
# Pipeline diagram (spec 0401):
#
#   src (Rust sources, fixtures/)
#     │
#     ├──[buildDepsOnly]──▶  depsCache  ──────────────────────────────────┐
#     │                                                                    │
#     ├──[cargoFmt]──▶  rustFmt                                            │
#     │                                                                    │
#     ├──[cargoClippy, cargoArtifacts=depsCache]──▶  rustClippy            │
#     │                                                                    │
#     ├──[cargoTest, profile quick]──▶  rustTests  (a ci leaf)              │
#     │                                                                    │
#     └──[buildPackage, cargoArtifacts=depsCache]──▶  workspaceBuild
#            │  one `cargo build --release --workspace --features prebuilt-wkt`
#            ├──▶  prototext            (copied out, completions, man page)
#            ├──▶  protolensUnwrapped  ──▶  protolens, protolensLean
#            └──▶  prototextCodec, fdpScanLib, prototextGraphLib  (.so + .pyi)
#
# Every shipped crate embeds the WKT scoring graph committed under
# prototext/wkt/prebuilt/ (S2); default.nix's wkt-prebuilt-check keeps that
# copy equal to what the code generates (S3). Nothing here waits for the
# tests (S4).

{ pkgs
, crane
, pythonPkgs
, pythonBin
, pythonExecutable
, pyo3Rustflags
, depsSrc
, workspaceSrc
, protoPatchPhase
, treeSitterTextprotoRustLib   # static lib + queries/highlights.scm for protolens's build.rs
, buf               # narrow-pinned buf (newer than the main nixpkgs pin's 1.59.0; see default.nix)
}:

let

  # ---------------------------------------------------------------------------
  # Shared flag strings — single source of truth for repeated cargo arguments.
  # ---------------------------------------------------------------------------

  # Cargo flags for workspace-wide derivations (fmt, clippy, tests).
  # pyo3 crates are included: PYO3_PYTHON is set in commonArgs so every
  # sandbox can compile prototext_codec_lib without a separate dep cache.
  workspaceArgs = "--no-default-features --workspace";

  # Same, plus prototext's `prebuilt-wkt`: every build embeds the WKT scoring
  # graph committed under prototext/wkt/prebuilt/ (spec 0401 S2).
  #
  # fdp_scan_lib depends on prototext with default features (`wkt-db`), and
  # Cargo unifies features over `--workspace`, so with `prebuilt-wkt` added
  # every crate that embeds a graph, fdp_scan_lib included, embeds the
  # committed one. Without it, prototext's build.rs would run reproto to
  # generate a graph, and reproto needs the extensions built here: a cycle.
  # The committed copy breaks it, and default.nix's wkt-prebuilt-check fails
  # `ci` when the copy no longer matches what the code generates (S3).
  prebuiltArgs = "${workspaceArgs} --features prebuilt-wkt";

  # ---------------------------------------------------------------------------
  # Base argument sets — hierarchic composition.
  #
  # commonArgs: base for ALL Crane derivations (Rust + pyo3).
  #   Carries PYO3_PYTHON and RUSTFLAGS globally so that a single depsCache
  #   covers the whole workspace including prototext_codec_lib.
  #
  # protocArgs: extends commonArgs with pkgs.protobuf + protoPatchPhase.
  #   Used by ALL derivations including depsCache, so the sandbox environment
  #   is identical everywhere and Cargo fingerprints are stable across the chain.
  #   (buildDepsOnly stubs build.rs so protoc is never actually invoked there.)
  #
  # Crane builds in release mode by default via configureCargoCommonVarsHook.
  # All cargo build invocations in the shellHook must pass --release explicitly.
  # ---------------------------------------------------------------------------
  # commonArgs omits src — each derivation sets its own focused src.
  commonArgs = {
    pname             = "prototools";
    version           = "0.1.4";
    strictDeps        = true;
    nativeBuildInputs = [ pkgs.cargo pkgs.rustc pythonBin ];
    env.PYO3_PYTHON   = pythonExecutable;
    env.TREE_SITTER_TEXTPROTO_LIB_DIR     = "${treeSitterTextprotoRustLib}/lib";
    env.TREE_SITTER_TEXTPROTO_QUERIES_DIR = "${treeSitterTextprotoRustLib}/queries";
    RUSTFLAGS         = pyo3Rustflags;
  };

  protocArgs = commonArgs // {
    nativeBuildInputs = commonArgs.nativeBuildInputs ++ [ pkgs.protobuf ];
    patchPhase        = protoPatchPhase;
  };

  # ---------------------------------------------------------------------------
  # Shared dependency cache — built once, reused by all Crane derivations.
  # Uses protocArgs (includes pkgs.protobuf) so the sandbox environment matches
  # all consumers. buildDepsOnly stubs build.rs so protoc is never invoked, but
  # having protobuf present prevents fingerprint mismatches that would force
  # external deps to recompile in every downstream derivation.
  # No patchPhase needed: dummy build.rs never calls protoc.
  # ---------------------------------------------------------------------------
  depsCache = crane.buildDepsOnly (protocArgs // {
    src            = workspaceSrc;
    pname          = "prototools-deps";
    cargoExtraArgs = workspaceArgs;
    # patchPhase must not run: buildDepsOnly uses dummy sources so proto
    # fixtures are absent and protoc would fail. Override it away.
    patchPhase     = "runHook prePatch; runHook postPatch";
  });

  # ---------------------------------------------------------------------------
  # Lint checks — separate derivations for Nix-level caching and parallelism.
  #
  # cargoFmt needs no compiled artifacts.
  # cargoClippy reuses depsCache so only the thin analysis layer is added.
  # A single workspace-wide clippy replaces the former three derivations
  # (rustClippy, rustClippyPyo3, rustClippyScoringGraph).
  # ---------------------------------------------------------------------------
  rustFmt = crane.cargoFmt (commonArgs // {
    src   = workspaceSrc;
    pname = "prototools-fmt";
  });

  rustClippy = crane.cargoClippy (protocArgs // {
    src                  = workspaceSrc;
    pname                = "prototools-clippy";
    cargoArtifacts       = depsCache;
    cargoExtraArgs       = prebuiltArgs;
    cargoClippyExtraArgs = "-- -D warnings";
  });

  # ---------------------------------------------------------------------------
  # Tests — workspace-wide, reusing depsCache. A leaf of `ci`: nothing builds
  # from them (spec 0401 S4), so a package never waits for the suite, and a
  # failing test fails `ci` without blocking the packages.
  # ---------------------------------------------------------------------------
  #
  # The `quick` profile (Cargo.toml): release codegen without LTO and with 16
  # codegen units (spec 0401 S8). The tests compile in a third of the time,
  # and leave the cores to workspaceBuild and clippy, which run alongside;
  # with `release` the three LTO builds starved each other. It needs its own
  # dependency cache, since a profile is part of every artifact's identity.
  depsCacheTests = crane.buildDepsOnly (protocArgs // {
    src             = workspaceSrc;
    pname           = "prototools-deps-tests";
    CARGO_PROFILE   = "quick";
    cargoExtraArgs  = workspaceArgs;
    # Only what cargoTest compiles: no check or build pass.
    cargoCheckCommand = "true";
    cargoBuildCommand = "true";
    patchPhase      = "runHook prePatch; runHook postPatch";
  });

  rustTests = crane.cargoTest (protocArgs // {
    src            = workspaceSrc;
    pname          = "prototools-tests";
    CARGO_PROFILE  = "quick";
    cargoArtifacts = depsCacheTests;
    cargoExtraArgs = prebuiltArgs;
    # Tell supports_rgb() that RGB is available so color-sensitive tests
    # exercise the RGB code path in the sandbox (no real terminal there).
    COLORTERM      = "truecolor";
  });

  # Common postInstall for both prototext variants.
  prototextPostInstall = ''
    # Install shell completions.
    installShellCompletion --cmd prototext \
      --bash <(PROTOTEXT_COMPLETE=bash $out/bin/prototext | sed \
        -e 's|-o nospace -o bashdefault|-o nospace -o filenames -o bashdefault|g' \
        -e 's|words\[COMP_CWORD\]="$2"|local _cur="''${COMP_LINE:0:''${COMP_POINT}}"; _cur="''${_cur##* }"; words[COMP_CWORD]="''${_cur}"|') \
      --zsh  <(PROTOTEXT_COMPLETE=zsh  $out/bin/prototext) \
      --fish <(PROTOTEXT_COMPLETE=fish $out/bin/prototext)

    # Generate and install man page.
    $out/bin/prototext-gen-man $out/share/man/man1
  '';

  prototextMeta = with pkgs.lib; {
    description  = "Command-line tool for Protocol Buffer messages (prototext binary)";
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

  # ---------------------------------------------------------------------------
  # The three PyO3 extensions, as workspaceBuild installs them.
  #
  #   crateName    — Cargo package name, e.g. "prototext_codec_lib"
  #   crateDir     — the crate directory, relative to the workspace root; the
  #                  stub generator runs with it as CARGO_MANIFEST_DIR
  #   libName      — cdylib base name (Cargo [[lib]] name); lib<libName>.so
  #   pyiName      — the name pyo3-stub-gen gives the .pyi (= pyproject
  #                  [project] name), e.g. "prototext_codec"
  #   postBuildBin — the stub-generator binary target
  # ---------------------------------------------------------------------------
  pyo3Extensions = {
    prototextCodec = {
      crateName = "prototext_codec_lib"; crateDir = "prototext-pyo3";
      libName = "prototext_codec_lib";   pyiName  = "prototext_codec";
      postBuildBin = "prototext_post_build";
    };
    fdpScan = {
      crateName = "fdp_scan_lib";        crateDir = "fdp-scan-pyo3";
      libName = "fdp_scan_lib";          pyiName  = "fdp_scan";
      postBuildBin = "fdp_scan_post_build";
    };
    prototextGraph = {
      crateName = "prototext_graph_lib"; crateDir = "prototext-graph-pyo3";
      libName = "prototext_graph_lib";   pyiName  = "prototext_graph";
      postBuildBin = "prototext_graph_post_build";
    };
  };

  # lib<libName>.so on Linux, .dylib on Darwin; installed as <libName>.so,
  # the name Python imports.
  libExt = if pkgs.stdenv.isDarwin then "dylib" else "so";

  # ---------------------------------------------------------------------------
  # workspaceBuild — the one release build of the workspace (spec 0401 S1).
  #
  # A single `cargo build --workspace` with depsCache's flags plus
  # prebuilt-wkt, so Cargo reuses every external-dependency artifact. (A
  # scoped -p invocation computes different unit hashes for the external
  # deps and recompiles them — see constant-rebuilds in the Crane FAQ; the
  # former per-extension builds paid that, about a minute each.) It builds
  # every binary and every cdylib, the stub generators included, so
  # everything that ships is copied out of it:
  #
  #   $out/bin/{prototext,prototext-gen-man,protolens}
  #   $out/ext/<libName>/<libName>.{so,pyi}
  #
  # The stub generators run here, with CARGO_MANIFEST_DIR set so
  # pyo3-stub-gen finds pyproject.toml and writes the .pyi beside it (the
  # NotPresent panic of spec 0038 was a missing CARGO_MANIFEST_DIR).
  #
  # doInstallCargoArtifacts = false: nothing builds on top of it, and an
  # installed target.tar.zst (with `.prev` pointing at depsCache and the
  # vendored registry) would enter the closure of whatever copies from it
  # (spec 0374 S2). Crane's postInstall hook strips the vendored sources'
  # store paths rustc embeds as panic locations, for the same reason.
  # ---------------------------------------------------------------------------
  workspaceBuild = crane.buildPackage (protocArgs // {
    src                                = workspaceSrc;
    pname                              = "prototools-workspace";
    cargoArtifacts                     = depsCache;
    doCheck                            = false;
    doInstallCargoArtifacts            = false;
    buildPhaseCargoCommand             = "cargoWithProfile build ${prebuiltArgs}";
    doNotPostBuildInstallCargoBinaries = true;
    installPhaseCommand                = ''
      mkdir -p $out/bin
      cp target/release/prototext target/release/prototext-gen-man \
         target/release/protolens $out/bin/
    '' + pkgs.lib.concatMapStrings (e: ''
      CARGO_MANIFEST_DIR="$PWD/${e.crateDir}" ./target/release/${e.postBuildBin}
      mkdir -p $out/ext/${e.libName}
      cp target/release/lib${e.libName}.${libExt} $out/ext/${e.libName}/${e.libName}.so
      cp ${e.crateDir}/${e.pyiName}.pyi $out/ext/${e.libName}/${e.libName}.pyi
    '') (builtins.attrValues pyo3Extensions);
  });

  # ---------------------------------------------------------------------------
  # prototext — the binary, copied out of workspaceBuild, with its shell
  # completions and man page. It embeds the committed WKT graph (S2).
  # ---------------------------------------------------------------------------
  prototext = pkgs.runCommand "prototext-${commonArgs.version}" {
    nativeBuildInputs = [ pkgs.installShellFiles ];
    meta              = prototextMeta;
  } ''
    mkdir -p $out/bin
    cp ${workspaceBuild}/bin/prototext ${workspaceBuild}/bin/prototext-gen-man $out/bin/
    ${prototextPostInstall}
  '';

  # ---------------------------------------------------------------------------
  # protolens — interactive TUI to decode/navigate/extract a binary protobuf.
  # It always takes an explicit --descriptor-set (spec 0111 v1, no embedded
  # WKT fallback). Its binary comes out of workspaceBuild with the others.
  # ---------------------------------------------------------------------------
  protolensPostInstall = ''
    installShellCompletion --cmd protolens \
      --bash <(PROTOLENS_COMPLETE=bash $out/bin/protolens | sed \
        -e 's|-o nospace -o bashdefault|-o nospace -o filenames -o bashdefault|g' \
        -e 's|words\[COMP_CWORD\]="$2"|local _cur="''${COMP_LINE:0:''${COMP_POINT}}"; _cur="''${_cur##* }"; words[COMP_CWORD]="''${_cur}"|') \
      --zsh  <(PROTOLENS_COMPLETE=zsh  $out/bin/protolens) \
      --fish <(PROTOLENS_COMPLETE=fish $out/bin/protolens)

    # Generate and install man page (spec 0228 S11), from the real binary.
    PROTOLENS_GEN_MAN=$out/share/man/man1 $out/bin/protolens

    # spec 0145 G5: a minimal Neovim config wiring `.proto` filetype/syntax
    # and `buf lsp serve` navigation, loaded via `-u` by the wrapper below.
    install -Dm444 ${../protolens/nvim/init.lua} \
      "$out/share/protolens/nvim/init.lua"
  '';

  protolensMeta = with pkgs.lib; {
    description = "Interactive TUI to decode, navigate, and extract raw bytes from a binary protobuf";
    homepage    = "https://github.com/douzebis/prototools";
    license     = licenses.mit;
    maintainers = with maintainers; [ ];  # add: douzebis once registered
    mainProgram = "protolens";
    platforms   = platforms.unix;
  };

  # The binary, its completions, man page and Neovim config — copied out of
  # workspaceBuild once, and wrapped below as many ways as needed (spec 0374
  # S2/G7; spec 0401 S1).
  protolensUnwrapped = pkgs.runCommand "protolens-unwrapped-${commonArgs.version}" {
    nativeBuildInputs = [ pkgs.installShellFiles ];
    meta              = protolensMeta;
  } ''
    mkdir -p $out/bin
    cp ${workspaceBuild}/bin/protolens $out/bin/
    ${protolensPostInstall}
  '';

  # `v`'s Neovim handoff (spec 0144 G5/G6) is a mandatory runtime dependency,
  # not merely a dev-shell convenience — bundle a pinned Neovim and `buf`
  # (for `buf lsp serve`) onto PATH so they resolve regardless of the user's
  # own $PATH. A separate derivation from the compile (spec 0374 S2), so a
  # different Neovim costs a shell script, not a Rust build.
  bufFull = buf;
  wrapProtolens = { neovim, buf ? bufFull, name ? "protolens" }:
    pkgs.runCommand "${name}-${commonArgs.version}" {
      nativeBuildInputs = [ pkgs.makeWrapper ];
      meta              = protolensMeta;
    } ''
      mkdir -p $out/bin
      ln -s ${protolensUnwrapped}/share $out/share
      makeWrapper ${protolensUnwrapped}/bin/protolens $out/bin/protolens \
        --prefix PATH : ${pkgs.lib.makeBinPath [ neovim buf ]} \
        --set PROTOLENS_NVIM_CONFIG ${protolensUnwrapped}/share/protolens/nvim/init.lua
    '';

  # The default Neovim: its wrapper keeps the Wayland clipboard provider
  # (wl-clipboard), which desktop users want.
  protolens = wrapProtolens { neovim = pkgs.neovim; };

  # A lean Neovim for the workshop image (spec 0374 S2): no clipboard (there
  # is no desktop clipboard in a container; wl-clipboard also brings perl),
  # and no Ruby or Python providers, which protolens's init.lua — pure Lua and
  # Neovim's built-in LSP client — never uses. 98 MiB instead of 407 MiB, and
  # no compilation: `wrapNeovimUnstable` only wraps the shared neovim-unwrapped.
  # (`pkgs.neovim.override { waylandSupport = false; }` does not evaluate: the
  # argument belongs to wrapNeovimUnstable, not to the `neovim` package.)
  #
  # wrapRc = false: the default wrapper exports VIMINIT pointing at a generated
  # (here empty) init.lua, and with VIMINIT set Neovim never reads
  # $XDG_CONFIG_HOME/nvim/init.lua — which is how teleprompt's config (desert
  # theme, proto/textproto syntax, spec 0395) gets loaded. protolens passes its
  # own config explicitly and is unaffected.
  neovimLean = pkgs.wrapNeovimUnstable pkgs.neovim-unwrapped {
    wrapRc         = false;
    waylandSupport = false;
    withRuby       = false;
    withPython3    = false;
  };
  # buf for the image (spec 0375 S9): its `buf` binary alone, copied rather
  # than linked so the full package leaves the closure. protolens runs only
  # `buf lsp serve`; the two protoc-gen-buf-* plugins are 72 MiB unpacked.
  bufLean = pkgs.runCommand "buf-lean-${buf.version}" { } ''
    install -Dm755 ${buf}/bin/buf $out/bin/buf
  '';

  protolensLean = wrapProtolens {
    neovim = neovimLean;
    buf    = bufLean;
    name   = "protolens-lean";
  };

  # ---------------------------------------------------------------------------
  # PyO3 extensions — prototext_codec_lib, fdp_scan_lib, prototext_graph_lib.
  #
  # Each is a buildPythonPackage that copies its .so and .pyi, built by
  # workspaceBuild (S1), into the pyproject source tree beside __init__.py,
  # where hatchling picks them up. `artifacts` exposes the same directory to
  # pyright (pythonLint) and the PyPI wheels.
  # ---------------------------------------------------------------------------
  makePyo3Extension = e:
    let
      artifacts = "${workspaceBuild}/ext/${e.libName}";
      pkg = pythonPkgs.buildPythonPackage {
        pname     = e.crateName;
        version   = "0.1.0";
        format    = "pyproject";
        src       = ../. + "/${e.crateDir}";
        buildInputs = [ pythonPkgs.hatchling ];
        patchPhase = ''
          cp ${artifacts}/${e.libName}.* ${e.libName}/
        '';
      };
    in { inherit pkg artifacts; };

  _prototextCodecExt    = makePyo3Extension pyo3Extensions.prototextCodec;
  _fdpScanLibExt        = makePyo3Extension pyo3Extensions.fdpScan;
  _prototextGraphLibExt = makePyo3Extension pyo3Extensions.prototextGraph;

  prototextCodec     = _prototextCodecExt.pkg;
  fdpScanLib         = _fdpScanLibExt.pkg;
  prototextGraphLib  = _prototextGraphLibExt.pkg;

in {
  inherit
    commonArgs
    depsCache
    rustFmt
    rustClippy
    rustTests
    workspaceBuild
    prototext
    protolens
    protolensUnwrapped
    protolensLean
    neovimLean
    bufLean
    prototextCodec
    fdpScanLib
    prototextGraphLib;
  prototextExtensionArtifacts      = _prototextCodecExt.artifacts;
  fdpScanExtensionArtifacts        = _fdpScanLibExt.artifacts;
  prototextGraphExtensionArtifacts = _prototextGraphLibExt.artifacts;
}
