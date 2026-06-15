# SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
#
# SPDX-License-Identifier: MIT

# nix/pypi.nix — Assemble per-platform .whl files for PyPI publishing.
#
# Produces $out/ with one .whl per package:
#   prototext_graph-0.2.0-cp313-cp313-<platform>.whl   (binary, PyO3)
#   prototext_codec-0.1.0-cp313-cp313-<platform>.whl   (binary, PyO3)
#   fdp_scan-0.1.0-cp313-cp313-<platform>.whl           (binary, PyO3)
#   reproto-0.2.0-py3-none-any.whl                      (pure Python)
#   protoscan-0.2.0-py3-none-any.whl                    (pure Python)
#
# The derivation does not publish — publish.sh is assembled by the CI
# assemble job (spec 0098 S6).

{ pkgs
, pythonPkgs
, workspaceSrc       # filtered Rust workspace source (for PyO3 .so files)
, reprotoSrcFull     # enriched reproto source tree (from nix/python.nix)
, prototextExtensionArtifacts       # $out/artifacts/ from prototext_codec ext
, prototextGraphExtensionArtifacts  # $out/artifacts/ from prototext_graph ext
, fdpScanExtensionArtifacts         # $out/artifacts/ from fdp_scan ext
}:

let
  # ---------------------------------------------------------------------------
  # Platform tag — computed at Nix eval time from stdenv.
  #
  # PyPI wheel filenames use a platform tag:
  #   Linux x86_64:  manylinux_2_28_x86_64
  #   Linux aarch64: manylinux_2_28_aarch64
  #   macOS arm64:   macosx_11_0_arm64
  #   macOS x86_64:  macosx_10_15_x86_64
  #
  # We use manylinux_2_28 because the Nix glibc is >= 2.28 on nixos-25.11.
  # For macOS we use conservative deployment targets (11.0 for arm64,
  # 10.15 for x86_64) matching the GitHub Actions runner base.
  # ---------------------------------------------------------------------------
  platformTag =
    if pkgs.stdenv.isLinux && pkgs.stdenv.isx86_64  then "manylinux_2_28_x86_64"
    else if pkgs.stdenv.isLinux && pkgs.stdenv.isAarch64 then "manylinux_2_28_aarch64"
    else if pkgs.stdenv.isDarwin && pkgs.stdenv.isAarch64  then "macosx_11_0_arm64"
    else if pkgs.stdenv.isDarwin && pkgs.stdenv.isx86_64   then "macosx_10_15_x86_64"
    else throw "Unsupported platform for PyPI wheel assembly";

  pyVer = "cp313";  # CPython 3.13

  # ---------------------------------------------------------------------------
  # makeWheel — helper that zips up a pre-staged $wheelDir into a .whl file.
  #
  # A wheel is simply a zip archive.  The directory layout must contain:
  #   {dist_name}-{version}.dist-info/  (WHEEL, METADATA, RECORD)
  #   <package source tree>
  #
  # We rely on `python -m wheel pack` which rebuilds a .whl from a directory
  # that was previously unpacked by `python -m wheel unpack`, or we use the
  # lower-level zip approach to avoid requiring wheel itself.
  # ---------------------------------------------------------------------------

  # makeDistInfo name version isPure — write the dist-info directory into $PWD.
  # Returns a shell fragment (used inside buildPhase).
  makeDistInfoShell = name: version: pyTag: abiTag: plTag: ''
    DI="${name}-${version}.dist-info"
    mkdir -p "$DI"

    cat > "$DI/WHEEL" <<EOF
    Wheel-Version: 1.0
    Generator: nix-pypi (prototools)
    Root-Is-Purelib: false
    Tag: ${pyTag}-${abiTag}-${plTag}
    EOF

    cat > "$DI/METADATA" <<EOF
    Metadata-Version: 2.1
    Name: ${name}
    Version: ${version}
    EOF
  '';

  # ---------------------------------------------------------------------------
  # Binary PyO3 wheel helper.
  #
  # Takes:
  #   pkgName    — PyPI distribution name, e.g. "prototext_graph"
  #   version    — version string
  #   libName    — .so base name, e.g. "prototext_graph_lib"
  #   artifacts  — store path containing <libName>.so and <libName>.pyi
  #   initPy     — path to the __init__.py for the <libName>/ subpackage
  # ---------------------------------------------------------------------------
  makeBinaryWheel = { pkgName, version, libName, artifacts, initPy }:
    pkgs.runCommand "${pkgName}-whl" {
      buildInputs = [ pkgs.zip pythonPkgs.python ];
    } ''
      set -euo pipefail
      WORK=$(mktemp -d)
      cd "$WORK"

      # Package source tree: <libName>/__init__.py + <libName>.so
      mkdir -p "${libName}"
      cp "${initPy}"                      "${libName}/__init__.py"
      cp "${artifacts}/${libName}.so"     "${libName}/${libName}.so"

      ${makeDistInfoShell pkgName version pyVer pyVer platformTag}

      mkdir -p "$out"
      WHL="${pkgName}-${version}-${pyVer}-${pyVer}-${platformTag}.whl"
      zip -r "$out/$WHL" "${libName}" "$DI"
    '';

  # ---------------------------------------------------------------------------
  # Pure Python wheel helper.
  #
  # Takes:
  #   pkgName  — PyPI distribution name, e.g. "reproto"
  #   version  — version string
  #   src      — path to the package source tree (contains src/<pkg>/)
  #   pkgDir   — bare name of the Python package dir under src/, e.g. "reproto"
  # ---------------------------------------------------------------------------
  makePureWheel = { pkgName, version, src, pkgDir }:
    pkgs.runCommand "${pkgName}-whl" {
      buildInputs = [ pkgs.zip pythonPkgs.python ];
    } ''
      set -euo pipefail
      WORK=$(mktemp -d)
      cd "$WORK"

      # Copy the Python package tree.
      cp -r "${src}/src/${pkgDir}" .

      ${makeDistInfoShell pkgName version "py3" "none" "any"}

      mkdir -p "$out"
      WHL="${pkgName}-${version}-py3-none-any.whl"
      zip -r "$out/$WHL" "${pkgDir}" "$DI"
    '';

in pkgs.runCommand "prototools-pypi" {
  buildInputs = [ pkgs.zip ];
} ''
  set -euo pipefail
  mkdir -p "$out"

  # Copy all wheels from the individual per-package derivations.
  cp ${makeBinaryWheel {
    pkgName   = "prototext_graph";
    version   = "0.2.0";
    libName   = "prototext_graph_lib";
    artifacts = prototextGraphExtensionArtifacts;
    initPy    = ../prototext-graph-pyo3/prototext_graph_lib/__init__.py;
  }}/*.whl "$out/"

  cp ${makeBinaryWheel {
    pkgName   = "prototext_codec";
    version   = "0.1.0";
    libName   = "prototext_codec_lib";
    artifacts = prototextExtensionArtifacts;
    initPy    = ../prototext-pyo3/prototext_codec_lib/__init__.py;
  }}/*.whl "$out/"

  cp ${makeBinaryWheel {
    pkgName   = "fdp_scan";
    version   = "0.1.0";
    libName   = "fdp_scan_lib";
    artifacts = fdpScanExtensionArtifacts;
    initPy    = ../fdp-scan-pyo3/fdp_scan_lib/__init__.py;
  }}/*.whl "$out/"

  cp ${makePureWheel {
    pkgName = "reproto";
    version = "0.2.0";
    src     = reprotoSrcFull;
    pkgDir  = "reproto";
  }}/*.whl "$out/"

  cp ${makePureWheel {
    pkgName = "protoscan";
    version = "0.2.0";
    src     = ../protoscan;
    pkgDir  = "protoscan";
  }}/*.whl "$out/"
''
