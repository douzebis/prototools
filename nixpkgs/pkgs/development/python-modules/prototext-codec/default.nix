## =============================================================================
## pkgs/development/python-modules/prototext-codec/default.nix
##
## prototext-codec is structurally identical to fdp-scan: a PyO3 Rust extension
## built with cargo and installed manually. The key difference is that its
## build.rs requires pre-compiled .pb fixture files (from prototools.fixtures)
## to be present before cargo runs.
##
## The importable module is `prototext_codec_lib`.
## The distribution name is "prototext-codec".
## =============================================================================

{
  lib,
  stdenv,
  buildPythonPackage,
  writeText,          ## creates a text file as a Nix store path at eval time
  prototools,         ## top-level prototools package — provides src, version, fixtures
  rustPlatform,
  cargo,
  rustc,
  python,
  pythonProtobuf,     ## Python protobuf library (google.protobuf) — needed by tests
                      ## Named `pythonProtobuf` to distinguish it from the C++ `protobuf`
                      ## package (which provides protoc). In python-packages.nix this is
                      ## wired to `self.protobuf` (the Python package set's protobuf).
  pytestCheckHook,
}:

## The `finalAttrs` pattern:
##
##   buildPythonPackage (finalAttrs: { pname = "…"; … cargoDeps = … ${finalAttrs.pname} … })
##
## `finalAttrs` is a special argument provided by buildPythonPackage (via
## lib.makeOverridable under the hood) that gives the attrset access to its
## own *final* values after any overrides have been applied.  It replaces the
## older `rec { … }` idiom.
##
## Why prefer `finalAttrs` over `rec`?
##   - With `rec { pname = "x"; cargoDeps = … pname … }`, overriding `pname`
##     via `.override { pname = "y"; }` does NOT propagate into `cargoDeps`
##     because `rec` captured the original `pname` at definition time.
##   - With `finalAttrs`, self-references always see the post-override values,
##     making the package correctly overridable.
##
## pyproject = false: there is no pyproject.toml for this Rust extension,
## so we disable PEP 517 build and write buildPhase/installPhase manually.
buildPythonPackage (finalAttrs: {
  pname = "prototext-codec";

  ## `inherit (prototools) version` is equivalent to `version = prototools.version`.
  inherit (prototools) version;

  pyproject = false; # manual build/install phases

  ## __structuredAttrs = true: nixpkgs policy for all new packages.
  ## Switches the build environment from space-separated strings to proper
  ## bash arrays for list-valued variables (nativeBuildInputs, etc.).
  ## This is more correct and avoids quoting bugs when paths contain spaces.
  __structuredAttrs = true;

  ## The entire prototools monorepo is one source tree; all sub-packages share
  ## the same fetchFromGitHub result exposed via prototools passthru.
  inherit (prototools) src;

  ## workspace-hack is a cargo-hakari crate that deduplicates dependency
  ## feature unification across all crates, speeding up from-scratch builds.
  ## It appears in the vendor tree but has no effect on built artefacts.
  ##
  ## `inherit (finalAttrs) pname version src`: passes the *final* (post-override)
  ## values into fetchCargoVendor.  We use finalAttrs rather than bare names
  ## because without `rec`, those names are not in scope inside the attrset.
  cargoDeps = rustPlatform.fetchCargoVendor {
    inherit (finalAttrs) pname version src;
    hash = "sha256-7zgovPU/MiKwyRdDpL5SyFlsLHmB6mSgDbt32D9ClGU=";
  };

  nativeBuildInputs = [
    cargo
    rustc
    rustPlatform.cargoSetupHook
    python # needed at build time for PYO3_PYTHON (Rust build scripts)
  ];

  buildInputs = [ python ]; # needed for linking against libpython

  env.PYO3_PYTHON = python.interpreter;

  ## ---------------------------------------------------------------------------
  ## buildPhase
  ##
  ## Before running cargo, we must populate prototext/fixtures/prebuilt/ with
  ## the pre-compiled .pb files. prototext-core's build.rs reads these at
  ## compile time to embed the descriptor pool into the binary.
  ##
  ## prototools.fixtures is the store path of the `fixtures` runCommand
  ## derivation defined in package.nix and exposed via passthru. It contains:
  ##   descriptor.pb     — all WKT file descriptors (compiled with --include_imports)
  ##   knife.pb          — test fixture
  ##   enum_collision.pb — test fixture
  ##
  ## Using prototools.fixtures here (rather than re-running protoc) ensures
  ## the Rust build and Python build use exactly the same .pb files.
  ##
  ## ${prototools.fixtures} is a Nix interpolation: the Nix evaluator substitutes
  ## the store path of that derivation (e.g. /nix/store/…-prototools-fixtures)
  ## at graph-construction time, before the shell script runs in the sandbox.
  ## ---------------------------------------------------------------------------
  buildPhase = ''
    runHook preBuild
    # prototext-pyo3/build.rs links against prototext-core which requires
    # three pre-compiled .pb fixture files.
    mkdir -p prototext/fixtures/prebuilt
    cp ${prototools.fixtures}/descriptor.pb     prototext/fixtures/prebuilt/
    cp ${prototools.fixtures}/knife.pb          prototext/fixtures/prebuilt/
    cp ${prototools.fixtures}/enum_collision.pb prototext/fixtures/prebuilt/
    cargo build --release --lib -p prototext_codec_lib \
      --offline \
      --frozen
    runHook postBuild
  '';

  ## ---------------------------------------------------------------------------
  ## installPhase
  ##
  ## Same pattern as fdp-scan. Key differences:
  ## - The crate is prototext_codec_lib → libprototext_codec_lib.so
  ## - The module directory is prototext_codec_lib/
  ## - The .dist-info directory is prototext_codec-${version}.dist-info
  ##   ("prototext-codec" normalized: hyphen → underscore → "prototext_codec")
  ##
  ## Note: ${finalAttrs.version} and ${finalAttrs.pname} are Nix interpolations
  ## (evaluated at graph-construction time), not shell variable expansions.
  ## We use finalAttrs (rather than the old `rec` approach) so that overrides
  ## to pname or version propagate correctly into the .dist-info directory name
  ## and the METADATA file content.
  ## ---------------------------------------------------------------------------
  installPhase = ''
    runHook preInstall
    site="$out/${python.sitePackages}"
    mkdir -p "$site/prototext_codec_lib"

    cp "target/release/libprototext_codec_lib${stdenv.hostPlatform.extensions.sharedLibrary}" \
       "$site/prototext_codec_lib/prototext_codec_lib.so"
    # .pyi type stub (generated by pyo3-stub-gen, committed to the repo).
    cp prototext-pyo3/prototext_codec_lib/prototext_codec_lib.pyi \
       "$site/prototext_codec_lib/"
    cp prototext-pyo3/prototext_codec_lib/__init__.py \
       "$site/prototext_codec_lib/"

    # Install minimal .dist-info so importlib.metadata can find the package.
    distinfo="$site/prototext_codec-${finalAttrs.version}.dist-info"
    mkdir -p "$distinfo"
    cp ${writeText "prototext-codec-METADATA" ''
      Metadata-Version: 2.1
      Name: ${finalAttrs.pname}
      Version: ${finalAttrs.version}
    ''} "$distinfo/METADATA"
    runHook postInstall
  '';

  nativeCheckInputs = [
    pytestCheckHook
    pythonProtobuf
  ];

  enabledTestPaths = [ "prototext-pyo3/tests/" ];

  pythonImportsCheck = [ "prototext_codec_lib" ];

  meta = {
    description = "Lossless protobuf decoder Python extension (PyO3)";
    homepage = "https://github.com/ThalesGroup/prototools";
    license = lib.licenses.mit;
    ## `with lib.maintainers; [ douzebis ]` is shorthand for
    ## `[ lib.maintainers.douzebis ]`.  The `with ATTRSET; EXPR` construct
    ## brings all attributes of ATTRSET into scope for EXPR.
    maintainers = with lib.maintainers; [ douzebis ];
    ## platforms is intentionally omitted — buildPythonPackage sets a sensible
    ## default.  There is nothing platform-specific enough here to restrict it.
  };
})
## Note the closing `})`:
##   - `)` closes the argument to buildPythonPackage (the finalAttrs function call)
##   - `}` closes the finalAttrs attrset literal
## Compare to a plain attrset: buildPythonPackage { … } — single closing `}`.
