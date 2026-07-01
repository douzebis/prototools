## =============================================================================
## pkgs/development/python-modules/prototext-codec/default.nix
##
## Structurally identical to fdp-scan — same hatchling + preBuild cargo trick.
## Two key differences:
##
## 1. prototext-core's build.rs requires pre-compiled .pb fixture files before
##    `cargo build` can run.  Its build.rs checks for DESCRIPTOR_PB (and
##    siblings) env vars first; when set, it copies the files directly from
##    those store paths into OUT_DIR — no directory copying into the source tree
##    needed.  prototools.fixtures is a runCommand derivation (in package.nix)
##    that runs protoc once and caches the .pb files in the Nix store.
##
## 2. pname = "prototext-codec", importable as `prototext_codec_lib`.
## =============================================================================

{
  buildPythonPackage,
  cargo,
  hatchling,
  lib,
  prototools,   ## top-level prototools package — provides src, version, fixtures
  python,
  pytestCheckHook,
  pythonProtobuf, ## Python protobuf library (google.protobuf) — needed by tests
                  ## Named pythonProtobuf (not protobuf) to distinguish it from
                  ## the C++ protobuf package (which provides protoc).
                  ## In python-packages.nix this is wired to `self.protobuf`.
  rustPlatform,
  rustc,
  stdenv,
}:

## See fdp-scan/default.nix for a full explanation of the finalAttrs pattern,
## pyproject = true, __structuredAttrs, sourceRoot, cargoRoot, and preBuild.
buildPythonPackage (finalAttrs: {
  pname = "prototext-codec";
  inherit (prototools) version;
  pyproject = true;
  __structuredAttrs = true;

  inherit (prototools) src;
  sourceRoot = "${prototools.src.name}/prototext-pyo3";

  ## Cargo.lock is at the workspace root, one level above sourceRoot.
  ## cargoRoot = ".." and fetchCargoVendor without sourceRoot both target
  ## the workspace root — see fdp-scan/default.nix for the full rationale.
  cargoRoot = "..";
  cargoDeps = rustPlatform.fetchCargoVendor {
    inherit (finalAttrs) pname version src;
    hash = "sha256-c4HxWaAaMygeUbJL9xlt80H486NTcVWHP3NeWDqXGVc=";
  };

  build-system = [ hatchling ];

  nativeBuildInputs = [
    cargo
    rustc
    rustPlatform.cargoSetupHook
    python # needed at build time for PYO3_PYTHON (Rust build scripts)
  ];

  buildInputs = [ python ]; # needed for linking against libpython

  env.PYO3_PYTHON = python.interpreter;

  ## prototext-core's build.rs fast path: when DESCRIPTOR_PB is set, it copies
  ## the .pb files directly from the given store paths into OUT_DIR, skipping
  ## the fallback that would look for them under fixtures/prebuilt/ in the
  ## source tree (which is read-only in the Nix sandbox).
  ## prototools.fixtures is a Nix store path, e.g.:\
  ##   /nix/store/…-prototools-fixtures/descriptor.pb
  ## These Nix interpolations are evaluated at graph-construction time and
  ## baked into the derivation as literal store paths.
  env.DESCRIPTOR_PB = "${prototools.fixtures}/descriptor.pb";
  env.KNIFE_PB = "${prototools.fixtures}/knife.pb";
  env.ENUM_COLLISION_PB = "${prototools.fixtures}/enum_collision.pb";
  env.MESSAGE_SET_PB = "${prototools.fixtures}/message_set.pb";

  ## CARGO_TARGET_DIR keeps cargo's output inside the writable build directory.
  ## See fdp-scan/default.nix for the full rationale.
  preBuild = ''
    CARGO_TARGET_DIR="$PWD/target" \
      cargo build --release --lib -p prototext_codec_lib --offline --frozen
    cp target/release/libprototext_codec_lib${stdenv.hostPlatform.extensions.sharedLibrary} \
       prototext_codec_lib/prototext_codec_lib.so
  '';

  nativeCheckInputs = [
    pytestCheckHook
    pythonProtobuf
  ];

  ## enabledTestPaths: relative to sourceRoot (prototext-pyo3/).
  enabledTestPaths = [ "tests/" ];

  pythonImportsCheck = [ "prototext_codec_lib" ];

  meta = {
    description = "Lossless protobuf decoder Python extension (PyO3)";
    homepage = "https://github.com/ThalesGroup/prototools";
    license = lib.licenses.mit;
    maintainers = with lib.maintainers; [ douzebis ];
  };
})
