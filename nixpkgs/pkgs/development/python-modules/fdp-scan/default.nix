## =============================================================================
## pkgs/development/python-modules/fdp-scan/default.nix
##
## fdp-scan is a PyO3 Rust extension: the core logic is written in Rust and
## exposed to Python as a native shared library (.so).
##
## The upstream fdp-scan-pyo3/pyproject.toml declares hatchling as its build
## backend.  Hatchling cannot compile Rust itself, so the pattern is:
##   1. Compile the .so with cargo in preBuild.
##   2. Drop the .so into fdp_scan_lib/ alongside the committed __init__.py
##      and .pyi stub — hatchling then packages whatever is in that directory.
##   3. buildPythonPackage with pyproject = true lets hatchling drive the
##      install, generating .dist-info automatically.
##
## This is the same two-step trick used by the upstream Crane pipeline in
## nix/rust.nix (makePyo3Extension): compile first, then let hatchling wrap.
##
## The importable module is `fdp_scan_lib` (underscore).
## The distribution name (pname) is "fdp-scan" (hyphen).
## =============================================================================

{
  buildPythonPackage, ## Python package builder — used here mainly for its
                      ## phase infrastructure and hook integration
  cargo,        ## Rust build tool
  ## hatchling: the build backend declared in fdp-scan-pyo3/pyproject.toml.
  ## It packages the fdp_scan_lib/ directory into a wheel and generates
  ## .dist-info automatically — no manual installPhase or METADATA writing needed.
  hatchling,
  lib,
  protobuf,     ## Python google.protobuf library — needed by the test suite
  prototools,   ## top-level prototools package — provides src, version
  python,       ## Python interpreter — needed for PyO3 linking
  pytestCheckHook,
  rustPlatform, ## Rust build helpers (fetchCargoVendor, cargoSetupHook)
  rustc,        ## Rust compiler
  stdenv,
}:

## The `finalAttrs` pattern:
##
##   buildPythonPackage (finalAttrs: { pname = "…"; cargoDeps = … ${finalAttrs.pname} … })
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
buildPythonPackage (finalAttrs: {
  pname = "fdp-scan";

  ## `inherit (prototools) version` pulls `version` from the prototools
  ## passthru attrset, equivalent to `version = prototools.version`.
  inherit (prototools) version;

  ## pyproject = true: use the PEP 517 build path — buildPythonPackage calls
  ## `python -m build --wheel` (via pypa/build), which invokes the hatchling
  ## backend declared in pyproject.toml.  Contrast with pyproject = false
  ## (the old approach), which disabled this and required manual buildPhase
  ## and installPhase.
  pyproject = true;

  ## __structuredAttrs = true: nixpkgs policy for all new packages.
  ## Switches the build environment from space-separated strings to proper
  ## bash arrays for list-valued variables (nativeBuildInputs, etc.).
  __structuredAttrs = true;

  ## The entire prototools monorepo is one source tree fetched once by the
  ## top-level prototools package.nix and shared via passthru.
  inherit (prototools) src;

  ## sourceRoot: after unpacking, the build changes into this subdirectory.
  ## All subsequent phases (configure, build, install, check) run from there.
  ## hatchling sees pyproject.toml and fdp_scan_lib/ directly.
  ## ${prototools.src.name} evaluates to the unpacked archive directory name
  ## (e.g. "prototools-prototext-v0.2.0").
  sourceRoot = "${prototools.src.name}/fdp-scan-pyo3";

  ## Cargo.lock lives at the workspace root, one level above sourceRoot.
  ##
  ## cargoRoot = "..": tells cargoSetupPostPatchHook (part of cargoSetupHook)
  ## to look for Cargo.lock at $(pwd)/../Cargo.lock — i.e. the workspace root
  ## — rather than in $(pwd) (which is fdp-scan-pyo3/ after the cd).
  ##
  ## fetchCargoVendor receives no sourceRoot or cargoRoot, so it also scans
  ## from the workspace root and finds the same Cargo.lock.  cargoSetupHook
  ## validates that the two are identical, ensuring the vendor tree is current.
  ##
  ## workspace-hack is a cargo-hakari crate that deduplicates dependency
  ## feature unification across all crates, speeding up from-scratch builds.
  ## It appears in the vendor tree but has no effect on built artefacts.
  cargoRoot = "..";
  cargoDeps = rustPlatform.fetchCargoVendor {
    inherit (finalAttrs) pname version src;
    hash = "sha256-c4HxWaAaMygeUbJL9xlt80H486NTcVWHP3NeWDqXGVc=";
  };

  build-system = [ hatchling ];

  ## nativeBuildInputs vs buildInputs:
  ## nativeBuildInputs: tools that run on the *build machine* (not linked into output).
  ## buildInputs: libraries *linked into* the output (must match target arch).
  ##
  ## python appears in both:
  ## - nativeBuildInputs: Rust build scripts (build.rs) call `python` to
  ##   locate PyO3 headers. Must be a build-machine binary.
  ## - buildInputs: the .so must link against libpython at runtime.
  ##   Must match the target architecture.
  nativeBuildInputs = [
    cargo
    rustc
    ## cargoSetupHook: unpacks cargoDeps into the build tree and configures
    ## Cargo to use the vendored deps (.cargo/config.toml).
    ## It runs during postUnpack (before cd into sourceRoot), writing
    ## .cargo/config.toml at the unpack root.  Cargo finds it by walking up
    ## the directory tree from fdp-scan-pyo3/, so --offline vendor resolution
    ## still works correctly.
    rustPlatform.cargoSetupHook
    python # needed at build time for PYO3_PYTHON (Rust build scripts)
  ];

  buildInputs = [ python ]; # needed for linking against libpython

  ## PYO3_PYTHON: tells PyO3's build.rs which Python interpreter to use.
  ## python.interpreter is the store path of the `python3` binary
  ## (e.g. /nix/store/…-python3-3.13.x/bin/python3).
  env.PYO3_PYTHON = python.interpreter;

  ## preBuild runs from inside fdp-scan-pyo3/ (the sourceRoot), before
  ## hatchling's build step (pypaBuildPhase).
  ##
  ## CARGO_TARGET_DIR="$PWD/target": without this, cargo would write its
  ## output to the default location relative to the workspace root —
  ## ../target/ from our working directory — which is read-only in the
  ## Nix sandbox.  Redirecting to $PWD/target keeps everything inside the
  ## writable fdp-scan-pyo3/ build directory.
  ##
  ## After cargo finishes, we copy the compiled .so into fdp_scan_lib/.
  ## The destination is always named fdp_scan_lib.so (Python extension module
  ## convention: no "lib" prefix, always .so even on macOS for modules inside
  ## a package directory).
  ## The committed __init__.py and fdp_scan_lib.pyi are already in place.
  ## Hatchling picks up the entire fdp_scan_lib/ directory (as declared in
  ## [tool.hatch.build.targets.wheel] packages = ["fdp_scan_lib"]) and
  ## packages it into a wheel, generating .dist-info automatically.
  preBuild = ''
    CARGO_TARGET_DIR="$PWD/target" \
      cargo build --release --lib -p fdp_scan_lib --offline --frozen
    cp target/release/libfdp_scan_lib${stdenv.hostPlatform.extensions.sharedLibrary} \
       fdp_scan_lib/fdp_scan_lib.so
  '';

  ## nativeCheckInputs: only available during the check phase, not propagated.
  ## protobuf: the Python google.protobuf library is imported by the test suite.
  nativeCheckInputs = [
    pytestCheckHook
    protobuf
  ];

  ## enabledTestPaths: relative to sourceRoot (fdp-scan-pyo3/).
  enabledTestPaths = [ "tests/" ];

  ## pythonImportsCheck: verifies `import fdp_scan_lib` succeeds after install.
  pythonImportsCheck = [ "fdp_scan_lib" ];

  meta = {
    description = "Rust extension for scanning binaries for embedded protobuf FileDescriptorProto blobs";
    homepage = "https://github.com/ThalesGroup/prototools";
    license = lib.licenses.mit;
    maintainers = with lib.maintainers; [ douzebis ];
  };
})
## Note the closing `})`:
##   - `)` closes the argument to buildPythonPackage (the finalAttrs function call)
##   - `}` closes the finalAttrs attrset literal
## Compare to a plain attrset: buildPythonPackage { … } — single closing `}`.
