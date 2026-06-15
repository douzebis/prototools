## =============================================================================
## pkgs/development/python-modules/fdp-scan/default.nix
##
## fdp-scan is a PyO3 Rust extension: the core logic is written in Rust and
## exposed to Python as a native shared library (.so). There is no standard
## Python build system involved — we drive cargo directly and install the
## resulting .so by hand.
##
## The importable module is `fdp_scan_lib` (note: underscore, not hyphen).
## The distribution name (pname) is "fdp-scan" (hyphen), following PyPA
## convention where distribution names use hyphens.
## =============================================================================

{
  lib,
  stdenv,
  buildPythonPackage, ## Python package builder — used here mainly for its
                      ## phase infrastructure and hook integration
  writeText,          ## creates a text file as a Nix store path at eval time
  prototools,         ## top-level prototools package — provides src, version
  rustPlatform,       ## Rust build helpers
  cargo,              ## Rust build tool
  rustc,              ## Rust compiler
  python,             ## Python interpreter — needed for PyO3 linking
  pytestCheckHook,    ## runs pytest during the check phase
  protobuf,           ## Python google.protobuf library — needed by the test suite
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
  pname = "fdp-scan";

  ## `inherit (prototools) version` pulls `version` from the prototools
  ## passthru attrset, equivalent to `version = prototools.version`.
  ## This ensures all packages in the monorepo share a single version string.
  inherit (prototools) version;

  pyproject = false; # manual build/install phases

  ## __structuredAttrs = true: nixpkgs policy for all new packages.
  ## Switches the build environment from space-separated strings to proper
  ## bash arrays for list-valued variables (nativeBuildInputs, etc.).
  ## This is more correct and avoids quoting bugs when paths contain spaces.
  __structuredAttrs = true;

  ## Inherit the source from prototools.  The entire prototools monorepo is
  ## one source tree; all sub-packages share the same fetchFromGitHub result.
  ## `inherit (prototools) src` is equivalent to `src = prototools.src`.
  inherit (prototools) src;

  ## ---------------------------------------------------------------------------
  ## cargoDeps
  ##
  ## fetchCargoVendor downloads and vendors all Cargo dependencies declared in
  ## Cargo.lock. The `hash` covers the entire vendored tree. The build will then
  ## run with --offline --frozen so no network access is needed.
  ##
  ## `inherit (finalAttrs) pname version src`: passes the *final* (post-override)
  ## values into fetchCargoVendor.  We use finalAttrs rather than bare names
  ## because without `rec`, those names are not in scope inside the attrset.
  ## (The old `rec` approach would fail to propagate overrides correctly —
  ## see the finalAttrs explanation above.)
  ##
  ## workspace-hack is a cargo-hakari crate that deduplicates dependency
  ## feature unification across all crates, speeding up from-scratch builds.
  ## It appears in the vendor tree but has no effect on built artefacts.
  ## ---------------------------------------------------------------------------
  cargoDeps = rustPlatform.fetchCargoVendor {
    inherit (finalAttrs) pname version src;
    hash = "sha256-7zgovPU/MiKwyRdDpL5SyFlsLHmB6mSgDbt32D9ClGU=";
  };

  ## ---------------------------------------------------------------------------
  ## nativeBuildInputs vs buildInputs
  ##
  ## nativeBuildInputs: tools that run on the *build machine* (the machine
  ## running nix-build). In a cross-compilation scenario, these are the host
  ## architecture tools.
  ##
  ## buildInputs: libraries that are *linked into* the output and must match
  ## the *target* architecture.
  ##
  ## For PyO3:
  ## - python in nativeBuildInputs: Rust build scripts (build.rs) call
  ##   `python` to locate PyO3 headers. Must be a build-machine binary.
  ## - python in buildInputs: the .so must link against libpython at runtime.
  ##   Must match the target architecture.
  ## - cargo, rustc, cargoSetupHook: build-time tools only.
  ## ---------------------------------------------------------------------------
  nativeBuildInputs = [
    cargo
    rustc
    rustPlatform.cargoSetupHook # sets up the vendored deps so cargo --offline works
    python # needed at build time for PYO3_PYTHON (Rust build scripts)
  ];

  buildInputs = [ python ]; # needed for linking against libpython

  ## PYO3_PYTHON: tells PyO3's build.rs which Python interpreter to use when
  ## generating bindings. python.interpreter is the store path of the python
  ## binary (e.g. /nix/store/…-python3-3.13.x/bin/python3).
  env.PYO3_PYTHON = python.interpreter;

  ## ---------------------------------------------------------------------------
  ## buildPhase
  ##
  ## We only need to build the shared library, not any binaries, hence --lib.
  ## -p fdp_scan_lib: build only the fdp_scan_lib crate within the workspace.
  ## --offline --frozen: use the vendored deps set up by cargoSetupHook.
  ## ---------------------------------------------------------------------------
  buildPhase = ''
    runHook preBuild
    cargo build --release --lib -p fdp_scan_lib \
      --offline \
      --frozen
    runHook postBuild
  '';

  ## ---------------------------------------------------------------------------
  ## installPhase
  ##
  ## pyproject = false means there is no pip install — we copy files manually.
  ##
  ## python.sitePackages: the canonical site-packages path relative to $out,
  ## e.g. "lib/python3.13/site-packages". Using this attribute (rather than
  ## hardcoding the path) ensures correctness across Python versions.
  ##
  ## stdenv.hostPlatform.extensions.sharedLibrary: ".so" on Linux, ".dylib"
  ## on macOS. Cargo produces libfdp_scan_lib.so (or .dylib), so we use this
  ## to construct the source path portably.
  ##
  ## The destination filename is always fdp_scan_lib.so (plain .so, no ABI
  ## tags) because Python's import system finds the module by name within the
  ## package directory — ABI tags are only needed for top-level extension
  ## modules installed directly into site-packages.
  ##
  ## writeText NAME CONTENT: a Nix built-in that creates a store path containing
  ## a single file with the given content at eval time (not build time).
  ## ${writeText ...} interpolates its store path into the shell script.
  ## Nix's indented string literals ('' ... '') strip the common leading
  ## whitespace, so the METADATA file will have headers at column 0.
  ##
  ## The .dist-info directory name follows PEP 427 normalization:
  ## hyphens in the distribution name become underscores.
  ## "fdp-scan" → "fdp_scan-0.2.0.dist-info"
  ##
  ## Note: ${finalAttrs.version} and ${finalAttrs.pname} here are Nix
  ## interpolations (evaluated at graph-construction time by the Nix evaluator),
  ## not shell variable expansions.  They expand to the string values of those
  ## attributes before the shell script is even written to the build sandbox.
  ## ---------------------------------------------------------------------------
  installPhase = ''
    runHook preInstall
    site="$out/${python.sitePackages}"
    mkdir -p "$site/fdp_scan_lib"

    cp "target/release/libfdp_scan_lib${stdenv.hostPlatform.extensions.sharedLibrary}" \
       "$site/fdp_scan_lib/fdp_scan_lib.so"
    # .pyi type stub (generated by pyo3-stub-gen, committed to the repo).
    cp fdp-scan-pyo3/fdp_scan_lib/fdp_scan_lib.pyi \
       "$site/fdp_scan_lib/"
    cp fdp-scan-pyo3/fdp_scan_lib/__init__.py \
       "$site/fdp_scan_lib/"

    # Install minimal .dist-info so importlib.metadata can find the package.
    distinfo="$site/fdp_scan-${finalAttrs.version}.dist-info"
    mkdir -p "$distinfo"
    cp ${writeText "fdp-scan-METADATA" ''
      Metadata-Version: 2.1
      Name: ${finalAttrs.pname}
      Version: ${finalAttrs.version}
    ''} "$distinfo/METADATA"
    runHook postInstall
  '';

  ## nativeCheckInputs: only available during the check phase, not propagated.
  ## pytestCheckHook: with pyproject = false and buildPythonPackage, tests run
  ## in installCheckPhase (after install), so the .so is already in site-packages.
  ## protobuf: the Python google.protobuf library is imported by the test suite.
  nativeCheckInputs = [
    pytestCheckHook
    protobuf
  ];

  enabledTestPaths = [ "fdp-scan-pyo3/tests/" ];

  ## pythonImportsCheck: verifies that `import fdp_scan_lib` succeeds after install.
  pythonImportsCheck = [ "fdp_scan_lib" ];

  meta = {
    description = "Rust extension for scanning binaries for embedded protobuf FileDescriptorProto blobs";
    homepage = "https://github.com/ThalesGroup/prototools";
    license = lib.licenses.mit;
    ## `with lib.maintainers; [ douzebis ]` is shorthand for
    ## `[ lib.maintainers.douzebis ]`.  The `with ATTRSET; EXPR` construct
    ## brings all attributes of ATTRSET into scope for EXPR, avoiding
    ## repetitive `lib.maintainers.` prefixes when listing multiple maintainers.
    maintainers = with lib.maintainers; [ douzebis ];
    ## platforms is intentionally omitted — buildPythonPackage sets a sensible
    ## default.  There is nothing platform-specific enough here to restrict it.
  };
})
## Note the closing `})`:
##   - `)` closes the argument to buildPythonPackage (the finalAttrs function call)
##   - `}` closes the finalAttrs attrset literal
## Compare to a plain attrset: buildPythonPackage { … } — single closing `}`.
