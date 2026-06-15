## =============================================================================
## pkgs/development/python-modules/protoscan/default.nix
##
## protoscan is a pure Python package (uses setuptools). It is the simpler of
## the four packages — no Rust compilation required.
##
## It lives in pkgs/development/python-modules/ because it is a Python library
## (consumed by the Python package set), even though it also provides a CLI.
## =============================================================================

{
  lib,
  stdenv,
  buildPythonPackage, ## standard nixpkgs builder for Python packages
  prototools,         ## the top-level prototools package — provides src, version
  setuptools,         ## Python build backend
  click,              ## Python CLI framework (runtime dependency)
  protobuf,           ## Python protobuf library (google.protobuf) — runtime dep
  fdp-scan,           ## sibling Python package (also from this PR) — runtime dep
  installShellFiles,  ## setup hook for installing shell completions
  pytestCheckHook,    ## setup hook that runs pytest during the check phase
}:

## buildPythonPackage (without `rec` or `finalAttrs`) because no attribute
## references itself or siblings.
## pyproject = true: use PEP 517 build (setuptools reads pyproject.toml).
## __structuredAttrs = true: nixpkgs policy for all new packages. Switches the
## build environment from space-separated strings to proper bash arrays for
## list-valued variables, which is more correct and avoids quoting bugs.
buildPythonPackage {
  pname = "protoscan";

  ## `inherit (prototools) version` is shorthand for `version = prototools.version`
  ## — pulls the version from the prototools passthru rather than duplicating it.
  inherit (prototools) version;
  pyproject = true;
  __structuredAttrs = true;

  ## Similarly, inherit the source from prototools. Since the entire prototools
  ## monorepo is one source tree, all sub-packages share the same src.
  inherit (prototools) src;

  ## protoscan lives in the protoscan/ subdirectory of the monorepo.
  ## ${prototools.src.name} evaluates to the name of the unpacked source
  ## directory (e.g. "prototools-prototext-v0.2.0"), which is used as the
  ## sourceRoot so the build starts in the right place.
  sourceRoot = "${prototools.src.name}/protoscan";

  ## build-system: tools needed to *build* the Python package (PEP 517).
  ## These are build-time only and not propagated to consumers.
  ## Note: `wheel` is not listed — modern setuptools pulls it in automatically.
  build-system = [
    setuptools
  ];

  ## dependencies: runtime dependencies propagated to consumers. When another
  ## package depends on protoscan, these are automatically added to its Python
  ## environment (via propagatedBuildInputs under the hood).
  dependencies = [
    click
    protobuf
    fdp-scan
  ];

  ## nativeBuildInputs: build-time tools (not propagated, not linked).
  ## installShellFiles provides the `installShellCompletion` function.
  nativeBuildInputs = [ installShellFiles ];

  ## nativeCheckInputs: tools available only during the check phase.
  ## pytestCheckHook rewires the check phase to run pytest.
  ## With pyproject = true, buildPythonPackage sets doInstallCheck = true
  ## and runs pytest after install, so the package is importable.
  nativeCheckInputs = [ pytestCheckHook ];

  enabledTestPaths = [ "src/protoscan/tests/" ];

  ## postInstall: runs after the package has been installed into $out.
  ## lib.optionalString: only generate completions and man pages when we can
  ## actually execute the just-built binary (i.e. not cross-compiling).
  ##
  ## _PROTOSCAN_COMPLETE=bash_source/zsh_source/fish_source: Click's mechanism
  ## for generating shell completion scripts (different from clap's approach
  ## used by prototext above — Click uses _APPNAME_COMPLETE=shell_source).
  ##
  ## protoscan-gen-man calls Path.mkdir(parents=True) internally, so the
  ## destination directory need not pre-exist.
  postInstall = lib.optionalString (stdenv.buildPlatform.canExecute stdenv.hostPlatform) ''
    installShellCompletion --cmd protoscan \
      --bash <(_PROTOSCAN_COMPLETE=bash_source $out/bin/protoscan) \
      --zsh  <(_PROTOSCAN_COMPLETE=zsh_source  $out/bin/protoscan) \
      --fish <(_PROTOSCAN_COMPLETE=fish_source $out/bin/protoscan)
    # protoscan-gen-man calls mkdir(parents=True) internally; no mkdir needed.
    # SOURCE_DATE_EPOCH and LC_ALL ensure reproducible man page output.
    SOURCE_DATE_EPOCH=0 LC_ALL=C $out/bin/protoscan-gen-man $out/share/man/man1
  '';

  ## pythonImportsCheck: after install, nixpkgs tries `python -c "import protoscan"`
  ## to verify the package is importable. Catches missing files or bad installs.
  pythonImportsCheck = [ "protoscan" ];

  meta = {
    description = "Scan binary files for embedded protobuf FileDescriptorProto blobs";
    homepage = "https://github.com/ThalesGroup/prototools";
    license = lib.licenses.mit;
    maintainers = with lib.maintainers; [ douzebis ];
    mainProgram = "protoscan";
    ## platforms is not set here — buildPythonPackage sets it automatically.
    platforms = lib.platforms.unix;
  };
}
