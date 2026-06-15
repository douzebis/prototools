## =============================================================================
## pkgs/by-name/pr/prototools/package.nix
##
## This is the top-level "prototools" package. It is discovered automatically
## by pkgs/by-name/ based on the directory name (pr/prototools → "prototools").
##
## The package bundles two CLIs:
##   - prototext  (Rust)
##   - protoscan  (Python)
## They are merged into a single store path using symlinkJoin.
## =============================================================================

## -----------------------------------------------------------------------------
## FUNCTION ARGUMENTS
##
## Every .nix file in nixpkgs is a Nix function. The argument set is the list
## of dependencies that nixpkgs will inject automatically by matching names
## against the package set. This is "dependency injection via callPackage".
## -----------------------------------------------------------------------------
{
  lib,             ## nixpkgs standard library (lib.optionalString, lib.licenses, ...)
  rustPlatform,    ## helpers for building Rust packages (buildRustPackage, fetchCargoVendor, ...)
  installShellFiles, ## setup hook that installs shell completions
  versionCheckHook,  ## setup hook that runs "$bin --version" and checks the output
  stdenv,          ## standard build environment (compiler, libc, ...)
  fetchFromGitHub, ## fetcher for GitHub source archives
  runCommand,      ## builds a simple derivation by running a shell script
  protobuf,        ## the protobuf C++ library *and* the protoc compiler
  nix-update-script, ## script used by nix-update to bump version/hash automatically
  symlinkJoin,     ## merges multiple store paths by symlinking their contents
  python3Packages, ## the Python 3 package set (gives access to python3Packages.protoscan)
}:

## -----------------------------------------------------------------------------
## LET BINDINGS
##
## `let ... in` introduces local variables. These are evaluated lazily and are
## in scope for the rest of the file. We use it here to share `version`, `src`,
## and `fixtures` between the inner `prototext` derivation and the outer
## `symlinkJoin`.
## -----------------------------------------------------------------------------
let
  version = "0.2.0";

  ## ---------------------------------------------------------------------------
  ## SOURCE FETCH
  ##
  ## fetchFromGitHub downloads a source archive from GitHub and unpacks it into
  ## the Nix store. The `hash` is the SRI hash of the unpacked tree; Nix will
  ## refuse to use the result if it doesn't match (reproducibility guarantee).
  ##
  ## `tag` is equivalent to `rev = "refs/tags/..."` — fetchFromGitHub supports
  ## it as a first-class parameter.
  ##
  ## The resulting `src` is a store path such as:
  ##   /nix/store/…-prototools-prototext-v0.2.0/
  ## ---------------------------------------------------------------------------
  src = fetchFromGitHub {
    owner = "ThalesGroup";
    repo = "prototools";
    tag = "prototext-v${version}"; ## Nix string interpolation: embeds `version`
    hash = "sha256-MItheisua8Zzx3HJkMGq2y4CB8b+OufM9V5xXHkZfOc=";
  };

  ## ---------------------------------------------------------------------------
  ## FIXTURES DERIVATION
  ##
  ## `runCommand` is the simplest way to create a derivation: give it a name,
  ## an attribute set of build inputs, and a shell script. The script must
  ## populate $out (the output store path).
  ##
  ## Why a separate derivation?  prototext-core's build.rs requires three
  ## pre-compiled .pb files at *Cargo build time* (not at runtime). They must
  ## be compiled with protoc before cargo runs. Doing this in a separate
  ## derivation means:
  ##   1. It is cached independently — protoc only re-runs if the .proto files
  ##      or protobuf version changes.
  ##   2. Both the Rust build (prototext) and the Python build (prototext-codec)
  ##      can share the exact same .pb files via passthru.fixtures.
  ##
  ## nativeBuildInputs: tools available at *build time* (run on the build
  ## machine). protobuf provides `protoc`. This is distinct from buildInputs
  ## (libraries linked into the output).
  ##
  ## ${protobuf} interpolates the store path of the protobuf derivation, e.g.:
  ##   /nix/store/…-protobuf-27.5/
  ## so ${protobuf}/include expands to the directory containing the .proto files.
  ##
  ## ${src} similarly interpolates the source store path, giving access to the
  ## fixture .proto files committed in the repo.
  ## ---------------------------------------------------------------------------
  fixtures = runCommand "prototools-fixtures" { nativeBuildInputs = [ protobuf ]; } ''
    mkdir -p $out
    # Compile all well-known types into a single descriptor set with
    # --include_imports so the embedded descriptor pool covers exactly the same
    # types as the WKT scoring graph (wkt/SOURCES).  If wkt/SOURCES changes
    # upstream, this list must be updated in sync.
    protoc \
      --descriptor_set_out=$out/descriptor.pb \
      --proto_path=${protobuf}/include \
      --include_imports \
      google/protobuf/any.proto \
      google/protobuf/api.proto \
      google/protobuf/descriptor.proto \
      google/protobuf/duration.proto \
      google/protobuf/empty.proto \
      google/protobuf/field_mask.proto \
      google/protobuf/source_context.proto \
      google/protobuf/struct.proto \
      google/protobuf/timestamp.proto \
      google/protobuf/type.proto \
      google/protobuf/wrappers.proto
    protoc \
      --descriptor_set_out=$out/knife.pb \
      --proto_path=${src}/prototext/fixtures/schemas \
      knife.proto
    protoc \
      --descriptor_set_out=$out/enum_collision.pb \
      --proto_path=${src}/prototext/fixtures/schemas \
      enum_collision.proto
  '';

  ## ---------------------------------------------------------------------------
  ## RUST PACKAGE
  ##
  ## buildRustPackage is the standard nixpkgs builder for Rust projects. It:
  ##   1. Fetches/verifies the vendored Cargo dependencies (cargoHash).
  ##   2. Runs `cargo build` and `cargo test`.
  ##   3. Installs the resulting binaries to $out/bin/.
  ## ---------------------------------------------------------------------------
  prototext = rustPlatform.buildRustPackage {
    pname = "prototext";

    ## `inherit version src` is shorthand for `version = version; src = src;`
    ## — it pulls the values from the enclosing `let` scope.
    inherit version src;

    ## cargoRoot: the directory containing the top-level Cargo.toml. "." means
    ## the workspace root (the repo root), which is correct here since the repo
    ## is a Cargo workspace.
    cargoRoot = ".";

    ## cargoHash: SRI hash of the *vendored* Cargo dependencies. nixpkgs fetches
    ## all dependencies declared in Cargo.lock, vendors them into the store, and
    ## verifies this hash. The build then runs fully offline (--offline --frozen).
    cargoHash = "sha256-7zgovPU/MiKwyRdDpL5SyFlsLHmB6mSgDbt32D9ClGU=";

    ## In a Cargo workspace, these flags restrict the build/test to the specific
    ## crate we care about, avoiding building unrelated workspace members.
    cargoBuildFlags = [
      "-p"
      "prototext"
    ];
    cargoTestFlags = [
      "-p"
      "prototext"
    ];

    ## Disable the default features:
    ## - "protox" would embed a protoc binary and attempt network access.
    ## - The default wkt-db path would invoke reproto (not available here).
    ## Re-enable wkt-db via "prebuilt-wkt", which copies wkt/prebuilt/*.rkyv
    ## committed to the repository — no reproto needed.
    buildNoDefaultFeatures = true;
    buildFeatures = [
      "wkt-db"
      "prebuilt-wkt"
    ];

    ## installShellFiles provides the `installShellCompletion` shell function
    ## used in postInstall below.
    nativeBuildInputs = [
      installShellFiles
    ];

    ## ---------------------------------------------------------------------------
    ## patchPhase
    ##
    ## Runs before the build. We copy the pre-compiled .pb fixture files from the
    ## `fixtures` derivation into the source tree where build.rs expects them.
    ## ${fixtures} expands to the store path of the fixtures derivation, e.g.:
    ##   /nix/store/…-prototools-fixtures/
    ##
    ## runHook prePatch / runHook postPatch: convention that allows other hooks
    ## to inject additional patch steps before/after ours.
    ## ---------------------------------------------------------------------------
    patchPhase = ''
      runHook prePatch
      mkdir -p prototext/fixtures/prebuilt
      cp ${fixtures}/descriptor.pb    prototext/fixtures/prebuilt/
      cp ${fixtures}/knife.pb         prototext/fixtures/prebuilt/
      cp ${fixtures}/enum_collision.pb prototext/fixtures/prebuilt/
      runHook postPatch
    '';

    ## ---------------------------------------------------------------------------
    ## postInstall
    ##
    ## Runs after `cargo install` has placed binaries in $out/bin/.
    ##
    ## lib.optionalString COND STR: returns STR if COND is true, "" otherwise.
    ## stdenv.buildPlatform.canExecute stdenv.hostPlatform: true when we can run
    ## the just-built binaries (i.e. native build, not cross-compiling). Shell
    ## completions require executing the binary, so we skip them when
    ## cross-compiling.
    ##
    ## installShellCompletion: provided by the installShellFiles hook.
    ## The <(...) syntax is bash process substitution — the binary generates
    ## completion scripts on stdout which are piped directly to the installer.
    ##
    ## PROTOTEXT_COMPLETE=bash/zsh/fish: clap-derive environment variable that
    ## makes the binary emit completion scripts instead of running normally.
    ##
    ## SOURCE_DATE_EPOCH=0 LC_ALL=C: ensure the man page output is reproducible
    ## (no embedded timestamps or locale-dependent formatting).
    ## prototext-gen-man calls std::fs::create_dir_all internally, so the
    ## destination directory need not pre-exist.
    ## ---------------------------------------------------------------------------
    postInstall = lib.optionalString (stdenv.buildPlatform.canExecute stdenv.hostPlatform) ''
      installShellCompletion --cmd prototext \
        --bash <(PROTOTEXT_COMPLETE=bash $out/bin/prototext) \
        --zsh  <(PROTOTEXT_COMPLETE=zsh  $out/bin/prototext) \
        --fish <(PROTOTEXT_COMPLETE=fish $out/bin/prototext)
      # prototext-gen-man calls create_dir_all internally; no mkdir needed.
      # SOURCE_DATE_EPOCH and LC_ALL ensure reproducible man page output.
      SOURCE_DATE_EPOCH=0 LC_ALL=C $out/bin/prototext-gen-man $out/share/man/man1
    '';

    ## versionCheckHook runs `prototext --version` after install and checks that
    ## the output contains the expected version string. doInstallCheck = true
    ## enables the installCheck phase that runs it.
    nativeInstallCheckInputs = [ versionCheckHook ];
    doInstallCheck = true;

    ## -------------------------------------------------------------------------
    ## passthru
    ##
    ## Extra attributes attached to the derivation that are not part of the build
    ## itself. Consumers can access them as e.g. `pkgs.prototools.fixtures`.
    ##
    ## updateScript: used by `nix-update` to automatically bump version and hash.
    ## src, version, fixtures: exposed so that the Python sub-packages
    ## (protoscan, fdp-scan, prototext-codec) can inherit them without
    ## re-fetching the source or re-running protoc.
    ## -------------------------------------------------------------------------
    passthru = {
      updateScript = nix-update-script { };
      inherit src version fixtures;
    };

    meta = {
      description = "Lossless protobuf <-> enhanced textproto converter";
      longDescription = ''
        Command-line tool for converting protobuf binary wire format to and
        from an enhanced textproto representation, with lossless round-trip.
        Supports automatic schema inference for Well-Known Types without a
        .proto file.
      '';
      homepage = "https://github.com/ThalesGroup/prototools";
      changelog = "https://github.com/ThalesGroup/prototools/releases/tag/prototext-v${version}";
      license = lib.licenses.mit;
      maintainers = with lib.maintainers; [ douzebis ];
      mainProgram = "prototext";
      ## lib.platforms.unix: restricts the package to Linux and macOS, excluding
      ## Windows where .so files and bash phases won't work.
      platforms = lib.platforms.unix;
    };
  };

## -----------------------------------------------------------------------------
## TOP-LEVEL RESULT: symlinkJoin
##
## The `let ... in EXPR` returns EXPR as the value of the whole file.
## Here we return a symlinkJoin rather than the `prototext` derivation directly,
## because "prototools" is a bundle: it should provide both `prototext` (Rust)
## and `protoscan` (Python) from a single package.
##
## symlinkJoin creates a new store path whose contents are symlinks into each
## of the `paths`. The result looks like a single merged $out/bin/ containing
## both prototext and protoscan binaries.
##
## strictDeps = true: ensures build-time and runtime deps are not conflated
## (best practice for correctness and cross-compilation).
##
## __structuredAttrs = true: switches the build environment from exporting
## arrays as space-separated strings to proper bash arrays. Required for
## symlinkJoin to work correctly with multiple paths.
##
## passthru here mirrors the one on `prototext` so that consumers of
## `pkgs.prototools` (not `pkgs.prototools.prototext`) can still access
## src, version, and fixtures.
##
## meta = prototext.meta // { ... }: inherits all meta fields from prototext
## and overrides description and mainProgram for the bundle.
## -----------------------------------------------------------------------------
in
symlinkJoin {
  name = "prototools-${version}";
  strictDeps = true;
  __structuredAttrs = true;
  paths = [
    prototext
    python3Packages.protoscan
  ];
  passthru = {
    inherit src version fixtures;
  };
  meta = prototext.meta // {
    description = "Protocol Buffer utilities: prototext and protoscan CLIs";
    mainProgram = "prototext";
  };
}
