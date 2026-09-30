# SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
#
# SPDX-License-Identifier: MIT

# nix/grehack2026.nix — the GreHack 2026 workshop image (spec 0374).
#
# One image per architecture, built by Nix on that architecture: CI builds
# linux/amd64 on ubuntu-latest and linux/arm64 on ubuntu-24.04-arm, and joins
# them under one reference (.github/workflows/workshop-image.yml).
#
# Attributes (exported from default.nix as `grehack2026.*`):
#   runtime      — the tools, lean: prototext, protolens with a lean Neovim,
#                  reproto, protoscan, and the WKT schema database
#   image        — a streamLayeredImage script: `./result | docker load`
#   closureCheck — fails when a denied store path enters the image
#   publishTools — skopeo and crane, for the CI workflow
{ pkgs
, prototext
, protolensLean
, reproto
, protoscan
, wktDb
, googleapisDb
, googleapisPbs
, mkClosureCheck
, gitRevision ? null
}:

let
  lib = pkgs.lib;

  # The tools the image carries (spec 0374 S2): the regular bundle's
  # members, but protolens wrapped with the lean Neovim.
  runtime = pkgs.symlinkJoin {
    name  = "prototools-runtime";
    paths = [ prototext protolensLean reproto protoscan wktDb ];
  };

  uid = 1000;
  gid = 1000;
  home = "/home/hacker";

  # /etc/passwd and /etc/group with root, nobody and `hacker` (spec 0374 S4),
  # so the prompt and `whoami` work for the default user. Any other uid
  # (`docker run --user "$(id -u):$(id -g)"`) still works: HOME is set
  # explicitly and writable by everyone.
  nss = pkgs.dockerTools.fakeNss.override {
    extraPasswdLines = [
      "hacker:x:${toString uid}:${toString gid}:GreHack workshop:${home}:${pkgs.bashInteractive}/bin/bash"
    ];
    extraGroupLines = [ "hacker:x:${toString gid}:" ];
  };

  # The login shell's banner and prompt: what the tools are, where the
  # material is, and how to mount a directory from the laptop.
  profile = pkgs.writeTextDir "etc/profile" ''
    export PS1='\[\e[1;32m\]prototools\[\e[0m\]:\w\$ '
    if [ -t 1 ] && [ -z "''${PROTOTOOLS_QUIET:-}" ]; then
      cat <<'BANNER'

      prototools — GreHack 2026 workshop

      Tools:     prototext  protolens  reproto  protoscan
      Material:  /workshop   (try: protolens --type google.protobuf.FileDescriptorProto anomalies.pb)
      Your files: mount a directory at /work, e.g.
                 docker run -it --rm -v "$PWD":/work ghcr.io/douzebis/prototools-workshop:grehack2026

      Schema databases: $PROTOTEXT_DESCRIPTOR_SET (well-known types, the default)
                        $PROTOTEXT_GOOGLEAPIS_SET (googleapis; pass it with --descriptor-set)

    BANNER
    fi
  '';

  # What goes into the image's root (symlinked from the store). The
  # googleapis databases are not here: they are referenced from `config.Env`
  # below, which puts them in the closure — each in its own layer — without
  # scattering their files across `/`.
  contents = [
    runtime
    pkgs.bashInteractive
    pkgs.coreutils
    pkgs.gnugrep
    pkgs.less
    pkgs.ncurses
    pkgs.cacert
    nss
    profile
  ];

  wktSet        = "${wktDb}/share/prototools/wkt.desc";
  googleapisSet = "${googleapisDb}/googleapis.desc";
  googleapisPbs' = "${googleapisPbs}/googleapis.pb";

  image = pkgs.dockerTools.streamLayeredImage {
    name = "prototools-workshop";
    tag  = "latest";
    inherit contents;

    # Writable directories, created in the customisation layer (spec 0374
    # S4). `/tmp`: protolens's Neovim socket and blob scratch files go to
    # std::env::temp_dir(), and a Nix image has none. `$HOME` and
    # `/workshop` are 1777 too, so every uid can write there.
    extraCommands = ''
      mkdir -p tmp .${home} workshop work
      chmod 1777 tmp .${home} workshop work
      cp ${../tests/fixtures/anomalies.pb}     workshop/anomalies.pb
      cp ${../tests/fixtures/anomalies.script} workshop/anomalies.script
      cp ${../tests/fixtures/README.md}        workshop/README.md
      chmod 0666 workshop/*
    '';

    config = {
      User       = "${toString uid}:${toString gid}";
      WorkingDir = "/workshop";
      Cmd        = [ "${pkgs.bashInteractive}/bin/bash" "--login" ];
      Env = [
        "HOME=${home}"
        "PATH=/bin"
        "SSL_CERT_FILE=/etc/ssl/certs/ca-bundle.crt"
        "LANG=C.UTF-8"
        # The tools read PROTOTEXT_DESCRIPTOR_SET (spec 0090). The googleapis
        # pair are conveniences for people and scripts: no tool reads them.
        "PROTOTEXT_DESCRIPTOR_SET=${wktSet}"
        "PROTOTEXT_GOOGLEAPIS_SET=${googleapisSet}"
        "PROTOTEXT_GOOGLEAPIS_PBS=${googleapisPbs'}"
      ];
      Labels = {
        "org.opencontainers.image.title"    = "prototools-workshop";
        "org.opencontainers.image.source"   = "https://github.com/douzebis/prototools";
        "org.opencontainers.image.licenses" = "MIT";
      } // lib.optionalAttrs (gitRevision != null) {
        "org.opencontainers.image.revision" = gitRevision;
      };
    };
  };

  # Spec 0374 S2: the leaks, plus what is a feature on a desktop and dead
  # weight in a container.
  closureCheck = mkClosureCheck {
    name  = "grehack2026-image-closure-check";
    roots = contents ++ [ googleapisDb googleapisPbs ];
    deny  = [ "-deps-deps" "winapi" "cargo-package" "wl-clipboard" "perl" "ruby" ];
  };

  # What CI publishes with (spec 0374 S6), from the repository's nixpkgs pin:
  # skopeo pushes an image archive, crane joins the pushed images in an index.
  publishTools = pkgs.symlinkJoin {
    name  = "grehack2026-publish-tools";
    paths = [ pkgs.skopeo pkgs.crane ];
  };

in { inherit runtime image closureCheck publishTools; }
