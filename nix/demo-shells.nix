# SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
#
# SPDX-License-Identifier: MIT

# nix/demo-shells.nix — one shell per demo directory (spec 0394).
#
#   teleprompt         — bin/teleprompt, wrapped with what it calls
#   grehack2026-shell  — `cd grehack2026` (or eve/, bob/), then `nix-shell`
#   grpconf2026-shell  — `cd grpconf2026`, then `nix-shell`
#
# Every tool comes from Nix, built from committed sources, as the workshop
# image does (G2); nothing from target/release/ or bin/. These are not
# development shells (N3): no cargo, no Python environment, and no
# NIXSHELL_REPO, so the post-edit lint hook does not take them for the
# dev-shell.
{ pkgs
, telepromptSrc     # ./bin/teleprompt, as a path: imported into the store
, grehackRuntime    # grehack2026.runtime: the workshop image's tool set
, prototext
, protolensLean
, reproto
, protoscan
, wktDb
, googleapisDb
, googleapisPbs
, grpconfDemo
, buf             # narrow-pinned buf, for the proto LSP in the nvim config
}:

let
  # Neovim config for `view` / `view_textproto` / `view_proto`: desert theme,
  # proto and textproto highlighting (spec 0395 fix). The dev-shell writes the
  # same highlighting through _hook_nvim; the demo shells no longer run that
  # hook (spec 0394), so teleprompt carries its own config under XDG_CONFIG_HOME.
  telepromptNvimConfig = pkgs.runCommand "teleprompt-nvim-config" { } ''
    mkdir -p $out/nvim
    cp ${../nix/demo-nvim/init.lua} $out/nvim/init.lua
  '';

  # bin/teleprompt calls python3 (its readline coprocess, which finds
  # libreadline through TELEPROMPT_LIBREADLINE), magick and chafa (`header`),
  # nvim (`view`, `view_textproto`, `view_proto`), and tput/stty. buf is on
  # PATH for the proto LSP the nvim config starts.
  teleprompt = pkgs.runCommand "teleprompt"
    { nativeBuildInputs = [ pkgs.makeWrapper ]; }
    ''
      mkdir -p $out/bin
      cp ${telepromptSrc} $out/bin/teleprompt
      chmod +x $out/bin/teleprompt
      patchShebangs $out/bin/teleprompt
      wrapProgram $out/bin/teleprompt \
        --prefix PATH : ${pkgs.lib.makeBinPath (with pkgs; [
          bash python3 imagemagick chafa neovim ncurses coreutils
        ]) + ":" + buf + "/bin"} \
        --set TELEPROMPT_LIBREADLINE ${pkgs.readline}/lib/libreadline.so \
        --set XDG_CONFIG_HOME ${telepromptNvimConfig}
    '';

  # What both decks call besides the prototools: protoc and hexdump.
  deckTools = [ teleprompt pkgs.protobuf pkgs.util-linux ];

  wktSet = "${wktDb}/share/prototools/wkt.desc";

  # Spec 0394 S4: not a development shell. nix-shell inherits the caller's
  # environment, so a demo shell entered from the dev-shell would otherwise
  # keep its NIXSHELL_REPO, and the post-edit lint hook would take this
  # shell, which has no cargo or ruff, for the dev-shell.
  notDevShell = "unset NIXSHELL_REPO";
in
{
  inherit teleprompt;

  # grehack2026/, eve/ and bob/ (spec 0394 S1).
  #
  # neovim and buf are on the shell PATH (not only inside teleprompt's own
  # wrapper) so that protolens's `v` jump-to-definition works when
  # protolens is run directly in the shell, not only through the deck: `v`
  # spawns a bare `nvim`, whose config then starts `buf lsp serve`.
  grehack2026-shell = pkgs.mkShell {
    name = "grehack2026";
    packages = [ grehackRuntime pkgs.neovim buf ] ++ deckTools;
    shellHook = ''
      ${notDevShell}
      export PROTOTEXT_DESCRIPTOR_SET="${wktSet}"
    '';
  };

  # grpconf2026/ (spec 0394 S1, S5).
  grpconf2026-shell = pkgs.mkShell {
    name = "grpconf2026";
    packages = [ prototext protolensLean reproto protoscan wktDb ] ++ deckTools;
    shellHook = ''
      ${notDevShell}
      export PROTOTEXT_DESCRIPTOR_SET="${wktSet}"
      export PROTOTEXT_GOOGLEAPIS_SET="${googleapisDb}/googleapis.desc"
      export PROTOTEXT_GOOGLEAPIS_PBS="${googleapisPbs}/googleapis.pb"

      # Spec 0394 S5 (from the dev-shell's former _hook_demo): populate
      # bob/ and alice/ from the grpconf-demo derivation, writable, so the
      # presenter has a working directory. Guarded by a sentinel recording
      # the store path that last populated bob/, so re-entering is free.
      # bob/ and alice/ are gitignored; beats/ is committed and untouched.
      _grpconf_stage() {
        local bob="$PWD/bob"
        local sentinel="$bob/.demo-source"
        local demo="${grpconfDemo}"
        if [[ "$(cat "$sentinel" 2>/dev/null)" == "$demo" ]]; then
          return
        fi
        echo "grpconf2026: populating bob/ and alice/ from grpconf-demo"
        rm -rf "$bob"
        mkdir -p "$bob" "$PWD/alice"
        cp --no-preserve=mode "$demo/bin/bobapp" "$bob/app"
        chmod +x "$bob/app"
        cp --no-preserve=mode "$demo/logfile" "$bob/logfile"
        cp --no-preserve=mode "$demo/capture" "$bob/capture"
        echo "$demo" > "$sentinel"
      }
      if [[ "$(basename "$PWD")" == grpconf2026 ]]; then
        _grpconf_stage
      else
        echo "grpconf2026 shell: run nix-shell from grpconf2026/ to populate bob/" >&2
      fi
      unset -f _grpconf_stage
    '';
  };
}
