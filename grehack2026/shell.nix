# SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
#
# SPDX-License-Identifier: MIT

# The grehack2026 demo's shell (spec 0394): `cd grehack2026`, then `nix-shell`.
# Every tool is built by Nix from committed sources; see nix/demo-shells.nix.
(import ../default.nix { }).grehack2026-shell
