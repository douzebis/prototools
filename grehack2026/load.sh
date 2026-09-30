#!/usr/bin/env bash

# SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
#
# SPDX-License-Identifier: MIT

# load.sh — load the GreHack 2026 workshop image from this USB key, offline
# (spec 0374 S8).
#
#   ./load.sh              uses docker, or podman when docker is absent
#   RUNTIME=podman ./load.sh
#
# Picks the archive for this machine, checks it against SHA256SUMS, and
# loads it as ghcr.io/douzebis/prototools-workshop:grehack2026.
set -euo pipefail

cd "$(dirname "$0")"

case "$(uname -m)" in
  x86_64 | amd64)  arch=amd64 ;;
  arm64 | aarch64) arch=arm64 ;;
  *) echo "load.sh: no image for $(uname -m); ask the organizers" >&2; exit 1 ;;
esac
archive=prototools-workshop-$arch.tar

runtime=${RUNTIME:-}
if [ -z "$runtime" ]; then
  if command -v docker >/dev/null; then runtime=docker
  elif command -v podman >/dev/null; then runtime=podman
  else echo "load.sh: neither docker nor podman is installed (see SETUP.md)" >&2; exit 1
  fi
fi

# macOS has shasum but no sha256sum.
if command -v sha256sum >/dev/null; then sha=(sha256sum)
else sha=(shasum -a 256)
fi

echo "Checking $archive ..."
grep " \*\?$archive\$" SHA256SUMS | "${sha[@]}" -c -

echo "Loading $archive with $runtime ..."
"$runtime" load -i "$archive"

echo
echo "Done. Start the workshop environment with:"
# Docker on Linux runs as root by default; --user makes files written to
# /work the participant's. Rootless Podman and the macOS VMs map this already.
if [ "$runtime" = docker ] && [ "$(uname -s)" = Linux ]; then
  cat <<'EOF'
  docker run -it --rm --user "$(id -u):$(id -g)" -e TERM -e COLORTERM -v "$PWD":/work ghcr.io/douzebis/prototools-workshop:grehack2026
EOF
else
  echo "  $runtime run -it --rm -e TERM -e COLORTERM -v \"\$PWD\":/work ghcr.io/douzebis/prototools-workshop:grehack2026"
fi
