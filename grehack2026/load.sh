#!/usr/bin/env bash

# SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
#
# SPDX-License-Identifier: MIT

# load.sh — load the GreHack 2026 workshop image from this USB key, offline
# (spec 0374 S8).
#
#   ./load.sh              uses podman, or docker when podman is absent
#   RUNTIME=docker ./load.sh
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
  if command -v podman >/dev/null; then runtime=podman
  elif command -v docker >/dev/null; then runtime=docker
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
echo "Done. Start the workshop environment with (SETUP.md, section 3):"
# Rootless Podman: container root is the participant, so --user 0 makes
# files written to /work theirs. Docker on Linux runs as the laptop's root,
# hence --user there; Colima's VM maps ownership already.
if [ "$runtime" = podman ]; then
  cat <<'EOF'
  podman run -it --rm --name workshop --user 0 --cap-add NET_RAW -e TERM -e COLORTERM -v "$PWD":/work ghcr.io/douzebis/prototools-workshop:grehack2026
EOF
elif [ "$(uname -s)" = Linux ]; then
  cat <<'EOF'
  docker run -it --rm --name workshop --cap-add NET_RAW --user "$(id -u):$(id -g)" -e TERM -e COLORTERM -v "$PWD":/work ghcr.io/douzebis/prototools-workshop:grehack2026
EOF
else
  cat <<'EOF'
  docker run -it --rm --name workshop --cap-add NET_RAW -e TERM -e COLORTERM -v "$PWD":/work ghcr.io/douzebis/prototools-workshop:grehack2026
EOF
fi
