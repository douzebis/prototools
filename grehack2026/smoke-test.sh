#!/usr/bin/env bash

# SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
#
# SPDX-License-Identifier: MIT

# grehack2026/smoke-test.sh — spec 0374 S7: check a workshop image.
#
# Runs on the host and drives `docker run` against an image reference, so
# the same script checks a local build and a CI build (S9):
#
#   nix-build -A grehack2026.image && ./result | docker load
#   grehack2026/smoke-test.sh prototools-workshop:latest
#
# Set DOCKER=podman to use Podman. When GITHUB_STEP_SUMMARY is set (CI),
# the image size and the store paths it holds go to the job summary.
#
# Each check is a bash script read from stdin and run inside the image, so
# its `$` expand there, not here.
set -euo pipefail

image=${1:?usage: smoke-test.sh IMAGE}
docker=${DOCKER:-docker}

failures=0
pass() { printf 'ok    %s\n' "$1"; }
fail() { printf 'FAIL  %s\n' "$1"; failures=$((failures + 1)); }
indent() { sed 's/^/      /'; }

# check WHAT [DOCKER-RUN-ARGS...] < script
check() {
  local what=$1 out
  shift
  if out=$("$docker" run --rm -i "$@" --entrypoint /bin/bash "$image" -s 2>&1); then
    pass "$what"
  else
    fail "$what"
    printf '%s\n' "$out" | indent
  fi
}

# ── The tools run ────────────────────────────────────────────────────────────

check "versions" <<'EOF'
set -e
prototext --version
protolens --version
reproto --help >/dev/null
protoscan --help >/dev/null
EOF

# ── The user and the writable directories (S4) ───────────────────────────────

check "user hacker, HOME and writable directories" <<'EOF'
set -e
[ "$(whoami)" = hacker ]
[ "$HOME" = /home/hacker ]
for d in /tmp /home/hacker /workshop /work; do
  [ "$(stat -c %a "$d")" = 1777 ] || { echo "$d is not 1777"; exit 1; }
done
EOF

if out=$("$docker" run --rm -t "$image" bash --login -c true 2>&1) \
    && grep -q "GreHack 2026" <<<"$out"; then
  pass "login banner"
else
  fail "login banner"
  printf '%s\n' "$out" | indent
fi

# ── The workshop material (S7) ───────────────────────────────────────────────

# anomalies.pb is authored in prototext; encode it, decode the binary and
# re-encode: the two binaries must be identical.
check "anomalies.pb round trip" <<'EOF'
set -e
cd /workshop
prototext encode anomalies.pb > /tmp/first.pb
prototext decode -t google.protobuf.FileDescriptorProto /tmp/first.pb > /tmp/first.txt
prototext encode /tmp/first.txt > /tmp/second.pb
a=$(sha256sum < /tmp/first.pb) b=$(sha256sum < /tmp/second.pb)
[ "$a" = "$b" ] || { echo "re-encoding differs: $a vs $b"; exit 1; }
EOF

check "protolens script walk" <<'EOF'
cd /workshop
out=$(protolens --type google.protobuf.FileDescriptorProto anomalies.pb script 2>&1) \
  || { printf '%s\n' "$out" | tail -20; exit 1; }
if grep -q "error:" <<<"$out"; then printf '%s\n' "$out" | tail -20; exit 1; fi
grep -q "^step 1/" <<<"$out" || { echo "no step was walked"; exit 1; }
EOF

# Type inference against the googleapis database. The flag is explicit:
# without it, inference would run against the WKT database.
check "googleapis type inference" <<'EOF'
set -e
db=$(dirname "$PROTOTEXT_GOOGLEAPIS_SET")
out=$(prototext --descriptor-set "$PROTOTEXT_GOOGLEAPIS_SET" decode \
        "$db/instances/google/type/PostalAddress.pb")
grep -qx "# Type: google.type.PostalAddress" <<<"$out" \
  || { printf '%s\n' "$out" | head -5; exit 1; }
EOF

# ── protolens's editor path, headless (S7) ───────────────────────────────────

# Neovim with protolens's init.lua, listening on a socket in /tmp as
# protolens starts it, opens a googleapis .proto and waits for `buf lsp
# serve` to attach. The Neovim and buf protolens runs are on its wrapper's
# PATH only, so they are read from the wrapper. Run also as a uid with no
# passwd entry, as Docker on Linux does with --user (S8), so $HOME must be
# writable for any uid.
editor_check=$(cat <<'EOF'
set -e
wrapper=$(cat /bin/protolens)
nvim_bin=$(grep -o "/nix/store/[a-z0-9]*-neovim-[^/']*/bin" <<<"$wrapper" | head -1)
buf_bin=$(grep -o "/nix/store/[a-z0-9]*-buf-[^/']*/bin" <<<"$wrapper" | head -1)
config=$(grep -o "PROTOLENS_NVIM_CONFIG='[^']*'" <<<"$wrapper" | cut -d"'" -f2)
[ -n "$nvim_bin" ] && [ -n "$buf_bin" ] && [ -n "$config" ] \
  || { echo "cannot read Neovim, buf and init.lua from the wrapper"; exit 1; }
export PATH=$buf_bin:$nvim_bin:$PATH
PROTOTEXT_PROTO_ROOT=$(dirname "$PROTOTEXT_GOOGLEAPIS_SET")/googleapis/proto
export PROTOTEXT_PROTO_ROOT
timeout 120 nvim --headless -u "$config" \
  --listen /tmp/protolens-smoke.sock \
  "$PROTOTEXT_PROTO_ROOT/google/type/date.proto" \
  +'lua local ok = vim.wait(60000, function()
      local c = vim.lsp.get_clients({ name = "buf" })[1]
      return c ~= nil and c.initialized end, 200)
    io.stdout:write(ok and "buf attached\n" or "buf did not attach\n")
    vim.cmd(ok and "qa!" or "cq!")'
EOF
)
check "editor path, default user" <<<"$editor_check"
check "editor path, uid 4242" --user 4242:4242 <<<"$editor_check"

# ── The closure: no denied store path (S2), and the size ─────────────────────

store=$("$docker" run --rm --entrypoint /bin/ls "$image" /nix/store)
denied=$(grep -E -- '-deps-deps|winapi|cargo-package|wl-clipboard|perl|ruby' \
           <<<"$store" || true)
if [ -z "$denied" ]; then
  pass "no denied store path"
else
  fail "denied store paths in the image:"
  printf '%s\n' "$denied" | indent
fi

size=$("$docker" image inspect --format '{{.Size}}' "$image")
size_mib=$(( size / 1048576 ))
printf 'info  image size: %s MiB unpacked, %s store paths\n' \
  "$size_mib" "$(wc -l <<<"$store")"

if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
  tick=$(printf '\140')
  fence=$tick$tick$tick
  cat >> "$GITHUB_STEP_SUMMARY" <<EOF
### $tick$image$tick ($(uname -m))

Unpacked size: $size_mib MiB. Smoke test failures: $failures.

<details><summary>Store paths</summary>

$fence
$store
$fence
</details>
EOF
fi

if [ "$failures" -ne 0 ]; then
  echo "$failures check(s) failed"
  exit 1
fi
echo "all checks passed"
