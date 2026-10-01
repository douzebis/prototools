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

# ── The game of life (spec 0375) ─────────────────────────────────────────────

# Test plan 1: the schema is in the binaries, for protoscan to find.
check "protoscan finds life.proto in the client and the server" <<'EOF'
set -e
for b in life-client life-server; do
  found=$(protoscan "$(readlink -f "/bin/$b")")
  [ "$found" = grehack/life/v1/life.proto ] || { echo "$b: $found"; exit 1; }
done
EOF

# Test plan 3: server, spy and a scripted client in the image. As root, as
# the spy must be; the image's own default user runs the rest in practice.
check "server, spy and client: every call saved, in pairs" --user 0 <<'EOF'
set -e
life-server 2>/tmp/server.log &
life-spy --out /tmp/cap >/tmp/spy.log 2>&1 &
sleep 3
life-client --steps 20 --size 20x10 --pattern glider
life-spy --out /tmp/cap --stop
grep -q "20 requests and 20 responses saved, 0 messages missed" /tmp/spy.log \
  || { tail -5 /tmp/spy.log; exit 1; }
for n in $(seq -f %06g 1 20); do
  for d in request response; do
    prototext decode --raw "/tmp/cap/$n-$d.pb" >/dev/null
  done
done
tshark -r /tmp/cap/capture.pcapng >/dev/null 2>&1
EOF

# Test plan 8: nothing but the two binaries names the schema's package.
check "only the binaries carry the schema" <<'EOF'
set -e
found=$(grep -rl grehack.life.v1 /nix/store | grep -v -e /bin/life-client -e /bin/life-server || true)
[ -z "$found" ] || { printf '%s\n' "$found"; exit 1; }
EOF

# Spec 0375 S8 and S9: tmux, and buf without its plugins.
check "tmux, and buf without protoc-gen-buf" <<'EOF'
set -e
tmux -V
! ls /nix/store/*/bin/protoc-gen-buf-* >/dev/null 2>&1
EOF

# Spec 0379 test plan 3: the server smuggles "hello client <N>" into each
# response's tags, the client echoes "hi server <N>" in the next request, and
# the server checks it. The handshake rides spec 0377's tag channel both ways.
check "the tags carry an echo handshake (spec 0379)" <<'EOF'
set -e
life-server >/tmp/tags.bin 2>/tmp/tags.err &
sleep 2
life-client --steps 6 --size 20x20 --pattern glider >/dev/null
sleep 0.5
kill %1 2>/dev/null || true
# The first request has nothing to echo (spec 0379 G4), so 6 requests give
# 5 "echo ok" lines and no mismatch.
ok=$(grep -c "echo ok" /tmp/tags.err || true)
[ "$ok" -eq 5 ] || { echo "got $ok 'echo ok' lines, want 5"; tail -8 /tmp/tags.err; exit 1; }
! grep -q "echo mismatch" /tmp/tags.err || { echo "a mismatch"; tail -8 /tmp/tags.err; exit 1; }
# One raw bit-field line per request on stdout.
[ "$(wc -l < /tmp/tags.bin)" -eq 6 ] || { echo "want 6 stdout lines"; exit 1; }
EOF

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
