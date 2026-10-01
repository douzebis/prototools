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

# Spec 0382 test plan 5: the operator types N on the server's stdin; the
# server sends "factor <N>" in the next response's tags, the client factors N
# in the background and sends "factors ..." back in a request's tags, and the
# server checks the factors and prints them on stdout. The exchange rides
# spec 0377's tag channel both ways.
check "the client factors the server's number (spec 0382)" <<'EOF'
set -e
# The operator: one rejected line (1 has no factors), then a number, then
# stdin held open a while.
{ sleep 1; echo 1; echo 600851475143; sleep 8; } |
  life-server --verbose >/tmp/tags.out 2>/tmp/tags.err &
sleep 2
life-client --steps 12 --size 20x20 --pattern glider >/dev/null
sleep 0.5
kill %1 2>/dev/null || true
grep -q 'rejected "1"' /tmp/tags.err || { echo "1 not rejected"; tail -12 /tmp/tags.err; exit 1; }
grep -q "N=600851475143 queued" /tmp/tags.err || { echo "N not queued"; tail -12 /tmp/tags.err; exit 1; }
# The number is sent once (spec 0379 S2), so it is answered once (0382 S4).
ok=$(grep -a -c "^600851475143 = 71 \* 839 \* 1471 \* 6857$" /tmp/tags.out || true)
[ "$ok" -eq 1 ] || { echo "got $ok result lines, want 1"; grep -a " = " /tmp/tags.out; exit 1; }
! grep -q "wrong\|nothing was awaited" /tmp/tags.err || { echo "a bad reply"; tail -12 /tmp/tags.err; exit 1; }
# Under --verbose (spec 0379 S7): one raw bit-field line per request on
# stdout beside the result line, and one generation line per request on
# stderr.
[ "$(wc -l < /tmp/tags.out)" -eq 13 ] || { echo "want 13 stdout lines"; exit 1; }
[ "$(grep -c ' generation ' /tmp/tags.err)" -eq 12 ] || { echo "want 12 generation lines"; exit 1; }

# stdin at end of file: the server keeps serving and sends nothing (0379 S6).
# Without --verbose (S7) it prints nothing per request: stdout stays empty.
life-server --listen 127.0.0.1:50052 </dev/null >/tmp/eof.out 2>/tmp/eof.err &
sleep 2
life-client --server http://127.0.0.1:50052 --steps 3 --size 20x20 >/dev/null
sleep 0.5
kill %2 2>/dev/null || true
! grep -q "factors\|awaited" /tmp/eof.err || { echo "a reply with no operator"; cat /tmp/eof.err; exit 1; }
! grep -q " generation " /tmp/eof.err || { echo "a generation line without --verbose"; exit 1; }
[ ! -s /tmp/eof.out ] || { echo "stdout not empty without --verbose"; exit 1; }
EOF

# Spec 0382 S3: at --self-echo-percentage 100 the server sends a random u64
# whenever no number awaits its factors; the client factors each one.
check "the server sends numbers on its own (spec 0382)" <<'EOF'
set -e
! life-server --self-echo-percentage 101 </dev/null 2>/dev/null || { echo "101 accepted"; exit 1; }
life-server --self-echo-percentage 100 </dev/null >/tmp/self.out 2>/tmp/self.err &
sleep 2
life-client --steps 50 --size 20x20 --pattern glider >/dev/null
sleep 0.5
kill %1 2>/dev/null || true
ok=$(grep -c " = " /tmp/self.out || true)
[ "$ok" -ge 1 ] || { echo "no result line"; tail -8 /tmp/self.err; exit 1; }
! grep -q "wrong\|nothing was awaited" /tmp/self.err || { echo "a bad reply"; tail -8 /tmp/self.err; exit 1; }
EOF

# Spec 0381 test plan 4: life-client renews its own connection between two
# steps, so no step races a close. The server keeps connections open (S8);
# the client renews every second, for about 65 renewals.
check "the client renews its connection (spec 0381)" <<'EOF'
set -e
life-server </dev/null >/dev/null 2>/tmp/renew.err &
sleep 2
rc=0
timeout 65 life-client --renew-every 1 --steps 100000000 --size 106x61 \
  >/tmp/renew.out 2>&1 || rc=$?
kill %1 2>/dev/null || true
# 124 is timeout's: the client was still stepping, with no error, at 65 s.
[ "$rc" -eq 124 ] || { echo "the client exited $rc"; cat /tmp/renew.out; exit 1; }
EOF

# Spec 0381 test plan 6: a spy started after the client misses the traffic
# of the connection it did not see open, says so, then reads the next one
# whole, which the client opens within 5 s (S7, S9).
check "a late spy catches up (spec 0381)" --user 0 <<'EOF'
set -e
life-server </dev/null >/dev/null 2>&1 &
timeout 14 life-client --steps 100000000 --size 20x10 >/dev/null 2>&1 &
sleep 1
life-spy --out /tmp/late >/tmp/late.log 2>&1 &
sleep 11
life-spy --out /tmp/late --stop
grep -q "life-client renews its connection every" /tmp/late.log \
  || { echo "no missed-messages note"; tail -5 /tmp/late.log; exit 1; }
summary=$(grep "stopped:" /tmp/late.log)
# The image has no sed: bash's own regex reads the two counts.
[[ $summary =~ stopped:\ ([0-9]+)\ requests.*saved,\ ([0-9]+)\ messages\ missed ]] \
  || { echo "no summary: $summary"; exit 1; }
[ "${BASH_REMATCH[1]}" -gt 0 ] && [ "${BASH_REMATCH[2]}" -gt 0 ] \
  || { echo "want calls saved and some missed: $summary"; exit 1; }
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
