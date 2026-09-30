<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# GreHack 2026 — prototools workshop setup

The workshop runs in a container image holding prototools and everything
they need. You need a container runtime on your laptop, nothing else. The
image exists for x86-64 and arm64, and your runtime picks the right one.

## 1. Install a container runtime (before the event)

Any OCI runtime works. We recommend:

| Laptop | Recommended | Install guide |
|---|---|---|
| Linux (x86-64 or arm64) | Docker Engine | <https://docs.docker.com/engine/install/> |
| Linux, alternative | Podman | <https://podman.io/docs/installation> |
| macOS (Apple silicon or Intel) | Colima with the `docker` CLI: `brew install colima docker` | <https://github.com/abiosoft/colima#installation> |
| macOS, alternative | Podman | <https://podman.io/docs/installation> |

All of these are open source. Docker Desktop works too if you already have
it.

Then start the runtime once and check it works:

```sh
colima start             # macOS with Colima only
podman machine init      # macOS with Podman only, then:
podman machine start
docker run --rm hello-world     # or: podman run --rm hello-world
```

**Please do this at home.** On macOS, Colima and Podman download a Linux VM
image on their first start (a few hundred MB). The USB keys at the event do
not carry it.

## 2. Get the workshop image

At home, if you can (about 240 MB):

```sh
docker pull ghcr.io/douzebis/prototools-workshop:grehack2026
```

Otherwise, at the event, from a USB key, offline:

```sh
/path/to/usb-key/load.sh        # RUNTIME=podman /path/to/usb-key/load.sh for Podman
```

`load.sh` picks the image for your laptop, checks its SHA-256 sum and loads
it.

## 3. Run it

From the directory you want to share with the container:

```sh
docker run -it --rm -e TERM -e COLORTERM -v "$PWD":/work \
    ghcr.io/douzebis/prototools-workshop:grehack2026
```

With **Docker on Linux**, add `--user "$(id -u):$(id -g)"` so the files you
write to `/work` are yours. Rootless Podman, and Colima or Podman on macOS,
handle this already. With Podman, replace `docker` with `podman`.

You land in `/workshop`, which holds the workshop material. Your directory
is at `/work`. Anything written elsewhere disappears when you leave the
container.

## If it does not start

- **"exec format error" on a Mac:** the runtime cannot run the arm64 image.
  Use the x86-64 image under Rosetta instead: start Colima with
  `colima start --vm-type vz --vz-rosetta`, then add `--platform linux/amd64`
  to `docker pull` and `docker run` (from the USB key:
  `docker load -i prototools-workshop-amd64.tar`, then the same `docker run`).
  It is slower, but works.
- **"permission denied" on the Docker socket (Linux):** see
  <https://docs.docker.com/engine/install/linux-postinstall/>, or use
  `sudo docker`.
