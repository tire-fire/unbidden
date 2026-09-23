#!/bin/bash
# Boots a disposable VM of a supported distribution, plants each PANIX
# persistence mechanism in it, and checks that unbidden finds it and stops
# reporting it once it is reverted.
#
# A VM rather than a container because half the mechanisms need a real boot
# and a running systemd, and because PANIX installs genuine persistence —
# nothing here should touch the machine you are sitting at.
#
# Everything is disposable: the image is a cached cloud image, the disk is a
# copy-on-write overlay thrown away at the end, and the network is qemu's
# user-mode NAT with a single forwarded SSH port bound to localhost.
#
#   ci/vm-harness.sh                       # Debian 12, the whole matrix
#   ci/vm-harness.sh --image fedora-44
#   ci/vm-harness.sh --modules "cron udev systemd"
#   ci/vm-harness.sh --keep                # leave it running to poke at
#   ci/vm-harness.sh --shell               # boot, provision, hand over a shell
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="${UNBIDDEN_VM_DIR:-/var/tmp/unbidden-vm}"
CACHE="$WORK/cache"
IMAGE=debian-12
MODULES=""
ALL=0
KEEP=0
SHELL_ONLY=0
MEM=2048
CPUS=2

while [ $# -gt 0 ]; do
    case "$1" in
        --image)   IMAGE="$2"; shift 2 ;;
        --all)     ALL=1; shift ;;
        --modules) MODULES="$2"; shift 2 ;;
        --keep)    KEEP=1; shift ;;
        --shell)   SHELL_ONLY=1; KEEP=1; shift ;;
        --mem)     MEM="$2"; shift 2 ;;
        --cpus)    CPUS="$2"; shift 2 ;;
        -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

# The supported set of §1. A defect on any of these blocks a release, so the
# matrix is a first-class mode rather than something a caller loops over.
SUPPORTED=(debian-12 debian-13 ubuntu-22.04 ubuntu-24.04 fedora-43 fedora-44)

if [ "$ALL" -eq 1 ]; then
    declare -a RESULTS=()
    worst=0
    for img in "${SUPPORTED[@]}"; do
        if "$0" --image "$img" ${MODULES:+--modules "$MODULES"}; then
            RESULTS+=("  PASS  $img")
        else
            RESULTS+=("  FAIL  $img")
            worst=1
        fi
    done
    printf '\n== the supported set\n'
    printf '%s\n' "${RESULTS[@]}"
    exit "$worst"
fi

# Cloud images, because they boot unattended and are the same artefacts the
# distributions publish for real use.
case "$IMAGE" in
    debian-12)    URL=https://cloud.debian.org/images/cloud/bookworm/latest/debian-12-genericcloud-amd64.qcow2; FAMILY=debian ;;
    debian-13)    URL=https://cloud.debian.org/images/cloud/trixie/latest/debian-13-genericcloud-amd64.qcow2;  FAMILY=debian ;;
    ubuntu-22.04) URL=https://cloud-images.ubuntu.com/jammy/current/jammy-server-cloudimg-amd64.img;           FAMILY=debian ;;
    ubuntu-24.04) URL=https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img;           FAMILY=debian ;;
    # Fedora names its images by compose, and a respin replaces the file, so
    # the name is read from the release directory rather than pinned.
    fedora-*)     URL=fedora:${IMAGE#fedora-}; FAMILY=fedora ;;
    *) echo "unknown image: $IMAGE" >&2; exit 2 ;;
esac

for tool in qemu-system-x86_64 qemu-img xorriso ssh-keygen curl ssh scp; do
    command -v "$tool" >/dev/null || { echo "missing: $tool" >&2; exit 1; }
done
[ -r /dev/kvm ] || echo "warning: /dev/kvm not readable, the VM will be emulated and slow" >&2

INSTANCE="$WORK/$IMAGE"
mkdir -p "$CACHE" "$INSTANCE"

say() { printf '\n== %s\n' "$*"; }

# --- the binary under test ---------------------------------------------
# Static musl, because that is what ships and what an operator copies onto a
# host. A glibc build from this machine would not run on the guest anyway.
BIN="$REPO/target/x86_64-unknown-linux-musl/release/unbidden"
# A binary older than the source it was built from is the quietest way to
# test the wrong thing: the run passes, and it passes on yesterday's code.
stale=0
if [ -x "$BIN" ]; then
    newer=$(find "$REPO/src" "$REPO/Cargo.toml" "$REPO/Cargo.lock" -newer "$BIN" -print -quit 2>/dev/null)
    if [ -n "$newer" ]; then
        echo "   the staged binary is older than $newer; rebuilding"
        stale=1
    fi
fi
if [ ! -x "$BIN" ] || [ "$stale" -eq 1 ]; then
    if rustup target list --installed 2>/dev/null | grep -q x86_64-unknown-linux-musl; then
        say "building the static binary"
        (cd "$REPO" && cargo build --release --locked --target x86_64-unknown-linux-musl)
    elif command -v docker >/dev/null; then
        say "building the static binary in a container"
        mkdir -p "$WORK/target"
        docker run --rm -v "$REPO:/src:ro" -v "$WORK/target:/target" -w /src \
            -e CARGO_TARGET_DIR=/target rust:alpine \
            sh -c 'apk add --no-cache musl-dev gcc >/dev/null && cargo build --release --locked --target x86_64-unknown-linux-musl'
        BIN="$WORK/target/x86_64-unknown-linux-musl/release/unbidden"
    else
        echo "no musl target and no docker; install one or build the binary yourself" >&2
        exit 1
    fi
fi
[ -x "$BIN" ] || { echo "no static binary at $BIN" >&2; exit 1; }

# --- the fixtures ------------------------------------------------------
BASE="$CACHE/$IMAGE.qcow2"
if [ ! -f "$BASE" ]; then
    if [[ "$URL" == fedora:* ]]; then
        release=${URL#fedora:}
        dir="https://dl.fedoraproject.org/pub/fedora/linux/releases/$release/Cloud/x86_64/images/"
        name=$(curl -fsSL --retry 3 "$dir" | grep -oE "Fedora-Cloud-Base-Generic-$release-[0-9.]+\.x86_64\.qcow2" | sort -uV | tail -1)
        [ -n "$name" ] || { echo "no Fedora $release cloud image listed at $dir" >&2; exit 1; }
        URL="$dir$name"
    fi
    say "fetching the $IMAGE cloud image"
    echo "   $URL"
    curl -fsSL --retry 3 -o "$BASE.part" "$URL"
    mv "$BASE.part" "$BASE"
fi

PANIX="$CACHE/panix"
if [ ! -d "$PANIX" ]; then
    say "cloning PANIX"
    git clone -q --depth 1 https://github.com/Aegrah/PANIX.git "$PANIX"
fi

KEY="$INSTANCE/key"
[ -f "$KEY" ] || ssh-keygen -q -t ed25519 -N '' -f "$KEY" -C unbidden-harness

# PANIX needs the mechanisms' own tooling present or it refuses to plant.
case "$FAMILY" in
    # gcc because two PANIX modules compile their payload before planting it;
    # libcap's tools for cap, rpm-build for malicious-package on Fedora.
    debian) PKGS='[cron, at, sudo, git, network-manager, dbus, openssh-server, python3, gcc, build-essential, udev, libcap2-bin]' ;;
    # Fedora's bus is dbus-broker, which reads the same activation and policy
    # directories as dbus-daemon. PANIX will not plant without the daemon's
    # binary on PATH, so it is installed; the running bus stays the broker.
    fedora) PKGS='[cronie, at, sudo, git, NetworkManager, dbus, dbus-daemon, openssh-server, python3, gcc, make, rpm-build, libcap]' ;;
esac
# lkm builds its module against the kernel that is running, whose version is
# only known inside the guest — so this line runs there. The single quotes
# keep the runner from expanding it, and a heredoc does not expand the value
# of a variable a second time.
# shellcheck disable=SC2016
HEADERS='[ sh, -c, "apt-get install -y linux-headers-$(uname -r) || dnf install -y kernel-devel-$(uname -r)" ]'

cat > "$INSTANCE/user-data" <<EOF
#cloud-config
disable_root: false
ssh_pwauth: false
users:
  - name: root
    lock_passwd: true
    ssh_authorized_keys:
      - $(cat "$KEY.pub")
package_update: true
packages: $PKGS
runcmd:
  - $HEADERS
  - [ systemctl, enable, --now, sshd ]
  - [ systemctl, enable, --now, ssh ]
  - [ touch, /root/.harness-ready ]
EOF
printf 'instance-id: unbidden-%s\nlocal-hostname: unbidden-target\n' "$IMAGE" > "$INSTANCE/meta-data"
xorriso -as mkisofs -quiet -output "$INSTANCE/seed.iso" -volid cidata -joliet -rock \
    "$INSTANCE/user-data" "$INSTANCE/meta-data"

# A fresh overlay every run: the base image is never written to, so a
# mechanism whose revert is incomplete cannot poison the next run.
rm -f "$INSTANCE/overlay.qcow2"
qemu-img create -q -f qcow2 -F qcow2 -b "$BASE" "$INSTANCE/overlay.qcow2" 20G

# --- boot --------------------------------------------------------------
PORT=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')
# scp spells the port -P and reads -p as "preserve timestamps", so the two
# cannot share one option array.
SSHOPTS=(-i "$KEY" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null
         -o LogLevel=ERROR -o ConnectTimeout=5)
vm_ssh() { ssh -p "$PORT" "${SSHOPTS[@]}" root@127.0.0.1 "$@"; }
vm_scp() { scp -q -P "$PORT" "${SSHOPTS[@]}" "$@"; }

cleanup() {
    status=$?
    if [ -f "$INSTANCE/qemu.pid" ] && [ "$KEEP" -eq 0 ]; then
        kill "$(cat "$INSTANCE/qemu.pid")" 2>/dev/null || true
        rm -f "$INSTANCE/qemu.pid" "$INSTANCE/overlay.qcow2"
    fi
    exit $status
}
trap cleanup EXIT INT TERM

ACCEL=()
[ -r /dev/kvm ] && ACCEL=(-enable-kvm -cpu host)
say "booting $IMAGE"
qemu-system-x86_64 \
    "${ACCEL[@]}" \
    -m "$MEM" -smp "$CPUS" -display none -daemonize \
    -drive "file=$INSTANCE/overlay.qcow2,if=virtio,format=qcow2" \
    -drive "file=$INSTANCE/seed.iso,if=virtio,format=raw,readonly=on" \
    -netdev "user,id=n0,hostfwd=tcp:127.0.0.1:$PORT-:22" -device virtio-net-pci,netdev=n0 \
    -serial "file:$INSTANCE/console.log" -pidfile "$INSTANCE/qemu.pid"

# One loop, not two. cloud-init restarts sshd as it provisions, so a probe
# that succeeds and is then verified a second time can fail on the restart —
# which looked exactly like a VM that never booted. Waiting for the marker
# file is the only condition that matters, and it tolerates ssh going away
# and coming back underneath it.
printf '   waiting for ssh and cloud-init on 127.0.0.1:%s' "$PORT"
ready=0
# Twelve and a half minutes under KVM. Emulated, provisioning alone (a
# package install with gcc in it) runs many times slower.
tries=150
[ ${#ACCEL[@]} -eq 0 ] && tries=900
for _ in $(seq 1 "$tries"); do
    if vm_ssh 'test -f /root/.harness-ready' 2>/dev/null; then
        ready=1
        break
    fi
    printf .
    sleep 5
done
echo
if [ "$ready" -ne 1 ]; then
    echo "the VM never finished provisioning; see $INSTANCE/console.log" >&2
    tail -5 "$INSTANCE/console.log" >&2 2>/dev/null
    exit 1
fi
vm_ssh 'cat /etc/os-release | sed -n "s/^PRETTY_NAME=//p"'

say "installing the harness"
vm_scp "$BIN" root@127.0.0.1:/usr/local/bin/unbidden
vm_scp "$REPO/ci/panix-loop.sh" "$REPO/ci/panix-coverage.tsv" "$REPO/ci/distro-check.sh" "$REPO/ci/live-check.sh" \
    root@127.0.0.1:/usr/local/bin/
vm_scp -r "$PANIX" root@127.0.0.1:/opt/panix
vm_ssh 'chmod +x /usr/local/bin/unbidden /usr/local/bin/*.sh /opt/panix/panix.sh'

if [ "$SHELL_ONLY" -eq 1 ]; then
    say "the VM is yours"
    echo "   ssh -p $PORT ${SSHOPTS[*]} root@127.0.0.1"
    echo "   console: $INSTANCE/console.log"
    echo "   stop it: kill \$(cat $INSTANCE/qemu.pid)"
    exit 0
fi

rc=0

say "packaging and provenance"
vm_ssh 'sh /usr/local/bin/distro-check.sh /usr/local/bin/unbidden' || rc=1

say "against the running system"
vm_ssh 'sh /usr/local/bin/live-check.sh /usr/local/bin/unbidden' || rc=1

say "persistence mechanisms"
vm_ssh "bash /usr/local/bin/panix-loop.sh /usr/local/bin/unbidden /opt/panix/panix.sh $MODULES" || rc=1

say "$IMAGE finished with status $rc"
exit $rc
