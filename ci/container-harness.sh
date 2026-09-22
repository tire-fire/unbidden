#!/bin/bash
# The PANIX loop and the live checks, for the supported distributions that
# publish no cloud image: Linux Mint and LMDE. The image boots systemd as PID
# 1 in a privileged container, which gives the mechanisms a real service
# manager, a real system bus and real timers to plant into.
#
# What a container cannot give them is a kernel of its own. The lkm module
# would load its module into the kernel the container shares with the runner,
# so it is the one module not run here — named, with the reason, in the
# loop's output rather than quietly missing. The VM harness runs it on the
# distributions these are built on.
#
#   ci/container-harness.sh --image linuxmintd/mint21-amd64 --expect linuxmint:21
#   ci/container-harness.sh --image linuxmintd/mint22-amd64 --expect linuxmint:22 --mint-base-files
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE=""
EXPECT=""
MINT_BASE=0
INSTALL=1
MODULES=""
BIN="${UNBIDDEN_BIN:-$REPO/target/x86_64-unknown-linux-musl/release/unbidden}"
PANIX="${UNBIDDEN_PANIX:-}"

while [ $# -gt 0 ]; do
    case "$1" in
        --image)           IMAGE="$2"; shift 2 ;;
        --expect)          EXPECT="$2"; shift 2 ;;
        --mint-base-files) MINT_BASE=1; shift ;;
        # For an image that already carries the tooling, or a machine with no
        # route to the archive: what cannot be planted then fails as such.
        --no-install)      INSTALL=0; shift ;;
        --modules)         MODULES="$2"; shift 2 ;;
        --bin)             BIN="$2"; shift 2 ;;
        --panix)           PANIX="$2"; shift 2 ;;
        -h|--help)         sed -n '2,16p' "$0"; exit 0 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done
[ -n "$IMAGE" ] || { echo "--image is required" >&2; exit 2; }
[ -x "$BIN" ] || { echo "no static binary at $BIN" >&2; exit 1; }

say() { printf '\n== %s\n' "$*"; }

if [ -z "$PANIX" ]; then
    PANIX=$(mktemp -d)/panix
    git clone -q --depth 1 https://github.com/Aegrah/PANIX.git "$PANIX"
fi

name="unbidden-$(echo "$IMAGE" | tr -c 'a-z0-9' -)$$"
cleanup() { docker rm -f "$name" >/dev/null 2>&1 || true; }
trap cleanup EXIT INT TERM

say "booting $IMAGE with systemd"
docker run -d --name "$name" --privileged --cgroupns=host \
    -v /sys/fs/cgroup:/sys/fs/cgroup:rw --tmpfs /run --tmpfs /run/lock \
    "$IMAGE" /sbin/init >/dev/null
for _ in $(seq 1 60); do
    state=$(docker exec "$name" systemctl is-system-running 2>/dev/null || true)
    case "$state" in running|degraded) break ;; esac
    sleep 2
done
echo "   systemd is $state"

in_box() { docker exec -e DEBIAN_FRONTEND=noninteractive "$name" "$@"; }

# Mint 22's published image carries Ubuntu's base-files and so reports
# itself as Ubuntu 24.04. Its apt sources already point at Mint's own
# repository, pinned above Ubuntu's, and Mint's base-files there is what
# makes a Mint 22 install say so. Installing it is the step the image skips.
if [ "$MINT_BASE" -eq 1 ]; then
    say "installing Mint's own base-files"
    in_box apt-get -qq update
    in_box apt-get -qq install -y base-files >/dev/null
fi

if [ "$INSTALL" -eq 1 ]; then
    say "installing what the mechanisms need"
    in_box apt-get -qq update
    # The same tooling the VM harness gives a Debian-family guest, less the
    # kernel headers lkm alone would use.
    in_box apt-get -qq install -y --no-install-recommends \
        cron at sudo git network-manager dbus openssh-server python3 gcc build-essential \
        udev libcap2-bin procps >/dev/null
    in_box systemctl enable --now cron atd ssh >/dev/null 2>&1 || true
fi

docker cp "$BIN" "$name:/usr/local/bin/unbidden"
for f in panix-loop.sh panix-coverage.tsv distro-check.sh live-check.sh; do
    docker cp "$REPO/ci/$f" "$name:/usr/local/bin/$f"
done
docker cp "$PANIX" "$name:/opt/panix"
in_box chmod +x /usr/local/bin/unbidden /opt/panix/panix.sh

rc=0
expect_id=${EXPECT%%:*}
expect_version=${EXPECT#*:}
[ "$expect_version" = "$EXPECT" ] && expect_version=""

say "packaging and provenance"
in_box env UNBIDDEN_EXPECT_ID="$expect_id" UNBIDDEN_EXPECT_VERSION="$expect_version" \
    sh /usr/local/bin/distro-check.sh /usr/local/bin/unbidden || rc=1

say "against the running system"
in_box sh /usr/local/bin/live-check.sh /usr/local/bin/unbidden || rc=1

say "persistence mechanisms"
# shellcheck disable=SC2086
in_box env UNBIDDEN_PANIX_SKIP=lkm \
    UNBIDDEN_PANIX_SKIP_REASON="a container shares the runner's kernel; the VM harness runs it" \
    bash /usr/local/bin/panix-loop.sh /usr/local/bin/unbidden /opt/panix/panix.sh $MODULES || rc=1

say "$IMAGE finished with status $rc"
exit $rc
