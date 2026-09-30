#!/bin/sh
# Builds the .deb and .rpm of one static binary with nfpm.
#
# Usage: package.sh <binary> <amd64|arm64> <version> <output directory>
#
# nfpm is downloaded at a pinned version and checked against the digest
# published with that release, so a release's packages do not depend on
# whatever a mirror serves that day.
set -eu

bin=$1 arch=$2 version=$3 out=$4
NFPM_VERSION_PIN=2.47.0
NFPM_SHA256=0660ca602b2d2d2ae4781a06c692b3eeb9d437ffea05b831d76e41f4a3188783

case "$arch" in amd64|arm64) ;; *) echo "unknown architecture: $arch" >&2; exit 2 ;; esac
[ -x "$bin" ] || { echo "$bin is not an executable file" >&2; exit 2; }

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
curl -fsSL -o "$work/nfpm.tgz" \
    "https://github.com/goreleaser/nfpm/releases/download/v$NFPM_VERSION_PIN/nfpm_${NFPM_VERSION_PIN}_Linux_x86_64.tar.gz"
echo "$NFPM_SHA256  $work/nfpm.tgz" | sha256sum -c - >/dev/null
tar -xzf "$work/nfpm.tgz" -C "$work" nfpm

mkdir -p "$out"
for format in deb rpm; do
    NFPM_ARCH=$arch NFPM_VERSION=$version NFPM_BINARY=$bin \
        "$work/nfpm" package --config "$(dirname "$0")/nfpm.yaml" --packager "$format" --target "$out"
done
ls -l "$out"
