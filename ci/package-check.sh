#!/bin/sh
# Installs the x86_64 packages of a release in a Debian and a Fedora container
# and checks each puts a working binary of the right version on the PATH.
#
# Usage: package-check.sh <version> <directory holding the packages>
set -eu

v=$1 dir=$(cd "$2" && pwd)

bash "$(dirname "$0")/pull-image.sh" debian:13
docker run --rm -v "$dir:/p:ro" debian:13 sh -c "
    apt-get install -y -qq /p/unbidden_${v}_amd64.deb >/dev/null &&
    [ \"\$(unbidden --version)\" = 'unbidden $v' ]" ||
    { echo "the .deb does not install a working unbidden $v" >&2; exit 1; }

bash "$(dirname "$0")/pull-image.sh" fedora:44
docker run --rm -v "$dir:/p:ro" fedora:44 sh -c "
    dnf -q -y install /p/unbidden-${v}-1.x86_64.rpm >/dev/null &&
    [ \"\$(unbidden --version)\" = 'unbidden $v' ]" ||
    { echo "the .rpm does not install a working unbidden $v" >&2; exit 1; }
echo "the packages install and report $v"
