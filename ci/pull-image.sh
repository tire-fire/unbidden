#!/bin/bash
# Pull a container image, retrying: any registry resets a connection now and
# then, and the pull is the only part of the checks that talks to one.
set -uo pipefail

image="${1:?usage: pull-image.sh IMAGE}"
for i in 1 2 3; do
    docker pull "$image" && exit 0
    # AWS caps anonymous pulls by volume, and the runners share addresses.
    # Google's mirror of the same library stands in.
    case "$image" in
        public.ecr.aws/docker/library/*)
            alt="mirror.gcr.io/library/${image#public.ecr.aws/docker/library/}"
            docker pull "$alt" && docker tag "$alt" "$image" && exit 0
            ;;
    esac
    sleep $((i * 10))
done
exit 1
