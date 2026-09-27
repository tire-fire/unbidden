# Test vectors

What pam-auth-update and authselect wrote when run on generated inputs,
recorded so that `src/provenance/reproduced.rs` can be required to reproduce
it byte for byte. That module is written from the tools' documentation and
from these recordings, not from the tools' source.

Each `*.case` file is one run: every file the tool read or wrote, as
`=== <path> <length>`, exactly that many bytes, then a newline, so a missing
final newline survives. The templates and profiles are generated here, not
copied from any package.

## Regenerating

Docker, with the images used offline:

    T=tests/vectors/tools
    W=$(mktemp -d)

    python3 $T/pam-auth-update/gen.py $W/pau 7 160
    docker run --rm --network none -e HOSTUID=$(id -u) \
        -v $W/pau:/cases -v $PWD/$T/pam-auth-update/run.sh:/run.sh \
        public.ecr.aws/docker/library/debian:12 /run.sh
    python3 $T/pack.py pam-auth-update $W/pau tests/vectors/pam-auth-update

    python3 $T/authselect/gen.py $W/as 2 150
    docker run --rm --network none -e HOSTUID=$(id -u) \
        -v $W/as:/cases -v $PWD/$T/authselect/run.sh:/run.sh \
        public.ecr.aws/docker/library/fedora:44 /run.sh
    python3 $T/pack.py authselect $W/as tests/vectors/authselect

The recorded runs used libpam-runtime 1.5.2 (Debian 12) and authselect 1.7.1
(Fedora 44). A case where pam-auth-update selects no profile makes it prompt
until `run.sh`'s 60-second timeout; it writes nothing and is not packed.
