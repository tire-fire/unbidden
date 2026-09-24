#!/bin/sh
# Fails unless the binary is statically linked (§3, §12).
#
# ldd cannot answer this for a binary built for another architecture: it
# reports every foreign binary as "not a dynamic executable", so on an x86
# runner the aarch64 build passed whatever it was. The ELF headers answer it
# for any architecture. A static binary has no interpreter to name and no
# shared object to need; a static-pie still has a dynamic section, for its
# own relocations, but no NEEDED entry in it.
#
# Usage: static-check.sh <binary>
set -eu

bin="${1:?path to the binary}"
[ -f "$bin" ] || { echo "no binary at $bin" >&2; exit 1; }

readelf -h "$bin" >/dev/null 2>&1 || { echo "$bin is not an ELF file" >&2; exit 1; }
machine=$(readelf -h "$bin" | sed -n 's/^ *Machine: *//p')

if readelf -lW "$bin" | grep -q 'Requesting program interpreter'; then
    echo "$bin ($machine) names a program interpreter; it is dynamically linked:" >&2
    readelf -lW "$bin" | grep 'program interpreter' >&2
    exit 1
fi
needed=$(readelf -dW "$bin" 2>/dev/null | grep '(NEEDED)' || true)
if [ -n "$needed" ]; then
    echo "$bin ($machine) needs shared objects:" >&2
    echo "$needed" >&2
    exit 1
fi
echo "$bin ($machine): static, no interpreter, no shared objects needed"
