#!/bin/sh
# The checks that need a running system rather than an image: a VM from
# vm-harness.sh, or a container booted with systemd as PID 1.
#
#   - §11 rule 2: the symlink-resolution enablement path is the offline
#     implementation, and a live host is the only place its answers can be
#     checked against systemd's. Every unit systemd answers for is compared.
#   - §13, Ubuntu: installed snaps do not flood the output as Unpackaged.
#   - §13, Fedora: SELinux enforcing does not block collection.
#
# Usage: live-check.sh <path-to-static-binary>
set -eu

BIN="$1"
fail() { echo "FAIL: $*" >&2; exit 1; }
note() { echo "  $*"; }
field() { sed -n "s/.*\"$1\":\"\([^\"]*\)\".*/\1/p"; }

. /etc/os-release
echo "== live checks on $ID $VERSION_ID"

[ -S /run/systemd/private ] || fail "systemd is not running here; these checks need a live manager"

# --- SELinux ----------------------------------------------------------
# Fedora ships enforcing. Collection must not be blocked by it, which shows
# as a collector that could not read something it needed.
if [ "$ID" = fedora ]; then
    [ -r /sys/fs/selinux/enforce ] || fail "no SELinux on a Fedora machine; this is not the configuration §13 names"
    [ "$(cat /sys/fs/selinux/enforce)" = 1 ] || fail "SELinux is not enforcing on this Fedora machine"
    note "SELinux is enforcing"
fi

# --- snap -------------------------------------------------------------
# A snap with a daemon brings a service unit no package database knows about.
# Unrecognised, it reads Unpackaged, the same verdict an attacker's unit gets.
# The snap has to have a service: one without, like hello-world, brings only
# mount units, which are not collected, and the check below would have
# nothing to look at. Ubuntu 24.04's image ships no snap with a service. The
# snap comes from the store, so this needs network.
if [ "$ID" = ubuntu ]; then
    command -v snap >/dev/null || fail "no snapd on Ubuntu"
    snap list mosquitto >/dev/null 2>&1 || {
        for i in 1 2 3; do snap install mosquitto >/dev/null 2>&1 && break; sleep $((i * 15)); done
    }
    snap list mosquitto >/dev/null 2>&1 || fail "could not install a snap to check against"
fi

out=$(mktemp)
"$BIN" --json --all > "$out"
header=$(head -1 "$out")

# A kernel with no /proc/modules at all — some sandboxed runtimes — leaves
# the kernel collector partial for a reason that is true and not unbidden's.
# That one case is allowed where, and only where, the file is really absent.
checked_header=$header
[ -e /proc/modules ] ||
    checked_header=$(echo "$header" | sed 's/{"name":"kernel","status":"partial","unreadable":\["proc\/modules: absent[^]]*\]/{"name":"kernel"/')
for status in partial failed; do
    echo "$checked_header" | grep -q "\"status\":\"$status\"" &&
        fail "a collector is $status on a live machine, as root: $header"
done
echo "$header" | grep -q '"enrichment_failures"' && fail "an enrichment stage failed: $header"
note "every collector is complete"

echo "$header" | grep -q '"enablement":"systemd-dbus"' ||
    fail "systemd is running but enablement did not come from it: $header"

# --- the symlink fallback against systemd -------------------------------
# D-Bus enrichment keeps what the walk inferred as inferred_enablement. A
# state systemd has its own word for — alias, indirect, generated, linked,
# transient — has no inferred counterpart to compare with and is left out.
checked=0
bad=""
tail -n +2 "$out" | grep -E '"kind":"systemd_(unit|timer)"' | grep '"inferred_enablement"' > "$out.units" || true
while IFS= read -r line; do
    inferred=$(echo "$line" | field inferred_enablement)
    state=$(echo "$line" | field unit_file_state)
    case "$state" in
        enabled|enabled-runtime) want=enabled ;;
        disabled)                want=disabled ;;
        static)                  want=static ;;
        masked|masked-runtime)   want=masked ;;
        *)                       continue ;;
    esac
    checked=$((checked + 1))
    [ "$inferred" = "$want" ] ||
        bad="$bad
    $(echo "$line" | field source): inferred $inferred, systemd says $state"
done < "$out.units"
rm -f "$out.units"
[ -z "$bad" ] || fail "the symlink fallback disagrees with systemd:$bad"
[ "$checked" -gt 20 ] || fail "only $checked units could be compared with systemd; the enrichment is not matching them"
note "the symlink fallback agrees with systemd on all $checked units it could be compared on"

if [ "$ID" = ubuntu ]; then
    snaps=$(tail -n +2 "$out" | grep -E '"source":"/etc/systemd/(system|user)/snap[.-]' || true)
    [ -n "$snaps" ] || fail "snaps are installed and no snap unit was reported"
    flooded=$(echo "$snaps" | grep -c '"unpackaged"' || true)
    [ "$flooded" -eq 0 ] || fail "$flooded snap units read as unpackaged: $(echo "$snaps" | grep '"unpackaged"' | field source | head -3 | tr '\n' ' ')"
    attributed=$(echo "$snaps" | grep -c '"by":"snapd"' || true)
    [ "$attributed" -gt 0 ] || fail "no snap unit is attributed to snapd"
    note "$(echo "$snaps" | wc -l) snap units reported, none unpackaged, $attributed attributed to snapd"
fi

rm -f "$out"
echo "== live checks on $ID $VERSION_ID OK"
