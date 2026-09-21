#!/bin/sh
# Runs a static unbidden binary inside a real distribution image and asserts
# the facts §13 of the spec names as the ones a generic test misses.
#
# Usage: distro-check.sh <path-to-static-binary>
# Expects to be running INSIDE the distribution container, as root.
set -eu

BIN="$1"
fail() { echo "FAIL: $*" >&2; exit 1; }
note() { echo "  $*"; }

. /etc/os-release
echo "== $ID $VERSION_ID"

out=$(mktemp)
"$BIN" --json > "$out"

header=$(head -1 "$out")
entries=$(tail -n +2 "$out" | wc -l)
note "$entries entries"
[ "$entries" -gt 50 ] || fail "only $entries entries; the scan found almost nothing"

echo "$header" | grep -q '"schema_version"' || fail "no scan header on the first line"
echo "$header" | grep -q '"status":"failed"' && fail "a collector failed: $header"

# Every supported distribution ships merged /usr, so a vendor unit reached
# through both /lib and /usr/lib must be reported exactly once.
dupes=$(tail -n +2 "$out" | sed -n 's/.*"id":"\([0-9a-f]*\)".*/\1/p' | sort | uniq -d | wc -l)
[ "$dupes" -eq 0 ] || fail "$dupes duplicate entry ids — merged-usr deduplication is broken"

packaged=$(tail -n +2 "$out" | grep -c '"verdict":"packaged"' || true)
note "$packaged entries owned by a package"
case "$ID" in
    debian|ubuntu|linuxmint)
        [ "$packaged" -gt 10 ] || fail "the dpkg backend claimed almost nothing ($packaged)"
        ;;
    fedora|rhel|centos)
        [ "$packaged" -gt 10 ] || fail "the rpm backend claimed almost nothing ($packaged)"
        ;;
    *)
        note "no supported package backend on $ID; provenance is expected to be unknown"
        ;;
esac

if [ "$packaged" -gt 0 ]; then
    intact=$(tail -n +2 "$out" | grep -c '"integrity":"intact"' || true)
    note "$intact verified intact against their package manifest"
    [ "$intact" -gt 0 ] || fail "no entry verified intact; digest checking is not working"
fi

# An edited configuration file is expected to differ from what the package
# shipped. Without conffile handling, every host with a customised config
# lights up with the tool's highest-signal finding.
conf=""
for c in /etc/ssh/sshd_config /etc/crontab /etc/sudoers /etc/profile; do
    if [ -f "$c" ] && tail -n +2 "$out" | grep -q "\"source\":\"$c\""; then conf="$c"; break; fi
done
if [ -n "$conf" ]; then
    cp "$conf" "$conf.unbidden-backup"
    printf '\n# edited by the distro check\n' >> "$conf"
    edited=$("$BIN" --json --all | tail -n +2 | grep "\"source\":\"$conf\"" | head -1)
    cp "$conf.unbidden-backup" "$conf"; rm -f "$conf.unbidden-backup"
    case "$edited" in
        *packaged-modified*) fail "editing $conf raised packaged-modified; conffile handling is broken" ;;
        *conffile-modified*) note "an edited $conf reads as conffile-modified, not a finding" ;;
        *) note "$conf carries no manifest digest; integrity is reported unknown" ;;
    esac
else
    note "no packaged config file to test conffile handling against"
fi

# A planted unit must be found, and must not be claimed by any package.
mkdir -p /etc/systemd/system
cat > /etc/systemd/system/unbidden-check.service <<'UNIT'
[Service]
ExecStart=/tmp/not-a-real-payload
[Install]
WantedBy=multi-user.target
UNIT
planted=$("$BIN" --json --all | tail -n +2 | grep '"name":"unbidden-check.service"' || true)
rm -f /etc/systemd/system/unbidden-check.service
[ -n "$planted" ] || fail "a unit planted in /etc/systemd/system was not reported"
case "$planted" in
    *'"unpackaged"'*) note "the planted unit reports unpackaged" ;;
    *) [ "$packaged" -gt 0 ] && fail "the planted unit was not flagged unpackaged: $planted" ;;
esac
case "$planted" in
    *target-missing*) note "and its missing target is flagged" ;;
    *) fail "the planted unit's absent target was not flagged" ;;
esac

rm -f "$out"
echo "== $ID $VERSION_ID OK"
