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

# Several images named after a distribution are built on its upstream and
# still carry the upstream's os-release — linuxmintd/mint22-amd64 reports
# Ubuntu 24.04. Running the checks against one of those is not a failure, it
# is a silent hole in the matrix, so the caller says what it expects.
[ -z "${UNBIDDEN_EXPECT_ID:-}" ] || [ "$ID" = "$UNBIDDEN_EXPECT_ID" ] ||
    fail "this image reports ID=$ID, not the $UNBIDDEN_EXPECT_ID it was added to the matrix for"

# The package backend follows from os-release rather than from a list of
# distribution names: a derivative inherits its parent's backend through
# ID_LIKE, which is how Mint and LMDE are read without either being named.
case "$ID ${ID_LIKE:-}" in
    *debian*|*ubuntu*)        FAMILY=dpkg ;;
    *fedora*|*rhel*|*centos*) FAMILY=rpm ;;
    *)                        FAMILY=none ;;
esac

# §13: mainline Mint and LMDE both report ID=linuxmint and differ only in the
# base they are built on, which os-release spells in ID_LIKE. An LMDE read as
# Ubuntu would have the rest of this script asserting Ubuntu behaviour, snap
# included, on a system that has never had snapd.
if [ "$ID" = linuxmint ]; then
    case "$NAME" in
        LMDE*) want=debian ;;
        *)     want=ubuntu ;;
    esac
    base=none
    case "${ID_LIKE:-}" in
        *ubuntu*) base=ubuntu ;;
        *debian*) base=debian ;;
    esac
    [ "$base" = "$want" ] ||
        fail "$PRETTY_NAME reports ID_LIKE='${ID_LIKE:-}', so its base reads as $base, not $want"
    note "$PRETTY_NAME is $base-based"
fi

out=$(mktemp)
"$BIN" --json > "$out"

header=$(head -1 "$out")
entries=$(tail -n +2 "$out" | wc -l)
note "$entries entries"
[ "$entries" -gt 50 ] || fail "only $entries entries; the scan found almost nothing"

echo "$header" | grep -q '"schema_version"' || fail "no scan header on the first line"
echo "$header" | grep -q '"status":"failed"' && fail "a collector failed: $header"

# §11 has distro detection read the scan root and nothing else, so the header
# must repeat what /etc/os-release on that root says.
echo "$header" | grep -q "\"distro_id\":\"$ID\"" ||
    fail "the header does not report distro_id $ID: $header"
echo "$header" | grep -q "\"distro_version\":\"$VERSION_ID\"" ||
    fail "the header does not report distro_version $VERSION_ID: $header"

# Every supported distribution ships merged /usr, so a vendor unit reached
# through both /lib and /usr/lib must be reported exactly once.
dupes=$(tail -n +2 "$out" | sed -n 's/.*"id":"\([0-9a-f]*\)".*/\1/p' | sort | uniq -d | wc -l)
[ "$dupes" -eq 0 ] || fail "$dupes duplicate entry ids — merged-usr deduplication is broken"

# In a container /proc/modules reports the HOST's loaded modules, which no
# package in this image owns. They would swamp every ratio below, so the
# provenance assertions look at the file-backed entries only.
tail -n +2 "$out" | grep -v '"kind":"kernel_module"' > "$out.files"
files=$(cat "$out.files")
note "$(wc -l < "$out.files") file-backed entries"

packaged=$(echo "$files" | grep -c '"verdict":"packaged"' || true)
note "$packaged entries owned by a package"
case "$FAMILY" in
    none) note "no supported package backend on $ID; provenance is expected to be unknown" ;;
    *)    [ "$packaged" -gt 10 ] || fail "the $FAMILY backend claimed almost nothing ($packaged)" ;;
esac

# A freshly pulled image has been modified by nobody, so the tool's
# highest-signal finding must not appear even once. A single false
# packaged-modified here would be thousands across a fleet.
bogus=$(echo "$files" | grep -c 'packaged-modified' || true)
[ "$bogus" -eq 0 ] || fail "$bogus entries report packaged-modified on a pristine image"

if [ "$packaged" -gt 0 ]; then
    intact=$(echo "$files" | grep -c '"integrity":"intact"' || true)
    note "$intact verified intact against their package manifest"
    [ "$intact" -gt 0 ] || fail "no entry verified intact; digest checking is not working"
fi

# An edited configuration file is expected to differ from what the package
# shipped. Without conffile handling, every host with a customised config
# lights up with the tool's highest-signal finding.
# A conffile that is also an autostart source is what this needs, and a
# minimal image may ship none. cron provides /etc/crontab as one on every
# supported distribution.
if [ ! -f /etc/crontab ]; then
    case "$FAMILY" in
        dpkg)
            apt-get -qq update >/dev/null 2>&1 && apt-get -qq install -y cron >/dev/null 2>&1 || true
            ;;
        rpm)
            (dnf -q -y install cronie >/dev/null 2>&1 || yum -q -y install cronie >/dev/null 2>&1) || true
            ;;
    esac
    [ -f /etc/crontab ] && "$BIN" --json --all > "$out"
fi

conf=""
for c in /etc/crontab /etc/ssh/sshd_config /etc/sudoers /etc/profile; do
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

# --- a desktop session -------------------------------------------------
# §13: an extension present on disk runs only if dconf says so, and nothing
# writes a dconf database until a session has run. A headless image therefore
# skips the enablement half of the extension collector without saying so,
# which is why at least one image per desktop has to boot one. UNBIDDEN_DESKTOP
# names the session the caller installed; booting one is a slow image, so it
# is opt-in rather than something every image in the matrix pays for.
if [ -n "${UNBIDDEN_DESKTOP:-}" ]; then
    planted="unbidden-check@example.test"
    case "$UNBIDDEN_DESKTOP" in
        cinnamon)
            session=cinnamon-session;  want_kind=cinnamon-applet
            extdir=".local/share/cinnamon/applets"; entry_file=applet.js
            sysdir=/usr/share/cinnamon/applets
            schema=org.cinnamon; key=enabled-applets; unlock=""
            # Cinnamon keys an applet by panel, side, order, uuid and instance.
            value="panel1:right:0:$planted:99" ;;
        gnome)
            session=gnome-session;  want_kind=gnome-shell-extension
            extdir=".local/share/gnome-shell/extensions"; entry_file=extension.js
            sysdir=/usr/share/gnome-shell/extensions
            schema=org.gnome.shell; key=enabled-extensions
            value="$planted"
            # A session that has never run an extension leaves the kill switch
            # on — this one writes it into its own database at startup — and a
            # desktop that runs one has it off.
            unlock="disable-user-extensions false" ;;
        *) fail "UNBIDDEN_DESKTOP=$UNBIDDEN_DESKTOP names no session this script can boot" ;;
    esac
    for t in "$session" Xvfb dbus-run-session dbus-daemon gsettings; do
        command -v "$t" >/dev/null || fail "$t is not installed on this image"
    done

    # gnome-session aborts outright when there is no system bus to connect
    # to, and an image that has never booted has none.
    [ -S /run/dbus/system_bus_socket ] || { mkdir -p /run/dbus; dbus-daemon --system --fork; }

    id -u unbidden-desk >/dev/null 2>&1 || useradd -m unbidden-desk
    home=$(getent passwd unbidden-desk | cut -d: -f6)
    rt="/tmp/xdg-unbidden-desk"
    mkdir -p "$rt"; chown unbidden-desk "$rt"; chmod 700 "$rt"
    rm -rf "$home/.config/dconf"

    Xvfb :99 -screen 0 1280x800x24 >/tmp/xvfb.log 2>&1 &
    xvfb=$!
    su unbidden-desk -c \
        "DISPLAY=:99 XDG_RUNTIME_DIR=$rt LIBGL_ALWAYS_SOFTWARE=1 dbus-run-session -- $session" \
        >/tmp/session.log 2>&1 &
    sess=$!

    # The session writes its first key within a second or two of the shell
    # coming up. The wait is for a slow image, not for a slow desktop.
    waited=0
    while [ ! -s "$home/.config/dconf/user" ] && [ "$waited" -lt 120 ]; do
        sleep 2
        waited=$((waited + 2))
    done
    [ -s "$home/.config/dconf/user" ] ||
        fail "$session wrote no dconf database in ${waited}s; see /tmp/session.log"
    note "$session wrote $(wc -c < "$home/.config/dconf/user") bytes of dconf after ${waited}s"

    # The session has done its job once the database exists. It is stopped
    # before the key below is written because a running shell rewrites the
    # enabled list when an extension it is told to load will not load.
    kill "$sess" "$xvfb" 2>/dev/null || true
    pkill -u unbidden-desk 2>/dev/null || true

    # An extension nobody shipped, enabled the way the desktop enables one:
    # through dconf, into the database the session just created. A fresh one
    # leaves the enabled list at its compiled schema default, so this is what
    # puts the key in the user database — the half no headless image reaches.
    appdir="$home/$extdir/$planted"
    mkdir -p "$appdir"
    printf '{"uuid":"%s","name":"unbidden check"}\n' "$planted" > "$appdir/metadata.json"
    : > "$appdir/$entry_file"
    chown -R unbidden-desk "$home/.local"
    [ -z "$unlock" ] ||
        su unbidden-desk -c \
            "XDG_RUNTIME_DIR=$rt dbus-run-session -- gsettings set $schema $unlock" \
            >>/tmp/gsettings.log 2>&1 ||
        fail "could not clear $schema $unlock; see /tmp/gsettings.log"
    su unbidden-desk -c \
        "XDG_RUNTIME_DIR=$rt dbus-run-session -- gsettings set $schema $key \"['$value']\"" \
        >/tmp/gsettings.log 2>&1 ||
        fail "could not enable $planted through dconf; see /tmp/gsettings.log"

    ext=$("$BIN" --json --all | tail -n +2 | grep '"kind":"desktop_extension"' || true)
    [ -n "$ext" ] || fail "the $UNBIDDEN_DESKTOP session produced no desktop_extension entries"
    note "$(echo "$ext" | wc -l) desktop extension entries"
    echo "$ext" | grep -q "\"extension_kind\":\"$want_kind\"" ||
        fail "no $want_kind entry from a booted $UNBIDDEN_DESKTOP session"

    # Presence on disk is not enablement, and an unreadable dconf stack is not
    # a verdict: a collector that cannot answer says so rather than guessing.
    degraded=$(echo "$ext" | grep -c 'degraded-enablement' || true)
    [ "$degraded" -eq 0 ] ||
        fail "$degraded extensions have an unresolved enablement beside a live dconf database"

    mine=$(echo "$ext" | grep "\"name\":\"$planted\"" || true)
    [ -n "$mine" ] || fail "the extension planted in $appdir was not reported"
    case "$mine" in
        *'"enabled":"enabled"'*) ;;
        *) fail "the planted extension is enabled in dconf but reads as not enabled: $mine" ;;
    esac
    case "$mine" in
        *'"enablement_source":"user-db'*) note "the planted extension reads as enabled from the session's own dconf database" ;;
        *) fail "the planted extension's enablement did not come from a user database: $mine" ;;
    esac

    # A user database is half of dconf. /etc/dconf/profile/user names a stack,
    # a system database answers for every account on the host, and a lock in
    # one stops the databases above it answering at all — an administrator
    # making a setting mandatory, and equally an attacker with root pinning an
    # extension on for everybody. dconf compiles the database here, so the
    # binary layout and the lock encoding are the ones the tool will meet
    # rather than this project's idea of them.
    # Compiling one needs dconf itself, which a desktop image carries only
    # sometimes: gsettings reaches dconf through a library, not the binary.
    command -v dconf >/dev/null ||
        { apt-get -qq update >/dev/null 2>&1; apt-get -qq install -y dconf-cli >/dev/null 2>&1 || true; }
    command -v dconf >/dev/null || fail "dconf is not installed and dconf-cli could not be added"

    pinned="unbidden-pinned@example.test"
    schemapath=$(echo "$schema" | tr . /)
    mkdir -p "$sysdir/$pinned" /etc/dconf/profile /etc/dconf/db/local.d/locks
    printf '{"uuid":"%s","name":"unbidden pin"}\n' "$pinned" > "$sysdir/$pinned/metadata.json"
    : > "$sysdir/$pinned/$entry_file"
    printf 'user-db:user\nsystem-db:local\n' > /etc/dconf/profile/user
    printf "[%s]\n%s=['%s']\n" "$schemapath" "$key" "$(echo "$value" | sed "s/$planted/$pinned/")" \
        > /etc/dconf/db/local.d/00-unbidden
    printf '/%s/%s\n' "$schemapath" "$key" > /etc/dconf/db/local.d/locks/00-unbidden
    dconf compile /etc/dconf/db/local /etc/dconf/db/local.d ||
        fail "dconf could not compile the system database"

    ext=$("$BIN" --json --all | tail -n +2 | grep '"kind":"desktop_extension"' || true)
    mine=$(echo "$ext" | grep "\"name\":\"$pinned\"" || true)
    [ -n "$mine" ] || fail "the extension pinned by a system database was not reported"
    case "$mine" in
        *'"enabled":"enabled"'*) ;;
        *) fail "a system database enables $pinned, but it reads as not enabled: $mine" ;;
    esac
    case "$mine" in
        *'"enablement_source":"system-db:local"'*) note "the pinned extension reads as enabled from the system database" ;;
        *) fail "the pinned extension's enablement did not come from the system database: $mine" ;;
    esac
    case "$mine" in
        *'"dconf_lock"'*) note "and the lock on /$schemapath/$key is reported" ;;
        *) fail "the lock on /$schemapath/$key was not reported: $mine" ;;
    esac

    # dconf(7): no database listed above the locking one may supply that key,
    # so the account's own choice stops counting the moment the lock lands.
    mine=$(echo "$ext" | grep "\"name\":\"$planted\"" || true)
    [ -n "$mine" ] || fail "the extension planted in $appdir stopped being reported"
    case "$mine" in
        *'"enabled":"enabled"'*) fail "the locked key still reads out of the user database: $mine" ;;
        *) note "the locked key demotes the account's own database, as dconf does" ;;
    esac
fi

rm -f "$out" "$out.files"
echo "== $ID $VERSION_ID OK"
