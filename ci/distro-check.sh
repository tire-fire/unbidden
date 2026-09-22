#!/bin/sh
# Runs a static unbidden binary inside a real distribution image and asserts
# the facts §13 of the spec names as the ones a generic test misses.
#
# Usage: distro-check.sh <path-to-static-binary>
# Expects to be running INSIDE the distribution container (or VM), as root.
#
# The checks here may run the host's own package tools — rpm, dpkg-query.
# unbidden itself never does (§3); this script is the test, and asking the
# package manager what it thinks is how the test knows unbidden is right.
set -eu

BIN="$1"
fail() { echo "FAIL: $*" >&2; exit 1; }
note() { echo "  $*"; }

. /etc/os-release
echo "== $ID $VERSION_ID"

# Several images named after a distribution are built on its upstream and
# still carry the upstream's os-release — linuxmintd/mint22-amd64 reports
# Ubuntu 24.04 until Mint's own base-files is installed. Running the checks
# against one of those is not a failure, it is a silent hole in the matrix,
# so the caller says what it expects.
[ -z "${UNBIDDEN_EXPECT_ID:-}" ] || [ "$ID" = "$UNBIDDEN_EXPECT_ID" ] ||
    fail "this image reports ID=$ID, not the $UNBIDDEN_EXPECT_ID it was added to the matrix for"
[ -z "${UNBIDDEN_EXPECT_VERSION:-}" ] || [ "$VERSION_ID" = "$UNBIDDEN_EXPECT_VERSION" ] ||
    fail "this image reports VERSION_ID=$VERSION_ID, not the $UNBIDDEN_EXPECT_VERSION it was added for"

# The package backend follows from os-release rather than from a list of
# distribution names: a derivative inherits its parent's backend through
# ID_LIKE, which is how Mint and LMDE are read without either being named.
case "$ID ${ID_LIKE:-}" in
    *debian*|*ubuntu*)        FAMILY=dpkg ;;
    *fedora*|*rhel*|*centos*) FAMILY=rpm ;;
    *)                        FAMILY=none ;;
esac

# Pull one string field out of a JSON line. The records are flat enough, and
# the images minimal enough (no python on Fedora's), that sed is the tool.
field() { sed -n "s/.*\"$1\":\"\([^\"]*\)\".*/\1/p"; }
ESC=$(printf '\033')

out=$(mktemp)
"$BIN" --json > "$out"

header=$(head -1 "$out")
entries=$(tail -n +2 "$out" | wc -l)
note "$entries entries"
[ "$entries" -gt 50 ] || fail "only $entries entries; the scan found almost nothing"

echo "$header" | grep -q '"schema_version"' || fail "no scan header on the first line"
echo "$header" | grep -q '"status":"failed"' && fail "a collector failed: $header"
echo "$header" | grep -q '"enrichment_failures"' && fail "an enrichment stage failed: $header"

# §11 has distro detection read the scan root and nothing else, so the header
# must repeat what /etc/os-release on that root says.
echo "$header" | grep -q "\"distro_id\":\"$ID\"" ||
    fail "the header does not report distro_id $ID: $header"
echo "$header" | grep -q "\"distro_version\":\"$VERSION_ID\"" ||
    fail "the header does not report distro_version $VERSION_ID: $header"

# §13: mainline Mint and LMDE both report ID=linuxmint and differ only in the
# base they are built on. What matters is that unbidden reads the difference,
# so the check is on its header, not on the image's own os-release: an LMDE
# read as Ubuntu would be expected to have snap, and never has.
if [ "$ID" = linuxmint ]; then
    case "$NAME" in
        LMDE*) want=debian ;;
        *)     want=ubuntu ;;
    esac
    like=$(echo "$header" | field distro_like)
    case " $like " in
        *" $want "*) note "unbidden reads $PRETTY_NAME as $want-based" ;;
        *) fail "unbidden reads $PRETTY_NAME as based on '$like', not $want" ;;
    esac
    [ "$want" = debian ] && case " $like " in *" ubuntu "*) fail "LMDE read as Ubuntu-based: '$like'" ;; esac
fi

# --- merged /usr ---------------------------------------------------------
# Every supported distribution ships /lib, /bin and /sbin as links into
# /usr. A vendor unit reached through both names must be reported once, and
# under the name the package database and an administrator use. Comparing
# entry ids cannot catch the failure, because the id includes the path: a
# unit reported under /lib and again under /usr/lib has two distinct ids.
sources=$(tail -n +2 "$out" | field source)
for d in lib bin sbin lib64; do
    [ -L "/$d" ] || continue
    aliased=$(echo "$sources" | grep -c "^/$d/" || true)
    [ "$aliased" -eq 0 ] ||
        fail "$aliased entries are reported under /$d, a link into /usr: $(echo "$sources" | grep "^/$d/" | head -3 | tr '\n' ' ')"
done
[ -L /lib ] && note "no entry is reported under a merged-usr alias"

vendor=$(find /usr/lib/systemd/system -maxdepth 1 \( -name '*.service' -o -name '*.timer' -o -name '*.socket' -o -name '*.path' \) 2>/dev/null | sort)
if [ -n "$vendor" ]; then
    # A unit's own entries only: a script it runs is followed to its
    # interpreter by an entry that keeps the unit's source, on purpose.
    reported=$(tail -n +2 "$out" | grep -E '"kind":"systemd_(unit|timer)"' | grep -v '"declared_by_entry"' |
        field source | grep -E '^/usr/lib/systemd/system/[^/]+$' | sort)
    missing=$(printf '%s\n' "$vendor" | while read -r u; do echo "$reported" | grep -qx "$u" || echo "$u"; done)
    [ -z "$missing" ] || fail "vendor units not reported under /usr/lib/systemd/system: $(echo "$missing" | head -3 | tr '\n' ' ')"
    twice=$(echo "$reported" | uniq -d)
    [ -z "$twice" ] || fail "vendor units reported more than once: $(echo "$twice" | head -3 | tr '\n' ' ')"
    note "each of $(echo "$vendor" | wc -l) vendor units is reported exactly once"
fi

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

# --- the package manager as referee ------------------------------------
# The unit tests check the backends against databases this project wrote.
# This checks them against the real database, through the real tool: every
# file-backed entry's owner as unbidden reports it must be the owner rpm or
# dpkg reports, and a file unbidden calls intact must be one the package
# manager's own verification passes. Entries about something other than
# their source file — a script's interpreter, a scriptlet read out of the
# database, a maintainer script dpkg lists nowhere — are left out, since the
# tool has no answer about them to compare.
owner_of() {
    case "$FAMILY" in
        rpm)  rpm -qf --qf '%{NAME}\n' "$1" 2>/dev/null | grep -v 'not owned' ;;
        dpkg)
            # dpkg records whichever spelling the package shipped, so a
            # merged-usr path is asked about both ways.
            for p in "$1" "$(echo "$1" | sed -E 's#^/usr/(lib|bin|sbin|lib64)/#/\1/#')"; do
                dpkg-query -S "$p" 2>/dev/null | sed -n "s#^\([^:]*\)\(:[^:]*\)\{0,1\}: $p\$#\1#p" | tr ',' '\n' | sed 's/^ *//'
            done | sort -u ;;
    esac
}
verify_failed() {
    # The digest column of rpm -V, and the digest column of dpkg --verify.
    case "$FAMILY" in
        rpm)  rpm -Vf "$1" 2>/dev/null | grep -E "^..5.* $1\$|^....L.* $1\$" ;;
        dpkg) dpkg --verify "$2" 2>/dev/null | grep -E "^..5.* $1\$" ;;
    esac
}
case "$FAMILY" in
    rpm)  referee=rpm ;;
    dpkg) referee=dpkg-query ;;
    *)    referee="" ;;
esac
if [ -n "$referee" ] && command -v "$referee" >/dev/null 2>&1; then
    : > "$out.checked"
    echo "$files" | grep -v -e '"declared_by_entry"' -e '"read_from"' -e '"digest_unavailable"' -e '"kind":"ld_preload"' |
    while IFS= read -r line; do
        src=$(echo "$line" | field source)
        [ -f "$src" ] && [ ! -L "$src" ] || continue
        case "$line" in
            *'"verdict":"packaged"'*)
                pkg=$(echo "$line" | field package)
                owners=$(owner_of "$src")
                echo "$owners" | grep -qx "$pkg" ||
                    { echo "FAIL: unbidden says $pkg owns $src; $referee says: $(echo "$owners" | tr '\n' ' ')" >&2; exit 1; }
                case "$line" in
                    *'"integrity":"intact"'*)
                        bad=$(verify_failed "$src" "$pkg")
                        [ -z "$bad" ] || { echo "FAIL: unbidden calls $src intact; the package manager says: $bad" >&2; exit 1; }
                        ;;
                esac
                echo "$src" >> "$out.checked"
                ;;
            *'"verdict":"unpackaged"'*)
                owners=$(owner_of "$src")
                [ -z "$owners" ] ||
                    { echo "FAIL: unbidden calls $src unpackaged; $referee says $(echo "$owners" | tr '\n' ' ')owns it" >&2; exit 1; }
                echo "$src" >> "$out.checked"
                ;;
        esac
    done || fail "provenance disagrees with the package manager"
    checked=$(wc -l < "$out.checked")
    rm -f "$out.checked"
    [ "$checked" -gt 10 ] || fail "only $checked verdicts could be checked against $referee"
    note "all $checked file-backed verdicts agree with $referee and the package manager's verification"
fi

# --- an edited configuration file ------------------------------------------
# Expected to differ from what the package shipped. Without conffile
# handling, every host with a customised config lights up with the tool's
# highest-signal finding. A conffile that is also an autostart source is what
# this needs, and a minimal image may ship none: cron provides /etc/crontab
# as one on every supported distribution.
if [ ! -f /etc/crontab ]; then
    case "$FAMILY" in
        dpkg) apt-get -qq update >/dev/null 2>&1 && apt-get -qq install -y cron >/dev/null 2>&1 || true ;;
        rpm)  (dnf -q -y install cronie >/dev/null 2>&1 || yum -q -y install cronie >/dev/null 2>&1) || true ;;
    esac
    [ -f /etc/crontab ] && "$BIN" --json --all > "$out"
fi

conf=""
for c in /etc/crontab /etc/ssh/sshd_config /etc/sudoers /etc/bash.bashrc /etc/profile; do
    if [ -f "$c" ] && tail -n +2 "$out" | grep "\"source\":\"$c\"" | grep -q '"integrity":"intact"'; then
        conf="$c"
        break
    fi
done
if [ -n "$conf" ]; then
    cp -p "$conf" "$conf.unbidden-backup"
    printf '\n# edited by the distro check\n' >> "$conf"
    edited=$("$BIN" --json --all | tail -n +2 | grep "\"source\":\"$conf\"" | head -1)
    cp -p "$conf.unbidden-backup" "$conf"; rm -f "$conf.unbidden-backup"
    case "$edited" in
        *packaged-modified*) fail "editing $conf raised packaged-modified; conffile handling is broken" ;;
        *'"integrity":"conffile-modified"'*) note "an edited $conf reads as conffile-modified, not a finding" ;;
        *) fail "the packaged conffile $conf was edited and does not read as conffile-modified: $edited" ;;
    esac
else
    [ "$FAMILY" = none ] || fail "no packaged, intact configuration file to test conffile handling against"
fi

# --- a package with no digests ---------------------------------------------
# §7: not every package ships md5sums, and a file whose package has none has
# integrity unknown — never intact, and never hidden from the default view,
# because that is exactly the file an attacker replaced. The case is made by
# taking a real package's manifest away.
if [ "$FAMILY" = dpkg ]; then
    line=$(echo "$files" | grep '"integrity":"intact"' | grep -v -e '"read_from"' -e '"digest_unavailable"' -e '"declared_by_entry"' |
        while IFS= read -r l; do
            src=$(echo "$l" | field source); pkg=$(echo "$l" | field package)
            [ -f "$src" ] && [ ! -L "$src" ] || continue
            # A conffile is checked against status, not md5sums.
            dpkg-query -W -f='${Conffiles}\n' "$pkg" 2>/dev/null | grep -q " $src " && continue
            echo "$l"; break
        done)
    [ -n "$line" ] || fail "no packaged, non-conffile entry to take the manifest away from"
    id=$(echo "$line" | field id); src=$(echo "$line" | field source); pkg=$(echo "$line" | field package)
    manifest=$(ls /var/lib/dpkg/info/"$pkg".md5sums /var/lib/dpkg/info/"$pkg":*.md5sums 2>/dev/null | head -1)
    [ -n "$manifest" ] || fail "$pkg has no md5sums to take away"
    mv "$manifest" "$manifest.unbidden-away"
    after=$("$BIN" --json --all | tail -n +2 | grep "\"id\":\"$id\"")
    shown=$(COLUMNS=250 "$BIN" | grep -c "^$(echo "$id" | cut -c1-12)" || true)
    mv "$manifest.unbidden-away" "$manifest"
    case "$after" in
        *'"integrity":"unknown"'*) ;;
        *) fail "$src lost its package's md5sums and does not read as integrity unknown: $after" ;;
    esac
    [ "$shown" -eq 1 ] || fail "$src has no digest to check against, and the default view hid it"
    note "with $pkg's md5sums gone, $src reads integrity unknown and is shown by default"
fi

# --- maintainer scripts ------------------------------------------------
# dpkg writes a package's .list and its scripts in one unpack; a script
# changed well after its list is noted as changed after install. On an image
# nobody has touched, and after a real apt-get install, that must be none of
# them — the ordering is dpkg's, and this is where it is checked against dpkg.
if [ "$FAMILY" = dpkg ]; then
    late=$(tail -n +2 "$out" | grep '"kind":"pkg_hook"' | grep -c '"changed_after_install"' || true)
    [ "$late" -eq 0 ] ||
        fail "$late maintainer scripts on a pristine image read as changed after install: $(tail -n +2 "$out" | grep '"changed_after_install"' | field source | head -3 | tr '\n' ' ')"
    note "no maintainer script reads as changed after its package was installed"

    if [ "${UNBIDDEN_SLOW_CHECKS:-}" = 1 ]; then
        script=$(ls /var/lib/dpkg/info/*.postinst | head -1)
        # Past the two-minute install window: ctime cannot be set any other way.
        sleep 125
        printf '\n# edited by the distro check\n' >> "$script"
        edited=$("$BIN" --json --all | tail -n +2 | grep "\"source\":\"$script\"")
        sed -i '$d' "$script"; sed -i '$d' "$script"
        case "$edited" in
            *'"changed_after_install"'*) note "a postinst edited after install is noted as such" ;;
            *) fail "$script was edited long after its package was installed and is not noted: $edited" ;;
        esac
    fi
fi

# --- planted persistence -------------------------------------------------
# A unit planted in each writable system search directory must be found, and
# must not be claimed by any package.
for dir in /etc/systemd/system /usr/local/lib/systemd/system; do
    mkdir -p "$dir"
    cat > "$dir/unbidden-check.service" <<'UNIT'
[Service]
ExecStart=/tmp/not-a-real-payload
[Install]
WantedBy=multi-user.target
UNIT
    planted=$("$BIN" --json --all | tail -n +2 | grep "\"source\":\"$dir/unbidden-check.service\"" || true)
    rm -f "$dir/unbidden-check.service"
    [ -n "$planted" ] || fail "a unit planted in $dir was not reported"
    case "$planted" in
        *'"unpackaged"'*) note "a unit planted in $dir reports unpackaged" ;;
        *) [ "$packaged" -gt 0 ] && fail "the unit planted in $dir was not flagged unpackaged: $planted" ;;
    esac
    case "$planted" in
        *target-missing*) ;;
        *) fail "the absent target of the unit planted in $dir was not flagged" ;;
    esac
done

# A command carrying terminal control sequences must reach the operator as
# text. ESC[2K ESC[1A erases the row above; printed raw, it rewrites the
# table line that reports it.
mkdir -p /etc/cron.d
printf '* * * * * root /tmp/x %s[2K%s[1Ahidden\n' "$ESC" "$ESC" > /etc/cron.d/unbidden-escape
table=$(COLUMNS=250 "$BIN" --kind cron)
explained=$("$BIN" explain "$(echo "$table" | grep 'unbidden-escape\|/tmp/x' | head -1 | cut -c1-12)" 2>&1 || true)
rm -f /etc/cron.d/unbidden-escape
case "$table$explained" in
    *"$ESC"*) fail "a control sequence from a scanned file reached the terminal raw" ;;
esac
echo "$table" | grep -q '\\x1b\[2K' || fail "the control sequence was not shown escaped: $table"
note "terminal control sequences in a command are shown, not obeyed"

# --- a home that reaches outside itself ----------------------------------
# Any account can link its own ~/.bashrc at /etc/shadow. The link must be
# reported and not read, and doing it must not turn the scan partial —
# which would make every later --against refuse to run.
cp -p /etc/passwd /etc/passwd.unbidden-backup
mkdir -p /home/unbidden-link
echo "unbidden-link:x:4242:4242::/home/unbidden-link:/bin/sh" >> /etc/passwd
ln -sf /etc/shadow /home/unbidden-link/.bashrc
"$BIN" --save "$out.base" > /dev/null
linkscan=$("$BIN" --json --all)
diffed=$("$BIN" --against "$out.base" --json 2>&1) || diffrc=$?
cp -p /etc/passwd.unbidden-backup /etc/passwd; rm -f /etc/passwd.unbidden-backup "$out.base"
rm -rf /home/unbidden-link
echo "$linkscan" | head -1 | grep -q '"name":"shell","status":"complete"' ||
    fail "a home link to /etc/shadow made the shell collector partial: $(echo "$linkscan" | head -1)"
bashrc=$(echo "$linkscan" | grep '"source":"/home/unbidden-link/.bashrc"')
case "$bashrc" in
    *'"not_followed"'*) ;;
    *) fail "the link out of the home was not recorded as not followed: $bashrc" ;;
esac
case "$bashrc" in
    *'"env.'*) fail "the target of a link out of the home was read: $bashrc" ;;
esac
[ "${diffrc:-0}" -eq 0 ] || fail "a scan with a home link out of the home would not diff: $diffed"
note "a home link to /etc/shadow is recorded, not followed, and leaves the scan comparable"

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
