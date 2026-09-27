#!/bin/sh
# Inside fedora: install each case's profile as a vendor profile, select it
# with its features, and save what authselect wrote.
set -u
for c in /cases/*/; do
    rm -rf /usr/share/authselect/vendor/tprof
    mkdir -p /usr/share/authselect/vendor
    cp -a "$c/profile" /usr/share/authselect/vendor/tprof
    rm -f /etc/authselect/authselect.conf /etc/authselect/system-auth /etc/authselect/password-auth /etc/authselect/fingerprint-auth /etc/authselect/smartcard-auth /etc/authselect/postlogin /etc/authselect/nsswitch.conf
    timeout 60 authselect select tprof $(cat "$c/FEATURES") --force >"$c/log" 2>&1
    echo $? > "$c/rc"
    mkdir -p "$c/out/etc/authselect" "$c/out/usr/share/authselect/vendor"
    cp /etc/authselect/authselect.conf "$c/out/etc/authselect/" 2>/dev/null
    for f in system-auth password-auth fingerprint-auth smartcard-auth postlogin nsswitch.conf; do
        cp /etc/authselect/$f "$c/out/etc/authselect/" 2>/dev/null
    done
    cp -a /usr/share/authselect/vendor/tprof "$c/out/usr/share/authselect/vendor/tprof"
done
chown -R "$HOSTUID" /cases
