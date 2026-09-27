#!/bin/sh
# Inside debian:12: for each case, install its profiles and templates in
# place of the stock ones, run pam-auth-update as an administrator would,
# and save what it wrote.
set -u
export DEBIAN_FRONTEND=noninteractive
cp -a /usr/share/pam-configs /tmp/base-configs
for c in /cases/*/; do
    name=$(basename "$c")
    rm -rf /usr/share/pam-configs; mkdir /usr/share/pam-configs
    for p in "$c"prof*; do cp "$p" /usr/share/pam-configs/; done
    rm -f /usr/share/pam/common-*; cp "$c"templates/common-* /usr/share/pam/
    rm -f /var/lib/pam/*; rm -f /etc/pam.d/common-*
    # Reset debconf's answer so each case starts from the profiles' defaults.
    echo "RESET libpam-runtime/profiles" | debconf-communicate >/dev/null 2>&1
    en=$(cat "$c/ENABLE")
    if [ -n "$en" ]; then timeout 60 pam-auth-update --force --enable $en >"$c/log" 2>&1; else timeout 60 pam-auth-update --force >"$c/log" 2>&1; fi
    echo $? > "$c/rc"
    mkdir -p "$c/out/etc/pam.d" "$c/out/var/lib/pam" "$c/out/usr/share"
    cp /etc/pam.d/common-* "$c/out/etc/pam.d/" 2>/dev/null
    cp /var/lib/pam/* "$c/out/var/lib/pam/" 2>/dev/null
    cp -a /usr/share/pam "$c/out/usr/share/pam"; cp -a /usr/share/pam-configs "$c/out/usr/share/pam-configs"
done
chown -R "$HOSTUID" /cases
