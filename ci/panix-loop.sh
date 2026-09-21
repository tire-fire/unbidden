#!/bin/bash
# The coverage matrix of §13, run inside a disposable VM as root.
#
# Per mechanism: baseline, plant with PANIX, scan and assert the entry
# appears with the expected kind, revert with PANIX, scan again and assert the
# diff is clean against the baseline.
#
# That last step matters as much as the first. A collector that reports stale
# or phantom entries after a mechanism is removed is how a tool loses an
# operator's trust permanently.
#
# Usage: panix-loop.sh <unbidden> <panix.sh> [module ...]
set -uo pipefail

BIN="${1:?path to the unbidden binary}"
PANIX="${2:?path to panix.sh}"
shift 2

# The planted payloads dial this. Nothing leaves the VM.
DEAD_IP=127.0.0.1
DEAD_PORT=9999

BASE=/tmp/panix-baseline.json
pass=0; fail=0; skip=0
declare -a FAILURES=()

# module → the Entry kind unbidden must report for it.
mechanism_kind() {
    case "$1" in
        at)                          echo at_job ;;
        authorized-keys|ssh-key)     echo ssh_authorized_key ;;
        cron)                        echo cron ;;
        dbus)                        echo dbus_service ;;
        generator)                   echo systemd_generator ;;
        git)                         echo git_hook ;;
        initd)                       echo sysv_init ;;
        ld-preload)                  echo ld_preload ;;
        lkm)                         echo kernel_module ;;
        malicious-package|package-manager) echo pkg_hook ;;
        motd)                        echo motd ;;
        network-manager)             echo network_dispatcher ;;
        pam)                         echo pam ;;
        rc-local)                    echo rc_local ;;
        shell-profile)               echo shell_profile ;;
        sudoers-backdoor)            echo sudoers ;;
        suid-backdoor)               echo suid_binary ;;
        cap-backdoor)                echo file_capability ;;
        system-binary)               echo systemd_unit ;;
        systemd)                     echo systemd_unit ;;
        udev)                        echo udev ;;
        xdg)                         echo xdg_autostart ;;
        # Mechanisms the spec puts out of scope or defers. Tracked, not
        # silently missing: §2 excludes rootkits, §5 defers GRUB, initramfs,
        # polkit, container runtimes and web shells, and user-account
        # creation is not an execution trigger.
        grub|initramfs|polkit|rootkit|web-shell|malicious-docker-container) echo OUT_OF_SCOPE ;;
        backdoor-user|backdoor-system-user|create-user|passwd-user|password-change) echo OUT_OF_SCOPE ;;
        bind-shell|reverse-shell)    echo OUT_OF_SCOPE ;;
        *)                           echo UNMAPPED ;;
    esac
}

scan() { "$BIN" --deep --json --all "$@"; }

plant() {
    # PANIX modules differ in whether they take a target. Try the richest
    # form first and fall back, rather than hand-curating 38 invocations.
    for args in "--default --ip $DEAD_IP --port $DEAD_PORT" "--default" ""; do
        # shellcheck disable=SC2086
        if timeout 120 bash "$PANIX" --"$1" $args >/tmp/plant.log 2>&1; then
            echo "$args"
            return 0
        fi
    done
    return 1
}

modules=("$@")
if [ ${#modules[@]} -eq 0 ]; then
    modules=(at authorized-keys cron dbus generator git initd ld-preload malicious-package \
             motd network-manager pam rc-local shell-profile ssh-key sudoers-backdoor \
             suid-backdoor cap-backdoor systemd udev xdg)
fi

rebaseline() {
    scan --save "$BASE" > /tmp/panix-baseline.ndjson || return 1
    echo "   baseline: $(( $(wc -l < /tmp/panix-baseline.ndjson) - 1 )) entries"
}

echo "== baseline"
rebaseline || { echo "baseline scan failed"; exit 1; }

for m in "${modules[@]}"; do
    want=$(mechanism_kind "$m")
    if [ "$want" = OUT_OF_SCOPE ]; then
        echo "-- $m: out of scope by design"
        skip=$((skip + 1))
        continue
    fi

    printf -- '-- %s (expect %s)\n' "$m" "$want"
    if ! used=$(plant "$m"); then
        echo "   SKIP: PANIX could not plant it here"
        tail -3 /tmp/plant.log | sed 's/^/     /'
        skip=$((skip + 1))
        continue
    fi

    found=$(scan --against "$BASE" | tail -n +2 | grep -E '"delta":"(added|changed)"')
    kinds=$(echo "$found" | sed -n 's/.*"kind":"\([a-z_]*\)".*/\1/p' | sort -u | tr '\n' ' ')

    if echo "$kinds" | grep -qw "$want"; then
        echo "   found as $want"
        detected=yes
    else
        echo "   MISS: planted but not reported as $want (saw: ${kinds:-nothing})"
        FAILURES+=("$m: not detected as $want, saw ${kinds:-nothing}")
        detected=no
    fi

    if ! timeout 120 bash "$PANIX" --revert "$m" >/tmp/revert.log 2>&1; then
        echo "   revert failed; resetting is the caller's job"
        FAILURES+=("$m: PANIX revert failed")
        fail=$((fail + 1))
        continue
    fi

    residue=$(scan --against "$BASE" | tail -n +2 | grep -cE '"delta":"(added|changed|removed)"')
    if [ "$residue" -eq 0 ]; then
        echo "   reverted clean"
        [ "$detected" = yes ] && pass=$((pass + 1)) || fail=$((fail + 1))
    elif true; then
        echo "   PHANTOM: $residue entries still differ after revert"
        scan --against "$BASE" | tail -n +2 | grep -E '"delta":"(added|changed|removed)"' \
            | sed -n 's/.*"delta":"\([a-z]*\)".*"source":"\([^"]*\)".*/     \1 \2/p' | head -5
        FAILURES+=("$m: $residue entries remain after revert")
        fail=$((fail + 1))
        # Whatever the revert left behind is now the state of the machine.
        # Re-baselining stops one module's residue being reported again
        # against every module that follows it.
        echo "   re-baselining so the residue is not counted twice"
        rebaseline || { echo "re-baseline failed"; exit 1; }
    fi
done

echo
echo "== $pass detected and reverted clean, $fail failed, $skip skipped"
if [ ${#FAILURES[@]} -gt 0 ]; then
    printf '%s\n' "${FAILURES[@]}" | sed 's/^/   /'
    exit 1
fi
