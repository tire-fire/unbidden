#!/bin/bash
# The coverage matrix of §13, run as root on a disposable machine: a VM from
# vm-harness.sh, or a systemd container for the distributions that publish no
# cloud image.
#
# Per mechanism: baseline, plant with PANIX, scan and assert the entry
# appears — with the expected kind, from the expected source, carrying the
# expected flag and tied to the planted payload — revert with PANIX, scan
# again and assert the diff is clean against the baseline.
#
# That last step matters as much as the first. A collector that reports stale
# or phantom entries after a mechanism is removed is how a tool loses an
# operator's trust permanently.
#
# What each module must produce, and which ones are out of scope and why,
# lives in panix-coverage.tsv beside this script. A mechanism PANIX cannot
# plant is a failure, not a skip: an untested mechanism must not read as a
# passing one. The one exception is UNBIDDEN_PANIX_SKIP, which names modules
# this machine cannot host at all, with the reason in
# UNBIDDEN_PANIX_SKIP_REASON — a container cannot load a kernel module into
# the kernel it shares with the runner.
#
# Usage: panix-loop.sh <unbidden> <panix.sh> [module ...]
set -uo pipefail

BIN="${1:?path to the unbidden binary}"
PANIX="${2:?path to panix.sh}"
shift 2

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COVERAGE="$HERE/panix-coverage.tsv"
[ -f "$COVERAGE" ] || { echo "no coverage table at $COVERAGE" >&2; exit 2; }

# The planted payloads dial this. Nothing leaves the machine.
DEAD_IP=127.0.0.1
DEAD_PORT=9999

BASE=/tmp/panix-baseline.json
pass=0; fail=0; skip=0; out_of_scope=0
declare -a FAILURES=()
declare -a MATRIX=()

row() { awk -F'\t' -v m="$1" '!/^#/ && $1 == m' "$COVERAGE"; }
col() { echo "$1" | cut -f"$2"; }

# Every module PANIX offers must have a row. PANIX's README carries its own
# table of them; a module added upstream and not here is a hole in the
# matrix, and it fails the run until someone decides what it is.
readme="$(dirname "$PANIX")/README.md"
if [ -f "$readme" ]; then
    missing=""
    for m in $(sed -n 's/^--\([a-z0-9-]*\) .*T1[0-9].*/\1/p' "$readme" | sort -u); do
        [ -n "$(row "$m")" ] || missing="$missing $m"
    done
    if [ -n "$missing" ]; then
        echo "PANIX offers modules the coverage table does not mention:$missing" >&2
        exit 1
    fi
fi

scan() { "$BIN" --deep --json --all "$@"; }

# What each module needs to plant. These genuinely differ — some take a
# callback address, some a target binary, some a sub-mechanism — and guessing
# a single shape silently turns "unbidden was never tested against this" into
# a failure that reads like an environment limitation.
DIAL="--ip $DEAD_IP --port $DEAD_PORT"
case "$(. /etc/os-release && echo "$ID ${ID_LIKE:-}")" in
    *debian*|*ubuntu*) PKG_FLAG=--dpkg; PM_FLAG=--apt ;;
    *)                 PKG_FLAG=--rpm;  PM_FLAG=--dnf ;;
esac
[ -f /tmp/panix-key.pub ] || ssh-keygen -q -t ed25519 -N '' -C unbidden-panix -f /tmp/panix-key >/dev/null 2>&1

plant_args() {
    case "$1" in
        at)                echo "--default $DIAL --time 'now + 1 minute'" ;;
        authorized-keys)   echo "--default --key '$(cat /tmp/panix-key.pub)'" ;;
        cap)               echo "--default" ;;
        generator)         echo "$DIAL" ;;
        git)               echo "--default $DIAL --hook" ;;
        ld-preload)        echo "$DIAL --binary /usr/bin/ls" ;;
        malicious-package) echo "$DIAL $PKG_FLAG" ;;
        package-manager)   echo "$DIAL $PM_FLAG" ;;
        pam)               echo "--pam-exec --backdoor $DIAL" ;;
        ssh-key)           echo "--default" ;;
        sudoers)           echo "--username root" ;;
        suid)              echo "--default" ;;
        udev)              echo "--default $DIAL --systemd" ;;
        *)                 echo "--default $DIAL" ;;
    esac
}

plant() {
    local args
    args=$(plant_args "$1")
    # shellcheck disable=SC2086
    timeout 300 bash -c "bash '$PANIX' --$1 $args" >/tmp/plant.log 2>&1
}

# Does this JSON line carry the marker, in its command or notes, or in the
# file it was read from or the file it runs? The last two are read here, by
# the test, which is free to: the tool itself only reports them.
carries() {
    local line="$1" marker="$2" f
    case "$line" in *"$marker"*) return 0 ;; esac
    for key in source target_path; do
        f=$(echo "$line" | sed -n "s/.*\"$key\":\"\([^\"]*\)\".*/\1/p")
        [ -n "$f" ] && [ -f "$f" ] && grep -aqF "$marker" "$f" 2>/dev/null && return 0
    done
    return 1
}

modules=("$@")
if [ ${#modules[@]} -eq 0 ]; then
    mapfile -t modules < <(awk -F'\t' '!/^#/ && NF >= 3 { print $1 }' "$COVERAGE")
fi

rebaseline() {
    scan --save "$BASE" > /tmp/panix-baseline.ndjson || return 1
    echo "   baseline: $(( $(wc -l < /tmp/panix-baseline.ndjson) - 1 )) entries"
}

echo "== baseline"
rebaseline || { echo "baseline scan failed"; exit 1; }

for m in "${modules[@]}"; do
    r=$(row "$m")
    [ -n "$r" ] || { echo "-- $m: no row in the coverage table"; FAILURES+=("$m: not in panix-coverage.tsv"); fail=$((fail + 1)); continue; }
    technique=$(col "$r" 2); want=$(col "$r" 3); source_re=$(col "$r" 4)
    flags_re=$(col "$r" 5); marker=$(col "$r" 6); why=$(col "$r" 7)

    if [ "$want" = OUT_OF_SCOPE ]; then
        echo "-- $m ($technique): out of scope — $why"
        MATRIX+=("$(printf '%-20s %-10s %s' "$m" "$technique" "out of scope: $why")")
        out_of_scope=$((out_of_scope + 1))
        continue
    fi
    if [[ " ${UNBIDDEN_PANIX_SKIP:-} " == *" $m "* ]]; then
        echo "-- $m ($technique): not run here — ${UNBIDDEN_PANIX_SKIP_REASON:-no reason given}"
        MATRIX+=("$(printf '%-20s %-10s %s' "$m" "$technique" "not run here: ${UNBIDDEN_PANIX_SKIP_REASON:-}")")
        skip=$((skip + 1))
        continue
    fi

    printf -- '-- %s (%s, expect %s)\n' "$m" "$technique" "$want"
    if ! plant "$m"; then
        echo "   FAIL: PANIX could not plant it ($(plant_args "$m"))"
        tail -5 /tmp/plant.log | sed 's/^/     /'
        FAILURES+=("$m: PANIX could not plant it on this machine, so it was never tested")
        MATRIX+=("$(printf '%-20s %-10s %s' "$m" "$technique" "NOT PLANTED")")
        fail=$((fail + 1))
        # Whatever it managed before failing is now part of the machine.
        timeout 120 bash "$PANIX" --revert "$m" >/dev/null 2>&1
        rebaseline || { echo "re-baseline failed"; exit 1; }
        continue
    fi

    found=$(scan --against "$BASE" | tail -n +2 | grep -E '"delta":"(added|changed)"')
    kinds=$(echo "$found" | sed -n 's/.*"kind":"\([a-z_]*\)".*/\1/p' | sort -u | tr '\n' ' ')

    # One entry has to satisfy the row whole: the right kind, from the right
    # place, flagged the right way, and tied to what PANIX planted. Any entry
    # of the right kind would pass a looser check while reporting something
    # else entirely.
    detected=no; closest=""
    while IFS= read -r line; do
        [ -n "$line" ] || continue
        kind=$(echo "$line" | sed -n 's/.*"kind":"\([a-z_]*\)".*/\1/p')
        [[ " $want " == *" $kind "* ]] || continue
        src=$(echo "$line" | sed -n 's/.*"source":"\([^"]*\)".*/\1/p')
        echo "$src" | grep -qE "$source_re" || { closest="$kind at $src, which is not where it was planted"; continue; }
        if [ "$flags_re" != - ]; then
            flags=$(echo "$line" | sed -n 's/.*"flags":\[\([^]]*\)\].*/\1/p')
            echo "$flags" | grep -qE "\"($flags_re)\"" || { closest="$kind at $src, flagged [$flags] rather than $flags_re"; continue; }
        fi
        if [ "$marker" != - ] && ! carries "$line" "$marker"; then
            closest="$kind at $src, which does not carry the planted payload"
            continue
        fi
        echo "   found as $kind at $src"
        detected=yes
        break
    done <<< "$found"
    if [ "$detected" = no ]; then
        echo "   MISS: planted but not reported as $want from $source_re (saw: ${kinds:-nothing}${closest:+; closest: $closest})"
        FAILURES+=("$m: not reported as $want${closest:+ — closest: $closest}")
    fi

    if ! timeout 120 bash "$PANIX" --revert "$m" >/tmp/revert.log 2>&1; then
        # PANIX's revert failing says nothing about unbidden, which has
        # already been judged on the mechanism. What it leaves behind is now
        # part of the machine, and the next module is measured against that.
        echo "   PANIX's own revert failed; re-baselining"
        MATRIX+=("$(printf '%-20s %-10s %s' "$m" "$technique" "$([ "$detected" = yes ] && echo detected || echo MISSED), PANIX revert failed")")
        [ "$detected" = yes ] && pass=$((pass + 1)) || fail=$((fail + 1))
        rebaseline || { echo "re-baseline failed"; exit 1; }
        continue
    fi

    scan --against "$BASE" | tail -n +2 | grep -E '"delta":"(added|changed|removed)"' > /tmp/residue.ndjson
    residue=$(wc -l < /tmp/residue.ndjson)
    phantom=0
    if [ "$residue" -eq 0 ]; then
        echo "   reverted clean"
    else
        # Two very different things look the same here, and only one of them
        # is unbidden's fault. A differing entry whose file is still on disk
        # means PANIX's revert left something behind. One whose file is gone
        # means unbidden is reporting a mechanism that no longer exists.
        leftover=0
        while IFS= read -r line; do
            src=$(echo "$line" | sed -n 's/.*"source":"\([^"]*\)".*/\1/p')
            delta=$(echo "$line" | sed -n 's/.*"delta":"\([a-z]*\)".*/\1/p')
            case "$src" in
                /proc/*|/sys/*) leftover=$((leftover + 1)); echo "     live kernel state moved: $delta $src"; continue ;;
            esac
            if [ -e "$src" ] || [ -L "$src" ]; then
                leftover=$((leftover + 1))
                echo "     left on disk by PANIX: $delta $src"
            elif [ "$delta" = removed ]; then
                # Gone from disk and reported gone: that is the tool being
                # right about something PANIX's revert took with it.
                leftover=$((leftover + 1))
                echo "     removed by PANIX's revert: $src"
            else
                phantom=$((phantom + 1))
                echo "     PHANTOM, the file is gone: $delta $src"
            fi
        done < /tmp/residue.ndjson
        if [ "$phantom" -gt 0 ]; then
            FAILURES+=("$m: $phantom entries reported for files that no longer exist")
        else
            echo "   reverted; $leftover entries differ for files PANIX left or took, nothing phantom"
        fi
        rebaseline || { echo "re-baseline failed"; exit 1; }
    fi

    if [ "$detected" = yes ] && [ "$phantom" -eq 0 ]; then
        pass=$((pass + 1))
        MATRIX+=("$(printf '%-20s %-10s %s' "$m" "$technique" "detected, reverted clean")")
    else
        fail=$((fail + 1))
        MATRIX+=("$(printf '%-20s %-10s %s' "$m" "$technique" "$([ "$detected" = yes ] && echo "detected, $phantom phantom after revert" || echo MISSED)")")
    fi
done

echo
echo "== coverage"
printf '%s\n' "${MATRIX[@]}" | sed 's/^/   /'
echo
echo "== $pass detected and reverted clean, $fail failed, $out_of_scope out of scope, $skip not run here"
if [ ${#FAILURES[@]} -gt 0 ]; then
    echo "   failures:"
    printf '%s\n' "${FAILURES[@]}" | sed 's/^/     /'
    exit 1
fi
