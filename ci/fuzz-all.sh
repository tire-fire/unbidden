#!/bin/sh
# Runs every cargo-fuzz target, one per CPU at a time, and fails if any
# target finds a crash, a hang or unbounded memory.
#
# The binaries `cargo fuzz build -O` left are run directly, with the corpus
# and artifact directories cargo-fuzz would have given them: running
# `cargo fuzz run` in parallel would queue every target on cargo's build lock.
#
# Usage: fuzz-all.sh <seconds for the §13 names> <seconds for the rest>
set -eu

long="${1:?seconds for the §13 names}"
short="${2:?seconds for every other target}"
bin=fuzz/target/x86_64-unknown-linux-gnu/release
logs=$(mktemp -d)

# -timeout turns a hang into a reported crash rather than a job that runs
# until GitHub kills it; the two memory limits are how "no unbounded memory"
# gets checked at all.
status=0
cargo +nightly fuzz list | xargs -P "$(nproc)" -I{} sh -c '
    t=$1
    case "$t" in
        unit_file|crontab|desktop_file|udev_rules|pam_config|shell_text) secs=$2 ;;
        *) secs=$3 ;;
    esac
    mkdir -p "fuzz/corpus/$t" "fuzz/artifacts/$t"
    if "$4/$t" -max_total_time="$secs" -timeout=10 -rss_limit_mb=2048 -malloc_limit_mb=512 \
        -artifact_prefix="fuzz/artifacts/$t/" "fuzz/corpus/$t" > "$5/$t.log" 2>&1; then
        echo "ok    $t (${secs}s)"
    else
        mv "$5/$t.log" "$5/$t.fail"
        echo "FAIL  $t (${secs}s)"
        exit 1
    fi
' _ {} "$long" "$short" "$bin" "$logs" || status=$?

for f in "$logs"/*.fail; do
    [ -e "$f" ] || continue
    echo "::group::$(basename "$f" .fail)"
    tail -n 60 "$f"
    echo "::endgroup::"
done
rm -rf "$logs"
exit "$status"
